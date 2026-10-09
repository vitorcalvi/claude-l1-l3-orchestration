#!/usr/bin/env bash
# Claude HUD launcher: one row per source, always printed in the same order
#
# Goals:
#   - fast: no ls/grep/awk/sort pipeline on every refresh
#   - update-safe: automatically selects newest installed claude-hud
#   - marketplace-safe: supports plugins/cache/*/claude-hud/*
#   - resilient: statusline failures never interfere with Claude Code
#   - portable across normal macOS Claude Code launches
#
# Each row is rendered by its own background job into a mktemp file; the rows
# are printed only once every job is in, so a slow source never serialises the
# others. Printed order:
#
#   [News]   dim label + headline from the news cache
#   [Sig]    dim label + signal-bar.py render
#   L3       dim label + busy/queued lanes, only while the cache still qualifies
#   HUD      claude-hud lines above its own rule, then
#   [Accts]  dim label + clauth usage windows, then
#   ─────    dim rule across the full usable width, then
#   HUD      claude-hud lines below its own rule
#
# Every printed row is cut to the usable width with ANSI escapes excluded, and
# the whole launcher exits 0 no matter what a source returns.
#
# HUD presentation belongs in:
#   ~/.claude/plugins/claude-hud/config.json

set -u

# ---------------------------------------------------------------------------
# Claude Code input
#
# statusLine commands receive the session JSON on stdin. Consume it once here so
# the HUD runtime can be handed the exact same payload via a here-string.
# ---------------------------------------------------------------------------

hud_stdin=$(cat 2>/dev/null || true)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

CLAUDE_DIR="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"

# Explicit override:
#   CLAUDE_HUD_RUNTIME=/path/to/bun
#
# Otherwise prefer the user's Bun installation.
PREFERRED_BUN="${CLAUDE_HUD_RUNTIME:-$HOME/.bun/bin/bun}"

# ---------------------------------------------------------------------------
# Terminal width
#
# Claude Code reserves ~2 columns of padding on each side of the status line.
# Avoid stty / /dev/tty here: statusLine commands are not guaranteed to have
# a usable interactive TTY. Everything below works on this reduced width.
# ---------------------------------------------------------------------------

if [[ "${COLUMNS:-}" =~ ^[0-9]+$ ]] && (( COLUMNS > 0 )); then
  if (( COLUMNS > 4 )); then
    COLUMNS=$((COLUMNS - 4))
  else
    COLUMNS=1
  fi
else
  COLUMNS=76
fi

# The cached rows are jq pipelines; without jq they are skipped silently and
# the HUD rows still print.
if command -v jq >/dev/null 2>&1; then
  have_jq=1
else
  have_jq=0
fi

# ---------------------------------------------------------------------------
# Locate newest claude-hud
#
# Typical marketplace layout:
#
#   ~/.claude/plugins/cache/<marketplace>/claude-hud/<version>/
#
# Do the version comparison with Bash built-ins so this launcher remains
# cheap even when Claude Code invokes it frequently.
# ---------------------------------------------------------------------------

plugin_dir=""

best_major=-1
best_minor=-1
best_patch=-1

# 1 = prerelease, 0 = stable.
# Stable wins over prerelease for an otherwise identical version.
best_prerelease=1

shopt -s nullglob

for dir in "$CLAUDE_DIR"/plugins/cache/*/claude-hud/*/; do
  [[ -d "$dir" ]] || continue

  version="${dir%/}"
  version="${version##*/}"

  # Accept:
  #   1.2.3
  #   v1.2.3
  #   1.2.3-beta.1
  #   1.2.3+build
  #   1.2.3-beta.1+build
  if [[ "$version" =~ ^v?([0-9]+)\.([0-9]+)\.([0-9]+)(-([^+]+))?(\+.*)?$ ]]; then
    major=$((10#${BASH_REMATCH[1]}))
    minor=$((10#${BASH_REMATCH[2]}))
    patch=$((10#${BASH_REMATCH[3]}))

    if [[ -n "${BASH_REMATCH[4]:-}" ]]; then
      prerelease=1
    else
      prerelease=0
    fi

    if (( major > best_major ||
          (major == best_major && minor > best_minor) ||
          (major == best_major && minor == best_minor && patch > best_patch) ||
          (major == best_major &&
           minor == best_minor &&
           patch == best_patch &&
           prerelease < best_prerelease) )); then

      best_major=$major
      best_minor=$minor
      best_patch=$patch
      best_prerelease=$prerelease
      plugin_dir="$dir"
    fi
  fi
done

shopt -u nullglob

src_entry="${plugin_dir}src/index.ts"
dist_entry="${plugin_dir}dist/index.js"

# ---------------------------------------------------------------------------
# Row inputs
#
# Configs and caches live next to each other in the Claude directory; the
# renders below only ever read the cache, refreshes are spawned detached.
# ---------------------------------------------------------------------------

news_config="$CLAUDE_DIR/news-bar.json"
news_cache="$CLAUDE_DIR/news-bar-cache.json"
news_fetcher="$CLAUDE_DIR/news-fetcher.sh"
news_lock="$CLAUDE_DIR/.news-bar.lock"

sig_config="$CLAUDE_DIR/signal-bar.json"
sig_cache="$CLAUDE_DIR/signal-bar-cache.json"
sig_script="$CLAUDE_DIR/signal-bar.py"
sig_lock="$CLAUDE_DIR/.signal-bar.lock"

# System python starts ~80ms faster than the pyenv shim (render runs every refresh).
sig_py=/usr/bin/python3; [[ -x "$sig_py" ]] || sig_py=python3

l3_config="$CLAUDE_DIR/l3-lanes.json"
l3_cache="$CLAUDE_DIR/l3-lanes-cache.json"
l3_fetcher="$CLAUDE_DIR/l3-lanes-fetcher.sh"
l3_lock="$CLAUDE_DIR/.l3-lanes.lock"

clauth_status="$HOME/.clauth/status.json"

# ---------------------------------------------------------------------------
# Scratch files
#
# One mktemp file per row, all inside a mktemp directory that is
# removed on exit. The render jobs are background subshells and each one
# owns its file until the print pass below.
# ---------------------------------------------------------------------------

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/statusline.XXXXXX" 2>/dev/null) || exit 0
trap 'rm -rf "$work_dir"' EXIT

f_news=$(mktemp "$work_dir/news.XXXXXX" 2>/dev/null) || exit 0
f_sig=$(mktemp "$work_dir/sig.XXXXXX" 2>/dev/null) || exit 0
f_l3=$(mktemp "$work_dir/l3.XXXXXX" 2>/dev/null) || exit 0
f_hud=$(mktemp "$work_dir/hud.XXXXXX" 2>/dev/null) || exit 0
f_accts=$(mktemp "$work_dir/accts.XXXXXX" 2>/dev/null) || exit 0

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

# Modification time of a path, BSD stat first and GNU stat as fallback so the
# lock throttles behave the same on both. Missing paths report 0.
mtime_of() {
  local mt

  mt=$(stat -f %m "$1" 2>/dev/null)
  [[ "$mt" =~ ^[0-9]+$ ]] || mt=$(stat -c %Y "$1" 2>/dev/null)
  [[ "$mt" =~ ^[0-9]+$ ]] || mt=0

  printf '%s' "$mt"
}

# ---------------------------------------------------------------------------
# Row: [News] headline
#
# The hot path only reads the local cache. When it is stale, the fetcher is
# spawned detached (all fds to /dev/null so it never holds the statusline
# pipe open); a lock dir throttles retries to one per minute on failure.
# Config: ~/.claude/news-bar.json   Fetcher: ~/.claude/news-fetcher.sh
# ---------------------------------------------------------------------------

render_news() {
  [[ "$have_jq" -eq 1 ]] || return 0
  [[ -f "$news_config" && -f "$news_cache" ]] || return 0
  [[ "$(jq -r '.enable_news_bar // false' "$news_config" 2>/dev/null)" == true ]] || return 0

  local now refresh_s fetched_at lock_mtime news_line

  now=$(date +%s)
  refresh_s=$(( $(jq -r '.refresh_minutes // 10' "$news_config" 2>/dev/null || echo 10) * 60 ))
  fetched_at=$(jq -r '.fetched_at // 0' "$news_cache" 2>/dev/null || echo 0)
  [[ "$fetched_at" =~ ^[0-9]+$ ]] || fetched_at=0

  if (( now - fetched_at >= refresh_s )) && [[ -x "$news_fetcher" ]]; then
    lock_mtime=$(mtime_of "$news_lock")
    if (( now - lock_mtime >= 60 )); then
      mkdir -p "$news_lock" 2>/dev/null && touch "$news_lock"
      ( "$news_fetcher" </dev/null >/dev/null 2>&1 & )
    fi
  fi

  news_line=$(jq -r --slurpfile cfg "$news_config" --argjson now "$now" '
    ($cfg[0]) as $c
    | [.items[]?.title] as $t
    | ($c.max_headline_length // 60) as $max
    | def cut($n): if length > $n then .[0:$n-1] + "…" else . end;
    if ($t | length) == 0 then empty
    elif ($c.mode // "rotate") == "ticker" then
      $t | map(cut($max)) | join(" | ") | cut($max * 3)
    else
      $t[(($now / ($c.rotate_seconds // 60)) | floor) % ($t | length)] | cut($max)
    end
  ' "$news_cache" 2>/dev/null)

  [[ -n "$news_line" ]] || return 0

  printf '\033[2m[News]\033[0m \033[38;5;250m%s\033[0m\n' "$news_line"
}

# ---------------------------------------------------------------------------
# Row: [Sig] intraday catalyst │ macro │ bias
#
# Same pattern as the news bar: render reads the local cache only (ages and
# countdowns computed live); the fetcher refreshes stale sections detached.
# Config: ~/.claude/signal-bar.json   Script: ~/.claude/signal-bar.py
# ---------------------------------------------------------------------------

render_sig() {
  [[ "$have_jq" -eq 1 ]] || return 0
  [[ -f "$sig_config" && -f "$sig_cache" && -f "$sig_script" ]] || return 0
  [[ "$(jq -r '.enable // false' "$sig_config" 2>/dev/null)" == true ]] || return 0

  local now sig_refresh sig_fetched lock_mtime sig_line

  now=$(date +%s)
  sig_refresh=$(jq -r '.market_ttl_s // 60' "$sig_config" 2>/dev/null || echo 60)
  sig_fetched=$(jq -r '.fetched_at // 0' "$sig_cache" 2>/dev/null || echo 0)
  [[ "$sig_fetched" =~ ^[0-9]+$ ]] || sig_fetched=0

  if (( now - sig_fetched >= sig_refresh )); then
    lock_mtime=$(mtime_of "$sig_lock")
    if (( now - lock_mtime >= sig_refresh )); then
      mkdir -p "$sig_lock" 2>/dev/null && touch "$sig_lock"
      ( "$sig_py" -I "$sig_script" fetch </dev/null >/dev/null 2>&1 & )
    fi
  fi

  sig_line=$("$sig_py" -I "$sig_script" render 2>/dev/null)

  [[ -n "$sig_line" ]] || return 0

  printf '\033[2m[Sig]\033[0m \033[38;5;252m%s\033[0m\n' "$sig_line"
}

# ---------------------------------------------------------------------------
# Row: L3 lanes (which remote worker lanes are busy)
#
# Same pattern as the news bar: read the local cache only; spawn the fetcher
# detached when stale (lock dir throttles to one attempt per refresh period).
# Hidden when the cache is too old or nothing is running.
# Config: ~/.claude/l3-lanes.json   Fetcher: ~/.claude/l3-lanes-fetcher.sh
# ---------------------------------------------------------------------------

render_l3() {
  [[ "$have_jq" -eq 1 ]] || return 0
  [[ -f "$l3_config" && -f "$l3_cache" ]] || return 0
  [[ "$(jq -r '.enable // false' "$l3_config" 2>/dev/null)" == true ]] || return 0

  local now l3_refresh l3_fetched lock_mtime l3_line

  now=$(date +%s)
  l3_refresh=$(jq -r '.refresh_seconds // 15' "$l3_config" 2>/dev/null || echo 15)
  l3_fetched=$(jq -r '.fetched_at // 0' "$l3_cache" 2>/dev/null || echo 0)
  [[ "$l3_fetched" =~ ^[0-9]+$ ]] || l3_fetched=0

  if (( now - l3_fetched >= l3_refresh )) && [[ -x "$l3_fetcher" ]]; then
    lock_mtime=$(mtime_of "$l3_lock")
    if (( now - lock_mtime >= l3_refresh )); then
      mkdir -p "$l3_lock" 2>/dev/null && touch "$l3_lock"
      ( "$l3_fetcher" </dev/null >/dev/null 2>&1 & )
    fi
  fi

  l3_line=$(jq -r --slurpfile cfg "$l3_config" --argjson now "$now" '
    ($cfg[0]) as $c
    | select(($now - (.fetched_at // 0)) <= ($c.max_age_seconds // 120))
    | select(.busy > 0 or .queued > 0 or ($c.show_when_idle // false))
    | def color($l):
        if $l == "paid" then "38;5;45"
        elif $l == "bulk" then "38;5;178"
        elif $l == "rq" then "38;5;244"
        else "38;5;76" end;
      (if .lanes != null then
         ([.lanes | to_entries | sort_by(-.value.active, -.value.cap, .key)[]
           | if .value.active > 0
             then "\u001b[\(color(.key))m\(.key) \(.value.active)/\(.value.cap)\u001b[0m"
             else "\u001b[2m\(.key) 0/\(.value.cap)\u001b[0m" end])
       else
         ([.by_lane | to_entries | sort_by(-.value)[]
           | "\u001b[\(color(.key))m\(.key) \(.value)\u001b[0m"])
       end) as $lanes
    | "\u001b[2mL3\u001b[0m \(.busy)/\(.capacity)"
      + (if ($lanes | length) > 0 then " · " + ($lanes | join(" · ")) else "" end)
      + (if .queued > 0 then " · \u001b[38;5;208mq\(.queued)\u001b[0m" else "" end)
      + (if .backend == "rq" then " \u001b[2m(old pool)\u001b[0m" else "" end)
  ' "$l3_cache" 2>/dev/null)

  [[ -n "$l3_line" ]] || return 0

  printf '%s\n' "$l3_line"
}

# ---------------------------------------------------------------------------
# Row: [Accts] usage windows per Claude account (clauth)
#
# Render reads ~/.clauth/status.json only. When it is stale (no daemon), the
# clauth daemon is spawned detached; it exits at once if one already runs.
# The row is a dim label, then per profile a bold star when it is the active
# one and the name before the at sign, then every window as label, space,
# coloured percent, space, time left. Windows and profiles are separated by a
# dim pipe.
# ---------------------------------------------------------------------------

render_accts() {
  [[ "$have_jq" -eq 1 ]] || return 0
  [[ -f "$clauth_status" ]] || return 0

  local now st_mtime acct_line

  now=$(date +%s)
  st_mtime=$(mtime_of "$clauth_status")

  if (( now - st_mtime > 300 )) && command -v clauth >/dev/null 2>&1; then
    ( clauth daemon </dev/null >/dev/null 2>&1 & )
  fi

  acct_line=$(jq -r --argjson now "$now" '
    def col(p): if p >= 90 then "\u001b[31m" elif p >= 70 then "\u001b[33m" else "\u001b[32m" end;
    def left(t): ((t | sub("\\.[0-9]+"; "") | sub("\\+00:00$"; "Z") | fromdateiso8601) - $now) as $s
      | if $s <= 0 then "now" elif $s < 3600 then "\($s / 60 | floor)m"
        elif $s < 86400 then "\($s / 3600 | floor)h\(($s % 3600) / 60 | floor)m"
        else "\($s / 86400 | floor)d\(($s % 86400) / 3600 | floor)h" end;
    [ .profiles[]
      | (if .active then "\u001b[1m*" else "" end) + (.name | split("@")[0]) + "\u001b[0m "
        + ( if (.windows | length) == 0 then "\u001b[2m–\u001b[0m"
            else [ .windows[]
                   | "\(.label) " + col(.utilization_pct) + "\(.utilization_pct | floor)%\u001b[0m"
                   + (if .resets_at then " " + left(.resets_at) else "" end) ]
                 | join(" \u001b[2m│\u001b[0m ") end ) ]
    | join(" \u001b[2m│\u001b[0m ")
  ' "$clauth_status" 2>/dev/null)

  [[ -n "$acct_line" ]] || return 0

  printf '\033[2m[Accts]\033[0m %s\n' "$acct_line"
}

# ---------------------------------------------------------------------------
# Row: claude-hud itself
#
# Runtime selection priority:
#   1. CLAUDE_HUD_RUNTIME / ~/.bun/bin/bun
#   2. Bun from PATH
#   3. Node >=18 + compiled dist/index.js
#
# Source execution requires Bun. With no HUD installed nothing is printed.
# ---------------------------------------------------------------------------

render_hud() {
  local hud_ran bun_bin node_bin node_major

  hud_ran=0

  if [[ "$hud_ran" -eq 0 ]] && [[ -f "$src_entry" ]]; then

    # Fast path: known Bun location.
    if [[ -x "$PREFERRED_BUN" ]]; then
      "$PREFERRED_BUN" \
        --env-file /dev/null \
        "$src_entry" \
        <<< "$hud_stdin" 2>/dev/null
      hud_ran=1

    # PATH fallback.
    elif command -v bun >/dev/null 2>&1; then
      bun_bin="$(command -v bun)"

      if [[ -x "$bun_bin" ]]; then
        "$bun_bin" \
          --env-file /dev/null \
          "$src_entry" \
          <<< "$hud_stdin" 2>/dev/null
        hud_ran=1
      fi
    fi
  fi

  # Node fallback.
  if [[ "$hud_ran" -eq 0 ]] &&
     [[ -f "$dist_entry" ]] && command -v node >/dev/null 2>&1; then
    node_bin="$(command -v node)"

    # claude-hud requires modern Node. Avoid expensive semver tooling.
    node_major="$("$node_bin" -p 'process.versions.node.split(".")[0]' 2>/dev/null || true)"

    if [[ "$node_major" =~ ^[0-9]+$ ]] && (( node_major >= 18 )); then
      "$node_bin" "$dist_entry" <<< "$hud_stdin" 2>/dev/null
    fi
  fi
}

# ---------------------------------------------------------------------------
# Render every row concurrently
# ---------------------------------------------------------------------------

render_news  >"$f_news"  2>/dev/null &
render_sig   >"$f_sig"   2>/dev/null &
render_l3    >"$f_l3"    2>/dev/null &
render_accts >"$f_accts" 2>/dev/null &
render_hud   >"$f_hud"   2>/dev/null &

wait

# ---------------------------------------------------------------------------
# Print in row order
#
# The HUD payload is split on its own rule line: everything above it lands
# before the accounts row, everything below it after the rule drawn here. Its
# " | " separators become the same dim pipe the rest of the statusline uses,
# the rule line itself is dropped, and every row is finally cut to COLUMNS
# visible cells in a single awk pass.
# ---------------------------------------------------------------------------

rule_width=$COLUMNS
printf -v rule_row '%*s' "$rule_width" ''
rule_row=${rule_row// /─}
divider=$'\033[2m'"$rule_row"$'\033[0m'

nocolor=""
[[ -n "${NO_COLOR:-}" ]] && nocolor=1

LC_ALL=C awk -v max="$COLUMNS" -v nocolor="$nocolor" -v divider="$divider" \
  -v newsf="$f_news" -v sigf="$f_sig" -v l3f="$f_l3" -v acktf="$f_accts" -v hudf="$f_hud" '
BEGIN {
  esc = sprintf("%c", 27)
  reset = esc "[0m"
  dim = esc "[2m"
  pipe = " " dim "\342\224\202" reset " "   # │ between windows and profiles
  ell = "\342\200\246"                        # … marks a cut row
  rule = "\342\224\200"                       # ─ the rule glyph
  ansi = esc "\\[[0-9;:]*[@-~]"
}

# One truncation pass: escape sequences are copied through untouched and only
# visible cells count, so the cut happens on what the terminal actually paints.
function fit(s, limit,   out, i, n, c, j, vis, plain, w) {
  if (nocolor != "") gsub(ansi, "", s)

  # A row that already fits is printed as it is: only a row wider than the
  # limit loses cells, so a row landing exactly on it keeps its full text.
  plain = s
  gsub(ansi, "", plain)
  w = 0
  for (i = 1; i <= length(plain); i++) if (substr(plain, i, 1) !~ /[\200-\277]/) w++
  if (w <= limit) { print s; return }

  out = ""; i = 1; n = length(s); vis = 0

  while (i <= n) {
    c = substr(s, i, 1)

    if (c == esc) {
      j = i + 1
      if (substr(s, j, 1) == "[") {
        j++
        while (j <= n && substr(s, j, 1) !~ /[@-~]/) j++
      } else if (substr(s, j, 1) == "]") {
        while (j <= n && substr(s, j, 1) != "\007") j++
      }
      out = out substr(s, i, j - i + 1)
      i = j + 1
      continue
    }

    if (c ~ /[\200-\277]/) { out = out c; i++; continue }   # UTF-8 tail byte

    if (vis < limit - 1) { out = out c; vis++; i++; continue }

    print out ell (nocolor != "" ? "" : reset)                    # cut: mark it
    return
  }

  print out
}

FILENAME == newsf { fit($0, max); next }
FILENAME == sigf  { fit($0, max); next }
FILENAME == l3f   { fit($0, max); next }
FILENAME == acktf { accts = accts $0 "\n"; next }

FILENAME == hudf {
  plain = $0
  gsub(ansi, "", plain)

  # The first all-dashes line is the plugin rule: everything after it is the
  # bottom half of the HUD and the rule itself is dropped.
  if (!split_done && gsub(rule, "", plain) > 0 && plain == "") { split_done = 1; next }

  gsub(/ \| /, pipe)

  if (split_done) hud_bot = hud_bot $0 "\n"
  else hud_top = hud_top $0 "\n"
  next
}

END {
  n = split(hud_top, rows, "\n"); for (i = 1; i <= n; i++) if (rows[i] != "") fit(rows[i], max)
  n = split(accts, rows, "\n");    for (i = 1; i <= n; i++) if (rows[i] != "") fit(rows[i], max)
  # The divider is drawn at exactly the usable width, so it is emitted as is
  # (escapes dropped when nocolor) instead of being cut and marked.
  if (divider != "") { d = divider; if (nocolor != "") gsub(ansi, "", d); print d }
  n = split(hud_bot, rows, "\n"); for (i = 1; i <= n; i++) if (rows[i] != "") fit(rows[i], max)
}
' "$f_news" "$f_sig" "$f_l3" "$f_accts" "$f_hud"

# Statusline should never break Claude Code.
exit 0
