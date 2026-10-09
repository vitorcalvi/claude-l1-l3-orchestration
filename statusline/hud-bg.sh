#!/usr/bin/env bash
# Third Claude HUD statusline row: permission mode + background work.
#
# Usage: hud-bg.sh TRANSCRIPT_PATH
#
# Prints a single line, or nothing at all, and always exits 0. A statusline row
# must never break Claude Code, so every failure path here is silent.
#
# Performance: transcripts get long, so this script does exactly one grep pass
# (prefilter) and one jq pass (parse). The prefilter drops the overwhelming
# majority of lines, which can carry neither permissionMode, nor a background
# tool_use, nor a task-notification completion marker.
#
# Set HUD_BG_NO_COLOR=1 to emit the same text without any ANSI escapes.

set -u

# ---------------------------------------------------------------------------
# Guards
# ---------------------------------------------------------------------------

if [[ $# -lt 1 || -z "${1:-}" ]]; then
  exit 0
fi

transcript="$1"

if [[ ! -f "$transcript" || ! -r "$transcript" ]]; then
  exit 0
fi

# ---------------------------------------------------------------------------
# Colors (true color)
# ---------------------------------------------------------------------------

if [[ "${HUD_BG_NO_COLOR:-}" == "1" ]]; then
  C_RESET=''
  C_RED=''
  C_YELLOW=''
  C_CYAN=''
  C_BLUE=''
  C_GRAY=''
else
  C_RESET=$'\033[0m'
  C_RED=$'\033[38;2;255;123;114m'
  C_YELLOW=$'\033[38;2;210;153;34m'
  C_CYAN=$'\033[38;2;86;211;214m'
  C_BLUE=$'\033[38;2;121;192;255m'
  C_GRAY=$'\033[38;2;72;79;88m'
fi

# ---------------------------------------------------------------------------
# Single grep pass
# ---------------------------------------------------------------------------

lines=$(grep -E 'permissionMode|run_in_background|task-notification' \
  "$transcript" 2>/dev/null || true)

if [[ -z "$lines" ]]; then
  exit 0
fi

# ---------------------------------------------------------------------------
# Single jq pass
#
# Emits  <mode>|<n_shell>|<n_agent>: a pipe cannot occur in a permission mode
# name, and it is not IFS whitespace (so `read -r` keeps a leading empty mode
# field intact). 0x01 was the separator before, but bash 3.2 (the /bin/bash on
# macOS) uses that byte as its internal CTLESC and refuses to split on it, so
# the whole result landed in $mode and both counts read back as 0.
# ---------------------------------------------------------------------------

result=$(printf '%s\n' "$lines" | jq -R -r -n '
  [inputs] as $lines
  # Malformed lines are dropped rather than aborting the whole row.
  | ([ $lines[] | (try fromjson catch null) | select(. != null) ]) as $entries
  # The last top-level permissionMode string wins.
  | ([ $entries[]
       | select((.permissionMode? | type) == "string")
       | .permissionMode ]) as $modes
  | (if ($modes | length) > 0 then $modes[-1] else "" end) as $mode
  # Background launches, keyed by tool_use id.
  | ([ $entries[]
       | select((.type? // "") == "assistant")
       | (.message.content? // empty)
       | if type == "array" then .[] else empty end
       | select((.type? // "") == "tool_use")
       | select(.input?.run_in_background? == true)
       | select((.id? | type) == "string")
       | [(.name? // ""), .id] ]) as $launched
  | ([ $launched[] | select(.[0] == "Bash") | .[1] ]) as $shell_ids
  | ([ $launched[] | select(.[0] == "Agent" or .[0] == "Task") | .[1] ]) as $agent_ids
  # Anything named inside a <tool-use-id>...</tool-use-id> tag has finished.
  # jq scan() yields one capture array per match, hence the trailing [].
  | ([ $lines[] | scan("<tool-use-id>([^<]*)</tool-use-id>")[] ] | unique) as $finished
  | ([ $shell_ids[]
       | select(. as $id | ($finished | index($id)) == null) ]
     | unique | length) as $n_shell
  | ([ $agent_ids[]
       | select(. as $id | ($finished | index($id)) == null) ]
     | unique | length) as $n_agent
  | "\($mode)|\($n_shell)|\($n_agent)"
' 2>/dev/null || true)

if [[ -z "$result" ]]; then
  exit 0
fi

IFS='|' read -r mode n_shell n_agent <<< "$result"

case "$n_shell" in ''|*[!0-9]*) n_shell=0 ;; esac
case "$n_agent" in ''|*[!0-9]*) n_agent=0 ;; esac

# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------

# "default" (and anything unrecognized) contributes no mode part.
mode_text=""
mode_color="$C_RESET"

case "$mode" in
  bypassPermissions)
    mode_text="⏵⏵ bypass permissions on"
    mode_color="$C_RED"
    ;;
  acceptEdits)
    mode_text="⏵⏵ accept edits on"
    mode_color="$C_YELLOW"
    ;;
  auto)
    mode_text="⏵⏵ auto mode on"
    mode_color="$C_YELLOW"
    ;;
  plan)
    mode_text="⏸ plan mode on"
    mode_color="$C_CYAN"
    ;;
esac

parts=()

if [[ -n "$mode_text" ]]; then
  parts+=("${mode_color}${mode_text}${C_RESET}")
fi

if (( n_shell > 0 )); then
  if (( n_shell == 1 )); then
    parts+=("${C_BLUE}1 shell${C_RESET}")
  else
    parts+=("${C_BLUE}${n_shell} shells${C_RESET}")
  fi
fi

if (( n_agent > 0 )); then
  if (( n_agent == 1 )); then
    parts+=("${C_BLUE}← 1 agent${C_RESET}")
  else
    parts+=("${C_BLUE}← ${n_agent} agents${C_RESET}")
  fi
fi

part_count=${#parts[@]}

if (( part_count == 0 )); then
  exit 0
fi

sep="${C_GRAY} · ${C_RESET}"
row="${parts[0]}"

i=1
while (( i < part_count )); do
  row="${row}${sep}${parts[$i]}"
  i=$(( i + 1 ))
done

printf '%s\n' "$row"

exit 0
