#!/usr/bin/env bash
# Re-export the allowlisted parts of a private ~/.claude into this repo, with
# personal hosts, users and paths replaced by placeholders. Then run scan.sh.
set -euo pipefail
SRC="${CLAUDE_DIR:-$HOME/.claude}"; BIN="${BIN_DIR:-$HOME/.local/bin}"
OUT="$(cd "$(dirname "$0")/.." && pwd)"
copy() { mkdir -p "$OUT/$(dirname "$2")"; cp "$1" "$OUT/$2"; }

copy "$SRC/CLAUDE.md"                     CLAUDE.md
copy "$SRC/settings.json"                 settings.example.json
for f in l1-policy.py policy.toon post-compact-handoff.sh; do copy "$SRC/hooks/$f" "hooks/$f"; done
for f in statusline.sh statusline-p10k.sh signal-bar.py signal-bar.json news-fetcher.sh news-bar.json l3-lanes-fetcher.sh l3-lanes.json hud-bg.sh; do
  copy "$SRC/$f" "statusline/$f"; done
copy "$SRC/skills/dispatch/SKILL.md"      skills/dispatch/SKILL.md
for f in dispatch remote-worker dispatch-plan brief brief.py fleet-metrics; do copy "$BIN/$f" "bin/$f"; done

# Placeholders. Personal values come from env so they never live in this repo.
: "${PRIV_HOST:?set PRIV_HOST}" "${PRIV_USER:?set PRIV_USER}" "${PRIV_HOME_USER:?set PRIV_HOME_USER}"
find "$OUT" -type f ! -path '*/.git/*' ! -path '*/scripts/*' ! -name README.md ! -name LICENSE -print0 |
  xargs -0 perl -pi -e "
    s#/Users/\Q$PRIV_HOME_USER\E#\\\$HOME#g;
    s#/home/\Q$PRIV_USER\E#/home/worker#g;
    s#\Q$PRIV_USER\E@\Q$PRIV_HOST\E#worker\@zeroclaw-host#g;
    s#\Q$PRIV_HOST\E#zeroclaw-host#g;
    s#\b\Q$PRIV_HOME_USER\E\b#you#g;
    s#\b\Q$PRIV_USER\E\b#worker#g;
    s#\b192\.168\.\d+\.\d+\b#192.0.2.10#g;
  "
# PRIV_MAP: extra "private=placeholder" pairs (host aliases, container names, git remotes).
for pair in ${PRIV_MAP:-}; do
  from="${pair%%=*}" to="${pair#*=}"
  find "$OUT" -type f ! -path '*/.git/*' ! -path '*/scripts/*' ! -name README.md ! -name LICENSE -print0 |
    xargs -0 perl -pi -e "s#\\Q$from\\E#$to#g"
done
python3 - "$OUT/settings.example.json" <<'PY'
import json,sys
p=sys.argv[1]; s=json.load(open(p))
for k in ("voice","voiceEnabled","pluginConfigs","extraKnownMarketplaces","enabledPlugins","skipDangerousModePermissionPrompt"):
    s.pop(k,None)
s.get("env",{}).pop("CLAUDE_CODE_PLUGIN_DIRS",None)
json.dump(s,open(p,"w"),indent=2); open(p,"a").write("\n")
PY
echo "exported to $OUT"
