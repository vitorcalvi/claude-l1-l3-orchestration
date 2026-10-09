#!/usr/bin/env bash
# Yahoo Finance headline fetcher for the statusline news bar.
#
# Fetches the RSS feed, parses the top N items (title/url/time) and writes
# them atomically to the cache JSON. On any failure the previous cache is
# left untouched. Invoked in the background by statusline.sh when stale.

set -u

CLAUDE_DIR="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
CONFIG="$CLAUDE_DIR/news-bar.json"
CACHE="$CLAUDE_DIR/news-bar-cache.json"

cfg() { jq -r "$1 // empty" "$CONFIG" 2>/dev/null; }

feed_url="$(cfg .feed_url)"
feed_url="${feed_url:-https://feeds.finance.yahoo.com/rss/2.0/headline?s=%5EGSPC,%5EDJI,%5EIXIC&region=US&lang=en-US}"
timeout_s="$(cfg .timeout_seconds)"
timeout_s="${timeout_s:-2}"
max_items="$(cfg .max_items)"
max_items="${max_items:-5}"

tmp="$(mktemp "${CACHE}.XXXXXX")" || exit 0
trap 'rm -f "$tmp" "$tmp.xml"' EXIT

curl -fsS -m "$timeout_s" -A 'Mozilla/5.0' -o "$tmp.xml" "$feed_url" 2>/dev/null || exit 0

# -I: isolated mode, so nothing from cwd/env is imported.
python3 -I - "$tmp.xml" "$max_items" >"$tmp" 2>/dev/null <<'PY' || exit 0
import json, sys, time
import xml.etree.ElementTree as ET

path, limit = sys.argv[1], int(sys.argv[2])
items = []
for item in ET.parse(path).getroot().iter("item"):
    title = " ".join((item.findtext("title") or "").split())
    if not title:
        continue
    items.append({
        "title": title,
        "url": (item.findtext("link") or "").strip(),
        "time": (item.findtext("pubDate") or "").strip(),
    })
    if len(items) >= limit:
        break
if not items:
    sys.exit(1)
json.dump({"fetched_at": int(time.time()), "items": items}, sys.stdout)
PY

mv -f "$tmp" "$CACHE"
