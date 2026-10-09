#!/usr/bin/env bash
# L3 lane fetcher for the statusline: which worker lanes are busy right now.
#
# Runs `remote-worker slots` (ssh) and normalizes both backends to
#   {fetched_at, backend, capacity, busy, queued, by_lane: {lane: n}, lanes: {lane: {active, cap}}}
# - ZeroClaw backend: uses active_by_lane / queued / per-worker lane.
# - Old RQ pool: no lane info, so each busy rq-worker counts as lane "rq".
# Writes the cache atomically; on any failure the previous cache is kept.
# Invoked in the background by statusline.sh when the cache is stale.

set -u

CLAUDE_DIR="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
CACHE="$CLAUDE_DIR/l3-lanes-cache.json"
RW="${L3_REMOTE_WORKER:-$HOME/.local/bin/remote-worker}"

[[ -x "$RW" ]] || exit 0

tmp="$(mktemp "${CACHE}.XXXXXX")" || exit 0
trap 'rm -f "$tmp" "$tmp.raw"' EXIT

# Hard timeout without coreutils `timeout` (not on stock macOS).
"$RW" slots >"$tmp.raw" 2>/dev/null &
pid=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
  kill -0 "$pid" 2>/dev/null || break
  sleep 0.5
done
if kill -0 "$pid" 2>/dev/null; then
  kill "$pid" 2>/dev/null
  exit 0
fi
wait "$pid" || exit 0

jq -c --argjson now "$(date +%s)" '
  select(.ok == true)
  | (.workers // []) as $w
  | ([$w[] | select(.state == "busy")]) as $busy
  | {
      fetched_at: $now,
      backend: (if (.active_by_lane != null) or ([$w[].name] | any(startswith("zeroclaw"))) then "zeroclaw" else "rq" end),
      capacity: (.capacity // .max_parallel // 5),
      busy: (.busy // ($busy | length)),
      queued: (.queued // ([(.queue_depths // .queues // {}) | to_entries[] | select(.key | startswith("claude")) | .value] | add) // 0),
      lanes: (.lanes // null | if . == null then null else with_entries(.value |= {active: (.active // 0), cap: (.cap // 0)}) end),
      by_lane: (
        if .active_by_lane != null then (.active_by_lane | with_entries(select(.value > 0)))
        else ($busy | map(.lane // "rq") | group_by(.) | map({key: .[0], value: length}) | from_entries)
        end)
    }' "$tmp.raw" >"$tmp" 2>/dev/null || exit 0

[[ -s "$tmp" ]] && mv -f "$tmp" "$CACHE"
