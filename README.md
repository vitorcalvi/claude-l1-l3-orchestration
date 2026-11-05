# claude-l1-l3-orchestration

A Claude Code setup where the main session (L1, Opus) only plans, dispatches and
reviews, and a remote worker fleet (L3, ZeroClaw) does the building in parallel
lanes. The goal is fewer L1 tokens with no loss in success rate.

## What's here

| Path | What it is |
|---|---|
| `CLAUDE.md` | Global rules: L1/L2/L3 routing, engineering gates, infra safety, token hygiene |
| `settings.example.json` | Permissions, the PreToolUse policy hook, statusline wiring |
| `hooks/l1-policy.py`, `hooks/policy.toon` | Capability-policy PreToolUse hook: allow/deny/escalate per tool call, audit log, `shadow` (log only) or `enforce` mode via `L1_POLICY_MODE` |
| `hooks/post-compact-handoff.sh` | Re-injects handoff context after compaction |
| `statusline/` | Statusline + HUD: signal bar, news bar, L3 lane status |
| `skills/autonomy/SKILL.md` | Autonomous decision-making, test-driven continuation, bounded repair and approval boundaries |
| `docs/autonomous-operation.md` | Setup, smoke test and optional unattended GitHub architecture |
| `skills/dispatch/SKILL.md` | How L1 dispatches to L3: lanes, envelope, fallback |
| `bin/dispatch`, `bin/dispatch-plan` | Submit a job brief (or a DAG of lanes) to the worker host, `--async` supported |
| `bin/remote-worker` | `wait`, `digest`, `fetch`, `status`, `logs`, `slots` for remote jobs |
| `bin/brief`, `bin/brief.py` | Generate recon/build/verify briefs |
| `bin/fleet-metrics` | Token and cost baseline from transcripts and the worker ledger |
| `scripts/export.sh`, `scripts/scan.sh` | How this repo is produced from a private `~/.claude`, and the leak check |

## Autonomous decision mode

Copy `skills/autonomy/SKILL.md` into your Claude Code skills directory and add the matching routing rule to your existing `CLAUDE.md`. It chooses a safe next action and continues to verified results without asking the owner to select routine alternatives. This is an opt-in policy, **not** an installed Mac configuration or a live background scheduler. Existing remote-worker routing, policy hooks, approvals and branch gates still apply. See [autonomous operation](docs/autonomous-operation.md).

## Using it

These files come from a working setup, so they assume a worker host. Every
personal value is replaced with a placeholder:

- `zeroclaw-host` / `worker@zeroclaw-host`: your worker machine and ssh user
- `192.0.2.10`: any LAN address (LiteLLM gateway on port 4000, for example)
- `$HOME`: your home directory

Copy what you want into `~/.claude` (hooks, statusline, skills) and `~/.local/bin`
(tools), then search for the placeholders and fill in your own values. Start the
policy hook in shadow mode, read `~/.local/state/claude-hooks/l1-policy/shadow-audit.jsonl`
for a week, and only then switch to `enforce`.

## Keeping a fork in sync with your own config

```
PRIV_HOST=<your host> PRIV_USER=<ssh user> PRIV_HOME_USER=<mac user> \
  PRIV_MAP='<ssh-alias>=zeroclaw-host <container>=zeroclaw-worker' scripts/export.sh
SCAN_EXTRA='<your name>|<your email user>' scripts/scan.sh
```

`scan.sh` must print `SCAN: PASS` before you commit.

## License

MIT
