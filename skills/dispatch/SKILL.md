---
name: dispatch
description: "Remote Claude pool dispatch, capacity, verification, and return contract."
---

# Dispatch

## Active route
L1 Opus -> optional L2 Sonnet 5.5 medium when the Agent tool is available -> L3 remote Claude workers. L3 is the implementation/execution plane. Do not use Codex, agy, Cline, Hermes, or Qwen as normal routes.

Before each wave:
1. Run `remote-worker slots`.
2. Treat live free slots as the only capacity truth.
3. Dispatch only independent lanes with disjoint write paths.
4. Use one worker for atomic work; never create work merely to fill slots.

## Command
Use:
`dispatch claude <delta.md> [--repo PATH]`

For a DAG with 2+ nodes use:
`dispatch-plan PLAN.json`

A remote Claude worker is pool-only. Do not use `--local` with `dispatch claude`.

## Lanes (ZeroClaw backend)
All repos run on ZeroClaw (`~/agent-work/zeroclaw-repos` = `*`). Caller commands do not change. Do not route work to the old RQ pool.
- Since 2026-10-08 every ZeroClaw lane (`paid | coding | fast | reasoning | bulk`) runs on `paid-workers` (MiniMax flat plan; free aliases stalled on daily quota). Leave `## lane` unset (→ `paid`). `reasoning` is read-only; editable jobs on it are rejected.
- On worker error or test failure the backend records the failed job and retries as `<id>-fb1` (same model now; max 2 hops) that CONTINUES from the failed attempt's commits (`base_branch` set; brief opens with `## previous_attempt` + failure lines). Merge the `-fbN` branch, not the first one. The original job id reports the final envelope, with `FALLBACK: a->b (reason)` in EVIDENCE. Failed/-fb jobs keep their trace at `/work/logs/<id>.trace.jsonl.gz`; each tool failure is a `ZC_TOOL_FAILURE` log line; ledger `provider_failures` and `tool_failures` are separate.
- A job editing test files ends `TEST_EDITED` (runner_exit=1) even when tests pass; review the branch and verify separately.
- The worker's final text is in `remote-worker logs <id>`, not worker_result; have reviewers commit `.agent-reports/<name>.md`.
- Read-only is detect-only on ZeroClaw: a commit makes the job BLOCKED but is not prevented up front.
- Per-job lane, tokens, tool calls and cost appear in the job log as `ZC_METRICS` (cost is nominal: flat plan); `zc-metrics.py` gives per-lane totals. Lane labels there may still show old alias names (cosmetic). The HUD `L3` line shows busy lanes.

## Delta
Every delta contains:

```markdown
## effort
low | medium
## execution: remote
## goal
<observable goal>
## user_request
<verbatim request>
## scope
<included work and owned paths>
## non_goals
<excluded work>
## constraints
<security, compatibility, no-secret rules>
## acceptance
<mechanically checkable completion criteria>
## evidence_required
<tests/commands/artifacts>
## unknowns
none | unresolved assumptions
## remote_worker
claude
## remote_mode
editable | read-only
## remote_test_cmd
<required for editable code AND independent read-only verification; omit only for read-only recon/non-code>
```

The worker shell blocks `$(...)`, `>`/`>>`, `python3 -m`/`-c`, `command -v` and non-allowlisted binaries (allowlist: `/work/zeroclaw/config.toml`); repeated rejections make the worker quit with zero commits. Tell workers to inspect files with file_read and put multi-step checks in a script run as `bash path/to/check.sh`.

Every brief needs at least one acceptance assertion on the real raw output (e.g. ANSI escapes present when colour is expected, exact visible widths), not only on what the code claims. Workers run Linux bash 5: for scripts that run on the Mac, name `/bin/bash` 3.2 in constraints and re-run the test locally with `/bin/bash` before install (a multibyte char right after `$var` breaks 3.2; use `${var}`). Read-only verifiers must execute the script and inspect its output, not only read the diff.

`remote_test_cmd` must be ONE line: only the first line is kept, so a multi-line `python3 -c '...'` becomes an unterminated quote and a false TEST_FAILED. Use `;`/`&&` or grep/sed checks.

A passing gate is not proof the scope was done: workers that hit the 80-tool cap still return DONE if old tests pass. Make `remote_test_cmd` also grep for each new symbol/test class. Name exact files and functions; tell the worker to start editing immediately; never inline large data. Write literal syntax literally (`'*'`, not "star"): workers copy words verbatim. Shell `>` and inline `node -e`/`python3 -c` are blocked in workers. Read-only verifiers: forbid probe scripts and cap tool calls, or the loop detector aborts them.

Keep briefs narrow. Ground claims in the actual repo. Never read whole credential-bearing files; inspect only the specific field needed and never emit secret values.

## Verification
Worker success is not proof. Require numeric exit codes for checks. For merged code or security/data/money/irreversible changes, launch a separate dispatch claude read-only verification job against the produced branch/change. Give that verifier an explicit mechanical remote_test_cmd; verification must not rely on prose alone and must not share the writer's mutable worktree. Returned worker tests are accepted as secondary evidence when each item contains a numeric exit code. Skip the extra verifier for read-only recon/measurement.

## Failure handling
A worker may make at most two bounded repairs. `BLOCKED` means revise the brief or dependency; `ASSUMPTION_INVALID` means revisit the premise. Never hand-fix worker output in L1.

## Return contract
The final worker envelope uses:
`STATUS, RUN_ID, BASE, HEAD, CHANGED, ANSWER, CHECKS, REPAIRS, FAILURE, DECISION NEEDED, ARTIFACTS`.
Keep ANSWER concise; keep raw logs/artifacts on disk and surface only targeted evidence.

## Token discipline
Use Grep/symbol lookup before large Read. Bound file ranges. Filter logs. Avoid rereading unchanged files. TokenSlim compresses tool results automatically; do not duplicate its implementation instructions here.
