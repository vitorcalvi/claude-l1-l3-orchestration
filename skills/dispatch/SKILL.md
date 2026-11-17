---
name: dispatch
description: "Use when sending work to remote Sonnet workers or Dagu lanes: delta format, capacity, verification, return contract. Not for single ChatGPT fixes."
---

# Dispatch

## Active route
**Lane choice follows docs/rules/routing-registry.toon** (Codex only as code-lane fallback). Claude plans the split (use `chatgpt-ask` for large waves) and merges the lane branches itself; a read-only verifier stays mandatory.

Wave flow (Opus 5.5 is the L1 coordinator; it plans, verifies and merges, and never writes project code): 1 Claude plans the split (read-only TOON, ≤5 lanes; `chatgpt-ask` for large waves) → 2 Claude `dispatch` / `dispatch-plan` to ≤5 Sonnet edit-worker lanes → 3 full-suite gate → 4 read-only verifier → 5 Claude merges. Cline, Hermes and Qwen are not routes; agy and Codex only where the registry lists them.

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


Every brief needs at least one acceptance assertion on the real raw output (e.g. ANSI escapes present when colour is expected, exact visible widths), not only on what the code claims. Workers run Linux bash 5: for scripts that run on the Mac, name `/bin/bash` 3.2 in constraints and re-run the test locally with `/bin/bash` before install (a multibyte char right after `$var` breaks 3.2; use `${var}`). Read-only verifiers must execute the script and inspect its output, not only read the diff.

`remote_test_cmd` must be ONE line: only the first line is kept, so a multi-line `python3 -c '...'` becomes an unterminated quote and a false TEST_FAILED. Use `;`/`&&` or grep/sed checks.

Workers have no pytest/ruff and cannot pip/uv install, so they code blind. Say in every editable brief: "you cannot run pytest/ruff; edit, then commit; the runner's gate tests after". Without this, workers burn all 80 tool calls planning and exit NO_CHANGES. Cap exploration ("open only these files; at most N tool calls"). A Python gate must build its own venv in one line: `V=$(mktemp -d)/v && python3 -m venv "$V" && "$V/bin/pip" install -q pytest -e . && "$V/bin/pytest" -q`. On a shared pool, tag the goal `[project:<name>]` and use at most 3 slots per project. read-only mode only detects commits (the runner then discards the work), so say "do not commit" explicitly. The paid lane is reliable for short single-focus analysis, fuzzing and review, and unreliable on multi-item builds: split those into one item per lane, or give them to ChatGPT.

A passing gate is not proof the scope was done: workers that hit the 80-tool cap still return DONE if old tests pass, and one returned DONE with 0 of 6 required items. Make `remote_test_cmd` also grep for each new symbol/test class, one named test per required item. Name exact files and functions; tell the worker to start editing immediately; never inline large data. Write literal syntax literally (`'*'`, not "star"): workers copy words verbatim. Shell `>` and inline `node -e`/`python3 -c` are blocked in workers. Read-only verifiers: forbid probe scripts and cap tool calls, or the loop detector aborts them.

Learned rules (swarm-v3 curator, from signed receipts, approved 2026-10-13; source `/home/worker/.swarm-v3/lessons/lessons-20261013-095243-4d8de6.md`):
- Unless the brief asks for test changes, tell workers: "do not edit existing test files; if a test looks wrong, leave it and say why in the commit message." (32 TEST_EDITED failures.)
- When the gate runs with allowed commands (e.g. stdlib `python3 -m unittest`), tell workers to run it before committing; otherwise keep "you cannot run tests; edit then commit". (About 150 TEST_FAILED with committed=1.)

Keep briefs narrow. Ground claims in the actual repo. Never read whole credential-bearing files; inspect only the specific field needed and never emit secret values.

## Verification
Worker success is not proof. Require numeric exit codes for checks. For merged code or security/data/money/irreversible changes, launch a separate dispatch claude read-only verification job against the produced branch/change. Give that verifier an explicit mechanical remote_test_cmd; verification must not rely on prose alone and must not share the writer's mutable worktree. Returned worker tests are accepted as secondary evidence when each item contains a numeric exit code. Skip the extra verifier for read-only recon/measurement.

## Failure handling
A worker may make at most two bounded repairs. `BLOCKED` means revise the brief or dependency; `ASSUMPTION_INVALID` means revisit the premise. Never hand-fix worker output in L1.

## Return contract
The final worker envelope uses:
`STATUS, RUN_ID, BASE, HEAD, CHANGED, ANSWER, CHECKS, REPAIRS, FAILURE, DECISION NEEDED, ARTIFACTS`.
Keep ANSWER concise; keep raw logs/artifacts on disk and surface only targeted evidence.
**L1 receipt (<=150 tokens):** after each lane, read only `id,status,head,changed,checks,blocker` (TOON, one line each). Never stream worker progress or paste logs into the conversation; read `remote-worker logs <id>` only on FAILED/BLOCKED, tail-capped. Wake on failed gate, conflict, decision or final receipt only.

## Token discipline
Use Grep/symbol lookup before large Read. Bound file ranges. Filter logs. Avoid rereading unchanged files.

Dagu lanes (owner-requested route): see `references/dagu.md`.
