# Autonomous decision loop

## What changes

The `autonomy` skill makes the L1 orchestrator **choose and follow through** on routine engineering decisions, while retaining the project's existing L1 planner / L3 worker division. It does **not** add a new agent runtime, replace workers, disable approvals, run continually in the cloud, or make unverified work safe.

It is opt-in, preserves the existing deny rules and policy hook, and reports `PASS`, `PARTIAL`, `BLOCKED` or `FAIL` based on evidence.

## Use it in Claude Code

1. Copy `skills/autonomy/SKILL.md` to `~/.claude/skills/autonomy/SKILL.md`, or put it under a specific project's `.claude/skills/autonomy/SKILL.md`. Keep existing settings, hooks, memory and routing intact.
2. Open a **new** Claude Code session; check the permission mode with Shift+Tab. This repo's example already has `permissions.defaultMode: auto`; do not turn off its PreToolUse policy hook.
3. Invoke `/autonomy` explicitly for a project goal, or add the minimal routing line from this repository's `CLAUDE.md` to your existing global rules for automatic use.
4. Ask for one objectively testable, low-risk coding task: e.g. "Find and fix the failing unit test in an isolated branch; verify the fix." Confirm the orchestrator selects its own safe next action, dispatches, waits for a real result, and presents exit-code/test evidence. Never test with live trades, deploys or destructive changes.

Example:
```text
/autonomy Fix the highest-priority reproducible TypeScript test failure in this repository.
Use an isolated branch, keep existing assertions, dispatch the edit to L3,
run the relevant tests, repair at most twice, and report a VERIFIED result
or the exact BLOCKED reason. Do not merge or deploy.
```

## Unattended GitHub operation

For **scheduled / webhook-based work**, use Claude Code Routines if your account offers it, or `anthropics/claude-code-action@v1` from GitHub Actions with a configured secret and a narrowly scoped repository token. Each run should select one authorized, reproducible issue, use a task branch, implement and test, then open a **draft PR** with evidence. Never automatically merge to main or deploy. Require standard GitHub branch protection and CI tests.

GitHub Actions needs an authenticated Claude credential and appropriate repository permissions; merely adding this skill or a workflow is not a functioning automation. Do not enable it until the runner, approval boundaries, secret handling, cost ceiling and failure behavior have been inspected.

For **bounded iterative retries inside one interactive session**, the official Anthropic Ralph Loop plugin is an optional complement. Use a finite `--max-iterations` and mechanically checkable completion criteria; do not pair it with another Stop hook that also forces continuation, and do not use it for vague goals or production debugging.

## Acceptance checklist

- Existing security/permission policy and L1/L3 routing are unchanged.
- The agent chooses routine reversible actions instead of requesting menu choices.
- No implementation worker edits main/master or collides with another writer.
- An actual diff and numeric exit codes support tests and final status.
- Consequential changes receive an independent read-only verifier where available.
- Repeated same-error attempts stop; capacity/quota/permission blocks surface clearly.
- No claim of unattended runtime, deployment or verification without direct evidence.

See `skills/autonomy/SKILL.md` for the normative decision and stop rules.
