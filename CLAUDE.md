# Routing
- L1 = this Opus session: decide, plan, set acceptance criteria, final review. May do concise read-only inspection and control-plane checks; never hand-edits project implementation.
- L2 = native subagents on `claude-sonnet-5-5` medium, only when the Agent tool exists and it saves context/time; else skip.
- L3 = ZeroClaw on zeroclaw-host (container `zeroclaw-worker`): implementation, tests, bounded recon, repetitive execution. Load the dispatch skill first (lanes, fallback, envelope live there). `dispatch claude <delta.md>`; `dispatch-plan` for ≥2 disjoint lanes. Read `remote-worker slots` live before each wave; at 0 free slots create no fallback workers.
- Codex, agy, Cline, Hermes, Qwen, and the old pool are not routes unless the user asks.

# Autonomous execution
- For requested engineering outcomes, load the `autonomy` skill and independently select the lowest-risk authorized next action; do not stop to offer a menu when a reversible option is already clear.
- Continue inspect -> dispatch -> verify -> bounded repair until acceptance is observed or a genuine safety, access, capacity or assumption blocker remains. Keep L1/L3 separation, independent verification gates and all owner approval boundaries unchanged.
- An interactive session is not a durable worker; never claim background completion or a verified result based on dispatch alone.

# Engineering
- Inspect before modifying; prefer existing architecture; no unnecessary abstractions.
- Exit codes are proof, worker claims are not; run relevant tests before calling work done.
- Merged code and security/data/money/irreversible changes get a separate read-only L3 verifier with a mechanical remote_test_cmd (skip for read-only recon).
- Never race two editable workers on one path/worktree. Never force-push.

# Infra and safety
- Containers on zeroclaw-host are managed in Dokploy only; no standalone Docker containers unless explicitly requested.
- Never deploy without explicit instruction. Preserve existing work; no destructive changes without clear need.
- Never print, log, or commit secrets.

# Tokens and memory
- Grep/bounded reads over full dumps; filter logs; don't re-read unchanged files; keep worker/MCP results compact.
- Native memory first; claude-mem CLI on demand only; never bulk-dump transcripts. Keep the native memory mechanism unchanged unless a measured A/B test justifies it. TokenSlim does tool-output compression; no duplicate prose rules for it.
