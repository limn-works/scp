---
name: pr105-pr6a-delete-dead-xctx-command
description: Review of PR-6a (#105 FFI-export track) deleting dead InitiateCrossContextToolInvocation mailbox command. APPROVED @621933fe7 (1 minor doc nit) and re-APPROVED CLEAN @301a1ac07 (nit fixed).
metadata:
  type: project
---

PR-6a of #105 FFI-export track. Branch chore/105-pr6a-delete-dead-xctx-command. Deletes `ToolsCommand::InitiateCrossContextToolInvocation` (4 NotImplemented-only sites, 0 non-test callers) + orphaned `reply_saga_deferred` helper; converts `tools_command_context_id` `_ => None` → explicit `ToolsCommand::Placeholder { .. } => None` (clippy match_wildcard_for_single_variants); re-exports `SagaSigningKeys` + `CrossContextToolInvocationRequest`; scrubs phantom "SAGA WIRING DEFERRED" prose from ADR-049 line 65 + DEFERRED-commit-11 ADR (incl. new Gap-2 RESOLVED banner).

**Verdict history:**
- @621933fe7 (parent f0cbad57e #1906): APPROVED with 1 MINOR — DEFERRED:214 still named nonexistent `reply_saga_deferred` placeholder in standing.rs (actual = `reply_not_implemented` via StandingCommand::Placeholder).
- @301a1ac07 (round E, parent f0cbad57e): **APPROVED CLEAN.** Prior nit FIXED — DEFERRED:214 now reads `reply_not_implemented` + explicit "No `tools` handler placeholder". Zero findings.
- @301a1ac07 (round E re-run, base origin/main=f0cbad57e): **RE-APPROVED CLEAN.** Re-verified every load-bearing claim against actual checkout (not frozen memory): grep confirms 0 lingering InitiateCrossContextToolInvocation/reply_saga_deferred refs except the 2 intentional RESOLVED-banner/prose mentions; CrossContextToolInvocationRequest@850 + SagaSigningKeys<'a>@889 (two `&'a SigningKey`) = exactly the 2 public inputs of start_cross_context_tool_invocation_saga@5309; saga executor `Send + 'static`@5316 (so off-mailbox SOLELY by borrowed keys — doc correct); invoke_tool_with_economy executor NO Send bound@9698 (distinct reason — doc correct); tools_command_context_id@10602 explicit 5-arm match (Placeholder=>None); clippy -p scp-runtime --all-targets --features testing CLEAN. standing.rs:40 = reply_not_implemented (DEFERRED:212 matches). Zero findings.

**Why deletion correct (ADR-049 §3):** §6.2.4 saga is produced supervisor-side `Supervisor::start_cross_context_tool_invocation_saga` (supervisor.rs:5309) → run_saga_fsm. Mailbox variant could never carry it: `SagaSigningKeys<'a>` (supervisor.rs:889) holds two `&'a ed25519_dalek::SigningKey` (borrowed, non-'static) → can't move into 'static mailbox msg.

**Verified signatures (load-bearing for doc-precision claims):**
- start_cross...saga takes EXACTLY `request: CrossContextToolInvocationRequest` + `signing_keys: SagaSigningKeys<'_>` → both re-exports are precisely its 2 public input types, necessary for future FFI caller. Both already pub — re-export only, no surface widening.
- saga executor `F: FnOnce -> Fut + Send + 'static` (supervisor.rs:5316) → kept off mailbox SOLELY by borrowed keys.
- invoke_tool_with_economy executor `F: FnOnce -> Fut` NO Send bound (supervisor.rs:9697) → distinct off-mailbox reason. Doc now states each correctly (old prose conflated them).

**ADR topology coherence (all code-grounded):** Gap-2 banner "drives co-resident target actors in-process" + cross-node wire transport = real remaining work, corroborated supervisor.rs:5190/5224/5246/5295/5306 ("co-resident participant context-actors", "co-resident core path does not yet have an untrusted leg"). FFI export deferred per §3a per-set gating — genuine. ADR-049 line 65 revised text correctly relocates producer supervisor-side, missing piece = FFI export.

**Explicit-arm conversion strictly better:** future variant addition now forces compile error at tools_command_context_id (supervisor.rs:10601) instead of silent `None`. 5 ToolsCommand variants total (Placeholder + TryConsume/Refund HardRateLimit + Reserve/Settle ToolEconomy). clippy -p scp-runtime --all-targets CLEAN @301a1ac07.
