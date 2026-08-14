---
name: outlet-streaming-pyo3-reference-bridge-eb75ce608
description: C7 PyO3 outlet-streaming FFI reference bridge (SCP-OUT-037) API review — canonical shape mirrored by C8/C9 (NAPI/UniFFI/WASM) + C11 4 SDKs; grant-credit custody asymmetry + terminate code-redundancy findings
metadata:
  type: project
---

Review of `crates/scp-ffi/src/outlet_stream.rs` @ eb75ce608 (branch feat/outlet-streaming-ffi, worktree scp-wt-ffi). This is the CANONICAL bridge shape mirrored ×3 native bridges + wrapped ×4 SDKs; findings propagate widely.

**Verdict: NEEDS REVISION.** Surface: `outlet_invoke_stream(context_id,outlet_id,input,caller_did,ucan_token,proof_tokens?,spending_ucan?,timeout_ms?,estimated_chunk_count?)->StreamHandleId(hex String)` + `outlet_stream_poll_next(handle_id)->Option<Vec<u8>>` (None==terminal, evicts) + `_grant_credit(handle_id,caller_did,grant:&[u8])` + `_cancel(handle_id,caller_did)` + `_terminate(handle_id,caller_did,slug,code,message)` + 2 pure wrappers.

Findings ranked:
- **MAJOR (cross-binding divergence + unauthorable): grant_credit asymmetry.** `grant:&[u8]` = pre-signed JSON `OutletStreamCredit` (Ed25519 sig over §5.4.5 preimage via `sign_credit_grant` + monotonic_seq the caller must track). NO mint/sign primitive exported anywhere in scp-ffi (grep confirmed). Contrast `cancel`: bridge signs internally via custody (`apply_outlet_cancel_signed`, key never leaves ADR-006 custody, CRITICAL #3 runtime cursor). Grant demands caller already hold a signed struct ⇒ either expose invoker privkey OUTSIDE custody (breaks ADR-006) or reimplement preimage+Ed25519+monotonic tracking in every SDK layer ×4. Unsatisfiable from the signature. FIX: add a bridge mint verb (grant:u32 → custody-sign + auto monotonic_seq internally), mirroring cancel.
- **MAJOR: terminate `code` param redundant with `slug`.** Both derive from closed `TerminateReason` enum (stream.rs:927; `slug()`/`code()` const fns; `from_slug`->Option rejects unknowns). Bridge validates `code==reason.code()` and rejects mismatch — zero safety, pure footgun; model must know exact SCP-OUTLET-NNNN per slug. Both free `&str`. FIX: drop `code`, derive internally (runtime already does). Propagates ×8.
- **MODERATE: poll_next conflates unknown/stale handle with terminal.** Lines 592-596 return Ok(None) for unknown handle_id — same sentinel as real terminal — no diagnostic. Inconsistent with control-plane (`authorized_control` errors "no active outlet stream"). Mistyped handle looks like instant clean EOF.
- **MODERATE: method-grouping/autocomplete.** Open is `outlet_invoke_stream` but its control family is `outlet_stream_*` (poll_next/grant_credit/cancel/terminate). Typing `outlet_stream_` misses the opener. Consider `outlet_stream_open`/`_invoke` to group the canonical family.
- **MODERATE: caller-principal param name drift.** New canonical picks `caller_did`; unary `outlet_invoke` uses `identity_did`, `outlet_invoke_cross_context` uses `invoker_did`, saga uses `caller_did`. Canonical chance to standardize (propagates ×8). Recurring vocab-drift axis in this codebase.
- **OBS: slug stringly-typed** — acceptable (closed-set validated via from_slug), but UniFFI/Swift/Kotlin bindings should surface a real `TerminateReason` enum (UniFFI supports enums) while keeping wire slug canonical — plan for per-binding type divergence.
- **OBS: poll_next has NO caller_did** (data-plane = bearer-token on unguessable 128-bit hex handle, per-instance) vs control-plane identity-pinned (CRITICAL #1). Intentional asymmetry; document.

SOUND for mirroring (don't re-flag): String hex handle translates cleanly ×4; open→poll_next→control shape wraps into async-iterator/AsyncSequence/Flow/Promise fine; sync block_on poll_next is right PyO3 idiom (others go async — not a divergence); single-verb SDK goal `ctx.outlets.invoke()->awaitable+iterable handle` achievable EXCEPT `handle.grant(n)` blocked by the missing mint primitive; caller_did-per-control-call is fine for single-verb (SDK stores it at open); open returns promptly (Commit, not block-till-terminal) — correct.
