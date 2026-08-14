---
name: scp-out-031-pr2a-runtime-surface
description: SCP-OUT-031 PR-2a per-variant OutletErrorSurface mapping audit @dccc50c1b — zero findings, COMPLETE (PR-2a scope)
metadata:
  type: project
---

# SCP-OUT-031 PR-2a — runtime→ContextError structured OutletErrorSurface

Audited commit dccc50c1b on branch feat/outlet-031-pr2a-runtime-surface. Verdict: **zero
findings — COMPLETE (PR-2a scope)**.

**What PR-2a does:** replaces `ContextError::PermissionDenied(String)` flattening of outlet
invocation errors with `ContextError::Outlet(Box<OutletErrorSurface>)` (scp-protocol new
variant + struct). Single-sourced `to_surface` producers on `InvocationError` (scp-runtime
invoke.rs:3214), legacy registration `OutletError` (scp-protocol mod.rs:470), and
`SchemaValidationError` (schema.rs:80). Bridges (pyo3/napi/uniffi) get minimal `CE::Outlet`
arms preserving code+slug with `// PR-2b` markers.

**Completeness proof — no `_` wildcard in ANY of the 3 to_surface matches** ⇒ Rust
compiler enforces per-variant exhaustiveness. All 15 InvocationError variants mapped; the
30+ legacy OutletError variants all mapped one-arm-per-variant.

**Registry consistency (the core invariant):** every produced surface satisfies
`error_code_to_class(code)==Some(class)` AND `slug_to_class(slug)==Some(class)`. Tested
exhaustively per-variant (invoke.rs `invocation_error_to_surface_is_consistent_per_variant`
iterates all 15 + both CaveatViolation branches; protocol `assert_surface_consistent` also
checks retry==code default). All slugs used confirmed in ALL_SLUGS + slug_to_class.

**Anti-fabrication (the PR-1 lesson — faked Protocol `rule`):** NO DetailBody::Protocol/
Authorization/Governance/EconomicInsufficient fabricated anywhere. Only real details:
Timeout→ExecutionTimeout{elapsed_ms}, HandlerPanic→ExecutionPanic{full 32-byte SHA-256 of
panic_message}, schema→FieldViolation, InterfaceRateLimited→TransportRateLimit. Key win:
BudgetExceeded→detail=None because no ISO-4217 currency exists at the seam (refuses to
fabricate). Oracle-collapse (InvokerNotAuthorized/OutletNotFound)→None.

**Two DOCUMENTED normalizations vs invocation_error_to_terminal_payload (honest, not
phantom):** the terminal wire path emits UNREGISTERED slugs for two variants
(ContextNotActive→"protocol.context-not-active"/6100; Cancelled→"execution.cancelled"/6130);
to_surface normalizes to the registered same-class equivalents
(protocol.context-closed-mid-stream/6101; execution.cancel-ack-timeout/6135). Doc says
"normalized to registered slugs" — accurate. to_surface is MORE consistent than the wire
path (which is PR-2c scope).

**Reserve reverse-map switch verified end-to-end:** reserve_error_to_open_rejection changed
from `PermissionDenied(msg).contains(SLUG)` to `Outlet(surface).slug==SLUG`. Traced producer:
OpenStreamRejection::{EscrowOverflow,InsufficientFunds}.to_invocation_error() →
CaveatViolation{slug: dispatch.rs slug()=SLUG_ECONOMIC_*} → to_surface via from_class →
Economic/6150/slug-preserved. Both ends use the SAME error_codes constant ⇒ cannot drift.
NOTE: escrow/insufficient reverse-map arm not DIRECTLY unit-tested (only via ContextError
Display-string assertions in overflow/insufficient reserve tests); correct by
shared-constant construction. The 6089 membership path HAS a dedicated reverse-map test.

**ensure_context_active** deliberately keeps raw SCP-OUTLET-6080 PermissionDenied
(internal-only, immediately reverse-mapped to OpenStreamRejection::ContextNotActive,
never FFI-facing) to preserve current_state — correct, documented, 3 tests still assert it.

**counter_exhausted_to_context** now emits registered slugs: AmountCumulative→
authorization.cumulative-exceeded, RateWindow→authorization.rate-exceeded, MaxCalls→
authorization.denied (no dedicated slug). NOTE: surface has NO message field, so the
camelCase kind name (maxCalls etc.) in CaveatViolation.message is DROPPED — Display is
`[code] class: slug`. The 6 updated caveat tests correctly switched assertions from
camelCase kind to registered slug (stronger/equivalent, not weakened).

**Non-blocking observations (NOT findings):** (1) from_code stores detail without
validating it matches class (wire OutletError validates; surface doesn't claim to) — all
current callers pass correct-class detail. (2) CrossContextPaidActionUnsupported shares
economic.budget-exceeded (semantic overload, documented; no dedicated §5.4.4 slug exists —
a candidate spec follow-up to mint one, respecting one-way flow). (3) escrow/insufficient
reverse-map arm lacks a direct unit test.

**Tests run green:** scp-protocol outlets::errors (49), schema surface test, runtime
invoke to_surface (all 15 variants), invocation_error_to_context_yields_typed_outlet,
outlets_helpers::tests (43). All 3 FFI bridges cargo check clean (lone warning =
pre-existing unrelated scp_clock::Clock unused import). auditNote honestly records PR-2a
scope + PR-2b/2c remaining; status stays pending.

Lesson: when a mapping "mirrors" a sibling function, diff the two side-by-side — the honest
divergences (registered-slug normalization) are the interesting part, and confirm they don't
create phantom provenance.

## Round-2 (@7eaebb81c) — re-verified, still COMPLETE (PR-2a scope), zero new gaps

Round-2 (10-reviewer) addressed a REAL SECURITY LEAK that round-1 had rationalized away:
round-1 claimed `ensure_context_active` was "internal-only, never FFI-facing" — FALSE for the
UNARY invoke path (reserve_outlet_economy → ? → invoke_outlet_with_economy propagates the
ContextError verbatim to FFI). The old raw `SCP-OUTLET-6080: context not active: {state}`
PermissionDenied leaked the exact lifecycle state (Closing/Expired/MigratingOut) to an
UNAUTHORIZED caller BEFORE authz. LESSON: don't take a code comment's "internal-only / never
FFI-facing" claim at face value — trace the actual propagation path to the FFI boundary.

Round-2 fix: new `ContextError::OutletContextNotActive { current_state: ContextState }` typed
carrier. Display is state-free `[SCP-OUTLET-6101] protocol: protocol.context-closed-mid-stream`
(via #[error] attr — never renders current_state). Handled at EVERY ContextError site:
3 FFI From impls (explicit arm→CODE_PROTOCOL_SESSION, each with a state-free parity test),
reserve_error_to_open_rejection (typed arm, reads current_state typed — no more string rsplit),
SagaReject From (pass-through wrap), Display. No wasm From<ContextError> exists. SCP_OUTLET_6080
marker const DELETED (no dead code). Security posture: unary pre-authz=state-free; streaming/
saga post-authz=state preserved for an already-authorized interface peer (documented in
dispatch.rs, consistent reverse-map↔to_invocation_error).

Other round-2 items all verified real: ExecutionPanic now hashes outlet_id not panic_message
(genuine field extraction, oracle-resistance; DetailBody doc reconciled to permit the outlet-id
proxy; test proves hash==SHA256(outlet_id) AND !=SHA256(message)). ucan_cid/caveat_kind now
tracing::debug!-logged in counter_exhausted_to_context + check_invocation_error_to_context (not
silently lost). New drift-guard test pins to_surface==terminal_payload except the 3 documented
normalizations. from_code gained a debug_assert! catching registered-wrong-class preferred_slug
(round-1 fall-back test converted to #[should_panic]). reserve_error_reverse_map_arms now
directly tests all 5 reverse-map arms (closed my round-1 obs#3). auditNote records PR-2b CHECKS
(from_envelope only test-exercised→wire it; OutletNotFound non-member existence-probe) + the
CrossContextPaidActionUnsupported dedicated-slug spec-follow-up (my round-1 obs#2); status pending.

Tests all green: scp-protocol lib 403, runtime drift-guard/reverse-map/gated/should_panic,
3 FFI state-free (features: scp-ffi{,-napi,-uniffi}/testing,scp-core/testing — NOT the deleted
allow_in_memory_custody). validate-prd: 18 files/443 stories pass.

NON-BLOCKING NIT (not a gap): the auditNote running-log still contains the stale round-1
sentence "ensure_context_active deliberately keeps its internal-only raw SCP-OUTLET-6080
PermissionDenied (never FFI-facing...)" — now contradicted by both the code and the round-2
paragraph in the same field. Reword on next auditNote revision; code is correct.
