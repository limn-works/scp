---
name: outlet-pr3-capability-migration
description: PR-3 ToolInvoke→OutletCall/OutletQuery migration — which flagged simplifications are real vs non-findings; CaveatResolver is justified NOT over-engineered.
metadata:
  type: project
---

Review of `feat/outlet-report-pr3` (range a65a778c9..b4e97ff50): capability `ToolInvoke`→`OutletCall`/`OutletQuery` split + §7.3.8 InvocationCaveats + CaveatResolver + UCAN origin_kind enforcement.

**Why:** Task hypothesized 5 simplification targets; most did not hold. Recording which so a future pass doesn't re-litigate.

**How to apply:** When reviewing this migration or its follow-ups:

- **REAL WIN — RESOLVED at tip 1ffe476e5.** Runtime `has_outlet_invoke_capability` was renamed to `has_outlet_call_capability` (invoke.rs:1116) and is now a thin delegating wrapper to `scp_protocol::context::outlets::has_outlet_call_capability` (mod.rs:597) — no duplicated body. All old-name refs gone. Also the 3 FFI `check_scoped_capability` helpers (scp-ffi src/context.rs, napi context.rs, uniffi bridge.rs) now route through `CapabilityCeiling::contains` (roles.rs:722), removing 3 copies of hand-rolled match AND fixing a pre-existing asymmetry: old FFI code honored `OutletCallAll ⊇ OutletCall(id)` but NOT the symmetric `OutletQueryAll ⊇ OutletQuery(id)`. `contains` is the same canonical check UCAN validation uses, so this is correct dedup, not obscuring indirection.
- **NOT over-engineered — CaveatResolver trait** (validate.rs:439): 3 genuine impls (No=None, TokenNb=signed nb read, InMemory=out-of-band map), held as &dyn in ValidationContext. TokenNb wired at all 4 bridges. No-vs-TokenNb per-call-site split is semantic classification (invocation paths enforce, generic ucan.rs validate = No), applied identically across bridges — a shared helper MUST NOT own the choice (trait doc says so). Do NOT flag as BLOCKER.
- **NOT boilerplate — `Capability::new -> Option` + filter_map/map:** mint.rs:260 is fail-closed `.map().collect::<Result>()` (SCP-OUT-014 differential guard) — collapsing would hide fail-closed intent; a filter_map there would be a security bug. Bridge filter_map(Capability::new) sites drop only grants/ceilings (both NARROW authority), required is explicitly fail-closed. Safe as-is.

**Collapsed re-port tip 2f45eefa6 (double-zero pass) — additional confirmations:**
- **narrow() (caveats.rs:669) is GENUINELY LIVE, not deferred.** Wired at mint (mint.rs:246,255) and every delegation edge (validate.rs:1751,1767,1773). Enforces origin_kind equality + scalar caveat attenuation (amount/calls/time/rate/adapter/did subsets). This is core delegation-chain security — do NOT confuse with the deferred VALUE-caveat *runtime* check ([[check_invocation_local]]).
- **json_schema_narrows (caveats.rs:1200) = CONVERGENT BY CONSTRUCTION, NOT a non-convergent denylist.** Uses a CLOSED whitelist `JSON_SCHEMA_NARROWING_WHITELIST` (9 keywords); any child keyword outside it → `AttenuationViolation::UnknownSchemaKeyword` (fail-closed). `pattern` refuses undecidable regex-subsumption, uses conservative byte-equality. Exactly the positive-whitelist pattern CLAUDE.md's guard asks for. The whole schema surface is dormant-in-prod (mint emits no input_schema) but is the sound attenuation half of deferred §7.3.8, property-tested (narrow_is_transitive). NOT over-engineering, NOT a BLOCKER.
- **narrow()'s `assert_mask_widths` re-assertion is justified defense-in-depth, not redundant type re-check.** Guards against serde/MessagePack-decoded values that bypass the newtype constructor (real Rust concern). Considered-and-kept.
- **SCP-CODE-OK marker (check-error-codes.sh) = legitimate bounded positive-exemption.** 44 uses = registry constants (SCP-TOOL-61xx) + validator self-ref (`b"SCP-TOOL-61"`) + labeled negative-test fixtures. Whole-file exemption deliberately unsupported (forces per-line intent). Cannot smuggle a real mis-ranged code. NOT a BLOCKER.
- check-sdk-coverage.py change = pure alias-table rename (Tools→outlet-prefixed), no new logic. Rebase-integration commit 2f45eefa6 = 3 files/13 lines, mechanical.
- **OutletCall vs OutletQuery split carries weight**: genuine write-vs-read least-privilege authority distinction on outlets, enforced via CapabilityCeiling::contains (All ⊇ id for each). Not over-modeled.

**Pre-existing, out-of-scope (observations, not this-PR findings):**
- PaidActionType string parser copy-pasted 3× (scp-ffi economy.rs / napi economy.rs / uniffi bridge.rs). No FromStr on the enum. Canonical fix = FromStr in scp-protocol economy/types.rs.
- `accept_tool_interface_with_kind` (interface.rs:1615) has ZERO production callers — all 3 bridges call kind-blind `accept_tool_interface` (uniffi bridge.rs:13768, napi outlets.rs:1367, scp-ffi outlets.rs:1626). Kind-aware path only in unit tests. Pre-existing dead branch. Confirmed unchanged at 1ffe476e5.
- `check_invocation_local` (caveats.rs:811) — fully-implemented value-caveat check (input_schema/amount_max_per_call/allowed_adapters/allowed_target_dids), 8 unit tests, but ZERO production callers. Pre-existing (introduced 18022ad65, before review baseline 7512e2159). At tip the §7.3.8 spec + doc-comment were UPDATED to honestly label it deferred/not-yet-wired. NOT dead-code-to-delete: mint (mint.rs:160-162) materializes ONLY origin_kind, never value-caveats, so no in-circulation token asserts a value-caveat → the unwired fn cannot under-enforce anything. "No live divergence" claim is factually correct. Spec-leads-code is a CLAUDE.md-sanctioned pattern here. NOT a BLOCKER.
- OutletInterface dual rate-limit (inbound_policy = declared vs inbound_rate_limit = lazy window state) — both live, different purposes, NOT dead.
