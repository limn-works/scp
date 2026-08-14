---
name: outlet-pr3-collapse-final-2f45eefa6
description: Security review of collapsed outlet re-port landing on main (feat/outlet-report-pr3 @2f45eefa6) — auth boundary SOUND, zero findings
metadata:
  type: project
---

# Outlet PR-3 COLLAPSED re-port — final auth-boundary review (2f45eefa6) — 2026-07-10 — ZERO FINDINGS

The branch was REBASED/COLLAPSED: prior per-commit hashes in my other outlet-pr3 memory
notes (1ffe476e5, 7512e2159, b4e97ff50, f6fd5705a, 4af0af916) are GONE from history. Log now
a1b3649a6..2f45eefa6. So I verified the FINAL STATE embodies all prior series fixes — it does.

**Why review target = final state not commits:** collapse squashed history; must grep final files.

## Verified SOUND (5 focus items + enforcement):
1. `Capability::new`→Option (context/roles.rs:220): hard-break legacy stems (`outlet:invoke:`,
   `outlet_invoke:`, `tool:invoke:`, `tool_invoke:`, `tool:register/interface`) return None BEFORE
   any prefix split/Custom fallback (L225-236). Outlet AUTHORITY only via 4 exact prefixes
   `outlet:call:`/`outlet_call:`/`outlet:query:`/`outlet_query:` → real enum variants. A legacy
   string dodging the reject (casing, missing colon) becomes INERT `Custom(..)` with NO outlet
   authority. FFI helpers (py_check_scoped_capability ctx.rs:1861, napi check_scoped_capability_inner
   context.rs:5045, uniffi sandbox_check_capability bridge.rs:8132) ALL route through
   `CapabilityCeiling::contains` — malformed required→deny, malformed granted→filter_map-dropped
   (fail-closed both directions).
2. Ceiling `contains` (roles.rs:719): DISJOINT — OutletQuery(id) only satisfied by OutletQuery(id)
   or OutletQueryAll; OutletCall(id) only by OutletCall(id)/OutletCallAll. NO cross-family. Read
   grant can NEVER satisfy a call requirement or vice-versa → no read→mutate escalation (item 3).
3. origin_kind unforgeable: mint infer_origin_kind_from_capabilities (mint.rs:124) mixed
   call+query→HARD ERROR, malformed URI→error, single-family→that kind. Validator INDEPENDENTLY
   re-derives via classify_outlet_stem_family + verify_origin_kind_matches_stem_family
   (validate.rs:1870) rejects declared≠inferred; verify_leaf_outlet_stem_consistency (1920) closes
   forged-depth-1 hole. Query/Call cannot be confused across mint→validate.
4. caveat_resolver classification CORRECT (the item-4 trap): ONLY 3 prod sites —
   broadcast.rs:231 subscribe=`NoCaveatResolver` (correct: subscribe validates non-outlet
   `messages:read`, caveats immaterial); outlets/invoke.rs:1860 + saga.rs:1226 (cross-ctx
   outlet-invoke)=TokenNb-derived. NoCaveat returns None-everywhere (docs L448); fail-open on
   caveats is immaterial for a non-outlet check. No subscribe-gets-outlet-resolver / vice-versa bug.
   Ban×outlet: invoke.rs:449 direct path `has_outlet_call_capability(role_state,...)` denies
   banned (removed from role_state) + require Active; UCAN path validate_ucan uses same
   revocation_checker wiring — rename didn't touch revocation semantics, no regression. (Pre-existing
   ban-UCAN-replay class is main's, not introduced here — see gated-broadcast-subscribe-38ba6a0f7.)
5. No secret/log exposure: added `.sign(&preimage)` are legit signature computations + test
   fixtures; no println!/eprintln!/dbg! of keys/tokens. mint.rs:134 logs capability URI (public).

## Enforcement — NOT weakened:
- check-error-codes.sh +13: `SCP-CODE-OK:` inline marker is LINE-SCOPED (whole-file explicitly
  unsupported), Phase-1-ONLY (marker at L108; Phase 2 collision L142 + Phase 3 registry-uniqueness
  L294 do NOT honor it → mis-registered codes still caught). Bounded, un-abusable.
- ffi-export-allowlist.json, bridge-aliases.json, check-sdk-coverage.py (+46/-45), pipeline_wiring.rs
  (2 asserts changed = COMMENT-only rename), check-handler-no-panic.sh: ALL pure tool→outlet rename,
  zero coverage reduction.

## Integration commit 2f45eefa6 (the collapse delta): 3 files, benign —
broadcast test val-ctxs + handle_subscribe_broadcast get NoCaveatResolver (correct), broadcast.rs
test header gets `nb: None`, persistence_ordering.rs suspension_ceiling uses `.expect("known
capability")` on Capability::new Option. All correct.
