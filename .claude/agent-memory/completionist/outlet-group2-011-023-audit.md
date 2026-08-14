---
name: outlet-group2-011-023-audit
description: Whole-outlet audit Group 2 (OutletKind SCP-OUT-011..017 + InvocationCaveats 018..023) @ origin/main d5de8b153 — authorization + economy semantics
metadata:
  type: project
---

# Outlet Group 2 audit (SCP-OUT-011..023) @ d5de8b153 (origin/main, wt /Users/alec/Developer/limn/scp-wt-audit)

All 13 stories marked status:done. Core protocol enforcement is SOLID; several stories are STALE (pre ADR-049/057 restructure) and one has a LIVE spec divergence + two are false-done SDK gaps.

**Why:** verifying authorization+economy semantics fire (amplification, ReadOnly, attenuation unbypassable, counter accounting).
**How to apply:** on future outlet work, 015's per-kind chain-depth is the concrete unfixed gap; 017/023 SDK surfaces are false-done.

## COMPLETE + correct (verified in code)
- 011 OutletKind enum + kind_byte(0x00/0x01) canonical_byte + preimage — in registry.rs (story said mod.rs). Tests present.
- 012 QueryCostViolation cost-floor: OutletRegistration::validate() in registry.rs:290 (story said lifecycle.rs), wired into register path, tests registry.rs:1782.
- 013 ReadOnlyInvocation/MutableInvocation/OutletExecutor(exec_query/exec_action/stream) + QueryViolation + QueryMisdeclaration emission — invoke.rs:1829/1995/2345. Solid.
- 014 Capability::OutletQuery/QueryAll/Call/CallAll; OutletInvoke DELETED; parse_outlet_suffix enforces ^[a-z0-9_-]{1,128}$ (empty/>128/uppercase/inner-colon→None); hard-break outlet:invoke:/tool:invoke: →None. roles.rs:220-291. Cross-class attenuation rejected by verify_edge_attenuation (validate.rs:1661) capability-subset + origin_kind equality.
- 016 OutletInterfaceDefaults::for_kind Query→(600,100) Action→(60,10) — interface.rs:106. (BUT see divergence below.)
- 018 InvocationCaveats 12 fields + RateWindow + HoursOfDayMask/DaysOfWeekMask from_bits(high-bit reject) + try_new(≤8 non-origin_kind, 4KiB, depth8, ≤16) + try_new_for_root(mixed-stem/mismatch) + assert_mask_widths shared. caveats.rs. Complete w/ tests.
- 019 narrow() all field rules + conservative JSON-schema (21 narrow tests ≥18 req) + pattern lexical-equality + mask shared + origin_kind equality/OriginKindUnspecified + narrow_is_transitive proptest(3996). Complete.
- 021 post-input value-caveat LIVE: check_invocation_local called reserve_outlet_economy outlets_helpers.rs:768; caveat_binding derived from INVOCATION UCAN nb via TokenNbCaveatResolver (NOT spending ucan) at all 3 native bridges (ffi/outlets.rs:537, napi:433, uniffi bridge.rs:13480). (Supersedes prior memory "check_invocation_local 0 prod callers" — NOW WIRED.)
- 020 (functionally): Class-S CaveatCounters (caveat_counters.rs) try_consume monotonic saturating, rejection-before-mutate (non-gameable), sliding-window prune-then-check, rides ContextSnapshot.caveat_counters + stripped on export. Correct per CURRENT spec.

## FINDINGS

### GENUINE LIVE GAP — SCP-OUT-015 per-kind chain-depth NOT enforced
Spec §5.4.2 (lines 264/272, STILL current, no ADR rescope) REQUIRES Query=full max_chain_depth, Action=max(1,max_chain_depth/2) (default 4). Runtime validate_chain_depth (saga.rs:1617) uses SINGLE effective_max_chain_depth for ALL kinds. grep `max(1`/`/2` chain-depth across crates = EMPTY. No AmplificationViolation constructed anywhere in scp-runtime/scp-testing (defined only in scp-protocol stream.rs + error_codes). Amplification Query→Action IS enforced STRUCTURALLY (invoke selects kind-matched stem ffi/outlets.rs:344; cross-ctx saga hardcodes outlet_call:1356; outlet_query can't attenuate→outlet_call), so the amplification SEMANTIC holds cryptographically — but the per-kind DEPTH BUDGET is a real unmet spec req + story-015 integration tests (Action→Action depth5 ChainDepthExceeded budget=4; Query→Query→Action AmplificationViolation) absent.

### STALE STORIES (code matches CURRENT spec; story text/paths wrong; done-marking OK-ish)
- 020: story wants repo-backed CaveatCounterStore at caveat_counter_store.rs (DOESN'T EXIST) under context/{id}/caveat_counters/{ucan_cid} w/ CAS. Spec §7.3.8 line145 SUPERSEDES→Class-S ClassSState.caveat_counters (single-owner mailbox, no CAS, rides snapshot). Code = Class-S = current spec. Story stale.
- 022: story wants evaluate_all_layers(ctx,caveats,outlet,input) fn + per-layer-denial unit tests. Fn DOESN'T EXIST (grep empty). Composition realized ACROSS reserve_outlet_economy (caveat/spending/budget/rate) + saga (Inbound/Outbound). AND-semantics/no-skip-gap hold; story's named fn + specific tests absent. Spec §7.3.8 composition met.

### FALSE-DONE SDK GAPS (real, not stale)
- 017: registerQuery/registerAction convenience wrappers ABSENT in all 4 SDKs (grep repo-wide=0; explicit AC2-5 + action-item-4). AC7 negative test (Query outlet+outlet_call UCAN→AuthViolation) absent all 4 SDKs+bridge tests (enforcement real, test missing). AC8 no-kind test present Python only (TS/Swift/Kotlin missing). SOLID: OutletKind on 3 bridges (WASM excluded ADR-057 node-delegated, but PRD file list cites nonexistent crates/scp-ffi/wasm/src/outlets.rs), kind required on all 4 defn types, invoke auto-stem real.
- 023: entire SDK mint(caveats)/narrow surface ABSENT all 4 bridges + 4 SDKs (no InvocationCaveats SDK type, no caveats param on ucan_mint, no narrow, no 6114 mapping, no round-trip test). BUT spec §7.3.8 line143 DEFERS value-caveat mint ORIGINATION ("mint materializes only origin_kind"; mint.rs:160 "SCOPE(PR-3) materializes ONLY origin_kind"). So absence matches current spec deferral → NOT code-vs-spec divergence; story stale+false-done. PRD files list cites 3 nonexistent files (wasm/ucan.rs, ts/ucan.ts, kt/Ucan.kt).

### ARTIFACT DIVERGENCE — SCP-OUT-016 rate tiers phantom-provenance
Code OutletInterfaceDefaults::for_kind + doc comments cite §6.2.0.2 "classification-aware rate tiers" Query 600/100. Spec §6.2.0.2 has SINGLE 60/10 default table, NO kind split, no "600". §6.2.0.3/§6.2.0.4 (cited by stories 015/016) DON'T EXIST in specs. Amplification+chain-depth semantics live in §5.4.2 (not §6.2.0.3/4). Fix spec-first per one-way flow (add kind tier to §6.2.0.2 or remove code tiers).

### Deferred-in-code (honest): allowed_target_dids cross-context
reserve_outlet_economy passes None target_did (outlets_helpers.rs:772); comment "cross-context targets are a later slice" — same-context FAIL-CLOSES any token bearing allowed_target_dids. Spec §7.3.8 intends it for cross-context. Function supports target (unit test caveats.rs:4300); runtime cross-ctx threading deferred.

LESSON: stories 011-023 predate ADR-049 actor + ADR-057 outlet redesign; story `files` arrays + named symbols (manager/outlets.rs, evaluate_all_layers, caveat_counter_store.rs) are systematically stale — verify against CURRENT spec not story text. The one LIVE code gap is 015 per-kind chain-depth.
