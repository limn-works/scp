# Event-log unification Phase 1 (feat/eventlog-unification-phase1, HEAD 658e1392)

EventType 36→76. payload.rs positional rmp_serde per-variant encoder. tags 36-75. is_structural_event exhaustive. §25.8 KAT Vectors 32/33. test-helper dedup (runtime integration tests now call tree::event_type_tag / tree::compute_event_canonical_hash, promoted pub(crate)→pub).

## Verified CLEAN
- Tags 0-75 all distinct, 0-35 unchanged (pinned by tree.rs tests). EconomicPolicyApplied=33 historical gap-fill preserved.
- is_structural_event exhaustive (no `_`); compiler enforces 76-way partition.
- KAT not tautological: spec hex == test expected_leaves byte-identical; checkpoint sig independently verified via production compute_checkpoint_canonical_hash. generate_checkpoint `5` arg = MLS epoch (count=7 derived internally).
- No destination_context_id dangling refs; rename to destination_id complete.
- Vector numbers unique; 32/33 avoid §25.9 collision. Doc order non-monotonic (cosmetic only).
- All tests pass: scp-event-log (197+10), phase2/phase5/economy, wasm_conformance event-tag. clippy clean.
- WASM bridge uses shared scp_event_log::EventType + append_unsigned_event → event_type_tag, so native↔WASM tag parity is automatic. WASM emits NONE of the 40 new variants in Phase 1 (types-only scope, correct).

## ONE finding (LOW): stale wasm_event_type_tag mirror in wasm_conformance.rs
- wasm_conformance.rs:1461 `wasm_event_type_tag` hardcoded string→tag mirror covers only 36 base variants; not updated for 40 new. Test passes because all_variants arrays also list only 36.
- NOT a production defect (WASM no longer uses string tags). But parity gate now silently incomplete; won't catch a future mis-tagged WASM variant.
- Pattern: parity/enforcement test not expanded alongside the enum it guards.
