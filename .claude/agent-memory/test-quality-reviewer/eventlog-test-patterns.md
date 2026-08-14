---
name: eventlog-test-patterns
description: scp-event-log test patterns from the native↔WASM unification (closed-taxonomy tag bijection, typed-leaf KAT, classification pin table, dedup-into-real-path)
metadata:
  type: project
---

# scp-event-log Test Patterns (native↔WASM unification, Phase 1)

Feature: ADR-011 Amendment (`.docs/adrs/phase-2.md`) expanded `EventType` from 36 → 76 closed variants (tags 0..=75). Phase 1 = types + tests only; production emit sites land later phases.

**Why:** before this, runtime call sites baked event params into the event NAME (`format!("ContextTombstoned:{dest}")` or whole-JSON-as-type-tag), making the signed Merkle leaf preimage non-convergent → native↔WASM root divergence → §9.9.3 equivocation false-positives.

**How to apply when reviewing event-log test changes:**

## Strong patterns worth replicating
- **Closed-taxonomy bijection pin** (`tree.rs all_event_type_tags_are_distinct` + `wasm_conformance.rs canonical_event_type_tag_is_a_closed_bijection`): assert tag fn is a bijection onto contiguous 0..=75 (distinct + first==0 + last==75 + len==76). Catches collisions AND gaps that corrupt the `SCP-EVENT-V1:` signature preimage.
- **Protocol-constant freeze** (`protocol_constant_tags_0_through_35_are_unchanged`): pins each historical tag (incl. deliberate out-of-order `EconomicPolicyApplied=33`) so wire compat can't silently break.
- **Full classification pin TABLE** (`pruning.rs structural_events_classified_correctly`): `[(EventType, bool); 76]` of EXPECTED structural/operational — pins the correct decision per variant, not just "a decision exists". Far stronger than the old 14-line spot-check.
- **Exhaustive match guard**: `is_structural_event` uses `match` with NO `_` arm → adding a variant forces compile-time classification decision. Arms merged (not origin-grouped) to satisfy clippy::match_same_arms; rationale preserved in comments.
- **Typed-leaf KAT** (`test_vectors.rs vector_32/33`): fixed Ed25519 seed (RFC 8032 deterministic) → reproducible full-Event rmp_serde bytes → pinned leaf hashes + tree::root. Builds log via PRODUCTION `tree::append` (verifies sigs, builds tree). Uses `did:dht:z<zbase32(pubkey)>` which `extract_public_key_from_did` accepts WITHOUT `testing` feature — KAT runs in default test set.
- **Positional-MessagePack fixarray assertion** (`payload.rs assert_positional_array`): checks first byte marker `& 0xf0 == 0x90` and low-nibble == field count, proving NOT a field-name map. Pins the "never reorder fields" wire contract mechanically.
- **Checkpoint KAT honesty** (vector_33): canonical hash/sig are timestamp-dependent → NOT byte-pinned; instead asserts timestamp-independent invariant (`merkle_root == tree::root`, `event_count`) AND dynamically `vk.verify(canonical, sig)` to pin the §23.16.1 layout. Spec doc matches exactly.

## Dedup-into-real-path STRENGTHENS (verify this pattern)
- phase2/phase5_integration.rs: deleted test-local `compute_event_canonical_hash` copy → call real `tree::compute_event_canonical_hash` (the fn `verify_event_signature`→`append` actually uses). Integration tests now sign through the production preimage; a preimage change breaks them. STRICT improvement.
- economy_integration.rs: deleted hand-copied 36-arm tag `match` → call `tree::event_type_tag`. (Minor: still hand-rolls the SCP-EVENT-V1 preimage rather than calling compute_event_canonical_hash like phase2/5 — not a regression, just less consistent.)

## Stale-mirror removal that LOOKS like weakening but isn't
- Old `wasm_event_type_tag_exhaustiveness` cross-checked a hand-maintained string→u16 mirror table against native `event_type_tag`. VERIFIED: WASM bridge (`crates/scp-ffi/wasm/src/manager.rs`) imports `append_unsigned_event`, appends with `signature: vec![]` and a real `EventType` enum value, and NEVER calls `event_type_tag`. The mirror table tested fictional code. WASM event-type parity is carried by the SHARED SERDE VARIANT NAME (same scp_event_log crate) + byte-level §25 KAT, not the tag. Replacing it with the bijection pin (what the tag actually feeds: native sig preimage + retention) is correct.
- LEFT-IN stale mirrors (out of scope, Phase 5/6 cleanup): `wasm_registry_mirror` / `wasm_proposal_mirror` re-implement registry semantics instead of exercising real `WasmContextManager`; comments now honestly say so and flag the follow-up.

## Known test-run gotcha
- `cargo test -p scp-event-log --lib` (no features) = 116 pre-existing `did:key`-rejected failures. MUST use `--features testing` (197 pass). The KAT vectors test uses `did:dht:` so it passes either way.
