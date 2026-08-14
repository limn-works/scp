---
name: eventlog-kat-patterns
description: Test-quality patterns and gotchas for scp-event-log EventType/KAT/Merkle tests (ADR-011 unification)
metadata:
  type: project
---

# scp-event-log test-quality patterns (ADR-011 native↔WASM unification)

**Why:** Phase 1 of event-log unification expanded EventType 36→76 and added typed-payload encoders + §25 KAT. Reviewed 2026-06-17, branch `feat/eventlog-unification-phase1`. Re-reviewed at HEAD 658e1392 — APPROVE. Verified all claims hold: KAT non-tautological (pinned hex through prod `tree::append`/`tree::root`/`generate_checkpoint`), vector_32/33 hex are NEW vs origin/main, ContextTombstoned `destination_id` rename left the pinned leaf hash UNCHANGED (positional rmp = name-independent → litmus confirmed), dedup removed exactly 1 named helper per phase2/phase5 file with #[test]/#[tokio::test] attribute counts IDENTICAL base↔HEAD (no test cases lost), economy inline `match`→`tree::event_type_tag`. Suites green: payload 9/9, test_vectors 10/10, lib 197/197 (with `--features testing`).

**How to apply:** When reviewing scp-event-log tests, use these as the bar.

## Harness gotcha (critical, non-obvious)
- `cargo test -p scp-event-log` WITHOUT `--features testing` produces ~116 failures: `InvalidSignature ... "unsupported DID format: did:key:..."`. `extract_public_key_from_did` only accepts `did:key` when the `testing` feature is on. ALWAYS run scp-event-log (and scp-runtime integration) tests with `--features testing`. The failures are environmental, not logic. With the feature: 197 lib + 10 test_vectors green.
- The §25 KAT (`tests/test_vectors.rs`) deliberately uses `did:dht:z<zbase32(pubkey)>` so it passes WITHOUT the testing feature. Good pattern.

## Good patterns worth replicating
- **Positional-encoding shape assertion**: `assert_positional_array(bytes, field_count)` checks rmp fixarray marker `0x9N` + low-nibble == field count. Proves positional (not named-map) MessagePack — the load-bearing wire contract. Pair with `decode(encode(p))==p`.
- **KAT bytes pinned as hex string literals**, computed through the PRODUCTION path (`tree::append`/`tree::root`/`generate_checkpoint`), not recomputed-and-self-compared. Non-tautological: catches encoder/tag/leaf-prefix regressions.
- **Field-rename-preserves-KAT as a litmus test**: under positional MessagePack, renaming a struct field (not its order/value) must NOT change any pinned hash. If a rename forces a hash update, the KAT was name-dependent (tautological). The ContextTombstoned `destination_context_id`→`destination_id` rename touched zero pinned hashes — proof the vectors pin bytes.
- **Exhaustive match (no `_` arm)** in `is_structural_event` and `event_type_tag` = compiler forces classification of every future variant. This is stronger than any test assertion.
- **Tag backward-compat guard**: `protocol_constant_tags_0_through_35_are_unchanged` pins each legacy wire tag incl. deliberate out-of-order `EconomicPolicyApplied=33`. Changing 0-35 breaks already-signed leaves.

## Known test gap (low-risk, non-blocking)
- `structural_events_classified_correctly` asserts 54/76 variants explicitly (all 40 NEW unification variants + sample of base). The 22 unasserted are all BASE variants with unchanged classification. Backstopped by exhaustive match. Could be completed to all-76 for self-documentation but not required.

## De-dup win
- Three scp-runtime integration tests previously copied the `event_type_tag` ladder (comment cited "issue #79: tests can't access pub(crate)"). Fn is now `pub`; all three route to `tree::event_type_tag`. Eliminates silent drift — exactly the hazard the unification targets. Obsolete-comment removal done.
