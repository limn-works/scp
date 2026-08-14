# WASM #1877 Slice 1 — encrypted-join leaf ordering tests (F1-REDO)

Branch `wasm/1877-slice1-adopt-context-role-state`, manager.rs. Reviewed @d96c38c0d, verdict SHIP.

## The bug class these tests guard (orphan append-only leaf)
- Encrypted join historically appended the durable `MemberJoined` Merkle leaf + buffer event via the inner `join_context` BEFORE the genuinely-fallible MLS `join_from_welcome`. The append-only log can't un-append, so a failed Welcome left an orphan leaf + phantom buffer event → WASM diverges from native (which produces neither) = latent cross-impl equivocation.
- Fix: split `join_context_membership_only` (commit members/role/seq seed, NO leaf). Encrypted path defers leaf+buffer-event until AFTER `join_from_welcome` succeeds. Unencrypted `join_context` appends immediately (no Welcome to fail).

## Non-vacuity pattern worth replicating
- Failure test asserts BOTH `event_log_leaf_count == before` AND no drainable `MemberJoined` buffer event. Under the OLD code both would be before+1 / present → caught. This is the load-bearing pair that proves the reorder.
- Sharpest membership-rollback assertion = `test_member_sequence_number(joiner) == None` (seeded to Some(0) by membership_only before the reachable failure; only rollback nulls it). Stronger signal than is_member/member_count which overlap.
- Success test uses `filter(type==MemberJoined && actor==joiner).count() == 1` on BOTH durable leaves and drained buffer — catches double-append (2) AND missing-append (0) in both dimensions. Good two-directional guard.

## Real-path Welcome minting (sound, not flaky) — reusable setup
- Joining mgr: `generate_key_package_for_join` stores real holder in `pending_key_packages` keyed `"{ctx}:{did}"`.
- Separate creator group: `WasmCryptoState::new_for_context(creator)` (crypto/state.rs:43) → real `mls_group.add_member(KeyPackageIn::tls_deserialize(kp_bytes))` returns TLS-serialized `(commit, welcome)` (crypto/group.rs:111).
- `join_context_encrypted(ctx, joiner, &welcome_bytes)` consumes the SAME holder → real `join_from_welcome` (group.rs:380). `max_past_epochs(2)` matches create_group, so no epoch flake.
- Counts key on type+actor_did, never timestamp/root → `now_secs()`/`creation_timestamp_secs:0` cannot induce flakiness. Per-manager registry, unique ctx id → no cross-test bleed.

## Honest unreachable-branch note (not a false coverage claim)
- `join_context_membership_only`'s `system_assign_role` rollback guards built-in "member" assign = infallible by construction; error branch unreachable today, comment says so. Reachable rollbacks (dispatch_add_member arbitrary role; encrypted-join Welcome failure) ARE exercised. Don't flag as fake coverage.

## Slice-1 suite coverage (solid) — for future regression checks
§5.3.1.1 ceiling grammar (9252/9306/9401/9560/9608), send-gate both-directions+suspension on send AND broadcast (9897/9939/9973/10009), #1886 undefined-role rejection on add+change (10209/10265/10309), rollbacks (subscribe/join/encrypted-join/remove fail-closed 11062), remove-member family (10843/10971/11343/11432/11511), export/import roundtrip (10382/8241/8259/8280).
