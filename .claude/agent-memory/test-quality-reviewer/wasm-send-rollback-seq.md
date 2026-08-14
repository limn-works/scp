# WASM send_message sequence-rollback coverage (slice1-roles, manager.rs)

## Production path (HEAD:crates/scp-ffi/wasm/src/manager.rs)
- `send_message` ~L2011: reserves+increments per-sender MLS seq (post-increment from 0) BEFORE the fallible encrypt closure (base64 decode CRYPTO_4001 / mls epoch CRYPTO_4002 / encrypt CRYPTO_4003).
- On any closure Err: rollback at L2138-2145: `*entry = entry.saturating_sub(1)`; THEN `if !seq_was_present && *entry == 0 { remove(sender_did) }`. Mirrors native MembershipState::rollback_sequence_number.
- `seq_was_present` (L2090) = whether sender had an entry before the `.entry().or_insert(0)`.

## New test: send_message_failure_does_not_advance_sequence_wasm (~L10331)
- NON-VACUOUS, real crypto path (WasmCryptoState::new_for_context → ctx.crypto=Some), mutation-sensitive (commit documents RED=2/GREEN=1). PASSES (414/414 in module).
- BUT only exercises the saturating_sub branch (creator seeded seq 0 by constructor L1421/1706, then send→1, fail→back to 1). seq_was_present=TRUE. The REMOVAL branch (L2142-2144) is NOT hit.

## CONFIRMED GAP (prior reviewer right): !seq_was_present removal branch untested
- Every test seeds a 0 entry: constructor L1421/1706, test_insert_member L913 (.entry().or_insert(0)), dispatch_add_member L1849/3938, subscribe L5596. So NO existing test has a member in role_state.members WITHOUT a member_sequence_numbers entry.
- A mutation deleting L2143 `remove(sender_did)` would go UNCAUGHT.
- Branch is PRODUCTION-REACHABLE (not dead): import_context L6912 restores member_sequence_numbers VERBATIM from snapshot, INDEPENDENTLY of role_state.members. A legit imported context with a member who never sent → in members, no seq entry → first send failing encrypt → removal branch.
- Closing test value = REAL. Recommend `send_message_first_send_failure_removes_unseeded_entry_wasm`: construct member in role_state.members with NO seq entry (manually remove after insert, or import path), attach crypto, send invalid base64, assert test_member_sequence_number(member) == None afterward. test_member_sequence_number already returns Option (None-distinguishing) — built for exactly this.

## Suite assessment: SOLID + ship-ready
- 414 tests, 0 ignored, ~6s, no sleep/rand/order-dependent iteration. Time via WasmClock→SystemTime fallback on native target; tests structured around now_ms WASM constraint.
- Export/import tests: real signed export_context→import_context into FRESH manager, BLACK-CEIL-01 verbatim-restore guard, identity-registry cleanup both ends (OnceLock-poison hygiene).
- subscribe_broadcast NOW covered (L8592, L8660) — closes prior memory gap.
- Membership matrix, send/publish role-grant+suspension gate, ModifyCeiling, deserialize/version/ceiling-reject all present.
- The one gap (removal branch) is the only material coverage hole; non-blocking but worth closing.
