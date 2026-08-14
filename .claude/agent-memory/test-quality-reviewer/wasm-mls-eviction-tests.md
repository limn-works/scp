# WASM governance RemoveMember MLS-eviction test suite (branch fix/wasm-governance-mls-eviction @97c351df9)

Security fix: WASM `dispatch_remove_member` now does real MLS eviction (was a governance-only no-op
leaving the removed member able to decrypt). Fail-closed-keep ordering: MLS evict FIRST, strip
governance state only after crypto cuts succeed. Mirrors native `execute_remove_member`
(governance_helpers.rs:1231).

## Verdict: SOLID. 5 new unit tests + 1 conformance KAT, all pass. Non-vacuous.

## Why the security proof (state.rs evicted_member_cannot_decrypt_after_removal_and_rotation) is real
- `decrypt_message` does MLS-decrypt FIRST (layer 1), sender-key decrypt SECOND (layer 2). Bob's
  stale `mls_group` is stuck at the pre-eviction epoch → layer-1 `process_message` returns Err on the
  new-epoch ciphertext, BEFORE the sender-key store is consulted. So Bob's lockout is proven at the
  MLS layer (the layer the fix restores), NOT confounded by the withheld sender key.
- If eviction were a no-op, Alice's epoch wouldn't advance → `epoch_post == epoch_pre + 1` fails first.
- Carol = positive control (still a member, decrypts post-eviction). Both assertions load-bearing.
- 3 members required because OpenMLS can't decrypt own sends.

## Conformance KAT caveat (CONFIRMED prior-reviewer concern, accepted limitation)
`cross_impl_remove_member_leaf_is_empty_and_precedes_executed` (wasm_conformance.rs): the NATIVE half
hand-replays `append_context_event(MemberLeft)` + `append_context_event_with_payload(GovActionExecuted)`
directly on a MerkleEventLogProvider — it does NOT call `execute_remove_member`. It uses the same
provider trait methods native production uses, but does NOT exercise native's ordering LOGIC (the
commit_class_s_keep closure + post-closure append). Reason: scp-runtime test crate can't dev-depend on
the scp-ffi-wasm cdylib. WASM half (`..._wasm` in manager.rs) DOES drive real execute_governance_action
→ dispatch_remove_member. Doc comment is accurate (says "drives native's REAL durable appends" — true
for the append calls, but readers may over-read "REAL" as "the real execute_remove_member path"). KAT
proves leaf-FORMAT parity (empty payload, executor actor_did, ordering), NOT that both impls emit in
that order from their real removal paths. Acceptable given the crate-dep constraint; WASM side covers
its real path; native real ordering is covered by native's own governance tests.

## Coverage gaps (LOW severity, all in the should-strengthen bucket)
1. No assertion that the encrypted-path `dispatch_remove_member` returns a non-empty `commit` hex JSON
   field (the relay-distribution surface, manager.rs:3555). Crypto path tested at WasmCryptoState level
   but not the bridge JSON return.
2. No test of dispatch_remove_member on a broadcast/author context (block_author cleanup + empty commit
   for crypto.is_none()).
3. Event-count-after-removal asserted via find/position, not an exact count (no extra/duplicate leaves).

## No flakiness: all timestamps are fixed literals (created_at, timestamp_secs); ordering asserted by
position not wall-clock; no randomness in assertions (key material random but only equality/err checked).

## UPDATE @ b98c5b1a9 (3 LOW gaps from prior review now CLOSED + new tests added)
Prior-review LOW gaps F6/F7/F8 are RESOLVED:
- F6 `remove_member_encrypted_path_returns_decodable_commit_hex` (manager.rs): adds a REAL 2nd MLS leaf,
  asserts non-empty hex commit that hex::decodes to non-empty bytes + Bob no longer resolves. Non-vacuous.
- F7 `remove_member_broadcast_path_empty_commit_still_appends_leaf`: crypto=None broadcast author;
  asserts empty commit + block_author cleanup (is_author false after) + MemberLeft leaf appended. Non-vacuous.
- F8 exact ==1 counts: live in the WASM-side KAT `remove_member_..._wasm` (manager.rs), NOT the conformance
  KAT. Both member_left_count==1 and executed_count==1 asserted — real regression guard (dispatch appends 1
  MemberLeft, wrapper appends 1 GovActionExecuted). The conformance KAT still uses find/position only, but
  that's a 2-append hand-replay so count is test-controlled there anyway — acceptable.
Plus: group.rs leaf_index_for_did + remove_member_by_did + is_noop_for_non_member + errors_on_destroyed_group;
manager.rs no_mls_leaf_removed_cleanly (F5 per-DID cleanup verified) + keeps_governance_state_when_mls_eviction_fails
(fail-closed-keep: asserts member RETAINED + role unchanged + NO MemberLeft leaf — the destroyed-group genuine
error). All 11 tests PASS. All non-vacuous.

## *** RESOLVED @ 66a2c6a5c (self-DID short-circuit landed + tests) ***
The self-removal divergence below is now FIXED in code AND covered by tests. group.rs gained `own_did()`
(derives local DID from own leaf — works for creator leaf 0 AND Welcome-joined non-zero leaf, no stored
state) + a self-DID short-circuit in `remove_member_by_did` (`if self.own_did()? == member_did { return
Ok(Vec::new()) }`) BEFORE the scan, plus the own-leaf skip retained in `leaf_index_for_did`. Mirrors
native's TWO mechanisms (provider.rs:1041 short-circuit + :1060 own-index skip). New tests, all verified
non-vacuous by hand-mutation:
- group.rs: `own_did_returns_local_member_did_for_creator`, `own_did_returns_joiner_did_for_welcome_joined_member`
  (FAILS if own_did hardcodes leaf 0 — mutation-confirmed), `own_did_errors_on_destroyed_group`,
  `remove_member_by_did_is_noop_for_self_did`, `remove_member_by_did_short_circuits_on_self_did_before_scan`,
  `remove_member_by_did_self_did_does_not_evict_duplicate_leaf` (FAILS if short-circuit removed — mutation-confirmed).
- state.rs: `governance_remove_self_did_no_op_in_dup_did_tree` (FAILS if short-circuit removed — mutation-confirmed).
- manager.rs: `remove_member_self_did_encrypted_empty_commit_strips_and_appends_leaf` (real dispatch path:
  empty commit + member stripped + F5 cleaned + MemberLeft leaf).
- conformance: `cross_impl_self_removal_leaf_is_empty_and_precedes_executed` (hand-replay; exact ==1 counts + ordering).
NOTE on a doc-accuracy nit (LOW): `remove_member_by_did_short_circuits_on_self_did_before_scan` PASSES even
with the short-circuit removed (single-member group → own-leaf skip also yields None). It does NOT distinguish
short-circuit from own-leaf-skip; the dup-DID tests are the real discriminators. Docstring overclaims it
"exercises the short-circuit path".
Security proof `evicted_member_cannot_decrypt_after_removal_and_rotation` re-confirmed non-vacuous by mutating
`governance_remove_from_group` to a no-op → epoch-advance assertion fails.
Residual LOW gap (still open): no TS-level test that `contextExecuteGovernanceAction` surfaces the `commit`
hex field (scp.ts/wasm.ts changes are doc-only; commit round-trip covered only at Rust dispatch layer).
VERDICT @ 66a2c6a5c: SHIP. All 41 wasm crypto/manager + conformance remove/self-removal tests pass.

## *** RE-VERIFIED @ c3f7fe48b (fresh independent pass, code re-read not memory) — VERDICT: SHIP ***
Ran both suites locally on HOST target (wasm32 target fails to link here — use `cargo test -p scp-ffi-wasm --lib`
+ `cargo test -p scp-runtime --test wasm_conformance --features testing` with DYLD_LIBRARY_PATH). Results:
379/379 wasm-ffi lib PASS (incl evicted_member_cannot_decrypt security proof), 57/57 conformance PASS,
1 honest unrelated #[ignore] (wasm_native_full_governance_eventtype_parity_pending, ~40-event scope, NOT
RemoveMember, NOT in diff). Re-read & confirmed non-vacuous by hand: state.rs:295 security proof (epoch+1
guard @401 + Bob stale-decrypt-Err @413 + Carol liveness @425); manager.rs:9729 fail-closed-keep (destroy
group → GroupDestroyed → member RETAINED + role unchanged + NO MemberLeft leaf); group.rs:877 dup-DID
discriminator (epoch-unchanged @916 + dup-leaf-still-resolves @926 both fail if short-circuit @347 removed);
manager.rs:9797 commit-hex; manager.rs:9510 exact ==1 counts. TS diff = doc-only (0 non-comment added lines,
verified via grep). TS deferral CORRECT (no runtime code; mocked test = inverted-mock anti-pattern; round-trip
proven at Rust dispatch manager.rs:9836). NEW observation: scp.ts JSDoc now asserts NAPI auto-broadcasts the
eviction commit — user-facing behavioral claim, no NAPI code in diff, out of test-review scope but worth a
NAPI-owner glance (wrong doc would mislead callers into NOT relaying a commit that needs relaying).

## *** RE-REVIEWED @ c3f7fe48b (doc commit) — VERDICT: SHIP ***
Doc-only commit (zero runtime change, verified: TS diff has ZERO non-comment added lines via
`git diff origin/main | grep -vE '^\+\s*(\*|//)'`). Three changes:
1. group.rs:842 softened docstring of `remove_member_by_did_short_circuits_on_self_did_before_scan` —
   NOW ACCURATE & HONEST. New text explicitly states the single-member test does NOT discriminate the
   self-DID short-circuit (group.rs:347) from the own-leaf skip (leaf_index_for_did:268-272) and points
   readers to `remove_member_by_did_self_did_does_not_evict_duplicate_leaf` as the real discriminator.
   Verified the claim: single-member group → only member IS own leaf → leaf_index_for_did skips it →
   None even with short-circuit removed. Correct. The misnamed test name remains (could rename to
   `..._self_did_is_empty_noop_on_single_member_group`) but the docstring fully owns the limitation =
   acceptable; NOT actionable.
2. scp.ts @returns reworded — now correctly scopes commit-relay obligation per backend (NAPI auto-broadcasts,
   WASM requires caller relay). Doc accuracy improvement.
3. manager.rs:3498 collapsed duplicated sender-key-gap prose to a pointer to state.rs canonical explanation.
Discriminator test re-verified non-vacuous by reading code: dup leaf carries local DID via fresh signing key;
short-circuit at :347 returns BEFORE scan; if removed, leaf_index_for_did resolves the non-own dup leaf
(own-leaf skip only skips leaf 0) → evicts → epoch advances → BOTH the epoch-unchanged AND the final
is_some() assertions (group.rs:916,926) fail. Solid.
TEST RUN: 379/379 wasm-ffi lib tests PASS; 57/57 wasm_conformance PASS (1 pre-existing honest #[ignore]:
`wasm_native_full_governance_eventtype_parity_pending` — NOT in this diff, broad ~40-event scope, unrelated
to RemoveMember). Both self-removal conformance KATs present (cross_impl_remove_member... :2414,
cross_impl_self_removal... :2515).
TS DEFERRAL = REASONABLE, NOT A BLOCKING GAP. `commit` field produced at manager.rs:3572 in dispatch;
encrypted-path test (manager.rs:9797) asserts non-empty hex-decodable commit + evicted member no longer
resolves; self-removal test (:9886) asserts EMPTY commit + strip + F5 clean + leaf. The TS layer adds no
runtime code — `commit` flows through the existing JSON return. A TS test would need the WASM bridge built
(not built by default in `bun test`); a mocked TS test would re-assert a value the mock itself sets =
worse than none (see inverted-mock anti-pattern in MEMORY.md). Deferral is correctly justified.
No flakiness (fixed timestamp literals, position/equality assertions, no wall-clock/random/order/network).
No actionable redundancy. SUITE IS SOLID.

## (HISTORICAL — now resolved above) CRITICAL UNRESOLVED GAP: SELF-REMOVAL native↔WASM DIVERGENCE (untested) ***
Native `MlsCryptoProvider::remove_member` (provider.rs:1040) has TWO self-guards WASM LACKS:
  (1) `if member_did == self.local_did { return RemoveMemberOutput::default() }` — empty-commit no-op BEFORE leaf lookup;
  (2) leaf scan skips own_index (`if member.index == own_index { continue }`).
Native test: `self_removal_is_noop` (provider.rs:3100) + "self-removal must return empty commit_bytes" (2717).
WASM `leaf_index_for_did` (group.rs) scans ALL members incl leaf 0, has NO local_did concept in crypto layer,
will return the LOCAL member's own leaf → OpenMLS `remove_members` on own leaf ERRORS → dispatch fails-closed KEEPS.
RESULT for governance RemoveMember{did=local own DID}: NATIVE=empty commit + member stripped + MemberLeft leaf;
WASM=Err + member kept + NO leaf. => breaks cross-platform tree::root parity (the KAT's whole point) AND is a
security-fix behavioral divergence. ZERO tests cover self-removal at any layer (group/state/dispatch/conformance KAT).
Also untested: removing the context creator/admin (no creator-protection guard exists in either impl — reachable).
Recommend: (a) group.rs unit test removing alice's OWN did (leaf 0) documenting actual OpenMLS behavior;
(b) manager dispatch test for self-DID removal asserting it matches native (empty commit + stripped + leaf);
(c) conformance KAT self-removal case. If WASM is meant to match native, the FIX needs a local_did guard too —
this is a code gap the missing test would have caught.
