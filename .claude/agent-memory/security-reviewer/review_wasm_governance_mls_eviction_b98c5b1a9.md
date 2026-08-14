# WASM governance MLS-eviction fix re-review (b98c5b1a9) — CLEAN

branch fix/wasm-governance-mls-eviction, worktree wasm-mls-evict, HEAD b98c5b1a9
(supersedes prior review @97c351df9 of same branch; this commit ADDS the
native-parity missing-leaf no-op behavior).

Task #227. ZERO findings (all 4 categories). 8 manager/crypto tests + decryption
security proof + cross-impl KAT all PASS; wasm32 build + clippy clean.

## What changed since 97c351df9
- crypto/group.rs: NEW `leaf_index_for_did` (byte-parity w/ native
  `find_leaf_index_by_did` wrapping_extension.rs:192 — scan members, exact-DID,
  first match, Ok(None) if absent, GroupDestroyed if group None) + NEW
  `remove_member_by_did` (missing leaf = Ok(empty commit) NO-OP w/ console.warn
  gated #[cfg(wasm32)], matching native MlsCryptoProvider::remove_member
  provider.rs:1077-1084 RemoveMemberOutput::default()). Genuine errors
  (GroupDestroyed, remove/serialize fail on FOUND leaf) propagate Err.

## Fail-closed ordering (VERIFIED airtight)
dispatch_remove_member: existence-check (no remove) → MLS evict (ONLY fallible
crypto step, `?`-propagated) → infallible remove_sender_key + rotate → THEN strip
members/suspended_capabilities/read_exclusion_list/broadcast → MemberLeft leaf.
WASM is SAFER than native here: governance_remove_sender_key &
governance_rotate_sender_key return () (infallible) — no partial-crypto window;
native's equivalents are fallible w/ explicit fail_close_remove_member handlers.
On Err the member stays FULLY present (proven by
remove_member_keeps_governance_state_when_mls_eviction_fails). Wrapper rollback
(execute_governance_action) only removes executed_proposals[id], never restores
members — consistent because strip never happened on the failed path.

## Missing-leaf no-op-then-strip = SAFE (the ★ question)
A governance member w/ no MLS leaf is NOT in the crypto group → no key schedule
to advance → no decryption-after-removal risk; stripping governance is correct
(governance is authoritative for membership). FALSE-NEGATIVE edge (member IS in
group but credential/DID won't decode): leaf silently skipped in BOTH WASM
leaf_index_for_did AND native find_leaf_index_by_did / inline loop — identical
parity. Unreachable via WASM add path (always builds WasmScpCredential w/ same
DID string that flows into ctx.members). Documented, parity-consistent.

## Native-divergence note (own_leaf): native remove_member (provider.rs) skips
own_index + short-circuits member_did==local_did → no-op. WASM
remove_member_by_did does NEITHER (scans own leaf too). Irrelevant for governance
RemoveMember (you don't governance-remove yourself; self-leave is a different
path). Not a finding.

## F5 (suspended_capabilities + read_exclusion_list strip) = correct
WASM analogs of native's role_state.members/assignments/member_capabilities +
access_key_store + peer_registry pseudonym cleanup. Re-admit under same DID starts
fresh = correct (suspension tied to prior membership instance). No security
regression.

## OBS (NOT a finding — pre-existing parity): neither native execute_remove_member
NOR WASM dispatch_remove_member strips the removed DID from `threshold_signers`
(native gov_helpers.rs 1044-1058 omits it; WASM omits it). Both consistent; gated
behind explicit Add/RemoveThresholdSigner gov actions. Not introduced by this PR.

## Convergence / Merkle parity
MemberLeft leaf: empty payload (b""), actor_did=EXECUTOR (resolved tracked
proposer, NOT removed DID — removed DID is buffer-event-only), timestamp=convergent
proposal.created_at (NEVER local now()), appended BEFORE GovernanceActionExecuted.
Native append_context_event now takes explicit ts arg (conformance test line:
append_context_event(&ctx, EventType::MemberLeft, executor_did, ts)) → byte-parity.
KAT cross_impl_remove_member_leaf_is_empty_and_precedes_executed PASSES.

## Commit-hex leak: NONE. Returned hex = public MLS Commit (HPKE-sealed path
secrets, no key material). Sender-key rotate zeroizes old key in place
(local_sender_key.zeroize() before overwrite) + removed member's stored key
ZeroizeOnDrop. WASM has no cross-member sender-key distribution for encrypted MLS
(pre-existing gap, orthogonal — MLS epoch advance is the operative lockout).
Commit-distribution-gap (caller MUST relay or group forks) documented at all 3
layers: context.rs, internal/wasm.ts, scp.ts.

## executor_did spoofing: NONE. Threaded from bridge as tracked-proposal-resolved
proposer (per merged SCP-1866 quorum-bypass fix), not caller-supplied. Out of
scope for this PR (signature predates it).
