# InvitationBundle runtime layer (FFI-02 Option A, ADR-049 Phase 2J)

Branch feat/adr049-2j-ffi-slice @0dc94674e. Reviewed Supervisor::invite_member (creator side) +
reshaped custody-generic spawn_actor_from_welcome<C: KeyCustody> (joiner side), envelope_seal
external-DH open, invitation_helpers.

## Verified SOUND
- HPKE seal/open symmetry: build_invitation_info/build_invitation_aad identical both sides;
  external-DH open path (custody dh + birational pkRm) is the standard ed25519->x25519 pair;
  kem_context = enc||pkRm matches. E2E test (two independent supervisors) round-trips MLS both ways.
- Signature preimage: invitation_bundle_signing_hash EXCLUDES self.signature, so sign(sig=empty)
  == verify(sig=filled). JCS over context_params; msgpack wire roundtrips.
- Join ordering: bundle open->verify sig->structural->0xFF02(at group install)->KP consume. ALL
  bundle checks are BEFORE the irreversible ConfirmConsume. Authority derives from signed bundle,
  not caller params (closes BLACK-2J10-001). Rich negative tests (forged signer, tampered ct,
  tampered sig, structural divergence) all reject with no side effects.
- No panic/unwrap/slice on attacker ct: aes-gcm decrypt handles short ct; enc is [u8;32] no trunc;
  active_pub try_into guarded.
- All non-ffi callers updated to 4-arg shape (tests). scp-ffi expected-broken (handed off).
- Worktree compiles clean (cargo check -p scp-runtime --features testing); 24 spawn_from_welcome
  + 9 envelope_seal + 3 invitation_helpers tests pass.

## FINDINGS
- MEDIUM: invite_member has NO rollback of the irreversible MLS add_member (which internally
  merge_pending_commit's, advancing the creator's group epoch + adding the invitee leaf). add_member
  (step 3) MUST precede sign (welcome goes in the bundle), but sign/to_wire_bytes/hpke_seal (steps
  5-6) are all fallible AFTER it. If the creator's `sign` CLOSURE fails (hardware custody: user
  declines biometric, key locked) the group is permanently advanced with a ghost member who never
  received a Welcome; retrying invite_member double-adds. Join side has meticulous rollback; invite
  side has none. Fix: on any post-add failure, drive a compensating remove_member commit, or make
  post-add steps infallible.
- LOW/informational: successful invite_member advances the creator's MLS roster but does NOT update
  runtime role_state/membership nor persist a Class-S snapshot. Alice's membership shows stale count
  vs her MLS group (split-brain). May be intended slice scope (membership via governance/admission).
- LOW: bundle-open block (custody.ed25519_to_x25519_agree().await + custody.public_key().await +
  AEAD open) runs under the GLOBAL bootstrap_spawn_lock and OUTSIDE the LIFECYCLE_TIMEOUT bound. The
  timeout comment claims only "fast" prechecks are outside the bound; custody awaits are NOT
  guaranteed fast (HSM/Secure Enclave). A slow custody backend pins the global bootstrap lock,
  wedging all node bootstraps. Joiner's own key (not attacker-timed), so soft DoS.

## GOTCHA (self): I cd'd to MAIN repo path and cargo-check'd the user's unrelated ceiling WIP
(governance_helpers/lifecycle_helpers role_state.remove_member break) instead of the worktree.
The MEMORY guardrail warned exactly this. Always run cargo IN the worktree cwd, no cd to /Users/alec/Developer/limn/scp.
