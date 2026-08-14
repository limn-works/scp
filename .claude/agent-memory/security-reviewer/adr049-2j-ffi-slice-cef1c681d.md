# ADR-049 Phase 2J FFI slice — security review (cef1c681d, 2026-07-05)

Branch feat/adr049-2j-ffi-slice. FFI reshape (invite_member + reshaped
context_join_from_welcome across pyo3/napi/uniffi) + KP-capability fix 9fe3b4c9b.
Runtime crypto core (FFI-02 InvitationBundle, creator_did<->0xFF02) pre-reviewed 4x.

VERDICT: NO BLOCKING FINDINGS. FFI key-handling + join-auth SOUND.

1. Raw signing-key handling — all 3 bridges identical + correct: resolve raw
   SigningKey -> pass by &ref to single sup.invite_member call -> explicit
   drop(signing_key) (ZeroizeOnDrop wipes). Never cloned into long-lived state,
   never logged, never returned across FFI. pyo3 context.rs:2997-3011,
   napi context.rs:1528-1553, uniffi bridge.rs:9858-9874.
   Impersonation-proof: pyo3/napi require creator_did locally custodied
   (resolve_signing_key/with_identity); uniffi uses identity.did (handle, not
   caller string) — prevents inviter/invitee transposition.

2. Reshaped join — SOUND. expect_32 on sealed.enc BEFORE irreversible KP consume
   (fail-closed). Authenticated ceiling GENUINELY installed: re-synced from
   joined.params().ceiling in all 3 (pyo3 sync_ceiling_from_params:2900,
   napi:1424, uniffi:9706-9725); returned handle built from joined.params()
   (pyo3:2937/napi:1463/uniffi:9761). NO elevation: joiner supplies no ceiling;
   transient precheck uses default_ceiling() (safe baseline, NOT empty/elevated —
   register_ffi_state runtime.rs:1486 maps default_ceiling names when user_ceiling
   empty). FFI ceiling_strings is defense-in-depth; runtime actor holds authoritative
   signed ceiling.
   Minor OBS (unreachable): pyo3/napi post-commit sync_ceiling_from_params Err would
   leave live actor + default-ceiling FFI state while returning Err — unreachable
   (with_ffi_state errors only if entry absent; just registered), zero exposure
   (caller gets no handle). uniffi already fails closed explicitly.

3. KP-capability fix 9fe3b4c9b — pure valn0502 MLS structural fix. 0xFF02
   *capability* = support declaration, NO key material, grants NO authority;
   valn0107 only constrains reverse. extract_wrapping_key reads leaf ext not
   capability -> member w/o wrapping key correctly skipped for sender-key seal.
   Auth is upstream (invite gate + signed bundle KP binding). NO new exposure.
   No-sender-keys = pre-existing #2032 (filed, out of scope).

4. Governance gate for invite — SECURITY IMPROVEMENT. invite_member
   (supervisor.rs:10620-10653) routes through
   propose_governance_action_checked_carrying_key_package ->
   ProposeGovernanceActionChecked: validates governance:propose IN-LOCK w/
   submission (no TOCTOU, :12056), SingleAdminEngine::propose rejects non-admin.
   Replaces old off-mailbox unchecked deps.crypto.add_member. Voting model returns
   RequiresGovernanceApproval before staging anything. Default-ceiling-lacks-
   governance:propose = fail-closed USABILITY not security.

Positive: SealedInvitation + PyInviteMemberOutcome carry only HPKE (enc,ciphertext);
InvitationKeyMaterial (context_metadata_key, sender_key_seed) rides INSIDE HPKE
ciphertext sealed to invitee — never cleartext across FFI.

GOTCHA REMINDER: Read tool default absolute path /Users/alec/Developer/limn/scp/...
= MAIN worktree (line numbers differ). MUST use
.claude/worktrees/2j-ffi-slice/... for this branch.
