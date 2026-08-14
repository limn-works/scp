# Signed InvitationBundle / FFI-02 Option A (ADR-049 Phase 2J)

Branch feat/adr049-2j-ffi-slice. Runtime layer reviewed at HEAD 0dc94674e (diff 982701e77..HEAD).
Pure-protocol bundle type + sign/verify landed in 982701e77; spec §5.12.3.

## Construction map
- Pure layer: crates/scp-protocol/src/context/invitation_bundle.rs — InvitationBundle/JoinResponse,
  invitation_bundle_signing_hash (SCP-INVITATION-BUNDLE-V1: || len-pfx ctx || len-pfx creator ||
  Fixed32 per-field SHA-256(JCS(field)) for relay_urls/welcome/key_material/context_params/metadata_snapshot),
  Ed25519 sign/verify (verify_strict via scp-primitives), verify_structural_consistency
  (set-compares ceiling+roles order-independently vs signed context_params).
- HPKE: crates/scp-protocol/src/crypto/envelope_seal.rs (hpke_seal_invitation, hpke_open_invitation_with_external_dh)
  over hpke.rs core. info="scp-invitation-v1"||len-pfx ctx||len-pfx creator; aad="scp-invitation-aad-v1"||...
  RFC 9180 Base, DHKEM(X25519,HKDF-SHA256), AES-128-GCM. kem_context=enc||pkRm (binds recipient, closes UKS).
  enc NOT in aad (already in kem_context). KAT-pinned to RFC 9180 A.1.
- Runtime glue: invitation_helpers.rs (SealedInvitation wire envelope, build_metadata_snapshot).
- Creator: Supervisor::invite_member (supervisor.rs ~10477) — Encrypted-only, resolves invitee #active->X25519,
  MLS add_member, sign via FFI closure (#active), seal, publish to scp-invitations routing id.
- Joiner: spawn_actor_from_welcome<C:KeyCustody> (~10727) — OPEN+VERIFY bundle FIRST (before prechecks/consume):
  dh=custody.ed25519_to_x25519_agree(#active,enc) [private key never leaves custody], pkRm from own #active,
  open, decode, resolve bundle.creator_did #active, verify sig, verify_structural_consistency, cross-check hints.
  ALL authority (context_id/creator_did/params/welcome) from bundle.*; hint_ vars only feed info/aad+cross-check.

## Soundness: HPKE SOUND, signature-binding SOUND, authority-derivation SOUND.
- Split-custody DH consistent: custody uses signing_key.to_scalar_bytes() as x25519 StaticSecret;
  seal recipient = VerifyingKey::to_montgomery(). Birational identity holds (test external_dh_open_matches_seal).
- Fresh OsRng ephemeral per seal => no AEAD nonce reuse. Distinct domain sep from sender/access/broadcast/private HPKE.
- welcome_message bound into signature => bundle can't pair with a different Welcome. Recipient-bound => can't replay to another DID.
  Replay-after-join closed by first-writer-wins prechecks A/D. No timestamp in bundle (matches spec; benign).
- Reject ordering: bad-sig + structural-inconsistency reject BEFORE irreversible ConfirmConsume; 0xFF02 mismatch
  after consume but installs NO crypto (unavoidable — needs joined group; only cost = burned KP).

## Findings (all non-blocking for the documented bilateral scope)
- MEDIUM (scoped): creator/admin identity NOT group-attested. ScpContextExtension (0xFF02) commits
  context_id/mode/governance_hash/ceiling_policy/ceiling_hash/parents — NOT creator DID.
  build_welcome_joiner_state (~11240) installs bundle.creator_did as admin unconditionally, no ratchet-tree
  credential check. Authenticates the SIGNER, not that signer is the group's rightful admin. Fine for bilateral
  first-invite (creator=sole member). Multi-member: admin-attribution split if MLS adds aren't admin-restricted.
  Harden by binding creator DID into 0xFF02 or checking inviter leaf in joined tree before extending scope.
- MEDIUM (scope limit): invite_member discards MLS Commit (uses only welcome_bytes). Correct only for creator-only
  group; adding to >=2-member context desyncs existing members. Consistent w/ fixed 2-member joiner state but unenforced.
- LOW: context_metadata_key minted fresh OsRng per-invite and NOT retained creator-side => even bilateral can't
  converge on metadata routing id. Inert today (metadata routing unwired). Needs genesis metadata key at creation.
- LOW (zeroize): decrypted bundle_wire (spawn) + serialized wire (invite_member) are plain Vec<u8> holding
  context_metadata_key cleartext, not zeroized. InvitationKeyMaterial field IS ZeroizeOnDrop; wrap the buffers in Zeroizing.
- Concurrency "race" follow-up is OVERSTATED: with_context holds DashMap entry write-lock over whole MLS mutation;
  take_crypto_state not yet prod-wired => no data race, only logical commit-epoch ordering. Benign for quiescent first invite.
- resolver-Option permanent fail-closed: correct, matches import path.
