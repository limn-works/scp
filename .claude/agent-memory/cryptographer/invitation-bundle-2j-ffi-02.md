---
name: invitation-bundle-2j-ffi-02
description: Runtime InvitationBundle (§5.12.3) crypto — invite_member seal + custody-generic spawn_actor_from_welcome open/verify; FFI-02 close
metadata:
  type: project
---

# §5.12.3 signed InvitationBundle — runtime crypto (ADR-049 Phase 2J, FFI-02 Option A)

Branch `feat/adr049-2j-ffi-slice`. Closes FFI-02 / BLACK-2J10-001 admin-hijack: joiner derives authority from the CREATOR-SIGNED bundle, not attacker-injectable caller params.

**Why:** BLACK-2J10-001 — pre-fix `spawn_actor_from_welcome` took `creator_did/context_params` as loose caller args; an attacker could inject `creator_did=self, governance=SingleAdmin` and hijack. Fix: caller passes a sealed signed bundle; authority = `bundle.context_params` after Ed25519 verify.
**How to apply:** when touching context join/invite crypto, preserve: verify-before-consume ordering, split-custody open, info/aad DRY with seal.

## Crypto construction (locked)
- Pure protocol layer already existed pre-slice: `scp_protocol::context::invitation_bundle` (InvitationBundle/JoinResponse, JCS signing-hash `SHA-256("SCP-INVITATION-BUNDLE-V1:"||lp(context_id)||lp(creator_did)||relay_urls_hash||welcome_hash||key_material_hash||genesis_params_hash||metadata_snapshot_hash)`, sign/verify, verify_structural_consistency). KAT-pinned.
- HPKE invitation seal/open pre-existed in `scp_protocol::crypto::envelope_seal`: `hpke_seal_invitation`, `hpke_open_invitation`, `derive_invitation_routing_id`, `ed25519_pubkey_to_x25519`. info=`"scp-invitation-v1"||lp(ctx)||lp(creator)`, aad=`"scp-invitation-aad-v1"||...`. RFC 9180 Base, DHKEM(X25519,HKDF-SHA256)/HKDF-SHA256/AES-128-GCM. enc bound via kem_context=enc||pkRm (NOT in aad).
- ADDED to envelope_seal.rs: `hpke_open_invitation_with_external_dh(sealed, dh, recipient_pk, enc, ctx, creator)` — split-custody counterpart, builds SAME info/aad → DRY. Joiner's #active priv key stays in custody.

## Runtime pieces (this slice)
- `crates/scp-runtime/src/context/invitation_helpers.rs` (NEW): `build_metadata_snapshot(params, SnapshotRuntimeFacts)` (structural verbatim from params → passes verify_structural_consistency; operational filtered by MetadataVisibilityPolicy, mirrors ContextParams::public_metadata); `SealedInvitation{context_id,creator_did,enc,ciphertext}` delivery wire type (MessagePack). economic_policy summary = `payee=..;adapters=N;locked=B`.
- `Supervisor::invite_member<F,E>(context_id, creator_did, invitee_did, invitee_key_package, relay_urls, sign)` — Encrypted-only (guards Broadcast); resolves invitee #active via key_resolver→X25519; `deps.crypto.add_member(ctx, invitee, Some(kp))`→welcome; builds+signs (sign closure over signing_hash, mirrors export_context — actor holds no key)+seals; delivers via `transport.send_to_routing_id(derive_invitation_routing_id(invitee), payload, INVITATION_TTL_SECS=7d)`; returns InviteMemberOutcome{enc,ciphertext,delivered}.
- Reshaped `WelcomeJoinRequest` = {context_id, creator_did (both UNTRUSTED info/aad hints), sealed_bundle_enc:[u8;32], sealed_bundle_ct:Vec<u8>, reservation_id, local_pseudonym}. Removed loose params/welcome_bytes.
- `spawn_actor_from_welcome<C:KeyCustody>(owning_did, custody:&C, active_key_handle:&KeyHandle, req)` — NOW GENERIC (custody NOT dyn-safe; mirrors dispatch_broadcast_command_with_custody). Top of body: `custody.ed25519_to_x25519_agree(handle, enc)`→dh; pk_rm=`ed25519_pubkey_to_x25519(custody.public_key(handle))`; `hpke_open_invitation_with_external_dh`→wire→`InvitationBundle::from_wire_bytes`; resolve creator #active via key_resolver→`bundle.verify(vk)`→`verify_structural_consistency`→cross-check hints==bundle. Then bind context_id/creator_did/params/welcome_bytes from bundle; rest of ladder unchanged (0xFF02 §5.13.3 verify_scp_context_binding KEPT — belt&suspenders: bundle authenticates signer, 0xFF02 authenticates group).

## Resolved gaps / flagged
- §9.10.4.B context_metadata_key: NO genesis storage in runtime create path (pre-existing gap). invite_member mints fresh OsRng per-invite — sound+signed, converges for bilateral (single invitee), but multi-invitee non-convergent until genesis-key stored at create_context. Metadata-routing publish also unwired → inert today. FOLLOW-UP.
- KeyResolver returns Option (no transient signal) → resolution failure = permanent reject (fail-closed), matches import_context. No retryable-vs-permanent modeled.
- Fork C: `send_to_routing_id` transport primitive EXISTS but NO production code published invitations pre-slice; invite_member ADDS the publish.
- MLS add_member in invite_member runs off the per-context mailbox (shared group Arc). Race-free for first invite to quiescent ctx; full serialization = future InviteMember lifecycle command. FOLLOW-UP.
- scp-ffi breakage EXPECTED (3 bridges call old spawn_actor_from_welcome shape) — next slice.

## Test harness facts
- scp-runtime `spawn_from_welcome_tests.rs`: `run_join_with` builds request+calls spawn; FFI-02 axis = committed(0xFF02) vs request_params. Bob custody = InMemoryKeyCustody import bob did_to_seed. Resolver must map ALICE_DID→alice_vk (trivial_resolver returns None → sig verify fails).
- scp-testing `fullstack/node.rs`: FullStackNode holds Supervisor + signing_key=SigningKey::from_bytes(did_to_seed(did)). add_member→invite_member; join_from_welcome→sealed spawn.
- Run tests with `--features scp-runtime/testing,scp-core/testing`; bare `-p scp-event-log` needs `--features testing`.
