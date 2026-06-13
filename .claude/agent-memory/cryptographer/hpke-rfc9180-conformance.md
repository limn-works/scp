# HPKE RFC 9180 Conformance (implemented 2026-06-13, branch fix/hpke-rfc9180-conformance)

## FINAL INDEPENDENT GATE @498292b95 (2026-06-13): SHIP
- Fresh read of full 22-file diff. hpke.rs conforms (LabeledExtract uses Some(salt)=empty-string per RFC5869 not zero-block; DHKEM kem_context=enc||pkRm KEM-suite-id; KeySchedule_base mode 0x00 HPKE-suite-id; seq-0 nonce=base_nonce). A.1 KATs assert genuine RFC intermediate values. 32 hpke tests green; oracle 3/3 (bidir+custody); wasm32 clean (hpke-rs dev-dep gated).
- No surviving old construction (derive_aead_key/HPKE_DOMAIN_TAG/SCP-HPKE-V1/hkdf_derive_key/aes128gcm_* = 0 matches). 60->48 wire consistent. 5 distinct BE32-len-prefixed info separators + §9.18.2 registry complete. Custody open_with_external_dh binds enc||pkRm, documented contract. Zeroization complete at all custody/recovery sites (hkdf PRK limitation documented).
- Consuming-path tests green (--features testing): hpke_backend 8, access wire 28, sender key_protocol 27, recovery psk 45.
- NON-BLOCKING: spec S5 "device-enroll" purpose only "psk-rotate" wired (pre-existing separate flow, not regression); rotate_psk early-return len!=32 skips new_psk.zeroize (minor stack wipe miss); scp-runtime lib-test needs --features testing (unrelated TestInducePanic cfg, not in diff).



Replaced the five hand-rolled custom-ECIES key-distribution constructions (mislabeled "HPKE")
with ONE correct, hand-implemented RFC 9180 Base-mode single-shot core. Supersedes the
hpke-custom-ecies-finding.md finding (now FIXED).

## The core: crates/scp-protocol/src/crypto/hpke.rs
- Suite: DHKEM(X25519, HKDF-SHA256) 0x0020 / HKDF-SHA256 0x0001 / AES-128-GCM 0x0001, Base mode.
- Single-shot only: every seal generates fresh ephemeral, one Seal at seq 0 => nonce = base_nonce
  (no ComputeNonce increment ever exercised).
- Public API: `seal(recipient_pk, info, aad, pt) -> (enc:[u8;32], ct:Vec<u8>)`,
  `open(recipient_sk, enc, info, aad, ct)`, `custody::open_with_external_dh(dh, pkRm, enc, info, aad, ct)`.
  `seal_with_ephemeral` is `#[cfg(test)] pub(crate)` — fixed-skEm KAT injection only.
- Labeled KDF over RustCrypto hkdf/sha2/aes-gcm + x25519-dalek (zero new prod deps, wasm32-clean).
  KEM suite_id="KEM"||0x0020; HPKE suite_id="HPKE"||kem||kdf||aead. LabeledExtract uses
  `Hkdf::extract(Some(salt),...)` (NOT None — None gives all-zero salt block, wrong per RFC).
  LabeledExpand uses `Hkdf::from_prk`. KeySchedule_base: mode 0x00, empty psk/psk_id.
- KAT: RFC 9180 Appendix A.1, transcribed from the RFC text (rfc-editor.org/rfc/rfc9180.txt).
  seq-0 ct = f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a
  (MATCHED the plan §11-C2 prior exactly). Asserts intermediate shared_secret/key/base_nonce too.
  Custody-path KAT (DH(skRm,enc)) also pinned.
- Oracle: hpke-rs 0.6 dev-dep (tests/hpke_oracle.rs, #![cfg(not(wasm32))]). Types via
  `hpke_rs::hpke_types::{Aead,Kdf,Kem}Algorithm`, `Hpke::<HpkeRustCrypto>::new(Mode::Base, DhKem25519,
  HkdfSha256, Aes128Gcm)`. Bidirectional. GOTCHA: hpke-rs `open` rejects EMPTY plaintext as
  InvalidInput (bytes_to_option maps empty->None) — our-seal->ref-open test must use >=1 byte pt;
  empty is covered by our own roundtrip + ref-seal->our-open direction.

## Custody Decap (C1)
- open_with_external_dh under hpke::custody submodule (NOT top-level). Caller contract (load-bearing):
  dh = KeyCustody::dh_agree(handle, enc), pkRm = KeyCustody::public_key(handle) — SAME handle, SAME enc.
  Binds enc||pkRm via kem_context => closes the UKS gap the legacy raw-DH-export paths had.
- SharedSecret::as_bytes() returns &[u8;32] (deref with `*`, NOT try_into). PublicKey::as_bytes()
  returns &[u8] (use try_into). traits.rs:182/250/277.

## Wire change: 60 -> 48 bytes
- SenderKeyResponse.hpke_sealed_key [u8;60]->[u8;48]; serde_hpke_sealed_60 -> serde_hpke_sealed_48.
  60 was nonce(12)+ct(32)+tag(16); 48 is ct(32)+tag(16), nonce internal per RFC 9180.
- handle_bridge_shadow_key_request 60->48. provider.rs 4 sites. AccessKeyResponse uses Vec (flexible).

## Call sites (all now route through hpke::)
- scp-protocol: key_protocol_verify hpke_seal/open_sender_key; envelope_seal ecies_seal/open ->
  hpke_seal_invitation/hpke_open_invitation (removed redundant eph-pub-in-AAD, RFC binds via kem_context);
  broadcast.rs NEW build_broadcast_key_hpke_info/aad + seal_broadcast_key_to_subscriber/open_broadcast_key.
- scp-runtime: key_protocol.rs + access_keys/wire.rs custody-open via open_with_external_dh; recovery.rs
  PSK now HPKE AES-128 (was salted-HKDF AES-256), info "scp-private-state-v1"||len(did)||did||"psk-rotate",
  empty aad, wire enc(32)||ct(48)=80B; PskRotationParams gained `did`; added unwrap_psk_for_device.
  hpke_backend.rs trait fixed: seal->(enc,ct), unseal+aad, ProductionHpkeBackend is thin shim over core.
  Deleted derive_aead_key + HPKE_DOMAIN_TAG "SCP-HPKE-V1:" (code-invented, in no spec).

## C5 — platform custody public_key for X25519: BOTH CORRECT, no fix needed
- Swift AppleKeyCustody.publicKey (AppleKeyCustody.swift:620-624): X25519 handle ->
  Curve25519.KeyAgreement.PrivateKey(rawRepresentation:).publicKey.rawRepresentation (raw 32B). Test exists.
- Kotlin AndroidKeyCustody (platform/AndroidKeyCustody.kt:790-808): X25519 always SOFTWARE,
  softwareKeyOps.publicKey -> X25519PublicKeyParameters.encoded (raw 32B). dhAgree validates key type.

## Spec edits landed first (artifact-flow): S1 broadcast len-prefixes (05-contexts §5.14.2),
## S2 registry rows (09 §9.18.3), S3 invitation HPKE (05 §5.12.3.1), S4 custody-Decap wording
## (09 §9.16.2), S5 psk-rotate purpose (03 §3.7.2).

## C4 (NOT done here — orchestrator's): file the broadcast pull-protocol wiring story (SCP-227).
## The broadcast seal/open HELPERS exist now but have no production caller yet (dead until wired).

## Re-audit @609fd7caa (2026-06-13) — VERDICT: 1 LOW + 2 NIT, no CRITICAL/HIGH/MED
- hpke.rs core verified line-by-line vs RFC 9180: LabeledExtract/Expand, kem/hpke suite_id, DHKEM
  ExtractAndExpand (eae_prk + kem_context=enc||pkRm), KeySchedule_base (psk_id_hash/info_hash/secret/
  key/base_nonce, mode 0x00), seq-0 nonce=base_nonce. CORRECT.
- A.1 KATs are GENUINE RFC 9180 A.1.1 values (info/skEm/enc/skRm/pkRm/SS/key/base_nonce/ct all verified).
  14 lib KATs + 3 hpke-rs oracle tests pass (both directions + custody). Oracle is real, not a no-op.
- LOW (zeroization): runtime custody open sites copy raw DH into BARE [u8;32] not Zeroizing:
  access_keys/wire.rs:381 `let dh_bytes: [u8;32] = *dh.as_bytes();` and
  sender_keys/key_protocol.rs:347 same. hpke.rs core wraps every such copy in Zeroizing (lines 362/388/407);
  runtime forwarding regresses it. SharedSecret zeroizes on drop but the explicit byte copy escapes.
  Neither file imports Zeroizing. recovery.rs unwrap_psk plaintext Vec also unzeroed (key_bytes moved to SenderKey).
- NIT: scp-private-state-v1 string shared by PSK HPKE info (recovery.rs:661) AND private_state.rs:265
  routing-ID HKDF. NOT a real collision (different salt/labels/suite_id/layout; never same KDF invocation)
  but an audit smell.
- NIT: key_protocol_verify.rs:64 docstring omits length-prefixes from abbreviated info description;
  actual build_hpke_info (line 710) IS correctly BE32 length-prefixed.
- WASM interop: NO drift. scp-protocol (where hpke.rs lives) compiles wasm32 and WASM re-exports it
  (sender_key.rs:7). ADR-034 reimpl constraint is for scp-runtime/tokio, not scp-protocol HPKE.
- Custody open_with_external_dh soundness CONFIRMED: enc||pkRm bound into SS; wrong dh/pkRm/enc => clean
  AEAD tag failure only, no oracle (identical error string). custody_wrong_pkrm_fails proves pkRm binding.
- Invitation AAD removal of eph-pubkey SAFE: enc flows kem_context->SS->key; tampered_enc_fails proves it.
- Unplanned touches (platform/traits.rs, context/membership.rs): doc-comment-only (ECIES->HPKE), correct.

## Review-fix round APPLIED (2026-06-13, commits 6ef4a47/6d3153f/6448e05/f44ea06 on branch)
- FIX1 (zeroize regression) DONE: wire.rs open_access_key_response + key_protocol.rs
  open_sender_key_response now `Zeroizing::new(*dh.as_bytes())` and recovered plaintext Vec
  wrapped in Zeroizing; recovery.rs unwrap_psk_for_device plaintext wrapped too. Both files now
  `use zeroize::Zeroizing`. NOTE: &Zeroizing<[u8;32]> deref-coerces to &[u8;32] at the open call
  site (Zeroizing: Deref) — call sites unchanged, builds clean.
- FIX3 (stale docstring) DONE: key_protocol_verify.rs HPKE_INFO_PREFIX docstring now shows the BE32
  length prefixes matching build_hpke_info.
- FIX4 (field parity / bounded deser) DONE: AccessKeyResponse.hpke_sealed_key changed from
  Vec<u8>+serde_bytes to [u8;48] with serde_hpke_sealed_48 (matches SenderKeyResponse). VERIFIED
  invariant: AccessKey is [u8;32], open enforces 32-byte plaintext => ct always 48 (32+16 GCM tag).
  Producer converts seal Vec via try_into with explicit length-check error.
- FIX2 (broadcast test gap) DONE: added 4 ciphertext-level negatives to broadcast.rs tests:
  tamper-ct, tamper-enc, wrong-recipient, and cross-path domain sep (seal under sender-key info/aad,
  prove open_broadcast_key rejects at AEAD). Kept the assert_ne! builder tests. GOTCHA: pre-commit
  clippy hook enforces clippy::similar_names — subscriber_a/_b_secret rejected; renamed to
  recipient_secret/intruder_secret.
