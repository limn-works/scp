---
name: adr057-t4-sender-key-distribution
description: ADR-057 T4 in-tab HPKE sender-key distribution (#1976) crypto review — SOUND, seal/open flow, wrapping keypair, ratchet-tree fix
metadata:
  type: project
---

# ADR-057 T4 — In-tab HPKE sender-key distribution (#1976, branch feat/1976-sender-key-distribution)

Reviewed 2026-07 at 52f22be4a/03d37fc1f on base 17100c35b. Verdict: SOUND, no blocking findings.

**Why:** Closes the sender-key DISTRIBUTION gap left by prior slices (members exchanged §9.16 sender keys out-of-band via test seams). Each member HPKE-seals its per-member AES-256 sender key to peers' STABLE X25519 wrapping keys (published in the `scp_wrapping_key` MLS leaf extension, type 0xFF01), delivered as MLS-authenticated SCPM-prefixed management frames.

**How to apply:** finding_hpke_not_rfc9180 memory is CONFIRMED STALE — the seal/open here is the SHARED `scp_protocol::crypto::sender_keys` (hpke_seal_sender_key/hpke_open_sender_key over RFC 9180 hpke). Do NOT re-raise custom-ECIES.

Key files: crates/scp-client/src/crypto_state.rs (seal_sender_key_distribution / install_incoming_distribution / rotate_sender_key), client.rs (3-trigger mesh), scp-mls/src/{group.rs,encrypt.rs,wrapping_extension.rs}.

## Soundness notes (all verified SOUND)
- **install_incoming_distribution ordering** (crypto_state.rs:518): (1) sender-DID binding response.sender_did==mls_sender_did, (2) epoch ceiling stored_high_water+MAX_EPOCH_ADVANCE(1000), (3) HPKE open with own wrapping_secret, (4) set_checked monotonic — ALL before store mutation. A member can only distribute its OWN key (sealer MLS-encrypts frame → mls_sender_did==sealer==response.sender_did). No cross-member forgery. epoch is AEAD-authenticated (bound in info+aad), so response.epoch can't be tampered without breaking open.
- **Poisoning is self-only:** sender_did==mls_sender_did means a member can only advance its OWN key's high-water; cannot poison another sender's tracker.
- **Wrapping keypair:** generate_wrapping_keypair = X25519 StaticSecret::random_from_rng(OsRng). Stable across MLS epochs (correct per §9.16.1; FS is from MLS beneath). wrapping_secret in Zeroizing (zeroized on drop). ContextCryptoState has NO Debug derive → can't leak. Snapshot v3 persists it, Debug="[REDACTED]", zeroize_secrets + std::mem::take-with-zeroed-placeholder on restore.
- **Ratchet-tree fix (group.rs:996):** join_group_from_bytes gained use_ratchet_tree_extension(true) to MIRROR create_group (group.rs:370). Cryptographically standard RFC 9420 (tree authenticated via signed GroupInfo tree_hash). CONFINED TO scp-mls (browser) — native scp-runtime uses its OWN openmls join (crypto/mls/), does NOT call scp_mls join_group_from_bytes → ZERO native KAT/wire impact.
- **Fail-closed INVARIANT 3:** Add whose KeyPackage leaf has no scp_wrapping_key extension rejected pre-merge (adder: key_package_in_wrapping_key; bystander: recover_added_members_pre_merge via `?`, drops staged commit unmerged, group stays on epoch). extract_wrapping_key length-validates exactly 32 bytes (no panic).
- **3-trigger mesh:** (1) adder→joiner seals from validated KeyPackage; (2) joiner→existing seals to adder-transported directory (the self-certifying residual); (3) bystander→joiner seals from validated Add-proposal leaf. Triggers 1&3 read authenticated wrapping keys; only trigger 2 trusts the adder directory.
- **member_wrapping_keys directory IS the member set** (INVARIANT 1) — removed parallel `members: Vec<String>`, no drift.
- **Disjointness:** SCPM_MAGIC=[53 43 50 4D]; app frame first 4 bytes = high bytes of BE u64 sender-key epoch≥1 = 00000000. Single magic check at MLS-plaintext boundary. Double size guard (MAX_MANAGEMENT_PAYLOAD_SIZE 64KiB on seal+open, MAX_SENDER_KEY_MESSAGE_SIZE 64KiB in from_bytes).

## LOW / informational (non-blocking)
- **L1 (hardening):** generate_wrapping_keypair returns raw [u8;32]; the transient Copy-type local bindings in create_context / generate_key_package_for_join (and the keygen return value itself) are not zeroized — only the persistent holders (Zeroizing / PersistedPendingJoin Drop) are. Inherent to a [u8;32]-returning keygen API + Rust Copy semantics; same shape native uses. Persistent copies are correctly wiped.
- **L2 (consistency):** adder-transported wrapping_keys directory is not cross-checked against the replayed event-log MemberJoined set. Advisory-only (MLS is authoritative for decrypt); documented as the §23.13 leaf-signing residual. Worst case = availability downgrade / phantom directory entry, NOT confidentiality break.
- **INFO:** disjointness claim "epoch≥1→00000000" holds only for epoch<2^32; infeasible to reach given MAX_EPOCH_ADVANCE=1000 monotonic increments. Same assumption as native.
