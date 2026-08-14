---
name: adr049-9b-joiner-send-h1-gate
description: ADR-049 §9(b) joiner-send — §9.16 H1 gate switched to MLS members(), store_member_sender_key ingest, §9.17 harness pull. SOUND.
metadata:
  type: project
---

# ADR-049 §9(b) joiner-send crypto review — SOUND (branch chore/adr049-2f-residual @8acbd3cbb vs origin/main)

**Why:** §9(b) requires a Welcome-joiner to actually SEND (not just receive). Old H1 gate `member_wrapping_keys.contains_key` made joiner permanently receive-only (empty cache) — the bug §9(b) closes.

**How to apply:** Reference when reviewing further §9.16/§9.17 pull-protocol or the deferred production actor-loop wiring (#2049 §9.16 pull, #2050 §9.17 distribution, #2051 spec↔ADR reconcile).

## Verdict: both crypto changes SOUND + spec-aligned. No new bypass, no weakened check, no gamed test.

### §9.16 H1 gate → MLS members() (provider.rs:1782-1817)
- Spec §9.16.6 Mitigation-1: requester MUST be CURRENT MLS member. New code DID-matches over `state.mls_group.members()` (BasicCredential→ScpCredential→.did), SAME pattern as remove_member (:1278-1292).
- STRICTLY STRONGER than old cache: old member_wrapping_keys was over-permissive (stale removed-member cache could pass) AND under-permissive (joiner empty map). Tree = authoritative; non-member can't appear (MLS validates leaf creds on Add). Fail-closed parse (malformed cred just doesn't match).
- Ordering: sig→freshness→nonce-replay→membership→blocked-DID→seal. Blocked check still AFTER membership (:1819) — blocked-not-removed member (still in tree) caught by block check.
- Seal UNCHANGED, still ephemeral §9.16.2: seals to request.wrapping_pubkey, epoch=state.sender_key_epoch (:1830-1838).

### store_member_sender_key (provider.rs:1689-1717)
- Store-half of pull ingest. LINE-EQUIVALENT defenses to push-path process_incoming_sender_key (:1648-1659): MAX_EPOCH_ADVANCE poisoning guard + set_checked monotonicity. HPKE-open (AEAD tag + ctx/sender/epoch binding) done by CALLER (open_sender_key_response) BEFORE store — key never injected blind.

### wrapping_extension.rs (:145-190) — CORRECTS prior over-claim
- openmls 0.8.1 exposes NO public way to read a REMOTE member's LeafNode extensions (export_ratchet_tree no public node iter; full_leaves pub(crate) on TreeSync; members() yields Member w/o extensions). extract_member_wrapping_key returns MemberNotFound for remote — behavior unchanged, comment now truthful. Pull carries ephemeral inline ⇒ no remote stable-key lookup needed. DO NOT assume openmls exposes remote leaf ext.

### §9.17 harness pull_access_keys_from_creator (scp-testing node.rs:609-694) — REAL crypto, not gamed
- Uses real wire.rs request_access_key→handle_access_key_request→open_access_key_response. Domain sep correct: HPKE_INFO_PREFIX b"scp-access-key-v1" (wire.rs:47), build_hpke_info/aad = prefix||BE32(len ctx)||ctx||BE32(len member_did)||member_did||epoch_BE (§9.17.1 exact). Ephemeral wrapping keypair FRESH per iteration (new InMemoryKeyCustody in loop, dropped at end); self.signing_key only SIGNS request not wraps. Seam = test_install_access_key final store (deferred prod #2050).
- §9.16 harness incumbents_pull_joiner_sender_key (:702-822): real round trip thru provider.handle_sender_key_request (the new members() gate), ctx_id_hex binding consistent seal/open. Exactly the scenario the gate unblocks.

### Test-seam containment: TestInstallAccessKey (commands.rs:390), dispatch (messaging.rs), Supervisor::test_install_access_key + provider.wrapping_keypair_snapshot all cfg(feature="testing")/cfg(test) — unreachable from prod FFI. Wrapping SECRET never leaves provider in prod.

## INFORMATIONAL (pre-existing, NOT introduced here) — pin on #2049
handle_sender_key_request verifies request sig against CALLER-SUPPLIED requester_public_key, gates membership on request.requester_did. Sig binds requester_did (SCP-KEY-REQUEST-V1 preimage, key_protocol_verify.rs:988). Soundness ⇒ caller MUST resolve requester_public_key from requester_did's DID document, NOT trust a key in the request. If #2049 actor-loop trusts attacker key + attacker-chosen requester_did of a real member ⇒ non-member bypasses gate. Harness resolves via did_to_seed (safe). Make explicit acceptance criterion on #2049. Orthogonal to this diff (which strengthened the gate).
