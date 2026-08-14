---
name: adr057-t4-sender-key-distribution-1976
description: Security review of #1976 in-tab HPKE sender-key distribution (ADR-057 T4) over scp_wrapping_key MLS extension — CLEAN
metadata:
  type: project
---

# #1976 ADR-057 T4 — In-tab HPKE sender-key distribution (CLEAN, 2026-07)

Range 17100c35b..52f22be4a. scp-client + scp-mls. Verdict: no blocking findings; ship.

Key files: crates/scp-client/src/crypto_state.rs (ContextCryptoState — the sequencer),
client.rs (driver: add_member/join_context_encrypted/receive_message/close_context/rotate),
context.rs (PerContextState — member Vec DELETED, unified into wrapping-key directory INVARIANT 1),
snapshot.rs (v3 persists wrapping keypair + directory), scp-mls/src/group.rs (key_package_in_wrapping_key),
scp-mls/src/encrypt.rs (recover_added_members_pre_merge, InboundChange::Commit.added_wrapping_keys).

**Sound properties (verified):**
- Sender-DID binding: install_incoming_distribution checks response.sender_did == mls_sender_did (authenticated MLS credential DID) FIRST, before ceiling/open/install. Member A cannot install a key attributed to B.
- Test/prod boundary: from_group, local_sender_key_bytes, insert_sender_key all #[cfg(test)] pub(crate); generate_wrapping_keypair import in crypto_state is #[cfg(test)]. ALL callers confirmed inside cfg(test) mods. Prod uses from_group_with_wrapping (caller-supplied keypair from published KeyPackage/leaf).
- Fail-closed missing wrapping ext (INVARIANT 3) at BOTH paths: adder = key_package_in_wrapping_key returns ExtensionError BEFORE any MLS mutation; bystander = recover_added_members_pre_merge `?` pre-merge, group stays on epoch (test asserts epoch unchanged). Real rejection, not warn-and-continue.
- Epoch DoS: MAX_EPOCH_ADVANCE=1000 ceiling enforced BEFORE tracker/store mutation on both install and app-decrypt paths. MAX_MANAGEMENT_PAYLOAD_SIZE=64KiB on seal+open. Attacker can only advance own DID slot.
- Key hygiene: wrapping_secret Zeroizing everywhere (crypto_state field, join-path copy line 612, restore 1371); PersistedPendingJoin has Drop zeroize; snapshot v3 zeroize_secrets + Drop wipes it. Debug redacts: Inbound::SenderKeyInstalled (did+epoch only), SenderKeyDistribution ([N bytes]), InboundChange::Commit ([N keys]).
- Ratchet-tree fix: join_group_from_bytes now use_ratchet_tree_extension(true) mirroring create_group. Only SCP leaf data = wrapping pubkey (public by design) + DID credential (known to members). No new secret exposed. Standard MLS.
- Enforcement files untouched.

**Documented residuals (correctly bounded, NOT new findings):**
- "Self-certifying directory" (join_context_encrypted ~L638-654): malicious adder can substitute existing member M's wrapping key in transported snapshot → joiner seals its key to a key M can't open → M can't read joiner (targeted within-group censorship/downgrade). No confidentiality escalation (adder already a full member with joiner's key). Auth source = signed leaf ext in Welcome-embedded ratchet tree, blocked only by openmls not exposing remote leaf extensions; lands with leaf-signing/custody slice §23.13. Triggers 1 (adder→joiner) & 3 (bystander→joiner) do NOT share the gap (read from validated KeyPackage/Add proposal).
- Offline re-drive gap: peer offline during push doesn't get key until future push (no pull path in MVP).

MLS-layer frame replay handled by MLS ratchet generation; sender-key store replay by set_checked monotonicity + recv_sequence_tracker. Magic disjointness: app epoch prefix 0x00.. (epoch>=1 BE) vs SCPM 0x53 — distinct.
