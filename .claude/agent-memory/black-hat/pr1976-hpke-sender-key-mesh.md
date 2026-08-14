---
name: pr1976-hpke-sender-key-mesh
description: Black-hat impl review of #1976 (ADR-057 T4 HPKE sender-key distribution mesh over scp_wrapping_key) — code-sound, no exploitable findings
metadata:
  type: project
---

# #1976 HPKE sender-key distribution mesh (branch feat/1976-sender-key-distribution)

Reviewed HEAD 52f22be4a atop 03d37fc1f on base 17100c35b. Correct range = 15 files
(14 rust + 1 ADR-057.md). scp-protocol UNCHANGED (reuses audited sender_keys primitives).
Files: scp-client/{crypto_state,client,context}.rs, scp-mls/{encrypt,group}.rs,
scp-client-wasm/lib.rs (pure delegation, no independent crypto).

## Verdict: code-sound. No exploitable findings. Design claims hold in the code.

### 1:1 alignment (added_dids ↔ added_wrapping_keys) — AIRTIGHT
- `recover_added_members_pre_merge` (scp-mls/encrypt.rs ~588) pushes DID + wk together
  per Add proposal in ONE loop iteration. Any per-proposal failure (bad Lifetime, or
  missing scp_wrapping_key ext → INVARIANT 3 fail-closed) returns Err → whole Commit
  dropped unmerged (epoch unchanged). So the two vecs are equal-length on success or the
  Commit never constructs. The `zip` in client.rs receive_message Commit arm (~927) reads
  from that single source → cannot pair member X's slot with member Y's key.
- Verified by tests/sender_key_distribution.rs::three_party_bob_adds_carol_full_mesh —
  Bob adds Carol, Alice (bystander) seals to Carol, full 3-party mesh decrypt.

### Adder-supplied directory — bounded to self-DoS, NOT impersonation (as designed)
- Documented residual client.rs:638-654. Directory (member_wrapping_keys) is used ONLY
  for OUTBOUND sealing. INBOUND install (`install_incoming_distribution`) attributes the
  key to `response.sender_did` AFTER checking `response.sender_did == mls_sender_did`
  (the MLS-authenticated frame sender). An attacker can NEVER get a key attributed to a
  victim DID. Adder-directory substitution → joiner seals to wrong wk → victim can't
  decrypt joiner (availability downgrade), re-drive/pull residual. Adder gaining joiner's
  sender key is not compromise (adder is entitled to it as a member); can't impersonate
  without joiner's MLS signing key.
- Bystander/adder triggers read wk from VALIDATED KeyPackage/Add proposal, not directory.

### Epoch attacks — sound
- set_checked (scp-protocol sender_keys/mod.rs:359) rejects epoch <= current → stale-over-
  fresh + same-epoch replay rejected. Ceiling = saturating_add(MAX_EPOCH_ADVANCE=1000)
  rejects u64::MAX. rotate uses checked_add. All BEFORE tracker/store mutation.

### Ratchet-tree fix (join_group_from_bytes) — no new SCP trust surface
- Only sets LOCAL join config use_ratchet_tree_extension(true) so THIS member's FUTURE
  Welcomes embed the (public) tree. Incoming Welcome still validated by openmls vs signed
  GroupInfo tree-hash. SCP reads wk from validated KeyPackages, never remote tree leaves.

### Mgmt/app confusion — two independent guards; even full break = self-DoS only
- SCPM_MAGIC = 53 43 50 4D. App frame prefix = high 4 bytes of 8B-BE sender-key epoch.
- Guard 1: disjointness holds for all epoch < 2^32 (honest epochs tiny).
- Guard 2: sender_did binding in install is airtight regardless of classification.
- Can't inject a key under victim DID (guard 2); can't suppress victim's msg (victim
  controls own epoch, unreachable SCPM band = 0x53435044_00000000 ≈ 6e18 rotations).

## LOW / informational (not exploitable)
- Disjointness comments (crypto_state.rs:110-113, ~744; test at ~1096) state the
  invariant as universal ("epoch ≥ 1 → first 4 bytes 00 00 00 00"); precise only for
  epoch < 2^32. Unreachable + guarded by sender_did binding, so cosmetic. Could tighten
  wording or assert epoch < 2^32.

## Enforcement/CI: nothing touched in range. Nothing weakened.
