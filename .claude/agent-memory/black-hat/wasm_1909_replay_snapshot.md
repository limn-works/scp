---
name: wasm-1909-replay-snapshot
description: #1909 P2 WASM sender-layer — replay tracker in cross-party signed export bypasses MAX_EPOCH_ADVANCE ceiling; native drops it (divergence)
metadata:
  type: project
---

# #1909 Phase 2 WASM sender-layer convergence — black-hat findings (commit 6952efad)

Target: crypto/state.rs (WasmCryptoState), manager.rs (import/export/seed), scp-protocol sender_keys.

## What is SOUND (verified by probes + reading)
- Header parse rejects <16 bytes (parse_sender_header). AAD is length-prefixed (no ctx/DID boundary confusion). Header epoch/seq feed AAD → any header tamper fails AEAD (cross-family conformance test proves epoch+1 header breaks AEAD).
- Receive path: ceiling enforced BEFORE replay tracker; tracker recorded ONLY after successful decrypt; failed/undecryptable msg does NOT advance tracker. Per-sender isolation correct.
- u64::MAX epoch header rejected by ceiling, tracker not poisoned. saturating_add ceiling (no wrap). Rotation epoch advance saturating.
- Version gate STRICT (==WASM_EXPORT_VERSION=6): v5 downgrade rejected outright (can't drop tracker by downgrade). replay_state is INSIDE the Ed25519-signed JCS snapshot preimage → tamper fails verify_strict (tampered_replay_state_fails_import test).
- Vector 5 CLOSED: context_decrypt_message dropped epoch/seq wasm-bindgen args entirely; header is sole source. No stale-arg caller path.

## THE FINDING (BLACK-1909-01) — MEDIUM, design-level
WASM persists recv_sequence_tracker + per-sender epoch high-water in the PORTABLE CROSS-PARTY signed export envelope and seeds it VERBATIM on import via restore_replay_state → restore_epoch_high_water (UNGUARDED) — NOT merge_incoming_epochs (which enforces the §9.16.1 MAX_EPOCH_ADVANCE ceiling under MergePolicy::RejectRegression).

Consequence: a malicious-but-valid context CREATOR (or compromised creator key) can craft a signed export whose replay_state targets ARBITRARY THIRD-PARTY sender DIDs and:
1. high-water = u64::MAX for victim sender → permanently wedges that sender's future set_checked rotations on the importer (deliverability DoS).
2. recv tracker = (u64::MAX,u64::MAX) for victim → importer permanently drops victim's real messages (targeted censorship).
3. recv tracker = (0,0) → re-opens replay of previously-seen messages.
Seed fires at manager.rs:2495 on encrypted (Welcome) rejoin after import. import_context does NOT require importer==creator; only blocks duplicate context_id.

### Why it matters (native divergence — the #1877 goal is to MATCH native)
Native's PORTABLE export (export_import.rs:819-820) EXPLICITLY DROPS the freshness/replay cache: "B's freshness/replay cache has no authority on a foreign node and a fresh node starts its own replay window." Native only persists the tracker on the TRUSTED-LOCAL restore_crypto_state path (rmp_serde local bytes, crash recovery — reconstructs real MLS group). Spec §9.16.1 line 1260: "The tracker is persisted in the crypto state snapshot" = the LOCAL crypto snapshot, not the portable envelope.

WASM has no local-restore path (ADR-034 ephemeral). Putting the tracker in the cross-party envelope is a defensible workaround BUT (a) diverges from native (the convergence goal), (b) makes receive-side replay state attacker-controllable across the trust boundary native tears down, (c) BYPASSES the §9.16.1 epoch-poisoning ceiling (line 1262) on the seed path.

### Minimal fix options
- Route the parked seed through merge_incoming_epochs(MAX_EPOCH_ADVANCE, RejectRegression) for the epoch high-water (closes the u64::MAX wedge), AND/OR
- Match native: DROP recv_sequence_tracker from the portable export and start a fresh receive window on import (cleanest, native-convergent). Sender_key_epoch high-water for ROLLBACK protection could still ride along but ceiling-guarded.
- At minimum cap/validate replay_state on import (currently only nonce timestamps are clamped + antispam validated; replay_state is unvalidated, bounded only by 16 MiB envelope).

Probe file (throwaway): tests/bh_probe_1909.rs in worktree — 11 passing probes, P4_* demonstrate the bypass/censorship/replay-reopen.

## Verdict: GO-WITH-CHANGES. Core crypto sound; the snapshot-seed ceiling bypass + native divergence is the one real item.
