# PR #1540 — Checkpoint Equivocation Sync + Reconnection Driver (reviewed 2026-06-14)

Branch: feat/1540-checkpoint-equivocation-sync. VERDICT: APPROVE (no blocking findings).

## Canonical checkpoint hash UNCHANGED (point 1 — SOUND)
- `ConsistencyCheckpoint` reconciled: scp-protocol/src/sync/mod.rs now `pub use scp_event_log::checkpoint::ConsistencyCheckpoint` (the pre-ADR-049 duplicate sync-local type DELETED).
- Signed bytes = `compute_checkpoint_canonical_hash` (checkpoint.rs:1143) — `SCP-CHECKPOINT-V1:` || 4-byte BE len-prefixed context_id || len-prefixed sender_did || event_count BE || merkle_root || epoch_flag(0x01/0x00) || epoch BE || timestamp BE. UNCHANGED by the merge.
- Adding `serde::{Serialize,Deserialize}` + `deny_unknown_fields` + `#[serde(with=serde_bytes)]` on `signature` does NOT affect signed bytes (signature field never in the hash). Field order identical to old sync type → msgpack wire byte-identical. Ed25519Signature=Vec<u8>, serde_bytes correct (msgpack bin).

## Equivocation detection (point 2 — SOUND)
- Old `sync::compare_checkpoints` free fn DELETED (had #1216 `epoch None ⇒ FullyCaughtUp` short-circuit defect; zero prod callers).
- Runtime path queries_helpers.rs:724 `compare_remote_checkpoint`: (1) membership check line 731, (2) resolve sender pk via deps.key_resolver line 739, (3) `verify_checkpoint_signature` (verify_strict over canonical) line 745 BEFORE any comparison, (4) equivocation keyed STRICTLY on equal event_count + different root (line 772-779) per §9.9.3. Sound.
- MINOR/LOW: line 773 uses `local_root == remote.merkle_root` (plain ==, not ct_eq); old sync code used ct_eq. No secret compared (root is public, divergence is published anyway) → not a vuln. Note only.

## Author/sender binding (point 4 — SOUND, defense in depth)
- Receive path messaging_helpers.rs:1040-1086: inner.context_id==context_id, inner.sender_did==MLS sender_did (credential-spoof defense line 1048), verify_and_unwrap (sig+AEAD+integrity) line 1069 BEFORE dispatch.
- Dispatch on `MessageType::ConsistencyCheckpoint` (=4) line 1084 — AFTER verify, BEFORE sequence tracker → checkpoint never advances per-sender app sequence (prevents seq-poison type confusion).
- deliver_checkpoint_message line 1147: CHECKPOINT_PAYLOAD_TAG="\0scp:checkpoint:v1" magic-tag check (line 1157), checkpoint.sender_did==envelope sender (line 1166). TRIPLE binding: MLS sender = inner.sender_did = checkpoint.sender_did + independent checkpoint Ed25519 sig.
- message_type IS bound into inner-envelope signature: compute_canonical_hash (envelope/inner/mod.rs:516) includes CanonicalField::U8(message_type.as_discriminator_byte()) line 534. CORRECTS old memory note that said discriminator unused in canonical hash — that was a DIFFERENT compute_canonical_hash. This inner-envelope one DOES use it. Captured Content envelope cannot be flipped to ConsistencyCheckpoint without breaking sig.

## Reconnection driver crypto (point 3 — SOUND)
- crates/scp-ffi/common/src/reconnect.rs: pure transport SEQUENCER. EVERY relay blob routes through `supervisor.deliver_commit_blob` → MessagingCommand::DeliverIncoming (supervisor.rs:5633) → SAME deliver_incoming path as live receive. NOT a privileged bypass. All MLS decrypt/verify/membership/integrity happen before any state advance. Relay material never trusted unverified.
- Phase 3 build_local_checkpoint signs over identical compute_checkpoint_canonical_hash (build_checkpoint queries_helpers.rs:661). Phase 5 issue_mls_update → advance_epoch → propose_update_with_wrapping_key (preserves scp_wrapping_key leaf ext §9.16.1, advances 1 epoch). Tier 2/3 snapshot/welcome bytes also fed through deliver_commit_blob.
- SigningKeyBytes(commands.rs:429) = zeroize::Zeroizing<[u8;32]> — zeroizes on drop through mailbox.
- LOW: RelayActorSyncDriver.signing_key is raw [u8;32] (not Zeroizing); doc says caller owns lifetime. Defense-in-depth: could wrap in Zeroizing.
- LOW/pre-existing: handle_issue_mls_update_actor mirrors state.epoch.mls_epoch via saturating_add(1) after advance_epoch; mirror could drift from true OpenMLS epoch if other paths don't update consistently. Checkpoint epoch is informational (equivocation keys on count+root), so not load-bearing.

## Enforcement
- pipeline_wiring.rs + bridge-aliases.json + sdk-capability-matrix.json changes are ADDITIONS (new coverage) — compliant with enforcement-file policy. RECONNECT_DRIVER_SRC include_str! assertion pins driver→checkpoint-exchange wiring.
