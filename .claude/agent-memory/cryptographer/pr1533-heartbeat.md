# #1533 Heartbeat send/receive (§9.9.2) — APPROVE (2026-06-15)

branch feat/1533-heartbeat-loop

## Construction
- Heartbeat = MessageType::Heartbeat discriminator **5** (envelope/inner/mod.rs:103).
- Discriminator IS in the signed canonical hash, field 2 (after version) at mod.rs:548 — type-flip defense (issue #290). NO downgrade/type-confusion with other MessageTypes.
- NOTE: corrects prior memory "as_discriminator_byte exists but NOT used" — it IS used now.

## Send path
- send_heartbeat (messaging_helpers.rs:1431) routes through `encrypt_and_send` exactly like send_checkpoint: MLS + sender-key + Ed25519. Empty payload `&[]`, sequence `0`.
- Routing mirrors app-data: broadcast contexts -> broadcast_routing_id; encrypted -> peer pseudonym fan-out; empty peer set = legit no-op.
- Driven by FFI subscribe-loop scheduler (run_heartbeat_scheduler in scp-ffi-common/heartbeat_scheduler.rs), per-profile cadence via Supervisor::send_heartbeat.

## Receive path
- verify_and_unwrap (sig + integrity) runs at deliver_incoming:1099 BEFORE heartbeat classification at :1126. So an inbound heartbeat reaching DeliverOutcome::Heartbeat was MLS-authenticated + Ed25519-verified — relay cannot forge.
- Classified before sequence tracker (like checkpoint) -> never advances per-sender app sequence, never surfaced as content.
- DeliverOutcome enum replaces Option<(Vec,String)>: Application/Heartbeat/Handled.
- deliver_commit_blob (reconnect catch-up) collapses Heartbeat|Handled -> None. Correct.

## Key handling
- SigningKeyBytes(Zeroizing<[u8;32]>) (commands.rs:501); from_signing_key copies seed (to_bytes), to_signing_key = from_bytes (RFC 8032 seed semantics, matches reference).
- Resolved from local custody (resolve_napi_signing_key -> export_ed25519_signing_key), passed INWARD via actor command. Never crosses FFI outward. Matches send_message per-call pattern.

## Empty-payload soundness
- wrap_content(&[]) -> AES-GCM seal of 0-byte plaintext (valid). payload_hash = SHA256(wrapped_bytes), wrapped struct never empty -> signature always well-defined. No malleability (empty payload committed via wrapped hash + discriminator byte).

## Replay (seq-0)
- Heartbeats bypass the inner-envelope sequence tracker (same as checkpoints), but MLS epoch/generation AEAD rejects stale replays at decrypt_and_dispatch BEFORE classification. Replay surface bounded identically to checkpoints. Sound.

## Other
- HeartbeatConfig::for_profile (heartbeat.rs): Server/Desktop 60s, Mobile 120s, Constrained None. Single source of truth shared by send-scheduler + receive-monitor — cadence cannot drift from threshold. Native adapter refactored to use it (no logic change).
- record_heartbeat_received: trait default no-op (traits.rs), TransportManager fans out to all adapters, NativeRelayAdapter refreshes HeartbeatMonitor baseline.
- pipeline_wiring b3_heartbeat_send_receive_loop_wired: 6 real call-site asserts; ratchet 41->42 (expansion, compliant with enforcement rule).
- handle_seed_peer_pseudonym + SeedPeerPseudonym variant both #[cfg(feature="testing")] — consistent gating, no non-testing compile break.

## No findings. Wire/canonical-hash change limited to the new discriminator append — forward-compatible.
