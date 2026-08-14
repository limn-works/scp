---
name: archive-pr-audits
description: Consolidated archive of black-hat findings from earlier PR/spec audits (PR #76, spec 22, PR #127, HTTP features #195, transport expansion, PR #1606, PR #1628, 2026-04-01 branch review). Historical — verify against current code before acting.
metadata:
  type: project
---

Historical findings. **Verify against current code before acting** — many are fixed.

## PR #76
- CRITICAL `claim_shadow()` does not verify signatures — `crates/scp-core/src/bridge/claiming.rs:206-218`; tests pass `vec![0u8; 64]`.
- CRITICAL PyO3 bridge skeleton, no crypto enforcement — `crates/scp-ffi/src/context.rs` (join/leave/send/close string-state stubs).
- HIGH Spending UCAN 24h `MAX_EXPIRY_SECS` never checked — `crates/scp-core/src/crypto/ucan/spending.rs`.
- HIGH Standing-channel TOCTOU — `crates/scp-core/src/context/standing.rs:166` (lock dropped before async create).
- HIGH `SenderVelocityTracker` accepts arbitrary timestamps — `crates/scp-core/src/economy/antispam.rs:153`.
- HIGH `SingleAdmin` TransferAdmin has no DID validation — `crates/scp-core/src/context/governance/mod.rs:503`.
- HIGH `TestAdapter` has no production exclusion — `crates/scp-testing/src/test_adapter.rs`.

## Spec 22 — human-readable addressing
- CRITICAL `MultiLayerCorroborated` gameable: one attacker holding domain + context + attestation reaches the top trust level; no independence check (§22.7, §22.8.2, §22.10.2).
- CRITICAL context-governance capture = total namespace hijack (§22.3.4).
- HIGH handle squatting, zero economic cost (§22.3.1); petname auto-creation permanent after one deception (§22.8.3-.4); all lookups DID-authenticated (§22.10.4); cache poisoning via stale-while-revalidate (§22.8.4).

## PR #127 (second pass, post-fix)
- CRITICAL WASM bridge UCAN validation missing steps 3-5, 7-9 — `crates/scp-ffi/wasm/src/ucan.rs`; self-signed DIDs pass.
- HIGH `context_close` auth bypass on NAPI/WASM/UniFFI (`let _ = identity_did`); PyO3 fixed only.
- HIGH broadcast UCAN validation skips all crypto — `crates/scp-core/src/context/broadcast.rs:423-442`.
- HIGH NAPI/UniFFI mint `[0u8; 64]` signature tokens with no `is_signed` indicator.
- MEDIUM nonce-replay TOCTOU (residual: crash-recovery window); cover-traffic 30s/1024B distinguishability; attestation renewal does not re-fetch external evidence.
- Confirmed sound: per-author broadcast key isolation, epoch overflow guard, key-material Debug redaction, scp-core 11-step UCAN pipeline, NAPI TLS enforcement, heartbeat suppression detection, broadcast wildcard rejection, Merkle equivocation detection.

## HTTP features (PR #195)
- CRITICAL bridge secret plaintext over localhost TCP — `crates/scp-node/src/http.rs:144` (`ws://…?token=`).
- HIGH `.well-known/scp` URI injection via unescaped context name — `crates/scp-node/src/well_known.rs:42-48`.
- HIGH conditional GET bypasses routing_id check (blob-existence oracle) — `crates/scp-node/src/projection.rs:570-578`.
- HIGH unbounded context/projection registry — `crates/scp-node/src/dev_api.rs:405-421`.
- MEDIUM dev-API loopback check only at builder; routing-id enumeration oracle; broadcast keys cloned without zeroization.
- Confirmed sound: `subtle::ConstantTimeEq` on bearer + bridge secret, 128-bit OsRng tokens, masked logs, hex-only context-id validation, blob routing_id cross-check, feed limit clamp, `#![forbid(unsafe_code)]`.

## Transport expansion (commit 8873a54)
- HIGH BLACK-201 `owner_id` collision across QUIC/WebTransport/WebSocket (three counters from 1; `SubscriptionRegistry` keys on it).
- HIGH BLACK-202 WASM `SendSyncWrapper` unsound under SharedArrayBuffer — `webtransport/client.rs:80-95`.
- HIGH BLACK-203 `backfill_complete` with `ref_id: None` broadcast to every subscription — `webtransport/client.rs:1273-1288`.
- HIGH BLACK-204 cover-traffic budget degradation is a traffic-analysis oracle — `cover_traffic.rs:298-338`.
- MEDIUM BLACK-205 `active_subscriptions` never pruned; BLACK-206 QUIC lifecycle manager never read; BLACK-208 HTTP/3 `serve()` has no rate limiting.
- CORRECTNESS CA-3 WebSocket QUERY clobbers an existing subscription — `webtransport/client.rs:1106-1154`.
- Confirmed sound: 0-RTT disabled, 512KB frame validation, server-side blob size/TTL, shared per-IP `PublishRateLimiter`, delivery jitter, TLS on all transports, per-listener connection tracking.

## PR #1606 — sender-key AAD, SCPM magic, timestamp bounds
- HIGH BLACK-1601 SCPM magic-prefix injection by any group member; BLACK-1602 no receive-side sequence tracking.
- MEDIUM BLACK-1603 access-key freshness widened 30s→300s; BLACK-1604 buffer-event timestamp estimation exploitable.
- Testing gap: `E2eCryptoProvider` hardcodes epoch=0, seq=0.

## PR #1628 — BridgeInstance extraction
See [pr1628-bridge-instance.md](pr1628-bridge-instance.md). BLACK-301 post-shutdown ghost ops; BLACK-303 placeholder-DID confusion; BLACK-308 rate-limiter ephemeral bypass; BLACK-309 economy unbounded growth.

## Branch review 2026-04-01 — consequence / economy / FFI
- CRITICAL BLACK-1706 `WarningCount` counts events *targeting* a DID, not actions *by* it → admin manufactures proposals to trigger automated eviction; `system_assign_role` bypasses the `RoleAssign` check; no recovery path.
- HIGH BLACK-1705 FFI string injection on NAPI+UniFFI (`format!("{other:?}")` unescaped; PyO3 escapes — parity gap).
- HIGH BLACK-1701 standing-score inflation (`evaluate_sybil_resistance` no-op; inflation computed before consequence evaluation); BLACK-1702 relay-pricing manipulation via velocity flooding (no per-member cap).
- MEDIUM BLACK-1703 escrow-capture failure harms operator (deliberate); BLACK-1704 `action_ucan=None` = "already verified" has no compile-time precondition.

## Refactoring plan adversarial analysis (2026-03-21)
See [refactor-plan-adversarial-analysis.md](refactor-plan-adversarial-analysis.md) — BLACK-301..311: facade divergence, Phase B TOCTOU, asymmetric wiring, BridgeInstance split-brain. Mitigations: generation counter, atomic send+receive wiring, CI mod/re-export check, feature-flagged BridgeInstance.

## Event-log substrate swap phase 2
See [eventlog_substrate_swap_phase2.md](eventlog_substrate_swap_phase2.md) — RFC6962 swap closed export forgery; equivocation detector false-positives under dormant cross-member replication; in-memory dedup wiped on respawn.
