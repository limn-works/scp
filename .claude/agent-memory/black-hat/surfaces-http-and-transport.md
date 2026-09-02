---
name: surfaces-http-and-transport
description: Attack surfaces in scp-node HTTP features (PR #195) and in transport expansion (commit 8873a54) — bridge secret exposure, blob existence oracle, owner_id collision, WASM Send/Sync unsoundness, cover-traffic budget oracle
metadata:
  type: project
---

# scp-node HTTP features (PR #195)

- **CRITICAL — bridge secret travels in plaintext over localhost TCP.** `crates/scp-node/src/http.rs:144` builds `ws://{relay_addr}/?token={token_hex}`, which a co-tenant sniffs.
- **HIGH — `.well-known/scp` URI injection through an unescaped context name.** `crates/scp-node/src/well_known.rs:42-48` interpolates a name into an `scp://` URI without percent-encoding.
- **HIGH — conditional GET bypasses a `routing_id` check, giving a cross-context blob existence oracle.** `crates/scp-node/src/projection.rs:570-578` runs an `If-None-Match` comparison before `routing_id` validation.
- **HIGH — context and projection registries are unbounded.** `crates/scp-node/src/dev_api.rs:405-421`: no `DefaultBodyLimit`, no maximum context count, no rate limit.
- **MEDIUM — dev API loopback check runs at a builder, not at a bind point.** `crates/scp-node/src/http.rs:319-343`: `serve()` binds `dev_addr` without revalidating `is_loopback()`.
- **MEDIUM — routing-id enumeration through timing plus a 404/200 oracle.** `crates/scp-node/src/projection.rs` `feed_handler`. `SHA-256(context_id)` is deterministic and publicly computable.
- **MEDIUM — broadcast keys cloned without zeroization.** `crates/scp-node/src/projection.rs:414, 594`.

Confirmed sound: bearer token comparison via `subtle::ConstantTimeEq`; bridge
secret comparison via `ct_eq` at relay level; 128 bits of token entropy from
`OsRng`; token masked in logs to a prefix; hex-only context-id validation
blocking injection; blob `routing_id` cross-check in `message_handler`; feed
limit clamped to 100; `#![forbid(unsafe_code)]` on scp-node.

# Transport expansion (commit 8873a54)

- **HIGH — `owner_id` collides across transports (BLACK-201).** QUIC, WebTransport, and WebSocket each keep an independent `AtomicU64` starting at 1, while `SubscriptionRegistry` treats `owner_id` as a sole identity for cleanup and removal. After a relay restart, session 1 over QUIC and session 1 over WebTransport collide. `webtransport/server.rs:153`, `quic/listener.rs`, `relay/subscription.rs`.
- **HIGH — WASM `SendSyncWrapper` is unsound under `SharedArrayBuffer` (BLACK-202).** `webtransport/client.rs:80-95` writes `unsafe impl Send/Sync` for JsValue types, resting on "WASM is single-threaded". No runtime guard detects `SharedArrayBuffer`, so enabling it yields undefined behavior with no compile-time or runtime signal.
- **HIGH — WebSocket `backfill_complete` broadcasts to every subscription (BLACK-203).** `webtransport/client.rs:1273-1288` sends an event carrying `ref_id: None` to every subscription sender, so a malicious relay truncates any subscription's backfill.
- **HIGH — cover-traffic budget degradation is a traffic-analysis oracle (BLACK-204).** `cover_traffic.rs:298-338`. A stepwise Full → Reduced → Off transition is observable on a wire, a 60-second period reset creates a synchronized burst, and budget-exhaustion timing reveals real traffic volume.
- **MEDIUM — `active_subscriptions` is never pruned on unsubscribe (BLACK-205).** `webtransport/session.rs` `handle_unsubscribe_inner` removes an entry from a registry and from `my_subscriptions`, never from `active_subscriptions`. Memory grows with subscribe/unsubscribe frequency.
- **MEDIUM — QUIC adapter lifecycle manager is never read after connect (BLACK-206).** `quic/adapter.rs` stores a `lifecycle` field and reads it nowhere, so no reconnection and no health monitoring exist and a network disruption is permanent.
- **MEDIUM — HTTP/3 `serve()` has no rate limiting (BLACK-208).** `http3/adapter.rs:195-293`: no `ConnectionTracker`, no per-IP limit, unbounded task spawning, unlike QUIC and WebTransport listeners.
- **CORRECTNESS — WebSocket QUERY clobbers an existing subscription (CA-3).** `webtransport/client.rs:1106-1154`: `query()` over WebSocket runs `HashMap::insert(routing_id, tx)`, overwriting an existing subscription, and query cleanup then removes it entirely.

Confirmed sound: 0-RTT disabled in HTTP/3 config (`http3/config.rs:364-370`);
512 KB frame-size validation on client and server paths; server-side blob size
and TTL validation in a WebTransport session handler; `PublishRateLimiter`
shared per-IP across transports; delivery jitter breaking timing correlation
(BLACK-001 mitigation); session cleanup correctly scoped by `owner_id` inside a
single transport; TLS enforced on every transport; connection tracking on QUIC
and WebTransport listeners.
