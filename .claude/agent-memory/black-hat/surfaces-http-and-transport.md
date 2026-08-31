---
name: surfaces-http-and-transport
description: Attack surfaces in the scp-node HTTP features PR #195 and the transport expansion commit 8873a54, plus the controls that held
metadata:
  type: project
---

## Key Attack Surfaces -- HTTP Features (PR #195)

### CRITICAL: Bridge secret in plaintext over localhost TCP
- File: `crates/scp-node/src/http.rs` line 144
- `ws://{relay_addr}/?token={token_hex}` -- co-tenant can sniff

### HIGH: .well-known/scp URI injection via unescaped context name
- File: `crates/scp-node/src/well_known.rs` lines 42-48
- Name interpolated into scp:// URI without percent-encoding

### HIGH: Conditional GET bypasses routing_id check (cross-context oracle)
- File: `crates/scp-node/src/projection.rs` lines 570-578
- If-None-Match check before routing_id validation = blob existence oracle

### HIGH: Unbounded context/projection registry (no max count, no rate limit)
- Dev API: `crates/scp-node/src/dev_api.rs` lines 405-421
- No DefaultBodyLimit, no max context count

### MEDIUM: Dev API loopback check only at builder, not at bind point
- File: `crates/scp-node/src/http.rs` lines 319-343
- serve() binds dev_addr without revalidating is_loopback()

### MEDIUM: Routing ID enumeration via timing + 404/200 oracle
- File: `crates/scp-node/src/projection.rs` feed_handler
- SHA-256(context_id) is deterministic and publicly computable

### MEDIUM: Broadcast keys cloned without zeroization
- File: `crates/scp-node/src/projection.rs` lines 414, 594

## Patterns Confirmed Working (HTTP Features)
- Bearer token uses subtle::ConstantTimeEq (correct)
- Bridge secret uses ct_eq at relay level (correct)
- Token entropy: 128 bits from OsRng (sufficient)
- Token masked in logs (only prefix shown)
- Context ID hex-only validation prevents injection
- Blob routing_id cross-check in message_handler
- Feed limit clamped to 100
- #![forbid(unsafe_code)] on scp-node

## Key Attack Surfaces -- Transport Expansion (commit 8873a54)

### HIGH: owner_id collision across transports (BLACK-201)
- Three independent AtomicU64 counters (QUIC, WebTransport, WebSocket) all start at 1
- SubscriptionRegistry uses owner_id as sole identity for cleanup/removal
- After relay restart, session 1 via QUIC and session 1 via WebTransport collide
- Files: webtransport/server.rs:153, quic/listener.rs, relay/subscription.rs

### HIGH: WASM SendSyncWrapper unsound under SharedArrayBuffer (BLACK-202)
- File: webtransport/client.rs lines 80-95
- `unsafe impl Send/Sync` for JsValue types, safety relies on "WASM is single-threaded"
- No runtime guard against SharedArrayBuffer multi-threading
- If SAB enabled, instant UB -- no compile-time or runtime detection

### HIGH: WebSocket backfill_complete broadcast to ALL subscriptions (BLACK-203)
- File: webtransport/client.rs lines 1273-1288
- Event with ref_id: None broadcast to every subscription sender
- Malicious relay can truncate any subscription's backfill

### HIGH: Cover traffic budget degradation = traffic analysis oracle (BLACK-204)
- File: cover_traffic.rs lines 298-338
- Stepwise Full->Reduced->Off creates observable pattern on wire
- 60-second period reset creates synchronized burst pattern
- Budget exhaustion timing reveals real traffic volume

### MEDIUM: active_subscriptions Vec never pruned on unsubscribe (BLACK-205)
- File: webtransport/session.rs handle_unsubscribe_inner
- Unsubscribe removes from registry + my_subscriptions but NOT active_subscriptions
- Memory leak proportional to subscribe/unsubscribe frequency

### MEDIUM: QUIC adapter lifecycle manager never used after connect (BLACK-206)
- File: quic/adapter.rs -- lifecycle field stored but never read
- No reconnection, no health monitoring, network disruption = permanent death

### MEDIUM: HTTP/3 serve() has no rate limiting (BLACK-208)
- File: http3/adapter.rs lines 195-293
- No ConnectionTracker, no per-IP limits, unbounded task spawning
- Unlike QUIC/WebTransport listeners which have full rate limiting

### CORRECTNESS: WebSocket QUERY clobbers existing subscription (CA-3)
- File: webtransport/client.rs lines 1106-1154
- query() over WS does HashMap::insert(routing_id, tx), overwrites existing sub
- After query cleanup, original subscription is gone entirely

## Patterns Confirmed Working (Transport Expansion)
- 0-RTT correctly disabled in HTTP/3 config (http3/config.rs:364-370)
- Frame size validation at 512KB in both client and server paths
- Blob size/TTL validated server-side in WebTransport session handler
- PublishRateLimiter shared across transports (per-IP)
- Delivery jitter breaks timing correlation (BLACK-001 mitigation)
- Session cleanup correctly scoped by owner_id (within single transport)
- TLS enforced on all transports (QUIC/rustls, WASM/wss:// or https://)
- Connection tracking on QUIC and WebTransport listeners (per-IP + total)

