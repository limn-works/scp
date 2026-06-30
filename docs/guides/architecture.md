# Transport Layer Architecture

## Overview

SCP's transport layer is deliberately transport-independent. All relay communication flows through a single abstraction -- the `TransportAdapter` trait -- which defines five operations: `send`, `subscribe`, `unsubscribe`, `query`, and `delete`. Every adapter implementation, from the native WebSocket relay to QUIC to CoAP, implements this same trait. The protocol core never knows which transport is in use.

Relays are untrusted dumb pipes. They store and forward opaque, encrypted blobs. Context access control is enforced by MLS encryption, not relay logic. This means any blob-capable relay -- including existing Nostr relays -- can serve as SCP transport without modification.

The `TransportAdapter` trait (defined in `crates/scp-transport/src/traits.rs`):

```rust
pub trait TransportAdapter: Send + Sync {
    fn send(&self, envelope: &OuterEnvelope) -> BoxFuture<'_, Result<BlobId, TransportError>>;

    fn subscribe(
        &self,
        routing_id: &RoutingId,
        since: Option<u64>,
    ) -> BoxFuture<'_, Result<SubscriptionStream, TransportError>>;

    fn unsubscribe(&self, routing_id: &RoutingId) -> BoxFuture<'_, Result<(), TransportError>>;

    fn query(
        &self,
        routing_id: &RoutingId,
        since: Option<u64>,
    ) -> BoxFuture<'_, Result<Vec<OuterEnvelope>, TransportError>>;

    fn delete(&self, blob_id: &BlobId) -> BoxFuture<'_, Result<(), TransportError>>;
}
```

All methods return `BoxFuture<'_, ...>` rather than `Result<...>` directly. This is required for dyn-compatibility: `async fn` in traits is not object-safe, so each method wraps its async body in `Box::pin(async move { ... })`. `BoxFuture<'a, T>` is a type alias for `Pin<Box<dyn Future<Output = T> + Send + 'a>>`.

Every implementation is verified by the `transport_conformance!()` macro, which tests send/subscribe roundtrips, backfill, unsubscribe, query, delete, and deduplication.

---

## Transport Profiles

Transport profiles bundle connection strategy, cover traffic tier, relay count, reconnect behavior, and connection budget for a device class. The SDK infers a profile from the compilation target and exposes it as a configurable override. Profiles are the foundation of resource management -- every profile-aware component (cover traffic, connection pool, budget enforcement) reads its defaults from the active profile.

### Profile Definitions

| Profile | Connections | Cover Traffic | Min Relays | Reconnect | Max Connections |
|---------|------------|---------------|------------|-----------|-----------------|
| **`Server`** | Persistent to all assigned relays | `Full` (30s/1024B) | 3 | Aggressive (1-30s backoff) | Unlimited |
| **`Desktop`** | Persistent to all assigned relays | `Full` (30s/1024B) | 3 | Aggressive (1-30s backoff) | 50 |
| **`Mobile`** | Active contexts only; push bridge for inactive | `Reduced` (120s/256B) | 2 | Conservative (5-60s backoff) | 10 |
| **`Constrained`** | On-demand only; poll via QUERY | `Off` | 1 | None (poll-based) | 2 |

### When to Use Each Profile

- **`Server`** -- Always-on infrastructure: dedicated relay hosts, agent workstations, CI runners. No connection budget ceiling. Full cover traffic and suppression resistance. Use this for processes that run 24/7 and have no resource constraints.
- **`Desktop`** -- Laptops, desktops, browser tabs (wasm32 defaults here). Persistent connections with a 50-connection budget. Full cover traffic. Suitable for interactive use where the process has substantial memory but is not permanently online.
- **`Mobile`** -- iOS/Android devices. Proactively sheds connections for inactive contexts (5 min idle) and relies on push notification bridging (SS10.7) for wakeup. Reduced cover traffic (120s intervals, 256B padding) trades metadata privacy for battery life. Accepts reduced suppression detection (2-relay minimum) -- a 30s cross-check window with 2 relays detects suppression only when one relay is fully compromised, not when both selectively suppress.
- **`Constrained`** -- IoT, embedded, resource-limited devices. Single relay, no cover traffic, no suppression detection. Typically operates behind a gateway agent (a `Server` or `Desktop` participant) that bridges between the constrained device's local transport and the full SCP relay network. The gateway provides the suppression resistance, cover traffic, and real-time delivery that the constrained device cannot sustain.

### Platform Inference

The SDK selects a default profile using a two-stage strategy: compile-time target narrows the candidate set, then optional runtime heuristics refine within that set.

**Compile-time defaults:**
- `#[cfg(target_os = "ios")]` or `#[cfg(target_os = "android")]` -> `Mobile`
- `#[cfg(target_arch = "wasm32")]` -> `Desktop` (browser tabs behave like desktop)
- `#[cfg(target_os = "linux")]` -> runtime refinement (see below), fallback `Desktop`
- `#[cfg(target_os = "windows")]` or `#[cfg(target_os = "macos")]` -> `Desktop`

**Runtime refinement for Linux:**
- **Server detection:** No display server (`$DISPLAY` unset, `$WAYLAND_DISPLAY` unset) AND total system memory exceeds 2 GB -> `Server`. Catches headless VMs, containers, dedicated server processes.
- **Constrained detection:** Total system memory below 256 MB OR target arch is `arm`, `riscv32`, or `mips` -> `Constrained`. Catches Raspberry Pi Zero-class and smaller embedded devices.
- **Fallback:** Neither heuristic matches -> `Desktop`.

**Explicit override:** `.profile(TransportProfile::Server)` (or any variant) overrides all inference. Operators deploying SCP on Linux servers SHOULD set the profile explicitly.

### Cover Traffic Tiers

Cover traffic is the primary mechanism for metadata privacy (SS9.10.6). The `CoverTrafficTier` enum is tightly coupled to transport profiles -- each profile selects a default tier via `CoverTrafficTier::from_profile()`.

| Tier | Interval | Padding | Profile Mapping |
|------|----------|---------|-----------------|
| `Full` | 30s | 1024B | Server, Desktop |
| `Reduced` | 120s | 256B | Mobile |
| `Off` | -- | -- | Constrained |
| `Custom { interval, padding_bytes }` | User-specified | User-specified | Any (explicit override) |

Cover traffic dummy packets are structurally identical to PUBLISH operations. Over WebSocket, they are binary frames indistinguishable from real messages. Over QUIC, they are short-lived bidirectional streams identical in structure to PUBLISH streams -- the relay cannot distinguish dummy streams from real PUBLISH streams. One QUIC connection covers all streams, so cover traffic cost is amortized.

See spec **SS10.13** for full profile definitions and **SS9.10.6** for cover traffic security rationale.

---

## Adapter Tier System

Adapters are organized into three tiers by specification depth:

### Tier 1: Fully Specified

Wire format mapping, conformance suite, and fallback behavior defined. Must pass `transport_conformance!()`. All Tier 1 adapters use the same MessagePack wire format (ADR-004) -- the only differences are framing and connection lifecycle.

| Adapter | Transport | Feature Flag | Key Characteristic |
|---------|-----------|-------------|-------------------|
| SCP native relay | WebSocket (ADR-004) | Always enabled | Mandatory baseline. MessagePack binary frames over TCP. Single bidirectional channel with `ref_id` correlation. 30s PING/PONG keepalive. |
| QUIC | Per-operation QUIC streams | `quic` | No head-of-line blocking. Native keepalive (no PING/PONG). 0-RTT connection resumption. Connection migration on IP change. |
| WebTransport | HTTP/3 streams | `webtransport-wasm` | Browser equivalent of QUIC. Uses browser `WebTransport` API over HTTP/3. Falls back to WebSocket when unavailable. |
| UDP/DTLS | DTLS 1.3 datagrams | `udp` | Constrained devices. Connectionless. No SUBSCRIBE (poll via QUERY only). Session resumption via DTLS session tickets. |
| CoAP-over-DTLS | CoAP (RFC 7252) over DTLS | `coap` | IoT interoperability. CoAP framing maps POST/GET/DELETE to SCP operations. CoAP Observe (RFC 7641) for best-effort subscription. |

### Tier 2: Mapping Documented

Each adapter documents how the 5 `TransportAdapter` methods map to native primitives, plus connection model and key constraints. Sufficient for implementation without a full wire spec.

**12 adapters:** Nostr, Matrix, libp2p, Hyperswarm, WebRTC, MQTT, NATS, Tor, I2P, BLE, Yggdrasil/cjdns, ZeroMQ.

### Tier 3: Named

Feasibility confirmed through analysis. Spec pending.

**1 adapter:** SSB (gossip/append-only model diverges from SCP's request/response semantics).

**What this means for implementors:**
- Tier 1 adapters have everything needed for a conformant implementation. Start here.
- Tier 2 adapters have the method mapping and constraints documented. You know what to build; you decide the wire details.
- Tier 3 adapters need design work before implementation.

See spec **SS10.5.1** for tier requirements and **SS10.5.2** for Tier 2 mapping briefs. See [transport-adapters.md](transport-adapters.md) for a step-by-step implementation guide using MQTT as the walkthrough example.

---

## Tier 1 Transport Bindings

### SCP Native Relay (WebSocket)

The mandatory baseline. Every relay supports WebSocket. Every client can connect via WebSocket. This is the fallback for all other transports.

- **Framing:** MessagePack binary frames over a single bidirectional WebSocket connection.
- **Correlation:** Operations share the connection. Responses are matched to requests via `ref_id` field.
- **Keepalive:** Application-level PING/PONG at 30-second intervals (ADR-004).
- **Subscription:** `SUBSCRIBE` message on the shared connection. BLOBs arrive tagged with `routing_id`. Up to 100 subscriptions per connection.
- **Cover traffic:** Binary frames indistinguishable from PUBLISH. Per-profile tier (SS9.10.6).

### QUIC Transport Binding (SS10.14)

QUIC replaces WebSocket for native (non-browser) clients. Same relay, same MessagePack wire format, different framing. Each SCP operation gets its own QUIC stream -- no shared channel, no `ref_id` correlation needed.

**Operation mapping:**

| ADR-004 Operation | WebSocket | QUIC |
|---|---|---|
| PUBLISH | Binary frame on shared connection; correlate via `ref_id` | New bidirectional stream -> send PUBLISH -> receive ACK/ERR -> close stream |
| SUBSCRIBE | Binary frame; BLOBs arrive on shared connection | Long-lived bidirectional stream -> send SUBSCRIBE -> receive BLOBs until close |
| UNSUBSCRIBE | Binary frame | Close the subscription's stream (clean FIN) |
| QUERY | Binary frame; results arrive tagged with `ref_id` | New bidirectional stream -> send QUERY -> receive results + `query_complete` -> close |
| DELETE | Binary frame; correlate via `ref_id` | New bidirectional stream -> send DELETE -> receive ACK/ERR -> close |
| PING/PONG | WebSocket frames, 30s interval | Not needed -- QUIC native keepalive via PING frames (RFC 9000 SS19.2) |

**Connection lifecycle:**
1. **Initial connection.** TLS 1.3 built into QUIC -- no separate TLS handshake. Uses `quinn` crate.
2. **0-RTT resumption.** Session tickets stored locally. 0-RTT sends application data immediately without waiting for handshake completion. 0-RTT data has no replay protection (RFC 9001 SS9.2) -- SCP operations sent as 0-RTT must be idempotent or the relay must implement anti-replay.
3. **Connection migration.** When the client's IP changes (WiFi -> cellular), QUIC migrates the connection without closing it. Active subscription streams continue uninterrupted. Critical for mobile profiles.
4. **Reconnection.** Profile-aware exponential backoff (SS10.13.1). After reconnection, re-open subscription streams with `since = last_received_stored_at - 5s` overlap (same gap-fill as WebSocket).
5. **Keepalive.** QUIC native PING frame mechanism replaces WebSocket PING/PONG. No application-level keepalive needed.

**Client fallback:** If a relay does not advertise QUIC, clients fall back to WebSocket. The client MAY probe QUIC with a single initial packet; if no response within 3 seconds, it falls back without further QUIC attempts until the next `.well-known/scp` refresh.

### HTTP/3 and WebTransport (SS10.15)

HTTP/3 (QUIC-based HTTP) serves two roles: as the relay's HTTP upgrade path for all HTTP endpoints, and as the foundation for WebTransport.

**HTTP/3 upgrade path:**
- Relay serves HTTP/1.1 + HTTP/2 on TCP:443 (via ALPN) and HTTP/3 on UDP:443 (via QUIC ALPN `h3`).
- Clients discover HTTP/3 via `Alt-Svc` headers on HTTP/1.1 and HTTP/2 responses.
- All relay HTTP endpoints benefit: `.well-known/scp` (0-RTT on repeat visits), `/scp/dev/v1/*` (local dev API), `/scp/v1/feed/*` (broadcast projection).
- HTTP/3 is RECOMMENDED for public relays. Not required -- HTTP/1.1 remains the baseline.

**WebTransport for browser clients:**
- Browser opens `new WebTransport("https://<host>/scp/v1")` -- establishes HTTP/3 + WebTransport session.
- Same per-operation stream model as QUIC (SS10.14.1). Streams map identically.
- Server-side, relay handles both QUIC connections and WebTransport sessions -- both are QUIC underneath, sharing the same subscription registry and blob storage.

**Browser fallback chain:**
1. **WebTransport** -- attempt `new WebTransport(url)`. If the `WebTransport` API is unavailable (Safari, older browsers) or connection fails, fall through.
2. **WebSocket** -- fall back to `new WebSocket("wss://<host>/scp/v1")`. Mandatory baseline.
3. **Error** -- if WebSocket also fails, report connection failure.

The fallback is transparent to `TransportAdapter` callers. The browser client transport wraps both transports behind the same adapter interface. Mid-session upgrade from WebSocket to WebTransport is supported when the relay advertises WebTransport via `Alt-Svc`.

### Constrained Device Transport (SS10.16)

For IoT, embedded, and resource-limited devices that cannot sustain TCP connections. Two options are provided; implementors choose based on their ecosystem.

**MessagePack-over-DTLS (SCP-native, feature = `udp`):**
- DTLS 1.3 session with the relay. TLS 1.3 security guarantees apply.
- Each operation (PUBLISH, QUERY, DELETE) is an independent DTLS datagram (or datagram sequence for payloads exceeding path MTU).
- Session resumption via DTLS session tickets for 0-RTT reconnection. Connection IDs (RFC 9146) maintain associations across NAT rebinding.
- No SUBSCRIBE -- `subscribe()` returns `TransportError::NotSupported`. Constrained devices poll via QUERY.
- Max datagram size constrained by path MTU (typically ~1200 bytes; 6LoWPAN may be smaller). Recommended max blob size: 1024 bytes for single-datagram delivery.
- Relay MUST implement DTLS 1.3 `HelloRetryRequest` for address validation (anti-amplification, RFC 9147 SS5.1).

**CoAP-over-DTLS (IoT interop, feature = `coap`):**
- CoAP (RFC 7252) framing layer over DTLS. Interoperable with existing IoT infrastructure (CoAP proxies, LwM2M).
- Operation mapping: `POST /scp/{hex(routing_id)}` -> PUBLISH, `GET /scp/{hex(routing_id)}?since=...` -> QUERY, `DELETE /scp/{hex(routing_id)}/{blob_id}` -> DELETE.
- CoAP Observe (RFC 7641) provides lightweight best-effort subscription: server pushes new blobs as notifications, but may stop notifying at any time. Not equivalent to persistent SUBSCRIBE.
- Content-format: `application/msgpack` for SCP blobs.

**Constrained profile trade-offs:**

| Property | Full Profile (SS10.13) | Constrained Profile |
|----------|----------------------|-------------------|
| Cover traffic | Full or Reduced | Off |
| Suppression resistance | 3+ relays with cross-check | Single relay, no cross-check |
| Real-time delivery | Persistent subscription streams | Poll-based or CoAP Observe (best-effort) |
| Connection overhead | Persistent TCP/QUIC + keepalive | Connectionless UDP datagrams |
| Metadata privacy | Pseudonyms + padding + jitter | Pseudonyms only |

---

## Connection Model

### Connection Pool

The `ConnectionPool` (defined in `crates/scp-transport/src/pool.rs`) ensures at most one connection per relay per transport type. It is the central deduplication layer between `TransportManager` and the network.

- **Key:** `(relay_url, transport_type)` tuple. A single relay may have separate WebSocket, QUIC, and WebTransport connections, but at most one of each type.
- **Per-relay deduplication.** One connection per key, regardless of how many contexts use that relay.
- **Reuse on assignment.** When a context is assigned a relay that already has an active connection, no new connection is opened.
- **Cross-manager sharing.** Multiple `TransportManager` instances in the same process share connections via `Arc<ConnectionPool>`.
- **Subscription multiplexing.** Up to 100 subscriptions per connection (default, per ADR-004). For QUIC, each subscription is its own bidirectional stream within the single QUIC connection -- no head-of-line blocking.

### Context Isolation on Shared Connections

When multiple contexts share a connection to the same relay, isolation is maintained at three layers:

1. **Transport layer:** Each context subscribes under its own `routing_id`. The relay delivers BLOBs tagged with the matching `routing_id`, and the client demultiplexes by this field. For QUIC, each subscription gets its own bidirectional stream.
2. **Pseudonym layer:** `routing_id` values are per-context HMAC-SHA256 pseudonyms (SS9.10.4). Different contexts produce cryptographically unlinkable routing identifiers.
3. **Encryption layer:** Each context is an independent MLS group (SS9.7.1). Even if the transport layer erroneously delivered a blob to the wrong subscription, the recipient could not decrypt it. Encryption-as-access-control is the ultimate isolation boundary.

### Budget Enforcement

Each profile defines a maximum total connection count across all adapters. `TransportManager` tracks total active connections and enforces the budget.

**When the budget is reached:**

1. **LRU eviction** -- close the least-recently-used connection (by last message send or receive timestamp).
2. **Subscription migration** -- move subscriptions from the evicted connection to a surviving connection to the same relay (if one exists), or trigger relay reassignment to a different relay in the context's relay set.
3. **Mobile shedding** -- the `Mobile` profile proactively drops connections for inactive contexts (no sends or receives in 5+ minutes) before the budget is reached. Push notification bridging (SS10.7) wakes the connection on new messages.

Budgets are soft limits. The SDK may temporarily exceed during relay set reassignment or context join operations, then converge back within 30 seconds.

### QUIC Multiplexing

QUIC makes pooling natural: multiple independent streams over a single QUIC connection. Each operation gets its own bidirectional stream -- no head-of-line blocking between contexts sharing a connection. Cover traffic is amortized across all streams on the connection.

WebTransport inherits this property: browser clients using WebTransport get the same per-operation stream isolation as native QUIC clients.

---

## Feature Flag Strategy

Optional transports are gated behind Cargo feature flags. The native WebSocket relay is always compiled (no feature flag) -- it is the mandatory baseline. All other Tier 1 transports are opt-in.

### Feature Flags

| Feature | Crate Dependency | What It Enables |
|---------|-----------------|-----------------|
| `quic` | `quinn` (optional) | `QuicAdapter`, QUIC listener, per-operation stream model. |
| `webtransport-wasm` | `h3` + `h3-quinn` (optional) | WebTransport server-side session handling, HTTP/3 listener, `Alt-Svc` advertisement. |
| `udp` | DTLS crate (optional) | `UdpDtlsAdapter`, MessagePack-over-DTLS datagrams, UDP listener. |
| `coap` | CoAP crate (optional) | `CoapAdapter` (extends `udp`), CoAP framing, CoAP Observe. |

### Conditional Compilation

Each transport module uses `#[cfg(feature = "...")]` for conditional compilation:

```rust
// In crates/scp-transport/src/lib.rs
#[cfg(feature = "quic")]
pub mod quic;

#[cfg(feature = "webtransport-wasm")]
pub mod webtransport;

#[cfg(feature = "udp")]
pub mod udp;
```

The relay server's multi-transport listener in `crates/scp-transport/src/native/server.rs` conditionally starts each listener:

- WebSocket listener: always started.
- QUIC listener: started when `feature = "quic"` is enabled.
- WebTransport listener: started when `feature = "webtransport-wasm"` is enabled (implies HTTP/3).
- UDP/DTLS listener: started when `feature = "udp"` is enabled.

### Transport Advertisement

The relay auto-detects which transports are available based on enabled feature flags and active listeners, then advertises them in `.well-known/scp`:

```json
{
  "relay_config": {
    "transports": ["websocket", "quic", "webtransport", "udp-dtls"]
  }
}
```

`"websocket"` is always present. Other entries appear only when the corresponding listener is active. Clients use this array to select the best available transport.

**Client transport preference order:**
- Native clients: prefer QUIC over WebSocket when both are available.
- Browser clients: prefer WebTransport over WebSocket when the `WebTransport` API is available.
- Constrained clients: use UDP/DTLS directly (no preference negotiation).

---

## Architecture Diagram

### Client-to-Relay Transport Flow

```
                         SCP Client
                    +------------------+
                    |  TransportManager |
                    |  (profile-aware)  |
                    +--------+---------+
                             |
                    +--------+---------+
                    |  Connection Pool  |
                    | (per-relay dedup) |
                    +--+-----+-----+---+
                       |     |     |
          +------------+     |     +------------+
          |                  |                  |
  +-------+------+  +-------+-------+  +-------+-------+
  | WebSocket    |  | QUIC          |  | WebTransport  |
  | (mandatory   |  | (native       |  | (browser      |
  |  baseline)   |  |  clients)     |  |  clients)     |
  +--------------+  +---------------+  +---------------+
          |                  |                  |
          |     +------------+                  |
          |     |  UDP/DTLS (constrained)       |
          |     |                               |
  +-------+-----+------+-----------------------+
  |            Relay (untrusted)                |
  |  +----------+  +----------+  +-----------+ |
  |  | Blob     |  | Sub      |  | Rate      | |
  |  | Storage  |  | Registry |  | Limiter   | |
  |  +----------+  +----------+  +-----------+ |
  +--------------------------------------------+

  Fallback chains:
    Native clients:  QUIC -> WebSocket
    Browser clients: WebTransport -> WebSocket
    Constrained:     UDP/DTLS (poll-only, no fallback)
```

All four transport paths carry the same MessagePack wire format (ADR-004). The relay shares subscription registry, blob storage, rate limiters, and delivery jitter across all transport types.

### Transport Module Dependencies

```
crates/scp-transport/
  |
  +-- traits.rs          TransportAdapter trait (5 methods)
  |     ^                  All adapters implement this
  |     |
  +-- config.rs          TransportConfig + CoverTrafficTier
  |     |
  +-- profile.rs         TransportProfile enum (Server/Desktop/Mobile/Constrained)
  |     |                  Feeds defaults into config, cover_traffic, pool, manager
  |     |
  +-- pool.rs            ConnectionPool: Arc<RwLock<HashMap<(Url, Type), Adapter>>>
  |     |                  Keyed by (relay_url, transport_type)
  |     |
  +-- manager.rs         TransportManager
  |     |                  Uses pool, enforces budget, routes operations
  |     |
  +-- cover_traffic.rs   CoverTrafficGenerator (reads tier from profile)
  |
  +-- native/            SCP native relay adapter (always compiled)
  |     +-- server.rs      Multi-transport listener (starts per-feature listeners)
  |
  +-- quic/              [feature = "quic"]
  |     +-- adapter.rs     QuicAdapter: TransportAdapter
  |     +-- streams.rs     Per-operation stream helpers
  |     +-- lifecycle.rs   0-RTT, migration, reconnect
  |     +-- listener.rs    Relay-side QUIC accept loop
  |
  +-- webtransport/      [feature = "webtransport-wasm"]
  |     +-- client.rs      Client-side WASM adapter (wasm32 target only)
  |     +-- fallback.rs    WebSocket fallback when WebTransport unavailable
  |     +-- session.rs     Server-side HTTP/3 + WebTransport session
  |
  +-- udp/               [feature = "udp"]
  |     +-- adapter.rs     UdpDtlsAdapter: TransportAdapter
  |     +-- listener.rs    Relay-side DTLS accept loop
  |
  +-- coap/              [feature = "coap"]
        +-- adapter.rs     CoapAdapter: TransportAdapter
        +-- message.rs     CoAP message encoding/decoding
```

### Profile-Driven Resource Management

```
  TransportProfile (inferred or explicit)
        |
        +---> CoverTrafficTier::from_profile()
        |       Server/Desktop -> Full (30s, 1024B)
        |       Mobile -> Reduced (120s, 256B)
        |       Constrained -> Off
        |
        +---> max_connections
        |       Server -> usize::MAX
        |       Desktop -> 50
        |       Mobile -> 10
        |       Constrained -> 2
        |
        +---> min_relays
        |       Server/Desktop -> 3
        |       Mobile -> 2
        |       Constrained -> 1
        |
        +---> reconnect_backoff
                Server/Desktop -> 1-30s exponential
                Mobile -> 5-60s exponential
                Constrained -> None (poll-based)
```

---

## Relay Multi-Transport Architecture

A single relay process accepts connections across all enabled transport types. All transport handlers share the same backend state:

- **Subscription registry:** A subscription created via QUIC is visible to WebSocket queries and vice versa. A message published via WebSocket is delivered to QUIC subscribers.
- **Blob storage:** All transports read from and write to the same blob store.
- **Rate limiters:** Per-client rate limits apply across transport types.
- **Delivery jitter:** Timing randomization for metadata privacy applies uniformly.

**ALPN negotiation** distinguishes protocols at the TLS level:
- TCP connections: ALPN selects `http/1.1` or `h2` for HTTP, then WebSocket upgrade.
- UDP connections: ALPN selects `h3` for HTTP/3 or QUIC application protocol for direct QUIC.
- WebTransport sessions arrive as HTTP/3 CONNECT requests to `/scp/v1`.
- UDP/DTLS sessions are separate DTLS associations on a configured UDP port.

---

## Spec Cross-References

| Topic | Spec Section |
|-------|-------------|
| Transport profiles (device classes, budgets, cover traffic) | SS10.13 |
| Profile definitions table | SS10.13.1 |
| Connection pooling specification | SS10.13.2 |
| Connection budget enforcement | SS10.13.3 |
| Adapter tier system and tier requirements | SS10.5.1 |
| Tier 2 adapter mapping briefs | SS10.5.2 |
| QUIC transport binding (operation mapping, lifecycle) | SS10.14 |
| QUIC operation mapping table | SS10.14.1 |
| QUIC connection lifecycle (0-RTT, migration, reconnect) | SS10.14.2 |
| Relay QUIC support (listener, shared state, advertisement) | SS10.14.3 |
| HTTP/3 and WebTransport | SS10.15 |
| Relay HTTP/3 upgrade path (ALPN, Alt-Svc) | SS10.15.1 |
| WebTransport for browser clients | SS10.15.2 |
| Browser fallback chain (WebTransport -> WebSocket) | SS10.15.3 |
| Constrained device transport (DTLS, CoAP) | SS10.16 |
| MessagePack-over-DTLS | SS10.16.1 |
| CoAP-over-DTLS (RFC 7252, RFC 7641) | SS10.16.2 |
| Constrained profile trade-offs | SS10.16.3 |
| Wire format and relay protocol | ADR-004 |
| Transport profiles ADR (rationale, rejected alternatives) | ADR-036 |
| Alternative transport bindings ADR (QUIC, WebTransport, UDP/DTLS) | ADR-037 |
| Cover traffic tiers | SS9.10.6 |
| Suppression resistance | SS9.9.2 |
| Transport adapter conformance macro | SS16.12.1 |
| Transport security (TLS requirements) | SS9.13 |
| Transport adapter implementation guide | [transport-adapters.md](transport-adapters.md) |
