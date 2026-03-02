# Transport Layer Architecture

## Overview

SCP's transport layer is deliberately transport-independent. All relay communication flows through a single abstraction -- the `TransportAdapter` trait -- which defines five operations: `send`, `subscribe`, `unsubscribe`, `query`, and `delete`. Every adapter implementation, from the native WebSocket relay to Nostr to BLE, implements this same trait. The protocol core never knows which transport is in use.

Relays are untrusted dumb pipes. They store and forward opaque, encrypted blobs. Context access control is enforced by MLS encryption, not relay logic. This means any blob-capable relay -- including existing Nostr relays -- can serve as SCP transport without modification.

The `TransportAdapter` trait (defined in `crates/scp-transport/src/traits.rs`):

```rust
pub trait TransportAdapter: Send + Sync {
    fn send(&self, envelope: &OuterEnvelope) -> Result<BlobId, TransportError>;
    fn subscribe(&self, routing_id: &RoutingId, since: Option<u64>) -> Result<SubscriptionStream, TransportError>;
    fn unsubscribe(&self, routing_id: &RoutingId) -> Result<(), TransportError>;
    fn query(&self, routing_id: &RoutingId, since: Option<u64>) -> Result<Vec<OuterEnvelope>, TransportError>;
    fn delete(&self, blob_id: &BlobId) -> Result<(), TransportError>;
}
```

Every implementation is verified by the `transport_conformance!()` macro, which tests send/subscribe roundtrips, backfill, unsubscribe, query, delete, and deduplication.

## Transport Profiles

Transport profiles bundle connection strategy, cover traffic, relay count, and connection budget for a device class. The SDK infers the profile from the compilation target and exposes it as a configurable override.

| Profile | Connections | Cover Traffic | Min Relays | Reconnect | Max Connections |
|---------|------------|---------------|------------|-----------|-----------------|
| **`server`** | Persistent to all assigned relays | `full` | 3 | Aggressive (1-30s backoff) | Unlimited |
| **`desktop`** | Persistent to all assigned relays | `full` | 3 | Aggressive (1-30s backoff) | 50 |
| **`mobile`** | Active contexts only; push bridge for inactive | `reduced` | 2 | Conservative (5-60s backoff) | 10 |
| **`constrained`** | On-demand only; poll via QUERY | `off` | 1 | None (poll-based) | 2 |

**When to use each profile:**

- **`server`** -- Always-on infrastructure: dedicated relay hosts, agent workstations, CI runners. No connection budget ceiling.
- **`desktop`** -- Laptops, desktops, browser tabs (wasm32 defaults here). Persistent connections with a 50-connection budget.
- **`mobile`** -- iOS/Android devices. Proactively sheds connections for inactive contexts (5 min idle) and relies on push notification bridging for wakeup. Accepts reduced suppression detection (2-relay minimum).
- **`constrained`** -- IoT, embedded, resource-limited devices. Single relay, no cover traffic, no suppression detection. Typically operates behind a gateway agent that participates in full-profile contexts.

**Platform inference:**
- Linux/Windows/macOS -> `desktop`
- iOS/Android -> `mobile`
- wasm32 -> `desktop` (browser tabs)
- Explicit `.profile(TransportProfile::Server)` overrides inference

See spec **SS10.13** for full profile definitions and trade-off rationale.

## Adapter Tier System

Adapters are organized into three tiers by specification depth:

### Tier 1: Fully Specified

Wire format mapping, conformance suite, and fallback behavior defined. Must pass `transport_conformance!()`.

| Adapter | Transport | Key Characteristic |
|---------|-----------|-------------------|
| SCP native relay | WebSocket (ADR-004) | Mandatory baseline. MessagePack binary frames. |
| QUIC | Per-operation streams | No head-of-line blocking. Native keepalive. 0-RTT resumption. Connection migration. |
| WebTransport | HTTP/3 streams | Browser equivalent of QUIC. Uses `WebTransport` API. |
| UDP/DTLS | Datagrams | Constrained devices. Connectionless. No SUBSCRIBE (poll only). |

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

See spec **SS10.5.1** for tier requirements and **SS10.5.2** for Tier 2 mapping briefs.

## Connection Model

### Pooling

A single adapter connection to a relay is shared by all contexts assigned to that relay. The `TransportManager` maintains at most one connection per relay URL.

- **Per-relay deduplication.** One connection per `(relay_url, transport_type)` pair, regardless of how many contexts use that relay.
- **Reuse on assignment.** When a context is assigned a relay that already has an active connection, no new connection is opened.
- **Cross-manager sharing.** Multiple `TransportManager` instances in the same process share connections via a shared pool.
- **Subscription multiplexing.** Up to 100 subscriptions per connection (default, per ADR-004).

### Budget Enforcement

Each profile defines a max connection count. When the budget is reached:

1. **LRU eviction** -- close the least-recently-used connection.
2. **Subscription migration** -- move subscriptions to a surviving connection to the same relay or reassign to a different relay.
3. **Mobile shedding** -- the `mobile` profile proactively drops connections idle for 5+ minutes.

Budgets are soft limits. The SDK may temporarily exceed during relay reassignment or context join, then converge within 30 seconds.

### QUIC Multiplexing

QUIC makes pooling natural: multiple independent streams over a single QUIC connection. Each operation gets its own bidirectional stream -- no head-of-line blocking between contexts. Cover traffic is amortized across all streams on the connection.

## Architecture Diagram

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

## Spec Cross-References

| Topic | Spec Section |
|-------|-------------|
| Transport profiles (device classes, budgets, cover traffic) | SS10.13 |
| Adapter tier system and tier requirements | SS10.5.1 |
| Tier 2 adapter mapping briefs | SS10.5.2 |
| QUIC transport binding (operation mapping, lifecycle) | SS10.14 |
| HTTP/3 and WebTransport (browser transport, fallback chain) | SS10.15 |
| Constrained device transport (DTLS, CoAP) | SS10.16 |
| Wire format and relay protocol | ADR-004 |
| Cover traffic tiers | SS9.10.6 |
| Suppression resistance | SS9.9.2 |
| Transport adapter conformance macro | SS16.12.1 |
| Transport security (TLS requirements) | SS9.13 |
