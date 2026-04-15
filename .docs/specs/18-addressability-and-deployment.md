# 18. Addressability and Deployment

## 18.1 Philosophy

SCP's protocol layer — identity (§3), contexts (§5), relays (§10.4), encryption (§9) — is fully specified. What remains is how things get **found** and how complete applications get **deployed**. Addressability is the bridge between "the protocol works" and "agents can use it without prior knowledge."

The core protocol path avoids HTTP entirely:

```
DID (out-of-band exchange)
  → DHT resolution (Mainline, self-certifying via BEP44)
    → BEP44-signed relay list (in DID document SCPRelay entries)
      → WebSocket connection (TLS 1.3, §9.13)
        → MLS end-to-end encryption (§9.7)
```

Every step in this chain is self-certifying or cryptographically verified. No HTTP intermediary is required. Native clients (Swift, Kotlin, Python, Rust) never touch HTTP for protocol operations.

`scp://` URIs are the direct-connection mechanism — a context ID plus relay URL, no HTTP intermediary. They are the canonical way to share a context reference out-of-band.

`.well-known/scp` is an **optional web on-ramp** for the "I know a domain, nothing else" entry point. It is advisory only — HTTPS-dependent, not self-certifying. Clients MUST verify `.well-known/scp` data against DHT-resolved DID documents before trusting it (§18.3.2). Web clients (TypeScript/WASM in browser) use `.well-known/scp` to bridge from HTTP-land, then verify via DHT. This layering must be explicit: HTTP is the outermost, least-trusted discovery layer. The core protocol operates entirely without it.

The agent workstation tier (§10.2) is the primary deployment target for addressability. A dedicated always-on machine running builder agents is the natural host for SCP infrastructure: relay, identity, contexts, and HTTP serving are marginal additional load on hardware that's already running 24/7. The `ApplicationNode` (§18.6) is the SDK type that makes this deployment trivial.

## 18.2 DID Document Service Endpoints

DID documents (§3.7) carry service endpoints that declare how to reach the identity's infrastructure. SCP defines specific service endpoint types for protocol operations.

### 18.2.1 SCPRelay

The `SCPRelay` service endpoint type declares transport-layer relay URLs where the identity's SCP traffic is routed. These are the endpoints that `TransportManager` (ADR-012) uses to route encrypted blobs to the identity.

```json
{
  "id": "#scp-relay-1",
  "type": "SCPRelay",
  "serviceEndpoint": "wss://relay.example.com/scp/v1"
}
```

Properties:

- **URL format:** `wss://<host>/scp/v1` — the canonical SCP relay WebSocket endpoint (ADR-004). TLS 1.3 required (§9.13). **Exception:** Self-hosted relays without a domain MAY use `ws://` with IP literal addresses when discovered via DHT-resolved DID documents (§10.12.7). The SDK MUST reject `ws://` URLs from `.well-known/scp` or any non-DHT source.
- **Multiple entries allowed.** An identity MAY publish multiple `SCPRelay` entries for suppression resistance (§9.9.2, ADR-012). The recommended minimum is 3 relays.
- **Self-certified via BEP44.** For did:dht identities, relay URLs in the DID document are signed as part of the BEP44 record (§9.6.3). Substituting a relay URL requires the identity's private key.
- **Sequence number monotonicity.** Relay list updates follow the BEP44 sequence number rules (§9.6.3). Clients MUST reject DID documents with lower sequence numbers than previously observed.

When a peer resolves an identity's DID document, the `SCPRelay` entries tell them where to route encrypted envelopes destined for that identity. This is the primary relay discovery mechanism — out-of-band DID exchange leads to DHT resolution leads to relay URLs.

### 18.2.2 Existing Endpoint Types (Cross-Reference)

SCP uses multiple DID document service endpoint types, each serving a distinct purpose:

| Type | Purpose | Consumer | Spec Reference |
|------|---------|----------|----------------|
| `SCPRelay` | Transport-layer relay URLs for encrypted blob routing | `TransportManager` (ADR-012) | §18.2.1 |
| `SCPCapabilities` | Application-layer capability endpoints (tool schemas, agent descriptions) | Discovery Engine (§6.2.2) | ADR-020 |
| `IdentityPrivateState` | Relay URLs storing identity private state blobs | Identity Manager | §3.7 |
| `PreRotationCommitment` | SHA-256 commitment hash for pre-rotation key (applies to `#0` and `#active` only; `#agent` is a software key with simpler rotation — no pre-rotation needed, see ADR-039) | Identity Manager (§9.12) | ADR-003 |
| `SCPBroadcastContext` | Broadcast context ID + relay URLs for author discovery | Discovery Engine | §5.14.11 |
| `ParticipationStatements` | Relay URL(s) where the agent's participation statements can be fetched by verifiers | Participation Admission (§7.3.2.1) | §7.3.2.1 |
| `AttestationRevocations` | Endpoint(s) for checking attestation revocation status | Attestation Verification (§7.4.4) | §7.4.4 |
| `ScpIdentityLinkAttestation` | Identity link attestation entries for platform verification | Attestation Verification (§3.5.4) | §3.5.3 |

**SCPRelay vs SCPCapabilities.** These are distinct service types with different consumers and different purposes:

- `SCPRelay` = **transport layer**. Where to send encrypted blobs. Consumed by `TransportManager`. Any SCP participant publishing to this identity routes through these URLs.
- `SCPCapabilities` = **application layer**. What tools and capabilities an agent offers. Consumed by the Discovery Engine. Agents looking for specific capabilities query these endpoints.

A relay operator's DID document contains `SCPRelay` entries (where to connect). An agent's DID document may contain both `SCPRelay` entries (how to reach the agent) and `SCPCapabilities` entries (what the agent can do).

### 18.2.2A DID Document Field-Level Schema

SCP DID documents follow the W3C DID Core specification (v1.0) with SCP-specific verification methods and service endpoints. The canonical serialization is JSON (per did:dht spec). Two SDKs MUST produce byte-identical DID documents for the same identity state to ensure BEP44 signature verification.

**Canonical DID document structure:**

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "did:dht:<z-base-32-encoded-public-key>",
  "verificationMethod": [
    {
      "id": "did:dht:<key>#0",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:dht:<key>",
      "publicKeyMultibase": "z<multibase-encoded-ed25519-public-key>"
    },
    {
      "id": "did:dht:<key>#active",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:dht:<key>",
      "publicKeyMultibase": "z<multibase-encoded-ed25519-public-key>"
    },
    {
      "id": "did:dht:<key>#agent",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:dht:<key>",
      "publicKeyMultibase": "z<multibase-encoded-ed25519-public-key>"
    }
  ],
  "authentication": ["did:dht:<key>#active", "did:dht:<key>#agent"],
  "assertionMethod": ["did:dht:<key>#active", "did:dht:<key>#agent"],
  "capabilityDelegation": ["did:dht:<key>#0"],
  "capabilityInvocation": ["did:dht:<key>#0", "did:dht:<key>#active"],
  "service": [
    {
      "id": "#scp-relay-1",
      "type": "SCPRelay",
      "serviceEndpoint": "wss://relay.example.com/scp/v1"
    },
    {
      "id": "#scp-private-state",
      "type": "IdentityPrivateState",
      "serviceEndpoint": ["wss://relay1.example.com/scp/v1", "wss://relay2.example.com/scp/v1"]
    },
    {
      "id": "#scp-prerotation",
      "type": "PreRotationCommitment",
      "serviceEndpoint": "<sha256-hex-of-prerotation-public-key>"
    },
    {
      "id": "#scp-participation",
      "type": "ParticipationStatements",
      "serviceEndpoint": "https://relay.example.com/scp/v1/participation/<did>"
    },
    {
      "id": "#scp-attestation-revocations",
      "type": "AttestationRevocations",
      "serviceEndpoint": "https://relay.example.com/scp/v1/revocations/<did>"
    }
  ]
}
```

**Field constraints:**

| Field | Required | Constraints |
|-------|----------|-------------|
| `@context` | Yes | MUST include the two URIs shown above, in order. |
| `id` | Yes | MUST match `did:dht:<z-base-32(#0 public key)>`. |
| `verificationMethod` | Yes | MUST include `#0` (Identity Key). MUST include `#active` (Active Signing Key). MAY include `#agent` (Agent Signing Key, optional per ADR-039). No other verification methods permitted. |
| `verificationMethod[].publicKeyMultibase` | Yes | Multibase-encoded Ed25519 public key (prefix `z` for base58btc). |
| `authentication` | Yes | MUST reference `#active`. MAY reference `#agent`. MUST NOT reference `#0`. |
| `assertionMethod` | Yes | Same as `authentication`. |
| `capabilityDelegation` | Yes | MUST reference only `#0`. |
| `capabilityInvocation` | Yes | MUST reference `#0` and `#active`. |
| `service` | Yes | At least one `SCPRelay` entry required. Other types optional. |
| `service[].id` | Yes | Fragment identifier (e.g., `#scp-relay-1`). Unique within the document. |
| `service[].type` | Yes | One of the types in §18.2.2. |

**Canonical serialization rules:** JSON keys MUST be sorted lexicographically at every nesting level (RFC 8785 JSON Canonicalization Scheme). This ensures deterministic serialization for BEP44 signature computation. Whitespace: no extra whitespace (minified JSON). Unicode: NFC normalization.

### 18.2.3 Multiple Relay Entries

An identity SHOULD publish at least 3 `SCPRelay` entries for suppression resistance (§9.9.2). `TransportManager` reads all `SCPRelay` entries from a resolved DID document and routes to all of them. The relay set partitioning logic (ADR-012) operates on top of the published relay list.

Relay entries are ordered by preference (first entry = preferred relay). Clients SHOULD respect ordering when selecting a subset. When adding or removing relays, the identity updates its DID document and publishes with an incremented BEP44 sequence number. Peers that re-resolve the DID document discover the updated relay list.

## 18.3 .well-known/scp

An HTTP-accessible JSON document at `https://<domain>/.well-known/scp` that enables web-based discovery of SCP infrastructure associated with a domain. This is the web on-ramp — the entry point for users and agents who know a domain name but nothing else about the operator's SCP infrastructure.

### 18.3.1 Document Format

```json
{
  "version": 1,
  "did": "did:dht:z6Mk...",
  "relay": "wss://relay.example.com/scp/v1",
  "contexts": [
    {
      "id": "a1b2c3d4e5f6...",
      "name": "Example Community",
      "mode": "broadcast",
      "uri": "scp://context/a1b2c3d4e5f6...?relay=wss://relay.example.com/scp/v1&mode=broadcast&name=Example+Community"
    }
  ],
  "relay_config": {
    "max_blob_size": 262144,
    "max_blob_ttl": 86400,
    "rate_limit_publish": 6000,
    "rate_limit_subscribe": 100
  }
}
```

**Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | integer | Yes | Protocol version. Currently `1`. |
| `did` | string | Yes | The operator's DID (did:dht preferred). Enables partial verification via DHT resolution (§18.3.2). |
| `relay` | string | Yes | Primary relay URL (`wss://` scheme, `/scp/v1` path). |
| `contexts` | array | No | Publicly listed contexts. See constraints below. |
| `handles` | object | No | Map of local-part → resolution record for domain handles (§22.6.1). |
| `relay_config` | object | No | Relay operator configuration subset (§18.3.3). |

**Context entry fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Context ID (hex-encoded). |
| `name` | string | No | Human-readable name (advisory, unverified). |
| `mode` | string | No | `"encrypted"` or `"broadcast"`. Defaults to `"encrypted"`. |
| `uri` | string | No | Full `scp://` URI for the context (§18.4). |

### 18.3.2 Security Properties

`.well-known/scp` is **NOT self-certifying.** Its integrity depends on HTTPS (DNS + TLS + server integrity). An attacker who controls DNS or compromises the CA chain can serve a fraudulent `.well-known/scp` document. This is an inherent limitation of any HTTP-based discovery mechanism.

**Verification chain:**

1. Client reads `https://<domain>/.well-known/scp` → gets `did` + `relay` fields.
2. Client resolves `did` via Mainline DHT (self-certifying, no HTTPS in this step).
3. Client checks that the `relay` URL appears in the BEP44-signed DID document's `SCPRelay` service entries.
4. **Match** → BEP44-grade assurance of relay URL. The `.well-known/scp` data is consistent with the self-certifying DID document.
5. **Mismatch** → reject `.well-known/scp` data. The web document is inconsistent with the DHT-resolved identity.

**Attack analysis:**

- An attacker who controls DNS/CA can serve a fake `.well-known/scp` but **cannot forge the DHT-resolved DID document** without the identity's private key. The verification chain catches the discrepancy at step 5.
- Worst case without verification: the client connects to the wrong relay. Since the relay is a dumb pipe that cannot read MLS-encrypted content (§9.9.1), the impact is limited to availability (messages go to the wrong relay) rather than confidentiality. The math enforces access, not infrastructure.
- Clients MUST perform the verification chain before trusting `.well-known/scp` data for any protocol operation. Clients that skip verification (e.g., displaying a domain's broadcast context list in a web UI) MUST indicate that the data is unverified.

**What `.well-known/scp` MUST NOT expose** (§9.10 metadata privacy constraints):

- Encrypted context IDs (would leak context existence)
- Membership rosters or member counts for encrypted contexts
- Routing pseudonyms (§9.10.4)
- Subscriber lists for broadcast contexts
- Any data that is inside the encrypted envelope layer

**What `.well-known/scp` MAY expose:**

- Relay URLs (already public via DID document)
- Operator DID (already public)
- Protocol version
- Relay operator configuration (§18.3.3)
- Broadcast context IDs (public by design — §5.14.6, routing_id is SHA-256 of context_id)

### 18.3.3 Relay Operator Configuration Subset

The `relay_config` object exposes operational parameters that agents need to evaluate before connecting. These fields mirror the relay configuration table in ADR-004:

| Field | Type | Unit | Description |
|-------|------|------|-------------|
| `max_blob_size` | integer | bytes | Maximum blob size the relay accepts. |
| `max_blob_ttl` | integer | seconds | Maximum blob TTL the relay enforces. |
| `rate_limit_publish` | integer | per minute | PUBLISH rate limit per IP address (default: 6000/min = 100/sec). |
| `rate_limit_subscribe` | integer | per connection | Maximum concurrent subscriptions per connection (default: 100). |
| `economic` | object | — | Relay economic configuration (§19.8). Optional. Absence = free relay. |
| `economic.currency` | string | — | Currency code for all amounts in this economic config (e.g., `"USD"`). |
| `economic.per_publish` | integer | smallest unit | Cost per PUBLISH operation as `Amount` in smallest currency unit (§19.1.1). |
| `economic.per_byte_stored` | integer | smallest unit | Cost per byte stored as `Amount` in smallest currency unit (§19.1.1). |
| `economic.payment_adapters` | array | — | Accepted payment adapter IDs (e.g., `["x402", "lightning"]`). |
| `economic.payee` | string | — | Relay operator's DID for receiving payments. |

All fields are optional. Absent fields indicate the relay uses protocol defaults or has no limit. Absent `economic` field indicates a free relay.

ADR-004 specifies that relay configuration is available "out-of-band." `.well-known/scp` is the canonical location for this out-of-band configuration. Agents evaluating whether to use a relay can fetch `/.well-known/scp` and inspect `relay_config` before establishing a WebSocket connection.

## 18.4 Context URIs

SCP contexts are addressable via `scp://` URIs. Context URIs are **discovery-only** — they point to a context's metadata routing ID (§5.7.1) for inspection. They do not embed key material or grant membership. Joining a context is a separate protocol flow (MLS Welcome, §9.7).

### 18.4.1 Universal URI Format

```
scp://context/<context_id_hex>?relay=<url>[&relay=<url2>][&mode=<mode>][&name=<name>]
```

**Components:**

| Component | Required | Description |
|-----------|----------|-------------|
| `context/<context_id_hex>` | Yes | Hex-encoded context ID. |
| `relay` | Yes (at least one) | Relay URL(s) where the context is reachable. Multiple `relay` parameters for multi-relay contexts. |
| `mode` | No | `encrypted` or `broadcast`. Advisory — actual mode is verified from context metadata. |
| `name` | No | Human-readable context name. Advisory, unverified against context metadata. Percent-encoded per RFC 3986. |
| `handle` | No | Human-readable handle (§22.9.2). Advisory, same status as `name`. Provides a resolution hint for display and address resolution. |

**Parsing rules:**

- Scheme MUST be `scp`.
- Authority component is empty (double slash after scheme is part of the path).
- Path MUST start with `context/`.
- Context ID MUST be valid hexadecimal.
- Relay URLs MUST use the `wss://`, `ws://`, `https://`, or `http://` scheme.
- Unknown query parameters MUST be ignored (forward compatibility).
- Percent-encoding per RFC 3986 for all parameter values.

**Examples:**

```
scp://context/a1b2c3d4e5f6?relay=wss://relay.example.com/scp/v1
scp://context/a1b2c3d4e5f6?relay=wss://relay1.example.com/scp/v1&relay=wss://relay2.example.com/scp/v1&mode=broadcast&name=Tech+News
```

### 18.4.2 Encrypted Context URIs

Encrypted context URIs follow the universal format. The `mode` parameter is omitted or set to `encrypted`. The URI enables a prospective member to fetch context metadata from the metadata routing ID (§5.7.1) and evaluate whether to request membership.

```
scp://context/<context_id_hex>?relay=wss://relay.example.com/scp/v1
```

The URI does **not** contain key material. Membership requires an MLS Welcome message from an existing member — the URI is sufficient for discovery and metadata inspection, not for joining.

### 18.4.3 Broadcast Context URIs (Alias)

The legacy format `scp://broadcast/<context_id_hex>?relay=<url>` (§5.14.11) is accepted as an alias for `scp://context/<context_id_hex>?relay=<url>&mode=broadcast`. Parsers MUST accept both forms and normalize to the universal format.

### 18.4.4 Use Cases

| Use case | URI enables |
|----------|------------|
| Out-of-band sharing | Share a context reference via any channel (chat, email, QR code). Recipient fetches metadata, evaluates, requests to join. |
| Agent bootstrap | An agent receiving an `scp://` URI can resolve the context's metadata, evaluate governance and ceiling, and decide whether to participate — all without prior knowledge of the context. |
| Deep linking | Applications can register `scp://` as a URI scheme. Clicking an `scp://` link opens the app and navigates to the context's metadata view. |
| `.well-known/scp` integration | Broadcast contexts listed in `.well-known/scp` include their full `scp://` URI for direct access. |

## 18.5 Relay Bootstrap

How a new identity learns its first relay. This closes the relay discovery open question from §00.

### 18.5.1 Bootstrap Priority Order

When an identity needs to discover relays, the SDK follows this priority chain:

1. **Explicit configuration.** Relay URLs provided directly in `TransportConfig` at SDK initialization. Highest trust — the operator or user explicitly chose these relays.
2. **DID document resolution.** Resolve the identity's own DID document via Mainline DHT. Extract `SCPRelay` service entries. Self-certifying (§9.6.3).
3. **`.well-known/scp` resolution.** If a bootstrap domain is configured, fetch `https://<domain>/.well-known/scp` and extract the relay URL. Verify against DID document (§18.3.2).
4. **Peer relay discovery.** For identities that share contexts with known peers, resolve the peer's DID document and use overlapping relay sets. This enables relay discovery through the social graph.
5. **Fallback relay list.** A hardcoded list of well-known community relays shipped with the SDK. Last resort. These relays are not privileged — they are default suggestions that can be overridden. The SDK SHOULD warn when falling back to default relays. The fallback list MUST include at least one free relay (no `economic` field in `relay_config`) — this is a protocol invariant that prevents economic gatekeeping of basic protocol operation (§19.8, §19.14).

Each priority level is tried in order. The first level that yields at least one reachable relay is used. The SDK MAY combine results from multiple levels (e.g., explicit + DID document) for suppression resistance.

Bootstrap relays SHOULD support STUN service (§10.12.3) — this makes them available as NAT type detection endpoints for self-hosted relays behind residential NAT. Bootstrap relays also serve as DID resolution endpoints: identity owners SHOULD publish DID documents to bootstrap relays via the relay-based resolution layer (§3.10.2), and resolvers SHOULD query bootstrap relays when the identity's own relays are unknown.

### 18.5.2 Agent Deployment Case

An agent deploying via `ApplicationNode` (§18.6) follows a simplified bootstrap:

1. `ApplicationNode::builder().domain("example.com").build()` starts the relay server on the local machine.
2. The relay URL is `wss://example.com/scp/v1` (derived from the configured domain).
3. The identity's DID document is published with this relay URL as an `SCPRelay` entry.
4. `.well-known/scp` is generated and served at `https://example.com/.well-known/scp`.

The agent's relay is self-hosted — no external relay discovery needed. Peers discover the agent's relay by resolving its DID document.

### 18.5.3 Client Discovery Case

A client that knows only a domain name (e.g., from a website or advertisement):

1. Fetch `https://example.com/.well-known/scp` → get `did` + `relay`.
2. Resolve `did` via DHT → get `SCPRelay` entries.
3. Verify `relay` from step 1 appears in step 2 (§18.3.2).
4. Connect to the relay via WebSocket.
5. Subscribe to broadcast contexts listed in `.well-known/scp` or inspect encrypted context metadata via `scp://` URIs.

## 18.6 Application Node

`ApplicationNode` is a concrete SDK type in the `scp-node` crate that composes an SCP relay, an identity, and an HTTP server into a single deployable unit. It is the "one box" deployment pattern — relay + participant + HTTP server on one machine.

`ApplicationNode` is NOT an HTTP framework. It exposes components (relay router, `.well-known` router, TLS configuration) that integrate with existing HTTP frameworks (axum, actix-web, etc.). Applications build their HTTP layer on top; `ApplicationNode` provides the SCP-specific pieces.

When `.no_domain()` is set (§10.12.8), `ApplicationNode` skips ACME TLS provisioning, does not serve `.well-known/scp`, and instead probes NAT type via STUN to determine the appropriate reachability tier (UPnP, STUN hole punch, or relay bridge). The DID document is published with a `ws://` relay URL. This is the zero-config deployment path for self-hosted relays behind residential NAT.

### 18.6.1 Components

An `ApplicationNode` composes:

| Component | Description |
|-----------|-------------|
| **SCP Relay** | A relay server listening at `wss://<domain>/scp/v1` (ADR-004). Handles PUBLISH, SUBSCRIBE, QUERY, DELETE for all contexts hosted on this node. |
| **Identity** | A DID identity (§3) with `SCPRelay` service entries pointing to this node's relay URL. Published to DHT on startup. |
| **Storage** | `ProtocolRepository` (§17.4) backed by `SqliteStorage` (§17.6). Stores identity state, context state, relay blobs, and TLS certificates. |
| **HTTP Server** | Serves `.well-known/scp` (§18.3) and provides WebSocket upgrade at `/scp/v1`. Merges with application-provided routes. |
| **TLS** | ACME-provisioned TLS certificates (§18.6.3). TLS 1.3 required (§9.13). |

### 18.6.2 SDK Surface

```rust
// scp-node crate

pub struct ApplicationNode<S: Storage> { /* ... */ }

/// Convenience free function: `scp_node::builder()`.
pub fn builder() -> ApplicationNodeBuilder;

impl<S: Storage> ApplicationNode<S> {
    /// The relay handle — for direct relay operations.
    pub fn relay(&self) -> &RelayHandle;

    /// The identity handle — for DID operations, context creation, messaging.
    pub fn identity(&self) -> &IdentityHandle;

    /// The storage handle — for direct ProtocolRepository access (§17.4).
    pub fn storage(&self) -> &ProtocolRepository<S>;

    /// Returns an axum Router serving GET /.well-known/scp.
    /// Dynamically generated from node state (DID, relay URL, registered contexts).
    pub fn well_known_router(&self) -> axum::Router;

    /// Returns an axum Router handling WebSocket upgrade at /scp/v1.
    pub fn relay_router(&self) -> axum::Router;

    /// Binds HTTPS on the configured address, merging:
    /// - Application-provided routes
    /// - .well-known/scp route
    /// - /scp/v1 WebSocket upgrade route
    /// The shutdown future resolves when the server should begin graceful
    /// shutdown (e.g., signal handler, test teardown). In-flight connections
    /// drain naturally.
    pub async fn serve(
        self,
        app_router: axum::Router,
        shutdown: impl Future<Output = ()> + Send + 'static,
    ) -> Result<(), NodeError>;
}

/// Type-state builder — generic over key custody (K), DID method (D),
/// storage backend (S), domain state, and identity state. The type system
/// enforces that `.build()` is only callable when both domain mode and
/// identity have been configured.
pub struct ApplicationNodeBuilder<K, D, S, Dom, Id> { /* ... */ }

impl ApplicationNodeBuilder {
    pub fn new() -> Self;
}

impl<...> ApplicationNodeBuilder<K, D, S, Dom, Id> {
    pub fn domain(self, domain: &str) -> ApplicationNodeBuilder<..., HasDomain, ...>;
    pub fn no_domain(self) -> ApplicationNodeBuilder<..., HasNoDomain, ...>;
    pub fn generate_identity(self, ...) -> ApplicationNodeBuilder<..., HasIdentity>;
    pub fn explicit_identity(self, ...) -> ApplicationNodeBuilder<..., HasIdentity>;
    pub fn storage<S2: Storage>(self, storage: S2) -> ApplicationNodeBuilder<..., S2, ...>;
    pub fn bind_addr(self, addr: SocketAddr) -> Self;
    pub fn acme_email(self, email: &str) -> Self;
    pub fn projection_rate_limit(self, rate: u32) -> Self;

    /// Build the ApplicationNode (available when domain + identity are set):
    /// 1. Initialize storage (create if needed)
    /// 2. Load or generate identity
    /// 3. Start relay server
    /// 4. Publish DID document with SCPRelay entry
    /// 5. Provision TLS certificate via ACME (domain mode) or probe NAT (no-domain mode)
    pub async fn build(self) -> Result<ApplicationNode<S>, NodeError>;
}
```

### 18.6.3 TLS Provisioning

`ApplicationNode` provisions TLS certificates automatically via ACME (Let's Encrypt):

- **ACME HTTP-01 challenge.** The node serves the ACME challenge response at `http://<domain>/.well-known/acme-challenge/<token>`. This requires port 80 to be reachable.
- **DNS-01 alternative.** For environments where port 80 is unavailable (home networks behind NAT, shared hosting), DNS-01 challenges are supported. The operator configures DNS TXT records manually or via DNS API.
- **Certificate storage.** Certificates and private keys are stored in `SqliteStorage` (§17.6), encrypted at rest.
- **Auto-renewal.** The node renews certificates 30 days before expiry. Renewal is background and non-disruptive.
- **TLS 1.3 required.** Per §9.13, all relay connections use TLS 1.3. The node's TLS configuration enforces this minimum version.
- **TLS skipped for `.no_domain()` mode.** When `.no_domain()` is set (§10.12.8), ACME provisioning is skipped entirely. The relay listens on `ws://` (plaintext WebSocket). MLS provides the confidentiality boundary; TLS is defense-in-depth that requires a domain to provision. See §10.12.6 for the security rationale.

### 18.6.4 Properties and Invariants

- `ApplicationNode` does not mandate a specific HTTP framework. The `well_known_router()` and `relay_router()` methods return axum `Router` instances that can be composed with any axum-compatible application.
- The relay started by `ApplicationNode` is a standard SCP relay (ADR-004). It accepts connections from any SCP client, not just the local identity. Other identities can use this relay for their contexts.
- DID publication happens once on `.build()` and on relay URL changes. The node does not continuously re-publish.
- `.well-known/scp` is dynamically generated from node state. Registering a broadcast context on the node automatically makes it appear in `.well-known/scp` responses.
- The node's identity is a full SCP identity. It can create contexts, join contexts, send messages — it is a protocol participant, not just infrastructure.

## 18.7 Federation

SCP does not have a federation protocol in the traditional sense (no homeserver-to-homeserver communication). Instead, federation emerges from three existing mechanisms:

1. **Multi-relay publishing (ADR-012).** Messages are published to 3+ relays. Any relay in the set can deliver to any subscriber. This provides relay-level redundancy without relay-to-relay coordination.
2. **DID-based relay discovery (§18.2).** Peers discover each other's relays by resolving DID documents. No central relay registry. Each identity declares its own relays.
3. **Transport independence.** Different participants in the same context can connect to different relays (or even different transport types). The `TransportManager` handles multi-relay fanout and deduplication transparently.

**Cross-operator messaging** works without explicit federation:

```
Alice (relay: relay-a.com)     Bob (relay: relay-b.com)
         │                              │
         ├── publishes to relay-a ──────┤ (Alice's relay set includes relay-a)
         ├── publishes to relay-b ──────┤ (Alice also publishes to Bob's relay)
         │                              │
         │     Bob subscribes to ───────┤ (Bob subscribes on relay-b)
         │     relay-b                  │
```

Alice resolves Bob's DID document, discovers Bob's `SCPRelay` entries, and includes Bob's relays in her publish set for contexts they share. Bob does the same for Alice. No relay-to-relay protocol needed — the clients handle cross-relay routing through `TransportManager`.

## 18.8 Agent Deployment Flow

End-to-end deployment of an SCP-enabled agent on a dedicated machine:

```
1. Agent provisions hardware (Mac Mini, VPS, etc.)

2. Agent runs:
   let node = ApplicationNode::builder()
       .domain("agent.example.com")
       .generate_identity()
       .build()
       .await?;

   This:
   a. Creates SqliteStorage at default path
   b. Generates a new DID identity
   c. Starts relay server at wss://agent.example.com/scp/v1
   d. Publishes DID document with SCPRelay entry to DHT
   e. Provisions TLS certificate via ACME
   f. Serves .well-known/scp at https://agent.example.com/.well-known/scp

3. Agent creates contexts:
   let broadcast = node.identity().create_context(
       template: "public-broadcast",
   ).await?;

   The broadcast context appears in .well-known/scp automatically.

4. Other agents discover this agent:
   a. Via domain: fetch .well-known/scp → get DID → resolve → connect
   b. Via DID: resolve DID document → get SCPRelay entries → connect
   c. Via URI: parse scp://context/... → connect to relay → inspect metadata

5. Steady state:
   node.serve(my_app_routes).await?;

   The node runs indefinitely, handling relay traffic, context operations,
   and application HTTP routes on the same HTTPS listener.
```

## 18.9 Phase Integration

`ApplicationNode` and addressability features integrate into the existing build phases (architecture.md §4):

| Component | Phase | Rationale |
|-----------|-------|-----------|
| `SCPRelay` DID service type | Phase 1 (patch) | Extends existing DidDocument from ADR-003. Required for relay discovery. |
| Relay URL in DID publish flow | Phase 1 (patch) | Extends existing DID publish from ADR-003. Required for peers to discover relays. |
| `ScpUri` type | Phase 2 | Context URI parsing is foundational for addressability. No external dependencies. |
| `WellKnownScp` type | Phase 2 | Data type for `.well-known/scp` serialization. No external dependencies. |
| `TransportConfig` + relay bootstrap | Phase 2 | Extends `TransportManager` (ADR-012). Requires DID relay publication. |
| `scp-node` crate + `ApplicationNode` | Phase 2 | Requires relay server (ADR-004), identity (ADR-003), and transport (ADR-012). |
| TLS provisioning (ACME) | Phase 2 | Required for `ApplicationNode` HTTPS. |
| HTTP server (`.well-known` + relay upgrade) | Phase 2 | Required for web discovery and WebSocket relay. |

The `scp-node` crate is added to the workspace as a new top-level crate at `crates/scp-node/`, depending on `scp-core`, `scp-transport`, and `scp-platform`.

## 18.10 Local HTTP Control API

SCP's core transport is MessagePack-over-WebSocket with encrypted blobs — deliberately opaque to intermediaries (§9.9.1). Standard HTTP dev tooling (curl, Postman, OpenAPI) cannot interact with this wire protocol. The local HTTP control API recovers HTTP-ecosystem usefulness for debugging and local integration without exposing any protocol endpoints.

### 18.10.1 Design Rationale

The dev API is **not a protocol endpoint**. It is a local control plane bound to the operator's machine. No SCP peer ever interacts with it — it exists solely for:

- **Debugging:** Inspecting node state, relay status, and registered contexts via curl or browser.
- **Local integration:** Non-Rust applications on the same machine can query node state over HTTP.
- **Tooling:** OpenAPI-compatible surface for Postman collections, monitoring dashboards, and health checks.

The dev API is a convenience projection of the SDK surface — all operations are also available directly via `ApplicationNode` methods in Rust. No functionality is exclusive to the HTTP API. It exists for tooling and non-Rust local integrations that cannot call Rust methods directly.

### 18.10.2 Binding and Authentication

The dev API listens on a **separate port** from the public HTTPS listener, bound to `127.0.0.1:<port>` by default. This separation prevents accidental exposure through reverse proxy misconfiguration — a reverse proxy forwarding to the public HTTPS port never sees the dev API.

Authentication uses a bearer token generated at startup:

- Token format: `scp_local_token_<32 random hex characters>` (e.g., `scp_local_token_a1b2c3...`).
- The token is logged at `INFO` level on startup and available via `node.dev_token()`.
- All requests to `/scp/dev/v1/*` require `Authorization: Bearer <token>`.
- Missing or invalid token returns `401 Unauthorized` with `{ "error": "unauthorized", "code": "UNAUTHORIZED" }`.

### 18.10.3 Endpoint Catalog

All endpoints are prefixed with `/scp/dev/v1/`.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/scp/dev/v1/health` | Uptime, relay connection count, storage status |
| `GET` | `/scp/dev/v1/identity` | DID string and DID document |
| `GET` | `/scp/dev/v1/relay/status` | Bound address, active connections, blob count |
| `GET` | `/scp/dev/v1/contexts` | List registered broadcast contexts |
| `GET` | `/scp/dev/v1/contexts/:id` | Single context (id, name, mode, subscriber count) |
| `POST` | `/scp/dev/v1/contexts` | Register a broadcast context |
| `DELETE` | `/scp/dev/v1/contexts/:id` | Deregister a broadcast context |

### 18.10.4 Response Format

All responses are JSON (`Content-Type: application/json`).

Success responses return the resource directly. Error responses use:

```json
{
  "error": "human-readable message",
  "code": "MACHINE_READABLE_CODE"
}
```

Standard HTTP status codes: `200` (success), `201` (created), `204` (deleted), `400` (bad request), `401` (unauthorized), `403` (forbidden — DNS rebinding), `404` (not found), `409` (conflict — duplicate resource), `500` (internal error).

Request bodies are limited to **64 KiB**. Requests exceeding this limit are rejected before handler dispatch.

### 18.10.5 SDK Surface

- `ApplicationNodeBuilder::local_api(addr: SocketAddr)` — enables the dev API on the specified address. Not called = dev API disabled (production default).
- `ApplicationNode::dev_router() -> axum::Router` — returns the dev API router for composition. Only available when `local_api()` was called on the builder.
- `ApplicationNode::dev_token() -> Option<&str>` — returns the bearer token if the dev API is enabled. `None` if disabled.
- `ApplicationNode::register_broadcast_context(id, name) -> Result<(), NodeError>` — registers a broadcast context for `.well-known/scp`. Validates hex format, length, and enforces the 1024-context limit. Also available via `POST /scp/dev/v1/contexts`.

### 18.10.6 Security Properties

- **Localhost binding** prevents remote access. Combined with bearer token authentication, this provides defense-in-depth against SSRF attacks (a compromised service on the same machine still needs the token).
- **DNS rebinding protection.** The dev API validates the `Host` header on every request, rejecting any value that is not `localhost`, `127.0.0.1`, or `[::1]` (with optional port). This prevents DNS rebinding attacks where a malicious website resolves its domain to `127.0.0.1` and accesses the dev API through the browser. Non-matching Host headers receive `403 Forbidden`.
- **Security response headers.** All dev API responses include `X-Content-Type-Options: nosniff` (prevents MIME sniffing), `Cache-Control: no-store` (prevents caching of sensitive diagnostics), and `X-Frame-Options: DENY` (prevents clickjacking via iframe embedding).
- **CORS preflight rejection.** `OPTIONS` requests to the dev API are rejected with `403 Forbidden`. The dev API is localhost-only and must not be accessible cross-origin.
- **No private key material** is exposed through any endpoint. The identity endpoint returns the DID string and DID document (public information).
- **No message content** is exposed. The relay status endpoint shows connection and blob counts, not blob contents.
- **Request body limit.** POST request bodies are limited to 64 KiB to prevent unbounded memory allocation.
- **Broadcast context limit.** A maximum of 1024 broadcast contexts may be registered per node. This prevents unbounded memory growth from registration floods via the dev API or SDK.
- **Production default: disabled.** The dev API is opt-in via `local_api()`. Deployments that do not call this method have zero additional attack surface.
- **Separate port** from the public HTTPS listener. Reverse proxy configurations that forward to the public port never accidentally expose the dev API.
- **No rate limiting required.** The dev API's localhost binding + bearer token authentication provide sufficient protection. Per-IP rate limiting is applied only to public projection endpoints (§18.11.6).

## 18.11 HTTP Broadcast Projection

Broadcast contexts (§5.14) distribute content to unlimited audiences using per-author AES-256 keys instead of MLS group encryption. The content is encrypted on the wire but intended for broad consumption — subscribers decrypt using the author's broadcast key. HTTP broadcast projection decrypts and re-serves this content over standard HTTP, enabling CDN distribution, web readers, RSS aggregation, search engine crawling, and monitoring dashboards.

### 18.11.1 Design Rationale

Projection is **author-side only**. The relay cannot decrypt broadcast content (§9.9.1 — relays are untrusted dumb pipes that see only encrypted blobs). The author's `ApplicationNode` holds the broadcast keys and is the only entity that can decrypt its own broadcast content for HTTP serving.

Use cases:

- **Web readers:** Standard browsers render broadcast content without SCP client software.
- **CDN distribution:** Immutable per-message endpoints are CDN-friendly (infinite cache TTL).
- **RSS/Atom feeds:** Feed readers poll the feed endpoint.
- **Search engine crawling:** Crawlers index projected content.
- **Monitoring:** HTTP health checks and content verification dashboards.

Subscriber-side projection is deliberately not supported — it would allow subscribers to redistribute content via HTTP without the author's control or knowledge.

### 18.11.2 Activation

Projection is opt-in per context. A maximum of **1024** simultaneously projected contexts may be registered per node; exceeding this limit returns an error.

```rust
node.enable_broadcast_projection(
    context_id,
    broadcast_key,
    admission,           // BroadcastAdmission — Open or Gated
    projection_policy,   // Option<ProjectionPolicy> — per-author overrides
).await?;
```

The `admission` parameter determines baseline authentication for projection endpoints (§5.14.4). The `projection_policy` provides per-author granularity within the bounds set by the admission mode.

Projected content is served at:

- **Feed:** `GET /scp/broadcast/<routing_id_hex>/feed`
- **Per-message:** `GET /scp/broadcast/<routing_id_hex>/messages/<blob_id_hex>`

Where `routing_id = SHA-256(context_id)` — this value is already public per §5.14.6 (used as the relay routing key for broadcast contexts). Exposing it in the URL path discloses no new information.

Projection is disabled per context via:

```rust
node.disable_broadcast_projection(context_id).await;
```

#### 18.11.2.1 Projection Policy

`ProjectionPolicy` controls per-author access rules for projected content, within the bounds set by the context's `BroadcastAdmission` mode.

```rust
pub struct ProjectionPolicy {
    /// Default rule for all authors without an explicit override.
    pub default_rule: ProjectionRule,
    /// Per-author overrides. Author DID → specific rule.
    pub overrides: Vec<ProjectionOverride>,
}

pub enum ProjectionRule {
    /// Content served without authentication.
    Public,
    /// Content requires valid messagesRead UCAN in Authorization header.
    Gated,
    /// Author chooses their own projection rule (author-side configuration).
    AuthorChoice,
}

pub struct ProjectionOverride {
    pub did: DID,
    pub rule: ProjectionRule,
}
```

**Ceiling constraints:**

- A **gated** context (`BroadcastAdmission::Gated`) cannot have `ProjectionRule::Public` as its default or as any per-author override. The admission mode is the floor — gated content cannot be projected publicly. `enable_broadcast_projection` rejects policies that violate this constraint.
- An **open** context (`BroadcastAdmission::Open`) can use any `ProjectionRule`. An author on an open context can choose to gate their projected content even though the broadcast key distribution is open.

**Template defaults:**

- `public-broadcast`: `ProjectionPolicy { default_rule: Public, overrides: vec![] }`
- `gated-broadcast`: `ProjectionPolicy { default_rule: Gated, overrides: vec![] }`
- `paid-broadcast`: `ProjectionPolicy { default_rule: Gated, overrides: vec![] }`

**Governance.** `ProjectionPolicy` is declared on `ContextParams` and follows the context's `CeilingPolicy` — immutable or governed. If governed, `ModifyCeiling` governance action can update the projection policy. Per-author overrides allow granular control: "everyone except Bob is gated — he's public" or "everyone gets to choose — except Dave, he's always public."

### 18.11.3 Feed Endpoint

`GET /scp/broadcast/<routing_id>/feed`

Returns the most recent messages in the broadcast context, decrypted and serialized as JSON:

```json
{
  "context_id": "<hex>",
  "author_did": "did:dht:...",
  "messages": [
    {
      "id": "<blob_id_hex>",
      "author_did": "did:dht:...",
      "key_epoch": 42,
      "published_at": "2025-01-15T10:30:00Z",
      "content": "<base64-encoded decrypted content>"
    }
  ]
}
```

Query parameters:

- `?since=<blob_id>` — return messages after the specified blob ID (exclusive). The `since` blob must belong to the same context (verified by `routing_id`); cross-context blob IDs return `400 Bad Request`.
- `?limit=N` — maximum number of messages to return. Default: 20, maximum: 100.

**Cursor expiry:** When a `since` blob ID refers to a blob that has expired or been purged from storage, the feed returns **empty** (no messages) rather than the full feed. Clients should treat an empty response to a previously-valid cursor as a signal to reset their cursor (omit `since`) and re-fetch from the beginning.

Caching headers:

- `Cache-Control: public, max-age=30, stale-while-revalidate=300` — content is public and changes as new messages arrive. 30-second freshness with 5-minute stale-while-revalidate gives CDNs useful cacheability without excessive staleness.
- `ETag: "<latest_blob_id>"` — the ETag is the most recent blob ID in the response.

### 18.11.4 Per-Message Endpoint

`GET /scp/broadcast/<routing_id>/messages/<blob_id>`

Returns a single decrypted message:

```json
{
  "id": "<blob_id_hex>",
  "author_did": "did:dht:...",
  "key_epoch": 42,
  "published_at": "2025-01-15T10:30:00Z",
  "content": "<base64-encoded decrypted content>"
}
```

Caching headers:

- `Cache-Control: public, immutable, max-age=31536000` — individual messages are immutable once published. Aggressive CDN caching with 1-year TTL.
- `ETag: "<blob_id>"` — the blob ID itself serves as a stable ETag.

Conditional GET: if the client sends `If-None-Match: "<blob_id>"`, the server returns `304 Not Modified` with no body.

**Error responses:**

- **400 Bad Request** — invalid hex in `routing_id` or `blob_id` path segment.
- **404 Not Found** — unknown routing ID (no projected context registered) or unknown blob ID (not in storage or routing ID mismatch).
- **410 Gone** — the message's key epoch has been purged from the projection registry after a `Both`-scope governance ban (§5.14.8). The content is permanently unavailable through projection. Clients should not retry. Body: `{"error": "content revoked", "code": "GONE"}`.
- **404 Not Found** — decryption failure (corrupt envelope or AEAD open failure). Returns the same `NOT_FOUND` response body as an unknown blob to prevent a decryption oracle — attackers cannot distinguish "blob exists but decryption failed" from "blob does not exist." Decryption failures are logged server-side at `WARN` level for operator diagnostics.

The feed endpoint (§18.11.3) silently omits messages whose epoch keys have been purged — they simply disappear from the feed rather than producing errors. This is consistent with the feed's role as a "latest content" view: revoked historical content is no longer latest.

### 18.11.5 Decryption Architecture

A `ProjectedContext` registry maps `routing_id → BroadcastKey` (per epoch):

1. On request: look up `routing_id` in the registry.
2. Query `BlobStorage` for the requested blob(s) using the existing `query(routing_id, since, limit)` interface.
3. Deserialize each blob as a `BroadcastEnvelope` (§5.14).
4. Open with the epoch-matched `BroadcastKey` from the registry.
5. Return decrypted content in the JSON response.

The `BlobStorage` instance is shared between the relay server and the projection handlers via `Arc<dyn BlobStorage>`. This requires `RelayServer::new` to accept `Arc<B>` so the same storage instance can be passed to both the relay and the `NodeState` (see ADR-035 for the architectural change).

Keys are retained per epoch for the blob TTL window. When a key epoch advances, the previous epoch's key remains available to decrypt blobs published under the old epoch until those blobs expire.

**Governance-ban key purge.** When a governance-level subscriber ban (§5.14.8) triggers key rotation via `RevokeAccess { access: Read }`, the projection registry must be updated to reflect the new key epoch(s). The SDK method `propagate_ban_keys()` (§18.11.8) handles this:

1. For each rotated author, the new post-rotation key is inserted into the `ProjectedContext` key registry.
2. If the ban's `AccessScope` is `Both`, all pre-ban epoch keys are **purged** from the registry via `retain_only_epochs()`. This ensures historical content encrypted under pre-ban keys is no longer decryptable by the projection endpoint — messages referencing purged epochs return 410 Gone (§18.11.4) on per-message requests and are silently omitted from feed responses (§18.11.3).
3. If the ban's `AccessScope` is `Write`, old-epoch keys are retained. Historical content remains accessible; only future content (under the new key) is inaccessible to the banned subscriber.

This differs from normal key rotation (where old keys are retained for the TTL window): a `Both`-scope governance ban is an explicit revocation of historical access, so old keys are immediately purged rather than retained.

### 18.11.6 Security Properties

- **Author's own keys only.** The node holds the broadcast keys it created. It cannot project contexts it merely subscribes to.
- **Read-only.** Projection endpoints serve content; they do not accept writes. The write path remains the SCP protocol (MLS or broadcast envelope).
- **Context-governed authentication.** Projection endpoints enforce authentication consistent with the context's `BroadcastAdmission` mode (§5.14.4):
  - **Open contexts** (`BroadcastAdmission::Open`): content served without authentication. Broadcast content was intended for broad distribution — the projection makes already-public content accessible via HTTP.
  - **Gated contexts** (`BroadcastAdmission::Gated`): content requires a `messagesRead` UCAN in the `Authorization: Bearer <token>` header. The projection layer performs **full cryptographic UCAN validation**: (1) JWT parse and UCAN header validation, (2) Ed25519 signature verification against the issuer's public key, (3) `exp`/`nbf` temporal bounds with clock skew tolerance, (4) capability matching (`messages:read` for the context), and (5) revocation check against the node's revocation set. The projection node maintains a cached set of valid issuer public keys derived from context membership (supplied via `enable_broadcast_projection` and updated via `update_projection_member_keys`). DID resolution is performed at registration time, not per-request — the node caches resolved public keys. Revocation status uses the same revocation set the node maintains for native protocol operations, updated via `revoke_projection_token`. Successfully validated tokens are cached briefly (60s TTL) to amortize the cost of Ed25519 verification across repeated requests. Requests with an invalid, expired, revoked, or forged UCAN receive `401 Unauthorized` with JSON error body `{"error": "...", "code": "UNAUTHORIZED"}`.
  - **Per-author overrides**: `ProjectionPolicy` overrides (§18.11.2.1) can specify different rules per author DID, within ceiling constraints. A gated context cannot have public per-author overrides (ceiling is the floor).
- **Cache-Control for gated content.** Gated projection responses use `Cache-Control: private` (not `public`) to prevent CDNs from caching authenticated content. Specifically:
  - Gated feed: `Cache-Control: private, max-age=30`
  - Gated per-message: `Cache-Control: private, immutable, max-age=31536000`
  - Open endpoints retain `Cache-Control: public` as specified in §18.11.3 and §18.11.4.
- **`routing_id` is not new disclosure.** The `routing_id = SHA-256(context_id)` is already visible to relays (§5.14.6). Using it in URL paths reveals nothing beyond what relays already observe.
- **Per-IP rate limiting.** Projection endpoints apply a per-IP token-bucket rate limiter (default 60 req/s, configurable via `SCP_NODE_PROJECTION_RATE_LIMIT`). Requests exceeding the limit receive HTTP 429 Too Many Requests. This prevents abuse of the endpoints that perform crypto decryption and blob reads per request. When deployed behind a reverse proxy or CDN, all requests arrive from the proxy's IP — operators in this topology MUST configure `X-Forwarded-For` / `X-Real-IP` extraction with a trusted-proxy allowlist. `X-Forwarded-For` extraction MUST only be enabled when the connecting IP is in the trusted-proxy list. Without this configuration, the node MUST rate-limit by connection source IP, and operators MUST rely on proxy-layer rate limiting.

### 18.11.7 `scp://` URI Integration

When broadcast projection is enabled for a context, the `scp://` URI (§18.4) gains an optional `projection` query parameter pointing to the HTTP feed URL:

```
scp://context/<context_id_hex>?relay=wss://example.com/scp/v1&projection=https://example.com/scp/broadcast/<routing_id_hex>/feed
```

This allows URI consumers to choose between the native SCP path (relay + broadcast key) and the HTTP projection path (standard GET request). The `projection` parameter is advisory — clients that support native SCP ignore it.

### 18.11.8 SDK Surface

- `ApplicationNode::enable_broadcast_projection(context_id, broadcast_key, admission, projection_policy, site_config, member_keys) -> Result<(), NodeError>` — activates HTTP projection for the specified broadcast context. `admission: BroadcastAdmission` determines baseline authentication (§5.14.4). `projection_policy: Option<ProjectionPolicy>` provides per-author overrides (§18.11.2.1). `site_config: Option<SiteConfig>` provides node-local site configuration for content delivery (§18.11.12). `member_keys: HashMap<String, [u8; 32]>` maps subscriber/member DIDs to their Ed25519 public keys for UCAN signature verification on gated projection endpoints (§18.11.6). Registers the context, key, admission mode, policy, site config, and member keys in the `ProjectedContext` registry. Returns `NodeError::InvalidConfig` if the projected context limit (1024) has been reached, if the projection policy violates ceiling constraints (e.g., `Public` rule on a gated context), if a duplicate hostname is detected, or if `SiteConfig` validation fails.
- `ApplicationNode::disable_broadcast_projection(context_id)` — deactivates HTTP projection for the specified context. Removes it from the registry. Existing CDN caches may continue serving stale content per their cache headers.
- `ApplicationNode::update_projection_member_keys(context_id, member_keys) -> Result<(), NodeError>` — updates the cached member public keys for a projected context. Called when context membership changes (new subscribers, removed subscribers, key rotations). No-op if the context is not projected.
- `ApplicationNode::revoke_projection_token(context_id, token_cid)` — adds a token CID to the projected context's revocation set. Tokens matching this CID will be rejected on subsequent requests. No-op if the context is not projected.
- `ApplicationNode::propagate_ban_keys(context_id, ban_result)` — updates the projection key registry after a governance-level subscriber ban. Inserts post-rotation keys for each rotated author. For `Both`-scope bans, purges all pre-ban epoch keys so historical content is no longer served (§18.11.5). No-op if the context is not projected. Must be called after `execute_governance_action` returns `GovernanceActionResult::SubscriberBanned`.
- `ApplicationNode::broadcastPublishAsset(asset: AssetEntry) -> Result<PublishResult, NodeError>` — publishes a single asset to the current deploy. Returns `{ blob_id: String, etag: String }` where `etag` is `SHA-256(body)` hex-encoded. Content-hash dedup: if a blob with the same `SHA-256(body)` already exists in the current `deploy_id`, skips re-upload and returns existing `blob_id`.
- `ApplicationNode::broadcastPublishAssets(assets: Vec<AssetEntry>, deploy_id: Option<String>) -> Result<Vec<PublishResult>, NodeError>` — publishes a batch of assets and commits the deploy atomically. If `deploy_id` is `None`, generates a new one. Returns `Vec<{ blob_id, etag }>`. Content-hash dedup applied per asset.
- `ApplicationNode::broadcast_projection_router() -> axum::Router` — returns the projection router for composition. Served on the public HTTPS port alongside `.well-known/scp` and `/scp/v1`.

```rust
/// A single asset to publish as broadcast content.
pub struct AssetEntry {
    pub path: ContentPath,
    pub content_type: MimeType,
    pub body: Vec<u8>,
}
```

### 18.11.9 Structured Broadcast Content

`BroadcastContent` is the canonical inner payload format for broadcast messages. It replaces opaque `Vec<u8>` payloads with a versioned, structured format that carries content metadata alongside the body. This is what `encrypted_content` decrypts to — the outer `BroadcastEnvelope` wire format is unchanged. Relays see the same opaque ciphertext blob they always have; the relay capability ceiling (§9.9.1) is preserved.

```rust
/// Magic byte prefix: ASCII "SCP" + version byte. Inside AEAD ciphertext.
/// Relay never sees this.
pub const BROADCAST_CONTENT_MAGIC: [u8; 3] = [0x53, 0x43, 0x50]; // "SCP"

/// Canonical inner payload of a broadcast message.
/// Wire format: BROADCAST_CONTENT_MAGIC ++ version_u8 ++ MessagePack(BroadcastContent)
/// Then AES-256-GCM encrypted into BroadcastEnvelope.encrypted_content.
pub struct BroadcastContent {
    pub version: u8,                          // inner content format version (1)
    pub metadata: ContentMetadata,
    pub body: Vec<u8>,                        // raw content bytes
}

pub struct ContentMetadata {
    pub path: Option<ContentPath>,            // validated URL path newtype
    pub content_type: Option<MimeType>,       // validated MIME type newtype
    pub deploy_id: Option<String>,            // groups assets into atomic deploys
    pub etag: Option<String>,                 // SHA-256(body), hex-encoded
    pub immutable: bool,                      // default false; determines cache behavior
}

/// Validated URL path. Rejects: `..`, `//`, `./`, `\`, null bytes, control chars,
/// non-UTF-8, percent-encoded traversals, query strings, fragments.
/// Rejects any `%`-encoded byte (paths are literal UTF-8, no percent-decoding).
/// Rejects non-ASCII whitespace (U+00A0, U+2000–U+200F, U+FEFF).
/// Path segments must not be `.` or `..` (but segments starting with `.` like `.hidden` are allowed).
/// NFC normalization recommended on construction.
/// Enforces: leading `/`, max 1024 bytes, no trailing slash (except root `/`).
/// Case-sensitive. Backslashes rejected (not silently normalized).
pub struct ContentPath(String);

/// Validated MIME type. Strictly `type/subtype` form. Parameters (e.g., `; charset=utf-8`) are rejected.
/// The node sets `charset=utf-8` automatically for `text/*` types.
/// Must match `type/subtype` grammar (RFC 7231 §3.1.1.1).
/// Rejects CRLF and control characters (prevents HTTP response splitting).
pub struct MimeType(String);
```

**Design choice:** Structured inner payload, NOT a `BroadcastEnvelope` wire format change. The outer envelope (`encrypted_content: Vec<u8>`) is unchanged — relays see the same opaque ciphertext blob they always have. The relay capability ceiling is preserved.

**Breaking change (pre-launch, acceptable):** SDK code that currently treats decrypted bytes as raw application data must now deserialize `BroadcastContent` first.

**Version detection algorithm:** After AES-256-GCM decryption, check first 3 bytes for `BROADCAST_CONTENT_MAGIC` ("SCP"). If matched, read 4th byte as version. If `version >= 1`, deserialize remaining bytes as MessagePack `BroadcastContent`. Otherwise, treat entire payload as legacy raw bytes. False-positive probability is approximately 1/2^24 for uniformly random legacy payloads. Since this is a pre-launch breaking change, all existing broadcast content should be re-published under the new format.

**Backward compatibility:** Legacy messages (no magic prefix) are served via existing JSON feed endpoints only, not path-based endpoints.

**Dual version relationship:** Outer `BroadcastEnvelope.version: u16` = protocol wire format (SCP/1.0 = 0x0100). Inner `BroadcastContent.version: u8` = content format (independent lifecycle).

**`deploy_id` validation:** `deploy_id` MUST be 1–128 bytes, ASCII alphanumeric plus `-` and `_`. Empty strings are rejected.

**ETag algorithm:** `SHA-256(body)` hex-encoded. Consistent across all SDKs.

**ETag verification:** On commit, the node MUST compute `SHA-256(body)` for each asset and verify it matches `ContentMetadata.etag`. If `etag` is `None`, the node computes and populates it. If `etag` is `Some` and mismatches, the asset is rejected.

**`immutable` flag:** `ContentMetadata.immutable: bool` (default `false`) determines cache behavior. When `immutable: true`, serve with `Cache-Control: public, immutable, max-age=31536000`. When `false`, `max-age=0, must-revalidate` with ETag. Cache behavior is determined by this flag, not by heuristic content-hash detection.

**`ContentEncoding` excluded** — tower-http handles compression on the fly. Pre-compressed content delivery introduces complexity (gzip bomb validation, encoding trust) without proportional value for the current use case.

**Resource limits:**

- Max 10,000 assets per deploy.
- Max 512 MiB total deploy size (sum of all bodies).
- Max 8 deploys retained per projected context (configurable).

### 18.11.10 Path-Based Projection Endpoints

Each projected context can be bound to a hostname via `SiteConfig` (§18.11.12). The node performs virtual host routing — requests to that hostname resolve directly to the context's path index. Visitors see clean URLs:

```
GET https://mysite.example.com/about        →  path index lookup for "/about"
GET https://mysite.example.com/styles.css   →  path index lookup for "/styles.css"
GET https://mysite.example.com/             →  index_path (default "/index.html")
```

An internal canonical path (`/scp/broadcast/<routing_id>/site/<path>`) is also available for programmatic access and debugging, but is never user-facing.

Path resolution:

- Resolves `path` to the blob in the current deploy with matching `ContentMetadata.path`.
- Returns the raw body (not JSON-wrapped) with the declared `Content-Type` header.
- **No Accept negotiation** — site endpoints always serve raw content. JSON envelopes remain available at `/messages/<blob_id>`.
- Unknown paths: 404 with `Cache-Control: no-store`.
- Path collision resolution: highest `sequence` number within current `deploy_id`.

**Required security headers on all site responses:**

- `X-Content-Type-Options: nosniff`
- `Content-Security-Policy: default-src 'self'` (configurable per-context via `SiteConfig`, validated: must not contain `unsafe-eval`, `unsafe-inline`, `unsafe-hashes`, wildcard `*` source expressions, or `data:` / `blob:` URI schemes)
- `X-Frame-Options: DENY`
- `Strict-Transport-Security: max-age=63072000; includeSubDomains`
- `Cross-Origin-Opener-Policy: same-origin`
- `Cross-Origin-Embedder-Policy: require-corp`
- `Referrer-Policy: same-origin`
- `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()`
- **MUST:** each projected context on its own hostname/subdomain for origin isolation (prevents cross-context XSS).

**Cache behavior:**

- Assets with `ContentMetadata.immutable: true`: `Cache-Control: public, immutable, max-age=31536000`.
- Assets with `immutable: false` (default): `Cache-Control: public, max-age=0, must-revalidate` with `ETag: "<deploy_id>:<content_hash>"` — forces CDN revalidation on every request (304 when unchanged, 200 on deploy swap).
- 404 responses: `Cache-Control: no-store`.
- Retains existing public/private distinction based on `ProjectionRule` (§18.11.2.1).
- **ETag format note:** `ContentMetadata.etag` stores the bare `SHA-256(body)` hex hash. The HTTP `ETag` header for non-immutable paths uses `<deploy_id>:<etag>` format to invalidate on deploy swap.

### 18.11.11 Atomic Deploys

A deploy is a set of content-addressed messages published under a shared `deploy_id`. The node maintains a `current_deploy_id` pointer per projected context.

**Implementation model (addresses concurrency, lock contention, partial failure):**

1. **Publish phase:** Assets are published as individual broadcast messages with `deploy_id` set. They go to blob storage only. The path index is NOT updated during publish.

2. **Commit phase:** On `broadcastPublishAssets` completion (or explicit commit), the node:
   - Scans all blobs matching the `deploy_id`.
   - Builds an immutable `PathIndex` (`HashMap<ContentPath, BlobId>`).
   - Stores the deploy manifest as a special blob (enables recovery on restart).
   - Atomically swaps the `current_deploy_id` pointer via `ArcSwap`.

3. **Concurrent reads:** HTTP handlers read `current_deploy_id` via `ArcSwap::load()` — lock-free. No contention with publish or commit operations.

4. **Deploy retention:** Double-buffer — current + previous deploy indexes kept in memory. Previous available for in-flight request draining. Configurable retention count (default 2) for multi-version rollback. Rollback only works within blob TTL window.

5. **Partial failure:** If publish crashes mid-batch, orphaned blobs expire via TTL. Path index was never built. Retry re-uploads all assets (new nonces, new blob_ids — clean slate).

6. **Deploy manifest blob:** A special broadcast message containing the complete `path -> blob_id` mapping for a deploy. Loaded on `enable_broadcast_projection()` to rebuild path index on node restart. Solves persistence.

7. **Key rotation during deploy:** If broadcast key rotates mid-publish (governance ban), mixed-epoch blobs are cryptographically sound (projection holds all epoch keys). The deploy commit proceeds normally.

**Per-context path index:** `Arc<ArcSwap<PathIndex>>` per `ProjectedContext` — NOT on the shared `projected_contexts` registry lock. Per-asset publish requires NO write locks on the registry.

### 18.11.12 Site Configuration

Node-local config passed to `enable_broadcast_projection()`. NOT part of governance-governed `ProjectionPolicy` — site configuration is a deployment concern, not a protocol concern:

```rust
/// Node-local projection site config.
pub struct SiteConfig {
    pub hostname: String,                            // e.g., "mysite.example.com" — virtual host routing
    pub index_path: ContentPath,                    // default: "/index.html"
    pub max_assets_per_deploy: usize,               // default: 10_000
    pub max_deploy_size_bytes: u64,                  // default: 512 MiB
    pub deploy_retention_count: usize,               // default: 2, max: 8
    pub csp_override: Option<String>,                // validated CSP string
}
```

`hostname` determines virtual host routing (§18.11.10). `hostname` MUST be a valid DNS hostname (RFC 1123): lowercase ASCII letters, digits, hyphens, and dots. No wildcards, no IP literals, no ports, no paths. Maximum 253 characters. MUST NOT match the node's own serving hostname. Each projected context MUST have a unique hostname — duplicate hostnames across contexts are rejected by `enable_broadcast_projection()`. `enable_broadcast_projection()` rejects invalid or duplicate hostnames. Projected content endpoints MUST NOT set cookies.

`index_path` is the `ContentPath` served for the root path (`/`). Default: `/index.html`.

`deploy_retention_count` maximum value: 8. Values above 8 are rejected by `enable_broadcast_projection()`.

`csp_override` replaces the default `Content-Security-Policy: default-src 'self'` header. Validated on assignment: must not contain `unsafe-eval`, `unsafe-inline`, `unsafe-hashes`, wildcard `*` source expressions, or `data:` / `blob:` URI schemes. Invalid CSP strings are rejected.

**SPA fallback excluded** — it introduces security edge cases (CDN 404 caching, information disclosure profile change) and is a deployment convenience, not a protocol concern. Reverse proxies handle this transparently.
