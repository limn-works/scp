# 22. Human-Readable Addressing

## 22.1 Design Principles

SCP identifiers are cryptographic — DIDs (`did:dht:z6Mk...`) and context IDs (hex-encoded hashes). These are canonical at the protocol level and will remain so. But cryptographic identifiers fail the verbal handoff: "join my app" or "find me at ___" requires something a human can say and an agent can resolve.

The addressing layer adds a **resolution protocol** that accepts human-readable strings and returns DIDs or context IDs. It does not replace cryptographic identifiers, create a global namespace, or require centralized infrastructure. Handles are resolution hints — they narrow search. They never define identity.

**Primary mechanism: discovery context handles.** SCP-native, DNS-free, community-governed. This is where the spec's weight is. Discovery contexts (§6.2.2B) already provide searchable registries — this section extends them with handle registration and lookup.

**Local floor: petnames.** User-assigned names stored in identity private state (§3.7). Always work, zero infrastructure, zero governance. Petnames also close the disambiguation loop — when an unscoped query returns multiple candidates, the user's choice becomes a petname, resolving future ambiguity permanently.

**External identity bridge: attestation-backed handles.** Identity attestations (§3.5) already bind external platform handles (`@alice` on X) to DIDs. This section adds a reverse-lookup index so agents can resolve external handles to DIDs.

**Web compatibility extension: domain handles.** For organizations and individuals who already have domains, `.well-known/scp` (§18.3) is extended with a handles map. This is the same role `.well-known/scp` already plays — an optional web on-ramp, not self-certifying, not required. Not a protocol pillar.

**Graceful degradation.** Petnames always work (zero infrastructure). Discovery context handles work with SCP infrastructure only. Attestation handles work if external platforms exist. Domain handles work if DNS exists. Each is independently useful; none is required. Remove any layer and the rest continue functioning.

**Historical context.** Zooko's triangle (2001) identified tensions between human-readable, decentralized, and secure naming. Modern systems — AT Protocol's domain handles, blockchain naming (ENS, Handshake), Nostr's NIP-05 — demonstrate that the tradeoffs are more nuanced than a strict trilemma, depending on trust model and infrastructure assumptions. SCP's layered approach sidesteps the framing entirely: different resolution paths make different tradeoffs, the protocol carries explicit trust metadata on every resolution result, and the DID remains canonical regardless of which path was used to find it.

## 22.2 Address Format

All SCP human-readable addresses use a single canonical text format:

```
<local-part>@<scope>
```

**`local-part`:** The name portion. Case-insensitive, Unicode-normalized (NFC). Restricted to lowercase ASCII letters, digits, hyphens, underscores, and periods: `[a-z0-9._-]`. Maximum 64 characters. Leading and trailing hyphens/periods are not allowed. Consecutive periods are not allowed.

**`scope`:** The resolution context — determines how the local-part is resolved. Either a DNS domain or a discovery context name.

**Scope disambiguation.** Scope type is determined by syntactic inspection:

| Pattern | Resolution path | Example |
|---------|----------------|---------|
| Scope contains a `.` | Domain handle (§22.6), then attestation fallback (§22.5) | `alice@example.com` |
| Scope has no `.` | Discovery context handle (§22.3) | `alice@cooking-community` |
| No `@` separator, starts with `@` | Attestation-backed handle (§22.5) | `@alice_on_x` |
| No `@`, no prefix (bare name) | Unscoped — try all layers | `alice` |

**Domain vs. attestation ambiguity.** A scoped address like `alice@x.com` could be a domain handle (X operates `.well-known/scp` with a handles map) or an attestation handle (an SCP user attested they are `@alice` on X). The protocol does not attempt to distinguish these syntactically — no hardcoded platform list, no heuristic. Instead, scoped addresses containing a `.` always resolve domain-first (fetch `.well-known/scp`), then fall back to attestation lookup if the domain either doesn't serve `.well-known/scp` or doesn't contain the requested handle. Both paths are tried; results are merged with their respective trust levels. This avoids the need for any protocol-maintained registry of "known platforms."

### 22.2.1 Address Types

Two address types share the same format:

- **Identity addresses** resolve to a DID.
- **Context addresses** resolve to a context ID + relay URLs.

The `local-part` does not encode which type it is. Resolution determines the type. The address `recipes@cooking-community` might resolve to a context, an identity, or both. The resolver returns typed results:

```
AddressResolution:
  | Identity  { did, trust_level, resolution_path }
  | Context   { context_id, relay_urls, mode, trust_level, resolution_path }
```

Agent capabilities are not part of the addressing layer. A handle resolves to a DID; the DID document is the authoritative source for capabilities (`SCPCapabilities` service endpoint, §6.2.2A). A handle registry caching capabilities would be stale by design — capabilities change when agents are updated, and the DID document reflects the current state. Discovery contexts already provide capability search via `agent_search` (§6.2.2B).

### 22.2.2 Normalization

Before resolution, addresses are normalized:

1. `local-part` is lowercased and NFC-normalized.
2. `scope` is lowercased.
3. Leading/trailing whitespace is stripped.
4. The `@` separator is literal (not percent-encoded).

Two addresses that normalize to the same string are considered identical.

## 22.3 Discovery Context Handles (Primary Mechanism)

Discovery context handles are the primary human-readable addressing mechanism. They are SCP-native, DNS-free, and community-governed. Each discovery context is its own namespace with its own authority.

**Format:** `<name>@<discovery-context-name>`

**Examples:**
```
alice@cooking-community
recipes@cooking-community
translator-ja@global-services
```

### 22.3.1 Handle Tools

Discovery contexts that support handles expose three additional standard tool schemas alongside the existing `agent_search`/`agent_register`/`agent_deregister` tools (§6.2.2B). These are conventions, not mandates — a discovery context opts into handle support by implementing these tools.

```
handle_register(handle, target, metadata?) → confirmation
  input:  {
    handle:      string,          // the local-part to register
    target:      HandleTarget,    // what the handle points to (see below)
    metadata:    {                // optional descriptive metadata
      description: string?,
      tags:        [string]?
    }
  }
  output: {
    status:    "registered" | "conflict",  // unambiguous outcome
    entry_id:  string?                     // present when status = "registered"
  }

  HandleTarget:
    | Identity  { did: DID }
    | Context   { context_id: hex, relay_urls: [url] }
```

```
handle_lookup(handle, type_filter?) → results
  input:  {
    handle:      string,                              // the local-part to look up
    type_filter: ("identity" | "context")?            // optional type constraint
  }
  output: {
    results: [HandleResult]
  }

  HandleResult:                    // sum type matching HandleTarget
    | Identity  {
        handle:        string,
        did:           DID,
        registered_at: timestamp,
        metadata:      object
      }
    | Context   {
        handle:        string,
        context_id:    hex,
        relay_urls:    [url],
        registered_at: timestamp,
        metadata:      object
      }
```

```
handle_deregister(handle, did) → removal
  input:  {
    handle: string,       // the local-part to deregister
    did:    DID            // registrant's DID (must match owner)
  }
  output: { removed: bool }
```

The `did` parameter in `handle_deregister` is explicit rather than inferred from the request signature — this ensures the tool schema is self-documenting and the DID-to-handle ownership check is visible in the interface. Writers verify the DID-signed request signature matches the provided DID and that the DID owns the handle.

**Uniqueness.** A discovery context enforces handle uniqueness within its own namespace. `handle_register` returns `{ status: "conflict" }` when another DID already holds the requested handle. The handle uniqueness constraint applies per local-part: there can be at most one `alice` in a given discovery context, regardless of target type. Governance determines conflict resolution policy (first-come-first-served, admin-arbitrated, etc.).

**Ownership and verification.** The registrant's DID (authenticated via the DID-signed request) is the handle owner. Only the owner can update or deregister. All handle tool requests MUST carry a DID signature over the request payload. Writers MUST verify the signature before processing. The event log entry for a registration includes the full signed request as payload, making verification replayable by any party with access to the event log. The ownership chain is: DID-signed request → writer verifies signature cryptographically → event log records the registration with the signed payload and owner DID.

**DID-signature verification scheme.** Handle tool requests use the same DID-authentication mechanism as discovery context reader requests (§6.2.2B). The signature is constructed as follows:

1. **Canonical payload.** The request payload is serialized to canonical JSON (keys sorted lexicographically, no whitespace, no trailing commas). This produces a deterministic byte sequence regardless of JSON serialization library.
2. **Signed content.** The signed bytes are: `"SCP-HANDLE-TOOL-V1:" || tool_name || ":" || canonical_json_bytes`, where `tool_name` is one of `"handle_register"`, `"handle_lookup"`, `"handle_deregister"`, and `||` denotes byte concatenation. The domain prefix `"SCP-HANDLE-TOOL-V1:"` prevents cross-protocol signature reuse.
3. **Signature algorithm.** Ed25519 using the requester's `#active` signing key (or `#agent` key if the request is agent-initiated under a valid UCAN delegation).
4. **Transport.** The signature is carried as an additional field in the tool call request envelope:
   ```
   {
     "input": { ... },                    // the tool's input payload
     "requester_did": "<DID>",            // explicit for verification
     "signature": "<base64url(Ed25519-sign(signing_key, signed_content))>",
     "signing_key_id": "#active"          // which verification method signed
   }
   ```
5. **Writer verification.** The writer resolves the `requester_did` via DID document, extracts the public key for `signing_key_id`, and verifies the Ed25519 signature over the reconstructed `signed_content`. If verification fails, the request is rejected with a `BRIDGE_NOT_AUTHORIZED` error. The writer MUST verify that the DID document is fresh (fetched within the last 300 seconds or cached with valid TTL).

**Two-tier model.** Handle tools follow the same two-tier architecture as existing discovery tools (§6.2.2B). Writers (MLS members) process handle registrations. Readers (DID-authenticated, unbounded) perform handle lookups. Registration is a write operation processed by writers; lookup is a read operation available to all.

### 22.3.2 Discovery Context Naming

Discovery contexts have a `name` field in their metadata (§5.7). The name used as the `scope` in addresses is this metadata name, normalized: lowercased, spaces replaced with hyphens, non-alphanumeric characters (except hyphens) removed. This normalized form is the **canonical scope name**.

Example: A discovery context with metadata name "Cooking Community" has canonical scope name `cooking-community`.

The SDK ships with a mapping of default discovery context IDs to their canonical scope names. This mapping is configurable and extensible — apps can add domain-specific discovery contexts with their own scope names.

**Scope name collisions.** Two discovery contexts may have the same canonical scope name. This is analogous to two email providers happening to exist — they are different namespaces with different content, and the resolver must distinguish them. The SDK maintains a local registry of known discovery contexts indexed by canonical scope name. If multiple contexts share a name, the SDK uses the most recently used or user-preferred context. Users can disambiguate by specifying a discovery context explicitly in client UI (selecting from a list rather than typing a scope name).

### 22.3.3 Resolution Flow

```
1. Client receives "alice@cooking-community"
2. Parse: local-part = "alice", scope = "cooking-community"
3. Scope has no "." → discovery context handle
4. Look up "cooking-community" in SDK's known discovery context registry
5. Call handle_lookup("alice") on the matched discovery context
6. Get result: Identity { did: "did:dht:z6MkAlice..." }
7. Resolve DID via Mainline DHT (self-certifying, §9.6.1)
8. Return AddressResolution::Identity {
     did: "did:dht:z6MkAlice...",
     trust_level: DiscoveryContextVerified,
     resolution_path: { layer: "discovery_context", context_name: "cooking-community", context_id: "..." }
   }
```

### 22.3.4 Handle Registry Template

A new well-known context template for discovery contexts that serve as handle registries:

```
Template: "scp:template/handle-registry"
  mode:          Encrypted
  ceiling:       [messagesRead, messagesWrite, toolRegister, toolInvokeAll]
  ceiling_policy: immutable
  roles:
    admin:       all capabilities + memberInvite, roleAssign
    registrar:   messagesWrite, toolInvokeAll      // processes registrations
    reader:      messagesRead                      // DID-authenticated readers (unbounded)
  governance:    single-admin
  memory_scope:  full
  tools:         handle_register, handle_lookup, handle_deregister,
                 agent_search, agent_register, agent_deregister
```

This template is a starting point. Discovery contexts can customize governance, add tools (reputation scoring, category browsing), or restrict registration policies via context governance. The template follows the two-tier model: bounded registrars/admins (MLS members), unbounded readers.

## 22.4 Petnames (Local Floor)

Petnames are locally-assigned names for contacts and contexts. They are private, immediate, and require zero infrastructure. Petnames are the resolution floor — the addressing capability that always works regardless of what else is available.

**Format:** Any string the user chooses. Not protocol-scoped, not shareable, not governed.

**Storage:** Identity private state (§3.7). Petnames are personal annotations — the same infrastructure that stores block/mute lists, graph visibility policies, and notes on other DIDs. New event types for the identity private state event log:

```
PrivateStateEvent:
  | SetPetname          { did: DID, name: string }
  | RemovePetname       { did: DID }
  | SetContextPetname   { context_id: ContextId, name: string }
  | RemoveContextPetname { context_id: ContextId }
```

Petnames sync across devices via the identity private state event log (§3.7). Set "mom" on your phone, it resolves on your laptop.

**Resolution.** Petnames are the first layer checked in resolution — before any network calls. If a petname matches the input, it returns immediately.

**Disambiguation.** When an unscoped query (`alice`) returns multiple candidates from different resolution paths, the client presents the options to the user. The user's selection auto-creates a petname, resolving future ambiguity for that name permanently (locally). This is the mechanism that makes the multi-namespace system tolerable — you disambiguate once, never again.

**Trust level:** `LocalPetname` — maximum personal trust (the user set it), zero shareability.

**Conflict within petnames.** A user can assign the same petname to multiple DIDs (e.g., two contacts both named "bob"). The resolver flags this as ambiguous and presents both. The user can differentiate by editing petnames ("work-bob", "gym-bob"). This is a local UX concern, not a protocol problem.

### 22.4.1 SDK Surface

```
SCP.PrivateState.write(
  did: myDID,
  event: .setPetname(did: aliceDID, name: "alice")
       | .removePetname(did: aliceDID)
       | .setContextPetname(contextID: recipesContext, name: "recipes")
       | .removeContextPetname(contextID: recipesContext)
)

// Petname lookup (local, instant)
SCP.AddressResolver.resolvePetname(name: "alice") → DID?
SCP.AddressResolver.resolveContextPetname(name: "recipes") → ContextId?
```

## 22.5 Attestation-Backed Handles (External Identity Bridge)

Identity attestations (§3.5) already bind external platform handles to DIDs — `@alice` on X → `did:dht:z6Mk...`. This binding is cryptographically signed, user-initiated, independently verifiable, and revocable. What's missing is a **reverse-lookup index**: given `@alice` on X, find the DID.

The addressing layer adds reverse-lookup as a discovery context tool, not a new protocol primitive. When a user creates an identity attestation, the SDK SHOULD (opt-out configurable) register the mapping in one or more discovery contexts that support attestation indexing.

**Format:** `@<handle>` (unqualified, searches all known platforms).

**Examples:**
```
@alice_cooks                    // search all platforms for "alice_cooks"
@alice_cooks:x                  // search X specifically (platform-qualified)
@alice:github                   // search GitHub specifically
```

The `@handle` prefix is the syntactic marker for attestation-backed handles. The optional `:platform` suffix qualifies the search to a specific platform — the platform identifier is the short name used in attestation metadata (§3.5), not a domain. This avoids all ambiguity with domain handles: `@alice:x` is unambiguously an attestation lookup on platform "x", while `alice@x.com` follows the standard scoped resolution path (domain first, then attestation fallback per §22.2).

### 22.5.1 Attestation Lookup Tool

A new standard discovery tool schema for reverse-lookup:

```
attestation_lookup(platform, handle) → results
  input:  {
    platform:    string,          // "x", "github", "mastodon", etc.
    handle:      string           // the platform handle
  }
  output: {
    results: [{
      did:             DID,
      attestation_id:  string,
      platform:        string,
      handle:          string,
      verified_via:    string,    // "oauth", "signed_post", "dns"
      last_verified:   timestamp,
      stale:           bool       // per §7.3.6 renewal intervals
    }]
  }
```

Multiple results are possible if multiple DIDs claim the same platform handle (one legitimate, others potentially fraudulent). The `verified_via` and `last_verified` fields help consumers evaluate freshness and strength. Results marked `stale: true` have not been re-verified within the renewal interval.

### 22.5.2 Auto-Registration

When a user creates an identity attestation (§3.5), the SDK SHOULD register the mapping in known discovery contexts that support `attestation_lookup`. This is opt-out via configuration. The registration flow:

1. User creates attestation: `SCP.Attestation.create(type: .identityLink, claim: { platform: "x", handle: "@alice_cooks" }, ...)`
2. SDK discovers which known discovery contexts support `attestation_lookup`.
3. SDK registers the mapping in each via a DID-authenticated request.
4. Writers in the discovery context verify the attestation before recording it.

The discovery context's governance determines what verification is required before a mapping is accepted. A permissive registry might accept any signed attestation. A strict registry might require challenge-verified attestation with recent verification timestamp.

### 22.5.3 Resolution Flow

```
1. Client receives "@alice_cooks" (or "@alice_cooks:x" for platform-qualified)
2. Parse: attestation-backed handle (leading @)
   - If platform-qualified: extract platform from ":x" suffix
   - Otherwise: platform = "*" (search all)
3. Query known discovery contexts that support attestation_lookup
4. For each: attestation_lookup(platform: platform, handle: "alice_cooks")
5. Merge results, deduplicate by DID
6. For each result, verify attestation is still valid (not revoked, not stale)
7. Resolve DID(s) via Mainline DHT
8. Return results with trust_level: AttestationVerified
```

**Trust level:** `AttestationVerified` — the binding is cryptographically signed by the DID holder and verified against the external platform. Trust depends on: (a) the attestation being valid and fresh, (b) the external platform identity being legitimate (the platform's problem, not SCP's).

## 22.6 Domain Handles (Web Compatibility Extension)

Domain handles are an optional web on-ramp for human-readable addressing — the same role `.well-known/scp` plays for relay discovery (§18.3). They are NOT self-certifying, NOT required, and NOT a protocol pillar. They exist for organizations and individuals who already have domains and want familiar addressing for web audiences.

**Format:** `<name>@<domain>`

**Examples:**
```
alice@example.com
recipes@cooking.example.com
translator@services.example.com
```

### 22.6.1 .well-known/scp Extension

The `.well-known/scp` document format (§18.3.1) is extended with an optional `handles` field:

```json
{
  "version": 1,
  "did": "did:dht:z6Mk...",
  "relay": "wss://relay.example.com/scp/v1",
  "handles": {
    "alice": {
      "type": "identity",
      "did": "did:dht:z6MkAlice..."
    },
    "recipes": {
      "type": "context",
      "context_id": "a1b2c3d4e5f6...",
      "relay": "wss://relay.example.com/scp/v1"
    }
  },
  "contexts": [ ... ],
  "relay_config": { ... }
}
```

**New field:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `handles` | object | No | Map of local-part → resolution record. Keys are handle local-parts; values are resolution records. |

**Resolution record fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | `"identity"` or `"context"`. |
| `did` | string | Conditional | DID. Required for `identity` type. |
| `context_id` | string | Conditional | Hex-encoded context ID. Required for `context` type. |
| `relay` | string | No | Override relay URL for context types. Defaults to document-level `relay`. |

**Constraints:**

- Handle keys must match the address format (§22.2): `[a-z0-9._-]`, max 64 chars.
- Only broadcast context IDs may appear in `context` type handles (same privacy constraint as the existing `contexts` field — encrypted context IDs MUST NOT appear, §9.10). Identity handles are unrestricted — DIDs are public by design.
- Domain operators control their namespace. The handles map is managed by whoever controls the domain's `.well-known/scp` file.

### 22.6.2 Resolution Flow

```
1. Client receives "alice@example.com"
2. Parse: local-part = "alice", scope = "example.com" (contains ".")
3. Try domain resolution:
   a. Fetch https://example.com/.well-known/scp
   b. Look up "alice" in the "handles" map
   c. If found: resolve DID via Mainline DHT (self-certifying, §9.6.1)
      Verify: DID document's SCPRelay entries are consistent
      Return AddressResolution with trust_level: DomainVerified
4. If domain resolution fails (no .well-known/scp, or handle not in map):
   a. Extract domain name as potential platform identifier
   b. Query attestation_lookup(platform: inferred, handle: "alice")
   c. If found: return with trust_level: AttestationVerified
5. If both fail: AddressError::NotFound
```

This two-phase resolution eliminates the need for a hardcoded platform list. `alice@example.com` tries the domain first; `alice@x.com` also tries the domain first — if X serves `.well-known/scp` with handles, the domain result wins. If not, attestation fallback catches it. The trust level on the result tells the consumer which path succeeded.

**Security properties.** Same as `.well-known/scp` generally (§18.3.2): NOT self-certifying, depends on HTTPS. The DID itself is verified via DHT, but the binding of a handle to that DID depends on domain control. An attacker who controls DNS/CA can serve fraudulent handles, but cannot forge the DHT-resolved DID document. Clients MUST perform the verification chain before trusting domain handle resolutions.

**Trust level:** `DomainVerified` — the binding is HTTPS-dependent and domain-operator-controlled.

## 22.7 Trust Levels

Every resolution result carries a trust level indicating the strength and source of the handle-to-identifier binding.

```
TrustLevel:
  | DirectExchange              // DID exchanged out-of-band, verified by the user
  | LocalPetname                // user-assigned, maximum personal trust
  | MultiLayerCorroborated {    // multiple resolution paths agree on the same DID
      sources: [ResolutionPath] // which paths corroborated
    }
  | DomainVerified              // HTTPS-dependent, domain operator controls binding
  | AttestationVerified         // cryptographically signed, platform-dependent verification
  | DiscoveryContextVerified    // community-governed, discovery context controls binding
```

Trust levels are not strictly ordered — their relative strength is context-dependent. `DomainVerified` is stronger than `DiscoveryContextVerified` in some threat models (established domain with TLS history) and weaker in others (DNS seizure risk). The SDK exposes trust levels to consumers (agents, client UI); consumers decide what's sufficient for their operation.

**`MultiLayerCorroborated`** indicates that multiple resolution paths agree on the same DID. The `sources` field records which paths corroborated, enabling consumers to evaluate the independence of the corroboration. **Caveat:** corroboration across layers is only as strong as the independence of those layers. An attacker who controls a domain, a discovery context, and an attestation can fake corroboration across all three cheaply. Consumers SHOULD evaluate the diversity of corroboration sources (e.g., a domain + an attestation from a major platform + an established discovery context is meaningfully harder to fake than a domain + a self-operated discovery context). The SDK SHOULD flag `MultiLayerCorroborated` results where all non-petname sources share a common operator or were registered within a short time window.

**`Ambiguous` is a resolution outcome, not a trust level.** When multiple resolution paths find different DIDs for the same handle, the resolver returns multiple `AddressResolution` results — each with its own trust level — rather than a single result tagged `Ambiguous`. The resolver's return type (`Vec<AddressResolution>`) naturally represents this: a single result means unambiguous resolution; multiple results mean the consumer must disambiguate (§22.8.3).

Each `AddressResolution` also carries a `ResolutionPath` — structured metadata recording which layer resolved the address, what source was used, and when. This is provenance for the resolution itself.

```
ResolutionPath {
  layer:         "petname" | "discovery_context" | "attestation" | "domain",
  source:        string,     // discovery context name, domain, platform
  source_id:     string?,    // discovery context ID (hex, for discovery_context layer)
  resolved_at:   timestamp,
}
```

## 22.8 Unified Resolution Protocol

The `AddressResolver` is an SDK-level type that implements multi-path resolution. It is not a wire-protocol component — it is standardized SDK behavior that ensures consistent resolution across implementations.

### 22.8.1 Scoped Resolution

When the address includes a scope, the scope determines the resolution path:

- **No `.` in scope** (`alice@cooking-community`): discovery context handle only. One namespace, one authority, one answer.
- **`.` in scope** (`alice@example.com`): domain-first with attestation fallback (§22.6.2). If the domain serves `.well-known/scp` with the handle, that answer wins with `DomainVerified`. If not, attestation fallback is tried. The result carries its trust level, so the consumer knows which path succeeded.

### 22.8.2 Unscoped Resolution

When the address has no scope (`alice` or `@alice`), the resolver searches all paths:

```
1. Check local petnames (instant, no network)
   → If found: return immediately with trust_level: LocalPetname

2. In parallel:
   a. Check domain handles for configured domains
   b. Query known discovery contexts via handle_lookup
   c. Query attestation indexes via attestation_lookup

3. Collect results, deduplicate by DID

4. Evaluate:
   a. No results → AddressError::NotFound
   b. One DID found via single path → return with that path's trust level
   c. One DID found via multiple paths → return with trust_level:
      MultiLayerCorroborated { sources: [all agreeing paths] }
   d. Multiple DIDs found → return all as separate AddressResolution entries,
      each with its own trust level. Client presents options (§22.8.3)
```

### 22.8.3 Collision and Disambiguation

**Scoped addresses: no collision possible.** Each scope is its own namespace with its own authority. `alice@example.com` has exactly one answer (domain operator controls it). `alice@cooking-community` has exactly one answer (discovery context enforces uniqueness via `handle_register`).

**Cross-scope: not a collision.** `alice@example.com` and `alice@cooking-community` may be different people. These are different addresses — like `alice@gmail.com` and `alice@yahoo.com` in email. No disambiguation needed.

**Unscoped addresses: the only place collisions occur.** When the resolver searches all paths and finds different DIDs from different sources, it returns multiple `AddressResolution` entries, each with its own trust level. The client presents the options:

> "Did you mean alice@cooking-community (Alice Chen) or alice@example.com (Alice Smith)?"

The user selects one. **The SDK auto-creates a petname** binding `alice` → the selected DID. Next time the user types `alice`, it resolves instantly via petname. The collision is resolved once, permanently (locally).

The protocol does not prevent name collisions — it surfaces them transparently and resolves them through user choice. This is why it does not need a central namespace or consensus mechanism.

### 22.8.4 Resolution Caching

The SDK caches resolution results locally to avoid redundant network calls. Cache entries are keyed by normalized address string, with per-layer TTLs: petnames are indefinite (user-managed); domain handles follow HTTP caching semantics (~1 hour); discovery context handles are short-lived (~15 minutes); attestation handles match attestation renewal intervals (§7.3.6). Cache misses trigger fresh resolution. Cache hits with expired TTL trigger background re-resolution (return cached result immediately, verify in background). Cache implementation details are specified in `.docs/scaffold/`.

### 22.8.5 SDK Surface

```
// Parse and resolve any human-readable address
SCP.Address.resolve(
  address: "alice@cooking-community"
) → [AddressResolution]

// Register a handle in a discovery context
SCP.Address.register(
  handle: "alice",
  scope: discoveryContextID,
  target: .identity(did: myDID)
        | .context(contextID: recipesCtx, relayURLs: [...])
) → { status: "registered" | "conflict", entryID: string? }

// Deregister a handle
SCP.Address.deregister(
  handle: "alice",
  scope: discoveryContextID
) → { removed: bool }

// Set a petname (local, private)
SCP.Address.setPetname(name: "alice", did: aliceDID)
SCP.Address.setContextPetname(name: "recipes", contextID: recipesCtx)

// Resolve with explicit scope
SCP.Address.resolveInContext(
  handle: "alice",
  discoveryContext: cookingCommunityID
) → [AddressResolution]
```

## 22.9 Wire Type Extensions

### 22.9.1 scp:// URI: Handle Query Parameter

The existing `scp://` URI format (§18.4) is extended with an optional `handle` query parameter:

```
scp://context/a1b2c3d4e5f6?relay=wss://relay.example.com/scp/v1&handle=recipes@cooking-community
```

The `handle` parameter is advisory — same status as the existing `name` parameter (§18.4.1). It provides a human-readable reference that clients can display and use as a resolution starting point, but the canonical reference remains the `context_id` in the path.

### 22.9.2 Identity Private State Extensions

New event types for the identity private state event log (§3.7):

```
PrivateStateEvent:
  // ... existing events (block, mute, grantGraphVisibility, etc.) ...

  | SetPetname            { did: DID, name: string }
  | RemovePetname         { did: DID }
  | SetContextPetname     { context_id: ContextId, name: string }
  | RemoveContextPetname  { context_id: ContextId }
```

These events follow the existing identity private state model: append-only event log, commutative operations, Merkle root for integrity, encrypted to the identity's own keys, synced across devices.

## 22.10 Security Analysis

### 22.10.1 Handle Squatting

**Discovery context handles.** Governance determines policy. First-come-first-served is the default. Discovery contexts can require attestation-backed registration (prove you are `@alice` on X before claiming `alice@premium-registry`), admin approval, or other policies. Squatting within a discovery context is a governance problem for that community.

**Domain handles.** Domain operators control their namespace. Squatting within a domain is the domain operator's problem — identical to email.

**Attestation handles.** Squatting is platform-level (`@alice` on X is X's problem, not SCP's). Within SCP, attestation verification prevents false claims — you must cryptographically prove you control the external identity.

**Petnames.** Cannot be squatted. Local namespace.

### 22.10.2 Handle Spoofing

A malicious actor registers a handle that resembles a legitimate one (homoglyph attack, typosquatting). This is the §5.8 problem: "Spoofing a name is a UI problem for clients to solve."

Protocol defenses:
- **Trust levels** on every resolution result. Clients SHOULD warn on first-contact resolutions and low-trust handles.
- **MultiLayerCorroborated** raises the bar — requires controlling multiple independent resolution sources. But see the caveat in §22.7: corroboration is only as strong as the independence of the sources.
- **DID is canonical.** The worst case of spoofing is connecting to the wrong DID. Since MLS encryption is keyed to specific DIDs (§9.7), messages intended for the legitimate party cannot be read by the spoofed identity.

### 22.10.3 Stale Handles

A handle that previously pointed to one DID now points to another (domain transfer, handle re-registration, revoked attestation).

Protocol defenses:
- **Resolution cache tracks history.** A handle whose target DID changed since last resolution triggers a warning.
- **DID is canonical.** If a user has previously communicated with a DID via a handle, the SDK tracks the DID, not the handle. Handle re-resolution is only needed for new contacts.
- **Attestation freshness.** Attestation-backed handles carry `last_verified` timestamps. Results past the renewal interval are marked `stale: true`.

### 22.10.4 Privacy

**Petnames.** Fully private. Encrypted in identity private state (§3.7). No external visibility.

**Discovery context handles.** Handle registrations are visible to the discovery context (writers see all registrations, readers can query). Handle lookups are DID-authenticated — the discovery context sees who queries what. This is an inherent property of any registry. Registration is opt-in per discovery context, withdrawable via `handle_deregister`.

**Attestation handles.** Attestation existence is public (published for discovery). The reverse-lookup query is a discovery context tool call with the same privacy properties as handle lookups.

**Domain handles.** The domain operator sees all handles and query traffic. HTTPS protects against third-party observation. Same privacy model as any HTTP-based service.

### 22.10.5 Query Surveillance

Discovery context handle lookups and attestation lookups are DID-authenticated tool calls. This means discovery context writers can observe every lookup — who searched for whom, when, how often. This is a structural property of any registry model and is not unique to SCP, but it bears explicit acknowledgment.

Mitigations:
- **Multiple discovery contexts.** Users can distribute their lookups across multiple registries, preventing any single registry from seeing the full query pattern.
- **SDK caching.** Resolution caching (§22.8.4) reduces repeat queries to the same discovery context.
- **No query logging mandate.** The protocol does not require discovery contexts to log queries. Writers process lookups but are not mandated to record them beyond what the event log requires (registrations are logged; reads are not).
- **Privacy-preserving lookup is a future direction.** Techniques like private information retrieval (PIR) or oblivious queries could be layered onto the discovery context tool interface without protocol changes — the tool schema is compatible. This is acknowledged as unspecified and not blocking for initial implementation.

## 22.11 Wire Format Tables

This section tabulates the wire format for all discovery and addressing types that cross the network. All types use serde serialization (JSON for tool call payloads, MessagePack for MLS application messages). An independent implementer MUST implement these types with exactly the field names, types, and semantics shown below.

### 22.11.1 Agent Registration and Search

These types are the tool call schemas for the standard discovery context tools defined in §6.2.2B.

**`AgentSearchParams`** — Input for `agent_search` tool.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `capability_filter` | `Vec<String>` | No | Filter by capability URIs (§9.18.13). Logical AND — all must match. |
| `keywords` | `Vec<String>` | No | Free-text keyword search. Logical OR — any may match. |
| `limit` | `u32` | No | Maximum results to return. Default: 100. |

**`AgentSearchResult`** — Output from `agent_search` tool.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `entries` | `Vec<RegistrationEntry>` | Yes | Matching agent entries. |
| `total_matches` | `u64` | Yes | Total matches (may exceed returned entries if `limit` applied). |

**`AgentRegisterParams`** — Input for `agent_register` tool.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `did` | `String` (DID) | Yes | The agent's DID to register. |
| `capabilities` | `Vec<String>` | Yes | Capability URIs the agent supports. |
| `metadata` | `Map<String, Value>` | Yes | Arbitrary metadata (description, tags, etc.). May be empty. |

**`AgentRegisterResult`** — Output from `agent_register` tool.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `registered` | `bool` | Yes | `true` if registration succeeded. |
| `entry_id` | `String` | Yes | Unique identifier for the registration entry. |

**`AgentDeregisterParams`** — Input for `agent_deregister` tool.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `did` | `String` (DID) | Yes | DID to deregister. Must match the authenticated requester. |

**`AgentDeregisterResult`** — Output from `agent_deregister` tool.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `removed` | `bool` | Yes | `true` if the entry was found and removed. |

**`RegistrationEntry`** — A single agent registration record.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `did` | `String` (DID) | Yes | The registered agent's DID. |
| `capabilities` | `Vec<String>` | Yes | Capability URIs. |
| `metadata` | `Map<String, Value>` | Yes | Registration metadata. |
| `entry_id` | `String` | Yes | Unique entry identifier. |
| `registered_at` | `u64` | Yes | Unix timestamp (seconds) of registration. |

**`RegistrationEvent`** — Tagged enum for registration lifecycle events (event log entries).

| Variant | Tag | Fields | Semantics |
|---------|-----|--------|-----------|
| `Registered` | `"registered"` | `did: String`, `capabilities: Vec<String>`, `metadata: Map`, `entry_id: String`, `timestamp: u64` | New registration. |
| `Updated` | `"updated"` | `did: String`, `capabilities: Vec<String>`, `metadata: Map`, `entry_id: String`, `timestamp: u64` | Updated existing registration. |
| `Deregistered` | `"deregistered"` | `did: String`, `entry_id: String`, `timestamp: u64` | Removed registration. |

**`MembershipTier`** — Enum for discovery context membership levels.

| Variant | Serde Tag | Semantics |
|---------|-----------|-----------|
| `Writer` | `"writer"` | MLS group member. Can process registrations and writes. |
| `Reader` | `"reader"` | DID-authenticated. Can query but not modify. Unbounded membership. |

### 22.11.2 Handle Registration and Lookup

**`HandleRegisterParams`** — Input for `handle_register` tool.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `handle` | `String` | Yes | The local-part to register. Must match `[a-z0-9._-]`, max 64 chars (§9.18.13). |
| `target` | `HandleTarget` | Yes | What the handle resolves to. |
| `metadata` | `HandleMetadata` | No | Optional descriptive metadata. |

**`HandleRegisterResult`** — Output from `handle_register` tool.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `status` | `HandleRegisterStatus` | Yes | Registration outcome. |
| `entry_id` | `String` | No | Present when `status` = `Registered`. Unique entry ID. |

**`HandleRegisterStatus`** — Enum for registration outcomes.

| Variant | Serde Tag | Semantics |
|---------|-----------|-----------|
| `Registered` | `"registered"` | Handle registered successfully. |
| `Conflict` | `"conflict"` | Another DID already holds this handle. |
| `OwnershipMismatch` | `"ownership_mismatch"` | Requester DID does not match handle owner. |

**`HandleMetadata`** — Optional descriptive metadata for handles.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `description` | `String` | No | Human-readable description. |
| `tags` | `Vec<String>` | No | Categorization tags. |

**`HandleLookupParams`** — Input for `handle_lookup` tool.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `handle` | `String` | Yes | The local-part to look up. |
| `type_filter` | `HandleTypeFilter` | No | Restrict results to identity or context handles. |

**`HandleLookupResult`** — Output from `handle_lookup` tool.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `results` | `Vec<HandleEntry>` | Yes | Matching handle entries. |

**`HandleTypeFilter`** — Enum for filtering handle lookup results.

| Variant | Serde Tag | Semantics |
|---------|-----------|-----------|
| `Identity` | `"identity"` | Only return identity handles. |
| `Context` | `"context"` | Only return context handles. |

**`HandleEntry`** — A resolved handle record.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `handle` | `String` | Yes | The local-part. |
| `target` | `HandleTarget` | Yes | What the handle points to. |
| `owner_did` | `String` (DID) | Yes | DID of the handle owner. |
| `registered_at` | `u64` | Yes | Unix timestamp (seconds). |
| `metadata` | `HandleMetadata` | Yes | Descriptive metadata. May have all fields absent. |
| `entry_id` | `String` | Yes | Unique entry identifier. |

**`HandleDeregisterParams`** — Input for `handle_deregister` tool.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `handle` | `String` | Yes | The local-part to deregister. |
| `did` | `String` (DID) | Yes | Must match the handle owner. |

**`HandleDeregisterResult`** — Output from `handle_deregister` tool.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `removed` | `bool` | Yes | `true` if the handle was found and removed. |

**`HandleTarget`** — Tagged enum for what a handle resolves to.

| Variant | Tag | Fields | Semantics |
|---------|-----|--------|-----------|
| `Identity` | `"identity"` | `did: String` | Handle points to a DID. |
| `Context` | `"context"` | `context_id: String`, `relay_urls: Vec<String>` | Handle points to a context. |

### 22.11.3 Address Resolution

**`AddressType`** — Enum for address categories.

| Variant | Serde Tag | Semantics |
|---------|-----------|-----------|
| `Identity` | `"identity"` | Address resolves to a DID. |
| `Context` | `"context"` | Address resolves to a context ID + relay URLs. |

**`AddressResolution`** — Tagged enum for resolution results.

| Variant | Tag | Fields | Semantics |
|---------|-----|--------|-----------|
| `Identity` | `"identity"` | `did: String`, `trust_level: TrustLevel`, `resolution_path: ResolutionPath` | Resolved to a DID. |
| `Context` | `"context"` | `context_id: String`, `relay_urls: Vec<String>`, `mode: String`, `trust_level: TrustLevel`, `resolution_path: ResolutionPath` | Resolved to a context. `mode` is `"encrypted"` or `"broadcast"`. |

**`TrustLevel`** — Tagged enum indicating binding strength. Not strictly ordered (§22.7).

| Variant | Tag | Fields | Semantics |
|---------|-----|--------|-----------|
| `DirectExchange` | `"direct_exchange"` | — | DID exchanged out-of-band and verified. Highest personal trust. |
| `LocalPetname` | `"local_petname"` | — | User-assigned name. Maximum personal trust, zero shareability. |
| `MultiLayerCorroborated` | `"multi_layer_corroborated"` | `sources: Vec<ResolutionPath>` | Multiple independent resolution paths agree. |
| `DomainVerified` | `"domain_verified"` | — | Resolved via `.well-known/scp`. HTTPS-dependent. |
| `AttestationVerified` | `"attestation_verified"` | — | Resolved via identity attestation. Platform-dependent. |
| `DiscoveryContextVerified` | `"discovery_context_verified"` | — | Resolved via discovery context handle. Community-governed. |

**`ResolutionPath`** — Provenance for the resolution itself.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `layer` | `ResolutionLayer` | Yes | Which resolution layer found the result. |
| `source` | `String` | Yes | Discovery context name, domain, or platform. |
| `source_id` | `String` | No | Discovery context ID (hex) when `layer` = `DiscoveryContext`. |
| `resolved_at` | `u64` | Yes | Unix timestamp (seconds) of resolution. |

**`ResolutionLayer`** — Enum for resolution path layers.

| Variant | Serde Tag | Semantics |
|---------|-----------|-----------|
| `Petname` | `"petname"` | Local petname store. |
| `DiscoveryContext` | `"discovery_context"` | Discovery context handle lookup. |
| `Attestation` | `"attestation"` | Attestation-backed reverse lookup. |
| `Domain` | `"domain"` | `.well-known/scp` domain handle. |
| `MultiLayerCorroborated` | `"multi_layer_corroborated"` | Multiple layers agreed. |

**`ParsedAddress`** — Tagged enum for parsed human-readable addresses.

| Variant | Tag | Fields | Semantics |
|---------|-----|--------|-----------|
| `DiscoveryHandle` | `"discovery_handle"` | `local_part: String`, `scope: String` | `alice@cooking-community` — scope has no `.` |
| `DomainHandle` | `"domain_handle"` | `local_part: String`, `domain: String` | `alice@example.com` — scope contains `.` |
| `AttestationHandle` | `"attestation_handle"` | `handle: String`, `platform: String` | `@alice:x` — leading `@`, optional `:platform` |
| `Unscoped` | `"unscoped"` | `name: String` | `alice` — bare name, search all layers |

### 22.11.4 Push Notifications

**`PushPlatform`** — Enum for push notification platforms. Tag bytes are used in the signature construction.

| Variant | Serde Tag | Tag Byte | Semantics |
|---------|-----------|----------|-----------|
| `Apns` | `"apns"` | `0x01` | Apple Push Notification Service. |
| `Fcm` | `"fcm"` | `0x02` | Firebase Cloud Messaging. |
| `WebPush` | `"web_push"` | `0x03` | Web Push API (RFC 8030). |

**`PushRegistration`** — Registers a device for push notifications.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `did` | `String` (DID) | Yes | Registrant's DID. |
| `platform` | `PushPlatform` | Yes | Target push platform. |
| `token` | `Vec<u8>` (serde_bytes) | Yes | Platform-specific device token. |
| `contexts` | `Vec<String>` | Yes | Context IDs to receive notifications for. |
| `timestamp` | `u64` | Yes | Unix timestamp (seconds). |
| `signature` | `Vec<u8>` (64 bytes) | Yes | Ed25519 signature over: `did \|\| platform_tag(1 byte) \|\| token \|\| contexts \|\| timestamp`. |

**`PushDeregistration`** — Removes push notification registration.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `did` | `String` (DID) | Yes | Registrant's DID. |
| `platform` | `PushPlatform` | Yes | Platform to deregister from. |
| `timestamp` | `u64` | Yes | Unix timestamp (seconds). |
| `signature` | `Vec<u8>` (64 bytes) | Yes | Ed25519 signature over: `did \|\| platform_tag(1 byte) \|\| timestamp`. |

### 22.11.5 Petname Events (Identity Private State)

These events are appended to the identity private state event log (§3.7). They are encrypted to the identity's own keys and synced across devices.

**`PetnameEvent`** — Tagged enum for petname lifecycle.

| Variant | Tag | Fields | Semantics |
|---------|-----|--------|-----------|
| `SetPetname` | `"set_petname"` | `did: String`, `name: String` | Assign a local name to a DID. |
| `RemovePetname` | `"remove_petname"` | `did: String` | Remove a DID's local name. |
| `SetContextPetname` | `"set_context_petname"` | `context_id: String`, `name: String` | Assign a local name to a context. |
| `RemoveContextPetname` | `"remove_context_petname"` | `context_id: String` | Remove a context's local name. |

### 22.11.6 Capability and Context Discovery

**`CapabilityEntry`** — A resolved DID's capabilities.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `did` | `String` (DID) | Yes | The capability holder's DID. |
| `capabilities` | `Vec<String>` | Yes | Capability URIs from DID document `SCPCapabilities` service. |
| `service_endpoints` | `Vec<String>` | Yes | Service endpoint URLs from DID document. |
| `resolved_at` | `u64` | Yes | Unix timestamp (seconds) of DID document resolution. |

**`ContextDiscoveryResult`** — A discovered broadcast context.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `context_id` | `String` | Yes | Hex-encoded context ID. |
| `relay_urls` | `Vec<String>` | Yes | Relay URLs serving this context. |
| `publisher_did` | `String` (DID) | Yes | DID that published the context. |
| `discovery_source` | `ContextDiscoverySource` | Yes | How the context was discovered. |
| `mode` | `String` | Yes | Context mode: `"broadcast"`. |
| `metadata_summary` | `Map<String, Value>` | Yes | Subset of context metadata visible pre-join. |

**`ContextDiscoverySource`** — Tagged enum for how a context was discovered.

| Variant | Tag | Fields | Semantics |
|---------|-----|--------|-----------|
| `DhtDidDocument` | `"dht_did_document"` | — | Found via `SCPBroadcastContext` service in publisher's DID doc. |
| `WellKnown` | `"well_known"` | — | Found via `.well-known/scp` on a domain. |
| `DiscoveryContext` | `"discovery_context"` | `context_id: String` | Found via search in a discovery context. |
| `ContextUri` | `"context_uri"` | — | Found via `scp://` URI. |

**`BootstrapConfig`** — Client bootstrap discovery configuration.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `default_context_ids` | `Vec<String>` | Yes | SDK default discovery context IDs. |
| `auto_query_on_identity_creation` | `bool` | Yes | Whether to auto-query discovery contexts on first identity creation. |
| `custom_context_ids` | `Vec<String>` | Yes | User-added discovery context IDs. May be empty. |
| `fallback_to_did_resolution` | `bool` | Yes | Whether to fall back to DID document capability resolution. |

**`DiscoveryQuery`** — Parameters for multi-source discovery search.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `capability_filter` | `Vec<String>` | No | Filter by capability URIs. Logical AND. |
| `keywords` | `Vec<String>` | No | Free-text keywords. Logical OR. |
| `min_history` | `u64` | No | Minimum participation history (seconds) required. |

**`DiscoveryResult`** — Aggregated discovery search results.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `entries` | `Vec<DiscoveryResultEntry>` | Yes | Matching entries across all queried sources. |
| `sources` | `Vec<String>` | Yes | Discovery context IDs that were queried. |

**`DiscoveryResultEntry`** — A single discovery result.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `did` | `String` (DID) | Yes | The discovered agent's DID. |
| `capabilities` | `Vec<String>` | Yes | Capability URIs. |
| `participation_summary` | `Map<String, Value>` | Yes | Participation profile summary. |
| `provenance` | `DataProvenance` | Yes | Provenance metadata (§24). |
| `relevance_score` | `f64` | Yes | Relevance score (0.0 to 1.0). |

### 22.11.7 Standard Tool Names

The following tool names are normative — independent implementations MUST use exactly these names for interoperability:

| Tool Name | Direction | Spec Reference |
|-----------|-----------|----------------|
| `agent_search` | Reader (DID-authenticated query) | §6.2.2B |
| `agent_register` | Writer (MLS member write) | §6.2.2B |
| `agent_deregister` | Writer (MLS member write) | §6.2.2B |
| `handle_register` | Writer (MLS member write) | §22.3.1 |
| `handle_lookup` | Reader (DID-authenticated query) | §22.3.1 |
| `handle_deregister` | Writer (MLS member write) | §22.3.1 |
| `attestation_lookup` | Reader (DID-authenticated query) | §22.5.1 |

### 22.11.8 DID Document Service Types

| Service Type | Semantics | Spec Reference |
|--------------|-----------|----------------|
| `SCPCapabilities` | Agent capability URIs | §6.2.2A |
| `SCPBroadcastContext` | Broadcast context advertisement | §5.14 |
| `SCPRelay` | Relay endpoint URL | §18.3 |

## 22.12 Phase Integration

Phase assignments for addressing components are tracked in `.docs/architecture.md` alongside all other build phase allocations. Summary: address format types, petname storage, `.well-known/scp` handles extension, and URI handle parameter land in Phase 2 (extending existing types, no external dependencies). Discovery context handle tools, attestation lookup, `AddressResolver`, and the handle-registry template land in Phase 3 (dependent on discovery context and attestation infrastructure).
