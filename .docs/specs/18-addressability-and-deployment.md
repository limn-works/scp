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

`.well-known/scp` is an **optional web on-ramp** for the "I know a domain, nothing else" entry point. It is advisory only — HTTPS-dependent, not self-certifying. Clients MUST verify `.well-known/scp` data against DHT-resolved DID documents before trusting it (§18.3.2). Web clients (a browser — normally an in-tab client running the protocol itself with keys on-device per ADR-057, or optionally a remote custodial thin client to a server-side `scp-node`) use `.well-known/scp` to bridge from HTTP-land, then verify via DHT. This layering must be explicit: HTTP is the outermost, least-trusted discovery layer. The core protocol operates entirely without it.

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
- **Sequence number monotonicity, per layer.** Relay list updates follow the BEP44 sequence number rules (§9.6.3). A client MUST reject a DID document whose sequence number is lower than the last sequence number that client observed **on the layer that served it**. Each layer signs its own bytes and advances its own sequence number (§18.2.2A), so a client compares a relay-layer sequence number only against a relay-layer sequence number, and a Mainline sequence number only against a Mainline sequence number.

When a peer resolves an identity's DID document, the `SCPRelay` entries tell them where to route encrypted envelopes destined for that identity. This is the primary relay discovery mechanism — out-of-band DID exchange leads to DHT resolution leads to relay URLs.

### 18.2.2 Existing Endpoint Types (Cross-Reference)

SCP uses multiple DID document service endpoint types, each serving a distinct purpose:

| Type | Purpose | Consumer | Spec Reference |
|------|---------|----------|----------------|
| `SCPRelay` | Transport-layer relay URLs for encrypted blob routing | `TransportManager` (ADR-012) | §18.2.1 |
| `SCPCapabilities` | Application-layer capability endpoints (outlet schemas, agent descriptions) | Discovery Engine (§6.2.2) | ADR-020 |
| `IdentityPrivateState` | Relay URLs storing identity private state blobs | Identity Manager | §3.7 |
| `PreRotationCommitment` | SHA-256 commitment hash for pre-rotation key (applies to `#0` and `#active` only; `#agent` is a software key with simpler rotation — no pre-rotation needed, see ADR-039) | Identity Manager (§9.12) | ADR-003 |
| `SCPBroadcastContext` | Relay URL(s) where a verifier fetches the author's broadcast-context list. One entry per DID, never one per context (§18.2.2B criterion 2). | Discovery Engine | §5.14.11 |
| `ParticipationStatements` | Relay URL(s) where the agent's participation statements can be fetched by verifiers | Participation Admission (§7.3.2.1) | §7.3.2.1 |
| `AttestationRevocations` | Endpoint(s) for checking attestation revocation status | Attestation Verification (§7.4.4) | §7.4.4 |
| `ScpIdentityLinkAttestation` | Identity link attestation entries for platform verification | Attestation Verification (§3.5.4) | §3.5.3 |
| `DeviceAttestations` | Endpoint where a verifier fetches this identity's device-attestation proofs. One entry per DID, never one per enrolled device (§18.2.2B criterion 2). | Sybil-resistance signal evaluation (§9.3) | §9.3 |

**SCPRelay vs SCPCapabilities.** These are distinct service types with different consumers and different purposes:

- `SCPRelay` = **transport layer**. Where to send encrypted blobs. Consumed by `TransportManager`. Any SCP participant publishing to this identity routes through these URLs.
- `SCPCapabilities` = **application layer**. What outlets and capabilities an agent offers. Consumed by the Discovery Engine. Agents looking for specific capabilities query these endpoints.

A relay operator's DID document contains `SCPRelay` entries (where to connect). An agent's DID document may contain both `SCPRelay` entries (how to reach the agent) and `SCPCapabilities` entries (what the agent can do).

### 18.2.2A DID Document Field-Level Schema

SCP DID documents follow the W3C DID Core specification (v1.0) with SCP-specific verification methods and service endpoints.

**SCP publishes a DID document in two encodings, one per resolution layer (§3.10).** The SCP relay network carries the **full document** as JSON. Mainline DHT carries a **reduced bootstrap core** as a did:dht-conformant DNS packet. The two encodings carry different bytes. Each layer signs its own bytes with its own BEP44 signature and advances its own sequence number, so no clause in this specification requires the relay layer and the Mainline layer to carry identical bytes, and no resolver compares a sequence number from one layer against a sequence number from the other (§3.10.4 step 5, §3.10.7).

| Layer | Encoding | Carries | Size cap |
|-------|----------|---------|----------|
| SCP relay network (§3.10.2) | JSON, as specified below | The full DID document | `MAX_DID_RECORD_VALUE_LEN` = 262,039 bytes |
| Mainline DHT (§3.10.3) | did:dht-conformant DNS packet | The bootstrap core (§18.2.2C) | 1,000 bytes, measured on the bencoded BEP44 `v` value (§18.2.2D) |

Every SDK MUST produce byte-identical bytes to every other SDK for the same identity state **within a layer**, because BEP44 signature verification reproduces the signed octets exactly. A byte comparison between the relay encoding and the Mainline encoding is not a conformance check and MUST NOT be performed.

**Correction to the previous text of this clause.** This paragraph previously read "The canonical serialization is JSON (per did:dht spec)". The parenthetical was wrong about did:dht: the did:dht method specifies a DNS-packet encoding within the BEP44 payload, never JSON. Because this clause was the only place in the corpus that authorized the JSON path, the error reached the implementation, which publishes pretty-printed JSON to Mainline and is rejected server-side by the 1,000-byte BEP44 cap. Issue #2297, "DID documents do not fit their transport", records the failure chain.

**Canonical DID document structure (relay-layer JSON encoding):**

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

**Field constraints (relay-layer JSON encoding):**

| Field | Required | Constraints |
|-------|----------|-------------|
| `@context` | Yes | MUST include the two URIs shown above, in order. This row binds the relay-layer JSON encoding alone: the did:dht method forbids `@context`, so the Mainline bootstrap core omits it (§18.2.2C). |
| `id` | Yes | MUST match `did:dht:<z-base-32(#0 public key)>`. The suffix is the z-base-32 encoding of the raw 32 Ed25519 public-key bytes with no character prepended, which the did:dht method fixes as `did-dht-format := did:dht:Z-BASE-32(raw-public-key-bytes)` (§ "Format"). Encoding 32 bytes yields 52 characters. |
| `verificationMethod` | Yes | MUST include `#0` (Identity Key). MUST include `#active` (Active Signing Key). MAY include `#agent` (Agent Signing Key, optional per ADR-039). **MAY include any number of `#retired-{sequence}` and `#retired-agent-{sequence}` entries**, which ADR-003 §4a and §4a′ (`.docs/adrs/phase-1.md`) require `rotate_active_key` and `rotate_agent_key` to retain, and which no clause caps. This row previously read "No other verification methods permitted," contradicting those two criteria, and a later revision suspended the prohibition for `#retired-*` pending an open question. Alec decided that question on 2026-08-17 (`.docs/specs/00-open-questions.md`, "Retired verification methods"): a retired verification method keeps verifying content signatures indefinitely, and retention carries no cap. Each `#retired-*` fragment appears at most once in a document. The row states that outcome. Every other verification method beyond `#0`, `#active`, `#agent` and `#retired-*` remains forbidden. |
| `verificationMethod[].publicKeyMultibase` | Yes | Multibase base58btc (`z` prefix) over the **multicodec-prefixed** Ed25519 public key. "Data Integrity EdDSA Cryptosuites v1.0" (W3C Recommendation, 15 May 2025) §A.1.1 states it for the `Ed25519VerificationKey2020` type this document's `verificationMethod[].type` declares: the encoded binary value "MUST consist of a binary value that starts with the two-byte prefix `0xed01`, which is the Multikey header for an Ed25519 public key, followed by the 32-byte public key data … Any other encoding MUST NOT be allowed." The 34-byte payload encodes to 47 base58btc characters for every Ed25519 key, so the value is always 48 characters including the `z` header. A 44- or 45-character value carries the bare 32 bytes and is non-conformant. |
| `authentication` | Yes | MUST reference `#active`. MAY reference `#agent`. MUST NOT reference `#0`. |
| `assertionMethod` | Yes | Same as `authentication`. |
| `capabilityDelegation` | Yes | MUST reference only `#0`. |
| `capabilityInvocation` | Yes | MUST reference `#0` and `#active`. |
| `alsoKnownAs` | No | At most one entry, and it names the DID that a Layer 2 identity migration moved this identity to (§9.12). Absent on an identity that has not migrated. |
| `service` | Yes | At least one `SCPRelay` entry required. At most one `PreRotationCommitment` entry. ADR-003 acceptance criterion 1 (`.docs/adrs/phase-1.md`) constructs one on every identity the shipped creation path builds, and `DidMethod::create` (`crates/scp-identity/src/dht.rs:2012`) takes a `PreRotationCustody` implementation it cannot omit. ADR-003 §4c invariant 7 defines what a verifier does with a document that publishes none: `pre_rotation_proof` MAY be `None`, and the migration verifies at MODERATE assurance. Whether an identity may be created carrying no commitment is Discussion #1553, the non-committing-identity question, which a human decides alongside issue #1729, the pre-rotation custody backend, so this row caps the count at one and does not make the entry mandatory. Every other type is optional. Each entry satisfies the three criteria in §18.2.2B. |
| `service[].id` | Yes | Fragment identifier (e.g., `#scp-relay-1`). Unique within the document. |
| `service[].type` | Yes | One of the types in §18.2.2. |

**Canonical serialization rules — relay layer.** A publisher MUST sort JSON keys lexicographically at every nesting level (RFC 8785 JSON Canonicalization Scheme), MUST emit no whitespace between tokens (minified JSON), and MUST normalize Unicode to NFC. The relay layer's BEP44 signature covers these octets, so two SDKs that canonicalize the same identity state produce the same signed bytes.

**Canonical serialization rules — Mainline layer.** The did:dht DNS-packet encoding fixes its own octet order, so a publisher canonicalizes the Mainline bytes by emitting that encoding as the did:dht method specifies it (§18.2.2C). RFC 8785 does not apply to the Mainline layer, because the Mainline layer carries no JSON.

**Every constraint in this section that the shipped code does not meet appears in the list below, and a code slice owes all nine.** A constraint qualifies when shipped code writes a document field the constraint rejects, or writes no field where the constraint requires one. Each entry names what the shipped code emits today and which constraint above it violates.

- **Canonical serialization.** `DidDocument::to_json` (`crates/scp-did/src/document.rs:390`) calls `serde_json::to_string_pretty`, which emits indentation and newlines and preserves struct field order rather than sorting keys, and no code path normalizes the document's strings to NFC, so the shipped relay-layer bytes satisfy none of the three rules above. Neither `crates/scp-did`, nor `crates/scp-identity`, nor `crates/scp-dht` contains an RFC 8785 canonicalizer or calls one; the workspace's RFC 8785 implementation lives in `crates/scp-protocol/src/jcs.rs` and no DID crate references it, and the workspace's `unicode-normalization` dependency reaches `crates/scp-protocol` and `crates/scp-runtime` alone.
- **The Mainline encoding.** No DNS-packet encoder exists in the workspace, and `DidDht::publish_document` (`crates/scp-identity/src/dht.rs:830`) publishes the `to_json` bytes (`:842`) to Mainline unchanged.
- **The DID string.** `did_dht_from_public_key` (`crates/scp-did/src/lib.rs:173`) formats `did:dht:z{}` around the z-base-32 encoding, so it prepends a `z` the did:dht method does not define and emits a 53-character suffix where the method's transformation yields 52. The `z` reads as a multibase prefix and is not one; z-base-32's own alphabet contains `z`, so the method's character-class rule accepts the string while the extra character makes it decode to 33 bytes rather than an Ed25519 public key.
- **`publicKeyMultibase`.** `multibase_encode` (`crates/scp-did/src/document.rs:1213`) formats `z{}` around base58btc of the bare 32 key bytes, with no `0xed 0x01` multicodec header, so the emitted value does not satisfy the `Ed25519VerificationKey2020` suite that `verificationMethod[].type` declares.
- **`capabilityDelegation`.** `DidDocument` (`crates/scp-did/src/document.rs:168`) declares seven fields — `@context`, `id`, `verificationMethod`, `authentication`, `assertionMethod`, `alsoKnownAs` and `service` — and none of them carries this array, so every document the workspace serializes omits a field the table above marks Required: Yes. No file under `crates/` writes the name.
- **`capabilityInvocation`.** The same seven fields carry no entry for this array either, and no file under `crates/` writes the name, so every serialized document omits a second field the table above marks Required: Yes.
- **The `SCPRelay` entry the `service` row requires.** `DidDocument::new_with_agent_key` (`crates/scp-did/src/document.rs:330`) builds `service` as a one-element vector holding the `PreRotationCommitment` entry (`:380`), `DidMethod::create` (`crates/scp-identity/src/dht.rs:2012`) builds its document through `DidDocument::new` (`:2089`), which delegates to that constructor, and hands the result back to its caller unchanged, and `DidDht::publish_document` (`:830`) publishes whatever document it receives without counting relay entries. A caller reaches the entries only by calling `publish_with_relay_urls` (`:891`) or `DidDocument::set_relay_services` (`crates/scp-did/src/document.rs:486`) first, and no code path requires either call, so the shipped creation path emits a document carrying zero of the at-least-one entries this row requires.
- **`service[].id`.** No constructor in the workspace emits a bare fragment; each one formats the document's own `id` in front of the fragment. `DidDocument::new_with_agent_key` writes `{did}#pre-rotation` (`crates/scp-did/src/document.rs:368`), `add_relay_service` and `set_relay_services` write `{did}#scp-relay-{n}` (`:450`, `:508`), `add_broadcast_context_service` writes `{did}#scp-broadcast-ctx-{n}` (`:564`), `add_device_attestation` and `set_device_attestation_token` write `{did}#device-attestation` (`:615`, `:848`), `ScpKeyCustodyAttestation::to_service_entry` writes `{did}#custody-attestation` (`crates/scp-did/src/attestation.rs:211`), `IdentityLinkServiceEntry::to_service_entry` writes `{did}#attestation-{platform}--{index}` (`:452`), and `add_participation_service` writes `{did}#participation-statements` (`crates/scp-runtime/src/trust/participation_service.rs:33`). The example document above spells that entry's `id` as `#scp-relay-1`.
- **`service[].type`.** Three type strings the shipped code writes name no row of §18.2.2's table. `ScpDeviceAttestation` (`crates/scp-did/src/document.rs:273`) reaches a published document through `DidDht::attach_device_attestation` (`crates/scp-identity/src/dht.rs:1387`), and §18.2.2's table names that entry `DeviceAttestations`. `ScpParticipationStatements` (`crates/scp-protocol/src/trust/participation.rs:1272`) is written by the shipped `add_participation_service` (`crates/scp-runtime/src/trust/participation_service.rs:26`), whose only callers inside this workspace are that module's own tests, and §18.2.2's table names that entry `ParticipationStatements`. `ScpKeyCustodyAttestation` (`crates/scp-did/src/attestation.rs:32`) is written by `DidDocument::set_custody_attestation` (`crates/scp-did/src/document.rs:665`), which §27.4.4 of `.docs/specs/27-attestations.md` records as having no production caller, and §18.2.2's table carries no row for it at all. The four other type strings the shipped code writes — `PreRotationCommitment`, `SCPRelay`, `SCPBroadcastContext` and `ScpIdentityLinkAttestation` — each name a row of that table.

Issue #2297, "DID documents do not fit their transport", carries the first two as fix items 1 and 3; the canonicalization call sites land with the encoder. Its fix list names none of the last five, and §3.10.12 of `.docs/specs/03-identity.md`, the phase-integration ledger, carries a row for each so that a reader executing that ledger reaches them.

### 18.2.2B What a DID Document Carries

Three criteria decide the contents of a DID document, and a publisher applies them in order. Criterion 1 decides whether an item may appear in the document at all. Criterion 2 decides whether an admitted item appears as a value or as a pointer naming where a verifier fetches the value. Criterion 3 decides whether the Mainline bootstrap core (§18.2.2C) carries the item. Each criterion states the test that decides the answer. The table under each criterion applies that test to the entries §18.2.2 defines today. An author proposing a new entry applies the criterion to it; the table supplies worked examples and does not itself decide anything.

**Criterion 1 — every value the document carries is one a reader can check without trusting the owner who published it.**

The document is a self-certifying record. The owner's signature over it proves the owner published these bytes, and nothing more; it never makes the *contents* true. So the test asks what a reader has to take on faith. A value passes when one of two things makes it checkable, and it fails when neither does:

- **The value is the identity's own configuration**, and the owner's authority over it is total: which keys this identity uses, which relays carry its traffic, which endpoint serves its private state, the hash it commits to for its next rotation. There is nothing here for a reader to disbelieve — the owner declaring a key *is* what makes that key the identity's key — so the document's own signature is the whole of what a reader needs.
- **The value asserts a fact the owner does not control, and carries a proof from whoever does.** That this DID controls a named account on another platform (§3.5.2's attestation), that a named device attested it (§9.3), that an established DID vouches for it (§9.3's endorsements, signed by the endorser), that another DID is this identity after a migration (§9.12's migration proof). The reader checks the proof, and the proof's issuer — not the owner — is who the reader is trusting.

A value that satisfies neither MUST NOT appear in the document. The clearest case: a bare self-declared judgement — an owner writing its own trust score — asserts a fact the owner does not control and carries no proof, so no reader can check it. A value carrying a proof from a party who does not control the fact it asserts fails the same way, and for the same reason: a stranger's signature over a claim about someone else's platform account proves only that the stranger signed it. These are instances of the criterion, not a closed list; the criterion is the test.

**Criterion 1 does not, by itself, keep participation records out of the document, and §9.3's storage split does not rest on it.** A `ParticipationProfile` (§7.3.2.1) is produced and Ed25519-signed by the source context, and agents cannot write their own — so it satisfies clause (b) exactly as an endorsement does, and clause (b) admits it. What keeps it out of the document as a *value* is **criterion 2**: an identity accrues one statement per context it participates in, and the count grows for as long as it participates. So the document carries an owner-asserted `ParticipationStatements` pointer naming where a reader fetches the statements, the pointer is configuration under clause (a), and the fetched statements arrive with their contexts' own signatures. §9.3 assigns protocol-derived signals to context state, and criterion 2 is the clause that enforces the assignment here. An earlier draft attributed the exclusion to criterion 1, on the reasoning that participation records are "checkable only against the records those participants hold" — which is equally true of an endorsement that criterion 1 admits, so it did not distinguish them.

**On §9.3's wording.** §9.3's storage split says self-asserted signals live in the DID document and protocol-derived signals live in context state, and its table marks endorsements "self-asserted? No (signed by endorser)" while placing them in "DID document or context." Read as a producer test, "self-asserted" would exclude an endorsement from the document; read against this criterion, an endorsement is admitted, because the endorser's signature is exactly the proof that makes it checkable. This criterion is the more specific rule and it governs. §9.3's table column records who produced each signal, which is evidence about checkability rather than the test itself.

| Entry | What makes it checkable | Criterion 1 |
|-------|------------------------|-------------|
| `#0`, `#active`, `#agent` verification methods | The owner declaring a key is what makes it this identity's key. | Admitted — configuration. |
| `PreRotationCommitment` service entry | The owner's own commitment, which the reveal at rotation checks against. | Admitted — configuration. |
| `SCPRelay`, `IdentityPrivateState`, `SCPCapabilities` service entries | The owner chooses where its own traffic, state and capabilities are served. | Admitted — configuration. |
| `ScpIdentityLinkAttestation` service entries | The platform's signature over the attestation (§3.5.2). | Admitted — proof from the party that controls the fact. |
| Device attestation proof | The attestation service's signature (§9.3). | Admitted — proof from the party that controls the fact. |
| Endorsements | The endorsing DID's signature (§9.3). | Admitted — proof from the party that controls the fact. |
| `alsoKnownAs` | The migration proof §9.12 defines, signed by the old identity key. | Admitted — proof from the party that controls the fact. |
| `AttestationRevocations` service entry | The endpoint is the owner's configuration; the fetched revocation list carries the issuer's signature. | Admitted as a pointer. |
| `ParticipationStatements` service entry | The endpoint is the owner's configuration; the fetched statements carry their contexts' provenance (§7.3.2.1). | Admitted as a pointer. |
| Participation history, participation record, economic activity | The source context's signature over each statement (§7.3.2.1). | Admitted by criterion 1, and moved to a pointer by criterion 2, whose count grows with every context joined. §9.3 puts the values in context state. |
| A bare self-declared trust or reputation value | Nothing. The owner does not control the fact and supplies no proof. | Excluded. |
| A third party's signed claim about an account that third party does not control | The signature proves only that the third party signed it. | Excluded — the proof does not come from the party controlling the fact. |

**Criterion 2 — every entry class that appears as a value carries a maximum count this specification states, and that count does not grow with the owner's further protocol activity.**

The reason the criterion exists: §18.2.2D caps the bytes a publisher may emit on each layer, and §18.2.2D's parse-side companion bounds what a resolver deserializes from an untrusted source. An entry class whose count the owner can raise without limit therefore makes the document unpublishable at the publishing end and a memory-amplification input at the resolving end.

The test asks what raises the count. An entry class whose count the owner raises by taking one more action of a kind the protocol invites it to repeat — creating another context, enrolling another device, publishing another outlet — appears as **one** pointer entry naming where a verifier fetches the list. An entry class whose count the protocol fixes (one `#0`, one `#active`, at most one `#agent`, at most one `PreRotationCommitment`, one `alsoKnownAs` target) or whose count this specification caps with a number (at most 64 `ScpIdentityLinkAttestation` entries, §3.5.3) appears as a value.

Two entry classes fail this criterion as §18.2.2 and §5.14.11 write them today, and both become pointers:

- **`SCPBroadcastContext`.** §5.14.11 discovery mechanism 1 published one entry per broadcast context the author creates, and an author creates broadcast contexts for as long as it publishes, so the count grew with the owner's activity and no number capped it. The entry becomes one `SCPBroadcastContext` pointer naming where a reader fetches the author's broadcast-context list. §5.14.11 specifies that fetch in full — the entry shape, the HTTP GET, the `BroadcastContextList` response, and the author's `#active` signature over it. That signature is load-bearing: in the inline form the DID document's own BEP44 signature covered every advertised context, and a pointer that carried no signature of its own would hand a relay the ability to add or remove one. The privacy rule is unchanged too — the fetched list carries broadcast context IDs only, because §5.14.11 and §9.10 forbid publishing any other context's ID.
- **The device-attestation proof.** `.docs/specs/00-open-questions.md` (the resolved Sybil-resistance entry) makes "attestation proof is stored in the DID document as a service entry" a protocol responsibility, and criterion 1 admits it because the attestation service's signature is what makes it checkable. One proof exists per device the owner enrolls, and the owner enrolls devices for as long as it uses the protocol, so criterion 2 makes it **one** pointer entry rather than one entry per device. §18.2.2's table now carries the `DeviceAttestations` row, and the entry takes the same shape as `ParticipationStatements` (§7.3.2.1) and `SCPBroadcastContext` (§5.14.11): an endpoint a verifier GETs, returning proofs each carrying the attestation service's own signature. The **proof format itself** is specified by the device-attestation work rather than here — §9.3 defines the signal and `.docs/specs/00-open-questions.md` tracks the remaining protocol responsibilities — and this section fixes only the DID-document entry, which is what criterion 2 governs.

**Alec's ruling of 2026-08-17 decided retired verification methods, so criterion 2 does not decide them.** Retained `#retired-*` entries accrue one per rotation, which is the growth criterion 2's count test asks about, and Alec answered that question directly by deleting ADR-003's cap and stating no replacement count (`.docs/specs/00-open-questions.md`, "Retired verification methods"). What bounds the class is §18.2.2D's relay-layer cap of 262,039 bytes rather than a count: ADR-003 §4a measures one retired active key at 263 bytes and one retired agent key at 269, which puts roughly 990 rotations of one identity inside the budget. Criterion 2 exists so that a publisher can always emit the document and a resolver can always bound what it deserializes, and a byte cap supplies both bounds, so no clause states a `#retired-*` count and none needs to. §18.2.2A's `verificationMethod` row records that outcome.

**Both of §18.2.2D's caps are owed, and admitting this class makes them load-bearing.** `SCP-IDENT-1061` appears in no Rust file, so no publisher measures a document against either layer's cap, and `DidDocument::from_json` (`crates/scp-did/src/document.rs:399`) is a bare `serde_json::from_str` with no length bound and no depth bound. Until both caps ship, the byte bound that answers criterion 2 for `#retired-*` is stated here and enforced nowhere. `.docs/specs/00-open-questions.md` carries the four rules the ruling leaves unstated, including what a `#retired-N` entry must contain and what an identity does when its document reaches the relay layer's cap. A human decides those four; this section states none of them.

§18.2.2A's `verificationMethod` row states the outcome: a document MAY carry `#retired-*` entries, and no clause caps how many. CONF-003 in §26.3 of `.docs/specs/26-conformance-suite.md`, "Key Rotation (Active Key Update)", asserted that the old `#active` key was absent and moves with this decision. CONF-001 in §26.3 does not move — it asserts three verification methods on a freshly created identity, which has rotated nothing.

**Criterion 3 — the Mainline bootstrap core carries what a resolver needs in order to reach a relay, and the verification material every identity carries. Everything else lives on the relay layer.**

The criterion has two clauses, and an entry qualifies under either one.

**Clause (a) — reaching a relay.** §18.5.1's bootstrap chain puts Mainline resolution at level 2, which is the first level where an SDK holding nothing but a DID learns of any relay. A pointer resolves only by fetching from a relay, so a pointer at level 2 names a relay the resolver does not yet know and the chain never starts. The `SCPRelay` entries are what this clause admits, and it admits nothing else: once level 2 completes the resolver holds the relay list and can fetch anything.

**Clause (b) — verifying this identity's signatures when no relay answers.** §3.10.3 keeps Mainline as the path that survives when every one of an identity's relays is unreachable, and that path is worth having only if a verifier holding it can check a signature the identity made. The material that check reads is the `#active` verification method, which §18.2.2A requires of every DID document, and the `PreRotationCommitment` service entry, which §9.12 reads when it checks whether a rotation was authorized. `#0` needs no separate element: the DID string encodes those same bytes (§9.6.1), so a resolver derives the key from the identifier it is already holding.

**What clause (b) excludes, and what a resolver does about the exclusion.** Verification material an identity MAY carry rather than MUST stays on the relay layer, and `#agent` is the only instance today (ADR-039 makes it optional). A resolver holding only the core, meeting an artifact whose `signing_key_id` names `#agent`, MUST report `#agent` unresolved and fetch the full document from a relay before it accepts the artifact. It MUST NOT read the core's silence as an assertion that the identity has no agent key (§3.10.10).

**Two costs this membership carries, stated because the criterion does not pay them.** Both follow from the core's four elements, which this specification records rather than derives — the membership was settled before this section was written, and neither cost was priced when it was.

1. **An agent identity whose relays are all unreachable cannot be verified at all.** Clause (b) says the Mainline path is worth having because it lets a verifier check a signature the identity made. For an artifact signed by `#agent` it does not: the key is on the relay layer, §9.7.1 fails closed on an unverifiable KeyPackage attestation, and the identity is therefore unadmittable to any group for as long as its relays stay down. The pre-amendment model, which put the whole document on both layers, did not have this hole. The measurements in §18.2.2D price the fix at 84 bytes for one more verification-method record against 284 bytes of headroom at three relay entries, so size is not what excludes `#agent`.
2. **A migrated identity looks live to a resolver that reaches only Mainline.** §9.12's identity-key migration writes `alsoKnownAs` into the old document and retires its operational verification methods, and `alsoKnownAs` is a relay-layer entry. After a migration the old identity's relays are exactly what stops being maintained, so the case where the forwarding record matters most is the case where only Mainline answers. That resolver holds a core with no signal that the identity moved. The migration path is also the `#0`-compromise recovery path (§9.12), which makes this a recovery property rather than a convenience.

**Neither cost is resolved here.** Changing the core's membership is a decision about the settled four elements, and this specification does not make it. `.docs/specs/00-open-questions.md` carries it as an open question alongside the retired-key question, and an implementation builds the four-element core until a human answers it.

Note that the relay layer's own DID record does not depend on clause (b). A resolver verifies that record's BEP44 signature against the key the DID string encodes (§3.10.4 step 4b), never against `#active`, so a resolver holding no core at all can still authenticate a relay's answer once it reaches a relay by some other route (§18.5.1 levels 1, 3, 4 and 5). Clause (b) is about verifying what the identity signs, not about verifying what a relay serves.

§18.2.2C lists what this criterion admits.

### 18.2.2C The Mainline Bootstrap Core

The Mainline DHT layer carries a **bootstrap core**: the entries criterion 3 of §18.2.2B admits, which are the entries a resolver needs before any relay has answered it. The core carries these four elements and nothing else:

| Element | Why criterion 3 admits it |
|---------|---------------------------|
| The identity key `#0` | Clause (b): it is the root of the identity's key material. The core carries no key bytes for it, because the DID string encodes the same bytes (§9.6.1) and a resolver derives the key from the identifier it already holds. The DNS packet still emits a `k0` record for it, because the method's root record carries a verification-method list "always containing at least `k0`" (§ "Root Record"). |
| The `#active` verification method | Clause (b): §18.2.2A requires `#active` of every DID document, and it is the key that verifies what this identity signs. |
| The `PreRotationCommitment` service entry | Clause (b): §9.12 reads the commitment when it checks whether a rotation was authorized, and a verifier that reached only Mainline needs that check to accept a rotated `#active`. |
| The `SCPRelay` service entries | Clause (a): level 2 of §18.5.1 is where the SDK first learns of any relay, so a pointer to a relay list would name a relay the resolver cannot yet reach. |

Everything else a DID document carries — `SCPCapabilities`, `IdentityPrivateState`, `SCPBroadcastContext`, `ParticipationStatements`, `AttestationRevocations`, `ScpIdentityLinkAttestation`, `alsoKnownAs`, and the `#agent` verification method — lives on the relay layer only. A resolver holding the bootstrap core holds the relay list, so it fetches the full document from a relay rather than reading those entries out of Mainline.

**The table lists which entry classes the core admits, and three of the four are present on every identity.** The `PreRotationCommitment` record appears in the core when the relay-layer document carries the entry, and §18.2.2A bounds that entry at one without requiring it, so a core built for an identity that published no commitment carries three elements. Whether an identity may be created carrying no commitment is Discussion #1553, the non-committing-identity question, which a human decides alongside issue #1729, the pre-rotation custody backend; ADR-003 §4c invariant 7 (`.docs/adrs/phase-1.md`) already defines how a verifier handles the document that results. Criterion 3 decides which entry classes the core carries, and it does not decide whether an identity publishes a commitment.

**The Mainline encoding is the did:dht method's DNS-packet encoding, and the method specification fixes it.** The did:dht method specification, § "Operations → Create" step 4 and § "DIDs as DNS Records", states: "Compress the DNS packet as per [RFC1035] section 4.1.4", and "`v` MUST be set to a bencoded compressed DNS packet from the prior step" (https://did-dht.com, `#create` and `#dids-as-dns-records`). RFC 1035 §4.1.4 defines DNS message name-pointer compression. **The method specifies no other compression, and the string "gzip" does not appear anywhere in it.** Issue #2297, "DID documents do not fit their transport", says did:dht "requires a gzipped DNS packet"; that sentence is wrong and the method specification governs.

The method fixes the record layout the encoder emits. SCP adopts that layout unchanged, and defines no layout of its own for this layer:

| Core element | did:dht record | Method section |
|--------------|----------------|----------------|
| Root record listing the aliases present | `_did.<ID>.` `TXT`, rdata `v=…;vm=…;auth=…;asm=…;inv=…;del=…;svc=…` | § "Root Record" |
| `#active` verification method | `_kN._did.` `TXT`, rdata `id=…;t=…;k=…;a=…` | § "Verification Methods" |
| `PreRotationCommitment` and `SCPRelay` service entries | `_sN._did.` `TXT`, rdata `id=…;t=…;se=…` | § "Services" |
| Verification relationships (`authentication`, `assertionMethod`) | Carried in the root record's `auth=` and `asm=` fields; they get no record of their own. | § "Verification Relationships" |

Two consequences of adopting the method's encoding, both of which the relay-layer JSON encoding does not share:

- **The bootstrap core MUST NOT carry `@context`.** The method specification states: "This specification does not make use of JSON-LD. As such, DID DHT Documents MUST NOT include the `@context` property" (§ "Operations → Create"). §18.2.2A requires `@context` on the relay-layer JSON encoding, and that requirement binds the relay layer alone.
- **The recommended record TTL is 7,200 seconds**, which the method names as "the default TTL for Mainline records" (§ "DIDs as DNS Records"). SCP's 2-hour Mainline republish cycle (§3.10.5) already matches it.
- **Mainline's BEP44 sequence number is a wall-clock timestamp, and the method fixes it.** § "Operations → Create" step 5b states: "`seq` MUST be set to the current Unix Timestamp in seconds." The relay layer's sequence number is SCP's own counter over SCP's own encoding, so the two layers' sequence numbers are not the same kind of quantity: one counts seconds since the Unix epoch and the other counts publishes. This is the strongest reason a resolver never compares them (§3.10.7), and it holds independently of the two layers carrying different payloads.

**The two mappings the method leaves to SCP, both decided here.** Each record the method defines carries an `id=` and a `t=` field whose values SCP chooses, and the choices change the packet's byte length, so §18.2.2D's measurements are not reproducible without them.

- **`t=` carries the SCP service type string verbatim** — `t=SCPRelay`, `t=PreRotationCommitment`. The method writes `t=N` where "`N` is the Service's `type`", and SCP's service types are SCP-defined strings the did:dht registry does not list, so writing the type is what the clause asks for. A did:dht resolver reconstructing the document then recovers exactly the `type` value §18.2.2's table defines, and the encoding round-trips without a versioned lookup table.
- **`id=` carries the entry's SCP fragment with the leading `#` removed** — `id=scp-prerotation`, `id=scp-relay-1`, and `id=0` / `id=active` for the two verification methods. The alternative, writing the record's own alias (`id=s0`, `id=s1`), is 22 bytes smaller at one relay entry and 58 smaller at five, and it is wrong: §18.2.2A requires `service[].id` to be a fragment identifier unique within the document, and a resolver reconstructing the document from an alias would rebuild `#s0` rather than `#scp-prerotation`. The encoding would not round-trip the identifier it is encoding. SCP pays the bytes.

**A measurement published before this decision was made carried the alias form without recording it.** §18.2.2D's figures were re-derived against the fragment form above, and every figure in this specification is now that form. The difference is one relay entry at the 1,000-byte cap.

These decisions belong here rather than in the encoder, because nothing about either requires code. An earlier draft assigned `t=` to the encoder slice and never named `id=` at all, which would have let an implementation choose both wire tokens and then back-fill this specification — the artifact-flow inversion.

**Three further encoding rules the method fixes, which the measurements below apply:**

- **Only the root record's name carries the DID.** The method states that "All resource record names, aside from the Root Record and optional Authoritative Gateway Records, MUST end in `_did.`" (§ "DIDs as DNS Records"), so a verification-method record's name is `_k0._did.` rather than `_k0._did.<ID>.`. The 52-character identifier therefore appears once per packet regardless of how many records the packet holds. This is why RFC 1035 §4.1.4 compression saves so little here — 12 to 28 bytes across the shapes measured below, entirely from the `_did.` suffix pointer — and why the method's compression requirement is not what makes the core fit.
- **`a=` is omitted at the registry default.** The method requires the algorithm identifier to be omitted when it equals the key type's registry default, and EdDSA is the default for the Ed25519 key type, so an SCP verification-method record writes `id=…;t=0;k=…` and no `a=`.
- **A TXT rdata longer than 255 bytes splits into multiple character-strings**, which the method permits explicitly. No record in the bootstrap core reaches that length: the longest single record is the `PreRotationCommitment` service record at 134 bytes (117 rdata characters) at one and three relay entries, and the root record at 136 bytes once five relay entries lengthen its `svc=` list. So the split path is unexercised by the core, and an encoder still implements it, because §18.2.2's other service types are not length-bounded.

**One contradiction inside the method specification, recorded so an encoder author does not resolve it silently.** The § "Root Record" prose says the `auth`, `asm`, `inv` and `del` fields carry "the set of Verification Method resource **aliases** (e.g., `k0`)", while the § "Verification Relationships" example table writes verification-method **`id` values** into the same fields (`auth=0,HTsY…`). The alias form is the one the normative clause states and the one all three of the method's test vectors use, so SCP writes aliases. An encoder author meeting the example table should know it disagrees with the clause above it.

### 18.2.2D Per-Layer Size Caps and the Publish-Side Size Gate

**Normative.** A publisher MUST measure each encoding it produces against the cap of the layer that encoding targets, and MUST reject an over-cap encoding at publish time. The publisher MUST NOT truncate the encoding, MUST NOT drop entries to fit, and MUST NOT publish the encoding to the other layer instead.

| Layer | Cap | What the publisher measures | Source |
|-------|-----|------------------------------|--------|
| Mainline DHT | 1,000 bytes | The **bencoded** form of the BEP44 `v` value, which is the length prefix plus the compressed DNS packet. | BEP44 § "Mutable Items": "Storing nodes MAY reject put requests where the bencoded form of v is longer than 1000 bytes." The did:dht method restates the bound as flat: "BEP44 payload sizes are limited to 1000 bytes" (§ "Implementation Considerations → Size Constraints"). |
| SCP relay network | 262,039 bytes | The `value` field the publisher wraps in a DID-record frame, before framing. | `MAX_DID_RECORD_VALUE_LEN` (`crates/scp-protocol/src/envelope/did_record.rs:88`) = `MAX_BLOB_SIZE` (262,144, §9.18.11) − `DID_RECORD_FIXED_PREFIX_LEN` (105). |

**Where the gate sits.** The publisher applies the gate after that layer's encoding completes and before it requests a signature over the encoded bytes, on both publish paths — the Mainline publisher and the relay publisher — so no publish path can reach a transport without passing it. The gate does not sit in the transport: a relay or a Mainline client receives bytes it did not encode and cannot distinguish an over-cap DID document from any other over-cap blob. The DID-record frame's own bound on `value` stays where it is, as a second check on the same quantity at the framing boundary.

**What the caller receives.** The publisher returns a typed error carrying the layer that rejected the encoding, the measured byte length, and the cap. The error code is `SCP-IDENT-1061` on every bridge and every SDK.

**Why the error must be typed and must surface.** An over-cap Mainline publish fails silently today. The Mainline node rejects the put with BEP44 error 205, the `mainline` crate surfaces that rejection as a timeout, `scp-dht` re-wraps the timeout as `DhtPublishFailed`, and the republish loop retries the same over-cap bytes on a backoff capped at 30 minutes. A caller reading that sequence sees intermittent network trouble and never learns that its document cannot fit the layer it is publishing to. `SCP-IDENT-1061` names the cause at the moment the publisher can still act on it.

**The gate is the first thing an implementation builds, and it is useful before the Mainline encoder exists.** An implementation that still serializes the full JSON document for Mainline measures 1,255 bytes against a 1,000-byte cap and is rejected by its own gate with `SCP-IDENT-1061`, at the publisher, before any byte reaches the transport. The capability is then honestly absent — a caller learns that this implementation cannot publish to Mainline — where today it is a false guarantee, because the caller is told the network timed out. Building the encoder first and the gate second would leave every regression in encoded size invisible again, because `InMemoryDhtClient` accepts any length.

**The gate ships with fixtures at and above each cap** — one encoding whose measured length equals the cap and publishes, and one that exceeds it by a single byte and is rejected. A later change that moves the measurement point then fails those fixtures, and the silent failure this section describes cannot return unnoticed. The Mainline fixtures are built by adding `SCPRelay` entries until the measured length crosses 1,000 bytes, which the table below shows happens at 8 entries with a short hostname and 6 with a realistic one.

**This publish-side cap is a different requirement from the parse-side cap that issue #1656, "add a `MAX_DID_DOCUMENT_SIZE` size gate before `serde_json::from_str`", asks for.** The publish-side cap bounds what a publisher emits. The parse-side cap bounds what a resolver deserializes from an untrusted source and guards the resolver against a memory-amplification input; `DidDocument::from_json` (`crates/scp-did/src/document.rs:399`) is a bare `serde_json::from_str` with no length bound and no depth bound. Issue #1656 is open, and both caps are owed.

**Measured sizes, against the relay-layer JSON encoding as the code emits it today.** Each figure is the byte length of `DidDocument::to_json` for a document built through `DidDocument::new` with Ed25519 public keys, a SHA-256 pre-rotation commitment, and `wss://relay.example.com/scp/v1` as the relay URL. "Minified" is `serde_json::to_string` of the same value.

| Shape | `to_json` (pretty) | Minified |
|-------|--------------------|----------|
| `#0` + `#active`, `PreRotationCommitment`, no relay entry | 1,281 bytes | 1,103 bytes |
| The same plus one `SCPRelay` entry (the minimum §18.2.2 permits) | 1,467 bytes | 1,255 bytes |
| The same plus the `#agent` verification method, no relay entry | 1,732 bytes | 1,502 bytes |
| Bootstrap-core entry set, still as JSON | 1,170 bytes | 1,000 bytes |
| The bootstrap-core entry set with `@context` removed | 1,058 bytes | 905 bytes |
| The same with every absolute `did:dht:…#fragment` identifier replaced by its bare fragment | 753 bytes | 600 bytes |

The fourth row is why the two layers carry two encodings rather than one. Reducing the entry set to the bootstrap core does not bring a JSON encoding under the BEP44 cap: the core measures exactly 1,000 bytes minified with the shortest relay URL this specification's own example uses, and bencoding that value adds its `1000:` length prefix, so the bencoded form BEP44 measures is 1,005 bytes before any real relay hostname is substituted. Every figure above was measured against the DID string the code emits today, which is 61 characters because `did_dht_from_public_key` prepends a `z`; fixing that string shortens each row by one byte per identifier it appears in.

**Measured sizes of the Mainline encoding.** These are the figures the two-encoding design rests on, and they are the length of the **bencoded BEP44 `v` value** — the quantity the 1,000-byte cap bounds. Each was derived by constructing the DNS wire-format packet for the bootstrap core with the record shapes and `t=` mapping §18.2.2C states, applying RFC 1035 §4.1.4 compression, and bencoding the result; a parser that follows the compression pointers reads every constructed packet back to the input records. The relay URL is the only variable, and both a short and a realistic hostname are measured, because this specification's own example hostname (`relay.example.com`, 30 bytes with the scheme and path) is shorter than an operator's would be.

| `SCPRelay` entries | Records | `wss://relay.example.com/scp/v1` | `wss://relay-eu-west-1.example-operator.net/scp/v1` |
|--------------------|---------|-----------------------------------|------------------------------------------------------|
| 1 | 5 | 501 bytes | 520 bytes |
| 3 (the minimum §18.2.3 recommends) | 7 | 659 bytes | 716 bytes |
| 5 | 9 | 817 bytes | 912 bytes |

Each additional `SCPRelay` entry costs 79 bytes with the short hostname and 98 bytes with the realistic one, rising by 3 bytes once a two-digit record index appears past nine entries. The cap admits **7 relay entries** at the short hostname (975 bytes) and **5** at the realistic one (912 bytes), so §18.2.3's recommended minimum of 3 fits with 284 bytes to spare at a realistic hostname, and an identity publishing more than 5 relay entries at a realistic hostname is what first presses the cap. A publisher that exceeds it is rejected by §18.2.2D's gate rather than by a Mainline node.

**A third verification method costs 84 bytes**, flat across both hostnames and every relay count: 75 for the `_k2` record and 9 for the aliases it adds to the root record's `vm=`, `auth=` and `asm=` lists. This is a different figure from the service-entry marginals above, and an earlier draft of this specification and of `.docs/specs/00-open-questions.md` reused the service figure for it.

**What these figures do not cover.** They measure the bootstrap core and only the bootstrap core. An identity's relay-layer document grows with attestations and service entries against a 262,039-byte bound, and none of that reaches Mainline (§18.2.2C). The one variable inside the core that this table does not sweep is the relay URL length beyond the two hostnames measured; the 70-and-89-byte marginal costs above are what a reader uses to price a longer one.

### 18.2.3 Multiple Relay Entries

An identity SHOULD publish at least 3 `SCPRelay` entries for suppression resistance (§9.9.2). `TransportManager` reads all `SCPRelay` entries from a resolved DID document and routes to all of them. The relay set partitioning logic (ADR-012) operates on top of the published relay list.

Relay entries are ordered by preference (first entry = preferred relay). Clients SHOULD respect ordering when selecting a subset. When adding or removing relays, the identity updates its DID document and republishes to both layers, each in its own encoding and each advancing its own sequence number (§3.10.5, §18.2.1). Peers that re-resolve the DID document discover the updated relay list.

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
- Relay URLs MUST use the `wss://` scheme.
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
2. **DID document resolution.** Resolve the identity's own bootstrap core via Mainline DHT. Extract `SCPRelay` service entries. Self-certifying (§9.6.3). This level is why the relay list stays inline in the Mainline bootstrap core (§18.2.2C) rather than behind a pointer: a pointer to a relay list would need a relay to fetch it, and this level is where the SDK first learns of any relay.
3. **`.well-known/scp` resolution.** If a bootstrap domain is configured, fetch `https://<domain>/.well-known/scp` and extract the relay URL. Verify against DID document (§18.3.2).
4. **Peer relay discovery.** For identities that share contexts with known peers, resolve the peer's DID document and use overlapping relay sets. This enables relay discovery through the social graph.
5. **Fallback relay list.** A hardcoded list of well-known community relays shipped with the SDK. Last resort. These relays are not privileged — they are default suggestions that can be overridden. The SDK SHOULD warn when falling back to default relays. The fallback list MUST include at least one free relay (no `economic` field in `relay_config`) — this is a protocol invariant that prevents economic gatekeeping of basic protocol operation (§19.8, §19.14).

Each priority level is tried in order. The first level that yields at least one reachable relay is used. The SDK MAY combine results from multiple levels (e.g., explicit + DID document) for suppression resistance.

Bootstrap relays SHOULD support STUN service (§10.12.3) — this makes them available as NAT type detection endpoints for self-hosted relays behind residential NAT. Bootstrap relays also serve as DID resolution endpoints: identity owners SHOULD publish DID documents to bootstrap relays via the relay-based resolution layer (§3.10.2), and resolvers SHOULD query bootstrap relays when the identity's own relays are unknown.

### 18.5.2 Agent Deployment Case

An agent deploying via `ApplicationNode` (§18.6) follows a simplified bootstrap:

1. `ApplicationNode::builder().domain("example.com").build()` starts the relay server on the local machine.
2. The relay URL is `wss://example.com/scp/v1` (derived from the configured domain).
3. The identity publishes this relay URL as an `SCPRelay` entry to both layers, each in that layer's own encoding (§3.10.5): the full JSON document to SCP relays and the DNS-encoded bootstrap core to Mainline.
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
   d. Publishes to both layers, each in its own encoding (§3.10.5): the full document carrying the `SCPRelay` entry to SCP relays, and the DNS-encoded bootstrap core carrying the same entry to Mainline
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
