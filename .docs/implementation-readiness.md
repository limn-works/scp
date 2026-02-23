# Implementation Preparation Checklist

**Date:** February 23, 2026
**Source:** Comprehensive artifact audit of all specs, ADRs, scaffolds, standards, and anchor files.
**Purpose:** Concrete implementation decisions to make during build. Design gaps live in `00-open-questions.md`.

---

## Phase 1 — Decide During Implementation

- [x] **Relay wire format (ADR-004).** ~~Choose: JSON over WebSocket text frames vs. MessagePack over binary.~~ **Decided:** MessagePack over WebSocket binary frames. Oldest-first backfill ordering. Error codes: 4xxx client, 5xxx server. URL path versioning (`/scp/v1`). PING/PONG keepalive every 30s. Client-assigned `ref` field for request correlation. EVENT signals for backfill/query completion. Full wire format specification written into ADR-004.
- [x] **DID library selection (ADR-003).** ~~Evaluate `did-dht` and `veilid-did` crates.~~ **Decided:** `pkarr` (v5.0.3+) + `mainline` (v6.1.1+) + `z-base-32`. No production Rust crate for did:dht exists — `did-dht` is not on crates.io, `web5-rs` (TBD) is abandoned (Nov 2024 shutdown), `veilid-did` does not exist. pkarr provides Ed25519 keys, BEP44 signed mutable items, DNS packet construction, and Mainline DHT publish/resolve. SCP implements ~300 lines of did:dht-specific DID Document to DNS record encoding on top. Both crates are actively maintained by the Pubky team (62K and 18K downloads/month respectively). `did:web` remains contingency fallback only.
- [x] **Test infrastructure (§16).** ~~Design simulation framework, conformance test approach, and relay storage abstraction.~~ **Decided:** `scp-testing` crate (dev-dependency only) with deterministic `SimulatedClock`, `InMemoryRelay` implementing full ADR-004 protocol with 8 `BehaviorMode` variants mapped 1:1 to §9.9.1 threat model, `InMemoryTransport` implementing `TransportAdapter`, `NetworkSimulator` orchestrator with configurable topology and fault injection, `ScenarioBuilder` fluent API, 7 distributed assertion functions, 8 preset scenarios, and 6 trait conformance macro generators (`transport_conformance!()`, `storage_conformance!()`, `key_custody_conformance!()`, `attestation_conformance!()`, `push_conformance!()`, `blob_store_conformance!()`). `Clock` trait in scp-core, `BlobStore` trait in scp-transport/native. Full spec in `.docs/specs/16-test-infrastructure.md`.
---

## Audit Results

The following areas passed audit with no issues (February 23, 2026):
- All 13 design decisions correctly propagated across specs
- A2A removal complete — no residual references
- ADR phasing and dependency ordering — no cycles, build order unambiguous
- Language binding surface area — all 8 languages cover same API
- Cross-language naming — comprehensive table in shared.md, idioms respected
- Scaffold files — exist with real content, standards references valid
- All well-known templates consistent with decisions
- Metadata privacy architecture (§9.10) — all 10 decisions correctly implemented
- Sender-side key layer (§9.16) — fully specified including wrapping key lifecycle
