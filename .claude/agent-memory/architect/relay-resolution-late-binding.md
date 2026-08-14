---
name: relay-resolution-late-binding
description: Architecture of the production relay-resolution (RelayQuerier) late-binding layer — dep direction, transport-slot handle, unspecced blob framing, NoOp legitimacy
metadata:
  type: project
---

Design context for bringing the production relay-DID-resolution arm online (ADR-062 Slice 11 intent; the ADR file itself is NOT present on branch feat/adr062-slice6-nullifier-severance).

**Verified facts (2026-07-17):**
- No production `impl MultiRelayQuerier`/`RelayQuerier` exists. Shipped relay arm = `NoOpRelayQuerier` (scp-identity/src/resolver.rs:309). Test double = `InMemoryRelayQuerier` (resolution.rs:246).
- Dep direction: scp-transport → scp-identity (transport depends on identity). So the production querier (does network QUERY) MUST live in scp-transport and implement scp-identity's trait (dependency inversion). scp-identity cannot name `TransportManager`.
- Both `RelayQuerier` (single-relay, resolution.rs:90) and `MultiRelayQuerier` (resolver.rs:131) use RPITIT → NOT object-safe → concrete impls are generic type params, never `dyn`.
- `DualLayerResolver<R: MultiRelayQuerier, D, C, H>` calls `relay_querier.query(did, relay_urls)` ONCE and re-validates the single returned `RelayRecord` via `verify_and_deserialize` (BEP44 sig + self-cert). So per-relay iteration + first-VALID selection MUST happen INSIDE the MultiRelayQuerier.
- Per-instance transport slot: `transport: RwLock<Option<Arc<TransportManager>>>` inside `CoreFields` of `BridgeInstance` (crates/scp-ffi/common/src/bridge_instance.rs:264). Accessed via `set_transport`/`clear_transport`/`with_transport`/`has_transport`. It is a struct FIELD, not an independently-shareable Arc — late-binding requires refactoring it into a cloneable handle type (defined in scp-transport so both the querier and BridgeInstance can name it; no cycle).
- `TransportManager::query(routing_id, since) -> Vec<OuterEnvelope>` (manager.rs:731) is ADAPTER-SET scoped (Phase-1: first adapter only), NOT relay-URL scoped. The resolver's per-relay-url priority list cannot be honored precisely today — bounded, documented limitation, tied to the existing manager.rs "Phase 2+: all adapters" TODO.

**Two non-obvious corrections to common framing:**
1. `NoOpRelayQuerier` is NOT purely a test double. self_host.rs:1341 (`build_shared_cache_key_resolver`) uses it in PRODUCTION deliberately — the node's loopback relay is a blob pipe, not a DID-QUERY source, so DID resolution flows through the DHT arm. (self_host.rs:2690/2764 ARE tests.) => NoOp CANNOT be demoted to test-only; only the 3 FFI-bridge NoOp uses switch to the real querier.
2. The FFI bridges' DHT arm is ALSO in-memory (`InMemoryDhtClient`, e.g. scp-ffi/src/identity.rs:85). So FFI DID resolution today = local-only. Relay is one of two non-production arms.

**THE blocking upstream ambiguity:** the relay DID-record blob framing is undefined. `RelayPublisher::publish(routing_id, blob_ttl, blob)` takes a raw blob = "BEP44-signed DID document bytes", but a BEP44 mutable item is (value, signature[64], seq) and `TransportManager::query` returns `OuterEnvelope` (whose `encrypted_blob` is MLS-encrypted — a DID record is PUBLIC, unencrypted). How {value,sig,seq} is packaged into/around an OuterEnvelope and decoded back is NOT specced in §3.10.12. Must be answered upstream (spec/ADR) before any real querier can decode. Do NOT invent it.

**Branch drift vs prompts:** ci.yml:374 clippy string on this branch STILL uses `allow_in_memory_custody` (+ `scp-runtime/saga-witness-test-mint`); claims that story 006 deleted it are stale for this branch. No `check-shipped-feature-graph.sh` exists — real gates are check-protocol-deps.sh, check-protocol-sync.py, check-cross-layer.sh. LAYER_TIMEOUT=10s (resolver.rs:245) diverges from spec §3.10.4's 5s.
