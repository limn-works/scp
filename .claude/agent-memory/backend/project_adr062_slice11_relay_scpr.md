---
name: project-adr062-slice11-relay-scpr
description: ADR-062 Slice 11 (SCP-CAPINJECT-011) DID relay READ+WRITE over SCPR frames — non-obvious findings on where the write path lives, testing-gating, and gate quirks
metadata:
  type: project
---

ADR-062 Slice 11 / SCP-CAPINJECT-011 — real relay DID resolution (READ) + publishing (WRITE) over SCPR kind-1 frames (Model A, spec §9.10.12 / §3.10.12). Branch `feat/adr062-slice11-relay-querier`, commit f4e1e2d08.

Non-obvious findings (the rest is derivable from code):

- **FFI DID-publish is entirely `#[cfg(feature="testing")]`.** All three bridges' DID-publish helpers (`publish_to_resolver_dht_for` in pyo3 `scp-ffi/src/identity.rs` + uniffi `bridge.rs`; `publish_to_shared_dht_for` in napi `identity.rs`) are testing-gated because **production `identity_create` fails closed** (ADR-062 §Decision 6 pre-rotation nullifier severance, pending RFC #2130). So there is NO production DID publish today — DHT or relay. The correct place to wire the relay WRITE half is *inside those same testing-gated helpers* (a best-effort one-shot relay publish alongside the one-shot DHT publish), NOT scp-node.
  - **Why:** scp-node's `publish_did_document_for_mode` (lib.rs) is the node's own-DID publish, but the node is a *relay server* with no outbound client `TransportManager` in its build path, and self_host deliberately KEEPS `NoOpRelayQuerier` (loopback relay is a protocol-unaware blob pipe, §10.4). So the write path belongs in the FFI where participants mint+publish and `bi.core.transport_handle()` exists.
  - **How to apply:** shared helper `scp_ffi_common::publish_did_record_to_relay(live, did, value, sig, seq)` in `resolvers.rs` (gated behind `resolvers` feature, glob-re-exported); called from each bridge's testing-gated DHT-publish helper. Fail-open (best-effort) mirrors the existing fail-open DHT publish.

- **Neither DHT nor relay uses a production `RepublishManager`** — both publish one-shot. `RepublishManager` has ZERO production constructions (only `#[cfg(test)]`). The story's action-item said "wire a production RepublishManager," but the AUTHORITATIVE 13 acceptanceCriteria require only the real `RelayPublisher` (severed default + demoted double + loop fix + tests), which one-shot relay publish satisfies consistently with the established one-shot DHT pattern. RepublishManager's relay loop was still fixed (SCPR-wrap) + tested (AC9).

- **cross-layer gate (`check-cross-layer.sh`) is PR-only** (`ci.yml` `if: github.event_name == 'pull_request'`), so a plain branch push does NOT trigger it. It flags new `pub fn` in scp-protocol/runtime lacking a matching name in the scp-ffi diff. `encode_did_record` matches (used in `scp-ffi/common/src/resolvers.rs`); `decode_did_record` does NOT (consumed only in scp-transport) → the PR body MUST carry `[cross-layer: pub-crate-visibility] decode_did_record` (its legitimate exemption category: cross-crate pub, not SDK surface).

- **`scp-relay::storage_backend` nextest failures are environmental, NOT regressions.** Those 4 tests `Command::new(relay_bin())` the `scp-relay` binary; nextest doesn't build it (shared target dir at `~/.cargo/shared-target`, fallback path wrong) → "NotFound". They PASS under `cargo test -p scp-relay --test storage_backend` (builds the bin, sets `CARGO_BIN_EXE_scp-relay`). Full suite: 10769/10773 pass, the 4 are this quirk.

- **Relay wire `blob_ttl` is `u32`** (`ClientMessage::Publish`), but the public-record API + `RelayPublisher` trait use `u64` (matches identity layer). Convert saturating at the native adapter (`native/adapter.rs::publish_raw`).

- **`LiveTransport`** (new, scp-transport `did_relay.rs`): cheaply-cloneable `Arc<RwLock<Option<Arc<TransportManager>>>>`. `current()` clones the Arc out under a short read-lock (safe across `.await`); `slot()` exposes the raw lock so `BridgeInstance` keeps its poison/`get_mut` policy. `BridgeInstance.transport` now holds it; `transport_handle()` hands clones to `TransportRelayQuerier`/`TransportRelayPublisher` (fail-closed when unset).
