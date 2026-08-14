---
name: adr057-d5-relay-client-crate
description: ADR-057 Slice-3 D5 move of ClientMessage/RelayMessage into wasm-safe scp-relay-client leaf — crypto verdict SOUND
metadata:
  type: project
---

# ADR-057 Slice-3 D5 — relay wire types → scp-relay-client leaf (branch refactor/adr057-d5-relay-client-crate)

VERDICT SOUND. The relay wire types `ClientMessage`/`RelayMessage` + size constants + protocol error moved from `crates/scp-transport/src/native/{protocol,error}.rs` into new wasm-safe leaf `crates/scp-relay-client/` so native relay + in-browser client share ONE definition.

**Why no crypto impact:** These are PURE TRANSPORT FRAMING around an OPAQUE `blob`/`payload` (serde_bounded_bytes, 512 KiB cap). They feed NO Merkle leaf, signature, or convergent-timestamp AAD. MLS ciphertext rides inside `blob`; relay never sees plaintext (untrusted dumb pipe). Grep of scp-event-log/scp-mls/scp-protocol for these types = only hit is unrelated `BridgeCapability::RelayMessages` enum variant (params.rs:408). No §9.9.3 convergent-log coupling.

**Byte-parity (rename-aware `git diff -M`):** ONLY changes = (1) error type rename NativeProtocolError→RelayProtocolError (Rust name, never serialized), (2) doc comments, (3) serde_bounded_bytes path re-point `scp_core::serde_util`→`scp_protocol::serde_util`. Verified scp-core/src/lib.rs:13 = `pub use scp_protocol::serde_util;` (SAME function). ZERO changed serde container/variant tag attrs. error.rs = pure rename, no changed ProtocolErrorCode constant values.

**KAT (crates/scp-client-wasm/tests/cross_target_determinism_kat.rs):** adds 2 FIXED golden hex consts (GOLDEN_CLIENT_PUBLISH_HEX 86-map/6-field Publish, GOLDEN_RELAY_BLOB_HEX 87-map/7-field Blob), asserts `to_hex(from_bytes→to_bytes)==GOLDEN` on BOTH native `#[test]` + wasm32 `wasm_bindgen_test`. True byte-identity pin (native==golden ∧ wasm==golden ⇒ native==wasm), NOT runtime recompute. Ran natively — passes.

**Wasm fence:** scp-relay-client deps = scp-protocol + serde/serde_bytes/rmp-serde/thiserror only. NO scp-runtime/scp-identity/scp-clock/tokio/openmls. Added to wasm32 CI check job. shim-reexport gate expanded (scp_relay_client added to closed positive set = coverage add, not weakening); native/mod.rs deliberately does NOT re-export (avoids forbidden shim). Exactly one def in tree (nostr/protocol.rs ClientMessage/RelayMessage are unrelated Nostr adapter types). No blocker.
