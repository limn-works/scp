---
name: adr057-d5-relay-client-crate
description: ADR-057 Slice-3 D5 relay-wire-types move to scp-relay-client leaf crate — CLEAN review, 0 defects
metadata:
  type: project
---

# ADR-057 Slice-3 D5 — relay wire types → scp-relay-client (branch refactor/adr057-d5-relay-client-crate)

**CLEAN, 0 defects.** Behavior-preserving move of `ClientMessage`/`RelayMessage` + `NativeProtocolError`→`RelayProtocolError` out of native-only `scp-transport::native::{protocol,error}` into new wasm-safe leaf `crates/scp-relay-client`.

Verified:
- **Wire byte-identity:** direct `diff` of old vs moved protocol.rs = ONLY doc-comment, error-rename, and `serde_bounded_bytes` path re-point (`scp_core::serde_util`→`scp_protocol::serde_util`). NO serde tag/rename/field-order/`with=` drift. Re-point is a no-op: `scp-core/src/lib.rs:13` is literally `pub use scp_protocol::serde_util;` → same function. error.rs diff = doc+rename only.
- **KAT real (not tautological):** cross_target_determinism_kat.rs relay leg compares re-encode against a committed hex LITERAL (GOLDEN_CLIENT_PUBLISH_HEX / GOLDEN_RELAY_BLOB_HEX), asserted on native+wasm32. Ran native → PASS. 71 moved unit tests PASS.
- **wasm-safe fence holds:** `cargo check -p scp-relay-client --target wasm32-unknown-unknown` builds (deps only scp-protocol + serde/serde_bytes/rmp-serde/thiserror). CI wasm-fence line + shim-check closed-set both correctly EXPANDED to include scp_relay_client (coverage growth, allowed).
- **No shim:** native/mod.rs deliberately does NOT re-export moved types; grep for `pub use scp_relay_client` in scp-transport = empty; check-no-shim-reexports.sh passes.
- **No false-positive damage:** nostr's own ClientMessage/RelayMessage (nostr/adapter.rs `super::protocol` correctly untouched), scp-testing RelayMessage struct, scp-protocol RelayMessages variant all intact.
- **Retarget complete:** no residual `native::protocol`/`native::error`/`NativeProtocolError` anywhere; quic/udp/webtransport/node-tests/testing-tests/fuzz all repointed; scp-transport + KAT compile.
- **Publish order correct:** release.yml publishes scp-relay-client after scp-protocol, before scp-transport.
