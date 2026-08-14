---
name: adr057-d5-relay-client-crate
description: COMPLETE zero-gap review of ADR-057 Slice-3 D5 crate extraction (scp-relay-client) at fd372704b
metadata:
  type: project
---

ADR-057 Slice-3 D5: extracted relay wire types (ClientMessage/RelayMessage + closure) from scp-transport/src/native/{protocol,error}.rs into new wasm-safe leaf `crates/scp-relay-client`. Reviewed @fd372704bf (branch refactor/adr057-d5-relay-client-crate, 34 files vs origin/main). VERDICT COMPLETE — all 7 plan items DONE.

**Why:** Native relay + future in-browser client must share ONE wire-type definition compilable to wasm32 (no forked copy / byte-parity tax).

**How to apply (evidence patterns for crate-extraction completeness reviews):**
- wasm-safe-by-construction = manifest audit: deps are ONLY scp-protocol/serde/serde_bytes/rmp-serde/thiserror; NO scp-runtime/scp-identity/tokio/openmls. rmpv correctly in [dev-dependencies] (moved tests need it).
- Closure complete: `grep -rn NativeProtocolError crates/` = 0 (renamed RelayProtocolError); constants+byte_array_32_opt+validate_* fns+`mod code`(server 4xxx/5xxx codes) all in relay-client protocol.rs/error.rs; `grep native::protocol|native::error` = 0.
- No shim: native/mod.rs declares NEITHER module, has explicit comment "deliberately NOT re-exported here (forbidden by ADR-057 Amendment)"; no `pub use scp_relay_client` in scp-transport (only plain `use`).
- Consumers retargeted: 8 internal scp-transport sites + quic/streams.rs:37,104 doc-links + external (scp-node 3 tests, scp-testing 1 test, 2 fuzz targets) all `use scp_relay_client::`.
- Enforcement = EXPAND-coverage: ci.yml wasm job adds `-p scp-relay-client`; check-no-shim-reexports.sh adds scp_relay_client to BOTH crates=() array AND owning_dir(); release.yml publish step at line 460 (protocol=412, transport=468 → correct dep order) + summary list. check-protocol-deps.sh correctly untouched (plan-specified).
- KAT dual-entry: relay_wire_encoding_is_target_deterministic has `#[cfg_attr(wasm32, wasm_bindgen_test)]` + `#[cfg_attr(not(wasm32), test)]`, round-trips golden ClientMessage::Publish/RelayMessage::Blob through relay-client codec; scp-client-wasm gained types-only dev-dep (comment: "pulls NO transport/pump code, stays inside D5 fence").
- Manifests: scp-transport prod dep (=0.1.0-beta.2 pin), scp-node/scp-testing dev-dep, fuzz dep — all correct sections.
