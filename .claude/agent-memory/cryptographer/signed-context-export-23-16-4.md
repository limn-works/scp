
## UPDATE: scope-byte binding (branch signed-ctx-export-rebase @1df6dba8c, ADR-050) — SOUND
NATIVE construction CHANGED. Preimage is now:
`SHA-256("SCP-CONTEXT-EXPORT-V1:" || [scope_tag_byte] || JCS(ContextSnapshot))`.
- Separator is now SCP-CONTEXT-EXPORT-V1: (NOT ...SNAPSHOT-V1: — that's the distinct sync-delta
  separator, export_import.rs:113/128). The earlier-memory "nothing appended" is SUPERSEDED.
- scope_tag: Full=0x00 / Public=0x01, shared consts scp-protocol/src/context/export.rs
  (EXPORT_SCOPE_TAG_FULL/PUBLIC). scope lives on the UNSIGNED ContextExport envelope; the tag byte
  is the ONLY thing binding scope into the sig → flipping envelope Public→Full breaks the sig by
  construction (no longer rests on hollow-context argument).
- Domain separation unambiguous: fixed ASCII sep ends ':', then 1 control-range scope byte (0x00/01),
  then JCS starting {/[ (0x7B/5B). No collision/parse ambiguity.
- verify_strict native (export_import.rs:631) + WASM (manager.rs:5405). Producer+verifier both call
  canonical_snapshot_hash (native) / wasm_export_snapshot_digest (WASM) — no drift.
- WASM scope: always Full (no scope field on WASM envelope). wasm_export_snapshot_digest helper
  (manager.rs:6118) extracted byte-faithfully; uses shared EXPORT_SCOPE_TAG_FULL const.
- Merkle binding, verify-before-restore, epoch-floor anti-rollback, JCS set/map determinism: all SOUND.
- Cross-family (native MessagePack ContextSnapshot vs WASM JSON WasmContextExportSnapshot which has
  NO event_log_merkle_root): NOT byte-compatible by design — only construction converges, not bytes.
- LOW: compute_entry_hash duplicated byte-identical export_import.rs:505 + providers/event_log.rs:145.
- NIT: compute_entry_hash docstring "canonical JSON" = serde_json default (preserve_order OFF →
  Value::Object BTreeMap, key-sorted, deterministic), not RFC8785 JCS. Internally consistent.
VERDICT at this state: cryptographically SOUND, no blocking findings.
