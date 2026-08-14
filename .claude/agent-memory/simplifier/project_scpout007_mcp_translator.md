---
name: scpout007-mcp-translator
description: SCP-OUT-007 scp-mcp lexical translator review — what is story-sanctioned vs a real simplification, and the sentinel/canonical-enum staleness.
metadata:
  type: project
---

SCP-OUT-007 re-ports `crates/scp-mcp/src/translator.rs` (lexical outlet↔tool at MCP boundary, §8.5).

Key facts (verify against code before acting — this is a point-in-time snapshot):
- The bulk value-level translators `mcp_to_scp`/`scp_to_mcp` (~880 impl lines, 6 message shapes × 2 dirs) have ZERO production callers. Only refs outside the module = lib.rs rustdoc examples + tests. The LIVE server boundary (`server.rs`) uses a TYPED path (`ToolsCallParams`/`ToolsListResult`/`context_tool_definition`) plus ONLY the two small name helpers `format_mcp_tool_name`/`parse_mcp_tool_name`. So two parallel boundary impls exist; only the name helpers are wired.
- This is STORY-SANCTIONED, NOT a BLOCKER: AC2/AC3 make the value translators the deliverable, tested via the fixed corpus; wiring the value path (proxy/forwarding mode where verbatim payload preservation matters) is a later slice. Complete + fully tested ≠ stub. Don't flag as over-engineering.
- Sentinel `OutletKind` (translator.rs:133): doc claims "real enum lands in SCP-OUT-017". FALSE — canonical `scp_protocol::context::outlets::OutletKind` (Query/Action, serde `rename_all="lowercase"`, `canonical_byte`) ALREADY EXISTS and is reachable as `scp_core::context::outlets::OutletKind` (server.rs already imports `validate_value_against_schema` from that exact module). FFI bridges the two via `outlet_kind_to_mcp`.
- Wire-spelling divergence risk: sentinel emits CAPITALIZED "Query"/"Action" as the SCP-side `kind`; canonical §5.4.2/serde is lowercase "query"/"action". Latent (no prod consumer yet); would break if value translator is ever fed to canonical deserialization. Route to bug-catcher/completionist.

Genuine simplifications found (behavior-preserving):
1. client.rs `list_outlets` returns `(OutletKind, String, ToolDefinition)` — element 1 == element 2's `.name` (redundant clone; test asserts both equal). Collapse to `(OutletKind, ToolDefinition)`.
2. Error-meta mapping = 6 symmetric field pairs (code↔scp_error_code, slug, class, retry, detail, source_chain) hand-written as 12 `if let` blocks across both directions. Table-collapsible to `const [(&str,&str);6]` + 2 loops (guarantees inverse). message/scp_message stays special-cased.
3. `rewrite_mcp_method_to_scp`/`rewrite_scp_method_to_mcp` = identical modulo inverse 3-entry table.

Appropriately simple (leave alone): the 4 verbatim payload pass-through sites (inline `if let Some` moves; the "VERBATIM, no recursion" COMMENT is the load-bearing security doc, not extractable). No dead code from the invoke_tool→invoke_outlet / ContextToolInfo→ContextOutletInfo rename (fully migrated incl. FFI). Two test files complementary (no name overlap).
