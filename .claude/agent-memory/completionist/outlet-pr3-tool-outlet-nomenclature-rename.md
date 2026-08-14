---
name: outlet-pr3-tool-outlet-nomenclature-rename
description: Wholesale tool→outlet nomenclature rename PR-3 completeness/consistency/boundary review — COMPLETE
metadata:
  type: project
---

# Outlet PR-3 wholesale `tool`→`outlet` nomenclature rename — COMPLETE + consistent + correctly-bounded

Reviewed `git diff 43c741f61..HEAD` @4e6fb43ef, worktree scp-wt-outlet-pr3, branch feat/outlet-report-pr3 (18 commits, 233 files). Renamed ALL SCP-outlet-domain `tool` nomenclature→`outlet`: error codes (SCP-TOOL→SCP-OUTLET), event records (Tool*→Outlet* enum variants, numeric wire tags KEPT), core types (ToolId→OutletId / ToolRegistration→OutletRegistration / EstablishToolInterface→EstablishOutletInterface), fields/tests/wire-strings/docs, Tools→Outlets domain label.

**Verdict COMPLETE.** All 5 focus axes clean:
1. Zero-outlet-tool gate: `git grep -in '\btool' -- crates/** bindings/** :!crates/scp-mcp` = 99 hits, EVERY one a justified keep (MCP protocol ToolDefinition/list_tools/mcp.py/Mcp.swift; toolchain/tooling English; TOML [tool.*]; BIP39 "tool"; roles.rs legacy hard-reject `tool:invoke:`/`tool_invoke:`/`tool:register`/`tool:interface` = SCP-OUT-014 MUST-stay; hash.rs:60 comment documenting pre-rename domain; SCP-TOOL-6100 negative fixture; invitation_bundle.rs:627 comment documenting JCS key `tools`→`outlets`). MCP-trait names (invoke_tool/context_tools/ContextToolInfo/list_tools) DON'T match `\btool` (word-boundary: preceded by `_`/`t`) — they stay legit as scp-mcp ContextProvider surface.
2. Cross-layer consistency: 0 surviving old core type names (grep ToolId|ToolRegistration|EstablishToolInterface|ToolInvokedEvent|struct Tool = EMPTY). Event enum Outlet* consistent event-log↔consumers, numeric tags 9/11/13/76 preserved (no wire break). EstablishOutletInterface 36 refs, 0 old. No serde(rename=…tool) half-renames. scp-protocol+scp-event-log `cargo check` = clean (half-rename would fail Rust compile).
3. Domain label 3-way consistent: matrix "domain":"Outlets" (single) + check-sdk-coverage ("Outlets",…) + bridge-aliases "category":"outlets". check-sdk-coverage PASS (233 ops, 0 err). check-bridge-symmetry PASS (0). check-error-codes PASS (2922 occurrences).
4. No new gap/stub/dead-ref; all enforcement green.
5. MCP boundary CORRECT: mcp.rs trait methods stay invoke_tool (external MCP), SCP-registry-lookup params → outlet_name uniformly across all 3 native bridges (pyo3 mcp.rs:838/1890, napi mcp_client_invoke_on:737, uniffi:15710). SDK public MCP-client invoke exposes `tool:` param (MCP nomenclature) mapped to FFI `outletName`/`outlet_name` — consistent boundary, not a half-job.

Internal wire consistency proof: KAT vector_28 byte-count bump 73→75 (commit 339caded3) exactly = `tools`(5)→`outlets`(7) JCS key +2 bytes.

**OUT-OF-SCOPE OBS (pre-existing, NOT this PR):** test_vectors.rs:1303 `domain_separators_are_all_unique` still catalogs phantom `SCP-TOOL-REGISTRATION-V1:` while real code constant is `SCP-OUTLET-REGISTRATION-V2:` (hash.rs:62, already V2 at diff base 43c741f61 — earlier PR-1/2 bump). Test still passes (stale string is unique) but no longer verifies the LIVE domain's uniqueness/non-prefix-collision. Latent gap, not a PR-3 rename finding. Worth a follow-up entry in that catalog.

LESSON: on wholesale rename reviews, `\btool` word-boundary grep MISSES `_tool`/`Xtool` composites (invoke_tool, ContextToolInfo) — good for filtering MCP-trait keeps but re-grep bare `[Tt]ool` if you need those too. A manually-maintained domain-separator uniqueness CATALOG (not bound to code constants) silently goes stale on a domain rename and keeps passing — grep the catalog against the actual `const *_DOMAIN` values.
