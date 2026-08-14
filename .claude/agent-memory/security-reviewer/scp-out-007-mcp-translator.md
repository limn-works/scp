---
name: scp-out-007-mcp-translator
description: Security review of scp-mcp MCP<->SCP lexical translator (SCP-OUT-007, fix/outlet-recover-007-mcp f23ed4923+2399b844e). Untrusted MCP wire input.
metadata:
  type: project
---

# SCP-OUT-007 MCP<->SCP translator security review (2026-08-02)

Branch fix/outlet-recover-007-mcp, commits f23ed4923 + 2399b844e, base 4e8297b8c.
Files: crates/scp-mcp/src/{translator.rs(new,1462L), client.rs, server.rs, allowlist.rs,
stdio.rs, sse.rs, namespace.rs}. Verdict: SECURE, 0 CRITICAL/HIGH. Findings LOW/observation only.

**Key architectural fact (drives most conclusions):** the recursive translator entry points
`mcp_to_scp` / `scp_to_mcp` (translate_*_value) are PUBLIC but currently UNWIRED — only
`parse_mcp_tool_name`, `format_mcp_tool_name`, `OutletKind` are used by server.rs/client.rs/FFI.
server.rs handle_request works on typed structs (ToolsCallParams etc.), not the recursive translator.

**Invariants that hold the posture:**
- Purely lexical: translator makes NO auth decision (string rewrite only). Confirmed.
- Fail-CLOSED kind classification (parse_mcp_tool_name translator.rs:776-786): ONLY explicit
  `query.` prefix -> Query; `call.` and everything else (unprefixed, slash-style, multi-prefix)
  -> Action (mutating default). Absence can never become read-only. Confirmed correct direction.
- Kind is NOT authoritative for authz: server.rs:443 discards inbound outlet_kind (`let _`);
  authz is validate_capability(context_id, outlet_id) on the prefix-STRIPPED outlet_id.
  server.rs:379 uses only the REGISTRY kind (outlet_info.kind) for outbound display naming.
- No cross-outlet/traversal: parse_namespaced_tool splits on FIRST '/', membership enforced on
  context_id, outlet_id is exact-match registry key (no path semantics). `../`, extra slashes,
  multi-prefix all fail closed. Three spellings (foo / call.foo / query.foo) collapse to same
  outlet_id but authz is on that id => no privilege gain.
- Depth/DoS: untrusted Value comes from serde_json::from_str (default RECURSION_LIMIT=128) =>
  translator recursion bounded, no stack overflow on wire path. No panic (no unwrap/index/`as`
  overflow outside tests; string slices at ASCII '/' boundaries).
- Verbatim opaque payload (arguments/_meta) is CORRECT/SAFE (translator.rs:312-319, 408-412,
  741-745): prevents envelope-shape-misdetection corrupting caller data; not injection (data only,
  schema-validated downstream at server.rs:479).
- Allowlist (allowlist.rs) FAIL-CLOSED: default enforcement on, no shells; rejects paths (/ and
  explicit backslash), NUL/control chars even in unrestricted mode; unknown->NotAllowed; returns
  basename for Command::new; configure validate-all-then-insert atomic; per-instance not global;
  disable_enforcement audited (tracing::warn+instance_id). Documented residual (by design, separate
  layer): malicious PATH shadow + malicious ARGS to allowed binaries (node -e, docker run -v /:/host).

**LOW / defense-in-depth (for future, not live vulns):**
1. Inbound (untrusted) mcp_to_scp emits caller-derived `kind` into SCP params (translator.rs:311).
   Not exploitable now (discarded). MUST-NOT for SCP-OUT-017: classification gate must use REGISTRY
   kind, never translator-emitted inbound kind. Action-as-Query risk the day someone wires it.
2. OutletError-envelope detection requires map.len()==1 (translator.rs:512): an error body with an
   extra sibling field loses the isError signal on scp_to_mcp -> fail-open error signaling.
3. isError parsed via as_bool().unwrap_or(false) (translator.rs:351): non-bool `isError:"true"`
   silently -> success. (Live client path uses typed ToolsCallResult so serde catches it.)
4. stdio.rs:120 read_line unbounded (pre-existing, test-only change here); stdin is trusted host in
   MCP stdio mode, low sev.
5. Outlet ids beginning with `query.`/`call.` are ambiguous under parse_mcp_tool_name (namespace
   hygiene, not authz bypass).

## Round-2 confirming pass (final commit 41b81f8bc, 2026-08-02) -- ZERO FINDINGS, SECURE
Verified the 3 prior LOW hardening items are fixed and no new hole vs malicious external MCP peer.
- A5: SECURITY note at inbound caller-derived `kind` write (translator.rs:332-340 + server.rs:439 mirror) is ACCURATE -- authoritative kind is always registry's (ContextOutletInfo.kind); server discards inbound kind (`_outlet_kind`), authz = validate_capability on prefix-stripped outlet_id; list path uses registry outlet_info.kind for display only. parse_mcp_tool_name still Action-fail-safe post canonical-swap.
- A3: OutletError detect changed map.len()==1 -> `matches!(map.get("error"),Some(Object))` presence-of-object-error. FAIL-CLOSED: sibling can't suppress isError. `matches!` peek short-circuits && so non-object error (string) falls through verbatim (no misclassify/no dropped data). scp_to_mcp direction is TRUSTED-produced (not attacker-reachable); success->error misclassify is fail-closed anyway.
- A4: is_error = `map.get("isError").is_some_and(|v| *v != Value::Bool(false))`. FAIL-CLOSED: only literal false/absent=success; "true"(string)/1/null/non-bool -> error envelope. THIS is the real attacker path (external server CallToolResult via mcp_to_scp).
- A6 lowercase: canonical scp_core::context::outlets::OutletKind has #[serde(rename_all="lowercase")] + #[default]Action. Translator re-exports it (was local sentinel). kind_scp_tag emits "query"/"action" pinned by round-trip test kind_scp_tag_matches_canonical_serde_spelling; kind_from_scp_tag rejects unknown/capitalized -> caller .unwrap_or(Action). FFI now moves canonical enum directly (kind:t.kind, shim outlet_kind_to_mcp deleted) => no spelling drift by type. Only capitalized literal left = negative test.
- OBSERVATION (non-exploitable, DiD): A3 sibling-merge loop (translator.rs:555) could overwrite just-set isError/content/_meta -- but scp_to_mcp input is trusted-produced + A4 emits clean single-key {"error":{...}}, so not attacker-reachable. Suggest skip reserved keys.
- Tests green: 18 integration (translator.rs) + unit suite + 5 doctests, 0 failed.
