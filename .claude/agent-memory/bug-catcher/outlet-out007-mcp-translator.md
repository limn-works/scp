---
name: outlet-out007-mcp-translator
description: SCP-OUT-007 MCP↔SCP lexical translator (scp-mcp/src/translator.rs) — arguments-payload corruption + client re-prefix mismatch
metadata:
  type: project
---

# SCP-OUT-007 MCP translator re-port (branch fix/outlet-recover-007-mcp @f23ed4923)

HIGH (latent, would be CRITICAL once wired): `mcp_to_scp`/`scp_to_mcp` recurse
structural shape-detection into OPAQUE user payload (tool `arguments`, `_meta`).
Any nested object with a string `"name"` and no inputSchema/content/tools/outlets
sibling matches `looks_like_tool_call_params` (translator.rs:936-947) and is
rewritten to `{outlet_id,kind:"Action"}` — e.g. arg `{"name":"Alice","age":30}`
→ `{"outlet_id":"Alice","kind":"Action","age":30}`. Same for args containing
`content`[]→chunks, `outlets`[], `chunks`[], `outlet_id`, single-key `error`→CallToolResult.
Root cause: args recursed via translate_*_value at translator.rs:312-314 (mcp→scp)
and :568-569 (scp→mcp). Fix: DO NOT translate arguments/_meta payload — pass verbatim.
Tests pass because corpus args only use safe keys (amount/q/{}). **Why:** arguments
are arbitrary user JSON; a "name" field is extremely common. Currently NOT call-wired
in prod (only format_/parse_mcp_tool_name are wired in server.rs/client.rs) but
lib.rs docstrings + PRD claim mcp_to_scp/scp_to_mcp are the client inbound/outbound
wiring → bites on wiring.

MEDIUM: client.rs list_outlets→invoke_outlet doesn't round-trip for generic
external MCP tools. Unprefixed external tool "get_weather" → parse→(Action,"get_weather")
→ invoke_outlet re-adds "call." → sends "call.get_weather" which the external
(non-SCP) server does not have → tool-not-found. The prefix convention only works
if the external server speaks SCP's query./call. convention (false for generic MCP).

LOW: client.rs:432-433 doc claims response "translated back via mcp_to_scp" — invoke_outlet
does NOT call it. lib.rs:23-25 same false claim (outbound scp_to_mcp / inbound mcp_to_scp
not actually invoked on payloads). server.rs:440 `let _ = outlet_kind` comment says
"Kind is recorded in the provenance path" but kind is discarded (not recorded anywhere).
translator.rs:501-503 let-chain: SCP error envelope whose `error` value is non-object
is silently emptied (remove side-effect before pattern fails) — SCP-side/malformed only.

CLEAN: name round-trip is genuinely lossless (format always prepends exactly one
prefix, parse strips exactly one matching-first; outlet_id containing "query."/"call."
or dots is safe). Server handle_tools_call path (parse_namespaced→parse_mcp_tool_name→
validate_capability/find_*_schema/invoke_outlet all on stripped outlet_id) is consistent,
no panic on untrusted input. napi context_tools returns Vec::new() (documented placeholder,
no misleading kind). bridge outlet_kind_to_mcp = pure exhaustive projection from real
registry OutletKind (not hardcoded). invoke_tool→invoke_outlet rename complete across
3 bridges + trait + sse/stdio mocks, no arg reorder, no old-name callsite left.
