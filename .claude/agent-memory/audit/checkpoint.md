# Audit checkpoint — defect-class sweep
Scope: six defect classes (placeholder/fake data; FFI/SDK exposure gaps; stubs/no-op/echo; vacuous tests; dead scaffolding; stale enforcement).
Repo: /home/user/scp  (NOTE: skill paths reference /Users/alec — ignore; use /home/user/scp). Use GitHub MCP tools, NOT gh CLI.

## Already filed THIS session (not duplicates to re-file)
#1829 P1 bridge tool registration fake operator_did/zeroed implementation_hash (CLASS 1)
#1830 P2 three cfg(any()) disabled integration suites (CLASS 5)
#1831 P2 uniffi e2e_bridge vacuous let _ = result tests (CLASS 4)
#1832 chore dead Placeholder command variants in prod enums (CLASS 5)
#1833 chore prune/de-stale enforcement apparatus (CLASS 6)

## Class 1 sweep result: only #1829 was real; event_log [0u8;32] hits benign (cfg(test) + resize-pad overwritten). dns_provider placeholder = doc example.

## Pre-existing open issues already covering these classes (DEDUP against these):
#1338 MCP ContextProvider 7/7 stubbed; #1016 WASM tool_invoke echo mode; #1344 Swift MCP not wired;
#1340 SSE MCP not impl NAPI/UniFFI; #1341 MCP resource subs no-ops; #1244 trust L4/sybil not exposed any bridge;
#1491 storage built not exposed FFI; #1492 offline recovery not wired FFI; #1339 NoOp UCAN validators broadcast;
#1347 NAPI credential lifecycle 16 fns missing; #1182 media WASM stub; #1174 tool interface WASM gaps;
#1345 provenance privacy fns not in SDK; #1244; #1258 query_trust_event_counts hardcoded (0,0);
#1256 python _ReceiveIterator hardcodes seq=0; #1422 epoch/seq always 0 in sender key AAD;
#1232 TS broadcastUnsubscribe vacuous test; #1014 NAPI event_log_query no verify; #1694 check_ready_coverage substring->AST.
