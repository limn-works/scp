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

## FINAL — issues filed (audit phase)
#1834 P2/major  Three cross-context sagas return NotImplemented (spec landed, code didn't) [class 3]
#1835 P1/major  check-handler-no-panic.sh broken — false-positives 5 test panics, FAILS on main (CI gate) [class 6]
#1836 P2/mod    Vacuous tests cluster: Python ~39, Kotlin SmokeTest, NAPI transport.rs:763 [class 4]
#1837 P2/mod    check-sdk-coverage.py stale alias table — ~20 'true' cells degrade to non-failing warnings [class 6]
#1838 P3/low    Stale provenance/diagnostic metadata (capability-matrix notes, falsy-optionals ptr, NETWORK allowlist) [class 6]
#1839 P1/major  send_heartbeat not exposed by any bridge/SDK — §9.9.2 suppression detection non-functional [class 2]
#1840 P2/mod    Capability matrix integrity: wrong exemptions (import_context, verify_attestation), missing export_context row [class 2]

## Punch-list issues filed earlier this session
#1829 P1 fake operator_did/zeroed implementation_hash (class 1) | #1830 cfg(any) disabled suites (class 5)
#1831 uniffi e2e vacuous (class 4) | #1832 dead Placeholder variants (class 5) | #1833 enforcement prune (class 6)

## Still scanning (may append to #1836): Rust-crate inline vacuous tests (protocol/identity/transport, ffi/node/core src).
## Adversarial validation: each finding verified at source; HIGH panic-gate finding re-verified by running the script (EXIT=1, wired in ci.yml:295).
