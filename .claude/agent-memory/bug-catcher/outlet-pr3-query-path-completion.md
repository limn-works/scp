---
name: outlet-pr3-query-path-completion
description: OutletQuery-path completion (0deac4bb7) — split-capability gate NOT wired into session/MCP/cross-context role checks; Query outlets still gated on Action-class OutletCall
metadata:
  type: project
---

# feat(outlet): complete OutletQuery path (0deac4bb7, branch feat/outlet-report-pr3)

Threads `OutletKind` (Query/Action) core→3 FFI bridges→4 SDKs; adds `has_outlet_query_capability` +
`has_outlet_invocation_capability(kind)`; makes `validate_outlet_invocation_ucan` + the 3 single-shot
runtime invoke sites (invoke.rs 266/462/698) select stem (`outlet_query` vs `outlet_call`) by registered kind.

## CLEAN
- Protocol layer (outlets/mod.rs): stem dispatch correct; canonical_byte Query=0x00/Action=0x01 matches doc; Action=fail-safe default.
- 3 single-shot runtime invoke sites: kind-aware, fail-closed, order (registry.get→OutletNotFound then cap-check) is REQUIRED to know kind.
- All bridge enum mappings exact (napi NapiOutletKind, uniffi OutletKind, PyO3 extract_kind). PyO3 extract_kind: absent/None→Action (safe, stricter), unknown-string→hard ValidationError (no silent downgrade).
- Tests for the covered paths are non-trivial: invoke_outlet Query-denied-with-Call + Action-denied-with-Query (real dispatch); validate_outlet_invocation_ucan_selects_stem_by_kind mints two real tokens (outlet_call vs outlet_query) and asserts all 4 accept/reject cases.

## HIGH — split gate NOT wired into 5 secondary/session gates (fail-CLOSED, Query-only locked out)
These still hardcode `has_outlet_call_capability` regardless of kind. For a Query outlet, a member holding
ONLY OutletQuery/OutletQueryAll (the §5.4.2-intended Query cap) is DENIED; and the "independent stems"
defense-in-depth guarantee is not enforced at the role layer (an OutletCall holder passes for a Query outlet).
Direction is fail-closed (no priv-escalation to Action; Action still needs OutletCall) but the shipped
"complete OutletQuery path" does NOT work through:
1. scp-runtime/.../outlets/session.rs:356 — `invoke_session` (public scp-core API, re-exported lib.rs:134)
2. scp-ffi/src/outlets.rs:1480 — PyO3 session invoke defense-in-depth (runs AFTER kind-aware validate_outlet_ucan)
3. scp-ffi/src/outlets.rs:924 — PyO3 cross-context invoke, SOURCE-context check (kind read from target; subtler)
4. scp-ffi/src/mcp.rs:799 — PyO3 McpFfiBridgeProvider::validate_capability defense-in-depth
5. scp-ffi/uniffi/src/bridge.rs:4706 — UniFFI McpUniFfiBridgeProvider::validate_capability defense-in-depth
FIX: replace with `has_outlet_invocation_capability(role_state, did, id, kind)` (helper added in THIS commit
at invoke.rs:1160). session.rs reads registry.get(&outlet_id).kind; FFI sites already fetch outlet_kind_for_ucan
for the UCAN gate — reuse it. napi has NO stale role check (UCAN-only). Main single-shot FFI invoke paths are fine.
UNTESTED: new tests cover only invoke_outlet + UCAN validator + role helper; none exercise session/MCP/cross-context with a Query outlet, so suite passes trivially over the gap.

## LOW — stale doc comments
- scp-ffi/src/outlets.rs:1403 (session invoke doc) still "Must contain outlet_call:{outlet_id}".
- uniffi bridge.rs:4586 comment "grants outlet_call:{outlet_name} or outlet_call:*".
