---
name: outlet-report-pr1-inert-rename-audit
description: Adversarial audit of PR-1 tool→outlet rename (branch feat/outlet-report). Verdict INERT with 3 wire-format changes that are intended-in-scope + 3 cosmetic findings.
metadata:
  type: project
---

# PR-1 outlet re-port (feat/outlet-report) — "inert rename" claim: VERIFIED INERT

**Why:** Claimed pure mechanical tool→outlet rename across 174 files / 6000+ sites, 6 coder agents. Task: prove it's NOT inert.
**How to apply:** If this PR resurfaces or a follow-on rename PR lands, these are the load-bearing checks + the known non-inert-but-intended wire changes.

## Method that worked
- Per-file multiset canonicalization: substitute Outlet→Tool on both `-`/`+` sides, strip whitespace, multiset-diff. Pure rename → residual removed=0. Any residual removed>0 = candidate real change. Then whitespace-insensitive logical-blob compare to clear reflow.
- ALL residuals traced to formatter reflow (rustfmt 100-col wrap on longer `outlet_` idents, biome/ruff trailing commas) or **import-list re-sorting** (rustfmt alphabetizes `use`; outlet sorts differently than tool). Zero arg-order swaps in CALLS, zero flipped booleans, zero changed values.

## Wire-format changes — REAL but INTENDED (pre-release, no deployed peers)
1. `ToolErrorCode::ToolNotFound`→`OutletErrorCode::OutletNotFound` (lifecycle.rs). Enum derives Serialize/Deserialize, NO #[serde(rename)] → wire tag changes "ToolNotFound"→"OutletNotFound" + Display string. In-scope per rename claim.
2. `OutletInvokedEvent` field `tool_id`→`outlet_id`. Struct IS serialized via serde_json::to_vec into event-log Merkle leaf (mcp.rs:1026 → append_unsigned_event). So the hashed preimage changes. `EventType::ToolInvoked` discriminant + tree tag `=>11` UNCHANGED (wire event-type preserved).
3. `CrossContextOutletReceipt` (cross_context_saga.rs) — SIGNED struct (serde_signature_64). Fields tool_registration_id→outlet_registration_id, tool_invoked_event_id→outlet_invoked_event_id. Signed preimage changes. BOTH Receipt AND ReceiptFields renamed consistently (no self-mismatch bug). No stray #[serde(rename="tool_")] left that would've preserved old wire.

## DO-NOT-RENAME set — ALL PRESERVED (verified byte/count identical origin vs HEAD)
- Capability::ToolInvoke/ToolRegister/ToolInvokeAll; UCAN wire `tool_invoke:` prefix (format!("tool_invoke:{TOOL}") byte-identical; TOOL="calculator-v1" test const kept)
- GovernanceAction RegisterTool/RemoveTool/EstablishToolInterface (33/14/33 both sides)
- EventType::ToolInvoked (51/51), "ToolInvoked" literal (10/10), tree tag =>11
- SCP error codes: distinct set 603==603, empty symmetric diff (no code renamed/dropped)
- MCP surface tools/call (46/46), mcp_client_list_tools (36/36)
- #[serde(rename="scp:template/tool-interface")] params.rs — KEPT
- roles.rs NOT in diff. NO serde container attr (rename_all/tag/untagged/skip/repr) changed anywhere.

## Cosmetic findings (non-blocking, worth a cleanup pass)
- check-sdk-coverage.py (ENFORCEMENT FILE): not pure rename — Kotlin/Swift alias lists WIDENED 1→2 (["invoke","outletInvoke"]). Defensible: both names really exist (Scp.outletInvoke + CoroutineBridge bare invoke), but dict KEYS still "Tools" while values "outlet". Loosening an enforcement assertion nominally needs human approval per CLAUDE.md.
- Doc placeholder inconsistency: 5 `tool_invoke:{tool_id}` still in HEAD vs 2 changed to {outlet_id}/{outlet_name}. Wire prefix correct everywhere; only metavar naming inconsistent.
- outlets_helpers.rs module doc still says "Tools helpers ... `tools` domain" (stale comment).
- ffi-export-allowlist.json `new` reason changed "PyScp constructor"→"OutletRegistration result-type constructor" (a correction, path moved tools.rs→outlets.rs).

## PR-1 rebase-conflict resolution audit (saga.rs, HEAD 5e4353904, 2026-07-10)
Conflict file: crates/scp-runtime/src/context/actor/handlers/saga.rs (main added newer behavior; PR-1 renamed older). VERDICT: CLEAN — rename+fmt only, behavior-preserving.
- Decisive method (reusable): collapse `tool` AND `outlet` (case-insensitive) to one token in BOTH origin/main and HEAD via `perl -pe 's/outlet/XX/gi; s/tool/XX/gi'`, then `diff`. Only survivors were rustfmt line-wraps (longer idents exceed width) + import reordering (Outlet sorts differently than Tool). ZERO control-flow/call/error-path/persist/statement diffs across the WHOLE file (covers auto-merged hunks, not just hand-edited regions).
- Region A `persist_state_best_effort` (partial-increment landing in prepare_a): 3 call sites identical modulo rename. Preserved.
- Region B `commit_a` `class_c_economy_reversed` binding + ADR-049 §Decision-9/N1 `ok_mutated` branch: byte-identical modulo rename. Preserved.
- All renamed targets exist: `cargo check -p scp-runtime --tests --features testing` clean (0 errors). settle_outlet_economy (NOT _capture), OutletInterface/OutletRegistration/OutletSchema, CrossContextOutletReceipt(Fields), CommittedOutletInvocation, SagaPreparedState::CrossContextOutletInvocation all resolve.
