---
name: outlet-pr3-capability-query-call-migration
description: Alignment review of outlet-redesign PR-3 (feat/outlet-report-pr3, a65a778c9..b4e97ff50) — ToolInvoke→OutletCall/OutletQuery capability redesign + §5.4.2 classification + §7.3.8 InvocationCaveats spec authoring + spec/ADR/PRD reconciliation. Verdict ALIGNED with 2 pre-existing inherited spec-drift findings.
metadata:
  type: project
---

# Outlet-redesign PR-3 capability Query/Call migration — ALIGNED, 2 inherited spec-drift findings

Reviewed `feat/outlet-report-pr3` range `a65a778c9..b4e97ff50` (9 commits L0-L7c + CI). Capability redesign: `ToolInvoke*` → `OutletQuery*`/`OutletCall*`; new §5.4.2 classification + §7.3.8 InvocationCaveats spec sections; 4 FFI + 4 SDK + docs/specs/ADRs/PRDs reconciliation; check-error-codes.sh `SCP-CODE-OK:` inline exemption port.

## Artifact-flow verdict: LEGITIMATE downstream reconciliation (NOT phantom provenance)
Code implements the DECIDED design (reference branch `origin/feat/outlet-redesign` has IDENTICAL capability model in roles.rs — same OutletQuery/OutletCall variants, same parser stems, same hard-reject of `outlet:invoke:`/`tool:invoke:`; and reference ALREADY contains §7.3.8 InvocationCaveats with same rules 1-4 + error slugs). Spec was LAGGING; edits describe the decided end-state. Spec→code direction preserved.

## Canonical stem model (roles.rs, ground truth)
- Enum: `OutletQuery(OutletId)`, `OutletQueryAll`, `OutletCall(OutletId)`, `OutletCallAll`, `OutletRegister`, `OutletInterface`.
- UCAN wire (canonical, underscore): `outlet_query:*`, `outlet_call:*`. Parser ALSO accepts colon form `outlet:query:*` (user-facing).
- Hard-reject (parse→None): `outlet:invoke:`/`outlet_invoke:` (deleted per ADR-049 §1/SCP-OUT-014) AND `tool:invoke:`/`tool_invoke:` (pre-rename legacy).
- Query/Call DISJOINT: OutletQueryAll does NOT cover OutletCall(id) and vice versa (roles.rs:717-720).

## §5.4.2 (newly authored) — GROUNDED, matches code
Query=read-only/idempotent/cacheable, Action=may-mutate/never-cached. Default=Action (fail-safe, code mod.rs:117). Real code enforcement: `query-cost-violation`, `query-violation`, `amplification-violation`, `kind-mismatch`, `query-misdeclaration` slugs all exist (error_codes.rs). Query structural cost floor (cost==0), ReadOnlyInvocation guard, Query→Action amplification block — all real. Query→Action forbidden, Action→Query allowed.

## §7.3.8 (newly authored) — GROUNDED, matches code + reference
InvocationCaveats struct in caveats.rs (from_bits newtypes, assert_mask_widths shared mint+narrow, SCP-TOOL-6114, CaveatCounterStore). origin_kind equality+explicit-on-non-root; validator step 7b (per-edge) + 7c (presenting-token stem consistency) in validate.rs. Rules 1/3/4 mixed-stem-root guard present. Reference cites §6.2.0.3 for amplification; PR-3 re-points to §5.4.2 (consistent — PR-3 authored §5.4.2 as amplification home).

## Focus 2 (call-vs-query semantic) — CLEAN
- Roles: every role that had ToolInvokeAll now gets BOTH OutletQueryAll+OutletCallAll (double-grant): member/moderator/author. observer/subscriber get neither (read-only). No role wrongly query-only.
- Billing: `PaidActionType::ToolInvoke`→`OutletCall` (mutating). NO `PaidActionType::OutletQuery` variant — Query never billed (§5.4.2). `per_tool_invoke`→`per_outlet_call`.
- PRD ACs migrated correctly (invoke_tool→invoke_outlet, capability strings, E2E steps show the double-grant).

## FINDING 1 (MODERATE, spec fix) — §06 saga-envelope still on `tool_*`, code on `outlet_*`
§06 (13 occurrences) names receipt TYPE `CrossContextToolReceipt` (does NOT exist in code) + fields `tool_registration_id`/`tool_invoked_event_id`. CODE (cross_context_saga.rs) = `CrossContextOutletReceipt` + `outlet_registration_id`/`outlet_invoked_event_id`. Rename landed in **PR-1** (`ae2c6f2da`), NOT this PR. PR-3 task #127 explicitly scoped "Migrate §06" — so this IS in-scope-declared but NOT fully executed (PR-3 only changed `tool:interface`→`outlet:interface` capability strings in §06, missed the struct/field renames). Also in phase-2.md ADR + DEFERRED-commit-11 ADR. Fix = SPEC (spec lags code). NUANCE: `EventType::ToolInvoked`/`CrossContextToolInvoked` are DELIBERATELY retained in code (closed 77-variant taxonomy, tag 76/77 wire+hash load-bearing) — so §06 mentioning `ToolInvoked` as an EVENT is CORRECT; only the receipt STRUCT type name + FIELD names are stale.

## FINDING 2 (LOW, consistency) — §25 Vector 32 AppBound carries `"tool:invoke:*"`
`AppBoundPayload.capabilities: Vec<String>` (payload.rs:109) is FREE-FORM app-manifest strings, NOT typed `Capability` — never parsed through `Capability::new` at event-log layer. The `"tool:invoke:*"` KAT string is opaque bytes feeding load-bearing leaf hash `0xe0c0691d...`. So the "won't desync a parser" claim is STRUCTURALLY TRUE. BUT: §08 in THIS PR migrated app-manifest vocab `tool_invoke(...)`→`outlet_call(...)`, so the vector models a manifest granting a now-deleted spelling. Also `payload.rs:437` unit test + `test_vectors.rs:385` KAT carry it. Not a correctness/desync risk (Vec<String> is uninterpreted); a consistency/example-hygiene gap. Fix (if taken) requires recomputing the leaf hash. Inherited from base (PR-3 didn't touch §25 AppBound vector).

## CLEAN / ALIGNED
- Focus 3b: `ContextParams.tools` field name CONSISTENT spec(§05)↔code(params.rs:689) — both keep `tools` (type is OutletRegistration). NOT a drift.
- Focus 5: validate-prd.py PASSES (13 files, 370 stories). Meaningful.
- check-error-codes.sh `SCP-CODE-OK:` = line-scoped exemption ported verbatim from reference (existed on feat/outlet-redesign, markers already in PR-2 fixtures); integrity probe (unmarked SCP-TOOL-9999→VIOLATION) confirmed; NOT in CLAUDE.md protected list; bounded, not a bypass.

## GOTCHAS
- Reference branch `origin/feat/outlet-redesign` has a DIFFERENT tree layout — some paths (§06 spec, cross_context_saga.rs) resolve empty via `git show origin/feat/outlet-redesign:<path>`. Use it for roles.rs + §07 comparison; it's NOT a comparator for §06 field spellings.
- The `tool→outlet` FIELD/STRUCT rename (PR-1 `ae2c6f2da`) is SEPARATE from the ToolInvoke→OutletCall CAPABILITY rename (PR-3). Don't conflate.
