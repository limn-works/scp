---
name: outlet-pr3-reconcile-7512e2159
description: Outlet Query/Call authz migration PR-3 artifact-flow review @ feat/outlet-report-pr3 tip 7512e2159 — §08 DSL, §06 saga, §7.3.8 caveats, Call/Query semantics, PRD. SHIP w/ 1 MOD spec finding.
metadata:
  type: project
---

# Outlet PR-3 authz migration reconcile @ `7512e2159` (feat/outlet-report-pr3, 2026-07-10) — SHIP, 1 MODERATE spec finding (§7.3.8 missing deferral marker), 1 LOW (§8.5.1 MCP projection not ported)

Successor to [[outlet_pr3_capability_query_call_migration.md]] (b4e97ff50). Tip adds 3 commits: f6fd5705a (materialize §7.3.8 origin_kind on minted/delegated caps), 4af0af916 (dedup capability-check helper + OutletQuery ceiling symmetry + §08 DSL consistency), 7512e2159 (§06 saga struct/field drift fix — RESOLVES prior MODERATE finding).

**Why:** independent artifact-flow verification of the 5-item outlet authz migration at current state.
**How to apply:** the CaveatCounterStore §7.3.8 gap is the one thing to insist on before merge; everything else is aligned.

## BRANCH TOPOLOGY (load-bearing gotcha)
`origin/feat/outlet-redesign` is NOT an ancestor — it is a PARALLEL sibling reference impl. merge-base = `e1d4beaba`; both branches ~240-252 commits past it. outlet-redesign is the DECIDED END-STATE (fully implements CaveatCounterStore across scp-runtime+4 FFI bridges, has `.docs/prds/outlet.json` tracking SCP-OUT-021..039). PR-3 (`feat/outlet-report-pr3`) is a SLICE: lands specs + protocol types + partial code; has NO outlet.json (only main.json). SCP-OUT-NNN are FEATURE-LOCAL story ids (on outlet-redesign's outlet.json), NOT in main.json; in PR-3 code they appear only as TEST-COMMENT labels (caveats.rs:4188 "SCP-OUT-021").

## ITEM 1 — §08 DSL migration: ALIGNED (0 findings)
Parser `CapabilityEntry::to_capabilities` (app_sandbox.rs:141): `outlets/{id}`+`invoke`→`OutletCall(id)` (line 154-155); `outlets` category+`invoke`→`OutletCallAll` (line 164). §08 table (line 100), prose, JSON example (line 79-80) all say `outlets/{outlet_id}` action `invoke`. THREE-WAY MUTUALLY CONSISTENT, no third form. Matches reference CODE form (ref app_sandbox already uses `outlets/`→OutletCall). NUANCE: reference §08 SPEC still says `tools/{tool_id}` (LAGGING) — PR-3 brought §08 spec FORWARD to the reference's decided code end-state → legit spec-follows-decided-design, artifact-flow preserved. WIRE-VERB `"invoke"` kept while cap=OutletCall: ACCEPTABLE (matches reference; `invoke` is the DSL action verb, kind comes from the outlets/ path + registration OutletKind; not a coherence problem).

## ITEM 2 — §06 saga-envelope fix: ALIGNED (0 findings) — RESOLVES prior b4e97ff50 MODERATE
7512e2159 migrated §06 struct/field names to match code EXACTLY. Verified: `CrossContextOutletReceipt` ✓, `outlet_registration_id` ✓, `outlet_invoked_event_id` ✓ (match cross_context_saga.rs:129/143/148). `CrossContextOutletInvoke` envelope, `CrossContextOutletInvocationPrepared`, `CrossContextDivergenceMarker` all consistent. Signature preimage field order + VarBytes(outlet_registration_id)+VarBytes(outlet_invoked_event_id) match. Grep for stale `CrossContextToolReceipt`/`tool_registration_id`/`tool_invoked_event_id` across ALL .docs/ = NONE (clean). EVENT taxonomy `ToolInvoked`/`CrossContextToolInvoked` DELIBERATELY PRESERVED in both code (cross_context_saga.rs:73/75/147; consequence.rs; summary.rs) and spec (§06 uses them as event-log record types throughout; phase-2.md:785/975; DEFERRED-commit-11:112). Struct=Outlet, event=Tool — correct split (tags 76/77 hash-load-bearing per prior memory).

## ITEM 3 — §7.3.8 CaveatCounterStore: MODERATE (fix SPEC — add deferral marker). Phantom-provenance RISK, mitigated by decided-design.
§7.3.8 (newly authored this branch — absent at merge-base e1d4beaba; present on reference) describes post-input runtime enforcement + `CaveatCounterStore` in UNQUALIFIED NORMATIVE PRESENT TENSE (line 918-925: "the runtime checks... consults CaveatCounterStore"; "The counter store is durable"). BUT on THIS branch: (a) `CaveatCounterStore` does NOT exist anywhere in code; (b) `check_invocation_local` (caveats.rs:807, the STATELESS post-input checks: input_schema/amount_max_per_call/allowed_adapters/allowed_target_dids) EXISTS + tested (SCP-OUT-021) but has ZERO non-test callers (unwired into invoke_outlet); (c) code comment caveats.rs:793 references `enforce_caveat_invocation` glue that DOES NOT EXIST on this branch. Reference branch FULLY implements CaveatCounterStore (scp-runtime + all 4 FFI bridges) → design is DECIDED, spec content is correct as end-state. THE DEFECT: §7.3.8 lacks the deferral marker that SIBLING sections use — §5.4.3 Query cache "is **deferred** (§5.4.3); every Query invocation currently executes live"; §5.15.8 length-prefix "the spec leads here, and because the standing-pair creation path is not yet wired, there is **no live divergence** to reconcile." §7.3.8's counter-store para needs the SAME "not-yet-wired / no-live-divergence" annotation. Fix = artifact (add marker), NOT code. Verdict: legit spec-leads-code, but MUST annotate to avoid phantom provenance.

## ITEM 4 — Call/Query semantics: ALIGNED (0 findings)
(a) roles.rs double-grant: admin/member/moderator/author all get BOTH OutletQueryAll+OutletCallAll (builtin_member:1372, builtin_moderator:1396, builtin_author:1436); observer(1415)/subscriber(1453) get NEITHER (MessagesRead only). (b) Query-never-billed STRUCTURAL: PaidActionType has `OutletCall`→per_outlet_call (policy.rs:345) but NO OutletQuery variant → Query has no billable action type. Matches §5.4.2 line 154/259 "Query outlets: amount==0" structural floor + QueryCostViolation. (c) Ceiling symmetry DISJOINT: app_sandbox.rs:776-794 — OutletCallAll covers only OutletCall(id), OutletQueryAll covers only OutletQuery(id), no cross-family; mirrors CapabilityCeiling::contains (roles.rs:722-735) — single semantics two enforcement sites consistent. §5.3.1 line 105 spec "outlet:query:* does NOT grant outlet:call:* and vice versa". origin_kind narrow() enforcement REAL (caveats.rs: OriginKindUnspecified/OriginKindMismatch, SCP-OUT-019).

## ITEM 5 — PRD: ALIGNED. validate-prd PASS (13 files, 370 stories). No caveat-counter story in main.json (tracked in reference outlet.json, feature-local).

## LOW — §8.5.1 MCP boundary not ported
Reference §08 has §8.5.1 "MCP ↔ SCP Boundary Translation" (26 lines: query./call. Kind projection §5.4.2, streaming/error projection) — ABSENT from PR-3 §08 (184 vs ref 211 lines). PR-3 scp-mcp crate has NO query./call. kind projection (grep empty). INTERNALLY CONSISTENT (PR-3 §08 no §8.5.1 ↔ PR-3 scp-mcp no projection); reference is simply AHEAD on the MCP-projection slice. Out of PR-3's declared scope (DSL-path migration). Flag as observation, not a PR-3 misalignment.

## GATES: bridge-symmetry 0 findings, sdk-coverage PASS, validate-prd PASS, cargo check scp-protocol+scp-runtime GREEN.

## VERDICT: SHIP (artifact-flow grounds) with 1 spec edit — add §7.3.8 CaveatCounterStore "not-yet-wired/no-live-divergence" deferral marker matching §5.4.3/§5.15.8 convention. All struct/field/event drift resolved; Call/Query model fully coherent; DSL three-way consistent. Spec-leads-code is legit here (reference proves decided design) provided the deferral is annotated.
