---
name: outlet-pr3-collapsed-report-2f45eefa6
description: Final double-zero alignment review of the collapsed outlet re-port landing on main (feat/outlet-report-pr3 @ 2f45eefa6) — ALIGNED, 1 LOW doc-drift finding
metadata:
  type: project
---

# Outlet re-port PR-3 collapsed / final @ 2f45eefa6 (feat/outlet-report-pr3, base 0f26442ac, 2026-07-10)

Successor tip to the 1ffe476e5 / 7512e2159 / b4e97ff50 reviews (see sibling memory entries). Branch was REBASED onto new main; tip commit `2f45eefa6` = pure mechanical rebase integration (broadcast mod.rs + broadcast handler + persistence_ordering test — reconciles main's new ValidationContext/UcanPayload/Capability::new sites with outlet APIs). NO spec files in the rebase commit → no smuggling there.

**Why:** final gate before PR merge to main.
**How to apply:** all prior-round findings re-verified RESOLVED and surviving the rebase; treat as ALIGNED. One LOW carryover.

## Re-verified aligned on this tip (post-rebase)
- §7.3.8 deferral markers INTACT (07-trust:918/923/925): 4-point enforcement, 7b/7c/11b LIVE (origin_kind family), value-caveat + CaveatCounterStore DEFERRED with "spec leads"/"no live divergence"/"not yet wired" convention (matches §5.4.3/§5.15.8). Code-grounded: CaveatCounterStore absent (only a doc-comment mention caveats.rs:791); check_invocation_local defined caveats.rs:811 with ZERO non-test callers; mint origin_kind-only CONFIRMED (mint.rs build_root_caveats returns None after mixed-family gate; build_delegated_caveats materializes ONLY origin_kind via `..parent_effective`, root parent effective=empty()).
- §06 receipt reconciliation held: CrossContextOutletReceipt / outlet_registration_id / outlet_invoked_event_id throughout 06-cross-context-communication.md; EventType ToolInvoked/CrossContextToolInvoked CORRECTLY RETAINED as wire/Merkle event records (ADR-011) at §06:265/287/300 — struct=Outlet, event=Tool split preserved exactly as intended.
- §5.4.2 query-cost / Query-never-billed / §5.4.2.1 parser (colon-in-suffix reject) all present + code-consistent; §5.4.5 attenuation + §6.2.0.2 present.
- Enforcement artifacts CORRECT: bridge-aliases.json:423 → outlet_invoke_cross_context_saga; sdk-capability-matrix.json:603 names outlet_invoke_cross_context_saga + Supervisor::start_cross_context_outlet_invocation_saga (matches code supervisor.rs:5588, uniffi bridge.rs:13236, napi scp.rs:3025, scp-ffi/src/outlets.rs:1957).
- validate-prd PASS 13/370.

## THE ONE FINDING (LOW, doc-only, artifact-reconciliation incompleteness)
DEFERRED-commit-11-saga-use-cases.md is IN the diff and was PARTIALLY migrated (line 128 renamed start_cross_context_tool_invocation_saga→outlet), but still names PRE-RENAME MACHINE METHOD IDENTIFIERS that no longer exist:
- Line 224: public FFI method `tool_invoke_cross_context_saga` (actual: outlet_invoke_cross_context_saga)
- Line 226: internal `start_cross_context_tool_invocation_saga` (actual: start_cross_context_outlet_invocation_saga)
- Lines 250/270: same two names but under "frozen definition-of-done, retained verbatim" blockquote → defensible as intentionally frozen.
- Line 103: internal name in a "RESOLVED 2026-06-26 ... historical provenance only" blockquote → borderline/dated snapshot.
Strongest sub-point = 224/226: they are the present-tense "**Status (resolved).**" paragraph (NOT verbatim/historical-marked) describing the CURRENT shipped surface with method names that don't exist = phantom provenance; contradicts the authoritative sdk-capability-matrix.json which is correct. Fix = rename these method identifiers to the outlet spelling.
RELATED (OUT OF DIFF): ADR-049-actor-per-context.md:66,95 also name start_cross_context_tool_invocation_saga — file untouched by branch, so pre-existing; but the branch renamed the code symbol they reference, so a corpus-wide sweep is warranted.
NAMING SPLIT (deliberate, do not over-flag): human/use-case name "cross-context tool invocation" + event records ToolInvoked/CrossContextToolInvoked STAY; machine identifiers (capabilities outlet:call/query/interface, structs CrossContextOutlet*, FFI/supervisor METHODS) migrate to outlet. §6.2.0.2 heading "Tool Interface Rate Limit Defaults" + "tool-session reservation" prose sit on the human-prose side → left as an OBSERVATION, not a hard finding.

VERDICT: ALIGNED (1 LOW doc-drift; not merge-blocking).
