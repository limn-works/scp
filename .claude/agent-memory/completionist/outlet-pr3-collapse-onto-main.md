---
name: outlet-pr3-collapse-onto-main
description: Outlet re-port PR-3 collapsed/rebased onto main @2f45eefa6 — layers COMPLETE, one phantom-provenance spec finding (§5.4.4 Outlet Error Taxonomy never written)
metadata:
  type: project
---

Review of `feat/outlet-report-pr3` @ `2f45eefa6` (worktree scp-wt-outlet-pr3), the
collapse/rebase of the outlet re-port onto NEW main (descendant of origin/main;
merge-base 0f26442ac). Supersedes my FINAL SIGN-OFF @baeebdd92 (which was on the
pre-rebase outlet-redesign lineage, not on current main).

**Collapse commit (2f45eefa6) is clean & mechanical** — reconciles main's 3 new API
shapes: (1) `ValidationContext` gained a `caveat_resolver` field ⇒ 7 broadcast test
sites + prod `handle_subscribe_broadcast` (broadcast.rs:231) set `&NoCaveatResolver`
(semantically correct: subscribe is not an outlet-invoke path; origin_kind caveats only
apply to outlet-call, and value-caveat enforcement is deferred, so NoCaveatResolver is
the consistent non-outlet choice — outlet-invoke paths use TokenNbCaveatResolver:
outlets/invoke.rs:1860, saga.rs:1226, ffi outlets.rs/mcp.rs). (2) `UcanPayload` gained
`nb` ⇒ `nb: None` added. (3) `Capability::new` became fallible ⇒ `.expect("known
capability")` on 3 persistence_ordering.rs sites. Full-feature workspace build = exit 0.
check-sdk-coverage.py PASS (0 err), check-error-codes.sh PASS (2785 codes).

**Layers COMPLETE (all confirmed against code):** enum roles.rs:81-88
OutletQuery/QueryAll/Call/CallAll + dual-form parser (outlet:query: & outlet_query:) +
symmetric Display; 4 SDK constructor helpers present (py outlet_query/outlet_call
types.py:256/268; ts outletQuery/outletCall types.ts:58/69 exported index.ts:304-305;
swift Types.swift:136/144 + outletQueryAll/CallAll consts; kt Types.kt:70/78). Matrix
domain label stays "Tools" with outlet-prefixed method aliases (check-sdk-coverage.py
ALIASES tool*→outlet* rename, all 4 SDKs — legit, cap-as-string adds no bridge op).
Enforcement changes ADDITIVE only: check-error-codes.sh adds same-line `SCP-CODE-OK:`
marker (no whole-file exemption); ffi-export-allowlist.json pure tools→outlets rename
(no new exemptions). Event wire-names PRESERVED: EventType::ToolInvoked tag=11,
CrossContextToolInvoked tag=76 (scp-event-log untouched); SCP-TOOL- error prefix
(6000-6999, sdk-common.md:38) preserved as wire-stable. No stubs/todo! in outlet code;
`let _ =` in stream.rs:1440 is documented forward-compat signature-stability (const fn),
1644-1646 are deferred-streaming-slice test constructions (AC-6 variants-exist) — not
theater.

**CONFIRMED FINDING — phantom provenance (artifact divergence, spec side wrong per
one-way flow):** `crates/scp-protocol/src/context/outlets/error_codes.rs` module doc +
16 inline `SCP-CODE-OK: §5.4.4 registry constant` markers cite **spec "§5.4.4 (Outlet
Error Taxonomy)"** and **ADR-049 §4** as the mandating authority for the SCP-TOOL-6100..
6199 compact code registry (14 `pub const CODE_*` + 42-entry slug_to_class table, FULLY
implemented & shipping). `grep -rn "5\.4\.4" .docs/` = EMPTY (airtight); spec 05 headers
jump §5.4.3 (Query Cache, line 291) → §5.5.1 (line 313); no ADR defines the SCP-TOOL-61xx
registry (only ADR-049 §91 defines the DISTINCT SCP-SAGA-* range). NOT collapse-induced
(present identically at baeebdd92 — my prior FINAL SIGN-OFF MISSED it) and NOT one of the
acknowledged deferrals (value-caveat/streaming/cross-context). The error-CLASS *names*
(OutletErrorClass::Protocol::QueryCostViolation etc.) ARE specced in prose (05 §5.4.2, 07
§7.3.x) and individual codes (SCP-TOOL-6114) cited in spec 07 — so the semantic taxonomy
is partially grounded — but the §5.4.4 *section itself* and the compact-code-registry
design it "mandates" were never authored. Fix per one-way flow: write spec §5.4.4 (and/or
correct the ADR §ref) BEFORE the code that cites it, or correct the citations to the real
governing sections. Secondary/lower: stream.rs:1428 cites "§5.4.5 contract" also absent —
but streaming is acknowledged-deferred, so its dangling spec ref is expected until the
streaming slice lands.

Pre-existing NON-gap (matches prior signoff): 25-test-vectors.md:375 AppBoundPayload
capabilities:["tool:invoke:*"] — opaque hash-pinned Vec<String>, not parsed through
Capability::new, introduced pre-PR-3, untouched.

LESSON: a fully-implemented, mechanically-gated (SCP-CODE-OK exemption markers) error-code
registry can carry a *load-bearing citation to a spec section that was never written* —
the exemption marker's REASON text ("§5.4.4 registry constant") reads as provenance but
governs nothing. When code cites a specific spec §for an exemption, grep that exact §into
.docs; a numbered section that headers skip (5.4.3 → 5.5.1) is the tell. Capability-model
axes passing does NOT clear the error-taxonomy sub-artifact.
