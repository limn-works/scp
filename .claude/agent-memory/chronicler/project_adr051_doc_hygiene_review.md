---
name: project-adr051-doc-hygiene-review
description: ADR-051 causal-DAG doc-hygiene review status — ALL prior findings (§5 collision, §9.8.5, §23.16.4) RESOLVED; round 2026-06-19 = APPROVE
metadata:
  type: project
---

ADR-051 (causal-DAG application-event ordering + receiver-quorum median clock) doc-hygiene reviews.

**Round 2026-06-19 (later pass) = APPROVE — all prior nits resolved.** §23.16.4→§23.16.8 anchor FIXED: Related (line 9) + body (line 88) now both cite §23.16.8 (Signed Context Export), the correct heading for "per-instance state wiped on import" (17-persistence:338 confirms). No stray §23.16.4. node-cut/C02 reframe clean: grep "node" hits ONLY line 101 REJECTED four-vantage entry; "multi-vantage"=none; `max(`/clamp = line 101 rejected upward clamp + lines 73/113/114 retained `max(sender,relay-ingest)` consistency FLOOR (distinct, legitimately kept). Lift-list (line 125) includes §9.8.5. `anchored` field realized in ParticipationProfile.tool_invocation_count_anchored (spec 07) + PaymentReceipt.anchored (spec 19). C01/C03/C05 coherent. Taxonomy 75 (Vector 32:363; phase-2 enum = 75 variants exactly). No #NNNN in ADR or added spec lines.

**Round 2026-06-18 (CHANGES-NEEDED) — both findings now RESOLVED in round 2026-06-19:**

1. **`§5` token collision — RESOLVED.** The spec-§5 occurrence (line 19, "beacon/heartbeat commits break zero-idle-cost") now reads "(§5 contexts; ...)" — the word "contexts" disambiguates it from the four ADR-internal §5 references (lines 29 "over a frontier", 71 "closure rule as §5", 106 heading, 108 "deterministic predicate"), which are all in clear ADR-structural phrasing. Acceptable.

2. **§9.8.5 amended-but-claimed — RESOLVED.** §9.8.5 (Sequence Validation, `09-security-model.md:746`) WAS amended this round: now says the SCP seq "is included in the envelope. For application messages it is no longer a Merkle event-log entry... DAG leaf carries causal head-references in place of a committer sequence." This makes ADR-051 line 23 (claims §9.8.3 AND §9.8.5 amended) TRUE and consistent with line 120 lift-list (includes §9.8.5). Internal contradiction gone. §9.8.3 also amended (09-security:728/732).

**Residual nit (minor, MENTION not blocker):** ADR-051 Related-list (line 9) glosses `§23.16.4` as "anti-spam state **wiped on import** — velocity is local". §23.16.4 is the `ContextSnapshot` *structure* (sync-delta type, `23-sync:363`); the anti-spam tracker FIELDS do live in that structure (so body line 84 "§23.16.4 local anti-spam state" is defensible), but the "wiped/sanitized on import" BEHAVIOR is specified in §23.16.8 (`23-sync:494`), not §23.16.4. The Related gloss conflates structure-location with import-behavior; correct citation for "wiped on import" is §23.16.8. Section number resolves to a real section, just not the one matching the gloss.

**Verified clean (round 2026-06-19):** taxonomy 75-variant consistent (25-test-vectors:363; no `76-variant` anywhere). No `#NNNN` introduced in ADR-051 (zero) or in the changed lines of phase-2/specs (pre-existing #586/#269/#290/#352/#346 are in untouched lines). All Related/body section refs resolve: §9.3, §9.8.3, §9.8.5, §9.9.2, §9.9.3, §23.16.1, §23.16.4, §23.16.6, §23.16.8, §7.3.2, §7.3.7, §19.7. Stale-prose grep (member-median/median-of-member/small-context floor) yields ONLY the explicit negations (ADR lines 96, 108). All five staging qualifications (messages §9.8.3/§9.8.5, payments §19.6, tool-count §7.3.2, velocity §7.3.7/§19.7, frontier §9.9.3) have a home + lift-condition (lift-list ADR line 120). Header matches ADR-050 house style (Status/Date/Phase/Related separate lines); ADR-051's parenthetical Status is a benign extension.
