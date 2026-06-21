---
name: project-adr051-causal-dag
description: ADR-051 causal-DAG application-event ordering + median clock — provenance/staging map and house-style facts
metadata:
  type: project
---

ADR-051 (`.docs/adrs/ADR-051-causal-dag-application-event-ordering.md`, Accepted 2026-06-18, Phase 6) — model decision: order application events (`MessageSent`/`ToolInvoked`/`PaymentReceived`) by a causal DAG + deterministic linearization, time them by median-of-member-receive-times. Sequenced AFTER the ADR-011 event-log-unification amendment.

**Why:** Per-author application events have no global order → honest members diverge at equal log position → false positive under §9.9.3 equivocation detection. Interim: they are excluded from the canonical Merkle log and surfaced as local `ContextEvent`s; velocity/rate consequences (§19.7), `tool_invocation_count` (§7.3.2), and velocity consequences (§7.3.7) computed locally. ADR-051 lifts all of that.

**How to apply / staging map (where each interim qualification lives):**
- ADR-011 amendment in `.docs/adrs/phase-2.md` — "Exclusion taxonomy" now 2 numbered categories: (1) local signals (permanent, never EventType: MessageReceived/EquivocationDetected/PseudonymAnnounced); (2) per-author application activity (interim, canonical under ADR-051).
- §9.9.3 (09-security-model.md) — "Convergent-log requirement" para; equal-FRONTIER (not equal-count) test for DAG leaves.
- §7.3.1/§7.3.2 (07) — leaf-hash recipe SHA-256(0x00‖rmp_serde(Event)); tool_invocation_count local until ADR-051.
- §7.3.7 (07) — "Convergent emission" para.
- §19.7 (19) — ContextMessageRate/SenderVelocity local until ADR-051.
- §25 (25-test-vectors.md) — taxonomy count corrected 76→75 (matches actual EventType enum count; verified no dup, no variant removed — the OLD 76 was an off-by-one error, not a deletion).

**House-style facts:** ADRs 046-051 are standalone `ADR-NNN-slug.md` files; ADR-001..045 live as `## ADR-NNN` inside phase-N.md. ADR-051 header uses `Related:` (matches ADR-050). All cited anchors verified to resolve (§9.9.2/§9.9.3/§7.3.2/§7.3.7/§19.7/§23.7/§23.16/§9.3/§5 zero-idle-cost). Minor anchor-precision nit: ADR cites §23.16 for "local anti-spam state" — §23.16 is "Sync Protocol Wire Formats"; the support is §23.16.4's import-wipe paragraph (local-instance anti-abuse state), adjacent but not the local-throttle's canonical home (§19.7/§7.3.7). Not a broken ref.
