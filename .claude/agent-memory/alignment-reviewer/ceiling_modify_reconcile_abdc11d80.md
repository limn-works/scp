---
name: ceiling-modify-reconcile-abdc11d80
description: Review of branch fix/ceiling-modify-reconcile (HEAD abdc11d80) — spec §5.3.2 step 5 + §7.2.2 eager ceiling-change cache reconciliation; verdict ALIGNED
metadata:
  type: project
---

# Eager Ceiling-Change Cache Reconciliation @ `abdc11d80` (2026-06-26) — ALIGNED

Branch `fix/ceiling-modify-reconcile` vs `origin/main`. Two spec edits + matching code:
- §5.3.2 step 5 (`05-contexts.md:132`): replaced lazy "SDK MUST re-validate cached UCANs on next action attempt" → normative EAGER reconciliation at ceiling-change activation.
- §7.2.2 (`07-trust-validation-and-capabilities.md`): added "Reconciled atomically on ceiling change" bullet; moved the bolded "no window where stale capabilities are served" guarantee onto the WRITE-TIME invariant.

**Why ALIGNED (0 blocking/material, 1 informational):**
- Legitimate spec-first correction — resolved a REAL internal contradiction: §7.2.2 "no window" was unsatisfiable under old lazy step 5. Not code-reshaping-spec.
- Code conforms: `crates/scp-protocol/src/context/roles.rs` `set_ceiling` (~1838: validate_entries → store → reconcile_to_ceiling) + `reconcile_to_ceiling` (~1873: intersect role_definitions[*].capabilities, member_capabilities[*], suspended_capabilities[*] with ceiling; SHRINK-ONLY + idempotent → preserves ADR-050/§23.16.8 export digest).
- Sound permanent invariant (no DOA): gate `member_has_capability` (~1664 doc) deliberately does NOT re-intersect at read time — write-time ceiling-bounding is the closed population set (mint-from-ceiling on role assign + eager prune on lowering + creator-signed import). A use-time re-check would be the redundant weaker re-check the over-engineering guard warns against.
- Single chokepoint: both native `apply_pending_ceiling_modification` (`governance_helpers.rs:489`) and WASM `dispatch_modify_ceiling` route through `set_ceiling`.
- Resolves the historical HIGH at `.docs/audits/adr-audit-phase-1-3.md:223` (ADR-009 immutable-ceiling vs ADR-008 Governed, mint-under-one-ceiling/validate-under-another race). ADR text already reconciled at `phase-2.md:305,310`.

**Completeness grep clean:** only old-behavior occurrence is the replaced line. `phase-2.md:313` ("next action fails") is about REVOCATION not ceiling-change — correctly unchanged. Cross-node re-presentation still guarded by §7.2.1 step 8 (signed lowered ceiling).

**INFORMATIONAL (optional, not flow violation):** ADR-016 two-tier narrative `phase-3.md:682` says cache "updated atomically on role change" but omits ceiling-change reconciliation; could mirror enriched §7.2.2. ADR=rationale, spec=normative — not contradictory.

GOTCHA: spec text enumerates 2 caches (role defs + member_capabilities) but code prunes a 3rd (suspended_capabilities) — that prune is cosmetic/digest-hygiene only (suspended-out-of-ceiling cap denied regardless), correct to omit at protocol altitude.
