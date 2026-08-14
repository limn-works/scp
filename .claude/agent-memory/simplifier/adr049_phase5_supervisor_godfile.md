---
name: adr049-phase5-supervisor-godfile
description: supervisor.rs is a 23.8K-line god-FILE with one undivided 171-method impl Supervisor — coherent ownership but unnavigable; split the impl across files (zero-cost). NOT a coupling defect.
metadata:
  type: project
---

`crates/scp-runtime/src/context/supervisor/supervisor.rs` = 23,804 lines (largest file in the repo by ~3×). Production `impl Supervisor` is a SINGLE undivided block, lines 1529–12759 (~11K LOC, **171 methods**); tests fill 13072–23804. Essentially no section banners in the prod half.

Responsibilities co-located on the one impl: provider registry + ~15 `*_ref` accessors; actor spawn/despawn/respawn lifecycle + watchdog + poison supervision; command/query dispatch routing across 6+ domains (dispatch_lifecycle/governance/economy/trust_recovery/queries…); wrapping-key + key-package custody.

**Verdict: MEDIUM god-FILE, not a god-OBJECT coupling defect.** The ownership is coherent — this is genuinely "the thing that owns and routes to actors," canonical for an actor supervisor. The `_helpers.rs` free-function domain files (governance/messaging/lifecycle/tools, some huge) are the CORRECT decomposition and are NOT god-objects (domain-grouped free fns). The issue is purely that `impl Supervisor` is one undivided 11K-line block in one 1.16 MB file — Rust splits an impl across files at ZERO type/runtime cost, so nothing forces the monolith; it accreted across ~12 PRs without sectioning. Recommend splitting the impl into cohesive files (accessors / dispatch / actor-lifecycle / key-custody / poison-watchdog). Don't overstate as a correctness/coupling finding.

The helpers/logic split (only economy/governance/lifecycle have a small pure `_logic.rs`) is PRINCIPLED — pure decision logic extracted where it exists, enforced by check-pure-helpers.sh (already audited convergent, see [[codebase-map-gate-audited-clean]] neighbourhood). Not duplicative.
