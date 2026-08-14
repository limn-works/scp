---
name: adr055-adr057-browser-model-sweep
description: ADR-055→ADR-057 browser-model doc sweep — convergence CLEAN; how to classify definitive-live vs historical supersession refs
metadata:
  type: project
---

ADR-057 amends ADR-055's browser-deployment conclusion: the browser is NOT a "remote
thin client with no in-browser protocol execution"; it runs the full protocol **in-tab**
over the wasm tier (`@limn-works/scp-ts-wasm` npm package / `scp-client-wasm` crate), keys
on-device. A remote custodial thin client remains an **opt-in secondary mode**.

**Why:** ADR-055 (2026-06-29) removed the WASM *bridge*; its thin-client *conclusion* was
later revised by ADR-057 after a wasm32 compile spike disproved the "re-implement or
delegate" premise. The bridge removal stands; only the deployment conclusion changed.

**How to apply (supersession-sweep classification):** when grepping for stale
`remote thin client` / `no in-browser protocol backend` refs, a hit is a FINDING only if it
is a **definitive live/consumer/code claim** in current docs/bindings/templates/scaffolds
(README, GETTING-STARTED, guides, code comments driving behavior). It is LEGITIMATE and must
NOT be re-flagged if it is: (a) ADR-057-aware optional-mode/"NOT a thin client" framing,
(b) a historical ADR-055 banner / amended-by note in an ADR, (c) a lesson/planning-session
narrative recording past state, or (d) a done-story PRD record (`main.json` description/result
fields log what was built at completion time — the PRD is a log, not a live claim).

Round-3 convergence (delta a8b0d5eaf..HEAD == commit fd07b1ed8) = **CLEAN**: 5 files, docs +
one test-helper comment only, no scaffold-slice regression. Package/crate names verified real.
Related: [[adr057_transport_wasm_surface_parity]].
