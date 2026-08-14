---
name: ps09-adr057-ts-packaging
description: Interrogation of planning-session-09 (ADR-057 Slice 3 TS SDK packaging, D1–D6, PR #2154) — decisions sound but recorded in wrong artifact tier
metadata:
  type: project
---

Reviewed `.docs/planning-sessions/planning-session-09-adr057-slice3-ts-sdk-packaging.md`
(PR #2154), which records DOA-grade permanent public-API decisions D1–D6 for shipping the
ADR-057 in-browser client through npm.

**Why:** These are permanent public-API commitments (two packages: `@limn-works/scp-ts` +
`@limn-works/scp-ts-wasm`). Interrogated their premises against ADR-057 and current code.

**How to apply — findings that recur in this codebase:**
- **Artifact-tier inversion is the real root cause here.** DOA/ADR-grade decisions were
  recorded in a *planning-session* doc. Planning sessions sit at the `plans` tier — UPSTREAM
  of ADRs in the one-way flow — yet D1/D3 revise ADR-057 Slice 3 (line 84: "wire the browser
  backend behind the existing `@limn-works/scp-ts` API") into a *separate* package the base
  package explicitly does NOT reach. Downstream revising upstream without amending it =
  phantom-provenance risk. Permanent API contracts belong in an ADR amendment + the governing
  spec/scaffold, not a dated planning-session.
- **Stale governing blueprint:** `.docs/scaffold/typescript.md` §line 54 still normatively
  states the *superseded* ADR-055 model ("browser = remote thin client, no in-browser MLS")
  and lines 75/206 assert a single npm package. The session scheduled a "stale-comment
  cleanup" for TS *source* only — it did not cite or schedule the scaffold blueprint (the
  actual authority for package structure). Watch for this drift class: comment cleanup folded
  in while the governing artifact keeps the dead premise.
- **D1's load-bearing premise ("native and wasm tiers never co-load in one JS realm") is
  overstated** — a Node process / test harness / edge-runtime-in-Node CAN co-load both. The
  decision survives anyway on a stronger ground the doc under-weights: error classification is
  by string-code prefix (`mapBridgeError` in `bindings/typescript/src/errors.ts`), not
  `instanceof`, so cross-tier co-load degrades only to an `instanceof`-false papercut, not a
  correctness break. Fix the *rationale*, keep the decision.
- D2 (keep `-ts` suffix), D3 (no transparent fallback — capability subset, aligns with
  no-silent-defaults tenet), D4 (injected `JsSocket`), D5 (move relay wire types), D6
  (panic=unwind prereq, traces to ADR-057 Prereq 4) are sound on merit, not inertia.
- Minor coherence QUESTION: D1 names the package by *mechanism* (portable: Deno/Bun/Workers)
  but bundles *browser*-named default adapters (`WebCryptoCustody`/`IndexedDbStorage`). Fine
  iff they are injected ports / exports only and the wasm `ScpClient` does not silently
  default to them (Workers has no IndexedDB).
