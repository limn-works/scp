---
name: capsel-17-17-capability-selection-46caacf38
description: Review of §17.17 CAPABILITY SELECTION cross-capability principle (SCP-CAPSEL-8000..8013) generalizing storage §17.6 rule; branch docs/adr-062-capability-injection @46caacf38
metadata:
  type: project
---

# §17.17 "Capability Selection Is Mandatory, Fails Closed, Never Defaults" — APPROVE-WITH-CHANGES @ 46caacf38

Branch `docs/adr-062-capability-injection`, worktree agent-ae0cddf9d3653e5ef. Spec-only diff on 17-persistence-and-storage.md (+§17.17/.1/.2/.3) and 03-identity.md (+DHT-backend note in §3.10.6). Generalizes storage-only §17.6 rule to EVERY provider capability. New prefix SCP-CAPSEL-8000/8001/8002 (selection mandatory/fails-closed/never-default) + 8010/8011 (durability-only classification) + 8012 (nullifier provably-absent) + 8013 (in-memory DHT = nullifier). Defers ALL mechanism (dispatch shape, build config, absence-proof) to ADR-062.

**Why (verdict basis):** Substance sound, artifact-flow CORRECT (genuine upstream spec generalization, stays at requirement altitude, mechanism explicitly deferred to ADR-062 — no Rust/enum/dyn/cargo-feature in normative text). Zero literal ID collision (SCP-CAPSEL is a brand-new prefix, 0 on origin/main). §17.6 rewording preserves original force + keeps SCP-STORAGE-8000 as storage error surface, no meaning drift. DHT-nullifier reasoning (fail-open freshness vs storage fail-closed) verified accurate vs §3.9/§3.10.6/§3.10.7/§3.10.8. CAPSEL-8012 pitched at right altitude (flag-guarded-but-compiled-in still violates).

**How to apply (residual findings, all LOW/non-blocking):**
- (LOW, ID hygiene) CAPSEL-8010/8011/8012/8013 numerically SHADOW existing SCP-STORAGE-8010/8011/8012/8013 (browser-wasm error codes: I/O fault, corrupt snapshot, owner-DID mismatch, poisoned — sdk-common.md:137-140). Different prefix = no literal collision, but the deliberate 8000↔8000 mnemonic parallel breaks/misleads at 801x. Consider a non-shadowing block or an explicit "801x does NOT parallel STORAGE-801x" note.
- (LOW, sequencing) ADR-062 does NOT exist yet (only referenced from this spec). Must be authored BEFORE downstream code builds on §17.17, else phantom provenance.
- (LOW, discoverability) Only DHT (§3.10.6) got a back-ref. §17.7 blobstore, §17.8 custody, credential storage, device attestation, relay querier are ENUMERATED as in-scope but got no back-pointer — a completionist should add one-line pointers.
- (OBS) CAPSEL-8013 "silently never propagates" is precise for the DHT namespace/DHT-reliant resolvers; in a both-layers-healthy deploy the relay layer still carries rotations (§3.10.7 highest-seq-wins) — the nullifier's teeth are silent destruction of the DHT half of the mandated dual-publish + §3.10.8 single-layer-suppression resilience, not universal immediate failure. Classification still holds (evil = silent false success, cf. explicit+warned disable_dht()).

Placement sound: §17.17 = clean sequential append after §17.16 (Saga Journal), no renumber. §3 cross-ref correctly placed in §3.10.6 Anti-Segmentation subsection.
