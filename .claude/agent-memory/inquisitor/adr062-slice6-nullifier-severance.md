---
name: adr062-slice6-nullifier-severance
description: ADR-062 Slice 6 / SCP-CAPINJECT-006 interrogation — fail-closed prod identity creation, 4-nullifier severance, G1 gate; decisions SOUND, findings are coherence/process
metadata:
  type: project
---

# ADR-062 Slice 6 (SCP-CAPINJECT-006) — nullifier severance, fail-closed pre-rotation

Branch `feat/adr062-slice6-nullifier-severance` @554994606. Verdict: **decisions SOUND on merit**, no reversal. Findings are coherence-surfacing + one process/enforcement-file finding, not premise-failures.

**Why:** interrogated 5 premises (Alec pre-approved fail-closed direction 2026-07-16; interrogate framing not reversal).
**How to apply:** when re-reviewing later slices (9-11 E2/E3/E4) or #1729/RFC-2130 backend, these hold.

## What held (premises verified against current code + spec)
- **Fail-closed prod identity creation is spec-FORCED, not an ADR free choice.** spec §9.7.4.1 item 3a now carries a canonical "**Fail closed — no fallback (normative)**" clause (my prior memory adr062-prerotation-failclosed-scope flagged it demoted to Proposed RFC — that was RESTORED to canonical spec). create signatures dht.rs:1094/1453/2013 all take `pre_rotation_custody: &impl PreRotationCustody` → structurally require a commitment; Option A (non-committing) genuinely out of scope (#1553) AND would violate §9.7.4.1. So given (sever nullifier now)+(no real backend)+(mandatory commitment), fail-closed is the ONLY option. Severing NOW vs waiting for #1729 is the real decision → sound: nullifier is a live shipping hazard, pre-severance identities were already unmigratable garbage (line 85), fail-closed > false-guarantee. create_inner (config.rs:333) clean: mint under `any(test,feature=testing)`, else `Err(NoPreRotationBackend)`=IDENT_1059.
- **in-memory-storage stays shipped = spec-blessed, NOT nullifier-adjacent.** §17.17.2 SCP-CAPSEL-8010 explicitly: durability-only fails CLOSED (lost state→no answer, not false answer). Orthogonal to pre-rotation custody capability. Allowlist permits BOTH in-memory-storage + sqlite → durable arm reachable (8011 satisfied).
- **G1 (check-shipped-feature-graph.sh) is NOT redundant with type-system.** Type system: "feature absent ⇒ nullifier type unnameable." G1: "feature absent" — the PREMISE the type guarantee rests on, which the type system CANNOT see (can't read Cargo feature graph). Orthogonal, not re-checking. Positive closed ⊆-whitelist (durability-only only, ZERO nullifiers) = convergent/bounded shape CLAUDE.md wants; self-test fixtures (a/b/c + soundness + hygiene). Sound.
- **`any(test, feature=testing)` in scp-identity create_inner is NOT an A5 violation.** A5 governs nullifier TYPE arms in BRIDGE crates (G1-checked). create_inner is a BRANCH in scp-identity; nullifier TYPE still gated scp-platform/testing (feature-only). `test` cfg doesn't propagate to dependencies, so shipped bridges (scp-identity as dep, no test cfg, no testing feature) → fail-closed. `test` is load-bearing: scp-identity dev-deps enable scp-platform/testing but NOT scp-identity's own `testing` feature, so own unit tests need the `test` arm to get minting path. node fail-closed test exploits this: `cargo test -p scp-node` (no testing feat) → scp-identity dep has test=false → fail-closed branch genuinely exercised. Clever + real.

## Findings surfaced (defensible-but-worth-noting)
- **[PROCESS/MED] pure-helpers-allowlist.txt +3 attestation entries = enforcement-file EXEMPTION, not in approved plan.** CLAUDE.md lists pure-helpers-allowlist.txt as enforcement file; "exempting existing assertions requires human approval"; plan approved fail-closed direction but NOT this specific allowlist weakening. AVOIDABLE alternative: fail-closed body could deref self via registry lookup (validate DID/identity known to instance before returning "no backend") → satisfies handle-affinity gate WITHOUT touching enforcement file, arguably more correct (distinguishes unknown-identity from no-backend). Note pre-empts `let _=&self.inner` as gaming, but a real registry lookup is a legit precondition. Transient, tracked #2171. QUESTION not UNSOUND.
- **[COHERENCE/LOW] ADR A5 prose ("gate feature=testing ONLY, never any(test,...)") reads as blanket but code has 6 `any(test,feature=testing)` sites.** Legit (branch selectors/imports in scp-identity/scp-node, not nullifier type defs; G1-sound) but a naive A5 audit would flag them. ADR could clarify A5 = nullifier TYPE arms in G1-checked crates, not branch selectors in leaf crates.
- **[FRAMING/LOW] roadmap-level implication understated.** Fail-closed = shipped SDK cannot onboard ANY end-user until #1729. Disclosed accurately (lines 85/126 "all production identity creation returns this error until #1729") but magnitude framed narrowly as severance-consequence; the "no shippable end-user product until #1729" statement is implied not stated. Not a defect — disclosure is complete.

## Attestation exemption (premise 4) — keeping always-erroring method exposed
SOUND: spec §9:187 device attestation is OPTIONAL, absence expected/conformant; bridge-symmetry requires method on all bindings; typed "unavailable" = honest-absent state. Not-exposing → symmetry gap + re-add churn (DOA). uniffi peer DOES deref self (check_handle); only pyo3/napi (take DID String) don't → the exemption. See process finding above for the avoidable angle.
