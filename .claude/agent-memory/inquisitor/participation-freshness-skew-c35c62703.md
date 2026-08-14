---
name: participation-freshness-skew-c35c62703
description: Interrogation of trust/participation freshness hardening (future-skew bound, fail-closed FFI clock panic, .pyi fix) on branch @c35c62703
metadata:
  type: project
---

Interrogated the trust/capability FFI change set @c35c62703 (fix: harden participation
freshness + fail-closed FFI clock + stale .pyi). Focus: decisions, not line-correctness.

**Why:** independent decision-soundness review requested; guard against sunk-cost /
cargo-culting / redundant enforcement.

**How to apply:** if re-reviewing participation freshness or clock handling, these verdicts hold
until the cited premises change.

Verdicts:
- **Future-skew bound (MAX_PARTICIPATION_FUTURE_SKEW_SECS=5min): SOUND.** `updated_at` is
  signed, but the signature proves AUTHENTICITY, not timestamp HONESTY. A trusted-but-misbehaving
  context signer can postdate `updated_at`; without the bound, `saturating_sub` reads age 0 →
  stays inside `max_age_secs` forever. Signature model does NOT cover this. Value is DERIVED from
  protocol-wide §9.14 (5min), same source as challenge.rs — coherence, not copy-paste. Spec §07
  L196 updated in-PR to document the exclusion (provenance intact, not phantom).
- **Skip (treat-as-not-fresh) vs hard-error: SOUND, and the better choice.** Erroring on any
  future-dated statement would let one injected profile DoS the whole admission. Skipping makes it
  inert. Minor: when ALL statements are future-dated it returns RecordTooStale — misleading name
  (they're future, not stale), diagnostic-only.
- **Fail-closed clock panic (SystemClock::now_secs) across FFI: SOUND.** Replaces OLD
  `map_or(0,...)` which was a real fail-OPEN (pre-epoch clock → time 0 → every statement maximally
  fresh). Workspace uses default panic=unwind (verified: Cargo.toml L91 `panic="deny"` is a CLIPPY
  lint, NOT a profile) → panic is CAUGHT at pyo3/napi/uniffi as an exception, not a process abort.
  Core stays pure (takes `current_time: u64`), impure clock+failure live at the edge — good
  layering. Typed error would add surface for zero behavioral gain (only correct action = refuse).
  Adopts the pre-existing, documented SystemClock invariant used on UCAN/challenge paths.

**UPDATE @9d32bb297 ("consolidate participation freshness predicate + close review nits"):**
The QUESTION-level "Duplicated freshness predicate" finding below was RESOLVED correctly.
The separate diagnostic re-filter (old `best_value`) was deleted; `best_fresh_value` is now a
u64 accumulator updated inside the single main loop (participation.rs:1050/1072), gated by the
SAME skew+max_age `continue` guards. VERIFIED behavior-identical by reading, not the test claim:
old filter's implicit set = {subject-matched (Step 0), sig-verified (Step 1 hard-fails first),
skew-bound, max_age}; new accumulation point sits after all four → identical set, identical
`.max()`, identical 0-default. This is single-sourcing one predicate, NOT coupling two concerns —
the diagnostic value is definitionally the max over the gate's own fresh set. SOUND.
Fail-closed panic: ADR-057 (phase-2.md:2008) now documents the unwind dependency. VERIFIED no
`panic="abort"` anywhere in workspace; root Cargo.toml:91 `panic="deny"` is still the clippy lint.
The panic is inherited from the project-wide `Clock` trait contract (time.rs:79 "implementations
should panic"), used on UCAN/challenge paths too — coherent, not a local choice. Residual QUESTION:
the now-named "FFI cdylibs MUST NOT be `panic=abort`" invariant has ZERO mechanical enforcement
(documentation-over-mechanism); it's foundational (governs ALL FFI panic→exception surfacing, not
just this check), so a bounded one-line Cargo-profile grep gate would be proportionate. Not a
blocker. Convergence tail is legitimate (real drift-seam removal), NOT grinding.

Findings (QUESTION-level, not blockers):
- **Skew-constant drift (root cause, pre-existing).** The §9.14 future-skew tolerance is
  re-declared as ~4 identical local consts with same semantics: envelope/validation.rs,
  crypto/ucan/validate.rs (`DEFAULT_CLOCK_SKEW_TOLERANCE_SECS`, pub — natural canonical home),
  trust/challenge.rs, and now trust/participation.rs. This PR adds the 4th. Internal
  inconsistency: the SAME PR created `TOOL_INVOCATION_COUNT_ANCHORED`/`ATTESTATION_COUNT_ANCHORED`
  as single-source-of-truth constants to prevent drift, yet re-declared the skew const locally.
- **Duplicated freshness predicate.** Gate (participation.rs ~L1055-1063, two `if...continue`) and
  the `best_value` diagnostic filter (~L1091-1093, combined) express the same freshness test twice.
  Not defense-in-depth — recomputation because the fresh set isn't retained. A shared
  `is_fresh(updated_at, now, max_age)` would prevent the diagnostic drifting from the gate.
  Diagnostic-only consequence.
- **.pyi hand-maintenance.** The stale 2-arg `verify_participation_requirements` stub IS the
  evidence that hand-maintained `.pyi` with no parity gate drifts. #1990 tracks a gate — acceptable
  disposition for a non-runtime artifact, BUT prefer GENERATING the .pyi from pyo3 signatures over
  hand-writing + gating a hand-written file.
