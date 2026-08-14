---
name: dedup-must-not-conflate-distinct-seals
description: Collapsing duplicated rationale comments must keep distinct enforcement mechanisms distinct; witness=ordering, pub(crate)=bare-leg-coverage are NOT the same guarantee
metadata:
  type: feedback
---

When de-duplicating a verbose comment that explains *multiple distinct enforcement mechanisms*, do not let the collapse merge them into one. A black-hat review (ADR-049 saga restore-then-replay gate, `crates/scp-testing/tests/integration/pipeline_wiring.rs`) caught a LOW finding where my collapse wrote "the type system guarantees **ordering**: `restore_all_contexts` being `pub(crate)` makes the bare leg unnameable cross-crate" — conflating two separate type-system seals.

The two seals in this system (verify against `crates/scp-runtime/src/context/supervisor/supervisor.rs` before citing — line numbers drift):
- **ORDERING** (restore-before-replay) is enforced by the `RestoredContexts` *witness* required as an argument on `replay_unresolved_sagas` — only `restore_all_contexts` can mint it, so replay-before-restore does not compile. The canonical doc (`RestoredContexts` struct doc) is explicit: the witness's mere EXISTENCE is the ordering enforcement, not its payload.
- **`pub(crate)`** enforces *no-bare-restore-leg cross-crate* (E0624) — leg coverage, NOT ordering.

**Why:** advertising the wrong mechanism as the load-bearing one is a future-author-misread hazard: someone trusting "ordering comes from `pub(crate)`" could conclude the witness is redundant and delete it, silently voiding the replay-before-restore compile barrier while the comment still reads plausible. The task's exact concern was "don't advertise a weaker/stronger seal than reality."

**How to apply:** when a single commit edits the same fact in two places (here, the ADR-049 split got it RIGHT — named both mechanisms separately — while the test-file collapse got it WRONG), cross-check the two for consistency before declaring done. If one artifact distinguishes mechanisms and a parallel one merges them, the merged one is the bug. Comment-only/doc-only changes still carry real semantic risk; run the full roster, and take adversarial doc-accuracy findings as seriously as code findings.
