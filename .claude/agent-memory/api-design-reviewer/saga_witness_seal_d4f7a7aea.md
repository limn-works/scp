---
name: saga-witness-seal-d4f7a7aea
description: §17.16.4 RestoredContexts witness seal review — exemplary sealed-type design; one MEDIUM on with_providers_and_journal over-broad pub + inaccurate doc
metadata:
  type: project
---

Reviewed commit `d4f7a7aea` (branch saga-2c worktree) — sealing the restore-then-replay ordering witness `RestoredContexts` against forgery (§17.16.4, ADR-049 §5 OwnedIdentityDid discipline).

**Reference design (approve-as-exemplary):** `RestoredContexts` in `crates/scp-runtime/src/context/supervisor/supervisor.rs:130-179`. Private `ids` field + module-private `const fn new` + NO `Default`/`Clone` + feature-gated `pub for_test`. Type stays `pub` ONLY so external-crate `compile_fail` doctests can name it; doc correctly states the witness's *existence* (not payload) is the enforcement. Paired compile_fail doctests pin E0599 (`default()`) + E0451 (private-field literal) for the right reasons. This is the canonical "nameable ≠ constructible" pattern — pair with [[classs_cell_field_granular_views]].

**`saga-witness-test-mint` cargo feature is the correct API choice.** A test-mint minter must NOT be implied by `testing`, because `testing` leaks into every `allow_in_memory_custody` build via `scp-ffi → dep:scp-testing → scp-core{testing} → scp-runtime/testing`. A `cfg(test)`-only minter fails because the consuming integration tests are SEPARATE crates, not `#[cfg(test)]` units. So a dedicated feature enabled solely by the two `actor_saga_*` targets' `required-features` is the only sound option.

**The one real finding (MEDIUM):** `Supervisor::with_providers_and_journal` widened `pub(in crate::context)` → unconditional `pub` to reach a test in the separate `scp-testing` crate. Its doc claims "does NOT widen the journal-injection surface — the already-`pub` `Self::new` accepts an arbitrary journal too." FALSE for production: `Supervisor::new` is `#[cfg(any(test, feature="testing"))]` (does not exist in non-testing builds) and `with_providers` hardcodes `NoopSagaJournal`. So this is the ONLY pub arbitrary-`SagaJournal` injector in a production build. Fix = gate it `#[cfg(any(test, feature="testing"))]` matching siblings `new`/`for_query_shim`/`SagaSetReservation` in the same file; `scp-testing` builds scp-runtime with `testing` so the test still reaches it.

**Why:** A reviewer must verify cfg-gating of the "precedent" a visibility-widening doc cites — `pub fn` that is `#[cfg(feature="testing")]` is NOT public in production. Check the cfg attribute, not just the `pub` keyword.
**How to apply:** When a constructor/method is made `pub` "to match an existing pub X," confirm X is unconditionally pub (not test-cfg-gated). Prefer `#[cfg(any(test, feature="testing"))]` over full `pub` when the sole consumer is a test crate that enables `testing`.
