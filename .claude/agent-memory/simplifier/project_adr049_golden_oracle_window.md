---
name: adr049-golden-oracle-window
description: ADR-049 crypto-move PRs use a "prep-then-atomic + golden byte-identity oracle" migration pattern; watch for oracles retained past the completed move.
metadata:
  type: project
---

ADR-049 PR-4→PR-7 move per-context crypto off `MlsCryptoProvider` onto actor-owned `PerContextState`. The migration style (PRD `adr049-crypto-state-move.json`, Decision 15, "prep-then-atomic"): a prep story defines the new method as a VERBATIM copy of the provider body, RETAINS the provider twin under `#[cfg(test)]`, and guards the copy with a "golden byte-identity" test asserting new==old. The atomic story then deletes the provider twins and flips call sites.

**Simplifier watch:** once the atomic move lands, a retained provider twin + its golden byte-identity oracle is a completed-migration artifact. If the oracle assertion is subsumed by an adjacent end-to-end/ground-truth assertion, it is tautological and imposes a manual "keep byte-for-byte in step" dual-maintenance obligation on crypto code — negative value. The correct end state (which PR-7 DID for its 11 steady-state methods: seal/open/rotate/export/…) is: delete the provider twin, replace the oracle test with a pure actor round-trip (seal→open→assert plaintext). Flag any surviving `*_matches_oracle` test whose oracle branch adds nothing over the ground-truth assertion.

**Why:** PR-7 correctly dropped oracles for 11 methods but left `golden_handle_sender_key_request_actor_matches_oracle` (state.rs) comparing actor vs a retained provider oracle — the `key_actor==key_oracle` assert is subsumed by `key_actor==actor_sender_key`. The provider method itself must stay (two_party_test_support.rs / spawn_from_welcome_tests.rs use it as a fixture BUILDER, not an oracle), but the tautological test assertion should go.

**How to apply:** on future ADR-049 (or similarly-styled) migration PRs, check whether retained `#[cfg(test)]` provider twins and their golden oracles still earn their keep after the atomic flip. Bounded source-text deletion checks like `provider_steady_state_crypto_methods_are_deleted` (a fixed 11-name list) are fine/defensible — NOT the non-convergent denylist pattern.
