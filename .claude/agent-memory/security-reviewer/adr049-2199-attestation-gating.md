# #2199 KeyDestructionAttestation observed-disposal gating — 2026-08-02 — APPROVED, no BLOCKER/HIGH

Branch adr049-2199-attestation-gating. Killed a hardcoded-`true` false guarantee on
`KeyDestructionAttestation.{mls_group_destroyed, sender_keys_destroyed}`.

## What the fix does (verified correct)
- `ContextCryptoState/PerContextState::dispose_secrets` (scp-runtime actor/state.rs:2172/2324) now
  returns `#[must_use] DisposalOutcome{mls,sender:bool}`, flags computed from PRE-disposal presence
  (`mls_group.is_some()`, `sender_key.is_some() || !sender_key_store.is_empty()`) BEFORE nulling.
- Attestation built at runtime seam `ttl_close_helpers::finalize_close` (ttl_close_helpers.rs:923)
  post-disposal from REAL `handle.params().memory_scope` + observed outcome + `deps.clock.now_secs()`.
  ttl.rs STEP bits gated on outcome; None-crypto on destruction-required scope => warn, NO bits set.
- `KeyDestructionOrchestrator::destroy_ephemeral_keys` (key_destruction.rs:118) now takes REQUIRED
  `disposal: DisposalOutcome` param — cannot omit/default a `true`.
- UniFFI bridge context_close: DELETED the fabricated pre-disposal `CloseOrchestrator::initiate_close`
  (built off `ContextParams::default()` FAKE scope, hardcoded true, discarded). FSM dispatch
  (LifecycleCommand::CloseContext) RETAINED before the deleted block — close still works.

## Key verifications
- Only 2 prod construction sites (key_destruction.rs:118, ttl_close_helpers.rs:923); all `true`
  literals elsewhere are test-only (memory_scope.rs:816 roundtrip test etc).
- Deleted bridge relay_urls/blob_ids were ALWAYS `&[]` => zero relay requests => nothing lost.
  Real relay ciphertext delete is done by ttl::finalize_close §5.11 (ttl.rs:585), independent path.
- Two unguarded `owned.dispose_secrets()` (builder.rs, supervisor.rs:13847) use the SEPARATE
  unit-returning provider.rs born-payload type — no must_use break. Actor-state callers all
  consumed or `let _ =`'d.
- Honest-absent tested: apply_ttl_terminal_transition_none_crypto_ephemeral_is_honest_absent +
  relay-stall test asserts !mls_destroyed && !sender_key_destroyed.
- #2215 (record attestation into ContextClosed leaf) is a LEGIT deferral: wire-format/signature-
  bytes/publication protocol are unsettled UPSTREAM spec open questions (CRYPTO-26,
  spec-audit-08:269). Pre-fix also only logged => no persistence regression.

## Residual findings (LOW / observation, not blocking)
- LOW-1: `DisposalOutcome` is `pub` struct w/ `pub` fields (state.rs:400), reachable crate-wide+ via
  `pub mod context`. A `true` is hand-forgeable in-crate. Guarantee is "can't-omit" not "unforgeable".
  Harden: privatize fields, make dispose_secrets the sole minter + pub(crate) accessors + cfg(test) ctor.
- LOW-2: KeyDestructionOrchestrator/initiate_close/destroy_ephemeral_keys now have NO prod callers
  (test-only). finalize_close builds attestation directly. Dead prod scaffolding — wire through or retire.
- Obs: disposal teardown is Class-C (class_c_view) — crash pre-snapshot could reload pre-disposal
  crypto. Pre-existing, orthogonal to #2199. Consider Class-S ticket.

Ethos anchor: spec §5.11 "Enforcement honesty" + §9.15 trust levels; phase-5:484 honest SoftwareOnly.
Fabricated true = nullifier-class false guarantee, worse than honest absence.
