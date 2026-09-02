---
name: pr2366-attestation-fail-closed
description: Attack surfaces surviving PR #2366 (fix/attestation-verification-fail-closed), which closed issue #2335 findings 2, 9, 11, 13 for identity-link, threshold, custody-violation, and revocation-writer paths
metadata:
  type: project
---

# PR #2366 — attestation verification fail-closed

Branch `fix/attestation-verification-fail-closed`, reviewed 2026-08-15 against issue
#2335 findings 2, 9, 11, 13.

## Six attacker-controlled inputs still reaching `true` / `Ok` / a counted attestation

**V1 (HIGH) — revocation-list poisoning via unscoped `attestation.id`.**
`crates/scp-ffi/common/src/trust_store.rs:296-317` writes an id into a context
revocation list whenever an ingested attestation carries an issuer-signed
`Revoked` status. Both readers discard `issuer`:
`crates/scp-ffi/common/src/trust_store.rs:152` and
`crates/scp-protocol/src/trust/aggregate.rs:153`, each `fn check_revocation(&self,
attestation_id: &str, _issuer: &DID)`. `Attestation.id` is a free `String`
(`crates/scp-protocol/src/trust/attestation.rs:56-58`) with no derivation and no
issuer scoping. Any party mints a DID (self-certifying via
`IdentityDidPublicKeyResolver`, `attestation.rs:694-707`), signs a self-revoked
attestation whose `id` collides with a victim's, and permanently suppresses that
victim's attestation in that context. Entry point is caller JSON:
`crates/scp-ffi/src/trust.rs:847-853` → `:918-932`, persisted to SQLCipher.
Author's own comment at `trust_store.rs:1314-1317` names this threat and closes
only its forged-signature half.

**V2 (HIGH) — DID document rollback.** Sequence monotonicity lives only in a
per-process `DidCache` (`crates/scp-identity/src/resolver.rs:497-525`,
`crates/scp-identity/src/cache.rs:96-99`). A fresh process accepts an older
validly-signed document, so a retired `#active` key verifies. `NoOpRelayQuerier`
on all three bridges makes DHT a single point of answer. Cache hits skip
re-query and discard staleness (`resolver.rs:438-444`), hiding a counterparty
rotation for up to a 7-day TTL.

**V3 (HIGH) — independence score is attacker-declared.**
`compute_independence_score` (`crates/scp-protocol/src/trust/attestation.rs:1380-1430`)
reads unsigned `AttestorInfo.context_memberships` / `.endorsements`. Penalties
only lower a score, so declaring both empty yields 1.0. Combined with free DID
minting, `met` is satisfiable by N sybils. `evaluate_sybil_resistance` still
called with `None` at `crates/scp-runtime/src/context/lifecycle_logic.rs:223`.

**V4 (MED-HIGH) — `challenge_response` proof never verified.** Class 1 method,
proof shape `{challenge, response_signature, verifier_did}`
(`crates/scp-protocol/src/identity/attestation.rs:130-137`), read by nothing.
`AttestationEvidence.verifier_did` (`:372-375`) names a third party bound by no
signature. Spec `.docs/specs/03-identity.md:280-287` lists no such step, so this
is a spec hole first.

**V5 (MED) — freshness discarded at bridge boundary.** `decide_link_attestation`
(`crates/scp-ffi/common/src/attestation.rs:284-323`) drops
`IdentityLinkFreshness::Stale`. Same boolean collapse merges "forged" with
"issuer rotated `#active`".

**V6 (MED) — custody-violation verifier has zero callers.** New
`verify_verifier_signature` (`crates/scp-protocol/src/trust/custody_violation.rs:493-541`)
appears only in its own tests. `validate()` still returns `Ok` on any non-empty
signature, and both types are re-exported through `scp_core::trust`.
`CounterAttestation.violation_reference` is an unconstrained `String` — no
cryptographic binding to a violation record's `signing_hash`.

## Process findings

- Three SDK wrappers (TypeScript `src/scp.ts:1041`, Swift `Identity.swift:181`,
  Kotlin `Identity.kt:479`) still route to a declining free function, so their
  verify operation always throws `SCP-IDENT-1060`. Capability matrix keeps
  `"kotlin": true`. TypeScript carries two contradictory routes.
- `scripts/bridge-aliases.json:2797-2812` now accepts `*_module_scope` as the
  canonical operation, so a declining stub alone satisfies bridge symmetry.
- New call invariant is vacuous: `scripts/check-call-invariants.py:876-899`
  iterates existing functions and emits nothing when no name matches.

## What resisted attack

Caller-supplied keys are comparison-only (never verification material); every
resolution failure raises a typed error rather than `Ok(false)`; `now_secs` reads
`SystemClock` inside each bridge; both live resolver layers run BEP44 plus
self-certification; canonical hashing for both custody records is injective with
distinct domain separators; `verify_strict` plus `decode_multibase_key`
curve-point validation reject non-curve and wrong-length keys.

See [[surfaces-crypto-economy-persona]] for older attestation-family surfaces.
