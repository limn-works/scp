//! Async, resolver-backed `KeyPackage`-attestation verification for the
//! **Add** path — §9.7.1 verifier checks 1–13 wired to real DID resolution.
//!
//! The pure, wasm-safe seam
//! ([`scp_mls::verify_attestation_with_resolution`], Layer A) enforces
//! §9.7.1 check 2 (the resolving document is fresh) and check 1 (the
//! credential's `signing_key_id` names the DID's *current* `#active`/`#agent`
//! verification method), then delegates checks 3–13 to the pure core
//! `verify_attestation`. It is deliberately I/O-free: it consumes an
//! *already-resolved* [`scp_did::DidDocument`] plus caller-supplied
//! `resolved_at`/`now` timestamps.
//!
//! This module is the **runtime caller** that produces those inputs. It:
//!
//! 1. resolves the attestation signer's DID through the injected
//!    [`DidDocumentResolver`] — the `dyn`-safe face of the canonical §3.10.4
//!    dual-layer resolver, never a `NoOp` / `Stub` / in-memory stand-in (the
//!    no-dev-stand-in tenet);
//! 2. applies the §9.7.1 **"Resolution failure policy"**: a resolution
//!    failure (`Err`), a not-found (`Ok(None)`), and an unwired resolver are
//!    each **fail-closed** — a typed reject with NO fallback to a
//!    stale/pre-rotation cached document;
//! 3. stamps `resolved_at` = the injected [`Clock`]'s time at the resolve call
//!    (HONEST — never a fabricated/hardcoded constant); and
//! 4. delegates to Layer A.
//!
//! # Where it runs
//!
//! `ProductionMlsBackend::validate_key_package` calls
//! [`verify_add_attestation`] on every `KeyPackage` an admission path presents.
//! Both admission paths — `execute_add_member` (the governance invite) and
//! `join_context` (the self-join) — reach a joiner's `KeyPackage` only through
//! that method, so one call there covers every `Add`.
//!
//! # Testing carve-out (folds away in shipped artifacts)
//!
//! [`resolution_exempt`] admits exactly the `did:test:` and `did:key:` prefixes
//! and only when this artifact is a test binary or carries the `testing`
//! feature, so the extensive non-`did:dht:` test suite runs without a live
//! resolver. On a shipped build the `cfg!` folds to `false` and no DID is
//! exempt — `did:dht:*` and `did:web:*` alike resolve and fail closed (§9.7.1
//! "Fail-closed scope"). The carve-out skips **resolution**, never the
//! attestation's presence: a leaf carrying no `0xFF03` extension is rejected
//! before this function runs.
//!
//! # Scope
//!
//! This is the Add path. Resolver-side privacy-cache freshness enforcement —
//! that a document served from the §9.10.7 24h/7d cache and older than
//! `MAX_ATTESTATION_KEY_RESOLUTION_STALENESS` MUST force a fresh
//! re-resolution — needs a resolver-freshness seam this trait does not yet
//! expose, and the already-admitted-member **Update last-known-good grace**
//! (§9.7.1 "Resolution failure policy", Update bullet) is likewise not
//! implemented; until it lands, an Update whose resolution fails also fails
//! closed (the conservative default — the grace would only *loosen* this, so
//! its absence never masks a missing backend).
//!
//! See spec §9.7.1 (checks 1–13, resolution failure policy, fail-closed
//! scope), §9.18.7 (the 300s staleness bound), §9.14 (clock skew), and
//! ADR-057 Amendment (2026-08-01).

use scp_clock::Clock;
use scp_mls::{
    AttestationLeafGroundTruth, AttestationResolutionVerifyError, AttestationTrigger,
    KeyPackageAttestation, ScpCredential, verify_attestation_with_resolution,
};

use super::attestation_signer::{DidDocumentResolveError, DidDocumentResolver};

/// Reports whether `did` is exempt from DID-document resolution for the §9.7.1
/// attestation current-key check.
///
/// **The criterion:** a DID is exempt when this artifact was built as a test
/// binary or with the `testing` feature **and** the DID names one of the two
/// non-resolvable test methods, `did:test:` or `did:key:`. On a shipped build
/// `cfg!(any(test, feature = "testing"))` is `false`, so the whole expression
/// folds to `false` and no DID is exempt — `did:dht:*` and `did:web:*` alike
/// resolve and fail closed (§9.7.1 "Fail-closed scope"). This mirrors
/// [`NodeMlsFactory::validate_creator_identity`](super::provider::NodeMlsFactory::validate_creator_identity),
/// which gates its own carve-out through the same `cfg!` mechanism.
///
/// Both admission paths — [`verify_add_attestation`] here and
/// `ProductionMlsBackend::validate_key_package` — call this one function, so
/// the exempt set has a single definition and the two paths cannot drift.
#[must_use]
pub(crate) fn resolution_exempt(did: &str) -> bool {
    cfg!(any(test, feature = "testing"))
        && (did.starts_with("did:test:") || did.starts_with("did:key:"))
}

/// The Add-path leaf/credential ground-truth for the async runtime seam
/// [`verify_add_attestation`].
///
/// This is deliberately the **Add-only** analogue of the pure, trigger-general
/// [`AttestationLeafGroundTruth`]: it carries the `KeyPackage`'s `init_key`
/// (`kp_init_key`) directly and has **no** `trigger` field. Because the async
/// resolver seam accepts only this type, an
/// [`AttestationTrigger::Update`] is **unrepresentable** there **by
/// construction** — not merely undocumented.
///
/// # Why Update is excluded here (not just deferred in prose)
///
/// §9.7.1's "Resolution failure policy" gives an already-admitted member's
/// **Update** a *last-known-good grace* on a transient resolution outage (a
/// bounded fallback to the member's prior document), whereas an **Add** is
/// strictly fail-closed. That grace is the S7 follow-on and is **not**
/// implemented on this async seam. If this seam accepted a general
/// `AttestationTrigger`, a future wirer could route the Update path through it
/// and a transient resolver outage would then hard-reject a legitimate existing
/// member's Update — a censorship/liveness regression. Making Update
/// unrepresentable at the type level (per SCP's "encode required choices as
/// required fields" / "make illegal states unrepresentable" tenets) forecloses
/// that regression mechanically. The pure Layer-A
/// [`verify_attestation_with_resolution`] remains trigger-general and its
/// Update path is complete (it does no resolution, so it has no
/// resolution-failure grace to get wrong).
#[derive(Debug, Clone, Copy)]
pub struct AttestationAddGroundTruth<'a> {
    /// The leaf's `ScpCredential`. Its `did` is the signer DID resolved here,
    /// and its `did`/`signing_key_id` are the check-9/10 ground truth; its
    /// `signing_key_id` names the current verification method for check 1.
    pub credential: &'a ScpCredential,
    /// The leaf's actual `signature_key` (check 4).
    pub leaf_signature_key: &'a [u8; 32],
    /// The leaf's actual ratchet-tree `encryption_key` (check 5).
    pub leaf_encryption_key: &'a [u8; 32],
    /// The value of the leaf's `scp_wrapping_key` (`0xFF01`) extension (check 6).
    pub leaf_wrapping_key: &'a [u8; 32],
    /// The leaf's `Lifetime.not_before` (check 11).
    pub leaf_lifetime_not_before: u64,
    /// The leaf's `Lifetime.not_after` (check 11).
    pub leaf_lifetime_not_after: u64,
    /// The `KeyPackage`'s `init_key` (checks 7–8) — the Add-specific payload
    /// the [`AttestationTrigger::Add`] variant carries. `verify_add_attestation`
    /// constructs that variant from this field internally.
    pub kp_init_key: &'a [u8; 32],
}

/// A typed reason [`verify_add_attestation`] rejected a
/// [`KeyPackageAttestation`] on the runtime (native, `DidResolver`-backed)
/// path — §9.7.1 checks 1–13, plus the resolution-failure policy.
///
/// Wraps the wasm-safe Layer-A [`AttestationResolutionVerifyError`] (checks
/// 1–13) via [`Verify`](Self::Verify) and adds the two resolution-failure
/// variants for the §9.7.1 "Resolution failure policy" fail-closed branch.
#[derive(Debug, thiserror::Error)]
pub enum AttestationRuntimeVerifyError {
    /// §9.7.1 "Resolution failure policy": resolving the signer's DID errored.
    /// Fail-closed on Add — NO fallback to a stale/pre-rotation cached document.
    #[error("attestation signer DID resolution failed (fail-closed): {0}")]
    Resolution(#[from] DidDocumentResolveError),

    /// No DID-document resolver was wired, so §9.7.1 checks 1–2 cannot run.
    /// Fail-closed: an unresolvable attestation is rejected, never accepted
    /// unverified.
    #[error("no DID-document resolver wired for attestation verification (fail-closed)")]
    ResolverUnavailable,

    /// §9.7.1 "Resolution failure policy": resolving the signer's DID returned
    /// no document (`Ok(None)`). Fail-closed on Add — no cache fallback.
    #[error("attestation signer DID resolved to no document (fail-closed)")]
    ResolutionNotFound,

    /// The current-key + freshness seam (Layer A, §9.7.1 checks 1–2) or the
    /// delegated pure core (checks 3–13) rejected. Surfaced verbatim.
    #[error(transparent)]
    Verify(#[from] AttestationResolutionVerifyError),
}

/// Verifies an **Add**-path leaf's [`KeyPackageAttestation`] against the
/// signer's **freshly-resolved current** DID document — §9.7.1 verifier checks
/// 1–13 (CRYPTO-22 S4, Layer B).
///
/// Resolves the signer DID (`ground_truth.credential.did`) through the injected
/// canonical `resolver`, stamps `resolved_at` from the injected `clock` at the
/// resolve call, constructs the Add trigger from `ground_truth.kp_init_key`
/// internally, and delegates to the pure Layer-A seam
/// [`verify_attestation_with_resolution`], which enforces check 2 (freshness),
/// check 1 (current key), then checks 3–13.
///
/// # Add-only by construction — Update is unrepresentable here
///
/// This seam accepts only [`AttestationAddGroundTruth`], which carries no
/// `trigger` field, so it can verify **only** the fail-closed Add path. The
/// already-admitted-member **Update** async path — which §9.7.1 grants a
/// bounded *last-known-good grace* on a transient resolution outage — is
/// deferred to **S7** and is intentionally **uncallable here by
/// construction** (not merely undocumented): routing Update through a
/// fail-closed-only seam would let a transient resolver outage hard-reject a
/// legitimate member's Update (a censorship/liveness regression). See
/// [`AttestationAddGroundTruth`]. The pure Layer-A
/// [`verify_attestation_with_resolution`] stays trigger-general (it does no
/// resolution, so its Update path is complete).
///
/// # Resolution failure policy (§9.7.1)
///
/// A resolution `Err` or `Ok(None)` is **fail-closed** — a typed reject with NO
/// fallback to a stale/pre-rotation cached document (the strict Add policy).
///
/// # Honest `resolved_at` (§9.7.1 check 2; §9.14)
///
/// `resolved_at` is read from `clock` immediately before the resolve call, and
/// `now` immediately after — both clock-derived, never fabricated. For a
/// freshly-resolved document `now - resolved_at` is within §9.14 clock-skew
/// tolerance, so Layer A's 300s freshness gate passes.
///
/// # Testing carve-out
///
/// Under `#[cfg(any(test, feature = "testing"))]` only, a signer DID with the
/// `did:test:` or `did:key:` prefix skips resolution and is accepted (mirroring
/// [`validate_creator_identity`](super::provider::NodeMlsFactory::validate_creator_identity)).
/// `did:web:*` is NOT exempt. The block is compiled out of shipped artifacts.
///
/// # Errors
///
/// Returns [`AttestationRuntimeVerifyError`] on a resolution failure
/// (fail-closed) or on any Layer-A/pure-core check failure.
pub(crate) async fn verify_add_attestation(
    resolver: Option<&dyn DidDocumentResolver>,
    clock: &dyn Clock,
    attestation: &KeyPackageAttestation,
    ground_truth: &AttestationAddGroundTruth<'_>,
) -> Result<(), AttestationRuntimeVerifyError> {
    // The signer DID is the attested DID, which check 9 binds to the leaf
    // credential's `did`; resolving the credential DID is therefore resolving
    // the signer.
    let signer_did = ground_truth.credential.did.as_str();

    // Testing carve-out — a positive whitelist compiled OUT of shipped builds.
    // Keyed on `did:test:` / `did:key:` ONLY (never `did:dht:z`); `did:web:*`
    // is not exempt (§9.7.1 "Fail-closed scope"). Mirrors
    // `validate_creator_identity`.
    if resolution_exempt(signer_did) {
        return Ok(());
    }

    // Stamp `resolved_at` from the injected clock at the resolve call (HONEST —
    // never a hardcoded constant), then resolve through the canonical injected
    // resolver (§3.10.4). NEVER a NoOp/Stub/in-memory stand-in — the resolver is
    // supplied by dependency injection (#2211, no-dev-stand-in tenet).
    let resolver = resolver.ok_or(AttestationRuntimeVerifyError::ResolverUnavailable)?;
    let resolved_at = clock.now_secs();
    let resolved_document = match resolver.resolve_document(signer_did).await {
        Ok(Some(document)) => document,
        // §9.7.1 "Resolution failure policy" — Add is fail-closed. There is NO
        // fallback to a stale/pre-rotation cached document.
        Ok(None) => return Err(AttestationRuntimeVerifyError::ResolutionNotFound),
        Err(source) => return Err(AttestationRuntimeVerifyError::Resolution(source)),
    };

    // `now` for the §9.7.1 check-13 freshness/expiry band and the check-2 age.
    let now = clock.now_secs();

    // Assemble the trigger-general Layer-A ground truth with the Add trigger
    // built INTERNALLY from `kp_init_key` — the caller never supplies a trigger,
    // so Update cannot be requested at this seam.
    let leaf_ground_truth = AttestationLeafGroundTruth {
        credential: ground_truth.credential,
        leaf_signature_key: ground_truth.leaf_signature_key,
        leaf_encryption_key: ground_truth.leaf_encryption_key,
        leaf_wrapping_key: ground_truth.leaf_wrapping_key,
        leaf_lifetime_not_before: ground_truth.leaf_lifetime_not_before,
        leaf_lifetime_not_after: ground_truth.leaf_lifetime_not_after,
        trigger: AttestationTrigger::Add {
            kp_init_key: ground_truth.kp_init_key,
        },
    };

    // Delegate to the pure, wasm-safe Layer-A seam (checks 2, 1, then 3–13).
    verify_attestation_with_resolution(
        attestation,
        &leaf_ground_truth,
        &resolved_document,
        resolved_at,
        now,
    )
    .map_err(AttestationRuntimeVerifyError::Verify)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
    use scp_clock::Clock;
    use scp_did::{DidDocument, SigningKeyId};
    use scp_mls::ScpCredential;
    use scp_mls::keypackage_attestation::AttestationVerifyError;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    const ISSUED: u64 = 1_700_000_000;
    const EXPIRES: u64 = 1_700_086_400;
    const NOW: u64 = 1_700_000_100; // inside [ISSUED, EXPIRES]
    const TEST_DID: &str = "did:dht:z6MkRuntimeSeamTest";

    /// A fixed-time clock: `now_secs()` always returns the same value, so a test
    /// can assert `resolved_at` is clock-derived (== this value), never 0 or a
    /// fabricated constant.
    struct FixedClock(u64);
    impl Clock for FixedClock {
        fn now_secs(&self) -> u64 {
            self.0
        }
        fn now_millis(&self) -> u64 {
            self.0.saturating_mul(1000)
        }
    }

    /// A clock that returns a DIFFERENT value on each successive `now_secs()`
    /// read, so a test can prove WHICH read `resolved_at` is captured at. Layer B
    /// reads `now_secs()` exactly twice — first for `resolved_at` (before the
    /// resolve call), then for `now` (after it) — so `[t0, t1]` scripts those two
    /// reads precisely. Reads past the end saturate on the last value.
    struct SteppingClock {
        values: Vec<u64>,
        idx: AtomicUsize,
    }
    impl SteppingClock {
        fn new(values: Vec<u64>) -> Self {
            Self {
                values,
                idx: AtomicUsize::new(0),
            }
        }
    }
    impl Clock for SteppingClock {
        fn now_secs(&self) -> u64 {
            let i = self.idx.fetch_add(1, Ordering::SeqCst);
            *self
                .values
                .get(i)
                .unwrap_or_else(|| self.values.last().expect("SteppingClock has ≥1 value"))
        }
        fn now_millis(&self) -> u64 {
            // Not read by Layer B; do not advance the step index.
            self.values
                .last()
                .copied()
                .unwrap_or(0)
                .saturating_mul(1000)
        }
    }

    /// A `DidDocumentResolver` that returns a preset outcome and records whether
    /// it was called — so a test can assert the carve-out SKIPS resolution while
    /// a non-exempt DID does NOT.
    struct MockResolver {
        outcome: MockOutcome,
        called: AtomicBool,
    }

    #[derive(Clone)]
    enum MockOutcome {
        Found(DidDocument),
        NotFound,
        Error,
    }

    impl MockResolver {
        fn new(outcome: MockOutcome) -> Self {
            Self {
                outcome,
                called: AtomicBool::new(false),
            }
        }
        fn was_called(&self) -> bool {
            self.called.load(Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl DidDocumentResolver for MockResolver {
        async fn resolve_document(
            &self,
            _did: &str,
        ) -> Result<Option<DidDocument>, DidDocumentResolveError> {
            self.called.store(true, Ordering::SeqCst);
            match self.outcome.clone() {
                MockOutcome::Found(document) => Ok(Some(document)),
                MockOutcome::NotFound => Ok(None),
                MockOutcome::Error => Err(DidDocumentResolveError::Failed(
                    "mock resolver error".to_owned(),
                )),
            }
        }
    }

    fn fresh_pub() -> [u8; 32] {
        SigningKey::generate(&mut OsRng).verifying_key().to_bytes()
    }

    fn did_doc_with_active(active_key: &[u8; 32]) -> DidDocument {
        let identity_key = fresh_pub();
        let commitment = [0u8; 32];
        DidDocument::new(TEST_DID, &identity_key, active_key, &commitment)
    }

    /// Builds a valid signed attestation + its owned leaf ground-truth material +
    /// the signer's current DID document, for a given signer DID.
    struct Fx {
        att: KeyPackageAttestation,
        credential: ScpCredential,
        leaf_sig: [u8; 32],
        leaf_enc: [u8; 32],
        leaf_wrap: [u8; 32],
        kp_init: [u8; 32],
        signer_pub: [u8; 32],
    }

    impl Fx {
        fn ground_truth(&self) -> AttestationAddGroundTruth<'_> {
            AttestationAddGroundTruth {
                credential: &self.credential,
                leaf_signature_key: &self.leaf_sig,
                leaf_encryption_key: &self.leaf_enc,
                leaf_wrapping_key: &self.leaf_wrap,
                leaf_lifetime_not_before: ISSUED,
                leaf_lifetime_not_after: EXPIRES,
                kp_init_key: &self.kp_init,
            }
        }
    }

    /// A signed Add fixture whose signer DID is `did`. The credential fields are
    /// set directly (bypassing `ScpCredential::new`'s prefix validation) so a
    /// `did:web:` signer can be modeled for the carve-out negative test.
    fn add_fixture(did: &str) -> Fx {
        let signer = SigningKey::generate(&mut OsRng);
        let signer_pub = signer.verifying_key().to_bytes();
        let leaf_sig = fresh_pub();
        let leaf_enc = fresh_pub();
        let leaf_wrap = fresh_pub();
        let kp_init = fresh_pub();
        let mut att = KeyPackageAttestation {
            did: did.to_owned(),
            leaf_signature_key: leaf_sig,
            leaf_encryption_key: leaf_enc,
            init_key: kp_init,
            wrapping_key: leaf_wrap,
            signing_key_id: SigningKeyId::Active,
            issued_at: ISSUED,
            expires_at: EXPIRES,
            signature: [0u8; 64],
        };
        att.signature = signer.sign(&att.signing_hash()).to_bytes();
        let credential = ScpCredential {
            did: did.to_owned(),
            ucan_token: None,
            signing_key_id: SigningKeyId::Active,
        };
        Fx {
            att,
            credential,
            leaf_sig,
            leaf_enc,
            leaf_wrap,
            kp_init,
            signer_pub,
        }
    }

    // -- AC5/AC7: resolve success + fresh + current key → Ok, honest resolved_at

    #[tokio::test]
    async fn resolve_success_fresh_current_key_ok() {
        let fx = add_fixture(TEST_DID);
        let resolver = MockResolver::new(MockOutcome::Found(did_doc_with_active(&fx.signer_pub)));
        let clock = FixedClock(NOW);

        let result = verify_add_attestation(
            Some(&resolver as &dyn DidDocumentResolver),
            &clock,
            &fx.att,
            &fx.ground_truth(),
        )
        .await;

        assert!(result.is_ok(), "expected Ok, got {result:?}");
        assert!(resolver.was_called(), "a did:dht: signer MUST be resolved");
    }

    #[tokio::test]
    async fn resolved_at_is_captured_at_the_earlier_resolve_read_not_the_later() {
        // AC7 (strengthened): prove `resolved_at` is the FIRST clock read (at the
        // resolve call), not the second (`now`). A two-value clock returns
        // `t0 = NOW` for the resolved_at read and `t1 = NOW + 400` for the `now`
        // read. Layer A then sees `age = now - resolved_at = 400 > 300` and MUST
        // reject with ResolvedDocumentStale{age_secs: 400}. This is impossible if
        // resolved_at were the later read (age 0), a fabricated constant, or equal
        // to `now` — so it uniquely pins resolved_at = the earlier resolve-time
        // read and `now` = the later read. (The everything-fresh Ok case is
        // covered by `resolve_success_fresh_current_key_ok`.)
        let fx = add_fixture(TEST_DID);
        let resolver = MockResolver::new(MockOutcome::Found(did_doc_with_active(&fx.signer_pub)));
        let clock = SteppingClock::new(vec![NOW, NOW + 400]);

        let err = verify_add_attestation(
            Some(&resolver as &dyn DidDocumentResolver),
            &clock,
            &fx.att,
            &fx.ground_truth(),
        )
        .await
        .unwrap_err();

        assert!(
            matches!(
                err,
                AttestationRuntimeVerifyError::Verify(
                    AttestationResolutionVerifyError::ResolvedDocumentStale { age_secs: 400 }
                )
            ),
            "resolved_at must be the earlier (resolve-time) read; expected stale age 400, got {err:?}"
        );
        assert!(resolver.was_called());
    }

    // -- Layer-B rotation reject: the RESOLVED doc drives check 3 ---------------

    #[tokio::test]
    async fn resolved_rotated_key_drives_check3_signature_invalid() {
        // The injected resolver returns a document whose #active VM holds a
        // DIFFERENT key than the attestation's signer (a rotated / wrong current
        // key). Check 1 passes (an #active VM exists), but the delegated pure
        // core's check 3 fails: the signature does not verify against the
        // RESOLVED current key. This proves the resolved document — not some
        // ignored default — drives check 3 at the runtime layer (§9.12
        // rotation-is-revocation).
        let fx = add_fixture(TEST_DID);
        let rotated_doc = did_doc_with_active(&fresh_pub()); // NOT fx.signer_pub
        let resolver = MockResolver::new(MockOutcome::Found(rotated_doc));
        let clock = FixedClock(NOW);

        let err = verify_add_attestation(
            Some(&resolver as &dyn DidDocumentResolver),
            &clock,
            &fx.att,
            &fx.ground_truth(),
        )
        .await
        .unwrap_err();

        assert!(
            matches!(
                err,
                AttestationRuntimeVerifyError::Verify(AttestationResolutionVerifyError::Delegated(
                    AttestationVerifyError::SignatureInvalid
                ))
            ),
            "the resolved (rotated) key must drive check 3 → SignatureInvalid, got {err:?}"
        );
        assert!(resolver.was_called());
    }

    // -- AC6: Add fail-closed on resolution failure (Err / None), no fallback ---

    #[tokio::test]
    async fn add_resolution_error_is_fail_closed_reject() {
        let fx = add_fixture(TEST_DID);
        let resolver = MockResolver::new(MockOutcome::Error);
        let clock = FixedClock(NOW);

        let err = verify_add_attestation(
            Some(&resolver as &dyn DidDocumentResolver),
            &clock,
            &fx.att,
            &fx.ground_truth(),
        )
        .await
        .unwrap_err();

        assert!(
            matches!(err, AttestationRuntimeVerifyError::Resolution(_)),
            "resolve Err on Add must fail closed with a typed reject, got {err:?}"
        );
        assert!(resolver.was_called());
    }

    #[tokio::test]
    async fn add_resolution_not_found_is_fail_closed_reject() {
        let fx = add_fixture(TEST_DID);
        let resolver = MockResolver::new(MockOutcome::NotFound);
        let clock = FixedClock(NOW);

        let err = verify_add_attestation(
            Some(&resolver as &dyn DidDocumentResolver),
            &clock,
            &fx.att,
            &fx.ground_truth(),
        )
        .await
        .unwrap_err();

        assert!(
            matches!(err, AttestationRuntimeVerifyError::ResolutionNotFound),
            "resolve Ok(None) on Add must fail closed with a typed reject, got {err:?}"
        );
        assert!(resolver.was_called());
    }

    // -- AC8: testing carve-out — did:test: skips resolution, did:web: does not -

    #[tokio::test]
    async fn testing_carveout_did_test_skips_resolution() {
        // Under the `testing`/`cfg(test)` gate, a did:test: signer is accepted
        // WITHOUT resolution. The resolver would ERROR if consulted, so an Ok
        // result proves resolution was skipped.
        let fx = add_fixture("did:test:carveout");
        let resolver = MockResolver::new(MockOutcome::Error);
        let clock = FixedClock(NOW);

        let result = verify_add_attestation(
            Some(&resolver as &dyn DidDocumentResolver),
            &clock,
            &fx.att,
            &fx.ground_truth(),
        )
        .await;

        assert!(result.is_ok(), "did:test: signer must skip resolution");
        assert!(
            !resolver.was_called(),
            "carve-out MUST NOT resolve a did:test: signer"
        );
    }

    #[tokio::test]
    async fn testing_carveout_did_key_skips_resolution() {
        let fx = add_fixture("did:key:z6MkCarveout");
        let resolver = MockResolver::new(MockOutcome::Error);
        let clock = FixedClock(NOW);

        let result = verify_add_attestation(
            Some(&resolver as &dyn DidDocumentResolver),
            &clock,
            &fx.att,
            &fx.ground_truth(),
        )
        .await;

        assert!(result.is_ok(), "did:key: signer must skip resolution");
        assert!(!resolver.was_called());
    }

    #[tokio::test]
    async fn testing_carveout_does_not_exempt_did_web() {
        // did:web: is NOT on the positive whitelist: it MUST be resolved (and
        // here fails closed because the mock resolver errors). This pins that the
        // carve-out is not keyed on a blanket non-dht rule.
        let fx = add_fixture("did:web:example.com");
        let resolver = MockResolver::new(MockOutcome::Error);
        let clock = FixedClock(NOW);

        let err = verify_add_attestation(
            Some(&resolver as &dyn DidDocumentResolver),
            &clock,
            &fx.att,
            &fx.ground_truth(),
        )
        .await
        .unwrap_err();

        assert!(
            resolver.was_called(),
            "did:web: MUST be resolved (not exempt from the carve-out)"
        );
        assert!(matches!(err, AttestationRuntimeVerifyError::Resolution(_)));
    }
}
