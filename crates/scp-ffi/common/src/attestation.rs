//! Shared identity link attestation construction and verification for FFI
//! bridges.
//!
//! All FFI bridges (`PyO3`, napi-rs, `UniFFI`) create identity link
//! attestations with identical logic: parse verification method, compute the
//! attestation ID, build the unsigned struct, validate structure, and compute
//! canonical signing bytes. [`build_unsigned_attestation`] holds that pipeline
//! so each bridge only handles custody access, signing, and storage — the
//! bridge-specific parts.
//!
//! All three bridges also verify identity link attestations with identical
//! logic. [`verify_link_attestation`] holds that flow, and each bridge supplies
//! only its own per-instance DID resolver and maps [`LinkVerifyError`] onto its
//! own error type.
//!
//! Gated behind the `resolvers` feature.
//!
//! See spec §3.5.1, §3.5.2, §3.5.4.

use std::borrow::Cow;
use std::fmt;

use scp_core::identity::attestation::{
    ATTESTATION_TYPE_IDENTITY_LINK, AttestationClaim, AttestationEvidence, IdentityLinkAttestation,
    VerificationMethod,
};
use scp_core::trust::attestation::RevocationStatus;
use scp_did::DID;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from the shared attestation construction pipeline.
///
/// Each bridge converts this to its own error type (e.g. `ScpPyError`,
/// `ScpNapiError`, `ScpError`).
#[derive(Debug)]
pub enum AttestationBuildError {
    /// The verification method string could not be parsed.
    InvalidMethod(String),
    /// The system clock is before the UNIX epoch.
    ClockError,
    /// Structural validation of the attestation failed.
    StructureValidation(String),
    /// Computing canonical signing bytes failed.
    Canonicalization(String),
}

impl fmt::Display for AttestationBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMethod(e) => write!(f, "{e}"),
            Self::ClockError => write!(f, "system clock is before UNIX epoch"),
            Self::StructureValidation(e) => {
                write!(f, "attestation structure validation failed: {e}")
            }
            Self::Canonicalization(e) => write!(f, "attestation signing failed: {e}"),
        }
    }
}

impl std::error::Error for AttestationBuildError {}

// ---------------------------------------------------------------------------
// Builder result
// ---------------------------------------------------------------------------

/// Result of [`build_unsigned_attestation`]: an unsigned attestation and the
/// canonical bytes that must be signed to complete it.
pub struct UnsignedAttestation {
    /// The attestation with an empty `signature` field.
    pub attestation: IdentityLinkAttestation,
    /// The canonical bytes to sign with the identity's active signing key.
    pub canonical_bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Shared construction pipeline
// ---------------------------------------------------------------------------

/// Builds an unsigned [`IdentityLinkAttestation`] and computes its canonical
/// signing bytes.
///
/// This is the shared logic across all FFI bridges. After calling this, the
/// bridge must:
/// 1. Sign `canonical_bytes` with the identity's active signing key.
/// 2. Set `attestation.signature` to the signature bytes.
/// 3. Store the attestation in the bridge-specific registry.
///
/// # Arguments
///
/// * `did` — The DID string of the attesting identity.
/// * `platform` — Platform identifier (e.g., `"github.com"`, `"x.com"`).
/// * `handle` — Handle on the platform (e.g., `"@alice"`, `"alice123"`).
/// * `proof` — Method-specific proof data (e.g., OAuth JWT, post URL).
///   Opaque string per §3.5.2 — passed through as-is.
/// * `verification_method` — One of `"oauth"`, `"signed_post"`, `"dns_record"`,
///   `"challenge_response"`.
/// * `platform_id` — Optional platform-specific immutable user ID.
///
/// # Errors
///
/// Returns [`AttestationBuildError`] if the verification method is invalid,
/// the system clock is before the UNIX epoch, structural validation fails,
/// or canonical byte computation fails.
pub fn build_unsigned_attestation(
    did: &str,
    platform: String,
    handle: String,
    proof: String,
    verification_method: &str,
    platform_id: Option<String>,
) -> Result<UnsignedAttestation, AttestationBuildError> {
    let method: VerificationMethod = verification_method
        .parse()
        .map_err(AttestationBuildError::InvalidMethod)?;

    let issuer = DID::from(did);
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| AttestationBuildError::ClockError)?
        .as_secs();

    let id = IdentityLinkAttestation::compute_id(&issuer, &platform, &handle, now_secs);

    let attestation = IdentityLinkAttestation {
        id,
        attestation_type: Cow::Borrowed(ATTESTATION_TYPE_IDENTITY_LINK),
        issuer: issuer.clone(),
        subject: issuer,
        issued_at: now_secs,
        expires_at: None,
        claim: AttestationClaim::new(platform, handle, platform_id),
        evidence: AttestationEvidence {
            method,
            proof,
            verified_at: now_secs,
            verifier_did: None,
        },
        revocation_status: RevocationStatus::Active,
        signature: Vec::new(),
    };

    // Structural validation before signing.
    let structure_errors = attestation.validate_structure();
    if !structure_errors.is_empty() {
        return Err(AttestationBuildError::StructureValidation(
            structure_errors
                .iter()
                .map(AsRef::as_ref)
                .collect::<Vec<_>>()
                .join("; "),
        ));
    }

    // Compute canonical bytes for signing.
    let canonical_bytes = attestation
        .canonical_signing_bytes()
        .map_err(|e| AttestationBuildError::Canonicalization(e.to_string()))?;

    Ok(UnsignedAttestation {
        attestation,
        canonical_bytes,
    })
}

// ---------------------------------------------------------------------------
// Shared verification pipeline (spec §3.5.4)
// ---------------------------------------------------------------------------

/// Message every bridge raises from its module-level
/// `identity_verify_link_attestation` free function, alongside
/// [`IDENT_1060`](crate::error_codes::IDENT_1060).
///
/// Spec §3.5.4 step 1 makes resolution of an issuer's DID document a
/// precondition of every later verification step. Phase D (pull request #1695)
/// deleted every process-wide default bridge instance, so a module-level free
/// function reaches no per-instance DID resolver and cannot perform step 1.
/// Verifying a caller-supplied key against a caller-supplied attestation would
/// answer `true` for an attacker who supplies both, which CLAUDE.md's
/// "No dev/test-only stand-ins in production" tenet classifies as a security
/// nullifier — a false guarantee, strictly worse than an honest absence. So
/// each free function fails closed with this message and names its
/// per-instance replacement.
pub const LINK_VERIFY_REQUIRES_INSTANCE: &str = "identity link attestation verification requires a bridge instance: spec §3.5.4 \
     step 1 resolves an issuer's DID document before any signature check, and a \
     module-level free function reaches no DID resolver (phase D, #1695, deleted \
     every process-wide default bridge instance). Call a per-instance method on \
     an `SCP` instance instead: `verify_identity_link_attestation` on PyO3, \
     `identity_verify_link_attestation` on napi-rs and on UniFFI. Verifying \
     against a caller-supplied key would return true for an attacker who supplies \
     both that key and that attestation.";

/// Wire value a caller passes to report that it fetched a class 2 proof
/// resource and found an issuer's DID in that resource (spec §3.5.4 Class 2
/// step 2).
pub const REFERENCE_PROOF_CONFIRMED: &str = "confirmed";

/// Wire value a caller passes to report that it fetched no class 2 proof
/// resource.
///
/// Spec §3.5.4 Class 2 step 3 then leaves a class 2 attestation unverified, so
/// [`verify_link_attestation`] raises
/// [`LinkVerifyError::ReferenceProofNotFetched`] rather than answering `false`.
pub const REFERENCE_PROOF_NOT_FETCHED: &str = "not_fetched";

/// Turns a caller's `reference_proof` string into a
/// [`ReferenceProofOutcome`](scp_core::identity::attestation::ReferenceProofOutcome).
///
/// Every bridge passes a caller's string straight through to
/// [`verify_link_attestation`], which calls this parser, so all four SDKs
/// accept exactly [`REFERENCE_PROOF_CONFIRMED`] and
/// [`REFERENCE_PROOF_NOT_FETCHED`] and reject every other string with one
/// message.
///
/// A string rather than a bridge-specific enum type: `signed_post` and
/// `dns_record` verification already cross all three bridges as strings, and
/// one shared parser gives `PyO3`, napi-rs, and `UniFFI` an identical
/// vocabulary without three generated enum types to keep in step.
///
/// # Errors
///
/// Returns [`LinkVerifyError::MalformedArgument`] for any string other than
/// those two values, so a typo fails closed instead of selecting a default.
pub fn parse_reference_proof(
    value: &str,
) -> Result<scp_core::identity::attestation::ReferenceProofOutcome, LinkVerifyError> {
    use scp_core::identity::attestation::ReferenceProofOutcome;

    match value {
        REFERENCE_PROOF_CONFIRMED => Ok(ReferenceProofOutcome::Confirmed),
        REFERENCE_PROOF_NOT_FETCHED => Ok(ReferenceProofOutcome::NotFetched),
        other => Err(LinkVerifyError::MalformedArgument(format!(
            "reference_proof must read \"{REFERENCE_PROOF_CONFIRMED}\" when a caller fetched a \
             class 2 proof resource and found this issuer's DID in it (spec §3.5.4 Class 2 \
             step 2), or \"{REFERENCE_PROOF_NOT_FETCHED}\" when a caller fetched nothing; got \
             {other:?}"
        ))),
    }
}

/// Why [`verify_link_attestation`] could not return a verdict.
///
/// Every variant reports a condition under which no verdict is honest, so a
/// bridge raises this error rather than answering `false`. A `false` on this
/// surface reads as "this attestation is forged", and none of these conditions
/// establishes that.
///
/// [`Self::error_code`] gives each variant its `SCP-IDENT-` code, so each
/// bridge maps a variant onto its own error type by reading two fields rather
/// than by repeating a match.
#[derive(Debug)]
pub enum LinkVerifyError {
    /// A caller's `attestation_json` did not parse as an
    /// [`IdentityLinkAttestation`], or a caller's `issuer_public_key_hex` did
    /// not decode to 32 Ed25519 bytes. Carries a message naming which string
    /// failed and why.
    MalformedArgument(String),

    /// A bridge instance holds no DID resolver, so it cannot perform §3.5.4
    /// step 1. See [`LINK_VERIFY_REQUIRES_INSTANCE`] for why a module-level
    /// free function always meets this condition.
    ResolverUnavailable,

    /// A resolver reported a fault while resolving an issuer's DID document
    /// (§3.5.4 step 1).
    IssuerResolutionFailed {
        /// DID an attestation names as its issuer.
        issuer: String,
        /// Message a resolver reported.
        detail: String,
    },

    /// A resolver found no DID document for an issuer (§3.5.4 step 1).
    IssuerDocumentMissing {
        /// DID an attestation names as its issuer.
        issuer: String,
    },

    /// This host's clock reads a time before the Unix epoch, so §3.5.4 steps 4
    /// and 5 have no `now_secs` to compare against.
    ClockBeforeEpoch,

    /// An issuer's resolved DID document publishes an
    /// [`AttestationRevocations`](scp_core::identity::attestation::SERVICE_TYPE_ATTESTATION_REVOCATIONS)
    /// service endpoint, and no bridge fetches one. See
    /// [`IDENT_1061`](crate::error_codes::IDENT_1061).
    RevocationListUnread {
        /// DID an attestation names as its issuer.
        issuer: String,
        /// `serviceEndpoint` value that issuer published, so a caller fetches
        /// it without resolving that document again.
        endpoint: String,
    },

    /// A class 2 (Reference) attestation's external proof resource went
    /// unfetched. See [`IDENT_1062`](crate::error_codes::IDENT_1062).
    ReferenceProofNotFetched {
        /// Wire-format name of a verification method (§3.5.2): `signed_post`
        /// or `dns_record`.
        method: &'static str,
        /// `evidence.proof` a caller fetches for itself — a post URL for
        /// `signed_post`, a domain for `dns_record`.
        proof: String,
    },
}

impl LinkVerifyError {
    /// Returns the `SCP-IDENT-` code a bridge reports for this variant.
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::MalformedArgument(_) => crate::error_codes::IDENT_1044,
            Self::ResolverUnavailable
            | Self::IssuerResolutionFailed { .. }
            | Self::IssuerDocumentMissing { .. }
            | Self::ClockBeforeEpoch => crate::error_codes::IDENT_1060,
            Self::RevocationListUnread { .. } => crate::error_codes::IDENT_1061,
            Self::ReferenceProofNotFetched { .. } => crate::error_codes::IDENT_1062,
        }
    }
}

impl fmt::Display for LinkVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedArgument(detail) => write!(f, "{detail}"),
            Self::ResolverUnavailable => {
                write!(f, "{LINK_VERIFY_REQUIRES_INSTANCE}")
            }
            Self::IssuerResolutionFailed { issuer, detail } => write!(
                f,
                "identity link attestation verification could not resolve issuer {issuer} \
                 (spec §3.5.4 step 1): {detail}"
            ),
            Self::IssuerDocumentMissing { issuer } => write!(
                f,
                "identity link attestation verification found no DID document for issuer \
                 {issuer} (spec §3.5.4 step 1)"
            ),
            Self::ClockBeforeEpoch => write!(
                f,
                "identity link attestation verification read a system clock before the Unix \
                 epoch, so spec §3.5.4 steps 4 and 5 have no current time to compare against"
            ),
            Self::RevocationListUnread { issuer, endpoint } => write!(
                f,
                "identity link attestation verification cannot check revocation: issuer \
                 {issuer} publishes an AttestationRevocations service endpoint at {endpoint}, \
                 spec §3.5.2 requires a verifier to read that list of revoked attestation IDs \
                 regardless of an attestation's own revocation_status, and no SCP bridge \
                 fetches it. Fetch that endpoint and check whether it lists this attestation's \
                 id before granting trust."
            ),
            Self::ReferenceProofNotFetched { method, proof } => write!(
                f,
                "identity link attestation carries class 2 (reference) verification method \
                 {method}, whose proof resource {proof} no SCP bridge fetches. Spec §3.5.4 \
                 Class 2 step 3 leaves such an attestation unverified and forbids caching a \
                 negative result, so this is not a rejection. Fetch that resource, confirm the \
                 issuer's DID appears in it, and decide."
            ),
        }
    }
}

impl std::error::Error for LinkVerifyError {}

/// Runs spec §3.5.4 identity-link verification against a DID document this
/// function resolves through `resolver`.
///
/// One flow serves all three bridges (`PyO3`, napi-rs, `UniFFI`). Each bridge
/// supplies its own per-instance resolver — the one genuinely per-bridge part —
/// and maps [`LinkVerifyError`] onto its own error type through
/// [`LinkVerifyError::error_code`].
///
/// # What runs, step by step
///
/// 1. Parse `attestation_json` into an [`IdentityLinkAttestation`] and decode
///    `issuer_public_key_hex` into 32 Ed25519 bytes.
/// 2. Resolve `attestation.issuer` through `resolver` (§3.5.4 step 1).
/// 3. Reject, fail closed, when that document publishes an
///    `AttestationRevocations` service endpoint (§3.5.2 revocation check).
/// 4. Run
///    [`verify_identity_link_attestation`](scp_core::identity::attestation::verify_identity_link_attestation):
///    structural validation, document-to-issuer binding, signature under an
///    `#active` or `#agent` key that document publishes under an issuer's
///    control (§3.5.4 steps 1–2), `revocation_status` (step 3), `expires_at`
///    (step 4), and evidence freshness (step 5, which degrades rather than
///    rejects).
/// 5. Check that `issuer_public_key_hex` names a key that same document
///    publishes at `#active` or `#agent` under an issuer's control.
///
/// # What a caller still owes
///
/// Step 3 above raises a typed error rather than returning a verdict, because
/// no fetch of an issuer's revocation list happens here. A caller performs that
/// fetch and decides.
///
/// # How a caller verifies a class 2 attestation
///
/// `reference_proof` carries a caller's own class 2 fetch outcome (§3.5.4
/// Class 2 step 2), which [`parse_reference_proof`] turns into a
/// [`ReferenceProofOutcome`](scp_core::identity::attestation::ReferenceProofOutcome).
/// A caller that fetched the resource `evidence.proof` names, and found an
/// issuer's DID in that resource, passes [`REFERENCE_PROOF_CONFIRMED`] and
/// receives a `true` or a `false`. A caller that fetched nothing passes
/// [`REFERENCE_PROOF_NOT_FETCHED`] and receives
/// [`LinkVerifyError::ReferenceProofNotFetched`], because §3.5.4 Class 2 step 3
/// leaves such an attestation unverified and forbids caching a negative result.
/// Every bridge takes this argument, so Python, TypeScript, Swift, and Kotlin
/// callers all reach a class 2 verdict.
///
/// A class 1 (`did_control`) attestation ignores `reference_proof`: §3.5.4
/// Class 1 verification reads a signature and a DID document, and fetches no
/// external resource.
///
/// # Why `issuer_public_key_hex` is checked against a document
///
/// GitHub issue #2335 finding 2 recorded each bridge calling
/// `attestation.verify_signature(&caller_key)` and returning that boolean, so
/// an attacker who supplied both an attestation and a key received `true`.
/// §3.5.4 step 1 takes a signing key from an issuer's resolved DID document, so
/// a key a caller supplies is an assertion this function checks against that
/// document rather than a source of truth. Step 5 above holds a caller to that
/// assertion without asking a caller to know which of two admissible fragments
/// signed: an attestation an `#agent` key signed, presented by a caller naming
/// that issuer's `#active` key, verifies, while an attacker's unpublished key
/// does not.
///
/// # Returns
///
/// `true` when steps 4 and 5 both pass. `false` when a §3.5.4 check rejects —
/// a bad signature, a revoked or expired attestation, or a key an issuer's
/// document does not publish. Every `false` reaches `tracing` at `info` level
/// with its reason, because a boolean return carries none.
///
/// # Errors
///
/// Returns [`LinkVerifyError`] for every condition under which no verdict is
/// honest: a malformed argument, an absent resolver, an unresolvable issuer, a
/// clock before the Unix epoch, an unread revocation list, and an unfetched
/// class 2 proof resource.
pub async fn verify_link_attestation<R>(
    resolver: &R,
    attestation_json: &str,
    issuer_public_key_hex: &str,
    reference_proof: &str,
) -> Result<bool, LinkVerifyError>
where
    R: scp_identity::resolver::DidResolver + ?Sized,
{
    use scp_core::identity::attestation::{
        IdentityLinkVerifyError, IdentityLinkVerifyInput, SERVICE_TYPE_ATTESTATION_REVOCATIONS,
        published_signing_keys, verify_identity_link_attestation,
    };

    // --- 1. Parse a caller's two strings.
    let attestation: IdentityLinkAttestation =
        serde_json::from_str(attestation_json).map_err(|e| {
            LinkVerifyError::MalformedArgument(format!("failed to parse attestation JSON: {e}"))
        })?;
    let key_bytes = hex::decode(issuer_public_key_hex).map_err(|e| {
        LinkVerifyError::MalformedArgument(format!("invalid issuer_public_key_hex: {e}"))
    })?;
    let caller_key: [u8; 32] = key_bytes.as_slice().try_into().map_err(|_| {
        LinkVerifyError::MalformedArgument(format!(
            "issuer_public_key_hex must decode to 32 Ed25519 bytes, got {}",
            key_bytes.len()
        ))
    })?;
    let reference_proof = parse_reference_proof(reference_proof)?;
    let issuer: &str = (*attestation.issuer).as_ref();

    // --- 2. Resolve an issuer's DID document (§3.5.4 step 1).
    let issuer_document = resolver
        .resolve(issuer)
        .await
        .map_err(|e| LinkVerifyError::IssuerResolutionFailed {
            issuer: issuer.to_owned(),
            detail: e.to_string(),
        })?
        .ok_or_else(|| LinkVerifyError::IssuerDocumentMissing {
            issuer: issuer.to_owned(),
        })?;
    let issuer_document = &issuer_document.document;

    // --- 3. Revocation list an issuer published (§3.5.2 revocation check).
    // Fail closed BEFORE any verdict: §3.5.2 requires this check "ALWAYS
    // required regardless of `revocation_status` value", and no bridge fetches
    // the endpoint. No shipped writer publishes such a service entry today, so
    // this rejects nothing that exists; it stops a future publisher from being
    // silently ignored.
    if let Some(service) = issuer_document
        .service
        .iter()
        .find(|s| s.service_type == SERVICE_TYPE_ATTESTATION_REVOCATIONS)
    {
        return Err(LinkVerifyError::RevocationListUnread {
            issuer: issuer.to_owned(),
            endpoint: service.service_endpoint.clone(),
        });
    }

    // --- 4. Every §3.5.4 check a pure function can perform.
    //
    // Read a clock fallibly. `scp_clock::SystemClock::now_secs` panics on a
    // clock before the Unix epoch, and `scp-clock` exports no fallible read
    // (`scp_clock::now_secs` and `scp_clock::ClockError` are both private), so
    // this reads `SystemTime` directly — matching what
    // `build_unsigned_attestation` above already does.
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| LinkVerifyError::ClockBeforeEpoch)?
        .as_secs();
    match verify_identity_link_attestation(&IdentityLinkVerifyInput {
        attestation: &attestation,
        issuer_document,
        now_secs,
        reference_proof,
    }) {
        Ok(_) => {}
        // A class 2 proof resource nobody fetched leaves an attestation
        // unverified (§3.5.4 Class 2 step 3), which is not the same claim as
        // "forged". Raise rather than hand a caller a negative result that
        // §3.5.4 forbids caching.
        Err(IdentityLinkVerifyError::ReferenceProofUnverified { method }) => {
            return Err(LinkVerifyError::ReferenceProofNotFetched {
                method,
                proof: attestation.evidence.proof.clone(),
            });
        }
        Err(reason) => {
            tracing::info!(
                attestation_id = %attestation.id,
                issuer = %attestation.issuer,
                %reason,
                "identity link attestation rejected (spec §3.5.4)"
            );
            return Ok(false);
        }
    }

    // --- 5. A caller's assertion about which key signed, checked against that
    // same document. §3.5.2 admits both `#active` and `#agent`, and an
    // attestation carries no field naming which fragment signed, so requiring a
    // caller to name the exact signing key would reject an honest caller who
    // named the other admissible fragment.
    if !published_signing_keys(issuer_document, issuer)
        .iter()
        .any(|(_, key)| *key == caller_key)
    {
        tracing::info!(
            attestation_id = %attestation.id,
            issuer = %attestation.issuer,
            "identity link attestation rejected: issuer_public_key_hex names a key the \
             issuer's DID document publishes at neither #active nor #agent (spec §3.5.4 step 1)"
        );
        return Ok(false);
    }

    Ok(true)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod link_verification_tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use scp_core::identity::attestation::SERVICE_TYPE_ATTESTATION_REVOCATIONS;
    use scp_identity::resolver::{ResolutionSource, ResolvedDidDocument};

    /// Resolver that answers with one document a test supplies, or with
    /// nothing.
    struct FixedResolver(Option<scp_did::DidDocument>);

    impl scp_identity::resolver::DidResolver for FixedResolver {
        async fn resolve(
            &self,
            _did: &str,
        ) -> Result<Option<ResolvedDidDocument>, scp_identity::IdentityError> {
            Ok(self.0.clone().map(|document| ResolvedDidDocument {
                document,
                seq: 1,
                source: ResolutionSource::MainlineDht,
            }))
        }
    }

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    /// Mints a signed attestation under `signer`, naming `did_str` as issuer
    /// and subject, with `method` as its verification method.
    fn mint(did_str: &str, signer: &SigningKey, method: &str) -> IdentityLinkAttestation {
        let built = build_unsigned_attestation(
            did_str,
            "github.com".to_owned(),
            "alice".to_owned(),
            r#"{"type":"oauth_verified","provider":"github.com","subject_id":"12345","verified_at":1700000000}"#.to_owned(),
            method,
            Some("12345".to_owned()),
        )
        .expect("building an unsigned attestation must succeed");
        let mut attestation = built.attestation;
        attestation.signature = signer.sign(&built.canonical_bytes).to_bytes().to_vec();
        attestation
    }

    /// Builds a DID document for `did_str` publishing `active` at `#active`,
    /// and `agent` at `#agent` when supplied.
    fn document(
        did_str: &str,
        active: &[u8; 32],
        agent: Option<&[u8; 32]>,
    ) -> scp_did::DidDocument {
        let identity_key = signing_key(0x11).verifying_key().to_bytes();
        scp_did::DidDocument::new_with_agent_key(
            did_str,
            &identity_key,
            active,
            &[0u8; 32],
            agent.map(<[u8; 32]>::as_slice),
        )
    }

    fn run(
        resolver: &FixedResolver,
        attestation: &IdentityLinkAttestation,
        key_hex: &str,
        reference_proof: &str,
    ) -> Result<bool, LinkVerifyError> {
        let json = serde_json::to_string(attestation).unwrap();
        block_on_verify(resolver, &json, key_hex, reference_proof)
    }

    /// Drives the async shared flow to completion on this thread. `FixedResolver`
    /// never yields, so one poll of a pinned future always completes it.
    fn block_on_verify(
        resolver: &FixedResolver,
        attestation_json: &str,
        key_hex: &str,
        reference_proof: &str,
    ) -> Result<bool, LinkVerifyError> {
        use std::future::Future;
        use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

        const VTABLE: RawWakerVTable = RawWakerVTable::new(
            |_| RawWaker::new(std::ptr::null(), &VTABLE),
            |_| {},
            |_| {},
            |_| {},
        );
        // SAFETY: every vtable entry is a no-op over a null data pointer, so no
        // entry dereferences it.
        let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) };
        let mut cx = Context::from_waker(&waker);
        let future = verify_link_attestation(resolver, attestation_json, key_hex, reference_proof);
        let mut future = std::pin::pin!(future);
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(result) => result,
            Poll::Pending => panic!("FixedResolver never yields, so this future must complete"),
        }
    }

    const DID: &str = "did:dht:z6MkSharedVerifyFlow";

    #[test]
    fn accepts_a_key_the_document_publishes_at_active() {
        let active = signing_key(0xAA);
        let attestation = mint(DID, &active, "oauth");
        let resolver = FixedResolver(Some(document(
            DID,
            &active.verifying_key().to_bytes(),
            None,
        )));
        let key_hex = hex::encode(active.verifying_key().to_bytes());
        assert!(
            run(
                &resolver,
                &attestation,
                &key_hex,
                REFERENCE_PROOF_NOT_FETCHED
            )
            .unwrap()
        );
    }

    /// GitHub issue #2335 finding 2 regression pin, in the shape that finding
    /// names: an attacker supplies BOTH an attestation and the key that signs
    /// it, keeping an honest issuer's DID in the `issuer` field.
    ///
    /// A verifier that calls `attestation.verify_signature(caller_key)` and
    /// returns that boolean answers `true` here. Taking a signing key from an
    /// issuer's resolved DID document instead answers `false`. Passing a key
    /// nobody signed with does NOT exhibit that gap — a signature check
    /// rejects it either way — so this test forges rather than mutating a key.
    #[test]
    fn rejects_an_attacker_supplied_key_and_attestation() {
        let honest = signing_key(0xAA);
        let attacker = signing_key(0x07);
        let mut forged = mint(DID, &honest, "oauth");
        forged.signature = Vec::new();
        let canonical = forged.canonical_signing_bytes().unwrap();
        forged.signature = attacker.sign(&canonical).to_bytes().to_vec();

        assert!(
            forged
                .verify_signature(&attacker.verifying_key().to_bytes())
                .is_ok(),
            "the forgery must verify under an attacker's own key, or this test exercises nothing"
        );

        let resolver = FixedResolver(Some(document(
            DID,
            &honest.verifying_key().to_bytes(),
            None,
        )));
        let attacker_hex = hex::encode(attacker.verifying_key().to_bytes());
        assert!(
            !run(
                &resolver,
                &forged,
                &attacker_hex,
                REFERENCE_PROOF_NOT_FETCHED
            )
            .unwrap()
        );
    }

    /// An `#agent` key signed, and a caller named that issuer's `#active` key.
    /// An attestation carries no field naming which fragment signed, so a
    /// caller cannot know; requiring an exact match returned `false` for an
    /// honest caller. A caller's key now has to be one that document
    /// publishes, which keeps an attacker's key failing.
    #[test]
    fn accepts_a_published_sibling_fragment_key() {
        let active = signing_key(0xAA);
        let agent = signing_key(0xBB);
        let attestation = mint(DID, &agent, "oauth");
        let resolver = FixedResolver(Some(document(
            DID,
            &active.verifying_key().to_bytes(),
            Some(&agent.verifying_key().to_bytes()),
        )));
        let active_hex = hex::encode(active.verifying_key().to_bytes());
        assert!(
            run(
                &resolver,
                &attestation,
                &active_hex,
                REFERENCE_PROOF_NOT_FETCHED
            )
            .unwrap(),
            "an #agent-signed attestation presented with a published #active key must verify"
        );
    }

    #[test]
    fn rejects_a_tampered_attestation() {
        let active = signing_key(0xAA);
        let mut attestation = mint(DID, &active, "oauth");
        attestation.claim.platform_handle = "mallory".to_owned();
        let resolver = FixedResolver(Some(document(
            DID,
            &active.verifying_key().to_bytes(),
            None,
        )));
        let key_hex = hex::encode(active.verifying_key().to_bytes());
        assert!(
            !run(
                &resolver,
                &attestation,
                &key_hex,
                REFERENCE_PROOF_NOT_FETCHED
            )
            .unwrap()
        );
    }

    /// Spec §3.5.2 requires a verifier to read an issuer's
    /// `AttestationRevocations` endpoint, and no bridge fetches one, so a
    /// document publishing one yields a typed error rather than a verdict.
    #[test]
    fn fails_closed_when_an_issuer_publishes_a_revocation_endpoint() {
        let active = signing_key(0xAA);
        let attestation = mint(DID, &active, "oauth");
        let mut doc = document(DID, &active.verifying_key().to_bytes(), None);
        doc.service.push(scp_did::Service {
            id: format!("{DID}#scp-attestation-revocations"),
            service_type: SERVICE_TYPE_ATTESTATION_REVOCATIONS.to_owned(),
            service_endpoint: "https://relay.example.com/scp/v1/revocations/alice".to_owned(),
        });
        let resolver = FixedResolver(Some(doc));
        let key_hex = hex::encode(active.verifying_key().to_bytes());

        match run(
            &resolver,
            &attestation,
            &key_hex,
            REFERENCE_PROOF_NOT_FETCHED,
        ) {
            Err(LinkVerifyError::RevocationListUnread { issuer, endpoint }) => {
                assert_eq!(issuer, DID);
                assert_eq!(
                    endpoint,
                    "https://relay.example.com/scp/v1/revocations/alice"
                );
            }
            other => panic!("expected RevocationListUnread, got {other:?}"),
        }
        let err = run(
            &resolver,
            &attestation,
            &key_hex,
            REFERENCE_PROOF_NOT_FETCHED,
        )
        .unwrap_err();
        assert_eq!(err.error_code(), crate::error_codes::IDENT_1061);
    }

    /// Spec §3.5.4 Class 2 step 3 forbids caching a negative result for an
    /// unfetched reference proof, and `false` on this surface is exactly that
    /// negative result, so a class 2 attestation raises instead.
    #[test]
    fn raises_rather_than_reporting_false_for_an_unfetched_reference_proof() {
        let active = signing_key(0xAA);
        let attestation = mint(DID, &active, "dns_record");
        let resolver = FixedResolver(Some(document(
            DID,
            &active.verifying_key().to_bytes(),
            None,
        )));
        let key_hex = hex::encode(active.verifying_key().to_bytes());

        match run(
            &resolver,
            &attestation,
            &key_hex,
            REFERENCE_PROOF_NOT_FETCHED,
        ) {
            Err(LinkVerifyError::ReferenceProofNotFetched { method, .. }) => {
                assert_eq!(method, "dns_record");
            }
            other => panic!("expected ReferenceProofNotFetched, got {other:?}"),
        }
        let err = run(
            &resolver,
            &attestation,
            &key_hex,
            REFERENCE_PROOF_NOT_FETCHED,
        )
        .unwrap_err();
        assert_eq!(err.error_code(), crate::error_codes::IDENT_1062);
    }

    /// A caller that fetched a class 2 proof resource, and found an issuer's
    /// DID in it, reports [`REFERENCE_PROOF_CONFIRMED`] and receives a verdict.
    /// Before `reference_proof` reached this flow, every class 2 attestation
    /// raised `SCP-IDENT-1062` through all four SDKs, so no SDK caller could
    /// obtain a `true` for one. Reverting `reference_proof` to a hardcoded
    /// `NotFetched` turns this assertion into that same error.
    #[test]
    fn a_confirmed_reference_proof_verifies_a_class_2_attestation() {
        let active = signing_key(0xAA);
        let attestation = mint(DID, &active, "dns_record");
        let resolver = FixedResolver(Some(document(
            DID,
            &active.verifying_key().to_bytes(),
            None,
        )));
        let key_hex = hex::encode(active.verifying_key().to_bytes());

        assert!(
            run(&resolver, &attestation, &key_hex, REFERENCE_PROOF_CONFIRMED).unwrap(),
            "a class 2 attestation whose proof a caller confirmed must verify"
        );
    }

    /// A confirmed class 2 proof reports one fetch outcome; it does not stand
    /// in for a signature. A tampered class 2 attestation stays rejected.
    #[test]
    fn a_confirmed_reference_proof_still_rejects_a_tampered_class_2_attestation() {
        let active = signing_key(0xAA);
        let mut attestation = mint(DID, &active, "dns_record");
        attestation.claim.platform_handle = "mallory".to_owned();
        let resolver = FixedResolver(Some(document(
            DID,
            &active.verifying_key().to_bytes(),
            None,
        )));
        let key_hex = hex::encode(active.verifying_key().to_bytes());

        assert!(
            !run(&resolver, &attestation, &key_hex, REFERENCE_PROOF_CONFIRMED).unwrap(),
            "a confirmed proof fetch must not excuse a broken signature"
        );
    }

    /// A `reference_proof` string outside the two admissible values selects no
    /// default. It raises `SCP-IDENT-1044`, so a caller who misspells
    /// `confirmed` never receives a silent `not_fetched` verdict.
    #[test]
    fn an_unknown_reference_proof_value_fails_closed() {
        let active = signing_key(0xAA);
        let attestation = mint(DID, &active, "oauth");
        let resolver = FixedResolver(Some(document(
            DID,
            &active.verifying_key().to_bytes(),
            None,
        )));
        let key_hex = hex::encode(active.verifying_key().to_bytes());

        let err = run(&resolver, &attestation, &key_hex, "Confirmed").unwrap_err();
        assert!(matches!(err, LinkVerifyError::MalformedArgument(_)));
        assert_eq!(err.error_code(), crate::error_codes::IDENT_1044);
    }

    #[test]
    fn raises_when_an_issuer_has_no_document() {
        let active = signing_key(0xAA);
        let attestation = mint(DID, &active, "oauth");
        let resolver = FixedResolver(None);
        let key_hex = hex::encode(active.verifying_key().to_bytes());

        let err = run(
            &resolver,
            &attestation,
            &key_hex,
            REFERENCE_PROOF_NOT_FETCHED,
        )
        .unwrap_err();
        assert!(matches!(err, LinkVerifyError::IssuerDocumentMissing { .. }));
        assert_eq!(err.error_code(), crate::error_codes::IDENT_1060);
    }

    #[test]
    fn raises_on_a_malformed_argument() {
        let resolver = FixedResolver(None);
        let err = block_on_verify(
            &resolver,
            "not json",
            &"00".repeat(32),
            REFERENCE_PROOF_NOT_FETCHED,
        )
        .unwrap_err();
        assert!(matches!(err, LinkVerifyError::MalformedArgument(_)));
        assert_eq!(err.error_code(), crate::error_codes::IDENT_1044);

        let attestation = mint(DID, &signing_key(0xAA), "oauth");
        let json = serde_json::to_string(&attestation).unwrap();
        let err = block_on_verify(&resolver, &json, "zz", REFERENCE_PROOF_NOT_FETCHED).unwrap_err();
        assert_eq!(err.error_code(), crate::error_codes::IDENT_1044);

        let err = block_on_verify(&resolver, &json, "00", REFERENCE_PROOF_NOT_FETCHED).unwrap_err();
        assert_eq!(err.error_code(), crate::error_codes::IDENT_1044);
    }

    #[test]
    fn an_absent_resolver_carries_the_precondition_code() {
        assert_eq!(
            LinkVerifyError::ResolverUnavailable.error_code(),
            crate::error_codes::IDENT_1060
        );
        assert_eq!(
            LinkVerifyError::ResolverUnavailable.to_string(),
            LINK_VERIFY_REQUIRES_INSTANCE
        );
    }
}
