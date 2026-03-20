//! UCAN token minting and delegation for SCP.
//!
//! Creates, signs, and delegates UCAN tokens with Ed25519 signatures, nonce
//! generation, and capability attestation construction. Tokens are scoped to a
//! specific context and audience (member DID).
//!
//! # Minting
//!
//! [`mint_ucan`] creates a new root UCAN token signed by the context creator.
//! The token includes a unique nonce, capability attestations scoped to a
//! context, and an Ed25519 signature.
//!
//! # Delegation
//!
//! [`delegate_ucan`] creates a delegated UCAN from an existing parent token.
//! Delegation enforces attenuation (capabilities can only narrow, never widen)
//! and links to the parent via its CID in the proof chain.
//!
//! # CID computation
//!
//! [`compute_cid`] produces a content identifier for a UCAN token, used as the
//! key in proof chains (`prf`) and revocation lists. The CID is a SHA-256 hash
//! of the encoded JWT, multibase-encoded with a `bafyrei` prefix following the
//! CID v1 / raw codec / sha2-256 convention.
//!
//! See ADR-009 in `.docs/adrs/phase-2.md` and ADR-016 in `.docs/adrs/phase-3.md`.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

use scp_platform::traits::{KeyCustody, KeyHandle};

use std::collections::HashSet;

use super::capability::{CapabilityUri, verify_ceiling_compliance};
use super::nonce::generate_nonce;
use super::{Attenuation, UcanError, UcanHeader, UcanPayload, UcanToken};
use crate::identity::SigningKeyId;

/// Maximum token lifetime: 24 hours in seconds (spec section 9.5).
const MAX_EXPIRY_SECS: u64 = 24 * 60 * 60;

/// Validates `key_scope` format: must start with `#` (verification method fragment).
///
/// Returns `Ok(())` if `key_scope` is `None` or a valid fragment.
fn validate_key_scope(key_scope: Option<&String>) -> Result<(), UcanError> {
    if let Some(scope) = key_scope
        && !scope.starts_with('#')
    {
        return Err(UcanError::MalformedToken(format!(
            "key_scope must be a verification method fragment starting with '#', got: {scope}"
        )));
    }
    Ok(())
}

/// Rejects self-delegation (iss == aud) without `key_scope` (ADR-039).
///
/// Self-delegation is the mechanism for human-to-agent key delegation on the
/// same DID. Without `key_scope`, such tokens always fail validation.
fn reject_self_delegation_without_scope(
    issuer: &str,
    audience: &str,
    key_scope: Option<&String>,
) -> Result<(), UcanError> {
    if issuer == audience && key_scope.is_none() {
        return Err(UcanError::MalformedToken(
            "self-delegation (iss == aud) requires key_scope (ADR-039)".to_owned(),
        ));
    }
    Ok(())
}

/// Verifies that attestation capability URIs are within the ceiling.
///
/// Parses each attestation's `with` field as a [`CapabilityUri`] and checks
/// it against the ceiling set. Returns an error if any capability is outside
/// the ceiling or if any URI is unparseable.
fn verify_attestation_ceiling_compliance(
    attenuations: &[Attenuation],
    ceiling: &HashSet<String>,
) -> Result<(), UcanError> {
    let cap_uris: Vec<CapabilityUri> = attenuations
        .iter()
        .map(|att| {
            att.with.parse::<CapabilityUri>().map_err(|e: UcanError| {
                UcanError::AttenuationViolation(format!(
                    "invalid capability URI '{}': {e}",
                    att.with
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    verify_ceiling_compliance(&cap_uris, ceiling)
}

/// Builds the `fct` (facts) section, merging `scp_key_scope` when present.
///
/// Returns an error if `facts` already contains an `scp_key_scope` value that
/// conflicts with the `key_scope` parameter.
fn build_facts_with_key_scope(
    facts: Option<&serde_json::Value>,
    key_scope: Option<&String>,
) -> Result<Option<serde_json::Value>, UcanError> {
    match key_scope {
        Some(scope) => {
            let mut facts_obj = match facts {
                Some(serde_json::Value::Object(map)) => map.clone(),
                Some(val) => {
                    // If facts is a non-object value, wrap it: preserve the
                    // original under "_original" and add scp_key_scope at the
                    // top level. This is defensive — callers should pass objects.
                    let mut map = serde_json::Map::new();
                    map.insert("_original".to_owned(), val.clone());
                    map
                }
                None => serde_json::Map::new(),
            };
            let old = facts_obj.insert(
                "scp_key_scope".to_owned(),
                serde_json::Value::String(scope.clone()),
            );
            if old
                .as_ref()
                .is_some_and(|existing| *existing != serde_json::Value::String(scope.clone()))
            {
                return Err(UcanError::MalformedToken(
                    "facts.scp_key_scope conflicts with key_scope parameter".to_owned(),
                ));
            }
            Ok(Some(serde_json::Value::Object(facts_obj)))
        }
        None => Ok(facts.cloned()),
    }
}

/// Parameters for minting a new UCAN token.
///
/// Encapsulates the inputs needed by [`mint_ucan`] to create a signed UCAN
/// token. The caller provides the issuer's signing key handle, the audience
/// DID, the context ID, the capabilities to grant, and the desired expiry.
///
/// # Key scope delegation (ADR-039)
///
/// When `key_scope` is set (e.g., `Some("#agent".to_owned())`), the minted
/// token includes:
/// - `kid` in the JWT header — identifies which verification method signed
///   the token (RFC 7515).
/// - `scp_key_scope` in the `fct` (facts) section — scopes the delegation
///   to the specified key.
///
/// Self-delegation (`iss == aud`, same DID) with `key_scope` is explicitly
/// valid per ADR-039 acceptance criterion 8. This is the mechanism by which
/// a human delegates permissions to their agent key on the same DID.
///
/// See ADR-016 acceptance criterion 3 and ADR-039 acceptance criterion 6.
pub struct MintParams<'a> {
    /// The issuer's DID string (context creator).
    pub issuer_did: &'a str,
    /// Handle to the issuer's Ed25519 signing key (managed by [`KeyCustody`]).
    pub issuer_key: &'a KeyHandle,
    /// The audience DID (the member receiving this token).
    pub audience_did: &'a str,
    /// The context ID this token is scoped to.
    pub context_id: &'a str,
    /// Capabilities to grant, as `{resource}:{action}` strings (e.g.,
    /// `"messages:write"`, `"tool_invoke:assistant"`).
    pub capabilities: &'a [String],
    /// Token lifetime in seconds from now. Must not exceed 24 hours (86400s).
    pub lifetime_secs: u64,
    /// Optional not-before timestamp (Unix seconds). If `None`, the token is
    /// valid immediately.
    pub not_before: Option<u64>,
    /// Optional proof chain CIDs (for delegated tokens).
    pub proofs: Vec<String>,
    /// Optional facts to attach to the token.
    pub facts: Option<serde_json::Value>,
    /// Optional key scope for key-specific delegation (ADR-039).
    ///
    /// When set, identifies which verification method on the issuer's DID
    /// document this token is scoped to (e.g., `"#active"` or `"#agent"`).
    /// The value is included as `scp_key_scope` in the payload `fct` section
    /// and also sets `kid` in the JWT header (unless overridden by
    /// `signing_key_id`).
    ///
    /// Self-delegation (`iss == aud`) is valid when `key_scope` is present.
    pub key_scope: Option<String>,
    /// Optional signing key identity for the JWT `kid` header (ADR-039).
    ///
    /// When set, explicitly identifies which verification method signed this
    /// token. This ensures agent-signed UCANs have `kid: "#agent"` in the
    /// header, enabling Category A enforcement during validation.
    ///
    /// If both `signing_key_id` and `key_scope` are set, `signing_key_id`
    /// takes precedence for the `kid` header value, while `key_scope` is
    /// still used for the `scp_key_scope` fact.
    ///
    /// If neither is set, the header has no `kid` field, which verifiers
    /// interpret as `#active` (the default human key).
    pub signing_key_id: Option<SigningKeyId>,
    /// Optional capability ceiling for the context (§5.3, ADR-016 step 8).
    ///
    /// When set, the requested capabilities are checked against the ceiling
    /// **before** the token is signed. Any capability not in the ceiling is
    /// rejected with [`UcanError::CapabilityOutsideCeiling`].
    ///
    /// The ceiling contains `{resource}:{action}` strings (e.g.,
    /// `"messages:read"`, `"tool_invoke:assistant"`).
    ///
    /// `None` means no ceiling enforcement (backward-compatible default).
    pub ceiling: Option<HashSet<String>>,
}

/// Returns the current Unix timestamp in seconds.
///
/// # Errors
///
/// Returns [`UcanError::ClockError`] if the system clock is before the Unix
/// epoch. Defaulting to zero would silently produce expired tokens.
fn now_secs() -> Result<u64, UcanError> {
    crate::time::now_secs().map_err(UcanError::from)
}

/// Mints a new UCAN token with Ed25519 signature.
///
/// Creates a complete UCAN token from the provided parameters: constructs
/// the JWT header and payload, generates a unique nonce, builds capability
/// attestations in the `scp:ctx:{context_id}/{capability}` format, encodes
/// the token as a JWT, and signs it with the issuer's Ed25519 key.
///
/// # Token structure
///
/// The minted token is a JWT with three base64url-encoded segments:
/// `base64url(header).base64url(payload).base64url(signature)`.
///
/// # Expiry constraint
///
/// The `lifetime_secs` must not exceed 24 hours (86400 seconds) per spec
/// section 9.5. If exceeded, returns [`UcanError::ExpiryTooFar`].
///
/// # Errors
///
/// Returns [`UcanError::ClockError`] if the system clock is before the Unix epoch.
/// Returns [`UcanError::ExpiryTooFar`] if `lifetime_secs` exceeds 24 hours.
/// Returns [`UcanError::MalformedToken`] if serialization or signing fails.
///
/// See ADR-016 acceptance criterion 3 and ADR-039 acceptance criterion 6.
pub async fn mint_ucan(
    params: &MintParams<'_>,
    custody: &impl KeyCustody,
) -> Result<UcanToken, UcanError> {
    validate_key_scope(params.key_scope.as_ref())?;
    reject_self_delegation_without_scope(
        params.issuer_did,
        params.audience_did,
        params.key_scope.as_ref(),
    )?;

    // Enforce 24-hour maximum expiry.
    if params.lifetime_secs > MAX_EXPIRY_SECS {
        return Err(UcanError::ExpiryTooFar(params.lifetime_secs));
    }

    // Convert capability strings to UCAN resource/action pairs. This bridges
    // the canonical user-facing colon format (e.g. "tool:invoke:*") to the
    // UCAN underscore format (e.g. resource="tool_invoke", action="*") by
    // parsing through the Capability enum. See #1293.
    let parsed_caps: Vec<(String, String)> = params
        .capabilities
        .iter()
        .map(|cap| {
            let capability = crate::context::roles::Capability::new(cap);
            let (resource, action) = capability.ucan_resource_action();
            (resource.into_owned(), action.into_owned())
        })
        .collect();

    // Enforce ceiling compliance before doing any work (§5.3, #339).
    // Defense-in-depth: when no explicit ceiling is provided, apply the
    // protocol default ceiling so that capabilities outside the standard
    // set are always rejected at the core layer.
    let effective_ceiling = params
        .ceiling
        .clone()
        .unwrap_or_else(|| crate::context::roles::default_ceiling().to_ucan_string_set());
    {
        let cap_uris: Vec<CapabilityUri> = parsed_caps
            .iter()
            .map(|(resource, action)| {
                CapabilityUri::new(params.context_id, resource.as_str(), action.as_str())
            })
            .collect();
        verify_ceiling_compliance(&cap_uris, &effective_ceiling)?;
    }

    let now = now_secs()?;
    let exp = now + params.lifetime_secs;

    // Build attestations from capabilities, scoped to the context.
    // Uses UCAN resource/action format for correct URI construction (#1293).
    let att: Vec<Attenuation> = parsed_caps
        .iter()
        .map(|(resource, action)| {
            let ucan_cap = format!("{resource}:{action}");
            Attenuation {
                with: format!("scp:ctx:{}/{ucan_cap}", params.context_id),
                can: action.clone(),
            }
        })
        .collect();

    // Build header — include kid when signing_key_id or key_scope is present
    // (ADR-039). signing_key_id takes precedence over key_scope for the kid
    // header value.
    let header = params.signing_key_id.as_ref().map_or_else(
        || {
            params
                .key_scope
                .as_ref()
                .map_or_else(UcanHeader::new, |scope| UcanHeader::with_kid(scope.clone()))
        },
        |signing_key_id| UcanHeader::with_kid(signing_key_id.as_fragment().to_owned()),
    );

    // Build facts — merge scp_key_scope into existing facts when key_scope
    // is present (ADR-039 acceptance criterion 6).
    let fct = build_facts_with_key_scope(params.facts.as_ref(), params.key_scope.as_ref())?;

    let payload = UcanPayload {
        iss: params.issuer_did.to_owned(),
        aud: params.audience_did.to_owned(),
        exp,
        nbf: params.not_before,
        nnc: generate_nonce()?,
        att,
        prf: params.proofs.clone(),
        fct,
    };

    // Encode header and payload as base64url JSON.
    let header_json = serde_json::to_vec(&header)
        .map_err(|e| UcanError::MalformedToken(format!("header serialization failed: {e}")))?;
    let payload_json = serde_json::to_vec(&payload)
        .map_err(|e| UcanError::MalformedToken(format!("payload serialization failed: {e}")))?;

    let header_b64 = URL_SAFE_NO_PAD.encode(&header_json);
    let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);

    // The signing input is `base64url(header).base64url(payload)`.
    let signing_input = format!("{header_b64}.{payload_b64}");

    // Sign with Ed25519 via KeyCustody.
    let sig = custody
        .sign(params.issuer_key, signing_input.as_bytes())
        .await
        .map_err(|e| UcanError::MalformedToken(format!("signing failed: {e}")))?;

    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.as_bytes());
    let encoded = format!("{signing_input}.{sig_b64}");

    Ok(UcanToken {
        header,
        payload,
        signature: sig.into_bytes(),
        encoded,
    })
}

// ---------------------------------------------------------------------------
// CID computation
// ---------------------------------------------------------------------------

/// Computes the content identifier (CID) for a UCAN token.
///
/// The CID is used as the key in proof chains (`prf` field) and revocation
/// lists. It is computed as the SHA-256 hash of the encoded JWT string,
/// hex-encoded with a `bafyrei` prefix following the CID v1 / raw codec /
/// sha2-256 convention used throughout SCP.
///
/// # Determinism
///
/// The CID is deterministic: the same encoded token always produces the same
/// CID. This is critical for revocation (a revoked CID must match the token
/// it was computed from) and proof chain integrity.
///
/// See ADR-016 acceptance criteria 4 and 5.
#[must_use]
pub fn compute_cid(token: &UcanToken) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.encoded.as_bytes());
    let hash = hasher.finalize();

    let hex = hash.iter().fold(String::with_capacity(64), |mut acc, b| {
        use std::fmt::Write;
        let _ = write!(acc, "{b:02x}");
        acc
    });

    format!("bafyrei{hex}")
}

// ---------------------------------------------------------------------------
// Delegation
// ---------------------------------------------------------------------------

/// Parameters for creating a delegated UCAN token.
///
/// Encapsulates the inputs needed by [`delegate_ucan`] to create a delegated
/// UCAN. The delegator (parent token's audience) delegates a subset of their
/// capabilities to a new delegatee.
///
/// See ADR-016 acceptance criterion 4.
pub struct DelegateParams<'a> {
    /// The parent UCAN token being delegated from. The delegator must be the
    /// audience (`aud`) of this token.
    pub parent_token: &'a UcanToken,
    /// The delegator's DID — must match `parent_token.payload.aud`.
    pub delegator_did: &'a str,
    /// Handle to the delegator's Ed25519 signing key.
    pub delegator_key: &'a KeyHandle,
    /// The delegatee's DID (the entity receiving the delegated capabilities).
    pub delegatee_did: &'a str,
    /// Capabilities to delegate, as full capability URI strings
    /// (`scp:ctx:{context_id}/{resource}:{action}`). Must be a subset of the
    /// parent token's `att` (attenuation, never widening).
    pub attenuated_capabilities: &'a [Attenuation],
    /// Token lifetime in seconds from now. Must not exceed 24 hours (86400s)
    /// and should not exceed the parent token's remaining lifetime.
    pub lifetime_secs: u64,
    /// Optional facts to attach to the delegated token.
    pub facts: Option<serde_json::Value>,
    /// Optional key scope for key-specific delegation (ADR-039).
    ///
    /// When set, identifies which verification method on the delegator's DID
    /// document signed this token (e.g., `"#active"` or `"#agent"`). Included
    /// as `scp_key_scope` in the payload `fct` and also sets `kid` in the
    /// JWT header (unless overridden by `signing_key_id`).
    pub key_scope: Option<String>,
    /// Optional signing key identity for the JWT `kid` header (ADR-039).
    ///
    /// When set, explicitly identifies which verification method signed this
    /// delegated token. Takes precedence over `key_scope` for the `kid`
    /// header value.
    ///
    /// See [`MintParams::signing_key_id`] for full documentation.
    pub signing_key_id: Option<SigningKeyId>,
    /// Optional capability ceiling for the context (§5.3, ADR-016 step 8).
    ///
    /// When set, delegated capabilities are checked against the ceiling
    /// **after** the attenuation check but **before** the token is signed.
    /// Any capability not in the ceiling is rejected with
    /// [`UcanError::CapabilityOutsideCeiling`].
    ///
    /// `None` means no ceiling enforcement (backward-compatible default).
    pub ceiling: Option<HashSet<String>>,
}

/// Creates a delegated UCAN token from a parent token.
///
/// Delegation enforces the following invariants from ADR-016:
///
/// 1. **Delegator identity** — The `delegator_did` must match the parent
///    token's `aud` field. Only the intended audience of a token can delegate
///    it further.
///
/// 2. **Attenuation** — The `attenuated_capabilities` must be a subset of the
///    parent token's `att`. Delegation can only narrow capabilities, never
///    widen them. This prevents privilege escalation through delegation chains.
///
/// 3. **Proof chain** — The delegated token's `prf` field includes the parent
///    token's CID (computed via [`compute_cid`]), linking the delegation chain
///    for verification.
///
/// 4. **Signing** — The delegated token is signed with the delegator's Ed25519
///    key, proving the delegation was authorized by the parent's audience.
///
/// # Errors
///
/// Returns [`UcanError::AudienceMismatch`] if `delegator_did` does not match
/// `parent_token.payload.aud`.
/// Returns [`UcanError::AttenuationViolation`] if any capability in
/// `attenuated_capabilities` is not granted by the parent token.
/// Returns [`UcanError::ClockError`] if the system clock is before the Unix epoch.
/// Returns [`UcanError::ExpiryTooFar`] if `lifetime_secs` exceeds 24 hours.
/// Returns [`UcanError::MalformedToken`] if serialization or signing fails.
///
/// See ADR-016 acceptance criterion 4.
pub async fn delegate_ucan(
    params: &DelegateParams<'_>,
    custody: &impl KeyCustody,
) -> Result<UcanToken, UcanError> {
    validate_key_scope(params.key_scope.as_ref())?;
    reject_self_delegation_without_scope(
        params.delegator_did,
        params.delegatee_did,
        params.key_scope.as_ref(),
    )?;

    // Step 1: Verify delegator DID matches parent token's audience.
    if params.delegator_did != params.parent_token.payload.aud {
        return Err(UcanError::AudienceMismatch {
            expected: params.parent_token.payload.aud.clone(),
            actual: params.delegator_did.to_owned(),
        });
    }

    // Step 2: Verify attenuation — all requested capabilities must be a subset
    // of the parent token's capabilities (never widen).
    // SECURITY: fail-closed — any unparseable parent URI rejects the entire delegation.
    let parent_caps: Vec<CapabilityUri> = params
        .parent_token
        .payload
        .att
        .iter()
        .map(|att| {
            att.with.parse::<CapabilityUri>().map_err(|_| {
                UcanError::MalformedToken(format!(
                    "unparseable capability URI in parent token: {}",
                    att.with
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    for child_att in params.attenuated_capabilities {
        let child_cap: CapabilityUri = child_att.with.parse().map_err(|e: UcanError| {
            UcanError::AttenuationViolation(format!(
                "invalid capability URI '{}': {e}",
                child_att.with
            ))
        })?;

        let is_granted = parent_caps.iter().any(|parent| parent.matches(&child_cap));
        if !is_granted {
            return Err(UcanError::AttenuationViolation(format!(
                "capability '{}' is not granted by the parent token",
                child_att.with
            )));
        }
    }

    // Step 2b: Enforce ceiling compliance on delegated capabilities (#339).
    // Defense-in-depth: when no explicit ceiling is provided, apply the
    // protocol default ceiling so that capabilities outside the standard
    // set are always rejected at the core layer.
    let effective_ceiling = params
        .ceiling
        .clone()
        .unwrap_or_else(|| crate::context::roles::default_ceiling().to_ucan_string_set());
    verify_attestation_ceiling_compliance(params.attenuated_capabilities, &effective_ceiling)?;

    // Step 3: Enforce 24-hour maximum expiry.
    if params.lifetime_secs > MAX_EXPIRY_SECS {
        return Err(UcanError::ExpiryTooFar(params.lifetime_secs));
    }

    let now = now_secs()?;
    let exp = now + params.lifetime_secs;

    // Step 4: Compute the parent token's CID for the proof chain.
    let parent_cid = compute_cid(params.parent_token);

    // Collect parent proofs and append the parent's own CID.
    let mut proofs = params.parent_token.payload.prf.clone();
    proofs.push(parent_cid);

    // Build header — include kid when signing_key_id or key_scope is present
    // (ADR-039). signing_key_id takes precedence.
    let header = params.signing_key_id.as_ref().map_or_else(
        || {
            params
                .key_scope
                .as_ref()
                .map_or_else(UcanHeader::new, |scope| UcanHeader::with_kid(scope.clone()))
        },
        |signing_key_id| UcanHeader::with_kid(signing_key_id.as_fragment().to_owned()),
    );

    // Build facts — merge scp_key_scope into existing facts when key_scope
    // is present (ADR-039).
    let fct = build_facts_with_key_scope(params.facts.as_ref(), params.key_scope.as_ref())?;

    let payload = UcanPayload {
        iss: params.delegator_did.to_owned(),
        aud: params.delegatee_did.to_owned(),
        exp,
        nbf: None,
        nnc: generate_nonce()?,
        att: params.attenuated_capabilities.to_vec(),
        prf: proofs,
        fct,
    };

    // Encode header and payload as base64url JSON.
    let header_json = serde_json::to_vec(&header)
        .map_err(|e| UcanError::MalformedToken(format!("header serialization failed: {e}")))?;
    let payload_json = serde_json::to_vec(&payload)
        .map_err(|e| UcanError::MalformedToken(format!("payload serialization failed: {e}")))?;

    let header_b64 = URL_SAFE_NO_PAD.encode(&header_json);
    let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);

    // The signing input is `base64url(header).base64url(payload)`.
    let signing_input = format!("{header_b64}.{payload_b64}");

    // Sign with the delegator's Ed25519 key via KeyCustody.
    let sig = custody
        .sign(params.delegator_key, signing_input.as_bytes())
        .await
        .map_err(|e| UcanError::MalformedToken(format!("signing failed: {e}")))?;

    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.as_bytes());
    let encoded = format!("{signing_input}.{sig_b64}");

    Ok(UcanToken {
        header,
        payload,
        signature: sig.into_bytes(),
        encoded,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;
    use scp_platform::testing::InMemoryKeyCustody;
    use scp_platform::traits::KeyType;

    /// Helper: create an `InMemoryKeyCustody`, generate a key, and return both.
    async fn setup_custody() -> (InMemoryKeyCustody, KeyHandle, String) {
        let custody = InMemoryKeyCustody::new();
        let handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let pubkey = custody.public_key(&handle).await.unwrap();
        let did = format!("did:dht:z{}", zbase32::encode(pubkey.as_bytes()));
        (custody, handle, did)
    }

    #[tokio::test]
    async fn mint_ucan_produces_valid_jwt_structure() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-abc123",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let token = mint_ucan(&params, &custody).await.unwrap();

        // Verify JWT has three segments.
        assert_eq!(
            token.encoded.split('.').count(),
            3,
            "JWT must have 3 segments"
        );

        // Verify header fields.
        assert_eq!(token.header.alg, "EdDSA");
        assert_eq!(token.header.typ, "JWT");
        assert_eq!(token.header.ucv, "0.10.0");

        // Verify payload fields.
        assert_eq!(token.payload.iss, issuer_did);
        assert_eq!(token.payload.aud, "did:dht:z6MkMember");
        assert_eq!(token.payload.att.len(), 1);
        assert_eq!(
            token.payload.att[0].with,
            "scp:ctx:ctx-abc123/messages:write"
        );
        assert_eq!(token.payload.att[0].can, "write");
        assert!(token.payload.nbf.is_none());
        assert!(token.payload.prf.is_empty());

        // Verify signature length (Ed25519 = 64 bytes).
        assert_eq!(token.signature.len(), 64);
    }

    #[tokio::test]
    async fn mint_ucan_signature_verifies_with_issuer_public_key() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:read".to_owned(), "messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkAudience",
            context_id: "ctx-test",
            capabilities: &caps,
            lifetime_secs: 7200,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let token = mint_ucan(&params, &custody).await.unwrap();

        // Reconstruct signing input from encoded token.
        let parts: Vec<&str> = token.encoded.split('.').collect();
        let signing_input = format!("{}.{}", parts[0], parts[1]);

        // Verify signature using ed25519-dalek directly.
        let pubkey = custody.public_key(&key_handle).await.unwrap();
        let pk_bytes: [u8; 32] = pubkey.as_bytes().try_into().unwrap();
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes).unwrap();

        let sig_bytes: [u8; 64] = token.signature.as_slice().try_into().unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

        assert!(
            verifying_key
                .verify(signing_input.as_bytes(), &signature)
                .is_ok(),
            "Ed25519 signature must verify"
        );
    }

    #[tokio::test]
    async fn mint_ucan_nonce_has_correct_format() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let token = mint_ucan(&params, &custody).await.unwrap();
        let nonce = &token.payload.nnc;

        // Nonce format: {unix_millis_timestamp}-{32_hex_chars}
        let parts: Vec<&str> = nonce.splitn(2, '-').collect();
        assert_eq!(parts.len(), 2, "nonce must have timestamp-hex format");

        // Timestamp part must be a valid integer.
        let _ts: u128 = parts[0].parse().expect("timestamp must be numeric");

        // Hex part must be exactly 32 hex chars (16 bytes).
        assert_eq!(parts[1].len(), 32, "random suffix must be 32 hex chars");
        assert!(
            parts[1].chars().all(|c| c.is_ascii_hexdigit()),
            "random suffix must be valid hex"
        );
    }

    #[tokio::test]
    async fn mint_ucan_nonces_are_unique() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let token1 = mint_ucan(&params, &custody).await.unwrap();
        let token2 = mint_ucan(&params, &custody).await.unwrap();

        assert_ne!(
            token1.payload.nnc, token2.payload.nnc,
            "nonces must be unique"
        );
    }

    #[tokio::test]
    async fn mint_ucan_rejects_expiry_beyond_24h() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: MAX_EXPIRY_SECS + 1,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let err = mint_ucan(&params, &custody).await.unwrap_err();
        assert!(matches!(err, UcanError::ExpiryTooFar(_)));
    }

    #[tokio::test]
    async fn mint_ucan_expiry_exactly_24h_succeeds() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: MAX_EXPIRY_SECS,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        assert!(mint_ucan(&params, &custody).await.is_ok());
    }

    #[tokio::test]
    async fn mint_ucan_multiple_capabilities() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec![
            "messages:read".to_owned(),
            "messages:write".to_owned(),
            "tool_invoke:assistant".to_owned(),
        ];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-multi",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let token = mint_ucan(&params, &custody).await.unwrap();

        assert_eq!(token.payload.att.len(), 3);
        assert_eq!(token.payload.att[0].with, "scp:ctx:ctx-multi/messages:read");
        assert_eq!(token.payload.att[0].can, "read");
        assert_eq!(
            token.payload.att[1].with,
            "scp:ctx:ctx-multi/messages:write"
        );
        assert_eq!(token.payload.att[1].can, "write");
        assert_eq!(
            token.payload.att[2].with,
            "scp:ctx:ctx-multi/tool_invoke:assistant"
        );
        assert_eq!(token.payload.att[2].can, "assistant");
    }

    #[tokio::test]
    async fn mint_ucan_with_proofs_and_facts() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: Some(1_700_000_000),
            proofs: vec!["bafyreiabc123".to_owned()],
            facts: Some(serde_json::json!({"role": "member"})),
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let token = mint_ucan(&params, &custody).await.unwrap();

        assert_eq!(token.payload.nbf, Some(1_700_000_000));
        assert_eq!(token.payload.prf, vec!["bafyreiabc123"]);
        assert_eq!(
            token.payload.fct,
            Some(serde_json::json!({"role": "member"}))
        );
    }

    #[tokio::test]
    async fn mint_ucan_encoded_token_decodes_correctly() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-decode",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let token = mint_ucan(&params, &custody).await.unwrap();

        // Decode the JWT parts and verify they match the struct fields.
        let parts: Vec<&str> = token.encoded.split('.').collect();
        let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();

        let decoded_header: UcanHeader = serde_json::from_slice(&header_bytes).unwrap();
        let decoded_payload: UcanPayload = serde_json::from_slice(&payload_bytes).unwrap();

        assert_eq!(decoded_header, token.header);
        assert_eq!(decoded_payload, token.payload);
    }

    // -------------------------------------------------------------------
    // compute_cid
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn compute_cid_returns_bafyrei_prefix() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-cid",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let token = mint_ucan(&params, &custody).await.unwrap();
        let cid = compute_cid(&token);

        assert!(
            cid.starts_with("bafyrei"),
            "CID must start with 'bafyrei' prefix, got: {cid}"
        );
    }

    #[tokio::test]
    async fn compute_cid_is_deterministic() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-cid",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let token = mint_ucan(&params, &custody).await.unwrap();
        let cid1 = compute_cid(&token);
        let cid2 = compute_cid(&token);

        assert_eq!(cid1, cid2, "CID must be deterministic for the same token");
    }

    #[tokio::test]
    async fn compute_cid_different_tokens_produce_different_cids() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-cid",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let token1 = mint_ucan(&params, &custody).await.unwrap();
        let token2 = mint_ucan(&params, &custody).await.unwrap();

        let cid1 = compute_cid(&token1);
        let cid2 = compute_cid(&token2);

        assert_ne!(
            cid1, cid2,
            "different tokens (different nonces) must produce different CIDs"
        );
    }

    #[tokio::test]
    async fn compute_cid_hex_has_correct_length() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-cid",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let token = mint_ucan(&params, &custody).await.unwrap();
        let cid = compute_cid(&token);

        // "bafyrei" (7 chars) + 64 hex chars (SHA-256) = 71 chars total.
        assert_eq!(cid.len(), 7 + 64, "CID must be 'bafyrei' + 64 hex chars");

        // The hex portion must be valid hex.
        let hex_part = &cid[7..];
        assert!(
            hex_part.chars().all(|c| c.is_ascii_hexdigit()),
            "CID hex portion must be valid hex"
        );
    }

    // -------------------------------------------------------------------
    // delegate_ucan — success cases
    // -------------------------------------------------------------------

    /// Helper: mint a root token from Alice to Bob with given capabilities.
    async fn mint_root_token(
        custody: &InMemoryKeyCustody,
        issuer_key: &KeyHandle,
        issuer_did: &str,
        audience_did: &str,
        context_id: &str,
        capabilities: &[String],
    ) -> UcanToken {
        let params = MintParams {
            issuer_did,
            issuer_key,
            audience_did,
            context_id,
            capabilities,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };
        mint_ucan(&params, custody).await.unwrap()
    }

    #[tokio::test]
    async fn delegate_ucan_creates_valid_delegated_token() {
        // Alice creates a root token for Bob.
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;

        let caps = vec!["messages:read".to_owned(), "messages:write".to_owned()];
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;

        // Bob delegates a subset to Carol.
        let carol_did = "did:dht:z6MkCarol";
        let attenuated = vec![Attenuation {
            with: "scp:ctx:ctx-1/messages:read".to_owned(),
            can: "read".to_owned(),
        }];

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: carol_did,
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let delegated = delegate_ucan(&delegate_params, &bob_custody).await.unwrap();

        // Verify structure.
        assert_eq!(delegated.payload.iss, bob_did);
        assert_eq!(delegated.payload.aud, carol_did);
        assert_eq!(delegated.payload.att.len(), 1);
        assert_eq!(delegated.payload.att[0].with, "scp:ctx:ctx-1/messages:read");
        assert_eq!(delegated.payload.att[0].can, "read");

        // Verify JWT has three segments.
        assert_eq!(
            delegated.encoded.split('.').count(),
            3,
            "delegated JWT must have 3 segments"
        );

        // Verify signature length.
        assert_eq!(delegated.signature.len(), 64);
    }

    #[tokio::test]
    async fn delegate_ucan_proof_chain_contains_parent_cid() {
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;

        let caps = vec!["messages:write".to_owned()];
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;

        let parent_cid = compute_cid(&root_token);

        let attenuated = vec![Attenuation {
            with: "scp:ctx:ctx-1/messages:write".to_owned(),
            can: "write".to_owned(),
        }];

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: "did:dht:z6MkCarol",
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let delegated = delegate_ucan(&delegate_params, &bob_custody).await.unwrap();

        // The proof chain must include the parent CID.
        assert!(
            delegated.payload.prf.contains(&parent_cid),
            "delegated token prf must contain parent CID"
        );
    }

    #[tokio::test]
    async fn delegate_ucan_signature_verifies_with_delegator_key() {
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;

        let caps = vec!["messages:write".to_owned()];
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;

        let attenuated = vec![Attenuation {
            with: "scp:ctx:ctx-1/messages:write".to_owned(),
            can: "write".to_owned(),
        }];

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: "did:dht:z6MkCarol",
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let delegated = delegate_ucan(&delegate_params, &bob_custody).await.unwrap();

        // Verify signature with Bob's public key.
        let bob_pubkey = bob_custody.public_key(&bob_key).await.unwrap();
        let pk_bytes: [u8; 32] = bob_pubkey.as_bytes().try_into().unwrap();
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes).unwrap();

        let parts: Vec<&str> = delegated.encoded.split('.').collect();
        let signing_input = format!("{}.{}", parts[0], parts[1]);

        let sig_bytes: [u8; 64] = delegated.signature.as_slice().try_into().unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

        assert!(
            verifying_key
                .verify(signing_input.as_bytes(), &signature)
                .is_ok(),
            "delegated token Ed25519 signature must verify with delegator's key"
        );
    }

    #[tokio::test]
    async fn delegate_ucan_preserves_all_parent_capabilities() {
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;

        let caps = vec![
            "messages:read".to_owned(),
            "messages:write".to_owned(),
            "tool_invoke:assistant".to_owned(),
        ];
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;

        // Delegate all capabilities (exact copy, no narrowing).
        let attenuated: Vec<Attenuation> = root_token.payload.att.clone();

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: "did:dht:z6MkCarol",
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let delegated = delegate_ucan(&delegate_params, &bob_custody).await.unwrap();
        assert_eq!(delegated.payload.att.len(), 3);
    }

    #[tokio::test]
    async fn delegate_ucan_narrows_to_single_capability() {
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;

        let caps = vec![
            "messages:read".to_owned(),
            "messages:write".to_owned(),
            "tool_invoke:assistant".to_owned(),
        ];
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;

        // Delegate only messages:read.
        let attenuated = vec![Attenuation {
            with: "scp:ctx:ctx-1/messages:read".to_owned(),
            can: "read".to_owned(),
        }];

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: "did:dht:z6MkCarol",
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let delegated = delegate_ucan(&delegate_params, &bob_custody).await.unwrap();
        assert_eq!(delegated.payload.att.len(), 1);
        assert_eq!(delegated.payload.att[0].with, "scp:ctx:ctx-1/messages:read");
    }

    #[tokio::test]
    async fn delegate_ucan_includes_facts() {
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;

        let caps = vec!["messages:write".to_owned()];
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;

        let attenuated = vec![Attenuation {
            with: "scp:ctx:ctx-1/messages:write".to_owned(),
            can: "write".to_owned(),
        }];

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: "did:dht:z6MkCarol",
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: Some(serde_json::json!({"delegated_by": "bob"})),
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let delegated = delegate_ucan(&delegate_params, &bob_custody).await.unwrap();
        assert_eq!(
            delegated.payload.fct,
            Some(serde_json::json!({"delegated_by": "bob"}))
        );
    }

    #[tokio::test]
    async fn delegate_ucan_generates_unique_nonces() {
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;

        let caps = vec!["messages:write".to_owned()];
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;

        let attenuated = vec![Attenuation {
            with: "scp:ctx:ctx-1/messages:write".to_owned(),
            can: "write".to_owned(),
        }];

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: "did:dht:z6MkCarol",
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let d1 = delegate_ucan(&delegate_params, &bob_custody).await.unwrap();
        let d2 = delegate_ucan(&delegate_params, &bob_custody).await.unwrap();

        assert_ne!(
            d1.payload.nnc, d2.payload.nnc,
            "delegated tokens must have unique nonces"
        );
    }

    // -------------------------------------------------------------------
    // delegate_ucan — chained delegation (A -> B -> C)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn delegate_ucan_chained_delegation_accumulates_proof_chain() {
        // Alice -> Bob -> Carol: verify the proof chain grows.
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;
        let (carol_custody, carol_key, carol_did) = setup_custody().await;

        let caps = vec!["messages:read".to_owned(), "messages:write".to_owned()];

        // Alice mints root token for Bob.
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;
        let root_cid = compute_cid(&root_token);
        assert!(root_token.payload.prf.is_empty());

        // Bob delegates to Carol.
        let bob_attenuated = vec![
            Attenuation {
                with: "scp:ctx:ctx-1/messages:read".to_owned(),
                can: "read".to_owned(),
            },
            Attenuation {
                with: "scp:ctx:ctx-1/messages:write".to_owned(),
                can: "write".to_owned(),
            },
        ];

        let bob_delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: &carol_did,
            attenuated_capabilities: &bob_attenuated,
            lifetime_secs: 1800,
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let bob_to_carol = delegate_ucan(&bob_delegate_params, &bob_custody)
            .await
            .unwrap();
        let bob_to_carol_cid = compute_cid(&bob_to_carol);

        // Bob's delegated token should have root CID in proof chain.
        assert_eq!(bob_to_carol.payload.prf.len(), 1);
        assert!(bob_to_carol.payload.prf.contains(&root_cid));

        // Carol delegates to Dave (further narrowing).
        let carol_attenuated = vec![Attenuation {
            with: "scp:ctx:ctx-1/messages:read".to_owned(),
            can: "read".to_owned(),
        }];

        let carol_delegate_params = DelegateParams {
            parent_token: &bob_to_carol,
            delegator_did: &carol_did,
            delegator_key: &carol_key,
            delegatee_did: "did:dht:z6MkDave",
            attenuated_capabilities: &carol_attenuated,
            lifetime_secs: 900,
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let carol_to_dave = delegate_ucan(&carol_delegate_params, &carol_custody)
            .await
            .unwrap();

        // Carol's delegated token should have root CID AND Bob-to-Carol CID.
        assert_eq!(carol_to_dave.payload.prf.len(), 2);
        assert!(carol_to_dave.payload.prf.contains(&root_cid));
        assert!(carol_to_dave.payload.prf.contains(&bob_to_carol_cid));
    }

    // -------------------------------------------------------------------
    // delegate_ucan — error cases
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn delegate_ucan_rejects_delegator_not_matching_parent_audience() {
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (_bob_custody, _bob_key, bob_did) = setup_custody().await;

        let caps = vec!["messages:write".to_owned()];
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;

        // Eve (not Bob) tries to delegate.
        let (eve_custody, eve_key, eve_did) = setup_custody().await;

        let attenuated = vec![Attenuation {
            with: "scp:ctx:ctx-1/messages:write".to_owned(),
            can: "write".to_owned(),
        }];

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &eve_did,
            delegator_key: &eve_key,
            delegatee_did: "did:dht:z6MkCarol",
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let err = delegate_ucan(&delegate_params, &eve_custody)
            .await
            .unwrap_err();
        assert!(
            matches!(err, UcanError::AudienceMismatch { .. }),
            "must reject delegator not matching parent aud: {err}"
        );
    }

    #[tokio::test]
    async fn delegate_ucan_rejects_capability_widening() {
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;

        // Root token only grants messages:read.
        let caps = vec!["messages:read".to_owned()];
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;

        // Bob tries to delegate messages:write (not in parent).
        let attenuated = vec![Attenuation {
            with: "scp:ctx:ctx-1/messages:write".to_owned(),
            can: "write".to_owned(),
        }];

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: "did:dht:z6MkCarol",
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let err = delegate_ucan(&delegate_params, &bob_custody)
            .await
            .unwrap_err();
        assert!(
            matches!(err, UcanError::AttenuationViolation(_)),
            "must reject capability widening: {err}"
        );
    }

    #[tokio::test]
    async fn delegate_ucan_rejects_widening_with_extra_capability() {
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;

        let caps = vec!["messages:read".to_owned(), "messages:write".to_owned()];
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;

        // Bob tries to delegate including tool_invoke:assistant (not in parent).
        let attenuated = vec![
            Attenuation {
                with: "scp:ctx:ctx-1/messages:read".to_owned(),
                can: "read".to_owned(),
            },
            Attenuation {
                with: "scp:ctx:ctx-1/tool_invoke:assistant".to_owned(),
                can: "assistant".to_owned(),
            },
        ];

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: "did:dht:z6MkCarol",
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let err = delegate_ucan(&delegate_params, &bob_custody)
            .await
            .unwrap_err();
        assert!(
            matches!(err, UcanError::AttenuationViolation(_)),
            "must reject widening with extra capability: {err}"
        );
    }

    #[tokio::test]
    async fn delegate_ucan_rejects_different_context_as_widening() {
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;

        let caps = vec!["messages:write".to_owned()];
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;

        // Bob tries to delegate for a different context.
        let attenuated = vec![Attenuation {
            with: "scp:ctx:ctx-OTHER/messages:write".to_owned(),
            can: "write".to_owned(),
        }];

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: "did:dht:z6MkCarol",
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let err = delegate_ucan(&delegate_params, &bob_custody)
            .await
            .unwrap_err();
        assert!(
            matches!(err, UcanError::AttenuationViolation(_)),
            "must reject delegation for a different context: {err}"
        );
    }

    #[tokio::test]
    async fn delegate_ucan_rejects_expiry_beyond_24h() {
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;

        let caps = vec!["messages:write".to_owned()];
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;

        let attenuated = vec![Attenuation {
            with: "scp:ctx:ctx-1/messages:write".to_owned(),
            can: "write".to_owned(),
        }];

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: "did:dht:z6MkCarol",
            attenuated_capabilities: &attenuated,
            lifetime_secs: MAX_EXPIRY_SECS + 1,
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let err = delegate_ucan(&delegate_params, &bob_custody)
            .await
            .unwrap_err();
        assert!(
            matches!(err, UcanError::ExpiryTooFar(_)),
            "must reject expiry beyond 24h: {err}"
        );
    }

    #[tokio::test]
    async fn delegate_ucan_rejects_invalid_capability_uri() {
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;

        let caps = vec!["messages:write".to_owned()];
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;

        let attenuated = vec![Attenuation {
            with: "not-a-valid-uri".to_owned(),
            can: "write".to_owned(),
        }];

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: "did:dht:z6MkCarol",
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let err = delegate_ucan(&delegate_params, &bob_custody)
            .await
            .unwrap_err();
        assert!(
            matches!(err, UcanError::AttenuationViolation(_)),
            "must reject invalid capability URI: {err}"
        );
    }

    #[tokio::test]
    async fn delegate_ucan_empty_capabilities_succeeds() {
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;

        let caps = vec!["messages:write".to_owned()];
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;

        // Delegating zero capabilities is valid attenuation (maximally narrow).
        let attenuated: Vec<Attenuation> = vec![];

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: "did:dht:z6MkCarol",
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let delegated = delegate_ucan(&delegate_params, &bob_custody).await.unwrap();
        assert!(delegated.payload.att.is_empty());
    }

    #[tokio::test]
    async fn delegate_ucan_wildcard_parent_grants_specific_child() {
        // A parent token with a wildcard capability should allow delegation to
        // a specific context.
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;

        // Manually create a root token with a wildcard capability.
        let wildcard_caps = vec![Attenuation {
            with: "scp:ctx:*/messages:write".to_owned(),
            can: "write".to_owned(),
        }];

        let params = MintParams {
            issuer_did: &alice_did,
            issuer_key: &alice_key,
            audience_did: &bob_did,
            context_id: "*",
            capabilities: &["messages:write".to_owned()],
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };
        let mut root_token = mint_ucan(&params, &alice_custody).await.unwrap();
        // Overwrite att to use the explicitly wildcard form.
        root_token.payload.att = wildcard_caps;

        // Bob delegates to Carol for a specific context.
        let attenuated = vec![Attenuation {
            with: "scp:ctx:ctx-specific/messages:write".to_owned(),
            can: "write".to_owned(),
        }];

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: "did:dht:z6MkCarol",
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let delegated = delegate_ucan(&delegate_params, &bob_custody).await.unwrap();
        assert_eq!(
            delegated.payload.att[0].with,
            "scp:ctx:ctx-specific/messages:write"
        );
    }

    // -----------------------------------------------------------------------
    // key_scope / kid tests (ADR-039)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn mint_ucan_without_key_scope_has_no_kid_in_header() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let token = mint_ucan(&params, &custody).await.unwrap();

        // Header must not have kid.
        assert!(
            token.header.kid.is_none(),
            "kid must be None without key_scope"
        );

        // Facts must not contain scp_key_scope.
        assert!(
            token.payload.fct.is_none(),
            "fct must be None without key_scope and no explicit facts"
        );

        // Serialized JWT header must not contain "kid".
        let parts: Vec<&str> = token.encoded.split('.').collect();
        let header_json = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let header_str = String::from_utf8(header_json).unwrap();
        assert!(
            !header_str.contains("kid"),
            "serialized header must not contain kid: {header_str}"
        );
    }

    #[tokio::test]
    async fn mint_ucan_with_key_scope_agent_sets_kid_in_header() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: Some("#agent".to_owned()),
            signing_key_id: None,
            ceiling: None,
        };

        let token = mint_ucan(&params, &custody).await.unwrap();

        // Header must have kid="#agent".
        assert_eq!(
            token.header.kid,
            Some("#agent".to_owned()),
            "kid must be #agent"
        );

        // Facts must contain scp_key_scope="#agent".
        let fct = token
            .payload
            .fct
            .as_ref()
            .expect("fct must be present with key_scope");
        assert_eq!(
            fct.get("scp_key_scope").and_then(|v| v.as_str()),
            Some("#agent"),
            "fct.scp_key_scope must be #agent"
        );
    }

    #[tokio::test]
    async fn mint_ucan_with_key_scope_active_sets_kid_in_header() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: Some("#active".to_owned()),
            signing_key_id: None,
            ceiling: None,
        };

        let token = mint_ucan(&params, &custody).await.unwrap();

        assert_eq!(
            token.header.kid,
            Some("#active".to_owned()),
            "kid must be #active"
        );

        let fct = token
            .payload
            .fct
            .as_ref()
            .expect("fct must be present with key_scope");
        assert_eq!(
            fct.get("scp_key_scope").and_then(|v| v.as_str()),
            Some("#active"),
            "fct.scp_key_scope must be #active"
        );
    }

    #[tokio::test]
    async fn mint_ucan_self_delegation_with_key_scope_succeeds() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned(), "messages:read".to_owned()];

        // Self-delegation: iss == aud, same DID. Per ADR-039 acceptance
        // criterion 8, this is explicitly valid when key_scope is present.
        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: &issuer_did,
            context_id: "ctx-self",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: Some("#agent".to_owned()),
            signing_key_id: None,
            ceiling: None,
        };

        let token = mint_ucan(&params, &custody).await.unwrap();

        // Verify self-delegation fields.
        assert_eq!(token.payload.iss, issuer_did);
        assert_eq!(token.payload.aud, issuer_did);
        assert_eq!(token.header.kid, Some("#agent".to_owned()));

        let fct = token.payload.fct.as_ref().expect("fct must be present");
        assert_eq!(
            fct.get("scp_key_scope").and_then(|v| v.as_str()),
            Some("#agent"),
        );

        // Verify JWT structure is valid (3 segments, signature verifies).
        assert_eq!(token.encoded.split('.').count(), 3);
        assert_eq!(token.signature.len(), 64);
    }

    #[tokio::test]
    async fn mint_ucan_kid_appears_in_serialized_jwt_header() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: Some("#agent".to_owned()),
            signing_key_id: None,
            ceiling: None,
        };

        let token = mint_ucan(&params, &custody).await.unwrap();

        // Decode the header segment from the JWT.
        let parts: Vec<&str> = token.encoded.split('.').collect();
        let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let header_value: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();

        assert_eq!(
            header_value.get("kid").and_then(|v| v.as_str()),
            Some("#agent"),
            "kid must appear in serialized JWT header"
        );
        assert_eq!(
            header_value.get("alg").and_then(|v| v.as_str()),
            Some("EdDSA"),
        );
    }

    #[tokio::test]
    async fn mint_ucan_scp_key_scope_appears_in_deserialized_fct() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: Some("#agent".to_owned()),
            signing_key_id: None,
            ceiling: None,
        };

        let token = mint_ucan(&params, &custody).await.unwrap();

        // Decode the payload segment from the JWT and verify fct.scp_key_scope.
        let parts: Vec<&str> = token.encoded.split('.').collect();
        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let payload_value: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

        let fct = payload_value
            .get("fct")
            .expect("fct must be present in serialized payload");
        assert_eq!(
            fct.get("scp_key_scope").and_then(|v| v.as_str()),
            Some("#agent"),
            "scp_key_scope must appear in deserialized fct"
        );
    }

    #[tokio::test]
    async fn mint_ucan_key_scope_roundtrip_serialize_parse() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: Some("#agent".to_owned()),
            signing_key_id: None,
            ceiling: None,
        };

        let token = mint_ucan(&params, &custody).await.unwrap();

        // Round-trip: serialize the token, then parse header and payload back.
        let parts: Vec<&str> = token.encoded.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must have 3 segments");

        // Parse header.
        let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let parsed_header: UcanHeader = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(parsed_header.kid, Some("#agent".to_owned()));
        assert_eq!(parsed_header.alg, "EdDSA");
        assert_eq!(parsed_header.typ, "JWT");
        assert_eq!(parsed_header.ucv, "0.10.0");

        // Parse payload.
        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let parsed_payload: UcanPayload = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(parsed_payload.iss, issuer_did);
        assert_eq!(parsed_payload.aud, "did:dht:z6MkMember");

        let fct = parsed_payload.fct.expect("fct must be present");
        assert_eq!(
            fct.get("scp_key_scope").and_then(|v| v.as_str()),
            Some("#agent"),
        );
    }

    #[tokio::test]
    async fn mint_ucan_key_scope_merges_with_existing_facts() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: Some(serde_json::json!({"role": "admin", "note": "test"})),
            key_scope: Some("#agent".to_owned()),
            signing_key_id: None,
            ceiling: None,
        };

        let token = mint_ucan(&params, &custody).await.unwrap();

        let fct = token.payload.fct.as_ref().expect("fct must be present");

        // scp_key_scope must be present.
        assert_eq!(
            fct.get("scp_key_scope").and_then(|v| v.as_str()),
            Some("#agent"),
        );

        // Original facts must be preserved.
        assert_eq!(fct.get("role").and_then(|v| v.as_str()), Some("admin"),);
        assert_eq!(fct.get("note").and_then(|v| v.as_str()), Some("test"),);
    }

    #[tokio::test]
    async fn mint_ucan_backward_compat_no_key_scope_no_scp_key_scope_fact() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        // Explicit facts but no key_scope — scp_key_scope must NOT be added.
        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: Some(serde_json::json!({"role": "member"})),
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let token = mint_ucan(&params, &custody).await.unwrap();

        let fct = token.payload.fct.as_ref().expect("fct must be present");
        assert!(
            fct.get("scp_key_scope").is_none(),
            "scp_key_scope must not appear without key_scope"
        );
        assert_eq!(fct.get("role").and_then(|v| v.as_str()), Some("member"));
    }

    // -----------------------------------------------------------------------
    // Bug fix tests: key_scope validation guards (AB-012 review)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn mint_ucan_rejects_conflicting_scp_key_scope_in_facts() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        // facts already contains scp_key_scope with a DIFFERENT value than key_scope.
        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: Some(serde_json::json!({"scp_key_scope": "#wrong"})),
            key_scope: Some("#agent".to_owned()),
            signing_key_id: None,
            ceiling: None,
        };

        let err = mint_ucan(&params, &custody).await.unwrap_err();
        assert!(
            matches!(err, UcanError::MalformedToken(ref msg) if msg.contains("conflicts")),
            "conflicting scp_key_scope must be rejected: {err:?}"
        );
    }

    #[tokio::test]
    async fn mint_ucan_accepts_matching_scp_key_scope_in_facts() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        // facts already contains scp_key_scope with the SAME value — should succeed.
        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: Some(serde_json::json!({"scp_key_scope": "#agent"})),
            key_scope: Some("#agent".to_owned()),
            signing_key_id: None,
            ceiling: None,
        };

        let token = mint_ucan(&params, &custody).await.unwrap();
        let fct = token.payload.fct.as_ref().expect("fct must be present");
        assert_eq!(
            fct.get("scp_key_scope").and_then(|v| v.as_str()),
            Some("#agent")
        );
    }

    #[tokio::test]
    async fn mint_ucan_rejects_self_delegation_without_key_scope() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: &issuer_did,
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let err = mint_ucan(&params, &custody).await.unwrap_err();
        assert!(
            matches!(err, UcanError::MalformedToken(ref msg) if msg.contains("self-delegation")),
            "self-delegation without key_scope must be rejected: {err:?}"
        );
    }

    #[tokio::test]
    async fn mint_ucan_allows_self_delegation_with_key_scope() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: &issuer_did,
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: Some("#agent".to_owned()),
            signing_key_id: None,
            ceiling: None,
        };

        let token = mint_ucan(&params, &custody).await.unwrap();
        assert_eq!(token.payload.iss, token.payload.aud);
    }

    #[tokio::test]
    async fn mint_ucan_rejects_key_scope_without_hash_prefix() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: Some("agent".to_owned()),
            signing_key_id: None,
            ceiling: None,
        };

        let err = mint_ucan(&params, &custody).await.unwrap_err();
        assert!(
            matches!(err, UcanError::MalformedToken(ref msg) if msg.contains("'#'")),
            "key_scope without '#' prefix must be rejected: {err:?}"
        );
    }

    #[tokio::test]
    async fn delegate_ucan_rejects_key_scope_without_hash_prefix() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let (custody_b, key_b, audience_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        // First mint a valid root token.
        let root_token = mint_ucan(
            &MintParams {
                issuer_did: &issuer_did,
                issuer_key: &key_handle,
                audience_did: &audience_did,
                context_id: "ctx-1",
                capabilities: &caps,
                lifetime_secs: 3600,
                not_before: None,
                proofs: vec![],
                facts: None,
                key_scope: None,
                signing_key_id: None,
                ceiling: None,
            },
            &custody,
        )
        .await
        .unwrap();

        let err = delegate_ucan(
            &DelegateParams {
                parent_token: &root_token,
                delegator_did: &audience_did,
                delegator_key: &key_b,
                delegatee_did: "did:dht:z6MkSomeone",
                attenuated_capabilities: &root_token.payload.att,
                lifetime_secs: 1800,
                facts: None,
                key_scope: Some("no-hash".to_owned()),
                signing_key_id: None,
                ceiling: None,
            },
            &custody_b,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, UcanError::MalformedToken(ref msg) if msg.contains("'#'")),
            "delegate_ucan must reject key_scope without '#' prefix: {err:?}"
        );
    }

    #[tokio::test]
    async fn delegate_ucan_rejects_self_delegation_without_key_scope() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let (custody_b, key_b, did_b) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let root_token = mint_ucan(
            &MintParams {
                issuer_did: &issuer_did,
                issuer_key: &key_handle,
                audience_did: &did_b,
                context_id: "ctx-1",
                capabilities: &caps,
                lifetime_secs: 3600,
                not_before: None,
                proofs: vec![],
                facts: None,
                key_scope: None,
                signing_key_id: None,
                ceiling: None,
            },
            &custody,
        )
        .await
        .unwrap();

        let err = delegate_ucan(
            &DelegateParams {
                parent_token: &root_token,
                delegator_did: &did_b,
                delegator_key: &key_b,
                delegatee_did: &did_b,
                attenuated_capabilities: &root_token.payload.att,
                lifetime_secs: 1800,
                facts: None,
                key_scope: None,
                signing_key_id: None,
                ceiling: None,
            },
            &custody_b,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, UcanError::MalformedToken(ref msg) if msg.contains("self-delegation")),
            "delegate_ucan must reject self-delegation without key_scope: {err:?}"
        );
    }

    #[tokio::test]
    async fn delegate_ucan_rejects_conflicting_scp_key_scope_in_facts() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let (custody_b, key_b, did_b) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let root_token = mint_ucan(
            &MintParams {
                issuer_did: &issuer_did,
                issuer_key: &key_handle,
                audience_did: &did_b,
                context_id: "ctx-1",
                capabilities: &caps,
                lifetime_secs: 3600,
                not_before: None,
                proofs: vec![],
                facts: None,
                key_scope: None,
                signing_key_id: None,
                ceiling: None,
            },
            &custody,
        )
        .await
        .unwrap();

        let err = delegate_ucan(
            &DelegateParams {
                parent_token: &root_token,
                delegator_did: &did_b,
                delegator_key: &key_b,
                delegatee_did: "did:dht:z6MkSomeone",
                attenuated_capabilities: &root_token.payload.att,
                lifetime_secs: 1800,
                facts: Some(serde_json::json!({"scp_key_scope": "#wrong"})),
                key_scope: Some("#agent".to_owned()),
                signing_key_id: None,
                ceiling: None,
            },
            &custody_b,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, UcanError::MalformedToken(ref msg) if msg.contains("conflicts")),
            "delegate_ucan must reject conflicting scp_key_scope: {err:?}"
        );
    }

    // -------------------------------------------------------------------
    // signing_key_id — Category A enforcement
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn mint_ucan_with_agent_signing_key_id_sets_kid_header() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: Some(SigningKeyId::Agent),
            ceiling: None,
        };

        let token = mint_ucan(&params, &custody).await.unwrap();

        // Header must have kid="#agent" from signing_key_id.
        assert_eq!(
            token.header.kid,
            Some("#agent".to_owned()),
            "signing_key_id=Agent must set kid=#agent in header"
        );
    }

    #[tokio::test]
    async fn mint_ucan_with_active_signing_key_id_sets_kid_header() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: Some(SigningKeyId::Active),
            ceiling: None,
        };

        let token = mint_ucan(&params, &custody).await.unwrap();

        // Header must have kid="#active" from signing_key_id.
        assert_eq!(
            token.header.kid,
            Some("#active".to_owned()),
            "signing_key_id=Active must set kid=#active in header"
        );
    }

    #[tokio::test]
    async fn mint_ucan_signing_key_id_takes_precedence_over_key_scope() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        // Self-delegation with key_scope="#active" but signing_key_id=Agent.
        // signing_key_id should win for the kid header, while key_scope still
        // populates scp_key_scope in facts.
        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: &issuer_did,
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: Some("#active".to_owned()),
            signing_key_id: Some(SigningKeyId::Agent),
            ceiling: None,
        };

        let token = mint_ucan(&params, &custody).await.unwrap();

        // kid header comes from signing_key_id, not key_scope.
        assert_eq!(
            token.header.kid,
            Some("#agent".to_owned()),
            "signing_key_id must take precedence over key_scope for kid"
        );

        // scp_key_scope in facts comes from key_scope.
        let fct = token.payload.fct.as_ref().unwrap();
        assert_eq!(
            fct.get("scp_key_scope"),
            Some(&serde_json::Value::String("#active".to_owned())),
            "scp_key_scope must come from key_scope parameter"
        );
    }

    #[tokio::test]
    async fn mint_ucan_without_signing_key_id_has_no_kid_header() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let token = mint_ucan(&params, &custody).await.unwrap();

        // Without signing_key_id or key_scope, kid must be absent.
        assert_eq!(
            token.header.kid, None,
            "kid must be None when neither signing_key_id nor key_scope is set"
        );
    }

    // -------------------------------------------------------------------
    // Ceiling enforcement — mint (#339)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn mint_ucan_rejects_capability_outside_ceiling() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["tool_invoke:assistant".to_owned()];
        let ceiling: HashSet<String> = ["messages:read".to_owned(), "messages:write".to_owned()]
            .into_iter()
            .collect();

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-ceiling",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: Some(ceiling),
        };

        let err = mint_ucan(&params, &custody).await.unwrap_err();
        assert!(
            matches!(err, UcanError::CapabilityOutsideCeiling(_)),
            "expected CapabilityOutsideCeiling, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn mint_ucan_succeeds_within_ceiling() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["tool_invoke:assistant".to_owned()];
        let ceiling: HashSet<String> = [
            "messages:read".to_owned(),
            "messages:write".to_owned(),
            "tool_invoke:assistant".to_owned(),
        ]
        .into_iter()
        .collect();

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-ceiling",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: Some(ceiling),
        };

        assert!(
            mint_ucan(&params, &custody).await.is_ok(),
            "minting with capabilities within the ceiling must succeed"
        );
    }

    #[tokio::test]
    async fn mint_ucan_no_ceiling_applies_default_ceiling() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        // These capabilities are within the default ceiling:
        // tool_invoke:assistant is covered by ToolInvokeAll (tool_invoke:*),
        // messages:write is exact match.
        let caps = vec![
            "tool_invoke:assistant".to_owned(),
            "messages:write".to_owned(),
        ];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-no-ceiling",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        assert!(
            mint_ucan(&params, &custody).await.is_ok(),
            "minting with ceiling: None must succeed for capabilities within the default ceiling"
        );
    }

    /// When `ceiling` is `None`, the default ceiling is applied as defense-in-depth.
    /// Capabilities outside the default ceiling must be rejected.
    #[tokio::test]
    async fn mint_ucan_no_ceiling_rejects_capability_outside_default() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        // "custom:exotic" is NOT in the default ceiling (which contains only
        // standard SCP capabilities like messages:*, tool_invoke:*, etc.).
        let caps = vec!["custom:exotic".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-default-ceiling",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let err = mint_ucan(&params, &custody).await.unwrap_err();
        assert!(
            matches!(err, UcanError::CapabilityOutsideCeiling(_)),
            "ceiling: None must apply default ceiling and reject non-standard capabilities, got: {err:?}"
        );
    }

    // -------------------------------------------------------------------
    // Ceiling enforcement — delegate (#339)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn delegate_ucan_rejects_capability_outside_ceiling() {
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;

        // Root token grants messages:read + tool_invoke:assistant.
        let caps = vec![
            "messages:read".to_owned(),
            "tool_invoke:assistant".to_owned(),
        ];
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;

        // Ceiling only allows messages:read — tool_invoke:assistant is outside.
        let ceiling: HashSet<String> = std::iter::once("messages:read".to_owned()).collect();

        let attenuated = vec![Attenuation {
            with: "scp:ctx:ctx-1/tool_invoke:assistant".to_owned(),
            can: "assistant".to_owned(),
        }];

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: "did:dht:z6MkCarol",
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: Some(ceiling),
        };

        let err = delegate_ucan(&delegate_params, &bob_custody)
            .await
            .unwrap_err();
        assert!(
            matches!(err, UcanError::CapabilityOutsideCeiling(_)),
            "expected CapabilityOutsideCeiling, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn delegate_ucan_succeeds_narrowing_within_ceiling() {
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;

        let caps = vec!["messages:read".to_owned(), "messages:write".to_owned()];
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;

        // Ceiling allows both capabilities.
        let ceiling: HashSet<String> = ["messages:read".to_owned(), "messages:write".to_owned()]
            .into_iter()
            .collect();

        // Delegate only messages:read — narrowing within ceiling.
        let attenuated = vec![Attenuation {
            with: "scp:ctx:ctx-1/messages:read".to_owned(),
            can: "read".to_owned(),
        }];

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: "did:dht:z6MkCarol",
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: Some(ceiling),
        };

        assert!(
            delegate_ucan(&delegate_params, &bob_custody).await.is_ok(),
            "delegation narrowing within ceiling must succeed"
        );
    }

    // -----------------------------------------------------------------------
    // #1293 — UCAN capability URI resource/action split
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn mint_ucan_tool_invoke_produces_underscore_resource() {
        // Minting with the colon-format name "tool:invoke:*" must produce
        // a UCAN URI with resource "tool_invoke", not "tool".
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["tool:invoke:*".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1293",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let token = mint_ucan(&params, &custody).await.unwrap();

        // The attestation URI must use underscore format.
        assert_eq!(
            token.payload.att[0].with, "scp:ctx:ctx-1293/tool_invoke:*",
            "tool:invoke:* must produce tool_invoke:* in UCAN URI"
        );
        assert_eq!(token.payload.att[0].can, "*");
    }

    #[tokio::test]
    async fn mint_ucan_tool_invoke_specific_produces_underscore_resource() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["tool:invoke:calculator".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1293",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let token = mint_ucan(&params, &custody).await.unwrap();

        assert_eq!(
            token.payload.att[0].with, "scp:ctx:ctx-1293/tool_invoke:calculator",
            "tool:invoke:calculator must produce tool_invoke:calculator in UCAN URI"
        );
        assert_eq!(token.payload.att[0].can, "calculator");
    }

    #[tokio::test]
    async fn mint_ucan_child_context_create_produces_underscore_resource() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["context:child:create".to_owned()];

        // context:child:create is NOT in the default ceiling, so provide an
        // explicit ceiling that includes it for this URI format test.
        let ceiling: HashSet<String> = std::iter::once("context_child:create".to_owned()).collect();

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1293",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: Some(ceiling),
        };

        let token = mint_ucan(&params, &custody).await.unwrap();

        assert_eq!(
            token.payload.att[0].with, "scp:ctx:ctx-1293/context_child:create",
            "context:child:create must produce context_child:create in UCAN URI"
        );
        assert_eq!(token.payload.att[0].can, "create");
    }

    #[tokio::test]
    async fn mint_ucan_simple_cap_unchanged() {
        // Capabilities without multi-segment resources should be unchanged.
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1293",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
        };

        let token = mint_ucan(&params, &custody).await.unwrap();

        assert_eq!(
            token.payload.att[0].with, "scp:ctx:ctx-1293/messages:write",
            "simple capabilities must pass through unchanged"
        );
        assert_eq!(token.payload.att[0].can, "write");
    }

    #[tokio::test]
    async fn mint_ucan_tool_invoke_passes_ceiling_check() {
        // A ceiling with UCAN-format entries must accept tool:invoke:* capabilities.
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["tool:invoke:*".to_owned()];

        let mut ceiling = HashSet::new();
        ceiling.insert("tool_invoke:*".to_owned());

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1293",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: Some(ceiling),
        };

        assert!(
            mint_ucan(&params, &custody).await.is_ok(),
            "tool:invoke:* must pass ceiling check with tool_invoke:* in ceiling"
        );
    }

    #[tokio::test]
    async fn mint_ucan_tool_invoke_rejected_when_not_in_ceiling() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["tool:invoke:*".to_owned()];

        let mut ceiling = HashSet::new();
        ceiling.insert("messages:write".to_owned());

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1293",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: Some(ceiling),
        };

        let err = mint_ucan(&params, &custody).await.unwrap_err();
        assert!(
            matches!(err, UcanError::CapabilityOutsideCeiling(_)),
            "tool:invoke:* must be rejected when not in ceiling: {err:?}"
        );
    }
}
