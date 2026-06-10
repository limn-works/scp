//! Shared exporter verifying-key resolution for signed context export
//! (spec §23.16.8, ADR-050).
//!
//! On `import_context`, an importing bridge must resolve the Ed25519 verifying
//! key used to check the snapshot signature. Per §23.16.8 the key is derived
//! from the snapshot's `creator_did` (`role_state.creator_did`) — never from an
//! unauthenticated envelope field. The resolution order is:
//!
//! 1. **Local custody first.** If the DID is a local identity, derive the
//!    verifying key from the custody signing key. This is what makes a
//!    self-export → self-import round-trip work before any DID resolver is
//!    configured (a fresh device importing its own exported context).
//! 2. **DID resolver fallback.** Otherwise resolve the DID's `#active` (then
//!    `#agent`, ADR-039 shared-DID model) verification-method key.
//!
//! Fails closed: if the DID is neither local nor resolvable, resolution fails
//! and the bridge MUST reject the import rather than proceed unverified.
//!
//! The helper is closure-based so each bridge passes its own local-custody
//! accessor and keeps its own error type (per-SDK idiom). The structured
//! [`ExportVerifyError`] carries enough context for each bridge to format its
//! own error message and map it to its own error code. Every bridge,
//! including `PyO3`, maps a snapshot *signature* failure to `SCP-CTX-2093`
//! and an export *version* gate to `SCP-CTX-2094` — the two are distinct.
//!
//! Requires the `resolvers` feature (scp-core, ed25519-dalek). NOT available
//! for WASM (ADR-034); the WASM bridge resolves keys via its own constrained
//! path.

use ed25519_dalek::VerifyingKey;

use scp_core::crypto::ucan::validate::DidResolver;

/// Failure modes for [`resolve_export_verifying_key`].
///
/// Each bridge maps every variant to its own error type and code. The variants
/// preserve the offending DID and a human-readable detail so the bridge can
/// build an actionable message without re-deriving context.
#[derive(Debug)]
pub enum ExportVerifyError {
    /// The DID is not a local identity and no DID resolver was configured, so
    /// the verifying key cannot be resolved at all. Import must fail closed.
    NoResolver {
        /// The `creator_did` whose key could not be resolved.
        did: String,
    },
    /// A DID resolver was configured but resolution of both `#active` and
    /// `#agent` verification methods failed.
    ResolutionFailed {
        /// The `creator_did` whose key could not be resolved.
        did: String,
        /// Resolver-supplied detail (the `#agent` fallback error).
        detail: String,
    },
    /// The resolved key bytes are not a valid Ed25519 verifying key.
    InvalidKey {
        /// The `creator_did` whose resolved key bytes were invalid.
        did: String,
        /// Decoder-supplied detail.
        detail: String,
    },
}

impl core::fmt::Display for ExportVerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoResolver { did } => write!(
                f,
                "creator '{did}' is not a local identity and no DID resolver is \
                 configured — cannot verify exporter snapshot signature"
            ),
            Self::ResolutionFailed { did, detail } => write!(
                f,
                "failed to resolve creator '{did}' verification key \
                 (#active/#agent): {detail}"
            ),
            Self::InvalidKey { did, detail } => write!(
                f,
                "creator '{did}' verification key is not a valid Ed25519 key: {detail}"
            ),
        }
    }
}

impl std::error::Error for ExportVerifyError {}

/// Resolves the Ed25519 verifying key for a signed-context-export importer
/// (spec §23.16.8, ADR-050), local-custody-first then DID-resolver fallback.
///
/// # Arguments
///
/// * `resolver` — the bridge's DID resolver. Pass `None` when the bridge has
///   no resolver configured; resolution then succeeds only if `local_custody`
///   yields a key, otherwise fails with [`ExportVerifyError::NoResolver`].
/// * `local_custody` — a closure that, given the DID, returns the verifying
///   key from the bridge's local key custody if (and only if) the DID is a
///   local identity. The closure returns the *public* verifying key so private
///   key material never leaves the bridge. Returns `None` when the DID is not
///   a local identity.
/// * `did` — the DID to resolve the key for. Callers MUST pass the snapshot's
///   `creator_did` (`role_state.creator_did`), never the envelope
///   `exporter_did` (§23.16.8 step 1).
///
/// # Errors
///
/// Returns [`ExportVerifyError`] when the DID is neither a local identity nor
/// resolvable, or when the resolved key bytes are not a valid Ed25519 key. The
/// caller MUST treat any error as a fail-closed import rejection.
pub fn resolve_export_verifying_key<R, F>(
    resolver: Option<&R>,
    local_custody: F,
    did: &str,
) -> Result<VerifyingKey, ExportVerifyError>
where
    R: DidResolver + ?Sized,
    F: FnOnce(&str) -> Option<VerifyingKey>,
{
    // 1. Local identity: derive the verifying key from the custody signing key.
    //    This path makes self-export → self-import round-trip before any
    //    resolver is configured (fresh device importing its own export).
    if let Some(key) = local_custody(did) {
        return Ok(key);
    }

    // 2. Remote creator: resolve via the DID resolver (#active then #agent,
    //    ADR-039). Fail closed if no resolver is configured.
    let resolver = resolver.ok_or_else(|| ExportVerifyError::NoResolver {
        did: did.to_owned(),
    })?;

    let key_bytes = resolver
        .resolve_public_key_by_kid(did, "active")
        .or_else(|_| resolver.resolve_public_key_by_kid(did, "agent"))
        .map_err(|e| ExportVerifyError::ResolutionFailed {
            did: did.to_owned(),
            detail: e.to_string(),
        })?;

    VerifyingKey::from_bytes(&key_bytes).map_err(|e| ExportVerifyError::InvalidKey {
        did: did.to_owned(),
        detail: e.to_string(),
    })
}

/// Decodes a platform [`PublicKey`](scp_platform::PublicKey) into an Ed25519
/// [`VerifyingKey`], enforcing the 32-byte length and canonical-point validity.
///
/// This is the byte-conversion tail shared by every non-WASM bridge's
/// local-custody verifying-key resolver: each bridge looks up the identity in
/// its own registry and calls `KeyCustody::public_key` (its own HEAD), then
/// funnels the resulting public key through this helper. Only the public
/// verifying key is handled here; private key material never reaches this path
/// (ADR-006).
///
/// Returns `None` when the key is not exactly 32 bytes or is not a valid
/// (decompressable) Ed25519 verifying key — the fail-closed signal each bridge
/// maps to "this DID has no usable local custody key."
#[must_use]
pub fn verifying_key_from_public_key(pk: &scp_platform::PublicKey) -> Option<VerifyingKey> {
    let bytes: [u8; 32] = pk.as_bytes().try_into().ok()?;
    VerifyingKey::from_bytes(&bytes).ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use scp_core::crypto::ucan::UcanError;

    struct StubResolver {
        key: Option<[u8; 32]>,
    }

    impl DidResolver for StubResolver {
        fn resolve_public_key(&self, did: &str) -> Result<[u8; 32], UcanError> {
            self.key
                .ok_or_else(|| UcanError::MalformedToken(format!("no key for {did}")))
        }

        // The helper queries `kid` = "active" / "agent" (no leading '#'),
        // mirroring the production `IdentityBackedDidResolver`, which strips a
        // leading '#'. The default trait impl only recognizes the literal
        // "#active", so the stub resolves the `active` fragment explicitly.
        fn resolve_public_key_by_kid(&self, did: &str, kid: &str) -> Result<[u8; 32], UcanError> {
            let fragment = kid.strip_prefix('#').unwrap_or(kid);
            if fragment == "active" {
                self.resolve_public_key(did)
            } else {
                Err(UcanError::MalformedToken(format!(
                    "no '{fragment}' key for {did}"
                )))
            }
        }
    }

    /// 32 bytes that are not a valid compressed Edwards point, so
    /// `ed25519_dalek::VerifyingKey::from_bytes` (which decompresses eagerly in
    /// dalek 2.x) rejects them. Y-coordinate = 2 with sign bit 0 is not a
    /// square residue, so decompression fails — verified empirically.
    fn non_canonical_key_bytes() -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[0] = 0x02;
        bytes
    }

    fn fixed_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn local_custody_resolves_before_resolver() {
        let expected = fixed_signing_key().verifying_key();
        // Resolver would return a *different* key — local custody must win.
        let other = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
        let resolver = StubResolver {
            key: Some(other.to_bytes()),
        };
        let got = resolve_export_verifying_key(
            Some(&resolver),
            |_did| Some(expected),
            "did:dht:zCreator",
        )
        .unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn resolver_used_when_not_local() {
        let key = fixed_signing_key().verifying_key();
        let resolver = StubResolver {
            key: Some(key.to_bytes()),
        };
        let got =
            resolve_export_verifying_key(Some(&resolver), |_did| None, "did:dht:zCreator").unwrap();
        assert_eq!(got, key);
    }

    #[test]
    fn no_resolver_and_not_local_fails_closed() {
        let err =
            resolve_export_verifying_key::<StubResolver, _>(None, |_did| None, "did:dht:zCreator")
                .unwrap_err();
        assert!(matches!(err, ExportVerifyError::NoResolver { .. }));
    }

    #[test]
    fn resolution_failure_surfaces_detail() {
        let resolver = StubResolver { key: None };
        let err = resolve_export_verifying_key(Some(&resolver), |_did| None, "did:dht:zCreator")
            .unwrap_err();
        assert!(matches!(err, ExportVerifyError::ResolutionFailed { .. }));
    }

    #[test]
    fn invalid_key_bytes_rejected() {
        // Non-decompressable point bytes — proving malformed resolved key bytes
        // are surfaced as InvalidKey rather than panicking or silently accepted.
        let resolver = StubResolver {
            key: Some(non_canonical_key_bytes()),
        };
        let err = resolve_export_verifying_key(Some(&resolver), |_did| None, "did:dht:zCreator")
            .unwrap_err();
        assert!(matches!(err, ExportVerifyError::InvalidKey { .. }));
    }

    #[test]
    fn verifying_key_from_public_key_roundtrips_valid_key() {
        let expected = fixed_signing_key().verifying_key();
        let pk = scp_platform::PublicKey::new(expected.to_bytes().to_vec());
        let got = verifying_key_from_public_key(&pk).expect("valid 32-byte Ed25519 key");
        assert_eq!(got, expected);
    }

    #[test]
    fn verifying_key_from_public_key_rejects_wrong_length() {
        // 31 bytes — fails the [u8; 32] length check before point decode.
        let pk = scp_platform::PublicKey::new(vec![0u8; 31]);
        assert!(verifying_key_from_public_key(&pk).is_none());
    }

    #[test]
    fn verifying_key_from_public_key_rejects_non_canonical_point() {
        // 32 bytes that are not a decompressable Edwards point.
        let pk = scp_platform::PublicKey::new(non_canonical_key_bytes().to_vec());
        assert!(verifying_key_from_public_key(&pk).is_none());
    }
}
