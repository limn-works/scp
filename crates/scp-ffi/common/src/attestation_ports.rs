//! The two custody-backed ports every bridge registers for the `KeyPackage`
//! attestation (§9.7.1; ADR-057 Amendment 2026-08-01).
//!
//! [`CustodyAttestationSigner`] signs a leaf's attestation with one identity's
//! `#active`/`#agent` custody key, and [`IdentityDidDocumentResolver`] resolves
//! a joiner's DID for the current-key checks the `Add` verifier runs. Both are
//! written once here rather than three times, because all three bridges hold
//! the same two things: a `KeyCustody` implementor per local identity, and the
//! canonical `IdentityBackedDidResolver`.
//!
//! # Why each one erases a non-`dyn` trait
//!
//! `scp_platform::KeyCustody::sign` and
//! `scp_identity::resolver::DidResolver::resolve` both return `impl Future`
//! (RPITIT), so neither can be stored as `Arc<dyn _>`. The runtime stores
//! `Arc<dyn KeyPackageAttestationSigner>` and `Arc<dyn DidDocumentResolver>`
//! instead, and these two types are what turn a bridge's concrete custody and
//! resolver into those trait objects — the same construction
//! `BridgeCustodyStreamSigner` uses for §5.4.5 outlet-stream chunks.

use std::sync::Arc;

use scp_core::crypto::mls::attestation_signer::{
    AttestationSignerError, DidDocumentResolveError, DidDocumentResolver,
    KeyPackageAttestationSigner,
};
use scp_did::{DidDocument, SigningKeyId};
use scp_identity::resolver::DidResolver;
use scp_platform::{KeyCustody, KeyHandle};

use crate::resolvers::IdentityBackedDidResolver;

/// Signs one identity's `KeyPackage` attestations through the platform custody
/// boundary (§9.7.1; §9.5.2).
///
/// The private key never enters the runtime address space: custody signs the
/// 32-byte §9.5.1 hash and returns only the signature, which is what makes a
/// hardware-backed key (Secure Enclave, Keystore) usable here.
///
/// One value binds one DID acting as one verification method, matching the
/// scope of the `KeyPackageStoreActor` that holds it.
pub struct CustodyAttestationSigner<C: KeyCustody> {
    /// The custody provider holding this identity's signing key.
    custody: Arc<C>,
    /// The handle naming the `#active` or `#agent` key inside custody.
    handle: KeyHandle,
    /// Which verification method `handle` names (§9.5.2 field 6).
    signing_key_id: SigningKeyId,
}

impl<C: KeyCustody> CustodyAttestationSigner<C> {
    /// Binds `custody` and `handle` as the signer for `signing_key_id`.
    ///
    /// The caller passes the handle it already resolved for that verification
    /// method, so this type never chooses a key: §9.7.1 forbids `#0` here, and
    /// the caller's own persona selection is what keeps `#0` out.
    pub const fn new(custody: Arc<C>, handle: KeyHandle, signing_key_id: SigningKeyId) -> Self {
        Self {
            custody,
            handle,
            signing_key_id,
        }
    }
}

#[async_trait::async_trait]
impl<C: KeyCustody + 'static> KeyPackageAttestationSigner for CustodyAttestationSigner<C> {
    fn signing_key_id(&self) -> SigningKeyId {
        self.signing_key_id
    }

    async fn sign_attestation(
        &self,
        signing_hash: &[u8; 32],
    ) -> Result<[u8; 64], AttestationSignerError> {
        // Ed25519 over the 32-byte §9.5.1 hash verbatim — custody does NOT
        // re-hash it, because the hash is already the domain-separated digest
        // §9.5.2 defines.
        let signature = self
            .custody
            .sign(&self.handle, signing_hash)
            .await
            .map_err(|e| AttestationSignerError::SigningFailed(e.to_string()))?;

        <[u8; 64]>::try_from(signature.as_bytes()).map_err(|_| {
            AttestationSignerError::SigningFailed(format!(
                "custody returned a {}-byte signature; Ed25519 signatures are 64 bytes",
                signature.as_bytes().len()
            ))
        })
    }
}

/// Resolves a joiner's DID document through the bridge's canonical resolver for
/// the §9.7.1 attestation current-key checks (checks 1–2).
///
/// Wraps [`IdentityBackedDidResolver`], which performs §3.10.4 dual-layer
/// resolution with BEP44 signature verification and sequence-number
/// monotonicity. Each `resolve_document` call performs a fresh resolution and
/// returns only the document, so no caller can substitute a stale or
/// pre-rotation cached document for a failed resolution — the fallback §9.7.1's
/// "Resolution failure policy" forbids on an `Add`.
pub struct IdentityDidDocumentResolver {
    /// The canonical production resolver.
    inner: Arc<IdentityBackedDidResolver>,
}

impl IdentityDidDocumentResolver {
    /// Wraps `inner` as the runtime's attestation resolver.
    #[must_use]
    pub const fn new(inner: Arc<IdentityBackedDidResolver>) -> Self {
        Self { inner }
    }
}

#[async_trait::async_trait]
impl DidDocumentResolver for IdentityDidDocumentResolver {
    async fn resolve_document(
        &self,
        did: &str,
    ) -> Result<Option<DidDocument>, DidDocumentResolveError> {
        self.inner
            .resolve(did)
            .await
            .map(|found| found.map(|resolved| resolved.document))
            .map_err(|e| DidDocumentResolveError::Failed(e.to_string()))
    }
}

/// Registers both attestation ports on `supervisor` for one local identity.
///
/// Every bridge calls this on the path that mints `KeyPackage`s, before the
/// identity's `KeyPackageStoreActor` spawns: the actor reads its signer at
/// spawn, so a signer registered afterwards would not reach it, and an actor
/// spawned without one refuses to mint (§9.7.1).
///
/// `resolver` is `None` when the bridge has not initialized the production DID
/// resolver. Passing `None` leaves the backend's resolver slot empty, and the
/// `Add` verifier then rejects every joiner whose DID resolution covers —
/// fail-closed, never admit-unverified.
///
/// # Errors
///
/// Returns whatever `Supervisor::set_attestation_resolver` returns when the
/// supervisor's provider slots are unpopulated.
pub async fn register_attestation_ports<C: KeyCustody + 'static>(
    supervisor: &Arc<scp_core::context::supervisor::Supervisor>,
    did: scp_did::DID,
    custody: Arc<C>,
    handle: KeyHandle,
    signing_key_id: SigningKeyId,
    resolver: Option<Arc<IdentityBackedDidResolver>>,
) -> Result<(), scp_core::context::ContextError> {
    supervisor
        .set_attestation_signer(
            did,
            Arc::new(CustodyAttestationSigner::new(
                custody,
                handle,
                signing_key_id,
            )),
        )
        .await;
    if let Some(resolver) = resolver {
        supervisor
            .set_attestation_resolver(Arc::new(IdentityDidDocumentResolver::new(resolver)))?;
    }
    Ok(())
}
