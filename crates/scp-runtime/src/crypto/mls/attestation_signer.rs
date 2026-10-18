//! The signer of a `KeyPackage`'s `0xFF03` attestation (`09-security-model.md`
//! §9.5.2, §9.7.1), bound to the owner's resolved `#active` key.
//!
//! Every native `KeyPackage` minter (the `KeyPackage` store and
//! `Supervisor::mint_attested_key_package`) mints through
//! [`mint_attested_key_package`], which signs the draft's attestation hash
//! with a [`KeyPackageAttestationSigner`]. The signer holds the identity's
//! custody-backed [`CommandSigner`], so no key leaves custody, and refuses to
//! sign unless that signer's public key is the key the owner's DID document
//! currently names at `#active`. A `KeyPackage` the owner's `#active` key did
//! not attest is never minted.

use ed25519_dalek::VerifyingKey;
use scp_did::{DID, SigningKeyId};
use scp_mls::attested_key_package::KeyPackageDraft;
use scp_mls::credential::ScpCredential;
use scp_protocol::context::ContextError;
use scp_protocol::context::governance::KeyResolver;

use super::backend::{GeneratedKeyPackage, MlsBackend};
use crate::context::actor::signer::CommandSigner;

/// Signs `KeyPackage` attestations for one owner with the owner's `#active`
/// key, through custody.
///
/// Built only inside the crate, from the identity's [`CommandSigner`] and the
/// supervisor's [`KeyResolver`]. Each sign re-resolves the owner's `#active`
/// key, so a signer held by the `KeyPackage` store stops signing once the
/// owner's DID document names another key (§9.12, rotation is revocation).
/// `Debug` names the owner only.
pub struct KeyPackageAttestationSigner {
    owner: DID,
    signer: CommandSigner,
    key_resolver: KeyResolver,
}

impl std::fmt::Debug for KeyPackageAttestationSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPackageAttestationSigner")
            .field("owner", &self.owner)
            .finish_non_exhaustive()
    }
}

impl KeyPackageAttestationSigner {
    /// A signer for `owner`'s attestations through `signer`, checked against
    /// the `#active` key `key_resolver` returns for `owner`.
    pub(crate) fn new(owner: DID, signer: CommandSigner, key_resolver: KeyResolver) -> Self {
        Self {
            owner,
            signer,
            key_resolver,
        }
    }

    /// The identity whose `KeyPackages` this signer attests.
    pub(crate) const fn owner(&self) -> &DID {
        &self.owner
    }

    /// The `#active` key the owner's DID document names now.
    ///
    /// # Errors
    ///
    /// [`ContextError::AttestationSignerActiveKeyUnresolved`] when the
    /// resolver returns no key.
    fn resolved_active(&self) -> Result<VerifyingKey, ContextError> {
        (self.key_resolver)(&self.owner, SigningKeyId::Active)
            .ok_or(ContextError::AttestationSignerActiveKeyUnresolved)
    }

    /// Checks that the held signer's key is the owner's resolved `#active`
    /// key, and returns that key.
    ///
    /// # Errors
    ///
    /// - [`ContextError::AttestationSignerActiveKeyUnresolved`] when the
    ///   owner's `#active` key does not resolve.
    /// - [`ContextError::AttestationSignerNotActiveKey`] when the held signer
    ///   is not an Ed25519 signer, or its key differs from the resolved key.
    pub(crate) fn check_active(&self) -> Result<VerifyingKey, ContextError> {
        let resolved = self.resolved_active()?;
        let held = self
            .signer
            .verifying_key()
            .map_err(|_| ContextError::AttestationSignerNotActiveKey)?;
        if held == resolved {
            Ok(resolved)
        } else {
            Err(ContextError::AttestationSignerNotActiveKey)
        }
    }

    /// Signs `draft`'s attestation hash with the owner's `#active` key.
    ///
    /// The method takes only a [`KeyPackageDraft`], so it signs nothing but an
    /// attestation hash. It re-runs [`Self::check_active`] before the sign and
    /// verifies the signature against the resolved key after it.
    ///
    /// # Errors
    ///
    /// - [`ContextError::InvalidState`] when the draft's credential names
    ///   another identity, or a `signing_key_id` other than `#active`.
    /// - The errors of [`Self::check_active`].
    /// - [`ContextError::Custody`] when custody refuses the sign or does not
    ///   answer within the signing budget.
    /// - [`ContextError::CryptoFailed`] when the signature does not verify
    ///   against the resolved key.
    pub(crate) async fn sign_attestation(
        &self,
        draft: &KeyPackageDraft,
    ) -> Result<[u8; 64], ContextError> {
        let credential = draft.credential();
        if credential.did != self.owner.0 {
            return Err(ContextError::InvalidState(
                "attestation signer owner mismatch".to_owned(),
            ));
        }
        if credential.signing_key_id != SigningKeyId::Active {
            return Err(ContextError::InvalidState(format!(
                "a KeyPackage attestation is signed by #active, not {:?}",
                credential.signing_key_id
            )));
        }
        let resolved = self.check_active()?;
        let hash = draft.signing_hash();
        let signature = self.signer.sign_bounded_ed25519(&hash).await?;
        scp_crypto::verify_ed25519_signature(resolved.as_bytes(), &hash, &signature).map_err(
            |e| {
                ContextError::CryptoFailed(format!(
                    "KeyPackage attestation signature does not verify against the resolved \
                     #active key: {e}"
                ))
            },
        )?;
        Ok(signature)
    }
}

/// Mints one attested `KeyPackage` for `signer`'s owner: plans it through
/// `mls` with `wrapping_pubkey` as its `0xFF01`, signs its attestation with
/// `signer`, and builds it.
///
/// # Errors
///
/// - [`ContextError::CryptoFailed`] when the owner's DID cannot form a
///   credential, or `mls` fails to plan or build the `KeyPackage`.
/// - The errors of [`KeyPackageAttestationSigner::sign_attestation`]; no
///   `KeyPackage` is built.
pub(crate) async fn mint_attested_key_package(
    mls: &dyn MlsBackend,
    signer: &KeyPackageAttestationSigner,
    wrapping_pubkey: &[u8; 65],
) -> Result<GeneratedKeyPackage, ContextError> {
    let credential = ScpCredential::new(signer.owner().0.clone(), None, SigningKeyId::Active)
        .map_err(|e| ContextError::CryptoFailed(format!("KeyPackage credential: {e}")))?;
    let draft = mls
        .prepare_key_package(&credential, wrapping_pubkey)
        .await
        .map_err(|e| ContextError::CryptoFailed(format!("planning key package: {e}")))?;
    let signature = signer.sign_attestation(&draft).await?;
    mls.finish_key_package(draft, signature)
        .await
        .map_err(|e| ContextError::CryptoFailed(format!("generating key package: {e}")))
}
