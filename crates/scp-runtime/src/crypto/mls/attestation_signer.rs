//! The signer of a `KeyPackage`'s `0xFF03` attestation (`09-security-model.md`
//! §9.5.2, §9.7.1), bound to the owner's resolved `#active` key.
//!
//! Every native `KeyPackage` minter (the `KeyPackage` store and
//! `Supervisor::mint_attested_key_package`) mints through
//! [`mint_attested_key_package`], which signs the draft's attestation hash
//! with a [`KeyPackageAttestationSigner`]. The signer holds the identity's
//! custody-backed [`CommandSigner`], so no key leaves custody. A signer exists
//! only after [`KeyPackageAttestationSigner::resolve`] resolved the owner's
//! `#active` key and found the custody signer holds it, and every mint hands
//! that resolved key to [`MlsBackend::finish_key_package`], which verifies the
//! signature under it before it builds anything. A `KeyPackage` the owner's
//! `#active` key did not attest is never minted.

use ed25519_dalek::VerifyingKey;
use scp_did::DID;
use scp_mls::error::MlsError;
use scp_protocol::context::ContextError;
use scp_protocol::context::governance::KeyResolver;

use super::attestation_verification::resolve_active_key;
use super::backend::{GeneratedKeyPackage, MlsBackend};
use crate::context::actor::signer::CommandSigner;

/// Signs `KeyPackage` attestations for one owner with the owner's `#active`
/// key, through custody.
///
/// Built only by [`Self::resolve`], which resolves the owner's `#active` key
/// and checks the custody signer holds it, so holding a value of this type is
/// proof of that check at resolution time. The `KeyPackage` store compares
/// [`Self::active_key`] across signers to retire the `KeyPackages` an older
/// `#active` key attested (§9.12, rotation is revocation). `Debug` names the
/// owner only.
///
/// The type is public only because the public `KeyPackageCommand::ReserveAny`
/// carries it; its fields and constructor are crate-private, so no code
/// outside this crate can build one.
pub struct KeyPackageAttestationSigner {
    owner: DID,
    signer: CommandSigner,
    active_key: VerifyingKey,
    /// The resolver `active_key` came from, kept so the `KeyPackage` store
    /// can re-resolve before it installs this signer
    /// ([`Self::confirm_still_active`]).
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
    /// Resolves `owner`'s `#active` key through `key_resolver` and returns a
    /// signer over `signer` when `signer` holds that key.
    ///
    /// The resolver is synchronous and may block on a network resolution, so
    /// it runs through [`resolve_active_key`] on the blocking pool, never on
    /// an async worker.
    ///
    /// # Errors
    ///
    /// - [`ContextError::AttestationSignerNotActiveKey`] when `signer` is not
    ///   an Ed25519 signer, or its key differs from the resolved key. The
    ///   signer's key is read before the resolver runs.
    /// - [`ContextError::AttestationSignerActiveKeyUnresolved`] when the
    ///   owner's `#active` key does not resolve.
    /// - [`ContextError::CryptoFailed`] when the resolver task panics or is
    ///   cancelled.
    pub(crate) async fn resolve(
        owner: DID,
        signer: CommandSigner,
        key_resolver: KeyResolver,
    ) -> Result<Self, ContextError> {
        let held = signer
            .verifying_key()
            .map_err(|_| ContextError::AttestationSignerNotActiveKey)?;
        let active_key = resolve_current_active(&key_resolver, &owner).await?;
        if held != active_key {
            return Err(ContextError::AttestationSignerNotActiveKey);
        }
        Ok(Self {
            owner,
            signer,
            active_key,
            key_resolver,
        })
    }

    /// Resolves the owner's `#active` key again and checks it is still
    /// [`Self::active_key`]. The `KeyPackage` store runs this, off its command
    /// turn, before it installs a signer, so a signer resolved before a
    /// rotation and delivered after a newer one never replaces the newer one
    /// or burns its pool (§9.12).
    ///
    /// # Errors
    ///
    /// - [`ContextError::AttestationSignerNotActiveKey`] when the owner's
    ///   `#active` key is now another key.
    /// - [`ContextError::AttestationSignerActiveKeyUnresolved`] when it no
    ///   longer resolves.
    /// - [`ContextError::CryptoFailed`] when the resolver task panics or is
    ///   cancelled.
    pub(crate) async fn confirm_still_active(&self) -> Result<(), ContextError> {
        let current = resolve_current_active(&self.key_resolver, &self.owner).await?;
        if current == self.active_key {
            Ok(())
        } else {
            Err(ContextError::AttestationSignerNotActiveKey)
        }
    }

    /// A signer over `signer` for `owner`, taking `active_key` as the
    /// owner's `#active` key without resolving it, for tests that drive the
    /// `KeyPackage` store directly. Its re-resolution
    /// ([`Self::confirm_still_active`]) names `active_key` for `owner` and
    /// nothing else.
    #[cfg(test)]
    pub(crate) fn for_test(owner: DID, signer: CommandSigner, active_key: VerifyingKey) -> Self {
        let resolved_owner = owner.clone();
        let key_resolver: KeyResolver =
            std::sync::Arc::new(move |did: &DID, kid: scp_did::SigningKeyId| {
                (did == &resolved_owner && kid == scp_did::SigningKeyId::Active)
                    .then_some(active_key)
            });
        Self {
            owner,
            signer,
            active_key,
            key_resolver,
        }
    }

    /// The identity whose `KeyPackages` this signer attests.
    pub(crate) const fn owner(&self) -> &DID {
        &self.owner
    }

    /// The owner's `#active` key as resolved when this signer was built: the
    /// key every attestation this signer makes verifies under.
    pub(crate) const fn active_key(&self) -> &VerifyingKey {
        &self.active_key
    }
}

/// `owner`'s `#active` key through `key_resolver`, on the blocking pool.
///
/// # Errors
///
/// [`ContextError::AttestationSignerActiveKeyUnresolved`] when the key does
/// not resolve; [`ContextError::CryptoFailed`] when the resolver task panics
/// or is cancelled.
async fn resolve_current_active(
    key_resolver: &KeyResolver,
    owner: &DID,
) -> Result<VerifyingKey, ContextError> {
    resolve_active_key(std::sync::Arc::clone(key_resolver), owner.clone())
        .await
        .map_err(|e| {
            ContextError::CryptoFailed(format!("#active key resolution task failed: {e}"))
        })?
        .ok_or(ContextError::AttestationSignerActiveKeyUnresolved)
}

/// Mints one attested `KeyPackage` for `signer`'s owner: plans it through
/// `mls` for the owner's DID with `wrapping_pubkey` as its `0xFF01`, signs its
/// attestation hash through custody, and builds it under the resolved
/// `#active` key.
///
/// # Errors
///
/// - [`ContextError::Custody`] when custody refuses or does not answer the
///   sign, and [`ContextError::CryptoFailed`] when the signer is not Ed25519.
/// - [`ContextError::AttestationSignerNotActiveKey`] when the signature does
///   not verify under the resolved `#active` key: the custody signs with a key
///   other than the one it reports. Nothing is built.
/// - [`ContextError::CryptoFailed`] when `mls` fails to plan or build the
///   `KeyPackage`.
pub(crate) async fn mint_attested_key_package(
    mls: &dyn MlsBackend,
    signer: &KeyPackageAttestationSigner,
    wrapping_pubkey: &[u8; 65],
) -> Result<GeneratedKeyPackage, ContextError> {
    let draft = mls
        .prepare_key_package(&signer.owner, wrapping_pubkey)
        .await
        .map_err(|e| ContextError::CryptoFailed(format!("planning key package: {e}")))?;
    let signature = signer
        .signer
        .sign_bounded_ed25519(&draft.signing_hash())
        .await?;
    mls.finish_key_package(draft, signature, &signer.active_key)
        .await
        .map_err(|e| match e {
            MlsError::KeyPackageAttestationSignatureInvalid => {
                ContextError::AttestationSignerNotActiveKey
            }
            other => ContextError::CryptoFailed(format!("generating key package: {other}")),
        })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::Arc;

    use ed25519_dalek::{Signer as _, SigningKey};
    use scp_crypto::{ScpSigner, SigAlg};

    use super::*;
    use crate::crypto::mls::production_backend::ProductionMlsBackend;
    use scp_did::SigningKeyId;

    fn owner() -> DID {
        DID("did:dht:z6MkAttestationSignerOwner".to_owned())
    }

    /// A signer that reports `reported` as its public key but signs with
    /// `signing`.
    struct LyingSigner {
        reported: SigningKey,
        signing: SigningKey,
    }

    impl ScpSigner for LyingSigner {
        fn algorithm(&self) -> SigAlg {
            SigAlg::Ed25519
        }
        fn public_key(&self) -> Vec<u8> {
            self.reported.verifying_key().to_bytes().to_vec()
        }
        fn sign(
            &self,
            digest: &[u8; 32],
        ) -> impl std::future::Future<Output = Result<[u8; 64], scp_crypto::SignError>> + Send
        {
            std::future::ready(Ok(self.signing.sign(digest).to_bytes()))
        }
    }

    /// A custody that reports the owner's `#active` key but signs with another
    /// key passes the resolve check, and the mint fails with a typed error
    /// before any `KeyPackage` is built.
    #[tokio::test]
    async fn a_custody_signing_with_another_key_mints_nothing() {
        let active = SigningKey::from_bytes(&[0x31; 32]);
        let active_vk = active.verifying_key();
        let resolver: KeyResolver = Arc::new(move |did: &DID, kid| {
            (did == &owner() && kid == SigningKeyId::Active).then_some(active_vk)
        });
        let lying = CommandSigner::new(Arc::new(LyingSigner {
            reported: active,
            signing: SigningKey::from_bytes(&[0x32; 32]),
        }));
        let signer = KeyPackageAttestationSigner::resolve(owner(), lying, resolver)
            .await
            .expect("the reported key is the resolved #active key");
        let mls = ProductionMlsBackend::new(Arc::new(scp_clock::SystemClock));
        let wrapping = scp_crypto::p256::testing::uncompressed_point_for(&owner().0);

        let err = mint_attested_key_package(&mls, &signer, &wrapping)
            .await
            .expect_err("a signature under another key is never built into a KeyPackage");
        assert!(
            matches!(err, ContextError::AttestationSignerNotActiveKey),
            "got {err:?}"
        );
    }

    /// The resolver is asked for `#active` and nothing else.
    #[tokio::test]
    async fn resolve_asks_for_the_active_role_only() {
        let active = SigningKey::from_bytes(&[0x41; 32]);
        let active_vk = active.verifying_key();
        let agent_vk = SigningKey::from_bytes(&[0x42; 32]).verifying_key();
        let resolver: KeyResolver = Arc::new(move |_did: &DID, kid| match kid {
            SigningKeyId::Active => Some(active_vk),
            SigningKeyId::Agent => Some(agent_vk),
        });
        let signer = KeyPackageAttestationSigner::resolve(
            owner(),
            CommandSigner::local_ed25519(active),
            resolver,
        )
        .await
        .expect("the #active signer resolves");
        assert_eq!(signer.active_key(), &active_vk);
    }
}
