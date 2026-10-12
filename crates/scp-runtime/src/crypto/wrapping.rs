//! The identity's DHKEM(P-256) wrapping key (spec 09 §9.16.1).
//!
//! One identity has one wrapping key, published as the `0xFF01` leaf
//! extension in every context the identity joins. Today the runtime uses it
//! to open the HPKE-sealed sender keys addressed to the identity (§9.16.2).
//! Spec 05 §5.12.3.1 also seals the invitation bundle to it; the Welcome join
//! still opens that bundle with the `#active` key until the join moves to
//! this key. The supervisor holds it as an [`IdentityWrappingKey`]: a
//! custody, the custody's opaque handle, and the public point.
//!
//! `KeyCustody` uses return-position `impl Trait`, so it is not object safe.
//! [`WrappingCustody`] is the object-safe slice of it the wrapping key needs.
//! The trait is sealed, so [`ErasedCustody`] is its only implementation and
//! any `KeyCustody` (test fakes included) reaches the supervisor through that
//! adapter. A bridge hands the supervisor a [`WrappingCustodySource`] that
//! finds an identity's custody by DID.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use scp_crypto::CustodyFailure;
use scp_did::DID;
use scp_platform::PlatformError;
use scp_platform::traits::{KeyCustody, KeyHandle, KeyType, PublicKey};
use scp_protocol::context::ContextError;
use scp_protocol::crypto::hpke::p256::ValidatedEnc;
use zeroize::Zeroizing;

use crate::context::actor::SIGN_TIMEOUT;
use crate::context::actor::signer::custody_timed_out;

/// A boxed custody future, the shape an object-safe async method returns.
pub type WrappingCustodyFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

mod sealed {
    /// Seals [`super::WrappingCustody`]: only this module implements it.
    pub trait Sealed {}
}

/// The object-safe slice of `KeyCustody` the identity wrapping key uses.
///
/// Sealed: [`ErasedCustody`] is the only implementation, so every wrapping
/// key the supervisor holds goes through that adapter over some `KeyCustody`.
/// The seal says nothing about which `KeyCustody`: the adapter's field is
/// public and accepts any implementation, test custodies included.
pub trait WrappingCustody: sealed::Sealed + Send + Sync {
    /// Generates a [`KeyType::HpkeP256`] key in the operational role.
    fn generate_hpke_p256(&self) -> WrappingCustodyFuture<'_, Result<KeyHandle, PlatformError>>;

    /// The public key of `handle`.
    fn public_key<'a>(
        &'a self,
        handle: &'a KeyHandle,
    ) -> WrappingCustodyFuture<'a, Result<PublicKey, PlatformError>>;

    /// The P-256 ECDH x-coordinate of `handle`'s private key and `enc`.
    fn dh_agree<'a>(
        &'a self,
        handle: &'a KeyHandle,
        enc: &'a ValidatedEnc,
    ) -> WrappingCustodyFuture<'a, Result<Zeroizing<[u8; 32]>, PlatformError>>;

    /// Destroys `handle`'s key.
    fn destroy_key<'a>(
        &'a self,
        handle: &'a KeyHandle,
    ) -> WrappingCustodyFuture<'a, Result<(), PlatformError>>;
}

/// A `KeyCustody` seen through [`WrappingCustody`].
pub struct ErasedCustody<C: KeyCustody + 'static>(pub Arc<C>);

impl<C: KeyCustody + 'static> sealed::Sealed for ErasedCustody<C> {}

impl<C: KeyCustody + 'static> WrappingCustody for ErasedCustody<C> {
    fn generate_hpke_p256(&self) -> WrappingCustodyFuture<'_, Result<KeyHandle, PlatformError>> {
        Box::pin(self.0.generate_keypair(KeyType::HpkeP256))
    }

    fn public_key<'a>(
        &'a self,
        handle: &'a KeyHandle,
    ) -> WrappingCustodyFuture<'a, Result<PublicKey, PlatformError>> {
        Box::pin(self.0.public_key(handle))
    }

    fn dh_agree<'a>(
        &'a self,
        handle: &'a KeyHandle,
        enc: &'a ValidatedEnc,
    ) -> WrappingCustodyFuture<'a, Result<Zeroizing<[u8; 32]>, PlatformError>> {
        Box::pin(async move {
            let shared = self.0.dh_agree(handle, enc.as_bytes()).await?;
            Ok(Zeroizing::new(*shared.as_bytes()))
        })
    }

    fn destroy_key<'a>(
        &'a self,
        handle: &'a KeyHandle,
    ) -> WrappingCustodyFuture<'a, Result<(), PlatformError>> {
        Box::pin(self.0.destroy_key(handle))
    }
}

/// Finds the custody that holds an identity's wrapping key. `None` means no
/// custody is registered for that identity, and the supervisor refuses to
/// build its actors.
pub type WrappingCustodySource =
    Arc<dyn Fn(&DID) -> Option<Arc<dyn WrappingCustody>> + Send + Sync>;

/// A source that answers every identity with `custody`.
#[must_use]
pub fn single_custody_source<C: KeyCustody + 'static>(custody: Arc<C>) -> WrappingCustodySource {
    let erased: Arc<dyn WrappingCustody> = Arc::new(ErasedCustody(custody));
    Arc::new(move |_owner: &DID| Some(Arc::clone(&erased)))
}

/// Awaits one custody call for at most [`SIGN_TIMEOUT`], the custody budget of
/// ADR-049 Decision 7a.
///
/// A timeout drops `call`; the host may still finish it. For `generate` that
/// leaves a key in custody that no record names and no caller holds a handle
/// to, so nothing can destroy it: the orphan is the cost of bounding a custody
/// that does not answer. Every other call creates nothing.
///
/// # Errors
///
/// [`ContextError::Custody`] with the custody's own kind when custody refuses,
/// and with kind [`scp_crypto::CustodyFailureKind::TimedOut`] (`SCP-CRYPTO-4061`) when it
/// does not answer in time.
pub(crate) async fn custody_bounded<T>(
    call: WrappingCustodyFuture<'_, Result<T, PlatformError>>,
    operation: &'static str,
) -> Result<T, ContextError> {
    match tokio::time::timeout(SIGN_TIMEOUT, call).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(e)) => Err(ContextError::Custody(CustodyFailure::from(&e))),
        Err(_) => Err(custody_timed_out(operation)),
    }
}

/// Reads `handle`'s public point from `custody`, under the custody budget.
///
/// # Errors
///
/// [`ContextError::Custody`] if custody refuses or times out, and
/// [`ContextError::CryptoFailed`] if the key is not a valid 65-byte
/// uncompressed P-256 point (§9.5).
async fn read_public_point(
    custody: &dyn WrappingCustody,
    handle: &KeyHandle,
) -> Result<[u8; 65], ContextError> {
    let public = custody_bounded(custody.public_key(handle), "public_key").await?;
    let point = scp_protocol::crypto::hpke::p256::validate_enc(public.as_bytes())
        .map_err(|e| ContextError::CryptoFailed(format!("custody wrapping public key: {e}")))?;
    Ok(*point.as_bytes())
}

/// Destroys `handle`'s key in `custody`, best effort: the caller is already
/// failing, so a failure here is logged and not returned.
async fn destroy_handle(custody: &dyn WrappingCustody, handle: &KeyHandle) {
    if let Err(e) = custody_bounded(custody.destroy_key(handle), "destroy_key").await {
        tracing::warn!(error = %e, "destroying an unrecorded wrapping key failed");
    }
}

/// An identity's wrapping key: its custody, the custody's handle, and the
/// 65-byte uncompressed public point read from custody when the key was
/// loaded.
///
/// `Debug` prints only the public point; the handle stays out of logs.
pub(crate) struct IdentityWrappingKey {
    custody: Arc<dyn WrappingCustody>,
    handle: KeyHandle,
    public: [u8; 65],
}

impl IdentityWrappingKey {
    /// A key whose public point `public` the caller has read from `custody`
    /// for `handle`.
    pub(crate) fn new(
        custody: Arc<dyn WrappingCustody>,
        handle: KeyHandle,
        public: [u8; 65],
    ) -> Self {
        Self {
            custody,
            handle,
            public,
        }
    }

    /// Generates a fresh `HpkeP256` key in `custody` and reads its public
    /// point, each under the custody budget.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::read_public`], and [`ContextError::Custody`] if
    /// the generation fails. A key whose public point cannot be read is
    /// destroyed (best effort) before the error returns.
    pub(crate) async fn generate(custody: Arc<dyn WrappingCustody>) -> Result<Self, ContextError> {
        let handle = custody_bounded(custody.generate_hpke_p256(), "generate").await?;
        match read_public_point(custody.as_ref(), &handle).await {
            Ok(public) => Ok(Self::new(custody, handle, public)),
            Err(e) => {
                destroy_handle(custody.as_ref(), &handle).await;
                Err(e)
            }
        }
    }

    /// The 65-byte uncompressed public point published in `0xFF01`.
    pub(crate) const fn public(&self) -> &[u8; 65] {
        &self.public
    }

    /// The custody handle of the private key.
    pub(crate) const fn handle(&self) -> &KeyHandle {
        &self.handle
    }

    /// Reads the public point from custody, under the custody budget.
    ///
    /// # Errors
    ///
    /// [`ContextError::Custody`] if custody refuses or times out, and
    /// [`ContextError::CryptoFailed`] if the key is not a valid 65-byte
    /// uncompressed P-256 point (§9.5).
    pub(crate) async fn read_public(&self) -> Result<[u8; 65], ContextError> {
        read_public_point(self.custody.as_ref(), &self.handle).await
    }

    /// The ECDH x-coordinate of the private key and `enc`, computed inside
    /// custody under the custody budget.
    ///
    /// # Errors
    ///
    /// [`ContextError::Custody`] if custody refuses (key-not-found is
    /// `SCP-CRYPTO-4006`) or times out (`SCP-CRYPTO-4061`).
    pub(crate) async fn agree(
        &self,
        enc: &ValidatedEnc,
    ) -> Result<Zeroizing<[u8; 32]>, ContextError> {
        custody_bounded(self.custody.dh_agree(&self.handle, enc), "dh_agree").await
    }

    /// Destroys the key in custody, best effort: the caller is already
    /// failing, so a failure here is logged and not returned.
    pub(crate) async fn destroy(&self) {
        destroy_handle(self.custody.as_ref(), &self.handle).await;
    }
}

impl std::fmt::Debug for IdentityWrappingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityWrappingKey")
            .field("public", &hex::encode(self.public))
            .finish_non_exhaustive()
    }
}

/// A custody-backed wrapping key generated in `custody`, for tests.
///
/// # Errors
///
/// The errors of [`IdentityWrappingKey::generate`].
#[cfg(test)]
pub(crate) async fn test_wrapping_key<C: KeyCustody + 'static>(
    custody: &Arc<C>,
) -> Result<Arc<IdentityWrappingKey>, ContextError> {
    IdentityWrappingKey::generate(Arc::new(ErasedCustody(Arc::clone(custody))))
        .await
        .map(Arc::new)
}
