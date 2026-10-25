//! In-memory [`NextSetCustody`] for tests (SCP-345).
//!
//! Holds P-256 next-set keys in a `HashMap` keyed by an opaque
//! [`NextSetKeyHandle`], with no state shared with
//! [`InMemoryKeyCustody`](crate::testing::InMemoryKeyCustody) or
//! [`InMemoryPreRotationCustody`](crate::testing::InMemoryPreRotationCustody).
//!
//! **Not suitable for production.** The keys sit in process memory beside the
//! operational keys, so the §9.7.4.1 §3 substrate isolation does not hold. A
//! shipped build compiles no `NextSetCustody` implementor from this crate;
//! SCP-311 owns the production implementors.

// The module declaration in `testing/mod.rs` carries the same gate; this
// file repeats it because scp-testing's `test_double_gating` test parses each
// file alone.
#![cfg(feature = "testing")]

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use scp_crypto::p256::P256SecretKey;
use scp_kel::{
    CustodyProbe, IndexedSignature, KeyEventSignError, KeyEventSigner, ProbeSignature,
    SigningChange,
};
use tokio::sync::Mutex;

use crate::traits::{
    NextSetCustody, NextSetCustodyError, NextSetKeyHandle, PreRotationCustodyKind,
    generate_p256_os_rng, sign_key_event_digest,
};

/// In-memory [`NextSetCustody`] for tests: software P-256 keys, raw-arm
/// signatures, [`PreRotationCustodyKind::InMemory`].
#[derive(Default)]
pub struct InMemoryNextSetCustody {
    keys: Mutex<HashMap<u64, P256SecretKey>>,
    next_id: AtomicU64,
}

impl std::fmt::Debug for InMemoryNextSetCustody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryNextSetCustody")
            .field("next_id", &self.next_id)
            .finish_non_exhaustive()
    }
}

impl InMemoryNextSetCustody {
    /// An empty custody.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Signs `digest` with the key under `member`, giving the raw form.
    async fn sign_digest(
        &self,
        member: &NextSetKeyHandle,
        digest: &[u8; 32],
    ) -> Result<[u8; 64], KeyEventSignError> {
        // One statement, so the guard drops as soon as the signature exists.
        let signed = self
            .keys
            .lock()
            .await
            .get(&member.id())
            .map(|key| sign_key_event_digest(key, digest));
        Ok(signed.ok_or(KeyEventSignError::MemberNotFound)??)
    }
}

impl KeyEventSigner for InMemoryNextSetCustody {
    type Member = NextSetKeyHandle;

    /// Signs the change's digest `D` (the raw arm).
    async fn sign_change(
        &self,
        member: &NextSetKeyHandle,
        change: &SigningChange,
    ) -> Result<IndexedSignature, KeyEventSignError> {
        let signature = self.sign_digest(member, &change.digest()).await?;
        Ok(IndexedSignature::Raw { signature })
    }

    /// Signs the probe's raw digest (§9.7.4.1 item 5, step d).
    async fn sign_probe(
        &self,
        member: &NextSetKeyHandle,
        probe: &CustodyProbe,
    ) -> Result<ProbeSignature, KeyEventSignError> {
        let signature = self.sign_digest(member, &probe.raw_digest()).await?;
        Ok(ProbeSignature::raw(signature))
    }
}

impl NextSetCustody for InMemoryNextSetCustody {
    async fn generate(&self) -> Result<NextSetKeyHandle, NextSetCustodyError> {
        let key =
            generate_p256_os_rng().map_err(|e| NextSetCustodyError::Unavailable(e.to_string()))?;
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.keys.lock().await.insert(id, key);
        Ok(NextSetKeyHandle::new(id))
    }

    async fn reveal_public_key(
        &self,
        handle: &NextSetKeyHandle,
    ) -> Result<[u8; 33], NextSetCustodyError> {
        self.keys
            .lock()
            .await
            .get(&handle.id())
            .map(|key| key.public_key().to_compressed())
            .ok_or(NextSetCustodyError::HandleNotFound)
    }

    async fn destroy(&self, handle: &NextSetKeyHandle) -> Result<(), NextSetCustodyError> {
        self.keys
            .lock()
            .await
            .remove(&handle.id())
            .map(drop)
            .ok_or(NextSetCustodyError::HandleNotFound)
    }

    fn custody_kind(&self) -> PreRotationCustodyKind {
        PreRotationCustodyKind::InMemory
    }
}

/// The five behaviours spec 16 §16.12.3a requires of every `NextSetCustody`.
#[cfg(test)]
mod tests {
    use scp_crypto::p256::{P256PublicKey, verify_prehash_strict};
    use scp_kel::{
        CustodyProbe, IndexedSignature, KeyEventSignError, KeyEventSigner, SignatureForm,
        SigningChange,
    };
    use sha2::{Digest, Sha256};

    use super::InMemoryNextSetCustody;
    use crate::traits::{
        NextSetCustody, NextSetCustodyError, NextSetKeyHandle, PreRotationCustodyKind,
    };

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// Spec 25 Vector 41's preimage (364 bytes, separator included).
    const V41_PREIMAGE: &str = concat!(
        "5343502d4b454c2d4556454e542d56313a010000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000100",
        "00000001010000000000000001033b1cac23f45cf1cdfdf0b32f8f777b99166c",
        "1b69649c2295b1517883d47f3027000000010000000100000002033b1cac23f4",
        "5cf1cdfdf0b32f8f777b99166c1b69649c2295b1517883d47f30270101000000",
        "000000000001010223702a648232f2d00713de9289753c2fbd4c4efa7e1e3390",
        "5e3723a412b20aea020100000000000000000101000000019d94df95bc0a13f1",
        "963f484414c320354c73c75bb86e96559e97765f5bc2d31300000e1002000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000100000001421be508c6ed135a9737895007e5ba16f9542e1b3440f6d00a51",
        "5de80a3e43eb010100000001",
    );
    /// Spec 25 Vector 41's preimage digest D.
    const V41_DIGEST: &str = "d8ba4ebad52657208736f4cac675352f5f9cc0aa837620f8d742dbf42aeedbd7";

    fn v41_change() -> Result<SigningChange, Box<dyn std::error::Error>> {
        let change = SigningChange::inception(&hex::decode(V41_PREIMAGE)?)
            .map_err(|refusal| format!("{refusal:?}"))?;
        assert_eq!(hex::encode(change.digest()), V41_DIGEST);
        Ok(change)
    }

    fn raw(signature: IndexedSignature) -> Result<[u8; 64], String> {
        match signature {
            IndexedSignature::Raw { signature } => Ok(signature),
            other @ IndexedSignature::WebAuthnAssertion(_) => {
                Err(format!("expected the raw arm, got {other:?}"))
            }
        }
    }

    #[tokio::test]
    async fn generate_then_reveal_gives_compressed_point() -> TestResult {
        let custody = InMemoryNextSetCustody::new();
        let first = custody.generate().await?;
        let second = custody.generate().await?;
        assert_ne!(first, second);
        let point = custody.reveal_public_key(&first).await?;
        assert!(matches!(point[0], 0x02 | 0x03), "{:#04x}", point[0]);
        P256PublicKey::from_sec1(&point)?;
        assert_ne!(point, custody.reveal_public_key(&second).await?);
        assert_eq!(custody.custody_kind(), PreRotationCustodyKind::InMemory);
        Ok(())
    }

    #[tokio::test]
    async fn sign_change_verifies() -> TestResult {
        let custody = InMemoryNextSetCustody::new();
        let handle = custody.generate().await?;
        let key = P256PublicKey::from_sec1(&custody.reveal_public_key(&handle).await?)?;
        let change = v41_change()?;
        let signature = raw(custody.sign_change(&handle, &change).await?)?;
        verify_prehash_strict(&key, &change.digest(), &signature)?;
        // Not a signature over the 49-byte assertion challenge's hash.
        let challenge_hash: [u8; 32] = Sha256::digest(change.key_event_challenge()).into();
        assert!(verify_prehash_strict(&key, &challenge_hash, &signature).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn sign_probe_signs_the_probe_preimage_only() -> TestResult {
        let custody = InMemoryNextSetCustody::new();
        let handle = custody.generate().await?;
        let point = custody.reveal_public_key(&handle).await?;
        let probe = CustodyProbe::fresh()?;
        let signature = custody.sign_probe(&handle, &probe).await?;
        assert_eq!(signature.form(), SignatureForm::Raw);
        // `verify` recomputes the probe's raw digest, so a signature over the
        // nonce, an event digest or a key-event challenge fails here.
        signature.verify(&probe, &point)?;
        // The signature covers this probe's nonce and no other.
        assert!(signature.verify(&CustodyProbe::fresh()?, &point).is_err());
        // A change signature by the same key is not a probe signature.
        let over_event = raw(custody.sign_change(&handle, &v41_change()?).await?)?;
        assert!(
            scp_kel::ProbeSignature::raw(over_event)
                .verify(&probe, &point)
                .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn destroy_prevents_sign() -> TestResult {
        let custody = InMemoryNextSetCustody::new();
        let handle = custody.generate().await?;
        let kept = custody.generate().await?;
        let change = v41_change()?;
        custody.sign_change(&handle, &change).await?;
        custody.destroy(&handle).await?;
        assert_eq!(
            custody.sign_change(&handle, &change).await,
            Err(KeyEventSignError::MemberNotFound)
        );
        assert_eq!(
            custody.sign_probe(&handle, &CustodyProbe::fresh()?).await,
            Err(KeyEventSignError::MemberNotFound)
        );
        assert!(matches!(
            custody.reveal_public_key(&handle).await,
            Err(NextSetCustodyError::HandleNotFound)
        ));
        assert!(matches!(
            custody.destroy(&handle).await,
            Err(NextSetCustodyError::HandleNotFound)
        ));
        // Destroying one key leaves the other.
        custody.sign_change(&kept, &change).await?;
        Ok(())
    }

    #[tokio::test]
    async fn invalid_handle_errors() -> TestResult {
        let custody = InMemoryNextSetCustody::new();
        custody.generate().await?;
        let unknown = NextSetKeyHandle::new(999);
        assert!(matches!(
            custody.reveal_public_key(&unknown).await,
            Err(NextSetCustodyError::HandleNotFound)
        ));
        assert!(matches!(
            custody.destroy(&unknown).await,
            Err(NextSetCustodyError::HandleNotFound)
        ));
        assert_eq!(
            custody.sign_change(&unknown, &v41_change()?).await,
            Err(KeyEventSignError::MemberNotFound)
        );
        assert_eq!(
            custody.sign_probe(&unknown, &CustodyProbe::fresh()?).await,
            Err(KeyEventSignError::MemberNotFound)
        );
        Ok(())
    }
}
