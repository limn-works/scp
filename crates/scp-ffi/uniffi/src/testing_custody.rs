//! Test-only `UniFFI` handles over the callback custody adapter.
//!
//! Swift and Kotlin tests check a host `KeyCustodyProvider` through the same
//! shared checks production runs (spec 09 §9.5, §9.5.1).
//!
//! [`TestingCallbackCustody`] wraps a host provider in the production
//! [`CallbackKeyCustody`] and exposes its `KeyCustody` operations, so a host
//! P-256 signature reaches the bridge's strict verification and a host HPKE
//! agreement reaches its peer check. It mirrors the napi-rs object of the
//! same name. [`testing_p256_verify_strict`] and [`testing_p256_ecdh`] are
//! independent oracles over `scp-crypto` a test compares the host's output
//! against.
//!
//! The whole module is compiled only with the `testing` feature, so no
//! shipped library carries it.

use std::sync::Arc;

use scp_crypto::p256::{P256PublicKey, P256SecretKey, ecdh_p256, verify_prehash_strict};
use scp_ffi_common::error_codes as codes;
use scp_platform::{CustodyType, KeyCustody, KeyHandle, PlatformError};
use zeroize::Zeroizing;

use crate::CustodyKeyType;
use crate::bridge::{CallbackKeyCustody, ScpError};

/// The error production reports for a custody failure: the bridge's
/// `From<PlatformError>`.
fn custody_err(e: PlatformError) -> ScpError {
    ScpError::from(e)
}

fn testing_handle(key_id: &str) -> Result<KeyHandle, ScpError> {
    scp_ffi_common::custody_parse::parse_handle("testing", key_id).map_err(custody_err)
}

fn validation(msg: String) -> ScpError {
    ScpError::Validation {
        msg,
        code: codes::VALID_7005.to_owned(),
    }
}

/// Test-only handle over one callback custody adapter built from a host
/// provider.
///
/// Each method runs the production adapter's `KeyCustody` operation, so the
/// bridge's checks run as they do for `identity_create_with_custody`: key
/// type and role binding, public key length and point validation, the P-256
/// signature's low-`s` normalisation and strict verification, and the HPKE
/// peer's validation before the host is called. Errors carry the codes
/// production reports.
#[derive(uniffi::Object)]
pub struct TestingCallbackCustody {
    inner: CallbackKeyCustody,
}

impl std::fmt::Debug for TestingCallbackCustody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TestingCallbackCustody")
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl TestingCallbackCustody {
    /// Wraps `provider` in a fresh callback custody adapter with an empty
    /// key registry.
    #[uniffi::constructor]
    #[must_use]
    pub fn new(provider: Box<dyn crate::KeyCustodyProvider>) -> Arc<Self> {
        Arc::new(Self {
            inner: CallbackKeyCustody::new(provider),
        })
    }

    /// Generates an operational key of `key_type` through the adapter, as
    /// `KeyCustody::generate_keypair` does in production: the host is asked
    /// for `(key_type, Operational)` and must report that type and role.
    ///
    /// # Errors
    ///
    /// The custody error production reports.
    pub async fn generate_keypair(&self, key_type: CustodyKeyType) -> Result<String, ScpError> {
        self.inner
            .generate_keypair(key_type.into())
            .await
            .map(|handle| handle.id().to_string())
            .map_err(custody_err)
    }

    /// Generates the Ed25519 identity key through the adapter, as
    /// `KeyCustody::generate_identity_keypair` does in production.
    ///
    /// # Errors
    ///
    /// The custody error production reports.
    pub async fn generate_identity_keypair(&self) -> Result<String, ScpError> {
        self.inner
            .generate_identity_keypair()
            .await
            .map(|handle| handle.id().to_string())
            .map_err(custody_err)
    }

    /// The public key the adapter holds for `key_id`: 32 bytes (Ed25519,
    /// X25519), the 33-byte compressed point (P-256 signing) or the 65-byte
    /// uncompressed point (HPKE P-256).
    ///
    /// # Errors
    ///
    /// The custody error production reports.
    pub async fn public_key(&self, key_id: String) -> Result<Vec<u8>, ScpError> {
        let key = testing_handle(&key_id)?;
        self.inner
            .public_key(&key)
            .await
            .map(|pk| pk.as_bytes().to_vec())
            .map_err(custody_err)
    }

    /// Signs `data` with `key_id` through the adapter and returns what the
    /// bridge returns: for a P-256 key, the 64-byte low-`s` signature that
    /// verified strictly over the 32-byte digest `data`.
    ///
    /// # Errors
    ///
    /// The custody error production reports.
    pub async fn sign(&self, key_id: String, data: Vec<u8>) -> Result<Vec<u8>, ScpError> {
        let key = testing_handle(&key_id)?;
        self.inner
            .sign(&key, &data)
            .await
            .map(|signature| signature.as_bytes().to_vec())
            .map_err(custody_err)
    }

    /// Runs the adapter's `dh_agree` for `key_id` against `peer_public` and
    /// returns the 32-byte shared secret the bridge read from the host.
    ///
    /// # Errors
    ///
    /// The custody error production reports.
    pub async fn dh_agree(
        &self,
        key_id: String,
        peer_public: Vec<u8>,
    ) -> Result<Vec<u8>, ScpError> {
        let key = testing_handle(&key_id)?;
        self.inner
            .dh_agree(&key, &peer_public)
            .await
            .map(|shared| shared.as_bytes().to_vec())
            .map_err(custody_err)
    }

    /// Destroys `key_id` through the adapter.
    ///
    /// # Errors
    ///
    /// The custody error production reports.
    pub async fn destroy_key(&self, key_id: String) -> Result<(), ScpError> {
        let key = testing_handle(&key_id)?;
        self.inner.destroy_key(&key).await.map_err(custody_err)
    }

    /// The custody class the bridge reads for `key_id` from the host's
    /// `custody_type` string: `"hardware"`, `"software"` or `"in_memory"`.
    ///
    /// # Errors
    ///
    /// The custody error production reports for a key id that is not a
    /// canonical decimal `u64`.
    pub fn custody_type(&self, key_id: String) -> Result<String, ScpError> {
        let key = testing_handle(&key_id)?;
        Ok(match self.inner.custody_type(&key) {
            CustodyType::Hardware => "hardware",
            CustodyType::Software => "software",
            CustodyType::InMemory => "in_memory",
        }
        .to_owned())
    }
}

/// Whether `signature` is a §9.5.1 signature over the 32-byte `digest` under
/// `public_key` (33- or 65-byte SEC1): exactly 64 bytes, low `s`, and a valid
/// ECDSA equation with no second hash.
///
/// # Errors
///
/// `SCP-VALID-7005` when `public_key` is not a valid P-256 point or `digest`
/// is not 32 bytes.
#[uniffi::export]
pub fn testing_p256_verify_strict(
    public_key: Vec<u8>,
    digest: Vec<u8>,
    signature: Vec<u8>,
) -> Result<bool, ScpError> {
    let key = P256PublicKey::from_sec1(&public_key)
        .map_err(|e| validation(format!("public_key is not a P-256 point: {e}")))?;
    let digest: [u8; 32] = digest
        .as_slice()
        .try_into()
        .map_err(|_| validation(format!("digest must be 32 bytes, got {}", digest.len())))?;
    Ok(verify_prehash_strict(&key, &digest, &signature).is_ok())
}

/// The P-256 ECDH shared secret of `peer_scalar` and `host_public`.
///
/// It is the 32-byte x-coordinate of the private scalar `peer_scalar` times
/// the 65-byte uncompressed point `host_public`: the value a host's
/// `dh_agree` must return when handed `peer_scalar`'s public point
/// (RFC 9180 §7.1.1 `DH`).
///
/// # Errors
///
/// `SCP-VALID-7005` when `peer_scalar` is not a 32-byte scalar in
/// `[1, n − 1]` or `host_public` is not a valid 65-byte uncompressed point.
#[uniffi::export]
pub fn testing_p256_ecdh(peer_scalar: Vec<u8>, host_public: Vec<u8>) -> Result<Vec<u8>, ScpError> {
    let peer_scalar = Zeroizing::new(peer_scalar);
    let scalar: Zeroizing<[u8; 32]> =
        Zeroizing::new(peer_scalar.as_slice().try_into().map_err(|_| {
            validation(format!(
                "peer_scalar must be 32 bytes, got {}",
                peer_scalar.len()
            ))
        })?);
    let secret = P256SecretKey::from_scalar_bytes(&scalar)
        .map_err(|e| validation(format!("peer_scalar is not a P-256 scalar: {e}")))?;
    let host = P256PublicKey::from_uncompressed(&host_public)
        .map_err(|e| validation(format!("host_public is not a 65-byte P-256 point: {e}")))?;
    Ok(ecdh_p256(&secret, &host).to_vec())
}

/// Makes `target` resolve DIDs through `source`'s DHT client.
///
/// Two processes sharing the Mainline DHT resolve each other's DIDs; this
/// gives two instances in one test process the same reach, so a Swift or
/// Kotlin test can invite an identity of one instance from another.
///
/// Call it after `source`'s first identity call, which creates its client,
/// and before `target`'s first identity call: a resolver keeps the client it
/// was given first.
///
/// # Errors
///
/// `SCP-VALID-7000` when `source` has made no identity call, so it has no
/// DHT client to share.
#[uniffi::export]
pub fn testing_share_did_resolver(
    source: Arc<crate::scp::Scp>,
    target: Arc<crate::scp::Scp>,
) -> Result<(), ScpError> {
    let client =
        crate::runtime::resolver_dht_client(&source.inner).ok_or_else(|| ScpError::Validation {
            msg: "the source instance has no DHT client; create an identity on it first".to_owned(),
            code: codes::VALID_7000.to_owned(),
        })?;
    crate::runtime::set_resolver_dht_client(&target.inner, client);
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::bridge::tests::FakeHostProvider;
    use scp_ffi_common::callback_custody::fake_host::{FakeHost, scalar_for};

    fn custody_over(
        host: &Arc<FakeHost>,
        custody_type: &'static str,
    ) -> Arc<TestingCallbackCustody> {
        let mut provider = FakeHostProvider::over(host);
        provider.custody_type = custody_type;
        TestingCallbackCustody::new(Box::new(provider))
    }

    /// A P-256 signature through the object is the 64-byte low-`s` form the
    /// strict oracle accepts (the fake host returns high-`s` DER), and the
    /// oracle rejects the same signature over another digest.
    #[tokio::test]
    async fn sign_returns_a_signature_the_strict_oracle_accepts() {
        let host = Arc::new(FakeHost::default());
        let custody = custody_over(&host, "software");
        let key = custody
            .generate_keypair(CustodyKeyType::P256)
            .await
            .unwrap();
        let public = custody.public_key(key.clone()).await.unwrap();
        assert_eq!(public.len(), 33);
        let digest = vec![9u8; 32];
        let signature = custody.sign(key, digest.clone()).await.unwrap();
        assert_eq!(signature.len(), 64);
        assert!(testing_p256_verify_strict(public.clone(), digest, signature.clone()).unwrap());
        assert!(!testing_p256_verify_strict(public, vec![8u8; 32], signature).unwrap());
    }

    /// The HPKE agreement through the object equals the oracle's ECDH of the
    /// peer scalar with the host's public point.
    #[tokio::test]
    async fn dh_agree_matches_the_ecdh_oracle() {
        let host = Arc::new(FakeHost::default());
        let custody = custody_over(&host, "software");
        let key = custody
            .generate_keypair(CustodyKeyType::HpkeP256)
            .await
            .unwrap();
        let host_public = custody.public_key(key.clone()).await.unwrap();
        assert_eq!(host_public.len(), 65);
        let peer_scalar = [0x5au8; 32];
        let peer = P256SecretKey::from_scalar_bytes(&peer_scalar)
            .unwrap()
            .public_key();
        let shared = custody
            .dh_agree(key, peer.to_uncompressed().to_vec())
            .await
            .unwrap();
        let expected = testing_p256_ecdh(peer_scalar.to_vec(), host_public).unwrap();
        assert_eq!(shared, expected);
        assert_eq!(shared.len(), 32);
    }

    /// The oracle's answer is the ECDH the host computes with its own
    /// scalar, so the oracle is not checked only against itself.
    #[test]
    fn ecdh_oracle_matches_the_host_side_computation() {
        let host = P256SecretKey::from_scalar_bytes(&scalar_for(1)).unwrap();
        let peer_scalar = [0x5au8; 32];
        let peer = P256SecretKey::from_scalar_bytes(&peer_scalar).unwrap();
        let from_host = ecdh_p256(&host, &peer.public_key());
        let from_oracle = testing_p256_ecdh(
            peer_scalar.to_vec(),
            host.public_key().to_uncompressed().to_vec(),
        )
        .unwrap();
        assert_eq!(from_oracle, from_host.to_vec());
    }

    /// The object reports the bridge's reading of the host's custody string:
    /// `"hardware"` is hardware, and an unrecognised string is in-memory.
    #[tokio::test]
    async fn custody_type_reports_the_bridge_mapping() {
        let host = Arc::new(FakeHost::default());
        for (reported, seen) in [
            ("hardware", "hardware"),
            ("software", "software"),
            ("software_biometric", "software"),
            ("secureEnclave", "in_memory"),
        ] {
            let custody = custody_over(&host, reported);
            let key = custody
                .generate_keypair(CustodyKeyType::P256)
                .await
                .unwrap();
            assert_eq!(custody.custody_type(key).unwrap(), seen, "{reported}");
        }
    }

    /// A wrong-type operation is `SCP-CRYPTO-4060` and never reaches the
    /// host; a destroyed key is key-not-found (`SCP-CRYPTO-4006`); a
    /// non-canonical id is `SCP-CRYPTO-4060`.
    #[tokio::test]
    async fn errors_carry_production_codes() {
        let host = Arc::new(FakeHost::default());
        let custody = custody_over(&host, "software");
        let signing = custody
            .generate_keypair(CustodyKeyType::P256)
            .await
            .unwrap();
        let peer = P256SecretKey::from_scalar_bytes(&[3u8; 32])
            .unwrap()
            .public_key()
            .to_uncompressed()
            .to_vec();
        let err = custody
            .dh_agree(signing.clone(), peer)
            .await
            .expect_err("a signing key does not agree");
        assert_eq!(err.code(), codes::CRYPTO_4060, "{err:?}");
        assert_eq!(host.calls("dh_agree"), 0);
        custody.destroy_key(signing.clone()).await.unwrap();
        let err = custody.public_key(signing).await.expect_err("destroyed");
        assert_eq!(err.code(), codes::CRYPTO_4006, "{err:?}");
        let err = custody
            .public_key("007".to_owned())
            .await
            .expect_err("non-canonical id");
        assert_eq!(err.code(), codes::CRYPTO_4060, "{err:?}");
    }

    /// The oracles reject malformed inputs with `SCP-VALID-7005`.
    #[test]
    fn oracles_reject_malformed_input() {
        let point = P256SecretKey::from_scalar_bytes(&[3u8; 32])
            .unwrap()
            .public_key();
        // x = 2^256 − 1 is above the field prime, so no point has it.
        let mut off_field = vec![0xffu8; 33];
        off_field[0] = 0x02;
        for err in [
            testing_p256_verify_strict(off_field, vec![0; 32], vec![0; 64]).unwrap_err(),
            testing_p256_verify_strict(point.to_compressed().to_vec(), vec![0; 31], vec![0; 64])
                .unwrap_err(),
            testing_p256_ecdh(vec![0; 32], point.to_uncompressed().to_vec()).unwrap_err(),
            testing_p256_ecdh(vec![1; 31], point.to_uncompressed().to_vec()).unwrap_err(),
            testing_p256_ecdh(vec![1; 32], point.to_compressed().to_vec()).unwrap_err(),
        ] {
            assert_eq!(err.code(), codes::VALID_7005, "{err:?}");
        }
    }

    /// Sharing fails while the source has no DHT client, and afterwards the
    /// target resolves through the source's client.
    #[test]
    fn share_did_resolver_hands_the_source_client_to_the_target() {
        let rt = crate::runtime();
        let source = crate::scp::Scp::new_in_memory_for_test();
        let target = crate::scp::Scp::new_in_memory_for_test();
        let err = testing_share_did_resolver(Arc::clone(&source), Arc::clone(&target))
            .expect_err("a source with no identity has no client to share");
        assert_eq!(err.code(), codes::VALID_7000, "{err:?}");

        rt.block_on(source.identity_create("in_memory".to_owned(), None))
            .expect("source identity");
        testing_share_did_resolver(Arc::clone(&source), Arc::clone(&target))
            .expect("the source now has a client");
        let shared = crate::runtime::resolver_dht_client(&source.inner).expect("source client");
        let installed = crate::runtime::resolver_dht_client(&target.inner).expect("target client");
        assert!(
            Arc::ptr_eq(&shared, &installed),
            "the target must resolve through the source's client"
        );
    }
}
