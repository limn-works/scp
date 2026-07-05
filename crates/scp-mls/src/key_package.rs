//! `KeyPackage` buffer management for SCP.
//!
//! MLS requires single-use `KeyPackage`s for offline member addition. The SDK
//! must maintain a ready supply so that new members can be added without
//! blocking on key generation.
//!
//! The [`KeyPackageBuffer`] wraps the existing [`generate_key_package`] function
//! from [`crate::group`] and maintains a pre-generated pool of key packages,
//! automatically replenishing when the buffer drops below a threshold.
//!
//! # Buffer defaults (ADR-001, criterion 8)
//!
//! - Minimum buffer size: 10 key packages per identity
//! - Replenish threshold: 5 (replenish when buffer drops below 5)
//!
//! [`generate_key_package`]: crate::group::generate_key_package

use std::sync::Arc;

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use scp_clock::Clock;

use crate::InMemoryMlsProvider;
use crate::credential::ScpCredential;
use crate::error::MlsError;
use crate::group::generate_key_package;

/// Default minimum buffer size: 10 key packages per identity.
const DEFAULT_MIN_BUFFER: usize = 10;

/// Default replenish threshold: replenish when buffer drops below 5.
const DEFAULT_REPLENISH_THRESHOLD: usize = 5;

/// A single entry in the key package buffer.
///
/// Each entry contains the key package bundle (public key package + private
/// keys), the associated signing key pair, and the MLS provider that holds
/// the key material in its storage. All three must be retained together because
/// the private keys stored in the provider are needed when the key package is
/// used to join a group via a Welcome message.
pub struct KeyPackageEntry {
    /// The `KeyPackage` bundle containing the public key package and private
    /// key material stored in the provider.
    pub bundle: KeyPackageBundle,
    /// The Ed25519 signing key pair associated with this key package.
    pub signer: SignatureKeyPair,
    /// The MLS provider holding the cryptographic state for this key package.
    pub provider: InMemoryMlsProvider,
}

/// Pre-generated buffer of single-use `KeyPackage`s for offline member addition.
///
/// Maintains a pool of key packages for a single identity, automatically
/// replenishing when the pool drops below the configured threshold. Each
/// key package is single-use (consumed when used to add the identity to a
/// group).
///
/// # Usage
///
/// ```rust,ignore
/// let cred = ScpCredential::new("did:dht:z6MkAlice".to_string(), None, SigningKeyId::Active)?;
/// let mut buffer = KeyPackageBuffer::new(cred, Arc::new(SystemClock), 10, 5)?;
///
/// // Take a key package to give to someone who wants to add us.
/// let entry = buffer.take()?;
/// // entry.bundle.key_package() is the public part to share.
/// ```
///
/// See ADR-001 acceptance criterion 8.
pub struct KeyPackageBuffer {
    /// The identity credential for which key packages are generated.
    credential: ScpCredential,
    /// The injected hardened [`Clock`] used to stamp each generated key
    /// package's `Lifetime` (ADR-057 §Prereq-1). Shared (`Arc`) because the
    /// buffer outlives individual generations and the same clock instance is
    /// threaded through the rest of the client.
    clock: Arc<dyn Clock>,
    /// The minimum number of key packages to maintain.
    min_buffer: usize,
    /// When the buffer drops below this count, replenish to `min_buffer`.
    replenish_threshold: usize,
    /// The pool of pre-generated key package entries.
    entries: Vec<KeyPackageEntry>,
}

impl KeyPackageBuffer {
    /// Creates a new key package buffer with the given parameters, pre-filled
    /// to `min_buffer` entries.
    ///
    /// # Arguments
    ///
    /// * `credential` - The identity credential to generate key packages for.
    /// * `clock` - The injected hardened [`Clock`] used to stamp each key
    ///   package's `Lifetime` (ADR-057 §Prereq-1).
    /// * `min_buffer` - The target buffer size (replenish up to this count).
    /// * `replenish_threshold` - When the buffer drops below this, trigger
    ///   replenishment.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError`] if initial key package generation fails.
    pub fn new(
        credential: ScpCredential,
        clock: Arc<dyn Clock>,
        min_buffer: usize,
        replenish_threshold: usize,
    ) -> Result<Self, MlsError> {
        let mut buffer = Self {
            credential,
            clock,
            min_buffer,
            replenish_threshold,
            entries: Vec::with_capacity(min_buffer),
        };
        buffer.replenish()?;
        Ok(buffer)
    }

    /// Creates a new key package buffer with the default parameters (10/5).
    ///
    /// # Arguments
    ///
    /// * `credential` - The identity credential to generate key packages for.
    /// * `clock` - The injected hardened [`Clock`] used to stamp each key
    ///   package's `Lifetime` (ADR-057 §Prereq-1).
    ///
    /// # Errors
    ///
    /// Returns [`MlsError`] if initial key package generation fails.
    pub fn with_defaults(
        credential: ScpCredential,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, MlsError> {
        Self::new(
            credential,
            clock,
            DEFAULT_MIN_BUFFER,
            DEFAULT_REPLENISH_THRESHOLD,
        )
    }

    /// Takes one key package from the buffer.
    ///
    /// If the buffer drops below the replenish threshold after taking, the
    /// buffer is automatically replenished back to `min_buffer`.
    ///
    /// # Returns
    ///
    /// A [`KeyPackageEntry`] containing the key package bundle, signing key,
    /// and provider. The caller must retain all three to later join a group
    /// via a Welcome message.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::KeyPackageBufferExhausted`] if the buffer is empty
    /// (should not happen under normal operation since replenishment is
    /// automatic, but can occur if key generation fails during replenishment).
    /// Returns [`MlsError`] if replenishment fails.
    pub fn take(&mut self) -> Result<KeyPackageEntry, MlsError> {
        let entry = self
            .entries
            .pop()
            .ok_or(MlsError::KeyPackageBufferExhausted)?;

        // Replenish if we've dropped below the threshold.
        if self.entries.len() < self.replenish_threshold {
            self.replenish()?;
        }

        Ok(entry)
    }

    /// Generates key packages until the buffer reaches `min_buffer` size.
    ///
    /// Each generated key package uses the buffer's credential and the SCP
    /// ciphersuite (`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`).
    ///
    /// # Errors
    ///
    /// Returns [`MlsError`] if any key package generation fails. Partially
    /// generated packages are retained in the buffer.
    pub fn replenish(&mut self) -> Result<(), MlsError> {
        while self.entries.len() < self.min_buffer {
            let (bundle, signer, provider) =
                generate_key_package(&self.credential, self.clock.as_ref())?;
            self.entries.push(KeyPackageEntry {
                bundle,
                signer,
                provider,
            });
        }
        Ok(())
    }

    /// Returns the current number of key packages in the buffer.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the buffer contains no key packages.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::SCP_CIPHERSUITE;
    use scp_clock::SystemClock;

    #[allow(clippy::unwrap_used)]
    fn test_credential(name: &str) -> ScpCredential {
        ScpCredential::new(
            format!("did:dht:z6Mk{name}"),
            None,
            scp_did::SigningKeyId::Active,
        )
        .unwrap()
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn new_buffer_has_min_buffer_entries() {
        let cred = test_credential("alice");
        let buffer = KeyPackageBuffer::new(cred, Arc::new(SystemClock), 10, 5).unwrap();
        assert_eq!(buffer.len(), 10);
        assert!(!buffer.is_empty());
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn with_defaults_creates_10_entries() {
        let cred = test_credential("alice");
        let buffer = KeyPackageBuffer::with_defaults(cred, Arc::new(SystemClock)).unwrap();
        assert_eq!(buffer.len(), 10);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn take_returns_valid_key_package() {
        let cred = test_credential("alice");
        let mut buffer = KeyPackageBuffer::new(cred, Arc::new(SystemClock), 10, 5).unwrap();

        let entry = buffer.take().unwrap();
        assert_eq!(
            entry.bundle.key_package().ciphersuite(),
            SCP_CIPHERSUITE,
            "key package must use SCP ciphersuite"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn take_replenishes_when_below_threshold() {
        let cred = test_credential("alice");
        let mut buffer = KeyPackageBuffer::new(cred, Arc::new(SystemClock), 10, 5).unwrap();

        // Take 6 entries to drop below threshold (10 - 6 = 4, which is < 5).
        for _ in 0..6 {
            let _entry = buffer.take().unwrap();
        }

        // After the 6th take, replenishment should have triggered.
        // Buffer should be back to min_buffer (10).
        assert_eq!(
            buffer.len(),
            10,
            "buffer should replenish to min_buffer after dropping below threshold"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn take_does_not_replenish_above_threshold() {
        let cred = test_credential("alice");
        let mut buffer = KeyPackageBuffer::new(cred, Arc::new(SystemClock), 10, 5).unwrap();

        // Take 4 entries. Remaining = 6, which is >= 5 (threshold).
        for _ in 0..4 {
            let _entry = buffer.take().unwrap();
        }

        assert_eq!(
            buffer.len(),
            6,
            "buffer should NOT replenish when still at or above threshold"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn each_key_package_is_unique() {
        let cred = test_credential("alice");
        let mut buffer = KeyPackageBuffer::new(cred, Arc::new(SystemClock), 5, 2).unwrap();

        let entry1 = buffer.take().unwrap();
        let entry2 = buffer.take().unwrap();

        // The key packages should have different HPKE init keys.
        let key1 = entry1
            .bundle
            .key_package()
            .hpke_init_key()
            .as_slice()
            .to_vec();
        let key2 = entry2
            .bundle
            .key_package()
            .hpke_init_key()
            .as_slice()
            .to_vec();

        assert_ne!(key1, key2, "each key package should have a unique HPKE key");
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn key_package_can_be_used_for_add_member() {
        let cred = test_credential("bob");
        let mut buffer = KeyPackageBuffer::new(cred, Arc::new(SystemClock), 10, 5).unwrap();

        let entry = buffer.take().unwrap();

        // Create a group and add the buffered key package's owner.
        let alice_cred = test_credential("alice");
        let mut alice_group = crate::group::create_group(&alice_cred, &SystemClock).unwrap();

        let kp_in: KeyPackageIn = entry.bundle.key_package().clone().into();
        let add_result = crate::group::add_member(&mut alice_group, kp_in, &SystemClock).unwrap();

        // Bob joins using the Welcome, with the provider and signer from the buffer entry.
        let bob_group =
            crate::group::join_group(&add_result.welcome, entry.provider, entry.signer).unwrap();

        assert_eq!(bob_group.epoch().unwrap(), 1, "Bob should join at epoch 1");
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn replenish_on_empty_buffer_fills_to_min() {
        let cred = test_credential("alice");
        let mut buffer = KeyPackageBuffer {
            credential: cred,
            clock: Arc::new(SystemClock),
            min_buffer: 10,
            replenish_threshold: 5,
            entries: Vec::new(),
        };

        assert!(buffer.is_empty());
        buffer.replenish().unwrap();
        assert_eq!(buffer.len(), 10);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn small_buffer_sizes_work() {
        let cred = test_credential("alice");
        let mut buffer = KeyPackageBuffer::new(cred, Arc::new(SystemClock), 2, 1).unwrap();
        assert_eq!(buffer.len(), 2);

        let _entry = buffer.take().unwrap();
        // Now at 1, which is >= threshold of 1, so no replenish.
        assert_eq!(buffer.len(), 1);

        let _entry = buffer.take().unwrap();
        // Now at 0, which is < threshold of 1, so replenish to 2.
        assert_eq!(buffer.len(), 2);
    }
}
