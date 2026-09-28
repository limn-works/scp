//! The in-memory P-256 pseudonym keys (§9.10.4) of a software custody, each
//! owned by the identity it was derived from.
//!
//! A pseudonym key is held in memory only, because it re-derives from its
//! identity key. Each one sits in a slot keyed on (identity, context, epoch),
//! so re-deriving returns the handle already there, and destroying the
//! identity removes every slot it owns (§9.10.4.A). A custody inserts only under
//! the lock its identity destroy holds, and only after finding the identity
//! still present under that lock, so a derive cannot land after the
//! identity's destroy.

use std::collections::HashMap;

use scp_crypto::p256::P256SigningKey;

/// A pseudonym's slot: the identity handle, the context id, and the epoch
/// (`None` for the v1 static pseudonym).
type Slot = (u64, Vec<u8>, Option<u64>);

/// The pseudonym keys of one software custody.
///
/// Each key is boxed, so a resize of `keys` moves only the pointer and never
/// frees an unwiped copy of a scalar.
#[derive(Default)]
pub struct PseudonymKeys {
    keys: HashMap<u64, Box<P256SigningKey>>,
    slots: HashMap<Slot, u64>,
}

impl PseudonymKeys {
    /// The key behind pseudonym handle `handle`.
    pub fn get(&self, handle: u64) -> Option<&P256SigningKey> {
        self.keys.get(&handle).map(|key| &**key)
    }

    /// The handle and compressed point already derived for `identity`,
    /// `context_id` and `epoch`.
    pub fn existing(
        &self,
        identity: u64,
        context_id: &[u8],
        epoch: Option<u64>,
    ) -> Option<(u64, [u8; 33])> {
        let handle = *self.slots.get(&(identity, context_id.to_vec(), epoch))?;
        let key = self.keys.get(&handle)?;
        Some((handle, key.public_key().to_compressed()))
    }

    /// Stores `key` under `handle` in the slot of `identity`, `context_id`
    /// and `epoch`.
    pub fn insert(
        &mut self,
        identity: u64,
        context_id: &[u8],
        epoch: Option<u64>,
        handle: u64,
        key: Box<P256SigningKey>,
    ) {
        self.keys.insert(handle, key);
        self.slots
            .insert((identity, context_id.to_vec(), epoch), handle);
    }

    /// Removes pseudonym handle `handle`; `false` when it is not a pseudonym.
    pub fn remove(&mut self, handle: u64) -> bool {
        if self.keys.remove(&handle).is_none() {
            return false;
        }
        self.slots.retain(|_, h| *h != handle);
        true
    }

    /// Removes every pseudonym derived from `identity` and returns their
    /// handles.
    pub fn remove_identity(&mut self, identity: u64) -> Vec<u64> {
        let mut removed = Vec::new();
        self.slots.retain(|(owner, _, _), handle| {
            if *owner == identity {
                removed.push(*handle);
                false
            } else {
                true
            }
        });
        for handle in &removed {
            self.keys.remove(handle);
        }
        removed
    }
}

/// Shared tests for the software custodies that hold pseudonym keys.
#[cfg(test)]
pub mod tests {
    /// Checks the two properties every software custody owes its pseudonyms: a
    /// re-derive returns the handle already in the slot, and destroying the
    /// identity destroys every pseudonym derived from it (§9.10.4.A), v1 and v2
    /// alike. Each custody's test module calls this with a fresh custody.
    pub async fn check_identity_owns_pseudonyms<C: crate::traits::KeyCustody>(
        custody: &C,
    ) -> Result<(), crate::error::PlatformError> {
        use crate::error::PlatformError;
        let identity = custody.generate_identity_keypair().await?;
        let other = custody.generate_identity_keypair().await?;

        let v1 = custody.derive_pseudonym(&identity, b"ctx-a").await?;
        let v2 = custody
            .derive_rotatable_pseudonym(&identity, b"ctx-b", 7)
            .await?;
        let kept = custody.derive_pseudonym(&other, b"ctx-a").await?;

        // A re-derive of the same (identity, context, epoch) returns the same
        // handle, not a second live scalar.
        let v1_again = custody.derive_pseudonym(&identity, b"ctx-a").await?;
        assert_eq!(v1_again.key_handle().id(), v1.key_handle().id());
        assert_eq!(v1_again.public_key().as_bytes(), v1.public_key().as_bytes());
        let v2_again = custody
            .derive_rotatable_pseudonym(&identity, b"ctx-b", 7)
            .await?;
        assert_eq!(v2_again.key_handle().id(), v2.key_handle().id());
        // Another epoch is another slot.
        let v2_next = custody
            .derive_rotatable_pseudonym(&identity, b"ctx-b", 8)
            .await?;
        assert_ne!(v2_next.key_handle().id(), v2.key_handle().id());

        custody.destroy_key(&identity).await?;

        for pseudonym in [&v1, &v2, &v2_next] {
            let handle = pseudonym.key_handle();
            assert!(
                matches!(
                    custody.sign(handle, &[0u8; 32]).await,
                    Err(PlatformError::KeyNotFound)
                ),
                "a pseudonym of a destroyed identity must not sign"
            );
            assert!(
                matches!(
                    custody.public_key(handle).await,
                    Err(PlatformError::KeyNotFound)
                ),
                "a pseudonym of a destroyed identity must have no public key"
            );
        }
        // Another identity's pseudonym is untouched.
        custody.sign(kept.key_handle(), &[0u8; 32]).await?;
        // A derive for the destroyed identity fails.
        assert!(matches!(
            custody.derive_pseudonym(&identity, b"ctx-a").await,
            Err(PlatformError::KeyNotFound)
        ));
        Ok(())
    }
}
