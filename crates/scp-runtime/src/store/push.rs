//! The push registrar's relay ledger: one record per relay that may hold a
//! registration of this device's push token
//! (`10-infrastructure-and-self-hosting.md` §10.7.1 **Re-registration**).
//!
//! The registrar writes a record before its first publish to a relay and
//! deletes it only once the relay has accepted a deregistration of that token,
//! or has refused in a way that shows it holds nothing. A registration whose
//! OK was lost, or a restart, therefore still leaves a record, and the
//! registrar deregisters every recorded relay that no longer hosts a context
//! of this device.
//!
//! # Key Convention
//!
//! ```text
//! push_relay/{sha256_hex(relay_url)}/{sha256_hex(token)}
//! ```
//!
//! See spec section 17.3.

use scp_platform::PushToken;
use scp_platform::traits::Storage;
use scp_protocol::discovery::push::PushPlatform;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{ProtocolRepository, StoreError};

/// The key prefix every ledger record sits under.
const PUSH_RELAY_PREFIX: &str = "push_relay/";

/// One relay that may hold a registration of `token` for `platform`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushRelayRecord {
    /// The relay's canonical URL.
    pub relay_url: String,
    /// The push platform the token belongs to.
    pub platform: PushPlatform,
    /// The token the relay may hold.
    pub token: PushToken,
}

/// The storage key of the record for (`relay_url`, `token`). Both components
/// are SHA-256 hex, so neither the URL's characters nor the token's bytes
/// reach the key.
fn push_relay_key(relay_url: &str, token: &PushToken) -> String {
    format!(
        "{PUSH_RELAY_PREFIX}{}/{}",
        hex::encode(Sha256::digest(relay_url.as_bytes())),
        hex::encode(Sha256::digest(token.as_bytes()))
    )
}

impl<S: Storage> ProtocolRepository<S> {
    /// Records that `record.relay_url` may hold a registration of
    /// `record.token`. Writing the same record again is a no-op.
    ///
    /// # Errors
    ///
    /// [`StoreError::SerializationFailed`] if serialization fails;
    /// [`StoreError::Storage`] if the write fails.
    pub(crate) async fn store_push_relay(
        &self,
        record: &PushRelayRecord,
    ) -> Result<(), StoreError> {
        let key = push_relay_key(&record.relay_url, &record.token);
        self.store_value_zeroize(&key, record).await
    }

    /// Deletes the record for (`relay_url`, `token`). Deleting a record that
    /// does not exist is a no-op.
    ///
    /// # Errors
    ///
    /// [`StoreError::Storage`] if the delete fails.
    pub(crate) async fn delete_push_relay(
        &self,
        relay_url: &str,
        token: &PushToken,
    ) -> Result<(), StoreError> {
        self.storage
            .delete(&push_relay_key(relay_url, token))
            .await?;
        Ok(())
    }

    /// Every ledger record, in key order.
    ///
    /// # Errors
    ///
    /// [`StoreError::Storage`] if a read fails;
    /// [`StoreError::DeserializationFailed`] or
    /// [`StoreError::IncompatibleVersion`] if a record does not decode. A
    /// record that does not decode fails the whole load, because skipping it
    /// would leave its relay never deregistered.
    pub(crate) async fn load_push_relays(&self) -> Result<Vec<PushRelayRecord>, StoreError> {
        let keys = self.storage.list_keys(PUSH_RELAY_PREFIX).await?;
        let mut records = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some(record) = self.load_value(&key).await? {
                records.push(record);
            }
        }
        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    use scp_platform::in_memory::InMemoryStorage;

    use super::*;

    fn record(relay_url: &str, token: &[u8]) -> PushRelayRecord {
        PushRelayRecord {
            relay_url: relay_url.to_owned(),
            platform: PushPlatform::Apns,
            token: PushToken::new(token.to_vec()),
        }
    }

    /// Records round-trip, one per (relay, token); a delete removes only its
    /// own record, and the keys hold neither the URL nor the token.
    #[tokio::test]
    async fn push_relay_records_round_trip_per_relay_and_token() -> Result<(), StoreError> {
        let store = ProtocolRepository::new_for_testing(InMemoryStorage::new());
        let a_old = record("wss://a.example/scp/v1", b"old-token");
        let a_new = record("wss://a.example/scp/v1", b"new-token");
        let b_old = record("wss://b.example/scp/v1", b"old-token");
        for r in [&a_old, &a_new, &b_old, &a_old] {
            store.store_push_relay(r).await?;
        }
        let mut loaded = store.load_push_relays().await?;
        loaded.sort_by(|x, y| {
            (&x.relay_url, x.token.as_bytes()).cmp(&(&y.relay_url, y.token.as_bytes()))
        });
        assert_eq!(loaded, vec![a_new.clone(), a_old.clone(), b_old.clone()]);

        store
            .delete_push_relay(&a_old.relay_url, &a_old.token)
            .await?;
        let mut loaded = store.load_push_relays().await?;
        loaded.sort_by(|x, y| x.relay_url.cmp(&y.relay_url));
        assert_eq!(loaded, vec![a_new, b_old]);

        for key in store.storage().list_keys(PUSH_RELAY_PREFIX).await? {
            assert!(!key.contains("example"), "{key}");
            assert!(!key.contains("token"), "{key}");
        }
        Ok(())
    }
}
