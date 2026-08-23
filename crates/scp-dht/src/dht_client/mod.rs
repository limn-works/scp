//! DHT client abstraction for DID publishing and resolution.
//!
//! Defines the [`DhtClient`] trait that abstracts Mainline DHT operations
//! (BEP44 signed mutable items). This enables testing with [`InMemoryDhtClient`]
//! while production code uses a real DHT client.
//!
//! # Production Implementations
//!
//! - [`PkarrDhtClient`] — Uses the `mainline` crate for direct Mainline DHT
//!   BEP44 operations, with optional HTTP gateway fallback for resolution
//!   behind restrictive firewalls. Enabled via the `production-dht` feature.
//!
//! See ADR-003 in `.docs/adrs/phase-1.md` and §3.10 (DID Resolution Layers).

// `HashMap`/`Mutex` back the testing-only `InMemoryDhtClient`; gate the imports
// so a shipped (non-testing) build carries no unused-import warning.
#[cfg(feature = "testing")]
use std::collections::HashMap;

#[cfg(feature = "testing")]
use tokio::sync::Mutex;

use crate::DhtError;

/// Abstraction over BEP44 signed mutable item operations on a DHT.
///
/// Production implementations use the `mainline` crate for Mainline DHT access.
/// The [`InMemoryDhtClient`] provides a `HashMap`-backed implementation for
/// unit tests that require no network access.
///
/// # BEP44 Model
///
/// Each item is keyed by a 32-byte Ed25519 public key. The value is an opaque
/// byte blob (the serialized DID document) with a monotonically increasing
/// sequence number and a 64-byte Ed25519 signature over the value + sequence.
pub trait DhtClient: Send + Sync {
    /// Publishes a BEP44 signed mutable item to the DHT.
    ///
    /// # Arguments
    ///
    /// * `public_key` — The 32-byte Ed25519 public key that identifies this item.
    /// * `signature` — The 64-byte Ed25519 signature over the encoded value + sequence.
    /// * `value` — The serialized DID document bytes.
    /// * `seq` — The monotonically increasing sequence number.
    ///
    /// # Errors
    ///
    /// Returns [`DhtError::DhtPublishFailed`] if the publish operation fails.
    fn publish(
        &self,
        public_key: &[u8; 32],
        signature: &[u8; 64],
        value: &[u8],
        seq: u64,
    ) -> impl Future<Output = Result<(), DhtError>> + Send;

    /// Resolves a BEP44 signed mutable item from the DHT.
    ///
    /// # Arguments
    ///
    /// * `public_key` — The 32-byte Ed25519 public key to look up.
    ///
    /// # Returns
    ///
    /// [`DhtLookup::Record`] when a source this client reached returned a BEP44
    /// record for `public_key`. [`DhtLookup::NoRecord`] when a source this
    /// client reached reported that it holds no record for `public_key`.
    ///
    /// An implementation returns `Ok(..)` only when it reached a source that
    /// reported on this key. It reports every other outcome as `Err`, so a
    /// caller never reads an unreached DHT as evidence that nobody published
    /// the key (§3.10.4).
    ///
    /// # Errors
    ///
    /// Returns [`DhtError::DhtResolveFailed`] when this client reached no
    /// source that reported on `public_key`, and [`DhtError::Disabled`] when
    /// the DHT layer is switched off.
    fn resolve(
        &self,
        public_key: &[u8; 32],
    ) -> impl Future<Output = Result<DhtLookup, DhtError>> + Send;
}

/// What a DHT lookup observed about a public key (§3.10.4).
///
/// **The criterion:** a lookup produces a `DhtLookup` only when the client
/// reached a DHT source that reported on the requested key. Both variants are
/// therefore answers, and the [`DualLayerResolver`] records either one as a DHT
/// layer that answered. A client that reached no source — the DHT arm is
/// switched off, every gateway request failed, no DHT node responded — returns
/// [`DhtError`] instead, which the resolver records as a layer that could not
/// answer.
///
/// The distinction is load-bearing: an unreachable DHT that reported
/// "no record" would let an attacker who blocks DHT traffic manufacture a
/// positive claim that nobody published a DID (§3.10.4, "One layer fails, the
/// other reports the DID absent").
///
/// [`DualLayerResolver`]: https://docs.rs/scp-identity
#[derive(Debug, Clone)]
pub enum DhtLookup {
    /// A source this client reached returned a BEP44 record for the key.
    Record(DhtRecord),
    /// A source this client reached reported that it holds no record for the
    /// key.
    NoRecord,
}

impl DhtLookup {
    /// Returns the record when a source returned one, and `None` when a source
    /// reported that it holds no record.
    #[must_use]
    pub fn into_record(self) -> Option<DhtRecord> {
        match self {
            Self::Record(record) => Some(record),
            Self::NoRecord => None,
        }
    }

    /// Borrows the record when a source returned one.
    #[must_use]
    pub const fn record(&self) -> Option<&DhtRecord> {
        match self {
            Self::Record(record) => Some(record),
            Self::NoRecord => None,
        }
    }
}

/// A BEP44 record retrieved from the DHT.
#[derive(Debug, Clone)]
pub struct DhtRecord {
    /// The serialized DID document bytes.
    pub value: Vec<u8>,
    /// The Ed25519 signature over the BEP44 encoded payload.
    pub signature: [u8; 64],
    /// The monotonically increasing sequence number.
    pub seq: u64,
}

/// In-memory DHT client for testing.
///
/// Stores BEP44 mutable items in a `HashMap` keyed by the 32-byte public key.
/// Enforces the BEP44 monotonic sequence number invariant: a publish with a
/// sequence number less than or equal to the existing one is silently ignored
/// (idempotent no-op).
///
/// This implementation requires no network access and is suitable for unit
/// tests. It is a **§17.17.3 resolve nullifier** — a publish reaches no peer
/// and a resolve sees no peer's writes — and therefore MUST NOT ship on any
/// production path. The type is compiled only under the `testing` feature
/// (ADR-062 §Decision 1 / A5) — a **single** activation path (never a bare
/// `#[cfg(test)]` disjunct, which is a second, cross-crate-invisible path that
/// G1's feature-graph check cannot see), so a shipped graph cannot name it.
/// This crate's own unit tests activate it via the `testing` dev-dependency.
#[cfg(feature = "testing")]
#[derive(Debug, Default)]
pub struct InMemoryDhtClient {
    /// Map from public key bytes to (value, signature, sequence number).
    items: Mutex<HashMap<[u8; 32], StoredItem>>,
}

/// A stored BEP44 item in the in-memory DHT.
#[cfg(feature = "testing")]
#[derive(Debug, Clone)]
struct StoredItem {
    value: Vec<u8>,
    signature: [u8; 64],
    seq: u64,
}

#[cfg(feature = "testing")]
impl InMemoryDhtClient {
    /// Creates a new empty in-memory DHT client.
    #[must_use]
    pub fn new() -> Self {
        Self {
            items: Mutex::new(HashMap::new()),
        }
    }

    /// Removes all stored items. Test-only utility for verifying republish behavior.
    pub async fn clear(&self) {
        let mut items = self.items.lock().await;
        items.clear();
    }
}

// Trait uses RPITIT with explicit `+ Send` bound; async fn in trait
// does not guarantee Send futures, so manual impl Future is required.
#[cfg(feature = "testing")]
#[allow(clippy::manual_async_fn)]
impl DhtClient for InMemoryDhtClient {
    fn publish(
        &self,
        public_key: &[u8; 32],
        signature: &[u8; 64],
        value: &[u8],
        seq: u64,
    ) -> impl Future<Output = Result<(), DhtError>> + Send {
        async move {
            let mut items = self.items.lock().await;
            let key = *public_key;

            // BEP44 semantics: only update if new sequence number is strictly greater.
            if let Some(existing) = items.get(&key)
                && seq <= existing.seq
            {
                // Idempotent no-op for same or lower sequence number.
                return Ok(());
            }

            items.insert(
                key,
                StoredItem {
                    value: value.to_vec(),
                    signature: *signature,
                    seq,
                },
            );
            drop(items);

            Ok(())
        }
    }

    fn resolve(
        &self,
        public_key: &[u8; 32],
    ) -> impl Future<Output = Result<DhtLookup, DhtError>> + Send {
        async move {
            let items = self.items.lock().await;
            let record = items.get(public_key).map(|item| DhtRecord {
                value: item.value.clone(),
                signature: item.signature,
                seq: item.seq,
            });
            drop(items);
            // The map IS this client's source, and the map reports on every key
            // it is asked about, so both outcomes are answers.
            Ok(record.map_or(DhtLookup::NoRecord, DhtLookup::Record))
        }
    }
}

// ---------------------------------------------------------------------------
// DisabledDhtClient — DHT layer turned off (unconditional, shippable)
// ---------------------------------------------------------------------------

/// A [`DhtClient`] with the DHT layer turned off.
///
/// Both operations fail closed with [`DhtError::Disabled`]: a switched-off arm
/// reaches no DHT node, so it can neither publish a record nor report on one.
/// Used by `DhtMode::Disabled`; the `DualLayerResolver` composes the relay layer
/// around it and records the DHT layer as unavailable, so a `Disabled` node
/// resolves over the relay arm alone and never tells a caller that the Mainline
/// DHT holds no record for a DID it never asked about (§3.10.4).
///
/// Unlike [`InMemoryDhtClient`], this is **not** a nullifier: it never reports a
/// false publish success, and it never reports a resolution result it did not
/// obtain — both harms §17.17.3 identifies. It is therefore compiled
/// unconditionally and safe to ship.
#[derive(Debug, Default, Clone, Copy)]
pub struct DisabledDhtClient;

// Trait uses RPITIT with explicit `+ Send` bound; async fn in trait does not
// guarantee Send futures, so manual impl Future is required.
#[allow(clippy::manual_async_fn)]
impl DhtClient for DisabledDhtClient {
    fn publish(
        &self,
        _public_key: &[u8; 32],
        _signature: &[u8; 64],
        _value: &[u8],
        _seq: u64,
    ) -> impl Future<Output = Result<(), DhtError>> + Send {
        // Fail closed. Silently returning Ok here would be exactly the
        // §17.17.3 "silent false success" nullifier this whole change removes.
        async { Err(DhtError::Disabled) }
    }

    fn resolve(
        &self,
        _public_key: &[u8; 32],
    ) -> impl Future<Output = Result<DhtLookup, DhtError>> + Send {
        // Fail closed. A switched-off arm asked no DHT node about this key, so
        // it holds no evidence either way. Returning `DhtLookup::NoRecord` here
        // would tell the resolver that the Mainline DHT answered and holds
        // nothing, which is the §17.17.3 "reports a result it never obtained"
        // nullifier this crate refuses to ship.
        async { Err(DhtError::Disabled) }
    }
}

// ---------------------------------------------------------------------------
// PkarrDhtClient — production Mainline DHT client (feature: production-dht)
// ---------------------------------------------------------------------------

#[cfg(feature = "production-dht")]
mod pkarr_client;

#[cfg(feature = "production-dht")]
pub use pkarr_client::{PkarrDhtClient, PkarrDhtClientBuilder};

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn publish_and_resolve_roundtrip() {
        let client = InMemoryDhtClient::new();
        let key = [1u8; 32];
        let sig = [2u8; 64];
        let value = b"test document";

        client.publish(&key, &sig, value, 1).await.unwrap();
        let record = client.resolve(&key).await.unwrap().into_record().unwrap();

        assert_eq!(record.value, value);
        assert_eq!(record.signature, sig);
        assert_eq!(record.seq, 1);
    }

    #[tokio::test]
    async fn resolve_returns_none_for_missing_key() {
        let client = InMemoryDhtClient::new();
        let key = [1u8; 32];

        let result = client.resolve(&key).await.unwrap();
        assert!(
            matches!(result, DhtLookup::NoRecord),
            "the map is this client's source and it reported that it holds no record"
        );
    }

    #[tokio::test]
    async fn disabled_client_reports_no_answer_rather_than_an_absence() {
        let client = DisabledDhtClient;
        let key = [7u8; 32];

        let error = client
            .resolve(&key)
            .await
            .expect_err("a switched-off arm asked no DHT node, so it must not answer");
        assert!(
            matches!(error, DhtError::Disabled),
            "a disabled arm reports DhtError::Disabled, got {error:?}"
        );
    }

    #[tokio::test]
    async fn disabled_client_refuses_to_publish() {
        let client = DisabledDhtClient;

        let error = client
            .publish(&[7u8; 32], &[8u8; 64], b"doc", 1)
            .await
            .expect_err("a switched-off arm publishes to no DHT node");
        assert!(matches!(error, DhtError::Disabled));
    }

    #[tokio::test]
    async fn publish_ignores_lower_sequence_number() {
        let client = InMemoryDhtClient::new();
        let key = [1u8; 32];
        let sig1 = [2u8; 64];
        let sig2 = [3u8; 64];

        client.publish(&key, &sig1, b"version 1", 5).await.unwrap();
        client.publish(&key, &sig2, b"version 2", 3).await.unwrap();

        let record = client.resolve(&key).await.unwrap().into_record().unwrap();
        assert_eq!(record.value, b"version 1");
        assert_eq!(record.seq, 5);
    }

    #[tokio::test]
    async fn publish_ignores_same_sequence_number() {
        let client = InMemoryDhtClient::new();
        let key = [1u8; 32];
        let sig1 = [2u8; 64];
        let sig2 = [3u8; 64];

        client.publish(&key, &sig1, b"version 1", 5).await.unwrap();
        client.publish(&key, &sig2, b"version 2", 5).await.unwrap();

        let record = client.resolve(&key).await.unwrap().into_record().unwrap();
        assert_eq!(record.value, b"version 1");
        assert_eq!(record.seq, 5);
    }

    #[tokio::test]
    async fn publish_updates_with_higher_sequence_number() {
        let client = InMemoryDhtClient::new();
        let key = [1u8; 32];
        let sig1 = [2u8; 64];
        let sig2 = [3u8; 64];

        client.publish(&key, &sig1, b"version 1", 1).await.unwrap();
        client.publish(&key, &sig2, b"version 2", 2).await.unwrap();

        let record = client.resolve(&key).await.unwrap().into_record().unwrap();
        assert_eq!(record.value, b"version 2");
        assert_eq!(record.seq, 2);
    }
}
