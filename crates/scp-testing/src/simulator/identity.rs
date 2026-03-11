//! Simulated identity for test scenarios.
//!
//! Wraps identity primitives (DID, key custody, storage, protocol store) into
//! a single container for convenient test setup. Does NOT create real MLS
//! groups or sender key stores -- those are complex and should be used directly
//! in integration tests.

#![forbid(unsafe_code)]

use std::sync::Arc;

use scp_core::store::ProtocolStore;
use scp_identity::DID;
use scp_platform::testing::{InMemoryKeyCustody, InMemoryStorage};

/// A test identity with custody, storage, and protocol store pre-wired.
///
/// Provides convenient access to all identity-related components needed for
/// protocol-level testing. The protocol store wraps its own `InMemoryStorage`
/// instance; the `storage` field is a separate instance for direct storage
/// access in tests.
pub struct SimulatedIdentity {
    /// The DID for this identity.
    did: DID,
    /// Key custody provider.
    custody: Arc<InMemoryKeyCustody>,
    /// Direct storage access for tests.
    storage: InMemoryStorage,
    /// Protocol store wrapping its own storage instance.
    protocol_store: ProtocolStore<InMemoryStorage>,
    /// Human-readable label for this identity.
    label: String,
}

impl SimulatedIdentity {
    /// Creates a new simulated identity.
    ///
    /// The `ProtocolStore` is created from a fresh `InMemoryStorage` instance.
    /// The `storage` parameter is retained separately for direct test access.
    #[must_use]
    pub fn new(
        label: impl Into<String>,
        did: DID,
        custody: Arc<InMemoryKeyCustody>,
        storage: InMemoryStorage,
    ) -> Self {
        let protocol_store = ProtocolStore::new(InMemoryStorage::new());
        Self {
            did,
            custody,
            storage,
            protocol_store,
            label: label.into(),
        }
    }

    /// Returns a reference to this identity's DID.
    #[must_use]
    pub const fn did(&self) -> &DID {
        &self.did
    }

    /// Returns the human-readable label for this identity.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Returns a reference to the key custody provider.
    #[must_use]
    pub const fn custody(&self) -> &Arc<InMemoryKeyCustody> {
        &self.custody
    }

    /// Returns a reference to the direct storage instance.
    #[must_use]
    pub const fn storage(&self) -> &InMemoryStorage {
        &self.storage
    }

    /// Returns a reference to the protocol store.
    #[must_use]
    pub const fn protocol_store(&self) -> &ProtocolStore<InMemoryStorage> {
        &self.protocol_store
    }
}
