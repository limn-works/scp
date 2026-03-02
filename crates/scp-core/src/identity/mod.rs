//! DID identity re-exports from [`scp_identity`].
//!
//! The identity subsystem has been extracted into the independent
//! [`scp-identity`](scp_identity) workspace crate. This module re-exports
//! all public types so that downstream consumers of `scp-core` see no
//! breaking change.
//!
//! See ADR-003 in `.docs/adrs/phase-1.md` for the full design.

// Re-export submodules so `use scp_core::identity::cache::*` etc. still work.
pub use scp_identity::cache;
pub use scp_identity::dht;
pub use scp_identity::dht_client;
pub use scp_identity::document;
pub use scp_identity::republish;

// Re-export top-level types so `use scp_core::identity::DID` etc. still work.
pub use scp_identity::{
    DID, DhtClient, DidCache, DidDht, DidDocument, DidMethod, DidResolutionResult,
    DidRotationEvent, IdentityError, InMemoryDhtClient, MigrationProof, PreRotationProof,
    RepublishManager, ScpIdentity, Staleness, verify_migration,
};
