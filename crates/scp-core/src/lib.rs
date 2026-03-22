//! SCP protocol + runtime — unified API surface.
//!
//! Merges [`scp_protocol`] (pure sync types) and [`scp_runtime`] (async
//! orchestration) into a single namespace. Downstream crates depend on
//! `scp-core` alone.
//!
//! MAINTENANCE: When adding a public module to scp-protocol or scp-runtime,
//! add the corresponding re-export here. The CI check and structural test
//! in tests/facade_completeness.rs will catch omissions.

// --- Modules that exist ONLY in scp-protocol (no conflict) ---
pub use scp_protocol::jcs;
pub use scp_protocol::serde_util;
pub use scp_protocol::time;
pub use scp_protocol::uri;

// --- Modules that exist ONLY in scp-runtime (no conflict) ---
pub use scp_runtime::store;
pub use scp_runtime::event_log;
pub use scp_runtime::metrics;
pub use scp_runtime::well_known;

// --- Modules split across both crates (explicit sub-module merging) ---

pub mod crypto {
    pub use scp_protocol::crypto::canonical;
    pub use scp_protocol::crypto::ed25519;
    pub use scp_protocol::crypto::tofu;
    pub use scp_protocol::crypto::key_continuity;
    pub use scp_protocol::crypto::envelope_seal;
    pub use scp_runtime::crypto::mls;
    pub mod sender_keys {
        pub use scp_protocol::crypto::sender_keys::*;
        pub use scp_runtime::crypto::sender_keys::key_protocol;
    }
    pub mod access_keys {
        pub use scp_protocol::crypto::access_keys::*;
        pub use scp_runtime::crypto::access_keys::lifecycle;
        pub use scp_runtime::crypto::access_keys::wire;
    }
    pub mod ucan {
        pub use scp_protocol::crypto::ucan::*;
        pub use scp_runtime::crypto::ucan::mint;
    }
}

pub mod context {
    pub use scp_protocol::context::*;
    pub use scp_runtime::context::manager;
    pub use scp_runtime::context::builder;
    pub use scp_runtime::context::providers;
    pub use scp_runtime::context::ttl;
    pub use scp_runtime::context::export_import;
    pub use scp_runtime::context::standing;
    pub use scp_runtime::context::app_sandbox;
    pub use scp_runtime::context::policy;
    pub mod governance {
        pub use scp_protocol::context::governance::*;
        pub use scp_runtime::context::governance::timeout;
    }
    pub mod tools {
        pub use scp_protocol::context::tools::*;
        pub use scp_runtime::context::tools::invoke;
        pub use scp_runtime::context::tools::session;
    }
}

pub mod trust {
    pub use scp_protocol::trust::*;
    pub use scp_runtime::trust::ProtocolRepositoryTrustBridge;
}

pub mod identity {
    pub use scp_protocol::identity::*;
    pub use scp_runtime::identity::blocking;
    pub use scp_runtime::identity::recovery;
    pub use scp_runtime::identity::custody_migration;
    pub use scp_runtime::identity::scpid;
}

pub mod economy {
    pub use scp_protocol::economy::*;
    pub use scp_runtime::economy::credentials;
    pub use scp_runtime::economy::integration;
    pub use scp_runtime::economy::adapter;
    pub use scp_runtime::economy::receipt;
}

pub mod discovery {
    pub use scp_protocol::discovery::*;
    pub use scp_runtime::discovery::addressing;
    pub use scp_runtime::discovery::search;
    pub use scp_runtime::discovery::did_capabilities;
    pub use scp_runtime::discovery::bootstrap;
    pub use scp_runtime::discovery::dht_context;
}

pub mod envelope {
    pub use scp_protocol::envelope::*;
    pub use scp_runtime::envelope::pseudonym;
    pub mod inner {
        pub use scp_protocol::envelope::inner::*;
        pub use scp_runtime::envelope::inner::sign;
    }
    pub mod outer {
        pub use scp_protocol::envelope::outer::*;
        pub use scp_runtime::envelope::outer::ops;
    }
}

pub mod sync {
    pub use scp_protocol::sync::*;
    pub use scp_runtime::sync::days_offline;
    pub use scp_runtime::sync::hours_offline;
    pub use scp_runtime::sync::weeks_offline;
}

pub mod bridge {
    pub use scp_protocol::bridge::*;
    pub use scp_runtime::bridge::oauth;
    pub use scp_runtime::bridge::credentials;
}

pub mod provenance {
    pub use scp_protocol::provenance::*;
}
