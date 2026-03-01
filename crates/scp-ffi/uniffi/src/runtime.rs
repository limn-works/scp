//! Global runtime registry mapping context IDs to live `scp-core` objects.
//!
//! Mirrors the `PyO3` bridge's `runtime.rs` pattern: a `DashMap` maps context IDs
//! to per-context runtime state (event log, revocation list, nonce tracker,
//! capability ceiling, creator DID). Bridge functions call [`with_context`] to
//! access this state.
//!
//! # Lifecycle
//!
//! 1. [`context_create`](super::bridge::context_create) calls [`register_context`].
//! 2. Bridge functions call [`with_context`] to read/write runtime objects.
//! 3. [`context_close`](super::bridge::context_close) calls [`remove_context`].

use std::collections::HashSet;
use std::sync::OnceLock;

use dashmap::DashMap;
use scp_core::context::roles::{Capability, CapabilityCeiling};
use scp_core::crypto::ucan::nonce::NonceTracker;
use scp_core::crypto::ucan::revoke::RevocationList;
use scp_core::event_log::EventLog;
use scp_core::identity::cache::SystemClock;

use crate::bridge::ScpError;

static CONTEXT_REGISTRY: OnceLock<DashMap<String, ContextRuntime>> = OnceLock::new();

fn registry() -> &'static DashMap<String, ContextRuntime> {
    CONTEXT_REGISTRY.get_or_init(DashMap::new)
}

/// Per-context runtime state: the live objects needed by bridge functions.
pub struct ContextRuntime {
    /// Event log (Merkle tree) for this context.
    pub event_log: EventLog,
    /// UCAN revocation list for this context.
    pub revocation_list: RevocationList,
    /// UCAN nonce tracker for replay prevention (ADR-016 step 9).
    pub nonce_tracker: NonceTracker<SystemClock>,
    /// Capability ceiling as `{resource}:{action}` strings (ADR-016 step 8).
    pub ceiling_strings: HashSet<String>,
    /// The DID of the context creator.
    pub creator_did: String,
}

/// Default capability ceiling for new contexts (matches `PyO3` bridge).
fn default_ceiling() -> CapabilityCeiling {
    CapabilityCeiling::new([
        Capability::MessagesRead,
        Capability::MessagesWrite,
        Capability::ToolRegister,
        Capability::ToolInvokeAll,
        Capability::RoleAssign,
        Capability::MemberInvite,
        Capability::MemberRemove,
        Capability::GovernancePropose,
        Capability::GovernanceVote,
        Capability::ContextClose,
    ])
}

/// Registers a new context in the global runtime registry.
///
/// Creates an [`EventLog`], [`RevocationList`], [`NonceTracker`], and
/// capability ceiling for the context. Called by `context_create`.
///
/// # Errors
///
/// Returns `ScpError::Context` if the context ID is already registered.
pub fn register_context(context_id: &str, creator_did: &str) -> Result<(), ScpError> {
    use dashmap::mapref::entry::Entry;

    let map = registry();

    match map.entry(context_id.to_owned()) {
        Entry::Occupied(_) => Err(ScpError::Context {
            message: format!("context '{context_id}' is already registered"),
            code: "SCP-CTX-2030".to_owned(),
        }),
        Entry::Vacant(vacant) => {
            let event_log = EventLog::new(context_id.to_owned());
            let ceiling = default_ceiling();
            let ceiling_strings = ceiling
                .capabilities
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<HashSet<String>>();
            let revocation_list = RevocationList::new(context_id.to_owned());
            let nonce_tracker = NonceTracker::new(context_id.to_owned(), SystemClock);

            vacant.insert(ContextRuntime {
                event_log,
                revocation_list,
                nonce_tracker,
                ceiling_strings,
                creator_did: creator_did.to_owned(),
            });

            Ok(())
        }
    }
}

/// Executes a closure with mutable access to a context's runtime state.
///
/// # Errors
///
/// Returns `ScpError::Context` if the context is not found.
pub fn with_context<T, F>(context_id: &str, f: F) -> Result<T, ScpError>
where
    F: FnOnce(&mut ContextRuntime) -> Result<T, ScpError>,
{
    let map = registry();

    let mut entry = map.get_mut(context_id).ok_or_else(|| ScpError::Context {
        message: format!(
            "context '{context_id}' not found in runtime registry \
             -- was it created with context_create?"
        ),
        code: "SCP-CTX-2031".to_owned(),
    })?;

    f(entry.value_mut())
}

/// Removes a context from the global runtime registry.
///
/// Called when a context is closed. All associated runtime objects are dropped.
pub fn remove_context(context_id: &str) {
    registry().remove(context_id);
}
