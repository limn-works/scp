//! Global runtime registry mapping context IDs to live `scp-core` objects.
//!
//! The NAPI bridge functions accept `&NapiContextHandle` references but need
//! access to real `scp-core` runtime objects (event logs, UCAN revocation
//! lists, nonce trackers). This module provides a global registry that maps
//! context IDs to their associated runtime state.
//!
//! # Lazy registration
//!
//! Unlike the `PyO3` bridge (where `py_context_create` eagerly registers state),
//! the NAPI bridge uses lazy registration: the first UCAN or event log call
//! on a context triggers registration from `NapiContextHandle` metadata. This
//! avoids modifying `context.rs` (which is out of scope for SCP-219).
//!
//! See SCP-219 and ADR-022 in `.docs/adrs/phase-4.md`.

use std::collections::HashSet;
use std::sync::OnceLock;

use dashmap::DashMap;
use scp_core::context::roles::default_ceiling;
use scp_core::crypto::ucan::nonce::NonceTracker;
use scp_core::crypto::ucan::revoke::RevocationList;
use scp_core::event_log::EventLog;
use scp_core::identity::cache::SystemClock;

use crate::context::NapiContextHandle;
use crate::error::ScpNapiError;

/// Global registry of per-context runtime state.
static CONTEXT_REGISTRY: OnceLock<DashMap<String, ContextRuntime>> = OnceLock::new();

/// Returns a reference to the global context registry.
fn registry() -> &'static DashMap<String, ContextRuntime> {
    CONTEXT_REGISTRY.get_or_init(DashMap::new)
}

/// Per-context runtime state: the live objects needed by bridge functions.
///
/// Each context gets its own event log, UCAN revocation list, nonce tracker,
/// and capability ceiling string set. These are created lazily on first access
/// from UCAN or event log bridge functions.
pub struct ContextRuntime {
    /// Event log (Merkle tree) for this context.
    pub event_log: EventLog,
    /// UCAN revocation list for this context.
    pub revocation_list: RevocationList,
    /// UCAN nonce tracker for replay prevention (ADR-016 step 9).
    pub nonce_tracker: NonceTracker<SystemClock>,
    /// Capability ceiling as a set of `{resource}:{action}` strings for
    /// UCAN validation (ADR-016 step 8).
    pub ceiling_strings: HashSet<String>,
    /// The DID of the context creator.
    pub creator_did: String,
}

// default_ceiling() imported from scp_core::context::roles.

/// Ensures a context is registered in the runtime registry.
///
/// If the context is already registered, this is a no-op. Otherwise, creates
/// runtime state from the `NapiContextHandle` metadata (context ID, creator
/// DID, ceiling).
///
/// # Errors
///
/// Returns `ScpNapiError::Context` if the context state cannot be determined.
pub fn ensure_registered(handle: &NapiContextHandle) -> Result<(), ScpNapiError> {
    let context_id = handle.context_id();
    let map = registry();

    if map.contains_key(&context_id) {
        return Ok(());
    }

    let creator_did = handle.creator_did();
    let handle_ceiling = handle.ceiling();

    let ceiling_strings = if handle_ceiling.is_empty() {
        default_ceiling()
            .capabilities
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<HashSet<String>>()
    } else {
        handle_ceiling.into_iter().collect::<HashSet<String>>()
    };

    let event_log = EventLog::new(context_id.clone());
    let revocation_list = RevocationList::new(context_id.clone());
    let nonce_tracker = NonceTracker::new(context_id.clone(), SystemClock);

    let runtime = ContextRuntime {
        event_log,
        revocation_list,
        nonce_tracker,
        ceiling_strings,
        creator_did,
    };

    map.entry(context_id).or_insert(runtime);
    Ok(())
}

/// Executes a closure with mutable access to a context's runtime state.
///
/// Looks up the context by ID in the global registry and calls `f` with a
/// mutable reference to the [`ContextRuntime`]. Uses `DashMap::get_mut` for
/// fine-grained per-key locking.
///
/// # Errors
///
/// Returns `ScpNapiError::Context` if the context is not found.
pub fn with_context<T, F>(context_id: &str, f: F) -> Result<T, ScpNapiError>
where
    F: FnOnce(&mut ContextRuntime) -> Result<T, ScpNapiError>,
{
    let map = registry();

    let mut entry = map
        .get_mut(context_id)
        .ok_or_else(|| ScpNapiError::Context {
            message: format!(
                "context '{context_id}' not found in runtime registry \
             -- call a UCAN or event log function with the context handle first"
            ),
            code: "SCP-CTX-2023".to_owned(),
        })?;

    f(entry.value_mut())
}

/// Removes a context from the global runtime registry.
///
/// Called when a context is closed. All associated runtime objects are dropped.
/// Does not error if the context was not found (idempotent).
#[allow(dead_code)]
pub fn remove_context(context_id: &str) {
    registry().remove(context_id);
}
