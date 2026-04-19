//! Full-stack E2E testing module for the `PyO3` bridge.
//!
//! Exposes `FullStackNetwork` and `FullStackNode` from `scp-testing` as Python
//! classes so Python tests can prove real encrypt-decrypt roundtrips through
//! the entire protocol stack (MLS + sender keys + `ContextManager`).
//!
//! Operations that produce or mutate the shared `FullStackNetwork` are exposed
//! as methods on `SCP`:
//!
//! - [`PyScp::fullstack_create_node`] -- Create a test node backed by the
//!   bridge's shared `FullStackNetwork`.
//! - [`PyScp::fullstack_reset_network`] -- Reset the shared network.
//! - [`PyScp::fullstack_create_context`] -- Create an encrypted context owned
//!   by a node.
//! - [`PyScp::fullstack_add_member`], [`PyScp::fullstack_join_from_welcome`],
//!   [`PyScp::fullstack_sync_sender_keys`], [`PyScp::fullstack_send_message`],
//!   [`PyScp::fullstack_decrypt_message`], [`PyScp::fullstack_remove_member`]
//!   -- Full-stack membership, messaging, and lifecycle operations.
//!
//! Migrated from flat `#[pyfunction]` exports to `#[pymethods] impl PyScp`
//! methods in Phase 4 PR 4 sub-slice E (#1549).
//!
//! Feature-gated behind `allow_in_memory_custody` -- never compiled into
//! production builds.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use scp_core::context::builder::ContextCryptoProvider;
use scp_core::context::governance::KeyResolver;
use scp_core::context::{Capability, ContextHandle, ContextMode, ContextParams, context_id_bytes};
use scp_testing::fullstack::{FullStackNetwork, FullStackNode};

use crate::runtime::PyBridgeInstance;

// ---------------------------------------------------------------------------
// Shared network
// ---------------------------------------------------------------------------
//
// The shared `FullStackNetwork` lives as a typed field on `PyBridgeInstance`
// (see `crate::runtime::PyBridgeInstance::network`). Using the per-bridge
// slot (instead of a process-global singleton) preserves the previous
// behaviour — all `py_fullstack_create_node` calls on the same instance
// share a `KeyExchange` — while still allowing a caller-owned `PyScp` to
// keep its test network isolated from other instances in the same process.
//
// `Mutex<Option<...>>` (rather than `OnceLock`) is used so tests can reset
// the network between runs, preventing cross-test state leakage via the
// `py_fullstack_reset_network` entry point.
// ---------------------------------------------------------------------------

/// Returns the result of calling `f` with the given bridge instance's
/// shared `FullStackNetwork`.
///
/// All nodes created via `fullstack_create_node` on the same instance share
/// the same `KeyExchange` so Welcome messages and sender keys can be
/// exchanged.
fn with_network<F, R>(bi: &PyBridgeInstance, f: F) -> PyResult<R>
where
    F: FnOnce(&FullStackNetwork) -> R,
{
    let mut guard = bi
        .network()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let network = guard.get_or_insert_with(FullStackNetwork::new);
    Ok(f(network))
}

/// Returns a permissive key resolver that always returns `None`.
fn permissive_key_resolver() -> KeyResolver {
    Arc::new(|_did| None)
}

// ---------------------------------------------------------------------------
// PyFullStackNode -- opaque Python class wrapping FullStackNode
// ---------------------------------------------------------------------------

/// Opaque handle to a full-stack test node with real MLS crypto.
///
/// Each node has its own [`ContextManager`] backed by [`E2eCryptoProvider`]
/// (real MLS + sender keys) with a shared [`KeyExchange`] for coordinating
/// Welcome messages and sender keys between nodes.
#[pyclass(name = "FullStackNode")]
pub struct PyFullStackNode {
    /// The underlying Rust `FullStackNode`.
    inner: FullStackNode,
    /// Stored context handles, keyed by context ID string.
    handles: Mutex<HashMap<String, ContextHandle>>,
}

#[pymethods]
impl PyFullStackNode {
    /// Returns this node's DID string.
    #[getter]
    fn did(&self) -> String {
        self.inner.did.to_string()
    }
}

// ---------------------------------------------------------------------------
// Exported Python functions
// ---------------------------------------------------------------------------

fn fullstack_create_node_impl(bi: &PyBridgeInstance, did: String) -> PyResult<PyFullStackNode> {
    with_network(bi, |network| {
        let node = network.create_node(&did, permissive_key_resolver());
        PyFullStackNode {
            inner: node,
            handles: Mutex::new(HashMap::new()),
        }
    })
}

fn fullstack_reset_network_impl(bi: &PyBridgeInstance) -> PyResult<()> {
    let mut guard = bi
        .network()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *guard = None;
    Ok(())
}

fn fullstack_create_context_impl(
    node: &PyFullStackNode,
    context_id: String,
    ceiling_json: String,
) -> PyResult<String> {
    let ceiling_obj: serde_json::Value = serde_json::from_str(&ceiling_json).map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!("invalid ceiling JSON: {e}"))
    })?;

    let ceiling = ceiling_obj
        .get("ceiling")
        .and_then(|v| v.as_array())
        .map_or_else(
            || {
                vec![
                    Capability::MessagesRead,
                    Capability::MessagesWrite,
                    Capability::RoleAssign,
                    Capability::MemberInvite,
                    Capability::MemberRemove,
                    Capability::ContextClose,
                ]
            },
            |arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(Capability::new)
                    .collect::<Vec<_>>()
            },
        );

    let params = ContextParams {
        mode: ContextMode::Encrypted,
        ceiling,
        ..ContextParams::default()
    };

    let rt = crate::runtime()?;
    let handle = rt
        .block_on(node.inner.create_context(&context_id, params))
        .map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("failed to create context: {e}"))
        })?;

    {
        let mut handles = node
            .handles
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        handles.insert(context_id.clone(), handle);
    }

    Ok(context_id)
}

fn fullstack_add_member_impl(
    node: &PyFullStackNode,
    context_id: String,
    member_did: String,
) -> PyResult<()> {
    let rt = crate::runtime()?;

    let handle = {
        let handles = node
            .handles
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        handles.get(&context_id).cloned().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err(format!(
                "context '{context_id}' not found in node's handles"
            ))
        })?
    };

    rt.block_on(node.inner.add_member(&handle, &member_did))
        .map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("failed to add member: {e}"))
        })
}

/// Joins a context by retrieving the Welcome from the shared `KeyExchange`.
///
/// After joining, the context is registered on the joiner's `ContextManager`
/// with a `ContextHandle`, enabling subsequent `py_fullstack_send_message`
/// and `py_fullstack_remove_member` calls on this node.
fn fullstack_join_from_welcome_impl(node: &PyFullStackNode, context_id: String) -> PyResult<()> {
    let ctx_bytes = context_id_bytes(&context_id);
    let rt = crate::runtime()?;

    // Step 1: Register the context on the joiner's ContextManager.
    let params = ContextParams {
        mode: ContextMode::Encrypted,
        ceiling: vec![
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::RoleAssign,
            Capability::MemberInvite,
            Capability::MemberRemove,
            Capability::ContextClose,
        ],
        ..ContextParams::default()
    };
    let handle = rt
        .block_on(node.inner.create_context(&context_id, params))
        .map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!(
                "failed to register context on joiner: {e}"
            ))
        })?;

    // Step 2: Replace the throwaway MLS group with the Welcome-derived one
    // and pick up the adder's sender keys and access key from the exchange.
    node.inner
        .join_from_welcome(&context_id, &ctx_bytes)
        .map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("failed to join from Welcome: {e}"))
        })?;

    // Step 2b: Regenerate the joiner's sender key and distribute it to
    // existing members. The key from create_context was for the throwaway
    // MLS group and is now stale.
    node.inner
        .regenerate_and_distribute_sender_key(&ctx_bytes)
        .map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!(
                "failed to distribute joiner sender key: {e}"
            ))
        })?;

    // Step 2c: Sync all members' access keys into the ContextManager's
    // PerContextState so that send_message wraps content for all recipients.
    // join_from_welcome already populates E2eCryptoProvider's local store;
    // this step ensures the ContextManager also has them.
    rt.block_on(
        node.inner
            .sync_access_keys_to_manager(&context_id, &ctx_bytes),
    );

    // Step 3: Store the handle.
    {
        let mut handles = node
            .handles
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        handles.insert(context_id, handle);
    }

    Ok(())
}

/// Synchronises sender keys between two nodes for a given context.
///
/// Each node distributes its own sender key to the other via the shared
/// `KeyExchange`, then picks up the other's key. After this call, both
/// nodes can encrypt and decrypt messages from each other.
fn fullstack_sync_sender_keys_impl(
    node_a: &PyFullStackNode,
    node_b: &PyFullStackNode,
    context_id: String,
) -> PyResult<()> {
    let ctx_bytes = context_id_bytes(&context_id);
    let did_a = node_a.inner.did.to_string();
    let did_b = node_b.inner.did.to_string();

    // A distributes to B, B distributes to A.
    node_a
        .inner
        .crypto
        .distribute_sender_key(&ctx_bytes, &did_b)
        .map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!(
                "failed to distribute sender key from A to B: {e}"
            ))
        })?;
    node_b
        .inner
        .crypto
        .distribute_sender_key(&ctx_bytes, &did_a)
        .map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!(
                "failed to distribute sender key from B to A: {e}"
            ))
        })?;

    // Both pick up the other's key.
    node_a.inner.pickup_sender_keys(&ctx_bytes).map_err(|e| {
        pyo3::exceptions::PyRuntimeError::new_err(format!(
            "failed to pick up sender keys for A: {e}"
        ))
    })?;
    node_b.inner.pickup_sender_keys(&ctx_bytes).map_err(|e| {
        pyo3::exceptions::PyRuntimeError::new_err(format!(
            "failed to pick up sender keys for B: {e}"
        ))
    })?;

    Ok(())
}

fn fullstack_send_message_impl<'py>(
    py: Python<'py>,
    node: &PyFullStackNode,
    context_id: String,
    payload: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let rt = crate::runtime()?;

    let handle = {
        let handles = node
            .handles
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        handles.get(&context_id).cloned().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err(format!(
                "context '{context_id}' not found in node's handles"
            ))
        })?
    };

    rt.block_on(node.inner.send_message(&handle, payload))
        .map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("failed to send message: {e}"))
        })?;

    let sent = node.inner.take_sent_ciphertexts();
    if sent.is_empty() {
        return Err(pyo3::exceptions::PyRuntimeError::new_err(
            "no ciphertext captured after send",
        ));
    }
    if sent.len() > 1 {
        return Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
            "expected 1 ciphertext after send, got {} — send_message should produce exactly one",
            sent.len()
        )));
    }

    Ok(PyBytes::new(py, &sent[0].1))
}

fn fullstack_decrypt_message_impl<'py>(
    py: Python<'py>,
    node: &PyFullStackNode,
    context_id: String,
    ciphertext: &[u8],
    sender_did: String,
) -> PyResult<Bound<'py, PyBytes>> {
    let ctx_bytes = context_id_bytes(&context_id);
    let plaintext = node
        .inner
        .decrypt_message(&context_id, &ctx_bytes, ciphertext, &sender_did)
        .map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("failed to decrypt message: {e}"))
        })?;

    Ok(PyBytes::new(py, &plaintext))
}

fn fullstack_remove_member_impl(
    node: &PyFullStackNode,
    context_id: String,
    member_did: String,
) -> PyResult<()> {
    let rt = crate::runtime()?;

    let handle = {
        let handles = node
            .handles
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        handles.get(&context_id).cloned().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err(format!(
                "context '{context_id}' not found in node's handles"
            ))
        })?
    };

    rt.block_on(node.inner.manager.leave_context(
        &handle,
        &node.inner.did,
        &scp_identity::DID::from(member_did.as_str()),
    ))
    .map_err(|e| {
        pyo3::exceptions::PyRuntimeError::new_err(format!("failed to remove member: {e}"))
    })?;

    // Drain the captured MLS Commit + sender-key messages that leave_context
    // sends via the transport. These are control-plane messages, not
    // application messages, and must not bleed into the buffer that
    // py_fullstack_send_message checks for exactly-one application ciphertext.
    node.inner.take_sent_ciphertexts();

    Ok(())
}

// ---------------------------------------------------------------------------
// PyScp methods — migrated from #[pyfunction] exports (Phase 4 PR 4, #1549).
// ---------------------------------------------------------------------------

#[pymethods]
impl crate::scp::PyScp {
    /// Creates a full-stack test node with real MLS crypto.
    #[pyo3(name = "fullstack_create_node")]
    pub fn fullstack_create_node(&self, did: String) -> PyResult<PyFullStackNode> {
        let bi = &*self.inner;
        fullstack_create_node_impl(bi, did)
    }

    /// Resets this bridge instance's `FullStackNetwork`, dropping all nodes
    /// and state.
    ///
    /// Call between test suites to prevent cross-test state leakage.
    #[pyo3(name = "fullstack_reset_network")]
    pub fn fullstack_reset_network(&self) -> PyResult<()> {
        let bi = &*self.inner;
        fullstack_reset_network_impl(bi)
    }

    /// Creates an encrypted context owned by the given node.
    ///
    /// Returns the context ID string on success.
    #[pyo3(name = "fullstack_create_context")]
    pub fn fullstack_create_context(
        &self,
        node: &PyFullStackNode,
        context_id: String,
        ceiling_json: String,
    ) -> PyResult<String> {
        fullstack_create_context_impl(node, context_id, ceiling_json)
    }

    /// Adds a member to the context (admin-side operation).
    #[pyo3(name = "fullstack_add_member")]
    pub fn fullstack_add_member(
        &self,
        node: &PyFullStackNode,
        context_id: String,
        member_did: String,
    ) -> PyResult<()> {
        fullstack_add_member_impl(node, context_id, member_did)
    }

    /// Joins a context by retrieving the Welcome from the shared `KeyExchange`.
    #[pyo3(name = "fullstack_join_from_welcome")]
    pub fn fullstack_join_from_welcome(
        &self,
        node: &PyFullStackNode,
        context_id: String,
    ) -> PyResult<()> {
        fullstack_join_from_welcome_impl(node, context_id)
    }

    /// Synchronises sender keys between two nodes for a given context.
    #[pyo3(name = "fullstack_sync_sender_keys")]
    pub fn fullstack_sync_sender_keys(
        &self,
        node_a: &PyFullStackNode,
        node_b: &PyFullStackNode,
        context_id: String,
    ) -> PyResult<()> {
        fullstack_sync_sender_keys_impl(node_a, node_b, context_id)
    }

    /// Encrypts a message and returns the ciphertext as bytes.
    #[pyo3(name = "fullstack_send_message")]
    pub fn fullstack_send_message<'py>(
        &self,
        py: Python<'py>,
        node: &PyFullStackNode,
        context_id: String,
        payload: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        fullstack_send_message_impl(py, node, context_id, payload)
    }

    /// Decrypts a message using the node's real MLS + sender key crypto.
    #[pyo3(name = "fullstack_decrypt_message")]
    pub fn fullstack_decrypt_message<'py>(
        &self,
        py: Python<'py>,
        node: &PyFullStackNode,
        context_id: String,
        ciphertext: &[u8],
        sender_did: String,
    ) -> PyResult<Bound<'py, PyBytes>> {
        fullstack_decrypt_message_impl(py, node, context_id, ciphertext, sender_did)
    }

    /// Removes a member from the context.
    #[pyo3(name = "fullstack_remove_member")]
    pub fn fullstack_remove_member(
        &self,
        node: &PyFullStackNode,
        context_id: String,
        member_did: String,
    ) -> PyResult<()> {
        fullstack_remove_member_impl(node, context_id, member_did)
    }
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

/// Registers the full-stack testing classes on the Python module.
///
/// Post-migration (Phase 4 PR 4 sub-slice E), full-stack testing operations
/// are exposed as methods on `SCP`. Only the opaque [`PyFullStackNode`]
/// class still requires manual registration here.
pub fn register_testing(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyFullStackNode>()?;
    Ok(())
}
