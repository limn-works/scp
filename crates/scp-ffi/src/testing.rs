//! Full-stack E2E testing module for the `PyO3` bridge.
//!
//! Exposes `FullStackNetwork` and `FullStackNode` from `scp-testing` as Python
//! classes so Python tests can prove real encrypt-decrypt roundtrips through
//! the entire protocol stack (MLS + sender keys + `ContextManager`).
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

// ---------------------------------------------------------------------------
// Shared network
// ---------------------------------------------------------------------------

/// Guards the shared `FullStackNetwork` instance.
///
/// Uses `Mutex<Option<...>>` instead of `OnceLock` so tests can reset
/// the network between runs (preventing cross-test state leakage).
static NETWORK: std::sync::Mutex<Option<FullStackNetwork>> = std::sync::Mutex::new(None);

/// Returns the result of calling `f` with the shared `FullStackNetwork`.
///
/// All nodes created via `py_fullstack_create_node` share the same
/// `KeyExchange` so Welcome messages and sender keys can be exchanged.
fn with_network<F, R>(f: F) -> R
where
    F: FnOnce(&FullStackNetwork) -> R,
{
    let mut guard = NETWORK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let network = guard.get_or_insert_with(FullStackNetwork::new);
    f(network)
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

/// Creates a full-stack test node with real MLS crypto.
#[must_use]
#[pyfunction]
pub fn py_fullstack_create_node(did: String) -> PyFullStackNode {
    with_network(|network| {
        let node = network.create_node(&did, permissive_key_resolver());
        PyFullStackNode {
            inner: node,
            handles: Mutex::new(HashMap::new()),
        }
    })
}

/// Resets the shared `FullStackNetwork`, dropping all nodes and state.
///
/// Call between test suites to prevent cross-test state leakage.
#[pyfunction]
pub fn py_fullstack_reset_network() {
    let mut guard = NETWORK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *guard = None;
}

/// Creates an encrypted context owned by the given node.
///
/// Returns the context ID string on success.
#[pyfunction]
pub fn py_fullstack_create_context(
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

/// Adds a member to the context (admin-side operation).
#[pyfunction]
pub fn py_fullstack_add_member(
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
#[pyfunction]
pub fn py_fullstack_join_from_welcome(node: &PyFullStackNode, context_id: String) -> PyResult<()> {
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
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current()
            .block_on(node.inner.regenerate_and_distribute_sender_key(&ctx_bytes))
    })
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
#[pyfunction]
pub fn py_fullstack_sync_sender_keys(
    node_a: &PyFullStackNode,
    node_b: &PyFullStackNode,
    context_id: String,
) -> PyResult<()> {
    let ctx_bytes = context_id_bytes(&context_id);
    let did_a = node_a.inner.did.to_string();
    let did_b = node_b.inner.did.to_string();

    // A distributes to B, B distributes to A.
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(
            node_a
                .inner
                .crypto
                .distribute_sender_key(&ctx_bytes, &did_b),
        )
    })
    .map_err(|e| {
        pyo3::exceptions::PyRuntimeError::new_err(format!(
            "failed to distribute sender key from A to B: {e}"
        ))
    })?;
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(
            node_b
                .inner
                .crypto
                .distribute_sender_key(&ctx_bytes, &did_a),
        )
    })
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

/// Encrypts a message and returns the ciphertext as bytes.
#[pyfunction]
pub fn py_fullstack_send_message<'py>(
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

/// Decrypts a message using the node's real MLS + sender key crypto.
#[pyfunction]
pub fn py_fullstack_decrypt_message<'py>(
    py: Python<'py>,
    node: &PyFullStackNode,
    context_id: String,
    ciphertext: &[u8],
    sender_did: String,
) -> PyResult<Bound<'py, PyBytes>> {
    let ctx_bytes = context_id_bytes(&context_id);
    let plaintext = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(node.inner.decrypt_message(
            &context_id,
            &ctx_bytes,
            ciphertext,
            &sender_did,
        ))
    })
    .map_err(|e| {
        pyo3::exceptions::PyRuntimeError::new_err(format!("failed to decrypt message: {e}"))
    })?;

    Ok(PyBytes::new(py, &plaintext))
}

/// Removes a member from the context.
#[pyfunction]
pub fn py_fullstack_remove_member(
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
// Module registration
// ---------------------------------------------------------------------------

/// Registers the full-stack testing functions in the Python module.
pub fn register_testing(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyFullStackNode>()?;
    m.add_function(wrap_pyfunction!(py_fullstack_create_node, m)?)?;
    m.add_function(wrap_pyfunction!(py_fullstack_create_context, m)?)?;
    m.add_function(wrap_pyfunction!(py_fullstack_add_member, m)?)?;
    m.add_function(wrap_pyfunction!(py_fullstack_join_from_welcome, m)?)?;
    m.add_function(wrap_pyfunction!(py_fullstack_sync_sender_keys, m)?)?;
    m.add_function(wrap_pyfunction!(py_fullstack_send_message, m)?)?;
    m.add_function(wrap_pyfunction!(py_fullstack_decrypt_message, m)?)?;
    m.add_function(wrap_pyfunction!(py_fullstack_remove_member, m)?)?;
    m.add_function(wrap_pyfunction!(py_fullstack_reset_network, m)?)?;
    Ok(())
}
