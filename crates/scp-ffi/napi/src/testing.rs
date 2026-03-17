//! Full-stack E2E testing module for the NAPI bridge.
//!
//! Exposes `FullStackNetwork` and `FullStackNode` from `scp-testing` as NAPI
//! classes so TypeScript tests can prove real encrypt-decrypt roundtrips
//! through the entire protocol stack (MLS + sender keys + `ContextManager`).
//!
//! Feature-gated behind `allow_in_memory_custody` -- never compiled into
//! production builds.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use napi::bindgen_prelude::Buffer;
use napi_derive::napi;
use scp_core::context::governance::KeyResolver;
use scp_core::context::{Capability, ContextHandle, ContextMode, ContextParams, context_id_bytes};
use scp_testing::fullstack::{FullStackNetwork, FullStackNode};

use crate::error::ScpNapiError;

// ---------------------------------------------------------------------------
// Shared network
// ---------------------------------------------------------------------------

/// Returns the shared `FullStackNetwork` instance.
///
/// All nodes created via `fullstack_create_node` share the same `KeyExchange`
/// so Welcome messages and sender keys can be exchanged between them.
fn shared_network() -> &'static FullStackNetwork {
    use std::sync::OnceLock;
    static NETWORK: OnceLock<FullStackNetwork> = OnceLock::new();
    NETWORK.get_or_init(FullStackNetwork::new)
}

/// Returns a permissive key resolver that always returns `None`.
///
/// Full-stack E2E tests verify crypto, not governance vote signatures.
fn permissive_key_resolver() -> KeyResolver {
    Arc::new(|_did| None)
}

// ---------------------------------------------------------------------------
// NapiFullStackNode -- opaque JS class wrapping FullStackNode
// ---------------------------------------------------------------------------

/// Opaque handle to a full-stack test node with real MLS crypto.
///
/// Each node has its own `ContextManager` backed by `E2eCryptoProvider`
/// (real MLS + sender keys) with a shared `KeyExchange` for coordinating
/// Welcome messages and sender keys between nodes.
#[napi]
pub struct NapiFullStackNode {
    /// The underlying Rust `FullStackNode`.
    inner: FullStackNode,
    /// Stored context handles, keyed by context ID string.
    handles: Mutex<HashMap<String, ContextHandle>>,
}

#[napi]
impl NapiFullStackNode {
    /// Returns this node's DID string.
    #[napi(getter)]
    pub fn did(&self) -> String {
        self.inner.did.to_string()
    }
}

// ---------------------------------------------------------------------------
// Exported NAPI functions
// ---------------------------------------------------------------------------

/// Creates a full-stack test node with real MLS crypto.
///
/// All nodes created via this function share a single `FullStackNetwork`
/// (and therefore a single [`KeyExchange`]), enabling Welcome message and
/// sender key exchange between them.
#[must_use]
#[napi]
pub fn fullstack_create_node(did: String) -> NapiFullStackNode {
    let network = shared_network();
    let node = network.create_node(&did, permissive_key_resolver());
    NapiFullStackNode {
        inner: node,
        handles: Mutex::new(HashMap::new()),
    }
}

/// Creates an encrypted context owned by the given node.
///
/// Returns the context ID string on success. The `ceiling_json` parameter
/// is a JSON-encoded object with optional `ceiling` (string array) and
/// `governance` (string) fields.
#[napi]
pub fn fullstack_create_context(
    node: &NapiFullStackNode,
    context_id: String,
    ceiling_json: String,
) -> napi::Result<String> {
    let ceiling_obj: serde_json::Value = serde_json::from_str(&ceiling_json).map_err(|e| {
        napi::Error::from(ScpNapiError::Validation {
            message: format!("invalid ceiling JSON: {e}"),
            code: "SCP-VALID-7050".to_owned(),
        })
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

    let rt = crate::runtime();
    let handle = rt
        .block_on(node.inner.create_context(&context_id, params))
        .map_err(|e| {
            napi::Error::from(ScpNapiError::Context {
                message: format!("failed to create context: {e}"),
                code: "SCP-CTX-2050".to_owned(),
            })
        })?;

    // Store the handle so subsequent operations can retrieve it.
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
///
/// Internally calls `add_member` on the node's `FullStackNode`, which
/// triggers `crypto.add_member` (capturing the Welcome) and
/// `crypto.distribute_sender_key` (depositing the sender key in the shared
/// `KeyExchange`).
#[napi]
pub fn fullstack_add_member(
    node: &NapiFullStackNode,
    context_id: String,
    member_did: String,
) -> napi::Result<()> {
    let rt = crate::runtime();

    let handle = {
        let handles = node
            .handles
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        handles.get(&context_id).cloned().ok_or_else(|| {
            napi::Error::from(ScpNapiError::Context {
                message: format!("context '{context_id}' not found in node's handles"),
                code: "SCP-CTX-2051".to_owned(),
            })
        })?
    };

    rt.block_on(node.inner.add_member(&handle, &member_did))
        .map_err(|e| {
            napi::Error::from(ScpNapiError::Crypto {
                message: format!("failed to add member: {e}"),
                code: "SCP-CRYPTO-4050".to_owned(),
            })
        })
}

/// Joins a context by retrieving the Welcome from the shared `KeyExchange`.
///
/// This is the joiner-side operation. The adder must have called
/// `fullstack_add_member` first to deposit the Welcome and sender keys.
#[napi]
pub fn fullstack_join_from_welcome(
    node: &NapiFullStackNode,
    context_id: String,
) -> napi::Result<()> {
    let ctx_bytes = context_id_bytes(&context_id);
    node.inner.join_from_welcome(&ctx_bytes).map_err(|e| {
        napi::Error::from(ScpNapiError::Crypto {
            message: format!("failed to join from Welcome: {e}"),
            code: "SCP-CRYPTO-4051".to_owned(),
        })
    })
}

/// Encrypts a message and returns the ciphertext.
///
/// Uses the node's real `ContextManager` + `E2eCryptoProvider` for double
/// encryption (sender key AES-256-GCM + MLS). The ciphertext is captured
/// by the node's `CapturingTransport` and returned here.
#[napi]
pub fn fullstack_send_message(
    node: &NapiFullStackNode,
    context_id: String,
    payload: Buffer,
) -> napi::Result<Buffer> {
    let rt = crate::runtime();

    let handle = {
        let handles = node
            .handles
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        handles.get(&context_id).cloned().ok_or_else(|| {
            napi::Error::from(ScpNapiError::Context {
                message: format!("context '{context_id}' not found in node's handles"),
                code: "SCP-CTX-2052".to_owned(),
            })
        })?
    };

    rt.block_on(node.inner.send_message(&handle, &payload))
        .map_err(|e| {
            napi::Error::from(ScpNapiError::Crypto {
                message: format!("failed to send message: {e}"),
                code: "SCP-CRYPTO-4052".to_owned(),
            })
        })?;

    // Retrieve the captured ciphertext from the transport.
    let sent = node.inner.take_sent_ciphertexts();
    if sent.is_empty() {
        return Err(napi::Error::from(ScpNapiError::Crypto {
            message: "no ciphertext captured after send".to_owned(),
            code: "SCP-CRYPTO-4053".to_owned(),
        }));
    }

    Ok(Buffer::from(sent[0].1.clone()))
}

/// Decrypts a message using the node's real MLS + sender key crypto.
///
/// Automatically processes any pending MLS commits first so the group
/// epoch is current (handles multi-party scenarios where a third member
/// was added after this node last synced).
#[napi]
pub fn fullstack_decrypt_message(
    node: &NapiFullStackNode,
    context_id: String,
    ciphertext: Buffer,
    sender_did: String,
) -> napi::Result<Buffer> {
    let ctx_bytes = context_id_bytes(&context_id);
    let plaintext = node
        .inner
        .decrypt_message(&ctx_bytes, &ciphertext, &sender_did, 0, 0)
        .map_err(|e| {
            napi::Error::from(ScpNapiError::Crypto {
                message: format!("failed to decrypt message: {e}"),
                code: "SCP-CRYPTO-4054".to_owned(),
            })
        })?;

    Ok(Buffer::from(plaintext))
}

/// Removes a member from the context.
///
/// After removal, the removed member should not be able to decrypt
/// new messages (MLS forward secrecy).
#[napi]
pub fn fullstack_remove_member(
    node: &NapiFullStackNode,
    context_id: String,
    member_did: String,
) -> napi::Result<()> {
    let rt = crate::runtime();

    let handle = {
        let handles = node
            .handles
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        handles.get(&context_id).cloned().ok_or_else(|| {
            napi::Error::from(ScpNapiError::Context {
                message: format!("context '{context_id}' not found in node's handles"),
                code: "SCP-CTX-2053".to_owned(),
            })
        })?
    };

    rt.block_on(node.inner.manager.leave_context(
        &handle,
        &node.inner.did,
        &scp_identity::DID::from(member_did.as_str()),
    ))
    .map_err(|e| {
        napi::Error::from(ScpNapiError::Context {
            message: format!("failed to remove member: {e}"),
            code: "SCP-CTX-2054".to_owned(),
        })
    })
}
