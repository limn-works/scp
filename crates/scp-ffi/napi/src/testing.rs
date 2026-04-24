//! Full-stack E2E testing module for the NAPI bridge.
//!
//! Exposes `FullStackNetwork` and `FullStackNode` from `scp-testing` as NAPI
//! classes so TypeScript tests can prove real encrypt-decrypt roundtrips
//! through the entire protocol stack (MLS + sender keys + `ContextManager`).
//!
//! Feature-gated behind `allow_in_memory_custody` -- never compiled into
//! production builds.

use scp_ffi_common::error_codes as codes;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use napi::bindgen_prelude::Buffer;
use napi_derive::napi;
use scp_core::context::governance::KeyResolver;
use scp_core::context::{Capability, ContextHandle, ContextMode, ContextParams, context_id_bytes};
use scp_testing::fullstack::{FullStackNetwork, FullStackNode};

use crate::error::ScpNapiError;
use crate::runtime::default_bridge_instance;

// ---------------------------------------------------------------------------
// Shared network
// ---------------------------------------------------------------------------
//
// The shared `FullStackNetwork` lives as a typed field on
// `NapiBridgeInstance` (see `crate::runtime::NapiBridgeInstance::network`).
// Using the per-bridge slot (instead of a process-global singleton)
// preserves the previous behaviour — all `fullstack_create_node` calls on
// the same instance share a `KeyExchange` — while still allowing a
// caller-owned `SCP` to keep its test network isolated from other
// instances in the same process.
//
// `Mutex<Option<...>>` (rather than `OnceLock`) is used so tests can reset
// the network between runs, preventing cross-test state leakage via the
// `fullstack_reset_network` entry point.
// ---------------------------------------------------------------------------

/// Returns the result of calling `f` with the default bridge instance's
/// `FullStackNetwork`.
///
/// All nodes created via `fullstack_create_node` on the same instance share
/// the same `KeyExchange` so Welcome messages and sender keys can be
/// exchanged between them.
fn with_network<F, R>(f: F) -> napi::Result<R>
where
    F: FnOnce(&FullStackNetwork) -> R,
{
    let bi = default_bridge_instance()?;
    let mut guard = bi
        .network()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let network = guard.get_or_insert_with(FullStackNetwork::new);
    Ok(f(network))
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
    /// `NapiBridgeInstance` id that minted this node. In the testing
    /// harness this is always the default instance — cross-instance
    /// isolation on test doubles is meaningless.
    pub(crate) instance_id: u64,
}

#[napi]
impl NapiFullStackNode {
    /// Returns this node's DID string.
    #[napi(getter)]
    pub fn did(&self) -> String {
        self.inner.did.to_string()
    }

    /// Returns the id of the `SCP` instance that minted this node, as a
    /// base-10 string.
    #[napi(getter, js_name = "instanceId")]
    pub fn instance_id_js(&self) -> String {
        self.instance_id.to_string()
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
#[napi]
pub fn fullstack_create_node(did: String) -> napi::Result<NapiFullStackNode> {
    let instance_id = crate::runtime::default_instance_id()
        .unwrap_or(scp_ffi_common::bridge_instance::UNSET_INSTANCE_ID);
    with_network(|network| {
        let node = network.create_node(&did, permissive_key_resolver());
        NapiFullStackNode {
            inner: node,
            handles: Mutex::new(HashMap::new()),
            instance_id,
        }
    })
}

/// Resets the default bridge instance's `FullStackNetwork`, dropping all
/// nodes and state.
///
/// Call between test suites to prevent cross-test state leakage.
#[napi]
pub fn fullstack_reset_network() -> napi::Result<()> {
    let bi = default_bridge_instance()?;
    let mut guard = bi
        .network()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *guard = None;
    Ok(())
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
            code: codes::VALID_7050.to_owned(),
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
                code: codes::CTX_2050.to_owned(),
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
                code: codes::CTX_2051.to_owned(),
            })
        })?
    };

    rt.block_on(node.inner.add_member(&handle, &member_did))
        .map_err(|e| {
            napi::Error::from(ScpNapiError::Crypto {
                message: format!("failed to add member: {e}"),
                code: codes::CRYPTO_4050.to_owned(),
            })
        })
}

/// Joins a context by retrieving the Welcome from the shared `KeyExchange`.
///
/// This is the joiner-side operation. The adder must have called
/// `fullstack_add_member` first to deposit the Welcome and sender keys.
///
/// After joining, the context is registered on the joiner's `ContextManager`
/// with a `ContextHandle`, enabling subsequent `fullstack_send_message` and
/// `fullstack_remove_member` calls on this node.
#[napi]
pub fn fullstack_join_from_welcome(
    node: &NapiFullStackNode,
    context_id: String,
) -> napi::Result<()> {
    let ctx_bytes = context_id_bytes(&context_id);
    let rt = crate::runtime();

    // Step 1: Register the context on the joiner's ContextManager.
    // This creates a throwaway MLS group + the joiner's own sender key +
    // a PerContextState entry so send_message / leave_context work.
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
            napi::Error::from(ScpNapiError::Context {
                message: format!("failed to register context on joiner: {e}"),
                code: codes::CTX_2055.to_owned(),
            })
        })?;

    // Step 2: Replace the throwaway MLS group with the Welcome-derived one
    // and pick up the adder's sender keys and access key from the exchange.
    node.inner
        .join_from_welcome(&context_id, &ctx_bytes)
        .map_err(|e| {
            napi::Error::from(ScpNapiError::Crypto {
                message: format!("failed to join from Welcome: {e}"),
                code: codes::CRYPTO_4051.to_owned(),
            })
        })?;

    // Step 2b: Regenerate the joiner's sender key and distribute it to
    // existing members. The key from create_context was for the throwaway
    // MLS group and is now stale.
    node.inner
        .regenerate_and_distribute_sender_key(&ctx_bytes)
        .map_err(|e| {
            napi::Error::from(ScpNapiError::Crypto {
                message: format!("failed to distribute joiner sender key: {e}"),
                code: codes::CRYPTO_4060.to_owned(),
            })
        })?;

    // Step 2c: Sync all members' access keys into the ContextManager's
    // PerContextState so that send_message wraps content for all recipients.
    // join_from_welcome already populates E2eCryptoProvider's local store;
    // this step ensures the ContextManager also has them.
    let rt = crate::runtime();
    rt.block_on(
        node.inner
            .sync_access_keys_to_manager(&context_id, &ctx_bytes),
    );

    // Step 3: Store the handle so subsequent operations can retrieve it.
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
///
/// Call this after `fullstack_join_from_welcome` to enable bidirectional
/// messaging in tests.
#[napi]
pub fn fullstack_sync_sender_keys(
    node_a: &NapiFullStackNode,
    node_b: &NapiFullStackNode,
    context_id: String,
) -> napi::Result<()> {
    let ctx_bytes = context_id_bytes(&context_id);
    let did_a = node_a.inner.did.to_string();
    let did_b = node_b.inner.did.to_string();

    // A distributes to B, B distributes to A.
    node_a
        .inner
        .crypto
        .distribute_sender_key(&ctx_bytes, &did_b)
        .map_err(|e| {
            napi::Error::from(ScpNapiError::Crypto {
                message: format!("failed to distribute sender key from A to B: {e}"),
                code: codes::CRYPTO_4056.to_owned(),
            })
        })?;
    node_b
        .inner
        .crypto
        .distribute_sender_key(&ctx_bytes, &did_a)
        .map_err(|e| {
            napi::Error::from(ScpNapiError::Crypto {
                message: format!("failed to distribute sender key from B to A: {e}"),
                code: codes::CRYPTO_4057.to_owned(),
            })
        })?;

    // Both pick up the other's key from the exchange.
    node_a.inner.pickup_sender_keys(&ctx_bytes).map_err(|e| {
        napi::Error::from(ScpNapiError::Crypto {
            message: format!("failed to pick up sender keys for A: {e}"),
            code: codes::CRYPTO_4058.to_owned(),
        })
    })?;
    node_b.inner.pickup_sender_keys(&ctx_bytes).map_err(|e| {
        napi::Error::from(ScpNapiError::Crypto {
            message: format!("failed to pick up sender keys for B: {e}"),
            code: codes::CRYPTO_4059.to_owned(),
        })
    })?;

    Ok(())
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
                code: codes::CTX_2052.to_owned(),
            })
        })?
    };

    rt.block_on(node.inner.send_message(&handle, &payload))
        .map_err(|e| {
            napi::Error::from(ScpNapiError::Crypto {
                message: format!("failed to send message: {e}"),
                code: codes::CRYPTO_4052.to_owned(),
            })
        })?;

    // Retrieve the captured ciphertext from the transport.
    let sent = node.inner.take_sent_ciphertexts();
    if sent.is_empty() {
        return Err(napi::Error::from(ScpNapiError::Crypto {
            message: "no ciphertext captured after send".to_owned(),
            code: codes::CRYPTO_4053.to_owned(),
        }));
    }
    if sent.len() > 1 {
        return Err(napi::Error::from(ScpNapiError::Crypto {
            message: format!(
                "expected 1 ciphertext after send, got {} — send_message should produce exactly one",
                sent.len()
            ),
            code: codes::CRYPTO_4055.to_owned(),
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
        .decrypt_message(&context_id, &ctx_bytes, &ciphertext, &sender_did)
        .map_err(|e| {
            napi::Error::from(ScpNapiError::Crypto {
                message: format!("failed to decrypt message: {e}"),
                code: codes::CRYPTO_4054.to_owned(),
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
                code: codes::CTX_2053.to_owned(),
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
            code: codes::CTX_2054.to_owned(),
        })
    })?;

    // Drain transport buffer: leave_context produces MLS Commit +
    // sender key rotation distributions. If not drained, the next
    // fullstack_send_message would see >1 ciphertext and fail the
    // single-ciphertext assertion.
    let _ = node.inner.take_sent_ciphertexts();

    Ok(())
}
