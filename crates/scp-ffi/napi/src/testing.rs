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
use scp_core::context::{Capability, ContextHandle, ContextMode, ContextParams};
use scp_testing::fullstack::{FullStackNetwork, FullStackNode};

use crate::error::ScpNapiError;
use crate::runtime::NapiBridgeInstance;

// ---------------------------------------------------------------------------
// Shared network
// ---------------------------------------------------------------------------
//
// The shared `FullStackNetwork` lives in a process-global slot owned by
// THIS module, NOT on `NapiBridgeInstance`. The test harness needs the
// network to survive across the default bridge's lifecycle: individual
// TypeScript test files exercise `scpShutdown`, which transitions the
// default `NapiBridgeInstance` into a permanent-shutdown state. If the
// test network lived on the default bridge, any test file that ran
// after a shutdown-exercising file would see
// `"default bridge instance has been permanently shut down"` and fail.
//
// A module-local `OnceLock<Mutex<Option<FullStackNetwork>>>` is simpler
// AND sufficient: fullstack nodes are feature-gated behind
// `allow_in_memory_custody`, only ever reached from the test harness,
// and the `KeyExchange` they share is unrelated to bridge-instance
// lifecycle (no handle-affinity, no shutdown hooks). Resetting the
// network between runs still works via `fullstack_reset_network`.
// ---------------------------------------------------------------------------

/// Per-bridge-instance implementation of `with_network`.
///
/// All nodes created via `fullstack_create_node_on` on the same instance
/// share the same `KeyExchange` so Welcome messages and sender keys can be
/// exchanged between them.
fn with_network_on<F, R>(bi: &NapiBridgeInstance, f: F) -> R
where
    F: FnOnce(&FullStackNetwork) -> R,
{
    let mut guard = bi
        .network()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let network = guard.get_or_insert_with(FullStackNetwork::new);
    f(network)
}

/// Returns a permissive key resolver that always returns `None`.
///
/// Full-stack E2E tests verify crypto, not governance vote signatures.
fn permissive_key_resolver() -> KeyResolver {
    Arc::new(|_did: &scp_identity::DID, _kid: scp_identity::SigningKeyId| None)
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
    /// `NapiBridgeInstance` id that minted this node.
    pub(crate) instance_id: u64,
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

/// Per-bridge-instance implementation of `fullstack_create_node`.
///
/// All nodes created via this helper on the same `NapiBridgeInstance`
/// share a single `FullStackNetwork` (and therefore a single
/// `KeyExchange`), enabling Welcome message and sender key exchange
/// between them.
pub(crate) fn fullstack_create_node_on(bi: &NapiBridgeInstance, did: String) -> NapiFullStackNode {
    let instance_id = bi.instance_id();
    with_network_on(bi, |network| {
        let node = network.create_node(&did, permissive_key_resolver());
        NapiFullStackNode {
            inner: node,
            handles: Mutex::new(HashMap::new()),
            instance_id,
        }
    })
}

/// Per-bridge-instance implementation of `fullstack_reset_network`.
///
/// Drops this instance's `FullStackNetwork` (and all nodes / state it
/// owns). Call between test suites to prevent cross-test state leakage.
pub(crate) fn fullstack_reset_network_on(bi: &NapiBridgeInstance) {
    let mut guard = bi
        .network()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *guard = None;
}

/// Per-bridge-instance implementation of [`fullstack_create_context`].
///
/// Enforces per-instance handle affinity: the supplied `node` must have
/// been minted by the same [`NapiBridgeInstance`] `bi` (see ADR-048).
/// A `NapiFullStackNode` from another `SCP` instance would otherwise
/// silently operate against the wrong bridge's shared `KeyExchange`.
pub(crate) fn fullstack_create_context_on(
    bi: &NapiBridgeInstance,
    node: &NapiFullStackNode,
    context_id: String,
    ceiling_json: String,
) -> napi::Result<String> {
    crate::napi_check_handle!(&bi.core, node);
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

/// Per-bridge-instance implementation of [`fullstack_add_member`].
pub(crate) fn fullstack_add_member_on(
    bi: &NapiBridgeInstance,
    node: &NapiFullStackNode,
    context_id: String,
    member_did: String,
) -> napi::Result<()> {
    crate::napi_check_handle!(&bi.core, node);
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

/// Per-bridge-instance implementation of [`fullstack_join_from_welcome`].
///
/// The joiner's `E2eCryptoProvider` processes the Welcome and picks up the
/// access/sender keys so it can DECRYPT messages from the creator. It does
/// NOT register a per-context send `ContextHandle`: the actor-per-context
/// model has no spawn-from-Welcome entrypoint yet (the separate
/// Welcome-Delivery work item), so a subsequent `fullstack_send_message` on a
/// Welcome-joined node fails closed with "context not found in node's
/// handles". The unidirectional path (creator sends, joiner decrypts) is
/// fully supported.
pub(crate) fn fullstack_join_from_welcome_on(
    bi: &NapiBridgeInstance,
    node: &NapiFullStackNode,
    context_id: String,
) -> napi::Result<()> {
    crate::napi_check_handle!(&bi.core, node);
    // ADR-056: key the shared crypto under the canonical digest via the
    // chokepoint, never the raw routing primitive (which double-hashes a real
    // 64-hex id and would diverge from the creator's deposit slot).
    let ctx_bytes = scp_core::context::state::context_id_to_bytes(&context_id);

    // ADR-049 commit 12c.9f: the joiner's MLS group, sender keys, and access
    // keys live directly in its `E2eCryptoProvider` (the joiner has no context
    // actor). `join_from_welcome` forms the group from the captured Welcome,
    // picks up the inviter-minted access keys, processes the inviter's
    // HPKE-sealed sender-key distribution, and applies any epoch-advance
    // Commits — all real crypto.
    node.inner
        .join_from_welcome(&context_id, &ctx_bytes)
        .map_err(|e| {
            napi::Error::from(ScpNapiError::Crypto {
                message: format!("failed to join from Welcome: {e}"),
                code: codes::CRYPTO_4051.to_owned(),
            })
        })
}

/// Per-bridge-instance implementation of [`fullstack_sync_sender_keys`].
pub(crate) fn fullstack_sync_sender_keys_on(
    bi: &NapiBridgeInstance,
    node_a: &NapiFullStackNode,
    node_b: &NapiFullStackNode,
    context_id: String,
) -> napi::Result<()> {
    // Both nodes must have been minted by this bridge — mixing nodes
    // from two different `SCP` instances would cross-wire the shared
    // `KeyExchange` used for sender key distribution.
    crate::napi_check_handle!(&bi.core, node_a, node_b);
    // ADR-056: key the shared KeyExchange under the canonical digest via the
    // chokepoint, never the raw routing primitive.
    let ctx_bytes = scp_core::context::state::context_id_to_bytes(&context_id);
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
    node_a
        .inner
        .pickup_sender_keys(&context_id, &ctx_bytes)
        .map_err(|e| {
            napi::Error::from(ScpNapiError::Crypto {
                message: format!("failed to pick up sender keys for A: {e}"),
                code: codes::CRYPTO_4058.to_owned(),
            })
        })?;
    node_b
        .inner
        .pickup_sender_keys(&context_id, &ctx_bytes)
        .map_err(|e| {
            napi::Error::from(ScpNapiError::Crypto {
                message: format!("failed to pick up sender keys for B: {e}"),
                code: codes::CRYPTO_4059.to_owned(),
            })
        })?;

    Ok(())
}

/// Per-bridge-instance implementation of [`fullstack_send_message`].
pub(crate) fn fullstack_send_message_on(
    bi: &NapiBridgeInstance,
    node: &NapiFullStackNode,
    context_id: String,
    payload: Buffer,
) -> napi::Result<Buffer> {
    crate::napi_check_handle!(&bi.core, node);
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
    // §9.10.4: an encrypted send fans the SAME MLS ciphertext out to each peer's
    // per-member pseudonym routing ID, so a multi-member context captures one
    // entry per peer. The inner encrypted blob is identical across them and
    // decryption ignores the outer routing ID, so any captured entry is a valid
    // ciphertext that every member can decrypt. Return the first.
    Ok(Buffer::from(sent[0].1.clone()))
}

/// Per-bridge-instance implementation of [`fullstack_decrypt_message`].
pub(crate) fn fullstack_decrypt_message_on(
    bi: &NapiBridgeInstance,
    node: &NapiFullStackNode,
    context_id: String,
    ciphertext: Buffer,
    sender_did: String,
) -> napi::Result<Buffer> {
    crate::napi_check_handle!(&bi.core, node);
    // ADR-056: key decryption under the canonical digest via the chokepoint,
    // never the raw routing primitive.
    let ctx_bytes = scp_core::context::state::context_id_to_bytes(&context_id);
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

/// Per-bridge-instance implementation of [`fullstack_remove_member`].
pub(crate) fn fullstack_remove_member_on(
    bi: &NapiBridgeInstance,
    node: &NapiFullStackNode,
    context_id: String,
    member_did: String,
) -> napi::Result<()> {
    crate::napi_check_handle!(&bi.core, node);
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

/// Per-bridge-instance implementation of [`fullstack_seed_peer_pseudonym`].
///
/// Test-only: seeds a peer's per-context pseudonym routing ID (§9.10.4) into
/// this node's `Supervisor`, simulating a delivered `PseudonymAnnouncement` so
/// multi-member encrypted sends do not fail closed with `SCP-CTX-2095`.
/// Mirrors the runtime `Supervisor::seed_peer_pseudonym` test helper.
pub(crate) fn fullstack_seed_peer_pseudonym_on(
    bi: &NapiBridgeInstance,
    node: &NapiFullStackNode,
    context_id: String,
    peer_did: String,
    pseudonym: Buffer,
) -> napi::Result<()> {
    crate::napi_check_handle!(&bi.core, node);

    let pseudonym_bytes: &[u8] = &pseudonym;
    if pseudonym_bytes.len() != 32 {
        return Err(napi::Error::from(ScpNapiError::Context {
            message: format!(
                "pseudonym must be exactly 32 bytes, got {}",
                pseudonym_bytes.len()
            ),
            code: codes::CTX_2095.to_owned(),
        }));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(pseudonym_bytes);

    let rt = crate::runtime();
    rt.block_on(node.inner.manager.seed_peer_pseudonym(
        &context_id,
        scp_identity::DID::from(peer_did.as_str()),
        arr,
    ))
    .map_err(|e| {
        napi::Error::from(ScpNapiError::Context {
            message: format!("failed to seed peer pseudonym: {e}"),
            code: codes::CTX_2095.to_owned(),
        })
    })?;

    Ok(())
}
