//! The node's own node key (`09-security-model.md` §9.6.3 "How a node gets
//! its key and its binding"; `10-infrastructure-and-self-hosting.md` §10.4
//! "Node key and binding").
//!
//! The node draws its node key on its first start and keeps the 32-byte
//! scalar in the storage its SCP instance hands it, under
//! [`NODE_KEY_STORAGE_KEY`], in a [`StoredValue`] version envelope. Every
//! later start reads the same key, so the `NodeId` an installed binding names
//! survives a restart. No separate store exists, and nothing here exports
//! the key: the scalar leaves this module only as the [`NodeSigningKey`],
//! whose secret is wiped when it drops.
//!
//! [`sign_possession`] is the body of the binary's local `sign-binding`
//! command (§9.6.3 step 2): it signs `possession_sig` for the operator's
//! choice of operator, canonical URL and key-state head, against the node's
//! own storage. Nothing that answers a wire message reaches it: the
//! transports hold only a [`BoundNodeKey`](scp_protocol::node::BoundNodeKey),
//! which signs node proofs and nothing else.
//!
//! [`binding_slot_from`] reads the operator's installed binding (step 4), and
//! [`install`] turns the key and that binding into the [`NodeProofs`] every
//! transport signs with, refusing a binding that fails step 4's checks.

use std::sync::Arc;

use scp_core::store::{CURRENT_STORE_VERSION, StoredValue};
use scp_did::{DidError, Identifier, NodeUrl};
use scp_platform::PlatformError;
use scp_platform::traits::Storage;
use scp_protocol::node::{
    NodeBinding, NodeBindingInstallError, NodeListError, NodeSigningKey, NodeSigningKeyError,
    node_url_hash,
};
use scp_transport::native::node_proof::NodeProofs;
use zeroize::{Zeroize, Zeroizing};

use crate::config::NodeBindingSlot;

/// The storage key of the node key, a top-level singleton beside
/// `scp/identity` (spec §17.3 key convention).
pub const NODE_KEY_STORAGE_KEY: &str = "scp/node-key";

/// Why the node key could not be read, created or stored.
#[derive(Debug, thiserror::Error)]
pub enum NodeKeyStoreError {
    /// The instance storage failed to read the key.
    #[error("reading the node key from instance storage: {0}")]
    Read(#[source] PlatformError),
    /// The instance storage failed to write a new key.
    #[error("writing the node key to instance storage: {0}")]
    Write(#[source] PlatformError),
    /// The stored bytes are not a node-key envelope.
    #[error("the stored node key is not a node-key envelope")]
    Malformed,
    /// The stored envelope is newer than this binary reads.
    #[error("the stored node key has version {0}, newer than this binary reads")]
    UnsupportedVersion(u16),
    /// The stored scalar is no P-256 key, or a fresh key names no `NodeId`.
    #[error("the node key: {0}")]
    Key(#[from] NodeSigningKeyError),
    /// A new key's envelope could not be encoded.
    #[error("encoding the node key envelope")]
    Encode,
}

/// Reads the node key from `storage`, or draws and stores one when
/// `storage` holds none (§9.6.3 step 1).
///
/// # Errors
///
/// [`NodeKeyStoreError`]: a storage failure, a stored value that is not a
/// node key, or a version this binary does not read. A stored key that
/// fails to read is never replaced by a fresh one, because a new key would
/// silently orphan the binding the operator installed for the old one.
pub async fn load_or_generate<S: Storage + ?Sized>(
    storage: &S,
) -> Result<NodeSigningKey, NodeKeyStoreError> {
    if let Some(bytes) = storage
        .retrieve(NODE_KEY_STORAGE_KEY)
        .await
        .map_err(NodeKeyStoreError::Read)?
    {
        let bytes = Zeroizing::new(bytes);
        let mut envelope: StoredValue<[u8; 32]> =
            rmp_serde::from_slice(&bytes).map_err(|_| NodeKeyStoreError::Malformed)?;
        let key = if envelope.version > CURRENT_STORE_VERSION {
            Err(NodeKeyStoreError::UnsupportedVersion(envelope.version))
        } else {
            NodeSigningKey::from_scalar_bytes(&envelope.data).map_err(NodeKeyStoreError::Key)
        };
        envelope.data.zeroize();
        let key = key?;
        tracing::info!(node_id = %key.node_id(), "loaded the node key from instance storage");
        return Ok(key);
    }
    let key = NodeSigningKey::generate(&mut rand::rngs::OsRng)?;
    let envelope = StoredValue {
        version: CURRENT_STORE_VERSION,
        data: *key.to_scalar_bytes(),
    };
    let encoded = rmp_serde::to_vec_named(&envelope).map(Zeroizing::new);
    let mut envelope = envelope;
    envelope.data.zeroize();
    let encoded = encoded.map_err(|_| NodeKeyStoreError::Encode)?;
    storage
        .store(NODE_KEY_STORAGE_KEY, &encoded)
        .await
        .map_err(NodeKeyStoreError::Write)?;
    tracing::info!(node_id = %key.node_id(), "drew a new node key into instance storage");
    Ok(key)
}

/// The [`NodeProofs`] the node's transports sign with: none for
/// [`NodeBindingSlot::Unbound`], and the bound key for an installed binding
/// that passes §9.6.3's installation checks.
///
/// # Errors
///
/// [`NodeBindingInstallError`] for a binding of another key, a
/// `possession_sig` that fails under the node key, or a `url_hash` that is
/// not the configured URL's.
pub fn install(
    key: NodeSigningKey,
    slot: NodeBindingSlot,
) -> Result<NodeProofs, NodeBindingInstallError> {
    match slot {
        NodeBindingSlot::Unbound => {
            tracing::info!(
                node_id = %key.node_id(),
                "no node binding installed; QUERY responses carry no node proof"
            );
            Ok(NodeProofs::Unbound)
        }
        NodeBindingSlot::Installed { binding, url } => {
            let bound = key.install(*binding, &url)?;
            tracing::info!(
                node_id = %bound.node_id(),
                operator = %bound.binding().operator,
                url = url.as_str(),
                "installed the node binding; QUERY responses carry node proofs"
            );
            Ok(NodeProofs::Sign(Arc::new(bound)))
        }
    }
}

/// Why the operator's binding configuration names no installable binding.
#[derive(Debug, thiserror::Error)]
pub enum NodeBindingConfigError {
    /// A binding is configured without the canonical URL it binds.
    #[error("a node binding is configured without its canonical node URL")]
    BindingWithoutUrl,
    /// A canonical URL is configured without a binding.
    #[error("a canonical node URL is configured without a node binding")]
    UrlWithoutBinding,
    /// The binding is not the RFC 8785 canonical JSON of a `NodeBinding`.
    #[error("the node binding is not the canonical JSON of a NodeBinding: {0}")]
    Binding(#[source] NodeListError),
    /// The URL has no canonical node-URL form.
    #[error("the canonical node URL: {0}")]
    Url(#[source] DidError),
}

/// The [`NodeBindingSlot`] the operator configured.
///
/// `binding` is the binding's RFC 8785 canonical JSON
/// ([`NodeBinding::to_canonical_json`]) and `url` the node's canonical URL.
/// Neither set is [`NodeBindingSlot::Unbound`].
///
/// # Errors
///
/// [`NodeBindingConfigError`] when only one of the two is set, or when either
/// does not parse. A malformed binding never reads as no binding, because
/// the operator who set one expects proofs.
pub fn binding_slot_from(
    binding: Option<&str>,
    url: Option<&str>,
) -> Result<NodeBindingSlot, NodeBindingConfigError> {
    match (binding, url) {
        (None, None) => Ok(NodeBindingSlot::Unbound),
        (Some(_), None) => Err(NodeBindingConfigError::BindingWithoutUrl),
        (None, Some(_)) => Err(NodeBindingConfigError::UrlWithoutBinding),
        (Some(binding), Some(url)) => Ok(NodeBindingSlot::Installed {
            binding: Box::new(
                NodeBinding::from_canonical_json(binding.as_bytes())
                    .map_err(NodeBindingConfigError::Binding)?,
            ),
            url: NodeUrl::new(url).map_err(NodeBindingConfigError::Url)?,
        }),
    }
}

/// What the local `sign-binding` command returns to the operator (§9.6.3
/// step 2): the node's own key, the URL hash it put into P, and its
/// signature over P.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PossessionSignature {
    /// The node's compressed SEC1 P-256 key, which P names.
    pub node_key: [u8; 33],
    /// SHA-256 of the canonical URL, which P names.
    pub url_hash: [u8; 32],
    /// The node key's signature over P.
    pub possession_sig: [u8; 64],
}

impl PossessionSignature {
    /// The three members as RFC 8785 canonical JSON, lowercase hex, spelled
    /// as the binding's own members are, so the operator copies them into
    /// the binding it signs.
    #[must_use]
    pub fn to_json(&self) -> String {
        // The members sort lexicographically and hold only hex, so this text
        // is the canonical form.
        format!(
            r#"{{"node_key":"{}","possession_sig":"{}","url_hash":"{}"}}"#,
            hex::encode(self.node_key),
            hex::encode(self.possession_sig),
            hex::encode(self.url_hash),
        )
    }
}

/// Signs `possession_sig` with the node key in `storage` (§9.6.3 step 2).
///
/// The signature is over P for `operator`, `url` and `key_state_head`, and
/// the key is drawn first when `storage` holds none. P carries the node's
/// own key, so no caller can make the node sign a binding of another key.
///
/// Only the binary's local `sign-binding` command calls this; no transport
/// holds the storage or the unbound key it reads.
///
/// # Errors
///
/// Every error of [`load_or_generate`], and [`NodeKeyStoreError::Key`] when
/// signing fails.
pub async fn sign_possession<S: Storage + ?Sized>(
    storage: &S,
    operator: &Identifier,
    url: &NodeUrl,
    key_state_head: &[u8; 32],
) -> Result<PossessionSignature, NodeKeyStoreError> {
    let key = load_or_generate(storage).await?;
    let url_hash = node_url_hash(url);
    let possession_sig = key.sign_possession(operator, &url_hash, key_state_head)?;
    Ok(PossessionSignature {
        node_key: *key.node_key(),
        url_hash,
        possession_sig,
    })
}

#[cfg(test)]
mod tests {
    use scp_platform::in_memory::InMemoryStorage;

    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    const URL: &str = "wss://node.example.com/scp/v1";

    fn operator() -> Identifier {
        Identifier::from_bytes([0x0a; 32])
    }

    /// The binding an operator assembles from `grant`, with an
    /// `operator_sig` the node does not check.
    fn binding_from(grant: &PossessionSignature) -> NodeBinding {
        NodeBinding {
            operator: operator(),
            node_key: grant.node_key,
            url_hash: grant.url_hash,
            key_state_head: [0x0b; 32],
            operator_sig: [0x0c; 64],
            possession_sig: grant.possession_sig,
        }
    }

    #[tokio::test]
    async fn the_stored_key_is_the_key_every_later_load_reads() -> TestResult {
        let storage = InMemoryStorage::new();
        let first = load_or_generate(&storage).await?;
        let second = load_or_generate(&storage).await?;
        assert_eq!(first.node_key(), second.node_key());
        assert_eq!(first.node_id(), second.node_id());
        Ok(())
    }

    #[tokio::test]
    async fn a_stored_value_that_is_no_key_refuses_and_stays() -> TestResult {
        let storage = InMemoryStorage::new();
        storage.store(NODE_KEY_STORAGE_KEY, b"not a key").await?;
        assert!(matches!(
            load_or_generate(&storage).await,
            Err(NodeKeyStoreError::Malformed)
        ));
        assert_eq!(
            storage.retrieve(NODE_KEY_STORAGE_KEY).await?.as_deref(),
            Some(b"not a key".as_slice()),
            "a key that fails to read is never replaced"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_zero_scalar_is_no_key() -> TestResult {
        let storage = InMemoryStorage::new();
        let envelope = StoredValue {
            version: CURRENT_STORE_VERSION,
            data: [0u8; 32],
        };
        storage
            .store(NODE_KEY_STORAGE_KEY, &rmp_serde::to_vec_named(&envelope)?)
            .await?;
        assert!(matches!(
            load_or_generate(&storage).await,
            Err(NodeKeyStoreError::Key(NodeSigningKeyError::Scalar(_)))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn a_newer_envelope_is_refused() -> TestResult {
        let storage = InMemoryStorage::new();
        let envelope = StoredValue {
            version: CURRENT_STORE_VERSION + 1,
            data: [7u8; 32],
        };
        storage
            .store(NODE_KEY_STORAGE_KEY, &rmp_serde::to_vec_named(&envelope)?)
            .await?;
        assert!(matches!(
            load_or_generate(&storage).await,
            Err(NodeKeyStoreError::UnsupportedVersion(v)) if v == CURRENT_STORE_VERSION + 1
        ));
        Ok(())
    }

    /// The local command's output, copied into a binding, installs on the
    /// key in the same storage.
    #[tokio::test]
    async fn the_possession_signature_installs_on_the_same_storage() -> TestResult {
        let storage = InMemoryStorage::new();
        let url = NodeUrl::new(URL)?;
        let grant = sign_possession(&storage, &operator(), &url, &[0x0b; 32]).await?;
        assert_eq!(grant.url_hash, node_url_hash(&url));
        let proofs = install(
            load_or_generate(&storage).await?,
            NodeBindingSlot::Installed {
                binding: Box::new(binding_from(&grant)),
                url,
            },
        )?;
        assert!(matches!(proofs, NodeProofs::Sign(_)));
        Ok(())
    }

    #[test]
    fn the_command_output_is_canonical_hex_json() {
        let grant = PossessionSignature {
            node_key: [1; 33],
            url_hash: [2; 32],
            possession_sig: [3; 64],
        };
        let json = grant.to_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap_or_default();
        assert_eq!(parsed["node_key"], hex::encode([1u8; 33]));
        assert_eq!(parsed["url_hash"], hex::encode([2u8; 32]));
        assert_eq!(parsed["possession_sig"], hex::encode([3u8; 64]));
        assert_eq!(
            serde_json::to_string(&parsed).ok().as_deref(),
            Some(json.as_str())
        );
    }

    #[test]
    fn no_binding_and_no_url_is_unbound() -> TestResult {
        assert_eq!(binding_slot_from(None, None)?, NodeBindingSlot::Unbound);
        Ok(())
    }

    #[tokio::test]
    async fn a_binding_and_its_url_read_back() -> TestResult {
        let storage = InMemoryStorage::new();
        let url = NodeUrl::new(URL)?;
        let binding =
            binding_from(&sign_possession(&storage, &operator(), &url, &[0x0b; 32]).await?);
        let json = String::from_utf8(binding.to_canonical_json()?)?;
        assert_eq!(
            binding_slot_from(Some(&json), Some(URL))?,
            NodeBindingSlot::Installed {
                binding: Box::new(binding),
                url
            }
        );
        Ok(())
    }

    #[test]
    fn half_a_binding_configuration_is_refused() {
        assert!(matches!(
            binding_slot_from(Some("{}"), None),
            Err(NodeBindingConfigError::BindingWithoutUrl)
        ));
        assert!(matches!(
            binding_slot_from(None, Some(URL)),
            Err(NodeBindingConfigError::UrlWithoutBinding)
        ));
    }

    #[test]
    fn a_malformed_binding_or_url_is_refused() -> TestResult {
        assert!(matches!(
            binding_slot_from(Some(""), Some(URL)),
            Err(NodeBindingConfigError::Binding(NodeListError::Json { .. }))
        ));
        let binding = binding_from(&PossessionSignature {
            node_key: [2; 33],
            url_hash: [0; 32],
            possession_sig: [0; 64],
        });
        let json = String::from_utf8(binding.to_canonical_json()?)?;
        let spaced = json.replacen(':', ": ", 1);
        assert!(matches!(
            binding_slot_from(Some(&spaced), Some(URL)),
            Err(NodeBindingConfigError::Binding(NodeListError::NotCanonical))
        ));
        assert!(matches!(
            binding_slot_from(Some(&json), Some("https://node.example.com/")),
            Err(NodeBindingConfigError::Url(_))
        ));
        Ok(())
    }
}
