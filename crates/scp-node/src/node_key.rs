//! The node's own node key (`09-security-model.md` §9.6.3 "How a node gets
//! its key and its binding"; `10-infrastructure-and-self-hosting.md` §10.4
//! "Node key and binding").
//!
//! The node draws its node key on its first start and keeps the 32-byte
//! scalar in the storage its SCP instance hands it, under `scp/node-key`,
//! through [`ProtocolRepository::store_node_key`] and
//! [`ProtocolRepository::load_node_key`] (`17-persistence-and-storage.md`
//! §17.3 "Node key", §17.4). Every later start reads the same key, so the
//! `NodeId` an installed binding names survives a restart. No separate store
//! exists, and nothing here exports the key: the scalar leaves storage only
//! as the [`NodeSigningKey`], whose secret is wiped when it drops.
//!
//! [`sign_possession`] is the body of the binary's local `sign-binding`
//! command (§9.6.3 step 2): it signs `possession_sig` for the operator's
//! choice of operator, canonical URL and key-state head, against the node's
//! own storage, and refuses when that storage holds no key, because only a
//! node's start draws one (§17.3). Nothing that answers a wire message reaches it: the
//! transports hold only a [`BoundNodeKey`](scp_protocol::node::BoundNodeKey),
//! which signs node proofs and nothing else.
//!
//! [`binding_slot_from`] reads the operator's installed binding (step 4), and
//! [`install`] turns the key and that binding into the [`NodeProofs`] every
//! transport signs with, refusing a binding that fails step 4's checks.

use std::sync::Arc;

use scp_core::store::{ProtocolRepository, StoreError};
use scp_did::{DidError, Identifier, NodeUrl};
use scp_platform::traits::Storage;
use scp_protocol::node::{
    NodeBinding, NodeBindingInstallError, NodeListError, NodeSigningKey, NodeSigningKeyError,
    node_url_hash,
};
use scp_transport::native::node_proof::NodeProofs;

use crate::config::NodeBindingSlot;

/// Why the node key could not be read, created, stored or used.
#[derive(Debug, thiserror::Error)]
pub enum NodeKeyStoreError {
    /// The instance storage failed to read the key, or holds a value that is
    /// no node key this build reads (§17.3 "Node key").
    #[error("reading the node key from instance storage: {0}")]
    Read(#[source] StoreError),
    /// The instance storage failed to write a new key.
    #[error("writing the node key to instance storage: {0}")]
    Write(#[source] StoreError),
    /// The instance storage holds no node key, and the operation only signs
    /// with one: only a node's start draws the key (§17.3 "Node key").
    #[error(
        "the instance storage holds no node key; start the node once on this storage so it \
         draws its key, then sign the binding"
    )]
    NoKey,
    /// A fresh key names no `NodeId`, or signing failed.
    #[error("the node key: {0}")]
    Key(#[from] NodeSigningKeyError),
}

/// Reads the node key from `repository`, or draws and stores one when it
/// holds none (§9.6.3 step 1). Only a node's start calls this.
///
/// # Errors
///
/// [`NodeKeyStoreError::Read`] for a storage failure or a stored value that
/// is not a node key this build reads, [`NodeKeyStoreError::Write`] when a
/// new key cannot be stored. A stored key that fails to read is never
/// replaced by a fresh one, because a new key would silently orphan the
/// binding the operator installed for the old one.
pub async fn load_or_generate<S: Storage>(
    repository: &ProtocolRepository<S>,
) -> Result<NodeSigningKey, NodeKeyStoreError> {
    if let Some(key) = repository
        .load_node_key()
        .await
        .map_err(NodeKeyStoreError::Read)?
    {
        tracing::info!(node_id = %key.node_id(), "loaded the node key from instance storage");
        return Ok(key);
    }
    let key = NodeSigningKey::generate(&mut rand::rngs::OsRng)?;
    repository
        .store_node_key(&key)
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

/// Signs `possession_sig` with the node key `repository` holds (§9.6.3
/// step 2).
///
/// The signature is over P for `operator`, `url` and `key_state_head`. P
/// carries the node's own key, so no caller can make the node sign a binding
/// of another key. It never draws a key: a key drawn here would be a key no
/// node has started with (§17.3 "Node key").
///
/// Only the binary's local `sign-binding` command calls this; no transport
/// holds the storage or the unbound key it reads.
///
/// # Errors
///
/// [`NodeKeyStoreError::NoKey`] when `repository` holds no node key,
/// [`NodeKeyStoreError::Read`] when the stored key cannot be read, and
/// [`NodeKeyStoreError::Key`] when signing fails.
pub async fn sign_possession<S: Storage>(
    repository: &ProtocolRepository<S>,
    operator: &Identifier,
    url: &NodeUrl,
    key_state_head: &[u8; 32],
) -> Result<PossessionSignature, NodeKeyStoreError> {
    let key = repository
        .load_node_key()
        .await
        .map_err(NodeKeyStoreError::Read)?
        .ok_or(NodeKeyStoreError::NoKey)?;
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
    use scp_core::store::node_key::NODE_KEY_KEY;
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

    fn repository() -> ProtocolRepository<InMemoryStorage> {
        ProtocolRepository::new_for_testing(InMemoryStorage::new())
    }

    #[tokio::test]
    async fn the_stored_key_is_the_key_every_later_load_reads() -> TestResult {
        let repository = repository();
        let first = load_or_generate(&repository).await?;
        let second = load_or_generate(&repository).await?;
        assert_eq!(first.node_key(), second.node_key());
        assert_eq!(first.node_id(), second.node_id());
        Ok(())
    }

    #[tokio::test]
    async fn a_stored_value_that_is_no_key_refuses_and_stays() -> TestResult {
        let repository = repository();
        repository
            .storage()
            .store(NODE_KEY_KEY, b"not a key")
            .await?;
        assert!(matches!(
            load_or_generate(&repository).await,
            Err(NodeKeyStoreError::Read(StoreError::DeserializationFailed(
                _
            )))
        ));
        assert_eq!(
            repository
                .storage()
                .retrieve(NODE_KEY_KEY)
                .await?
                .as_deref(),
            Some(b"not a key".as_slice()),
            "a key that fails to read is never replaced"
        );
        Ok(())
    }

    /// `sign-binding` signs only with a key a start drew; on storage that
    /// holds none it refuses and draws nothing (§17.3 "Node key").
    #[tokio::test]
    async fn signing_a_binding_without_a_held_key_refuses_and_draws_none() -> TestResult {
        let repository = repository();
        let refusal =
            sign_possession(&repository, &operator(), &NodeUrl::new(URL)?, &[0x0b; 32]).await;
        assert!(
            matches!(refusal, Err(NodeKeyStoreError::NoKey)),
            "{refusal:?}"
        );
        assert!(
            repository.load_node_key().await?.is_none(),
            "a refused signing draws no key"
        );
        Ok(())
    }

    /// The local command's output, copied into a binding, installs on the
    /// key in the same storage.
    #[tokio::test]
    async fn the_possession_signature_installs_on_the_same_storage() -> TestResult {
        let repository = repository();
        let key = load_or_generate(&repository).await?;
        let url = NodeUrl::new(URL)?;
        let grant = sign_possession(&repository, &operator(), &url, &[0x0b; 32]).await?;
        assert_eq!(grant.url_hash, node_url_hash(&url));
        assert_eq!(&grant.node_key, key.node_key());
        let proofs = install(
            load_or_generate(&repository).await?,
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
        let repository = repository();
        load_or_generate(&repository).await?;
        let url = NodeUrl::new(URL)?;
        let binding =
            binding_from(&sign_possession(&repository, &operator(), &url, &[0x0b; 32]).await?);
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
