//! Generic multi-relay DID-document querier composer (§3.10.2, §3.10.4).
//!
//! [`RealMultiRelayQuerier`] is the production, transport-agnostic composer that
//! wires the relay layer into dual-layer resolution. It bridges the two relay
//! abstractions:
//!
//! - [`RelayQuerier`](crate::resolution::RelayQuerier) — the SINGLE-relay QUERY
//!   trait. Its production implementation lives in `scp-transport`
//!   ([`TransportRelayQuerier`]) because only that crate can talk to a relay
//!   (`scp-transport` depends on `scp-identity`, so a reverse dependency would
//!   be circular). A relay implementation performs `query_raw` + SCPR-decode
//!   (§9.10.12) and returns the decoded `(value, signature, seq)` triple as a
//!   [`RelayQueryRecord`](crate::resolution::RelayQueryRecord).
//! - [`MultiRelayQuerier`] — the MULTI-relay trait the
//!   [`DualLayerResolver`](crate::resolver::DualLayerResolver) composes. It takes
//!   a slice of relay URLs and returns the first valid record.
//!
//! Because [`RealMultiRelayQuerier`] needs only the `scp-identity`
//! `RelayQuerier` trait, [`did_routing_id`], and the local BEP44 / self-cert
//! helpers — all in this crate — the composer itself does NOT depend on
//! `scp-transport` (§3.10.12; resolution.rs:22-24/:86-89 establish this
//! abstraction).
//!
//! [`TransportRelayQuerier`]: https://docs.rs/scp-transport

use std::sync::Arc;

use tracing::warn;

use crate::IdentityError;
use crate::dht::{extract_public_key, verify_self_certification};
use crate::resolution::{RelayQuerier, did_routing_id};
use crate::resolver::{MultiRelayQuerier, RelayRecord};
use scp_dht::verify_bep44_signature;
use scp_did::DidDocument;

/// The production [`MultiRelayQuerier`] composer over any single-relay
/// [`RelayQuerier`] (§3.10.2, §3.10.4 step 3a).
///
/// Queries the provided relay URLs in priority order (identity's known relays
/// first, then bootstrap relays per §3.10.4) and returns the FIRST valid
/// record: one whose BEP44 signature verifies against the DID's Ed25519 key
/// (§9.6.1) AND whose embedded identity key self-certifies against the DID
/// suffix. Invalid records and per-relay errors are logged at WARN and skipped
/// (fall through to the next relay).
///
/// # Layering
///
/// This composer performs **no** cache read/write and **no** sequence-number
/// freshness check — the [`DualLayerResolver`](crate::resolver::DualLayerResolver)
/// owns cross-layer sequence arbitration, rollback rejection, and caching
/// (§3.10.4/§3.10.7). It verifies each record only to select the first VALID
/// one across the relay set; the resolver independently re-verifies the returned
/// record (defense in depth).
pub struct RealMultiRelayQuerier<Q: RelayQuerier> {
    /// The single-relay querier (production: `TransportRelayQuerier`).
    inner: Arc<Q>,
}

impl<Q: RelayQuerier> RealMultiRelayQuerier<Q> {
    /// Creates a composer over the given single-relay querier.
    #[must_use]
    pub const fn new(inner: Arc<Q>) -> Self {
        Self { inner }
    }
}

// Trait uses RPITIT with an explicit `+ Send` bound; `async fn` in trait does
// not guarantee `Send` futures, so a manual `impl Future` is required.
#[allow(clippy::manual_async_fn)]
impl<Q: RelayQuerier + 'static> MultiRelayQuerier for RealMultiRelayQuerier<Q> {
    fn query(
        &self,
        did: &str,
        relay_urls: &[String],
    ) -> impl Future<Output = Result<Option<RelayRecord>, IdentityError>> + Send {
        let inner = Arc::clone(&self.inner);
        let did = did.to_owned();
        let relay_urls = relay_urls.to_vec();

        async move {
            // Compute the routing ID and extract the DID's Ed25519 key once.
            // A malformed DID string is a caller error, propagated as `Err`.
            let routing_id = did_routing_id(&did);
            let public_key = extract_public_key(&did)?;

            for relay_url in &relay_urls {
                let record = match inner.query(relay_url, &routing_id).await {
                    Ok(Some(record)) => record,
                    Ok(None) => continue,
                    Err(e) => {
                        warn!(relay_url, did = %did, error = %e, "relay query failed");
                        continue;
                    }
                };

                // BEP44 signature verification (seq before value, per BEP44).
                if let Err(e) = verify_bep44_signature(
                    &public_key,
                    &record.signature,
                    &record.value,
                    record.seq,
                ) {
                    warn!(relay_url, did = %did, error = %e, "BEP44 signature verification failed");
                    continue;
                }

                // Deserialize + self-certify: the embedded identity key must
                // match the DID suffix (record substitution is impossible).
                let Ok(doc_json) = String::from_utf8(record.value.clone()) else {
                    warn!(relay_url, did = %did, "relay returned non-UTF8 blob");
                    continue;
                };
                let Ok(document) = DidDocument::from_json(&doc_json) else {
                    warn!(relay_url, did = %did, "relay returned invalid DID document JSON");
                    continue;
                };
                if let Err(e) = verify_self_certification(&did, &document) {
                    warn!(relay_url, did = %did, error = %e, "self-certification failed");
                    continue;
                }

                // First valid record wins. The resolver re-verifies and owns
                // sequence arbitration + caching.
                return Ok(Some(RelayRecord {
                    value: record.value,
                    signature: record.signature,
                    seq: record.seq,
                    relay_url: relay_url.clone(),
                }));
            }

            Ok(None)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::resolution::{InMemoryRelayQuerier, RelayQueryRecord};
    use scp_dht::bep44_signable;

    fn make_ed25519_keypair() -> (ed25519_dalek::VerifyingKey, ed25519_dalek::SigningKey) {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let verifying_key = signing_key.verifying_key();
        (verifying_key, signing_key)
    }

    fn did_from_public_key(public_key: &ed25519_dalek::VerifyingKey) -> String {
        format!("did:dht:z{}", zbase32::encode(public_key.as_bytes()))
    }

    fn signed_record(
        did: &str,
        identity_key: &[u8; 32],
        signing_key: &ed25519_dalek::SigningKey,
        seq: u64,
    ) -> RelayQueryRecord {
        let doc = DidDocument::new(did, identity_key, &[2u8; 32], &[3u8; 32]);
        let value = serde_json::to_vec(&doc).unwrap();
        let payload = bep44_signable(&value, seq);
        let signature: ed25519_dalek::Signature =
            ed25519_dalek::Signer::sign(signing_key, &payload);
        RelayQueryRecord {
            value,
            signature: signature.to_bytes(),
            seq,
        }
    }

    #[tokio::test]
    async fn returns_first_valid_record_with_relay_url() {
        let (vk, sk) = make_ed25519_keypair();
        let did = did_from_public_key(&vk);
        let routing_id = did_routing_id(&did);
        let record = signed_record(&did, vk.as_bytes(), &sk, 7);

        let inner = InMemoryRelayQuerier::new();
        inner
            .insert("wss://relay-b.example.com/scp/v1", &routing_id, record)
            .await;

        let composer = RealMultiRelayQuerier::new(Arc::new(inner));
        let result = composer
            .query(
                &did,
                &[
                    "wss://relay-a.example.com/scp/v1".to_owned(),
                    "wss://relay-b.example.com/scp/v1".to_owned(),
                ],
            )
            .await
            .unwrap();

        let record = result.expect("relay-b has a valid record");
        assert_eq!(record.seq, 7);
        assert_eq!(record.relay_url, "wss://relay-b.example.com/scp/v1");
    }

    #[tokio::test]
    async fn skips_invalid_signature_and_falls_through() {
        let (vk, sk) = make_ed25519_keypair();
        let did = did_from_public_key(&vk);
        let routing_id = did_routing_id(&did);

        let mut bad = signed_record(&did, vk.as_bytes(), &sk, 1);
        bad.signature[0] ^= 0xFF;
        let good = signed_record(&did, vk.as_bytes(), &sk, 1);

        let inner = InMemoryRelayQuerier::new();
        inner
            .insert("wss://relay-a.example.com/scp/v1", &routing_id, bad)
            .await;
        inner
            .insert("wss://relay-b.example.com/scp/v1", &routing_id, good)
            .await;

        let composer = RealMultiRelayQuerier::new(Arc::new(inner));
        let result = composer
            .query(
                &did,
                &[
                    "wss://relay-a.example.com/scp/v1".to_owned(),
                    "wss://relay-b.example.com/scp/v1".to_owned(),
                ],
            )
            .await
            .unwrap();

        assert_eq!(
            result.expect("relay-b valid").relay_url,
            "wss://relay-b.example.com/scp/v1"
        );
    }

    #[tokio::test]
    async fn rejects_wrong_identity_key_self_certification() {
        let (vk, sk) = make_ed25519_keypair();
        let did = did_from_public_key(&vk);
        let routing_id = did_routing_id(&did);

        // Signed correctly, but the embedded identity key does not match the DID.
        let record = signed_record(&did, &[0xFFu8; 32], &sk, 1);

        let inner = InMemoryRelayQuerier::new();
        inner
            .insert("wss://relay-a.example.com/scp/v1", &routing_id, record)
            .await;

        let composer = RealMultiRelayQuerier::new(Arc::new(inner));
        let result = composer
            .query(&did, &["wss://relay-a.example.com/scp/v1".to_owned()])
            .await
            .unwrap();

        assert!(result.is_none(), "self-certification failure => no record");
    }

    #[tokio::test]
    async fn empty_relay_list_returns_none() {
        let (vk, _sk) = make_ed25519_keypair();
        let did = did_from_public_key(&vk);
        let composer = RealMultiRelayQuerier::new(Arc::new(InMemoryRelayQuerier::new()));
        let result = composer.query(&did, &[]).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn invalid_did_is_error() {
        let composer = RealMultiRelayQuerier::new(Arc::new(InMemoryRelayQuerier::new()));
        let result = composer
            .query("not-a-did", &["wss://relay.example.com/scp/v1".to_owned()])
            .await;
        assert!(result.is_err());
    }
}
