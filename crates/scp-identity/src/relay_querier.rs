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
//! - [`MultiRelayQuerier`](crate::resolver::MultiRelayQuerier) — the MULTI-relay
//!   trait the [`DualLayerResolver`](crate::resolver::DualLayerResolver) composes.
//!   It takes a slice of relay URLs and returns the first valid record.
//!
//! Because [`RealMultiRelayQuerier`] needs only the `scp-identity`
//! `RelayQuerier` trait, [`did_routing_id`](crate::resolution::did_routing_id),
//! and the local BEP44 / self-cert helpers — all in this crate — the composer
//! itself does NOT depend on `scp-transport` (§3.10.12;
//! `resolution.rs` §3.10.4 establishes this abstraction).
//!
//! [`TransportRelayQuerier`]: https://docs.rs/scp-transport

use std::sync::Arc;

use tracing::warn;

use crate::IdentityError;
use crate::dht::extract_public_key;
use crate::resolution::{RelayQuerier, did_routing_id, verify_relay_record};
use crate::resolver::{MultiRelayQuerier, RelayRecord};

/// The production [`MultiRelayQuerier`] composer over any single-relay
/// [`RelayQuerier`] (§3.10.2, §3.10.4 step 3a).
///
/// Queries the provided relay URLs in priority order (identity's known relays
/// first, then bootstrap relays per §3.10.4). For each relay it fetches **all**
/// decodable candidates (the `Vec` [`RelayQuerier`] contract) and returns the
/// FIRST valid one: a record whose BEP44 signature verifies against the DID's
/// Ed25519 key (§9.6.1) AND whose embedded identity key self-certifies against
/// the DID suffix. Invalid candidates are logged at WARN and skipped — WITHIN a
/// relay's candidate list AND across relays.
///
/// # Shadow-defeat (intra-relay suppression, §3.10.8)
///
/// Iterating *every* candidate at a routing ID — not just the first decodable
/// one — is load-bearing. A decodable-but-bad-signature frame co-located before
/// the genuine record must not shadow it; since raw publish is unauthenticated
/// and the routing ID is DID-derivable, an attacker could otherwise plant one
/// well-framed bad-signature blob to permanently suppress relay resolution.
///
/// # Layering
///
/// This composer performs **no** cache read/write and **no** sequence-number
/// freshness check — the [`DualLayerResolver`](crate::resolver::DualLayerResolver)
/// owns cross-layer sequence arbitration, rollback rejection, and caching
/// (§3.10.4/§3.10.7). It verifies each record only to select the first VALID
/// one; the resolver independently re-verifies the returned record (defense in
/// depth), via the same shared [`verify_relay_record`] path.
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
                // Fetch EVERY decodable candidate at this routing ID (the `Vec`
                // contract) so a bad-signature frame co-located before the
                // genuine record cannot shadow it.
                let candidates = match inner.query(relay_url, &routing_id).await {
                    Ok(candidates) => candidates,
                    Err(e) => {
                        warn!(relay_url, did = %did, error = %e, "relay query failed");
                        continue;
                    }
                };

                for record in candidates {
                    // Shared verify: BEP44 signature + UTF-8/JSON + self-cert.
                    // The embedded identity key must match the DID suffix, so
                    // record substitution is cryptographically impossible.
                    if let Err(e) = verify_relay_record(
                        &did,
                        &public_key,
                        &record.value,
                        &record.signature,
                        record.seq,
                    ) {
                        warn!(relay_url, did = %did, error = %e, "relay candidate failed verification — skipping");
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
    use scp_did::DidDocument;

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

    /// Returns the first valid record when relay-b has it and relay-a has none.
    /// The `relay_url` field in the returned record matches the serving relay.
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

    /// Shadow-defeat across relays: relay-a has a bad signature, relay-b has
    /// a valid record at the same routing ID — the composer returns relay-b's
    /// valid record instead of shadowing it with relay-a's bad one.
    #[tokio::test]
    async fn skips_invalid_signature_falls_through_to_next_candidate() {
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

    /// Intra-relay shadow-defeat (§3.10.8): a decodable but bad-signature frame
    /// co-located FIRST at the SAME `routing_id` on the SAME relay must NOT shadow
    /// the valid frame stored after it. The composer must iterate every candidate
    /// and still return the valid record — otherwise an attacker planting one
    /// well-framed bad-signature blob (raw publish is unauthenticated, the
    /// `routing_id` is DID-derivable) permanently suppresses relay resolution.
    #[tokio::test]
    async fn skips_bad_candidate_colocated_before_valid_at_same_relay() {
        let (vk, sk) = make_ed25519_keypair();
        let did = did_from_public_key(&vk);
        let routing_id = did_routing_id(&did);

        let mut bad = signed_record(&did, vk.as_bytes(), &sk, 3);
        bad.signature[0] ^= 0xFF; // decodes, but signature fails to verify
        let good = signed_record(&did, vk.as_bytes(), &sk, 3);

        let inner = InMemoryRelayQuerier::new();
        // Bad FIRST, valid SECOND — both at the SAME (relay_url, routing_id).
        inner
            .insert("wss://relay-a.example.com/scp/v1", &routing_id, bad)
            .await;
        inner
            .insert("wss://relay-a.example.com/scp/v1", &routing_id, good)
            .await;

        let composer = RealMultiRelayQuerier::new(Arc::new(inner));
        let result = composer
            .query(&did, &["wss://relay-a.example.com/scp/v1".to_owned()])
            .await
            .unwrap();

        let record = result.expect("valid co-located record must still resolve");
        assert_eq!(record.seq, 3);
        assert_eq!(record.relay_url, "wss://relay-a.example.com/scp/v1");
    }

    /// Self-certification failure: a record signed with the correct key but
    /// containing a mismatched identity key in the document body is rejected.
    #[tokio::test]
    async fn skips_bad_self_certification() {
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

    /// An empty relay list returns `Ok(None)` immediately without querying.
    #[tokio::test]
    async fn empty_relay_list_returns_none() {
        let (vk, _sk) = make_ed25519_keypair();
        let did = did_from_public_key(&vk);
        let composer = RealMultiRelayQuerier::new(Arc::new(InMemoryRelayQuerier::new()));
        let result = composer.query(&did, &[]).await.unwrap();
        assert!(result.is_none());
    }

    /// A malformed DID string (not `did:dht:z...`) returns `Err` immediately.
    #[tokio::test]
    async fn invalid_did_is_error() {
        let composer = RealMultiRelayQuerier::new(Arc::new(InMemoryRelayQuerier::new()));
        let result = composer
            .query("not-a-did", &["wss://relay.example.com/scp/v1".to_owned()])
            .await;
        assert!(result.is_err());
    }
}
