//! Production single-relay [`RelayQuerier`] over a live transport (§3.10.2,
//! §3.10.4) — the READ half of Model B relay DID resolution.
//!
//! [`TransportRelayQuerier`] is the concrete, non-test implementation of the
//! `scp-identity` [`RelayQuerier`] trait. It lives in `scp-transport` (not
//! `scp-identity`) because only this crate can talk to a relay: `scp-transport`
//! depends on `scp-identity`, so a relay-talking `RelayQuerier` in `scp-identity`
//! would be a circular dependency (`scp-identity::resolution` module docs).
//!
//! # What it does
//!
//! Given a `relay_url` and a DID `routing_id`, it performs the relay QUERY via
//! the transport's raw-blob path
//! ([`query_raw`](crate::traits::TransportAdapter::query_raw)) with
//! `limit = N` (N = 16, §3.10.2), decodes each returned blob as a
//! [`DidRecordV1`](scp_protocol::envelope::did_record::DidRecordV1) frame
//! (SCP-RELAYRES-001), **discards** any blob that fails to decode (§3.10.4 —
//! "relay blob fails frame decoding" falls through, never partially parsed),
//! and returns the surviving `(value, signature, seq)` triples as
//! [`RelayQueryRecord`]s.
//!
//! # Decode is not verify (§9.10.12 rule 4)
//!
//! This querier performs the **decode** half only. It does NOT verify BEP44
//! signatures and it **discards the frame's `public_key`** — the frame field is
//! for a validating relay's benefit and is never a client trust input. The
//! composer
//! ([`RealMultiRelayQuerier`](scp_identity::RealMultiRelayQuerier)) re-verifies
//! every candidate against the key it derives from the DID string itself and
//! selects the highest-seq valid one. Keeping decode here and verify there is
//! the single decode-and-verify discipline the spec mandates.
//!
//! # Late binding (fail-closed)
//!
//! DID resolvers are constructed at FFI init, before any relay connection
//! exists, so the transport is bound **after** the querier is built via
//! [`bind`](TransportRelayQuerier::bind). A query for an unbound relay URL
//! returns [`IdentityError::RelayNotConnected`] — a typed error, never an empty
//! candidate list, because an empty list asserts that the relay answered and
//! holds nothing, which this querier cannot claim about a relay it never
//! reached. The composer skips the relay and, when no relay answers, reports the
//! whole relay layer unavailable (§3.10.4). No lock is ever held across an
//! `.await`: the adapter handle is cloned out under a short synchronous lock,
//! which is then dropped before the query future runs.
//!
//! # Bootstrap relay set
//!
//! [`bound_relay_urls`](TransportRelayQuerier::bound_relay_urls) returns the
//! relay URLs with a live binding, and the
//! [`BootstrapRelays`](scp_identity::BootstrapRelays) impl exposes it to the
//! resolver. The resolver reads it on every resolve, so a relay connected after
//! the resolver was built is reachable (§3.10.4 step 3a, §18.5.1 priority 1).

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use scp_identity::IdentityError;
use scp_identity::relay_querier::MAX_CANDIDATES_PER_RELAY;
use scp_identity::resolution::{RelayQuerier, RelayQueryRecord};
use scp_protocol::envelope::did_record::DidRecordV1;
use tracing::debug;

use crate::traits::{RoutingId, TransportAdapter};

/// Production [`RelayQuerier`] that resolves DID records over a live transport.
///
/// Holds a per-instance, late-bound map of `relay_url -> adapter`. Bindings are
/// added as relay connections are established (see the module docs) and can be
/// removed on disconnect. A query for an unbound relay URL fails closed with an
/// empty candidate list.
#[derive(Default)]
pub struct TransportRelayQuerier {
    /// Late-bound live transports, keyed by relay URL. Guarded by a synchronous
    /// `RwLock` because every access is a brief clone-out; the lock is never
    /// held across an `.await` (see the module docs).
    relays: RwLock<HashMap<String, Arc<dyn TransportAdapter>>>,
}

impl std::fmt::Debug for TransportRelayQuerier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bound = self.relays.read().map_or(0, |m| m.len());
        f.debug_struct("TransportRelayQuerier")
            .field("bound_relays", &bound)
            .finish()
    }
}

impl TransportRelayQuerier {
    /// Creates a querier with no bound transports. Bind relays via
    /// [`bind`](Self::bind) once connections are established.
    #[must_use]
    pub fn new() -> Self {
        Self {
            relays: RwLock::new(HashMap::new()),
        }
    }

    /// Late-binds a live transport adapter for a relay URL.
    ///
    /// Idempotent: a subsequent bind for the same URL replaces the prior
    /// adapter. A poisoned lock is treated as "no binding possible" and the call
    /// is a no-op (a query for the URL then fails closed).
    pub fn bind(&self, relay_url: impl Into<String>, adapter: Arc<dyn TransportAdapter>) {
        if let Ok(mut relays) = self.relays.write() {
            relays.insert(relay_url.into(), adapter);
        }
    }

    /// Removes the binding for a relay URL (e.g. on disconnect). Absent bindings
    /// are ignored.
    pub fn unbind(&self, relay_url: &str) {
        if let Ok(mut relays) = self.relays.write() {
            relays.remove(relay_url);
        }
    }

    /// Returns the adapter bound for `relay_url`, cloned out under a short
    /// synchronous lock so the guard never crosses an `.await`.
    fn adapter_for(&self, relay_url: &str) -> Option<Arc<dyn TransportAdapter>> {
        self.relays.read().ok()?.get(relay_url).cloned()
    }

    /// Returns every relay URL that currently has a bound transport.
    ///
    /// This is the resolver's bootstrap relay set (spec §18.5.1 priority 1 —
    /// the relays the caller explicitly configured and this instance connected).
    /// A poisoned lock yields an empty list, which the composer reports as a
    /// relay layer that could not answer.
    #[must_use]
    pub fn bound_relay_urls(&self) -> Vec<String> {
        self.relays
            .read()
            .map(|relays| relays.keys().cloned().collect())
            .unwrap_or_default()
    }
}

/// Supplies the resolver's bootstrap relay set from the live bindings.
///
/// A bridge builds its DID resolver at FFI init, before it connects any relay,
/// and binds each relay into this querier as `transport_connect` establishes it.
/// Reading the bound set on every resolve — rather than capturing a list at
/// resolver-construction time — is what makes a relay connected after init
/// reachable to the resolver (§3.10.4 step 3a).
impl scp_identity::BootstrapRelays for TransportRelayQuerier {
    fn bootstrap_relay_urls(&self) -> Vec<String> {
        self.bound_relay_urls()
    }
}

// The `RelayQuerier` trait uses RPITIT with an explicit `+ Send` bound; an
// `async fn` in a trait does not guarantee a `Send` future, so a manual
// `impl Future` is required (matching `InMemoryRelayQuerier`).
#[allow(clippy::manual_async_fn)]
impl RelayQuerier for TransportRelayQuerier {
    fn query(
        &self,
        relay_url: &str,
        routing_id: &[u8; 32],
    ) -> impl Future<Output = Result<Vec<RelayQueryRecord>, IdentityError>> + Send {
        // Resolve the adapter synchronously and drop the lock before any await.
        let adapter = self.adapter_for(relay_url);
        let routing_id = *routing_id;
        let relay_url = relay_url.to_owned();

        async move {
            let Some(adapter) = adapter else {
                // Fail-closed with a TYPED error, never an empty candidate list.
                // An empty list would tell the composer "this relay answered and
                // holds nothing", which is a claim this querier cannot make about
                // a relay it never reached (§3.10.4). The composer skips this
                // relay and, if no relay answers, reports the whole layer
                // unavailable.
                debug!(
                    relay_url = %relay_url,
                    "TransportRelayQuerier: no live transport bound — reporting the relay unreachable"
                );
                return Err(IdentityError::RelayNotConnected(relay_url));
            };

            // QUERY limit N = 16 (§3.10.2), the one canonical N.
            let limit = u32::try_from(MAX_CANDIDATES_PER_RELAY).unwrap_or(u32::MAX);

            let blobs = adapter
                .query_raw(&RoutingId::new(routing_id), None, limit)
                .await
                .map_err(|e| IdentityError::RelayQueryFailed(e.to_string()))?;

            let mut records = Vec::with_capacity(blobs.len().min(MAX_CANDIDATES_PER_RELAY));
            for blob in blobs {
                match DidRecordV1::decode(&blob) {
                    Ok(frame) => {
                        // Single decode-and-verify discipline (§9.10.12 rule 4):
                        // keep only the BEP44 `(value, signature, seq)` triple
                        // and DISCARD `frame.public_key()` — the composer
                        // re-verifies against the DID-derived key; the frame key
                        // is never trusted.
                        records.push(RelayQueryRecord {
                            value: frame.value().to_vec(),
                            signature: *frame.signature(),
                            seq: frame.seq(),
                        });
                    }
                    Err(e) => {
                        // Undecodable blob: discard, never partially parse
                        // (§3.10.4). A non-frame or malformed blob is simply not
                        // a candidate DID record.
                        debug!(
                            relay_url = %relay_url,
                            error = %e,
                            "TransportRelayQuerier: discarding undecodable DID-record blob (§3.10.4)"
                        );
                    }
                }
            }
            Ok(records)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
    use scp_dht::bep44_signable;
    use scp_did::{DidDocument, did_dht_from_public_key};
    use scp_identity::RealMultiRelayQuerier;
    use scp_identity::resolver::MultiRelayQuerier;

    use crate::error::TransportError;
    use crate::traits::{BlobId, SubscriptionStream};

    // ------------------------------------------------------------------
    // Mock adapter: only `query_raw` is meaningful; every other method is an
    // honest "not connected" (never a fabricated success). Returns a preset
    // list of raw blobs for ANY routing_id, on every call (so repeat-query
    // behavior can be asserted).
    // ------------------------------------------------------------------
    struct MockRawAdapter {
        blobs: Vec<Vec<u8>>,
    }

    impl MockRawAdapter {
        fn new(blobs: Vec<Vec<u8>>) -> Self {
            Self { blobs }
        }
    }

    type BoxFut<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

    impl TransportAdapter for MockRawAdapter {
        fn send(
            &self,
            _envelope: &scp_core::envelope::OuterEnvelope,
        ) -> BoxFut<'_, Result<BlobId, TransportError>> {
            Box::pin(async { Err(TransportError::NotConnected) })
        }

        fn subscribe(
            &self,
            _routing_id: &RoutingId,
            _since: Option<u64>,
        ) -> BoxFut<'_, Result<SubscriptionStream, TransportError>> {
            Box::pin(async { Err(TransportError::NotConnected) })
        }

        fn unsubscribe(&self, _routing_id: &RoutingId) -> BoxFut<'_, Result<(), TransportError>> {
            Box::pin(async { Ok(()) })
        }

        fn query(
            &self,
            _routing_id: &RoutingId,
            _since: Option<u64>,
        ) -> BoxFut<'_, Result<Vec<scp_core::envelope::OuterEnvelope>, TransportError>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn delete(&self, _blob_id: &BlobId) -> BoxFut<'_, Result<(), TransportError>> {
            Box::pin(async { Ok(()) })
        }

        fn query_raw(
            &self,
            _routing_id: &RoutingId,
            _since: Option<u64>,
            limit: u32,
        ) -> BoxFut<'_, Result<Vec<Vec<u8>>, TransportError>> {
            let out: Vec<Vec<u8>> = self.blobs.iter().take(limit as usize).cloned().collect();
            Box::pin(async move { Ok(out) })
        }
    }

    const RELAY: &str = "wss://relay-a.example.com/scp/v1";

    fn keypair(seed: u8) -> (VerifyingKey, SigningKey) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        (sk.verifying_key(), sk)
    }

    fn did_of(vk: &VerifyingKey) -> String {
        did_dht_from_public_key(vk.as_bytes()).to_string()
    }

    /// Builds a signed DID-record frame's raw bytes.
    ///
    /// `identity_key` is the key embedded in the DID document body (self-cert);
    /// `signing_key` produces the BEP44 signature; `frame_public_key` is the
    /// frame's own `public_key` field — deliberately separable from the signing
    /// key so the "frame key is never trusted" property can be exercised.
    fn frame_bytes(
        did: &str,
        identity_key: &[u8; 32],
        signing_key: &SigningKey,
        frame_public_key: [u8; 32],
        seq: u64,
    ) -> Vec<u8> {
        let doc = DidDocument::new(did, identity_key, &[2u8; 32], &[3u8; 32]);
        let value = serde_json::to_vec(&doc).unwrap();
        let payload = bep44_signable(&value, seq);
        let signature: ed25519_dalek::Signature = signing_key.sign(&payload);
        DidRecordV1::try_new(frame_public_key, seq, signature.to_bytes(), value)
            .unwrap()
            .encode()
    }

    fn routing_id_of(did: &str) -> [u8; 32] {
        scp_identity::did_routing_id(did)
    }

    // ------------------------------------------------------------------
    // AC 2 / AC 3: decode + return all candidates, discard undecodable.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn decodes_all_candidates_and_discards_undecodable() {
        let (vk, sk) = keypair(7);
        let did = did_of(&vk);
        let rid = routing_id_of(&did);

        // Two decodable frames (seq 1 and 2) plus two undecodable blobs that
        // exercise BOTH discard paths (§3.10.4 "never partially parsed"):
        //   - `wrong_version`: first byte 0x00 != version 0x01 -> UnknownVersion
        //     (rejected at the version gate).
        //   - `truncated`: correct version 0x01 but shorter than the 105-byte
        //     fixed prefix -> Truncated (rejected in the body, the path a
        //     version-only-wrong fixture never reaches).
        let f1 = frame_bytes(&did, vk.as_bytes(), &sk, *vk.as_bytes(), 1);
        let wrong_version = vec![0x00, 0x01, 0x02, 0x03];
        let truncated = vec![0x01, 0xDE, 0xAD, 0xBE, 0xEF];
        let f2 = frame_bytes(&did, vk.as_bytes(), &sk, *vk.as_bytes(), 2);

        let querier = TransportRelayQuerier::new();
        querier.bind(
            RELAY,
            Arc::new(MockRawAdapter::new(vec![f1, wrong_version, truncated, f2])),
        );

        let records = RelayQuerier::query(&querier, RELAY, &rid).await.unwrap();

        assert_eq!(
            records.len(),
            2,
            "only the two decodable frames survive; both the wrong-version and \
             the correct-version-but-truncated blobs are discarded"
        );
        let seqs: Vec<u64> = records.iter().map(|r| r.seq).collect();
        assert!(seqs.contains(&1) && seqs.contains(&2));
    }

    /// The QUERY is bounded to `MAX_CANDIDATES_PER_RELAY` (N = 16, §3.10.2): the
    /// querier passes `limit = 16` to `query_raw`, so even when a relay holds far
    /// more co-located candidates, at most 16 are retrieved and decoded. This is
    /// the bound the composer docstrings call load-bearing against an
    /// unbounded-verification `DoS`.
    #[tokio::test]
    async fn caps_candidates_at_max_per_relay() {
        let (vk, sk) = keypair(13);
        let did = did_of(&vk);
        let rid = routing_id_of(&did);

        // 20 decodable frames co-located at one routing_id (> N = 16). The mock
        // honors the `limit` the querier passes (as a real relay's QUERY does),
        // so the querier must request exactly N.
        let frames: Vec<Vec<u8>> = (0..20u64)
            .map(|seq| frame_bytes(&did, vk.as_bytes(), &sk, *vk.as_bytes(), seq + 1))
            .collect();

        let querier = TransportRelayQuerier::new();
        querier.bind(RELAY, Arc::new(MockRawAdapter::new(frames)));

        let records = RelayQuerier::query(&querier, RELAY, &rid).await.unwrap();
        assert_eq!(
            records.len(),
            MAX_CANDIDATES_PER_RELAY,
            "querier must bound the QUERY to N = {MAX_CANDIDATES_PER_RELAY} candidates"
        );
    }

    // The former `unbound_relay_fails_closed_empty` asserted that an unbound
    // relay yields an EMPTY candidate list. That outcome is indistinguishable
    // from "the relay answered and holds no record", which this querier cannot
    // claim about a relay it never reached (§3.10.4). The stronger replacement
    // is `unbound_relay_reports_not_connected_rather_than_no_candidates` below,
    // which pins the typed `RelayNotConnected` error.

    // ------------------------------------------------------------------
    // AC 5 (querier/composer selection half): a genuine highest-seq record
    // co-located with a stale-valid record AND an undecodable blob resolves to
    // the genuine one — every time it is queried.
    //
    // NOTE: this proves the querier + composer are STATELESS across calls (the
    // decode/discard + highest-seq-valid selection is recomputed each call), NOT
    // the client-side dedup-bypass property. `MockRawAdapter` is stateless and
    // the real `NativeRelayClient` (which owns the `seen_blob_ids` LRU) is never
    // in this path. The actual dedup-bypass is proven by the client-level
    // `raw_query_subscription_bypasses_dedup_on_repeat` (dispatch) and the
    // end-to-end `query_raw_twice_same_did_returns_record_both_times` (real
    // relay) tests in `native::client`.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn genuine_selected_among_stale_and_junk_on_every_query() {
        let (vk, sk) = keypair(11);
        let did = did_of(&vk);

        let stale = frame_bytes(&did, vk.as_bytes(), &sk, *vk.as_bytes(), 2);
        let junk = vec![0x02, 0xAA, 0xBB]; // wrong version -> undecodable
        let genuine = frame_bytes(&did, vk.as_bytes(), &sk, *vk.as_bytes(), 9);

        let querier = Arc::new(TransportRelayQuerier::new());
        querier.bind(
            RELAY,
            Arc::new(MockRawAdapter::new(vec![stale, junk, genuine])),
        );

        let composer = RealMultiRelayQuerier::new(querier);

        // First resolution.
        let first = composer
            .query(&did, &[RELAY.to_owned()])
            .await
            .unwrap()
            .expect("genuine record resolves");
        assert_eq!(
            first.seq, 9,
            "genuine highest-seq must win over stale seq=2"
        );

        // A second resolution of the same unchanged DID recomputes selection
        // from scratch and returns the same genuine record — the querier and
        // composer hold no cross-call state that could drop it.
        let second = composer
            .query(&did, &[RELAY.to_owned()])
            .await
            .unwrap()
            .expect("genuine record still resolves on the second query");
        assert_eq!(second.seq, 9, "second query must still return the record");
    }

    // ------------------------------------------------------------------
    // AC 6: client re-verification against the DID-derived key; the frame's
    // public_key is never trusted.
    // ------------------------------------------------------------------

    /// A frame carrying a MISMATCHED `public_key` whose BEP44 triple still
    /// verifies against the DID-derived key is ACCEPTED — the resolver ignores
    /// the frame key (§9.10.12 "framing is outside the signed authority").
    #[tokio::test]
    async fn mismatched_frame_public_key_but_valid_triple_is_accepted() {
        let (vk, sk) = keypair(21);
        let did = did_of(&vk);

        // Sign with the real DID key, but set the frame's public_key to junk.
        let frame = frame_bytes(&did, vk.as_bytes(), &sk, [0xFF; 32], 4);

        let querier = Arc::new(TransportRelayQuerier::new());
        querier.bind(RELAY, Arc::new(MockRawAdapter::new(vec![frame])));

        let composer = RealMultiRelayQuerier::new(querier);
        let record = composer
            .query(&did, &[RELAY.to_owned()])
            .await
            .unwrap()
            .expect("valid triple must resolve despite a mismatched frame public_key");
        assert_eq!(record.seq, 4);
    }

    /// A frame whose triple only verifies against its OWN embedded key (signed
    /// by a different key than the DID's) is REJECTED — the resolver verifies
    /// against the DID-derived key, not the frame key.
    #[tokio::test]
    async fn frame_valid_only_against_embedded_key_is_rejected() {
        let (vk_a, _sk_a) = keypair(31); // the DID being resolved
        let (vk_b, sk_b) = keypair(32); // an attacker's key
        let did_a = did_of(&vk_a);

        // Signed by B, frame public_key = B, document identity key = B. The
        // triple verifies against B's key — but NOT against A's DID-derived key.
        let frame = frame_bytes(&did_a, vk_b.as_bytes(), &sk_b, *vk_b.as_bytes(), 4);

        let querier = Arc::new(TransportRelayQuerier::new());
        querier.bind(RELAY, Arc::new(MockRawAdapter::new(vec![frame])));

        let composer = RealMultiRelayQuerier::new(querier);
        let result = composer.query(&did_a, &[RELAY.to_owned()]).await.unwrap();
        assert!(
            result.is_none(),
            "a frame that verifies only against its embedded key must be rejected"
        );
    }

    // ------------------------------------------------------------------
    // Transport error surfaces as a soft relay failure (fall-through).
    // ------------------------------------------------------------------

    struct ErroringAdapter;

    impl TransportAdapter for ErroringAdapter {
        fn send(
            &self,
            _envelope: &scp_core::envelope::OuterEnvelope,
        ) -> BoxFut<'_, Result<BlobId, TransportError>> {
            Box::pin(async { Err(TransportError::NotConnected) })
        }
        fn subscribe(
            &self,
            _routing_id: &RoutingId,
            _since: Option<u64>,
        ) -> BoxFut<'_, Result<SubscriptionStream, TransportError>> {
            Box::pin(async { Err(TransportError::NotConnected) })
        }
        fn unsubscribe(&self, _routing_id: &RoutingId) -> BoxFut<'_, Result<(), TransportError>> {
            Box::pin(async { Ok(()) })
        }
        fn query(
            &self,
            _routing_id: &RoutingId,
            _since: Option<u64>,
        ) -> BoxFut<'_, Result<Vec<scp_core::envelope::OuterEnvelope>, TransportError>> {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn delete(&self, _blob_id: &BlobId) -> BoxFut<'_, Result<(), TransportError>> {
            Box::pin(async { Ok(()) })
        }
        fn query_raw(
            &self,
            _routing_id: &RoutingId,
            _since: Option<u64>,
            _limit: u32,
        ) -> BoxFut<'_, Result<Vec<Vec<u8>>, TransportError>> {
            Box::pin(async { Err(TransportError::Timeout) })
        }
    }

    #[tokio::test]
    async fn query_raw_transport_error_maps_to_relay_query_failed() {
        let (vk, _sk) = keypair(41);
        let did = did_of(&vk);
        let rid = routing_id_of(&did);

        let querier = TransportRelayQuerier::new();
        querier.bind(RELAY, Arc::new(ErroringAdapter));

        let result = RelayQuerier::query(&querier, RELAY, &rid).await;
        assert!(matches!(result, Err(IdentityError::RelayQueryFailed(_))));
    }

    /// An unbound relay URL yields a TYPED error, never an empty candidate list.
    ///
    /// An empty list would tell the composer "this relay answered and holds
    /// nothing", which this querier cannot claim about a relay it never reached
    /// (§3.10.4).
    #[tokio::test]
    async fn unbound_relay_reports_not_connected_rather_than_no_candidates() {
        let (vk, _sk) = keypair(42);
        let did = did_of(&vk);
        let rid = routing_id_of(&did);

        let querier = TransportRelayQuerier::new();

        let result = RelayQuerier::query(&querier, RELAY, &rid).await;
        match result {
            Err(IdentityError::RelayNotConnected(url)) => assert_eq!(url, RELAY),
            other => panic!("an unbound relay must report RelayNotConnected, got {other:?}"),
        }
    }

    /// With no relay bound anywhere, the composer reports the relay layer as
    /// unable to answer, not as a relay set that holds no record.
    #[tokio::test]
    async fn composer_errors_when_every_relay_is_unreachable() {
        let (vk, _sk) = keypair(43);
        let did = did_of(&vk);

        let querier = Arc::new(TransportRelayQuerier::new());
        let composer = RealMultiRelayQuerier::new(querier);

        let result = composer.query(&did, &[RELAY.to_owned()]).await;
        assert!(
            matches!(result, Err(IdentityError::RelayQueryFailed(_))),
            "every relay failing must surface as an error, not Ok(None)"
        );
    }

    /// An empty relay URL list is "no relay is available to ask", not "the
    /// relays hold no record".
    #[tokio::test]
    async fn composer_errors_when_no_relay_url_is_available() {
        let (vk, _sk) = keypair(44);
        let did = did_of(&vk);

        let querier = Arc::new(TransportRelayQuerier::new());
        let composer = RealMultiRelayQuerier::new(querier);

        let result = composer.query(&did, &[]).await;
        assert!(
            matches!(result, Err(IdentityError::RelayNotConnected(_))),
            "an empty relay list must surface as an error, not Ok(None)"
        );
    }

    /// `bound_relay_urls` reports exactly the relays with a live binding, which
    /// is the bootstrap relay set the resolver reads on every resolve
    /// (§3.10.4 step 3a, §18.5.1 priority 1).
    #[test]
    fn bound_relay_urls_tracks_bind_and_unbind() {
        use scp_identity::BootstrapRelays;

        let querier = TransportRelayQuerier::new();
        assert!(querier.bound_relay_urls().is_empty());

        querier.bind(RELAY, Arc::new(MockRawAdapter::new(Vec::new())));
        assert_eq!(querier.bound_relay_urls(), vec![RELAY.to_owned()]);
        assert_eq!(querier.bootstrap_relay_urls(), vec![RELAY.to_owned()]);

        querier.unbind(RELAY);
        assert!(querier.bound_relay_urls().is_empty());
        assert!(querier.bootstrap_relay_urls().is_empty());
    }
}
