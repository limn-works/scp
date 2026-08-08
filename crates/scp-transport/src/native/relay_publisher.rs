//! Production [`RelayPublisher`] over a live transport (§3.10.2, §3.10.5) — the
//! WRITE half of Model B relay DID resolution (SCP-RELAYRES-004).
//!
//! [`TransportRelayPublisher`] is the concrete, non-test implementation of the
//! `scp-identity` [`RelayPublisher`]
//! trait. It lives in `scp-transport` (not `scp-identity`) because only this
//! crate can talk to a relay: `scp-transport` depends on `scp-identity`, so a
//! relay-talking publisher in `scp-identity` would be a circular dependency
//! (mirrors [`TransportRelayQuerier`](crate::native::TransportRelayQuerier), the
//! READ counterpart).
//!
//! # What it does
//!
//! Given a bound set of relays, it
//! [`encode`](scp_protocol::envelope::did_record::DidRecordV1::encode)s the
//! caller-supplied [`DidRecordV1`] frame (§9.10.12) — which carries the full
//! BEP44 `(public_key, seq, signature, value)` — into its canonical bytes and
//! publishes those bytes, at the routing ID the frame's own key binds to, via
//! the transport's raw-blob path
//! ([`publish_raw`](crate::traits::TransportAdapter::publish_raw)) to every
//! bound relay (own relays + bootstrap relays, §3.10.2 / §18.5.1).
//!
//! Neither the blob nor the address is a free parameter — see the
//! [`RelayPublisher`] trait docs for
//! the authoritative statement of that contract.
//!
//! # Late binding, fail-closed, and partial reach
//!
//! Transports are bound **after** construction via
//! [`bind`](TransportRelayPublisher::bind) (see
//! `BoundRelays`). A publish with **no** relay
//! bound, or one that every bound relay rejects, **fails closed** with a typed
//! [`IdentityError::RelayPublishFailed`]: an unconnected publisher never reports
//! a phantom success, so the republish loop's backoff + degraded-warning path
//! (§3.10.6) engages honestly.
//!
//! A publish that reaches at least one relay succeeds — one relay accepting
//! makes the record resolvable — but the result reports **how many** of the
//! attempted relays accepted. Collapsing a partial accept to a plain success
//! would hand an attacker who controls one relay of N permanent, silent
//! suppression on that relay (§3.10.8): resolvers consulting it would never see
//! the record while the publisher saw nothing wrong. Per-relay rejections are
//! additionally logged at `warn` naming the relay URL.

use std::sync::Arc;

use scp_identity::IdentityError;
use scp_identity::republish::{RelayPublishOutcome, RelayPublisher};
use scp_protocol::envelope::did_record::DidRecordV1;
use tracing::{debug, warn};

use crate::native::BoundRelays;
use crate::traits::{RoutingId, TransportAdapter};

/// Production [`RelayPublisher`] that publishes DID-record frames over a live
/// transport.
///
/// A thin newtype over the shared late-bound
/// `BoundRelays` set (the READ-half
/// [`TransportRelayQuerier`](crate::native::TransportRelayQuerier) is the same
/// shape over the same type). A publish with no bound relay — or one every bound
/// relay rejects — fails closed (see the module docs).
#[derive(Debug, Default)]
pub struct TransportRelayPublisher {
    relays: BoundRelays,
}

impl TransportRelayPublisher {
    /// Creates a publisher with no bound transports. Bind relays via
    /// [`bind`](Self::bind) once connections are established.
    #[must_use]
    pub fn new() -> Self {
        Self {
            relays: BoundRelays::new(),
        }
    }

    /// Late-binds a live transport adapter for a relay URL.
    ///
    /// Idempotent: a subsequent bind for the same URL replaces the prior
    /// adapter.
    pub fn bind(&self, relay_url: impl Into<String>, adapter: Arc<dyn TransportAdapter>) {
        self.relays.bind(relay_url, adapter);
    }

    /// Removes the binding for a relay URL (e.g. on disconnect). Absent
    /// bindings are ignored.
    pub fn unbind(&self, relay_url: &str) {
        self.relays.unbind(relay_url);
    }
}

// The `RelayPublisher` trait uses RPITIT with an explicit `+ Send` bound; an
// `async fn` in a trait does not guarantee a `Send` future, so a manual
// `impl Future` is required (matching `InMemoryRelayPublisher` / the querier).
#[allow(clippy::manual_async_fn)]
impl RelayPublisher for TransportRelayPublisher {
    fn publish(
        &self,
        blob_ttl_secs: u64,
        record: &DidRecordV1,
    ) -> impl Future<Output = Result<RelayPublishOutcome, IdentityError>> + Send {
        // The one place the record becomes wire bytes, and the one place its
        // address is chosen — both via the shared derivations, so this write
        // path and the relay ADMISSION check cannot drift.
        let blob = record.encode();
        let routing_id = RoutingId::new(scp_identity::did_record_routing_id(record));
        // Resolve the bound adapters synchronously and drop the lock before await.
        let adapters = self.relays.snapshot();

        async move {
            if adapters.is_empty() {
                // Fail-closed: nothing to publish to. An unconnected publisher
                // never reports a phantom success (§3.10.6 republish backoff
                // relies on an honest error here).
                return Err(IdentityError::RelayPublishFailed(
                    "TransportRelayPublisher: no relay bound — cannot publish DID record"
                        .to_string(),
                ));
            }

            let attempted = adapters.len();
            let mut accepted = 0usize;
            let mut last_err: Option<String> = None;
            for (relay_url, adapter) in adapters {
                match adapter
                    .publish_raw(&routing_id, blob_ttl_secs, blob.clone())
                    .await
                {
                    Ok(()) => {
                        accepted = accepted.saturating_add(1);
                        debug!(relay_url = %relay_url, "TransportRelayPublisher: PUBLISHed DID record");
                    }
                    Err(e) => {
                        // A per-relay failure does not abort the fan-out
                        // (multi-relay publishing, §3.10.2) — but it is NAMED at
                        // `warn`, not buried at `debug`: a relay that
                        // consistently rejects is suppressing this DID for every
                        // resolver that consults it (§3.10.8), and the operator
                        // needs to know WHICH relay.
                        warn!(
                            relay_url = %relay_url,
                            error = %e,
                            "TransportRelayPublisher: relay PUBLISH rejected — this relay \
                             will not serve this DID; trying remaining relays"
                        );
                        last_err = Some(e.to_string());
                    }
                }
            }

            if accepted > 0 {
                Ok(RelayPublishOutcome {
                    accepted,
                    attempted,
                })
            } else {
                // Every bound relay rejected the publish — fail closed.
                Err(IdentityError::RelayPublishFailed(format!(
                    "TransportRelayPublisher: all {attempted} bound relays rejected the \
                     DID-record PUBLISH{}",
                    last_err.map_or_else(String::new, |e| format!(": {e}"))
                )))
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
    use scp_dht::bep44_signable;
    use scp_did::{DidDocument, did_dht_from_public_key};

    use crate::error::TransportError;
    use crate::traits::{BlobId, SubscriptionStream};

    type BoxFut<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

    // ------------------------------------------------------------------
    // Recording adapter: captures every `publish_raw` call so tests can decode
    // the published blob back into a frame. `should_fail` makes `publish_raw`
    // return an error (to exercise the multi-relay fall-through / fail-closed).
    // Every other method is an honest "not connected".
    // ------------------------------------------------------------------
    #[derive(Default)]
    struct RecordingPublishAdapter {
        published: Mutex<Vec<(RoutingId, u64, Vec<u8>)>>,
        should_fail: bool,
    }

    impl RecordingPublishAdapter {
        fn new() -> Self {
            Self::default()
        }

        fn failing() -> Self {
            Self {
                published: Mutex::new(Vec::new()),
                should_fail: true,
            }
        }

        fn recorded(&self) -> Vec<(RoutingId, u64, Vec<u8>)> {
            self.published.lock().unwrap().clone()
        }
    }

    impl TransportAdapter for RecordingPublishAdapter {
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

        fn publish_raw(
            &self,
            routing_id: &RoutingId,
            blob_ttl: u64,
            blob: Vec<u8>,
        ) -> BoxFut<'_, Result<(), TransportError>> {
            if self.should_fail {
                return Box::pin(async { Err(TransportError::Timeout) });
            }
            self.published
                .lock()
                .unwrap()
                .push((*routing_id, blob_ttl, blob));
            Box::pin(async { Ok(()) })
        }
    }

    const RELAY: &str = "wss://relay-a.example.com/scp/v1";
    const RELAY_B: &str = "wss://relay-b.example.com/scp/v1";
    const BLOB_TTL: u64 = 604_800;

    fn keypair(seed: u8) -> (VerifyingKey, SigningKey) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        (sk.verifying_key(), sk)
    }

    /// Builds a genuinely BEP44-signed DID-record frame for `did`, so the
    /// published blob verifies against the DID-derived key (§9.10.12).
    fn signed_record(vk: &VerifyingKey, sk: &SigningKey, seq: u64) -> (DidRecordV1, Vec<u8>) {
        let did = did_dht_from_public_key(vk.as_bytes()).to_string();
        let doc = DidDocument::new(&did, vk.as_bytes(), &[2u8; 32], &[3u8; 32]);
        let value = serde_json::to_vec(&doc).unwrap();
        let payload = bep44_signable(&value, seq);
        let signature: ed25519_dalek::Signature = sk.sign(&payload);
        let record =
            DidRecordV1::try_new(*vk.as_bytes(), seq, signature.to_bytes(), value.clone()).unwrap();
        (record, value)
    }

    fn routing_id_of(vk: &VerifyingKey) -> [u8; 32] {
        let did = did_dht_from_public_key(vk.as_bytes()).to_string();
        scp_identity::did_routing_id(&did)
    }

    // AC 1 / AC 4: a real publisher DidRecordV1-encodes and calls publish_raw;
    // the published blob decodes back to the exact frame.
    #[tokio::test]
    async fn publishes_encoded_frame_via_publish_raw() {
        let (vk, sk) = keypair(7);
        let (record, value) = signed_record(&vk, &sk, 3);

        let adapter = Arc::new(RecordingPublishAdapter::new());
        let publisher = TransportRelayPublisher::new();
        publisher.bind(RELAY, Arc::clone(&adapter) as Arc<dyn TransportAdapter>);

        RelayPublisher::publish(&publisher, BLOB_TTL, &record)
            .await
            .expect("publish succeeds when a relay is bound");

        let recorded = adapter.recorded();
        assert_eq!(recorded.len(), 1, "exactly one publish_raw call");
        let (got_rid, got_ttl, blob) = &recorded[0];
        assert_eq!(
            got_rid.as_bytes(),
            &routing_id_of(&vk),
            "publish at the DID routing_id derived from the frame key"
        );
        assert_eq!(*got_ttl, BLOB_TTL, "blob_ttl forwarded verbatim");

        // The published blob is the FRAME (not the bare value), and decodes back.
        assert_ne!(blob, &value, "the blob is the frame, not the bare document");
        let decoded = DidRecordV1::decode(blob).expect("published blob decodes as a frame");
        assert_eq!(
            decoded, record,
            "published frame is byte-identical to source"
        );
        assert_eq!(decoded.value(), &value[..]);
    }

    // WRITE ↔ ADMISSION agreement (SCP-RELAYRES-004 write path vs
    // SCP-RELAYRES-003 relay admission). The routing_id this publisher writes at
    // MUST be exactly the one a validating relay re-derives when it decides
    // whether to admit the frame, and the published bytes must satisfy that
    // relay's binding + signature check. Both sides derive it through the single
    // `scp_identity::republish::did_record_routing_id` helper; this test is the
    // mechanical guard that they can never drift apart. A drift would reject
    // every self-DID republish as `BindingMismatch` on every validating relay —
    // a silent, total availability failure for DID resolution.
    #[tokio::test]
    async fn published_frame_is_admitted_by_relay_validation() {
        use crate::relay::did_record_validation::{DidRecordClass, classify_did_record_frame};

        let (vk, sk) = keypair(23);
        let (record, _) = signed_record(&vk, &sk, 5);

        let adapter = Arc::new(RecordingPublishAdapter::new());
        let publisher = TransportRelayPublisher::new();
        publisher.bind(RELAY, Arc::clone(&adapter) as Arc<dyn TransportAdapter>);

        RelayPublisher::publish(&publisher, BLOB_TTL, &record)
            .await
            .expect("publish succeeds when a relay is bound");

        let recorded = adapter.recorded();
        assert_eq!(recorded.len(), 1, "exactly one publish_raw call");
        let (got_rid, _, blob) = &recorded[0];

        // Independent oracle (a third composition, via `did_dht_from_public_key`):
        // the write address is the DID-domain routing_id of the frame's own key.
        assert_eq!(got_rid.as_bytes(), &routing_id_of(&vk));

        // And the relay's own admission check accepts that exact
        // (routing_id, blob) pair — binding first, then the BEP44 signature.
        assert_eq!(
            classify_did_record_frame(got_rid.as_bytes(), blob),
            DidRecordClass::Valid { seq: 5 },
            "the WRITE path's routing_id must satisfy the relay's admission \
             binding byte-for-byte"
        );
    }

    // AC 4 (multi-relay, §3.10.2): every bound relay receives the frame.
    #[tokio::test]
    async fn publishes_to_all_bound_relays() {
        let (vk, sk) = keypair(9);
        let (record, _) = signed_record(&vk, &sk, 1);

        let a = Arc::new(RecordingPublishAdapter::new());
        let b = Arc::new(RecordingPublishAdapter::new());
        let publisher = TransportRelayPublisher::new();
        publisher.bind(RELAY, Arc::clone(&a) as Arc<dyn TransportAdapter>);
        publisher.bind(RELAY_B, Arc::clone(&b) as Arc<dyn TransportAdapter>);

        RelayPublisher::publish(&publisher, BLOB_TTL, &record)
            .await
            .expect("publish succeeds");

        assert_eq!(a.recorded().len(), 1, "relay A received the frame");
        assert_eq!(b.recorded().len(), 1, "relay B received the frame");
    }

    // Fail-closed: no relay bound → typed error, never a phantom success.
    #[tokio::test]
    async fn unbound_publisher_fails_closed() {
        let (vk, sk) = keypair(11);
        let (record, _) = signed_record(&vk, &sk, 1);

        let publisher = TransportRelayPublisher::new();
        let result = RelayPublisher::publish(&publisher, BLOB_TTL, &record).await;
        assert!(
            matches!(result, Err(IdentityError::RelayPublishFailed(_))),
            "an unbound publisher must fail closed"
        );
    }

    // Best-effort: one relay fails, another succeeds → overall success, and the
    // succeeding relay still got the frame.
    #[tokio::test]
    async fn one_relay_fails_other_succeeds_is_success() {
        let (vk, sk) = keypair(13);
        let (record, _) = signed_record(&vk, &sk, 1);

        let good = Arc::new(RecordingPublishAdapter::new());
        let bad = Arc::new(RecordingPublishAdapter::failing());
        let publisher = TransportRelayPublisher::new();
        publisher.bind(RELAY, Arc::clone(&good) as Arc<dyn TransportAdapter>);
        publisher.bind(RELAY_B, Arc::clone(&bad) as Arc<dyn TransportAdapter>);

        RelayPublisher::publish(&publisher, BLOB_TTL, &record)
            .await
            .expect("at least one relay accepted → success");
        assert_eq!(good.recorded().len(), 1, "the healthy relay got the frame");
    }

    // Fail-closed: every bound relay rejects → typed error.
    #[tokio::test]
    async fn all_relays_fail_is_fail_closed() {
        let (vk, sk) = keypair(17);
        let (record, _) = signed_record(&vk, &sk, 1);

        let bad = Arc::new(RecordingPublishAdapter::failing());
        let publisher = TransportRelayPublisher::new();
        publisher.bind(RELAY, Arc::clone(&bad) as Arc<dyn TransportAdapter>);

        let result = RelayPublisher::publish(&publisher, BLOB_TTL, &record).await;
        assert!(
            matches!(result, Err(IdentityError::RelayPublishFailed(_))),
            "all relays failing must fail closed"
        );
    }

    // unbind removes a relay from the publish set.
    #[tokio::test]
    async fn unbind_removes_relay() {
        let (vk, sk) = keypair(19);
        let (record, _) = signed_record(&vk, &sk, 1);

        let adapter = Arc::new(RecordingPublishAdapter::new());
        let publisher = TransportRelayPublisher::new();
        publisher.bind(RELAY, Arc::clone(&adapter) as Arc<dyn TransportAdapter>);
        publisher.unbind(RELAY);

        let result = RelayPublisher::publish(&publisher, BLOB_TTL, &record).await;
        assert!(
            matches!(result, Err(IdentityError::RelayPublishFailed(_))),
            "after unbind, no relay remains → fail closed"
        );
        assert!(adapter.recorded().is_empty());
    }
}
