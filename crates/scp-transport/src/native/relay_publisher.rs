//! Production [`RelayPublisher`] over a live transport (§3.10.2, §3.10.5) — the
//! WRITE half of Model B relay DID resolution (SCP-RELAYRES-004).
//!
//! [`TransportRelayPublisher`] is the concrete, non-test implementation of the
//! `scp-identity` [`RelayPublisher`](scp_identity::republish::RelayPublisher)
//! trait. It lives in `scp-transport` (not `scp-identity`) because only this
//! crate can talk to a relay: `scp-transport` depends on `scp-identity`, so a
//! relay-talking publisher in `scp-identity` would be a circular dependency
//! (mirrors [`TransportRelayQuerier`](crate::native::TransportRelayQuerier), the
//! READ counterpart).
//!
//! # What it does
//!
//! Given a bound set of relays and a DID `routing_id`, it
//! [`encode`](scp_protocol::envelope::did_record::DidRecordV1::encode)s the
//! caller-supplied [`DidRecordV1`] frame (§9.10.12) — which carries the full
//! BEP44 `(public_key, seq, signature, value)` — into its canonical bytes and
//! publishes those bytes at the routing ID via the transport's raw-blob path
//! ([`publish_raw`](crate::traits::TransportAdapter::publish_raw)) to every bound
//! relay (own relays + bootstrap relays, §3.10.2 / §18.5.1). The DID relay blob
//! is therefore ALWAYS the frame — never the bare document bytes and never an
//! `OuterEnvelope` (§9.10.12 publish contract).
//!
//! # Frame-wrapping happens here, and only here
//!
//! The [`RelayPublisher`](scp_identity::republish::RelayPublisher) contract takes
//! a `&DidRecordV1`, not an opaque `&[u8]`, so a caller can never hand this
//! publisher unframed bytes (the footgun that dropped the BEP44 signature/seq at
//! the republish site before SCP-RELAYRES-004). The single `encode()` call below
//! is the one place the record becomes wire bytes.
//!
//! # Late binding (fail-closed)
//!
//! Like the querier, this publisher is constructed at FFI init — before any relay
//! connection exists — so transports are bound **after** construction via
//! [`bind`](TransportRelayPublisher::bind). A publish with **no** relay bound,
//! or one that every bound relay rejects, **fails closed** with a typed
//! [`IdentityError::RelayPublishFailed`]: an unconnected publisher never reports a
//! phantom success, so the republish loop's backoff + degraded-warning path
//! (§3.10.6) engages honestly. A publish that reaches at least one relay
//! succeeds (multi-relay publishing is best-effort for availability; one relay
//! accepting is a successful publish, and more relays only improve reach). No
//! lock is ever held across an `.await`: the adapter handles are cloned out under
//! a short synchronous lock, which is dropped before any publish future runs.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use scp_identity::IdentityError;
use scp_identity::republish::RelayPublisher;
use scp_protocol::envelope::did_record::DidRecordV1;
use tracing::debug;

use crate::traits::{RoutingId, TransportAdapter};

/// Production [`RelayPublisher`] that publishes DID-record frames over a live
/// transport.
///
/// Holds a per-instance, late-bound map of `relay_url -> adapter`. Bindings are
/// added as relay connections are established (see the module docs) and can be
/// removed on disconnect. A publish with no bound relay — or one every bound
/// relay rejects — fails closed (see the module docs).
#[derive(Default)]
pub struct TransportRelayPublisher {
    /// Late-bound live transports, keyed by relay URL. Guarded by a synchronous
    /// `RwLock` because every access is a brief clone-out; the lock is never
    /// held across an `.await` (see the module docs).
    relays: RwLock<HashMap<String, Arc<dyn TransportAdapter>>>,
}

impl std::fmt::Debug for TransportRelayPublisher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bound = self.relays.read().map_or(0, |m| m.len());
        f.debug_struct("TransportRelayPublisher")
            .field("bound_relays", &bound)
            .finish()
    }
}

impl TransportRelayPublisher {
    /// Creates a publisher with no bound transports. Bind relays via
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
    /// is a no-op (a publish then fails closed if no relay remains bound).
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

    /// Snapshots the currently-bound `(relay_url, adapter)` pairs, cloned out
    /// under a short synchronous lock so the guard never crosses an `.await`.
    fn bound_adapters(&self) -> Vec<(String, Arc<dyn TransportAdapter>)> {
        self.relays.read().map_or_else(
            |_| Vec::new(),
            |m| {
                m.iter()
                    .map(|(url, a)| (url.clone(), Arc::clone(a)))
                    .collect()
            },
        )
    }

    /// Number of relays currently bound — the number a `publish` would reach.
    ///
    /// A caller wiring a self-DID republish cycle uses this to decide whether the
    /// relay layer is serviceable at all: with zero bound relays every publish
    /// fails closed, so driving the relay arm would only spin against no
    /// transport. Zero here means "do not advertise an active relay task."
    #[must_use]
    pub fn bound_relay_count(&self) -> usize {
        self.relays.read().map_or(0, |m| m.len())
    }
}

// The `RelayPublisher` trait uses RPITIT with an explicit `+ Send` bound; an
// `async fn` in a trait does not guarantee a `Send` future, so a manual
// `impl Future` is required (matching `InMemoryRelayPublisher` / the querier).
#[allow(clippy::manual_async_fn)]
impl RelayPublisher for TransportRelayPublisher {
    fn publish(
        &self,
        blob_ttl: u64,
        record: &DidRecordV1,
    ) -> impl Future<Output = Result<(), IdentityError>> + Send {
        // Wrap ONCE, here: the record becomes its canonical §9.10.12 frame bytes.
        // The publisher only ever accepts a `DidRecordV1`, so the bytes on the
        // wire are always the full framed record, never bare `document_bytes`.
        let blob = record.encode();
        // Derive the routing_id from the frame's own key (§9.10.12 binding) — a
        // record can only be published at the one routing_id its key binds to, so
        // a frame/routing_id mismatch is unrepresentable. This matches the binding
        // a validating relay re-checks (SCP-RELAYRES-003).
        let routing_id = RoutingId::new(scp_identity::republish::did_record_routing_id(record));
        // Resolve the bound adapters synchronously and drop the lock before await.
        let adapters = self.bound_adapters();

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

            let mut any_ok = false;
            let mut last_err: Option<String> = None;
            for (relay_url, adapter) in adapters {
                match adapter
                    .publish_raw(&routing_id, blob_ttl, blob.clone())
                    .await
                {
                    Ok(()) => {
                        any_ok = true;
                        debug!(relay_url = %relay_url, "TransportRelayPublisher: PUBLISHed DID record");
                    }
                    Err(e) => {
                        // A per-relay failure is best-effort: log and keep going
                        // to the other relays (multi-relay publishing, §3.10.2).
                        debug!(
                            relay_url = %relay_url,
                            error = %e,
                            "TransportRelayPublisher: relay PUBLISH failed — trying remaining relays"
                        );
                        last_err = Some(e.to_string());
                    }
                }
            }

            if any_ok {
                Ok(())
            } else {
                // Every bound relay rejected the publish — fail closed.
                Err(IdentityError::RelayPublishFailed(format!(
                    "TransportRelayPublisher: all bound relays rejected the DID-record PUBLISH{}",
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
