//! Tests for [`TransportPushPublisher`]. The registrar tests under
//! `push-store` run a real `PushRegistrar` against real push-enabled relays.

use std::error::Error;

use super::*;

type TestResult = Result<(), Box<dyn Error>>;

/// A relay with no bound connection is unreachable, and nothing is sent.
#[tokio::test]
async fn unbound_relay_is_unreachable() -> TestResult {
    let publisher = TransportPushPublisher::new();
    let result = publisher
        .publish("wss://relay.example/scp/v1", [1; 32], vec![1, 2, 3])
        .await;
    assert!(
        matches!(result, Err(PushPublishError::Unreachable { .. })),
        "{result:?}"
    );
    Ok(())
}

/// A URL that is not a relay URL is refused by `unbind` and, at publish
/// time, is unreachable.
#[tokio::test]
async fn invalid_relay_url_is_refused() -> TestResult {
    let publisher = TransportPushPublisher::new();
    assert!(publisher.unbind("not a url").is_err());
    let result = publisher.publish("not a url", [1; 32], Vec::new()).await;
    assert!(
        matches!(result, Err(PushPublishError::Unreachable { .. })),
        "{result:?}"
    );
    Ok(())
}

/// A relay `ERR` keeps its code and text; a transport with no raw-blob path
/// is `Unsupported`, which the registrar does not retry; every other failure
/// is `Unreachable` with sanitized text.
#[test]
fn transport_errors_map_to_publish_errors() {
    let rejected = publish_error(TransportError::RelayRejected {
        code: 4060,
        msg: "bad signature".to_owned(),
    });
    assert!(matches!(
        rejected,
        PushPublishError::Rejected { code: 4060, ref msg } if msg == "bad signature"
    ));
    let unreachable = publish_error(TransportError::SendFailed("down\nforged".to_owned()));
    assert!(matches!(
        unreachable,
        PushPublishError::Unreachable { ref reason } if !reason.contains('\n')
    ));
    assert!(matches!(
        publish_error(TransportError::NotConnected),
        PushPublishError::Unreachable { .. }
    ));
    let unsupported = publish_error(TransportError::NotSupported(
        "no raw publish\nforged".to_owned(),
    ));
    assert!(
        matches!(
            unsupported,
            PushPublishError::Unsupported { ref reason } if !reason.contains('\n')
        ),
        "{unsupported:?}"
    );
    let registrar_error = scp_core::push::PushError::from(unsupported);
    assert!(
        !registrar_error.retryable(),
        "{registrar_error:?} must not be retried"
    );
}

#[cfg(feature = "push-store")]
mod relays {
    use std::collections::BTreeSet;
    use std::net::SocketAddr;

    use scp_core::push::{
        PushError, PushRegistrar, PushRegistrarConfig, PushSigningKey, PushTarget,
    };
    use scp_core::store::ProtocolRepository;
    use scp_crypto::p256::P256SecretKey;
    use scp_did::DID;
    use scp_identity::push_verify::{KelPushVerifier, PushSignatureVerifier, TestPushVerifier};
    use scp_platform::in_memory::InMemoryStorage;
    use scp_platform::testing::InMemoryKeyCustody;
    use scp_platform::{KeyCustody, KeyType, PushToken};
    use scp_protocol::discovery::push::{
        PushPlatform, PushRegistration, PushRelay, push_registration_signing_bytes,
    };

    use super::*;
    use crate::native::NativeRelayAdapter;
    use crate::native::adapter::CoverTraffic;
    use crate::native::server::{RelayConfig, RelayServer};
    use crate::native::storage::BlobStorageBackend;
    use crate::relay::connection::{RelayUrlSource, SourcedRelayUrl};
    use crate::relay::push::{ApnsConfig, ApnsEnvironment, ApnsSender, PushSender};
    use crate::relay::push_dispatch::PushService;
    use crate::relay::push_gate::{LiveRelayUrl, PushRole, PushServiceConfig, RelayUrl};
    use crate::relay::push_store::{PushRegistrationKey, PushRegistrationStore};

    const REGISTRANT: &str = "did:dht:z6MkPushPublisherTest";
    const RELAY_A: &str = "wss://relay-a.push.test";
    const RELAY_B: &str = "wss://relay-b.push.test";
    const TOKEN: &[u8] = b"apns-device-token";

    /// One running push-enabled relay and its registration store.
    struct Relay {
        url: &'static str,
        addr: SocketAddr,
        store: PushRegistrationStore,
        _dir: tempfile::TempDir,
    }

    fn apns_sender() -> Result<PushSender, Box<dyn Error>> {
        Ok(PushSender::Apns(ApnsSender::new(ApnsConfig {
            signing_key: P256SecretKey::from_scalar_bytes(&[3; 32])?,
            key_id: "ABC123DEFG".to_owned(),
            team_id: "TEAM456XYZ".to_owned(),
            topic: "works.limn.app".to_owned(),
            environment: ApnsEnvironment::Sandbox,
        })?))
    }

    /// Starts a push-enabled relay whose own URL is `url`, with `verifier`.
    async fn start_relay(
        url: &'static str,
        verifier: Arc<dyn PushSignatureVerifier>,
    ) -> Result<Relay, Box<dyn Error>> {
        let dir = tempfile::tempdir()?;
        let store = PushRegistrationStore::open_sqlite(
            &dir.path().join("push.db"),
            crate::relay::push_store::PushStoreAtRest::Unkeyed,
        )?;
        let push = PushRole::Enabled(PushService::start(PushServiceConfig {
            store: store.clone(),
            verifier,
            senders: Arc::from(vec![apns_sender()?]),
        })?);
        let config = RelayConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            delivery_jitter_ms: 0,
            push,
            ..RelayConfig::defaults(LiveRelayUrl::new(RelayUrl::new(url)?))
        };
        let (_handle, addr) = RelayServer::new(config, Arc::new(BlobStorageBackend::in_memory()))
            .start()
            .await?;
        Ok(Relay {
            url,
            addr,
            store,
            _dir: dir,
        })
    }

    /// A publisher with one connection per relay, bound under that relay's
    /// own URL while the socket goes to the loopback listener.
    async fn bound_publisher(
        relays: &[&Relay],
    ) -> Result<Arc<TransportPushPublisher>, Box<dyn Error>> {
        let publisher = Arc::new(TransportPushPublisher::new());
        for relay in relays {
            let adapter = NativeRelayAdapter::connect_sourced(
                &SourcedRelayUrl {
                    url: format!("ws://{}/scp/v1", relay.addr),
                    source: RelayUrlSource::DhtResolved,
                },
                None,
                CoverTraffic::Off,
            )
            .await?;
            publisher.bind(relay.url, Arc::new(adapter))?;
        }
        Ok(publisher)
    }

    async fn signing_key() -> Result<PushSigningKey<InMemoryKeyCustody>, Box<dyn Error>> {
        let custody = Arc::new(InMemoryKeyCustody::new());
        let handle = custody.generate_keypair(KeyType::P256Signing).await?;
        Ok(PushSigningKey::for_testing(DID(REGISTRANT.to_owned()), custody, handle).await?)
    }

    async fn registrar(
        signing_key: PushSigningKey<InMemoryKeyCustody>,
        publisher: Arc<dyn PushRelayPublisher>,
    ) -> Result<PushRegistrar<InMemoryKeyCustody, InMemoryStorage>, Box<dyn Error>> {
        Ok(PushRegistrar::new(PushRegistrarConfig {
            signing_key,
            publisher,
            clock: Arc::new(scp_clock::SystemClock),
            monotonic_clock: Arc::new(scp_clock::SystemMonotonicClock::new()),
            platform: PushPlatform::Apns,
            token: PushToken::new(TOKEN.to_vec()),
            storage: Arc::new(ProtocolRepository::new_for_testing(InMemoryStorage::new())),
        })
        .await?)
    }

    fn target(url: &str, ids: &[[u8; 32]]) -> Result<PushTarget, Box<dyn Error>> {
        Ok(PushTarget {
            relay: PushRelay::direct(url)?,
            routing_ids: ids.iter().copied().collect(),
        })
    }

    fn store_key() -> PushRegistrationKey {
        PushRegistrationKey {
            registrant: REGISTRANT.to_owned(),
            platform: PushPlatform::Apns,
            token: TOKEN.to_vec(),
        }
    }

    /// Records each blob, so a test can replay one elsewhere. While `forward`
    /// is off it holds the blob back and answers `Unreachable`, so no relay
    /// stores it.
    struct Tap {
        inner: Arc<TransportPushPublisher>,
        sent: std::sync::Mutex<Vec<(String, Vec<u8>)>>,
        forward: std::sync::atomic::AtomicBool,
    }

    impl Tap {
        fn blob_for(&self, relay_url: &str) -> Result<Vec<u8>, Box<dyn Error>> {
            Ok(self
                .sent
                .lock()
                .map_err(|_| "tap poisoned")?
                .iter()
                .rev()
                .find(|(url, _)| url == relay_url)
                .map(|(_, blob)| blob.clone())
                .ok_or_else(|| format!("no blob sent to {relay_url}"))?)
        }
    }

    impl PushRelayPublisher for Tap {
        fn publish<'a>(
            &'a self,
            relay_url: &'a str,
            routing_id: [u8; 32],
            blob: Vec<u8>,
        ) -> BoxFuture<'a, Result<(), PushPublishError>> {
            if let Ok(mut sent) = self.sent.lock() {
                sent.push((relay_url.to_owned(), blob.clone()));
            }
            if self.forward.load(std::sync::atomic::Ordering::SeqCst) {
                self.inner.publish(relay_url, routing_id, blob)
            } else {
                Box::pin(async {
                    Err(PushPublishError::Unreachable {
                        reason: "held back by the test".to_owned(),
                    })
                })
            }
        }
    }

    /// PUSH-036 criterion 2: against relays wired with the signature-checking
    /// test verifier of PUSH-005, `register` stores one registration per
    /// relay for the device's token, holding that relay's own routing IDs.
    /// The test signs with a P-256 key it registers in the verifier; the
    /// device's `#active` key waits on PUSH-036's production constructor.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn register_stores_one_registration_per_relay() -> TestResult {
        let key = signing_key().await?;
        let verifier: Arc<dyn PushSignatureVerifier> = Arc::new(TestPushVerifier::new([(
            DID(REGISTRANT.to_owned()),
            *key.public_key(),
        )]));
        let relay_a = start_relay(RELAY_A, Arc::clone(&verifier)).await?;
        let relay_b = start_relay(RELAY_B, verifier).await?;
        let publisher = bound_publisher(&[&relay_a, &relay_b]).await?;
        let mut registrar = registrar(key, publisher).await?;

        let results = registrar
            .register(&[
                target(RELAY_A, &[[0xA1; 32], [0xA2; 32]])?,
                target(RELAY_B, &[[0xB1; 32]])?,
            ])
            .await?;
        assert!(results.values().all(Result::is_ok), "{results:?}");
        assert_eq!(results.len(), 2);

        for (relay, ids) in [
            (&relay_a, vec![[0xA1; 32], [0xA2; 32]]),
            (&relay_b, vec![[0xB1; 32]]),
        ] {
            let stored = relay
                .store
                .get(&store_key())
                .await?
                .ok_or_else(|| format!("{} stored no registration", relay.url))?;
            assert_eq!(
                stored.routing_ids.iter().copied().collect::<BTreeSet<_>>(),
                ids.into_iter().collect::<BTreeSet<_>>(),
                "{} holds its own routing IDs only",
                relay.url
            );
            assert_eq!(stored.registrant, REGISTRANT);
        }
        Ok(())
    }

    /// PUSH-036 criterion 3: each relay's message is signed over that
    /// relay's URL. Before either relay holds a registration, relay A's
    /// message replayed at relay B and relay B's replayed at relay A are both
    /// refused with 4060 and store nothing, and the two preimages differ.
    /// The registrar's own messages are then accepted at each relay.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn each_relay_message_signed_over_its_own_url() -> TestResult {
        let key = signing_key().await?;
        let verifier: Arc<dyn PushSignatureVerifier> = Arc::new(TestPushVerifier::new([(
            DID(REGISTRANT.to_owned()),
            *key.public_key(),
        )]));
        let relay_a = start_relay(RELAY_A, Arc::clone(&verifier)).await?;
        let relay_b = start_relay(RELAY_B, verifier).await?;
        let inner = bound_publisher(&[&relay_a, &relay_b]).await?;
        let tap = Arc::new(Tap {
            inner: Arc::clone(&inner),
            sent: std::sync::Mutex::new(Vec::new()),
            forward: std::sync::atomic::AtomicBool::new(false),
        });
        let mut registrar = registrar(key, Arc::clone(&tap) as Arc<dyn PushRelayPublisher>).await?;
        let targets = [
            target(RELAY_A, &[[0xA1; 32]])?,
            target(RELAY_B, &[[0xB1; 32]])?,
        ];

        // Held back: neither relay stores anything yet.
        registrar.register(&targets).await?;
        let blob_a = tap.blob_for(RELAY_A)?;
        let blob_b = tap.blob_for(RELAY_B)?;
        for (to, blob) in [(RELAY_B, blob_a.clone()), (RELAY_A, blob_b.clone())] {
            let replay = inner
                .publish(to, PushRelay::direct(to)?.push_routing_id(), blob)
                .await;
            assert!(
                matches!(replay, Err(PushPublishError::Rejected { code: 4060, .. })),
                "replay at {to}: {replay:?}"
            );
        }
        for relay in [&relay_a, &relay_b] {
            assert!(
                relay.store.get(&store_key()).await?.is_none(),
                "{} stored a replay",
                relay.url
            );
        }
        let preimage_a = push_registration_signing_bytes(
            &PushRegistration::from_msgpack(&blob_a)?,
            &PushRelay::direct(RELAY_A)?,
        )?;
        let preimage_b = push_registration_signing_bytes(
            &PushRegistration::from_msgpack(&blob_b)?,
            &PushRelay::direct(RELAY_B)?,
        )?;
        assert_ne!(preimage_a, preimage_b, "each preimage names its own relay");

        tap.forward.store(true, std::sync::atomic::Ordering::SeqCst);
        let results = registrar.register(&targets).await?;
        assert!(results.values().all(Result::is_ok), "{results:?}");
        for (relay, ids) in [(&relay_a, [0xA1; 32]), (&relay_b, [0xB1; 32])] {
            let stored = relay
                .store
                .get(&store_key())
                .await?
                .ok_or_else(|| format!("{} stored nothing", relay.url))?;
            assert_eq!(stored.routing_ids, vec![ids]);
        }
        Ok(())
    }

    /// Criterion 6 (PUSH-014): a registration followed by a deregistration
    /// leaves the relay's store with no registration for the token.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn register_then_deregister_leaves_no_registration() -> TestResult {
        let key = signing_key().await?;
        let verifier: Arc<dyn PushSignatureVerifier> = Arc::new(TestPushVerifier::new([(
            DID(REGISTRANT.to_owned()),
            *key.public_key(),
        )]));
        let relay_a = start_relay(RELAY_A, verifier).await?;
        let publisher = bound_publisher(&[&relay_a]).await?;
        let mut registrar = registrar(key, publisher).await?;

        let registered = registrar
            .register(&[target(RELAY_A, &[[0xA1; 32]])?])
            .await?;
        assert!(registered.values().all(Result::is_ok), "{registered:?}");
        assert!(
            relay_a.store.get(&store_key()).await?.is_some(),
            "the registration is stored"
        );

        let deregistered = registrar.deregister(&[PushRelay::direct(RELAY_A)?]).await?;
        assert!(deregistered.values().all(Result::is_ok), "{deregistered:?}");
        assert!(
            relay_a.store.get(&store_key()).await?.is_none(),
            "the deregistration removes it"
        );
        Ok(())
    }

    /// Criterion 1 (PUSH-014): relays whose verifier cannot read key state
    /// answer 5003, which reaches the caller per relay as
    /// `VerifierUnavailable`, a retryable error, and is not recorded.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn kel_verifier_yields_verifier_unavailable_per_relay() -> TestResult {
        let relay_a = start_relay(RELAY_A, Arc::new(KelPushVerifier)).await?;
        let relay_b = start_relay(RELAY_B, Arc::new(KelPushVerifier)).await?;
        let publisher = bound_publisher(&[&relay_a, &relay_b]).await?;
        let mut registrar = registrar(signing_key().await?, publisher).await?;

        let results = registrar
            .register(&[
                target(RELAY_A, &[[0xA1; 32]])?,
                target(RELAY_B, &[[0xB1; 32]])?,
            ])
            .await?;
        assert_eq!(results.len(), 2);
        for url in [RELAY_A, RELAY_B] {
            let outcome = results.get(url).ok_or("missing relay result")?;
            assert!(
                matches!(outcome, Err(err @ PushError::VerifierUnavailable { .. }) if err.retryable()),
                "{url}: {outcome:?}"
            );
        }
        for relay in [&relay_a, &relay_b] {
            assert!(relay.store.get(&store_key()).await?.is_none());
        }
        Ok(())
    }
}
