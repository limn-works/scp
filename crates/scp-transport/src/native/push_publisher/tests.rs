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

/// A relay `ERR` keeps its code and text; every other failure is
/// `Unreachable` with sanitized text.
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
}

#[cfg(feature = "push-store")]
mod relays {
    use std::collections::BTreeSet;
    use std::net::SocketAddr;

    use scp_core::push::{
        PushError, PushRegistrar, PushRegistrarConfig, PushSigningKey, PushTarget,
    };
    use scp_crypto::p256::P256SecretKey;
    use scp_did::DID;
    use scp_identity::push_verify::{KelPushVerifier, PushSignatureVerifier, TestPushVerifier};
    use scp_platform::testing::InMemoryKeyCustody;
    use scp_platform::{KeyCustody, KeyType};
    use scp_protocol::discovery::push::{PushPlatform, PushRelay};

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
        let store = PushRegistrationStore::open_sqlite(&dir.path().join("push.db"))?;
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

    fn registrar(
        signing_key: PushSigningKey<InMemoryKeyCustody>,
        publisher: Arc<dyn PushRelayPublisher>,
    ) -> Result<PushRegistrar<InMemoryKeyCustody>, Box<dyn Error>> {
        Ok(PushRegistrar::new(PushRegistrarConfig {
            signing_key,
            publisher,
            clock: Arc::new(scp_clock::SystemClock),
            platform: PushPlatform::Apns,
            token: TOKEN.to_vec(),
        })?)
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

    /// Records each blob it forwards, so a test can replay one elsewhere.
    struct Tap {
        inner: Arc<TransportPushPublisher>,
        sent: std::sync::Mutex<Vec<(String, Vec<u8>)>>,
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
            self.inner.publish(relay_url, routing_id, blob)
        }
    }

    /// Criterion 3 (PUSH-014): each relay hosting a context stores exactly one
    /// registration for the device's token, holding that relay's own routing
    /// IDs.
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
        let mut registrar = registrar(key, publisher)?;

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

    /// Criterion 4 (PUSH-014): each relay's message is signed over that
    /// relay's URL. Relay A's registration replayed at relay B is refused
    /// with 4060 and stores nothing there, while the registrar's own message
    /// to relay B is accepted.
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
        });
        let mut registrar = registrar(key, Arc::clone(&tap) as Arc<dyn PushRelayPublisher>)?;

        let results = registrar
            .register(&[target(RELAY_A, &[[0xA1; 32]])?])
            .await?;
        assert!(results.values().all(Result::is_ok), "{results:?}");
        let blob_a = tap
            .sent
            .lock()
            .map_err(|_| "tap poisoned")?
            .iter()
            .find(|(url, _)| url == RELAY_A)
            .map(|(_, blob)| blob.clone())
            .ok_or("no blob sent to relay A")?;

        // Relay B holds no accepted timestamp yet, so only the signature,
        // made over relay A's URL, can refuse the replay.
        let replay = inner
            .publish(
                RELAY_B,
                PushRelay::direct(RELAY_B)?.push_routing_id(),
                blob_a,
            )
            .await;
        assert!(
            matches!(replay, Err(PushPublishError::Rejected { code: 4060, .. })),
            "{replay:?}"
        );
        assert!(relay_b.store.get(&store_key()).await?.is_none());

        let results = registrar
            .register(&[target(RELAY_B, &[[0xB1; 32]])?])
            .await?;
        assert!(results.values().all(Result::is_ok), "{results:?}");
        let stored = relay_b
            .store
            .get(&store_key())
            .await?
            .ok_or("relay B stored nothing")?;
        assert_eq!(stored.routing_ids, vec![[0xB1; 32]]);
        Ok(())
    }

    /// Criterion 5 (PUSH-014): relays whose verifier cannot read key state
    /// answer 5003, which reaches the caller per relay as
    /// `VerifierUnavailable`, a retryable error, and is not recorded.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn kel_verifier_yields_verifier_unavailable_per_relay() -> TestResult {
        let relay_a = start_relay(RELAY_A, Arc::new(KelPushVerifier)).await?;
        let relay_b = start_relay(RELAY_B, Arc::new(KelPushVerifier)).await?;
        let publisher = bound_publisher(&[&relay_a, &relay_b]).await?;
        let mut registrar = registrar(signing_key().await?, publisher)?;

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
