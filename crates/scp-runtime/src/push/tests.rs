//! Tests for the push registrar (PUSH-014). The relay-backed tests live in
//! `scp-transport`'s `native::push_publisher`.

use std::error::Error;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

use scp_platform::KeyType;
use scp_platform::testing::InMemoryKeyCustody;
use scp_protocol::context::membership::KeyPackage;

use super::*;
use crate::context::ContextHandle;

type TestResult = Result<(), Box<dyn Error>>;

const REGISTRANT: &str = "did:dht:z6MkPushRegistrarTest";
const RELAY_A: &str = "wss://relay-a.example/scp/v1";
const RELAY_B: &str = "wss://relay-b.example/scp/v1";
const TOKEN: &[u8] = b"device-token-old";
const NEW_TOKEN: &[u8] = b"device-token-new";
const CTX_A: [u8; 32] = [0xA0; 32];
const CTX_B: [u8; 32] = [0xB0; 32];
const PSEUDONYM_A: [u8; 32] = [0xA1; 32];
const PSEUDONYM_A_NEW: [u8; 32] = [0xA2; 32];
const PSEUDONYM_B: [u8; 32] = [0xB1; 32];
/// How long a test waits for a publish that must come.
const ARRIVAL: Duration = Duration::from_secs(20);
/// How long a test watches for a publish that must not come.
const QUIET: Duration = Duration::from_millis(700);

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// One message a [`RecordingPublisher`] received.
#[derive(Debug, Clone)]
struct Published {
    relay_url: String,
    routing_id: [u8; 32],
    blob: Vec<u8>,
    /// The clock's second when the publisher received the message.
    clock_secs: u64,
    at: Instant,
}

type Answer = Box<dyn Fn(&str, usize) -> Result<(), PushPublishError> + Send + Sync>;

/// Records every publish and answers it with `answer(relay_url, attempt)`,
/// where `attempt` counts every earlier publish.
struct RecordingPublisher {
    tx: mpsc::UnboundedSender<Published>,
    answer: Answer,
    attempts: AtomicUsize,
    clock: Arc<dyn Clock>,
}

impl PushRelayPublisher for RecordingPublisher {
    fn publish<'a>(
        &'a self,
        relay_url: &'a str,
        routing_id: [u8; 32],
        blob: Vec<u8>,
    ) -> BoxFuture<'a, Result<(), PushPublishError>> {
        let attempt = self.attempts.fetch_add(1, Ordering::SeqCst);
        let answer = (self.answer)(relay_url, attempt);
        let record = Published {
            relay_url: relay_url.to_owned(),
            routing_id,
            blob,
            clock_secs: self.clock.now_secs(),
            at: Instant::now(),
        };
        // A closed receiver means the test stopped reading; nothing to record.
        let recorded = self.tx.send(record).is_ok();
        Box::pin(async move {
            if recorded {
                answer
            } else {
                Err(PushPublishError::Unreachable {
                    reason: "test receiver closed".to_owned(),
                })
            }
        })
    }
}

fn publisher(
    clock: Arc<dyn Clock>,
    answer: Answer,
) -> (
    Arc<dyn PushRelayPublisher>,
    mpsc::UnboundedReceiver<Published>,
) {
    let (tx, rx) = mpsc::unbounded_channel();
    let publisher = Arc::new(RecordingPublisher {
        tx,
        answer,
        attempts: AtomicUsize::new(0),
        clock,
    });
    (publisher, rx)
}

fn accept_all() -> Answer {
    Box::new(|_, _| Ok(()))
}

async fn signing_key() -> Result<PushSigningKey<InMemoryKeyCustody>, Box<dyn Error>> {
    let custody = Arc::new(InMemoryKeyCustody::new());
    let handle = custody.generate_keypair(KeyType::P256Signing).await?;
    Ok(PushSigningKey::for_testing(DID(REGISTRANT.to_owned()), custody, handle).await?)
}

async fn registrar(
    publisher: Arc<dyn PushRelayPublisher>,
    clock: Arc<dyn Clock>,
) -> Result<PushRegistrar<InMemoryKeyCustody>, Box<dyn Error>> {
    Ok(PushRegistrar::new(PushRegistrarConfig {
        signing_key: signing_key().await?,
        publisher,
        clock,
        platform: PushPlatform::Apns,
        token: TOKEN.to_vec(),
    })?)
}

fn system_clock() -> Arc<dyn Clock> {
    Arc::new(scp_clock::SystemClock)
}

/// An event log that stores nothing; these tests read push routes only.
struct NoEventLog;

#[async_trait::async_trait]
impl crate::context::builder::ContextEventLogProvider for NoEventLog {
    async fn init_event_log(
        &self,
        _context_id: &[u8; 32],
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        Ok(())
    }
    async fn append_event(
        &self,
        _context_id: &[u8; 32],
        _event: scp_event_log::EventType,
        _actor_did: &str,
        _payload: scp_event_log::EventPayload,
        _timestamp_secs: u64,
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        Ok(())
    }
    async fn destroy_event_log(
        &self,
        _context_id: &[u8; 32],
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        Ok(())
    }
}

/// A supervisor with real context actors and, when `events` holds, a
/// context-event channel.
fn supervisor(events: bool) -> Arc<Supervisor> {
    let crypto = Arc::new(crate::crypto::mls::provider::NodeMlsFactory::new(
        "did:dht:z6MkPushRegistrarNode".to_owned(),
        system_clock(),
    ));
    let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> = Arc::new(
        crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
            scp_platform::in_memory::InMemoryStorage::new(),
        )),
    );
    Supervisor::with_providers(
        crypto,
        Box::new(crate::context::builder::NotConfiguredTransportProvider),
        Box::new(NoEventLog),
        Arc::new(|_: &DID, _: scp_did::SigningKeyId| None),
        None,
        None,
        events.then(|| broadcast::channel(256).0),
        None,
        mls_storage,
    )
}

async fn create_context(
    sup: &Arc<Supervisor>,
    context_id: [u8; 32],
    pseudonym: [u8; 32],
    relays: &[&str],
) -> Result<ContextHandle, Box<dyn Error>> {
    let identity = sup.node_identity()?;
    Ok(Box::pin(sup.create_context(
        hex::encode(context_id),
        scp_protocol::context::ContextParams {
            ceiling: vec![scp_protocol::context::roles::Capability::MessagesRead],
            ..Default::default()
        },
        identity,
        Some(pseudonym),
        relays.iter().map(|url| (*url).to_owned()).collect(),
    ))
    .await?)
}

/// Waits for exactly `n` publishes, then checks that no other one follows.
async fn expect_publishes(
    rx: &mut mpsc::UnboundedReceiver<Published>,
    n: usize,
) -> Result<Vec<Published>, Box<dyn Error>> {
    let mut got = Vec::with_capacity(n);
    while got.len() < n {
        let next = tokio::time::timeout(ARRIVAL, rx.recv())
            .await?
            .ok_or("publisher dropped")?;
        got.push(next);
    }
    expect_quiet(rx).await?;
    Ok(got)
}

async fn expect_quiet(rx: &mut mpsc::UnboundedReceiver<Published>) -> TestResult {
    match tokio::time::timeout(QUIET, rx.recv()).await {
        Err(_) | Ok(None) => Ok(()),
        Ok(Some(extra)) => Err(format!("unexpected publish to {}", extra.relay_url).into()),
    }
}

fn relay_urls(published: &[Published]) -> BTreeSet<String> {
    published.iter().map(|p| p.relay_url.clone()).collect()
}

/// Decodes a registration and checks its signature over `relay_url`.
fn verified_registration(
    published: &Published,
    public_key: &P256PublicKey,
) -> Result<PushRegistration, Box<dyn Error>> {
    let registration = PushRegistration::from_msgpack(&published.blob)?;
    let relay = PushRelay::direct(&published.relay_url)?;
    let preimage = push_registration_signing_bytes(&registration, &relay)?;
    let digest: [u8; 32] = Sha256::digest(&preimage).into();
    verify_prehash_strict(public_key, &digest, &registration.signature)?;
    if published.routing_id != relay.push_routing_id() {
        return Err("registration published away from the relay's push routing ID".into());
    }
    Ok(registration)
}

/// Decodes a deregistration and checks its signature over `relay_url`.
fn verified_deregistration(
    published: &Published,
    public_key: &P256PublicKey,
) -> Result<PushDeregistration, Box<dyn Error>> {
    let deregistration = PushDeregistration::from_msgpack(&published.blob)?;
    let relay = PushRelay::direct(&published.relay_url)?;
    let preimage = push_deregistration_signing_bytes(&deregistration, &relay)?;
    let digest: [u8; 32] = Sha256::digest(&preimage).into();
    verify_prehash_strict(public_key, &digest, &deregistration.signature)?;
    if published.routing_id != relay.push_routing_id() {
        return Err("deregistration published away from the relay's push routing ID".into());
    }
    Ok(deregistration)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn target(url: &str, ids: &[[u8; 32]]) -> Result<PushTarget, Box<dyn Error>> {
    Ok(PushTarget {
        relay: PushRelay::direct(url)?,
        routing_ids: ids.iter().copied().collect(),
    })
}

// ---------------------------------------------------------------------------
// Criterion 4: re-registration on join, nothing on an unchanged set
// ---------------------------------------------------------------------------

/// A join that sets this device's pseudonym in a context on relay A changes
/// relay A's routing IDs only: the trigger task sends relay A one
/// registration with the new pseudonym and sends relay B nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn join_triggers_exactly_one_reregistration_on_affected_relay() -> TestResult {
    let sup = supervisor(true);
    let handle_a = create_context(&sup, CTX_A, PSEUDONYM_A, &[RELAY_A]).await?;
    create_context(&sup, CTX_B, PSEUDONYM_B, &[RELAY_B]).await?;
    let (sink, mut rx) = publisher(system_clock(), accept_all());
    let registrar = registrar(sink, system_clock()).await?;
    let public_key = *registrar.signing_key.public_key();
    let shutdown = CancellationToken::new();
    let task = registrar.spawn_trigger(Arc::clone(&sup), shutdown.clone())?;

    let initial = expect_publishes(&mut rx, 2).await?;
    assert_eq!(
        relay_urls(&initial),
        BTreeSet::from([RELAY_A.to_owned(), RELAY_B.to_owned()]),
        "the task registers every relay at start"
    );

    Box::pin(sup.join_context(
        &handle_a,
        KeyPackage::mock(DID("did:dht:z6MkPushRegistrarJoiner".to_owned())),
        None,
        Some(PSEUDONYM_A_NEW),
    ))
    .await?;
    let after = expect_publishes(&mut rx, 1).await?;
    assert_eq!(after[0].relay_url, RELAY_A, "only relay A's set changed");
    let registration = verified_registration(&after[0], &public_key)?;
    assert!(registration.routing_ids.contains(&PSEUDONYM_A_NEW));
    assert!(!registration.routing_ids.contains(&PSEUDONYM_A));

    shutdown.cancel();
    tokio::time::timeout(ARRIVAL, task.into_join_handle()).await??;
    Ok(())
}

/// Another member joining leaves this device's routing IDs unchanged, so the
/// trigger task publishes nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn foreign_member_join_triggers_no_publish() -> TestResult {
    let sup = supervisor(true);
    let handle_a = create_context(&sup, CTX_A, PSEUDONYM_A, &[RELAY_A]).await?;
    create_context(&sup, CTX_B, PSEUDONYM_B, &[RELAY_B]).await?;
    let (sink, mut rx) = publisher(system_clock(), accept_all());
    let registrar = registrar(sink, system_clock()).await?;
    let shutdown = CancellationToken::new();
    let task = registrar.spawn_trigger(Arc::clone(&sup), shutdown.clone())?;
    expect_publishes(&mut rx, 2).await?;

    Box::pin(sup.join_context(
        &handle_a,
        KeyPackage::mock(DID("did:dht:z6MkPushRegistrarForeign".to_owned())),
        None,
        None,
    ))
    .await?;
    expect_quiet(&mut rx).await?;

    shutdown.cancel();
    tokio::time::timeout(ARRIVAL, task.into_join_handle()).await??;
    Ok(())
}

// ---------------------------------------------------------------------------
// Criterion 5: no context ID on the wire or in the preimage
// ---------------------------------------------------------------------------

/// The registration and its preimage carry the context's routing ID and the
/// device's pseudonym, never the context ID in raw or hex form.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn preimage_contains_no_context_id() -> TestResult {
    let sup = supervisor(true);
    create_context(&sup, CTX_A, PSEUDONYM_A, &[RELAY_A]).await?;
    let (sink, mut rx) = publisher(system_clock(), accept_all());
    let mut registrar = registrar(sink, system_clock()).await?;
    let public_key = *registrar.signing_key.public_key();

    let results = registrar.reconcile(&sup).await?;
    assert!(
        results.get(RELAY_A).is_some_and(Result::is_ok),
        "{results:?}"
    );
    let published = expect_publishes(&mut rx, 1).await?;
    let registration = verified_registration(&published[0], &public_key)?;
    let preimage = push_registration_signing_bytes(&registration, &PushRelay::direct(RELAY_A)?)?;
    let hex_id = hex::encode(CTX_A);
    for (name, bytes) in [("preimage", &preimage), ("blob", &published[0].blob)] {
        assert!(!contains(bytes, &CTX_A), "{name} holds the raw context ID");
        assert!(
            !contains(bytes, hex_id.as_bytes()),
            "{name} holds the hex context ID"
        );
    }
    assert_eq!(
        registration
            .routing_ids
            .iter()
            .copied()
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            scp_protocol::context::context_routing_id(&hex_id),
            PSEUDONYM_A
        ])
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Criterion 7: bridge_target and tier 3
// ---------------------------------------------------------------------------

/// A relay that is not a tier 3 entry signs `bridge_target` = SHA-256(0x00),
/// for both message kinds.
#[tokio::test]
async fn non_tier3_preimage_ends_with_absent_bridge_target() -> TestResult {
    let (sink, mut rx) = publisher(system_clock(), accept_all());
    let mut registrar = registrar(sink, system_clock()).await?;
    let public_key = *registrar.signing_key.public_key();
    let absent: [u8; 32] = Sha256::digest([0x00u8]).into();
    let relay = PushRelay::direct(RELAY_A)?;

    registrar.register(&[target(RELAY_A, &[[7; 32]])?]).await?;
    registrar.deregister(std::slice::from_ref(&relay)).await?;
    let published = expect_publishes(&mut rx, 2).await?;

    let registration = verified_registration(&published[0], &public_key)?;
    let preimage = push_registration_signing_bytes(&registration, &relay)?;
    assert!(preimage.ends_with(&absent), "registration preimage");
    let deregistration = verified_deregistration(&published[1], &public_key)?;
    let preimage = push_deregistration_signing_bytes(&deregistration, &relay)?;
    assert!(preimage.ends_with(&absent), "deregistration preimage");
    Ok(())
}

/// A tier 3 entry is refused with `Tier3Unsupported` and nothing reaches it,
/// while the other relay in the same call registers.
#[tokio::test]
async fn tier3_relay_is_refused_without_publish() -> TestResult {
    let (sink, mut rx) = publisher(system_clock(), accept_all());
    let mut registrar = registrar(sink, system_clock()).await?;
    let tier3 = PushRelay::from(&scp_did::RelayService::bridge(
        scp_did::BridgeEndpoint::new("wss://bridge.example.com/scp/v1")?,
        scp_did::BridgeTarget::new([0x42; 32])?,
    ));
    let tier3_url = tier3.canonical_url().to_owned();

    let results = registrar
        .register(&[
            PushTarget {
                relay: tier3.clone(),
                routing_ids: BTreeSet::from([[7; 32]]),
            },
            target(RELAY_A, &[[7; 32]])?,
        ])
        .await?;
    assert!(
        matches!(
            results.get(&tier3_url),
            Some(Err(PushError::Tier3Unsupported { .. }))
        ),
        "{results:?}"
    );
    let deregistered = registrar.deregister(&[tier3]).await?;
    assert!(
        matches!(
            deregistered.get(&tier3_url),
            Some(Err(PushError::Tier3Unsupported { .. }))
        ),
        "{deregistered:?}"
    );
    let published = expect_publishes(&mut rx, 1).await?;
    assert_eq!(
        published[0].relay_url, RELAY_A,
        "only the direct relay is published to"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Criteria 8 and 9: deregistration, last context, token refresh
// ---------------------------------------------------------------------------

/// `deregister` sends each relay a deregistration signed over that relay's
/// URL, for the registration key `register` used, and forgets the relay.
#[tokio::test]
async fn deregister_mirrors_register() -> TestResult {
    let (sink, mut rx) = publisher(system_clock(), accept_all());
    let mut registrar = registrar(sink, system_clock()).await?;
    let public_key = *registrar.signing_key.public_key();
    registrar
        .register(&[target(RELAY_A, &[[1; 32]])?, target(RELAY_B, &[[2; 32]])?])
        .await?;
    let registrations = expect_publishes(&mut rx, 2).await?;
    assert_eq!(registrar.registered.len(), 2);

    let results = registrar
        .deregister(&[PushRelay::direct(RELAY_A)?, PushRelay::direct(RELAY_B)?])
        .await?;
    assert!(results.values().all(Result::is_ok), "{results:?}");
    let deregistrations = expect_publishes(&mut rx, 2).await?;
    assert_eq!(relay_urls(&deregistrations), relay_urls(&registrations));
    for published in &deregistrations {
        let deregistration = verified_deregistration(published, &public_key)?;
        assert_eq!(deregistration.registrant.0, REGISTRANT);
        assert_eq!(deregistration.platform, PushPlatform::Apns);
        assert_eq!(deregistration.token, TOKEN);
        let registered = registrations
            .iter()
            .find(|r| r.relay_url == published.relay_url)
            .ok_or("no registration for the relay")?;
        let registration = PushRegistration::from_msgpack(&registered.blob)?;
        assert!(deregistration.timestamp > registration.timestamp);
    }
    assert!(registrar.registered.is_empty(), "both relays are forgotten");
    Ok(())
}

/// When the device's last context on relay A goes away, the trigger task
/// sends relay A a deregistration and no registration, and relay B nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn leaving_last_context_on_relay_deregisters() -> TestResult {
    let sup = supervisor(true);
    create_context(&sup, CTX_A, PSEUDONYM_A, &[RELAY_A]).await?;
    create_context(&sup, CTX_B, PSEUDONYM_B, &[RELAY_B]).await?;
    let (sink, mut rx) = publisher(system_clock(), accept_all());
    let registrar = registrar(sink, system_clock()).await?;
    let public_key = *registrar.signing_key.public_key();
    let shutdown = CancellationToken::new();
    let task = registrar.spawn_trigger(Arc::clone(&sup), shutdown.clone())?;
    expect_publishes(&mut rx, 2).await?;

    assert!(sup.despawn_actor(&hex::encode(CTX_A)).await);
    let after = expect_publishes(&mut rx, 1).await?;
    assert_eq!(after[0].relay_url, RELAY_A);
    let deregistration = verified_deregistration(&after[0], &public_key)?;
    assert_eq!(deregistration.token, TOKEN);

    shutdown.cancel();
    tokio::time::timeout(ARRIVAL, task.into_join_handle()).await??;
    Ok(())
}

/// A token refresh sends each registered relay a deregistration of the old
/// token and then a registration of the same routing IDs for the new one.
#[tokio::test]
async fn token_refresh_deregisters_old_then_registers_new() -> TestResult {
    let (sink, mut rx) = publisher(system_clock(), accept_all());
    let mut registrar = registrar(sink, system_clock()).await?;
    let public_key = *registrar.signing_key.public_key();
    registrar
        .register(&[target(RELAY_A, &[[1; 32]])?, target(RELAY_B, &[[2; 32]])?])
        .await?;
    expect_publishes(&mut rx, 2).await?;

    let refresh = registrar.refresh_token(NEW_TOKEN.to_vec()).await?;
    assert!(
        refresh.deregistered.values().all(Result::is_ok),
        "{refresh:?}"
    );
    assert!(
        refresh.registered.values().all(Result::is_ok),
        "{refresh:?}"
    );
    let published = expect_publishes(&mut rx, 4).await?;
    for (relay_url, ids) in [(RELAY_A, [1; 32]), (RELAY_B, [2; 32])] {
        let mine: Vec<&Published> = published
            .iter()
            .filter(|p| p.relay_url == relay_url)
            .collect();
        assert_eq!(mine.len(), 2, "{relay_url} gets two messages");
        let deregistration = verified_deregistration(mine[0], &public_key)?;
        assert_eq!(deregistration.token, TOKEN, "the old token goes first");
        let registration = verified_registration(mine[1], &public_key)?;
        assert_eq!(registration.token, NEW_TOKEN, "then the new token");
        assert_eq!(registration.routing_ids, vec![ids]);
    }
    assert!(matches!(
        registrar.refresh_token(Vec::new()).await,
        Err(PushError::Message(PushMessageError::EmptyToken))
    ));
    assert_eq!(
        registrar.token, NEW_TOKEN,
        "a refused refresh keeps the token"
    );
    Ok(())
}

/// Two targets naming one relay, in any spelling, are refused before any
/// publish.
#[tokio::test]
async fn duplicate_relay_is_refused_before_publish() -> TestResult {
    let (sink, mut rx) = publisher(system_clock(), accept_all());
    let mut registrar = registrar(sink, system_clock()).await?;
    let result = registrar
        .register(&[
            target(RELAY_A, &[[1; 32]])?,
            target("WSS://Relay-A.example:443/scp/v1", &[[2; 32]])?,
        ])
        .await;
    assert!(
        matches!(result, Err(PushError::DuplicateRelay { .. })),
        "{result:?}"
    );
    expect_quiet(&mut rx).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Criterion 10: wire codes
// ---------------------------------------------------------------------------

/// Each relay code maps to its own variant; 5003, 5004, other 5xxx codes and
/// an unreachable relay are retryable, and 4060-4064 are not.
#[tokio::test]
async fn wire_codes_map_to_typed_errors() -> TestResult {
    let codes: [u16; 10] = [4060, 4061, 4062, 4063, 4064, 5003, 5004, 5000, 4001, 0];
    let urls: Vec<String> = codes
        .iter()
        .map(|code| format!("wss://relay-{code}.example/scp/v1"))
        .collect();
    let answer: Answer = Box::new(|url, _| {
        let code: u16 = url
            .trim_start_matches("wss://relay-")
            .split('.')
            .next()
            .and_then(|code| code.parse().ok())
            .unwrap_or(0);
        if code == 0 {
            return Err(PushPublishError::Unreachable {
                reason: "not connected".to_owned(),
            });
        }
        Err(PushPublishError::Rejected {
            code,
            msg: "refused\nsecond line".to_owned(),
        })
    });
    let (sink, _rx) = publisher(system_clock(), answer);
    let mut registrar = registrar(sink, system_clock()).await?;
    let targets = urls
        .iter()
        .map(|url| target(url, &[[1; 32]]))
        .collect::<Result<Vec<_>, _>>()?;
    let results = registrar.register(&targets).await?;
    let outcome = |code: u16| -> Result<&PushError, Box<dyn Error>> {
        match results.get(&format!("wss://relay-{code}.example/scp/v1")) {
            Some(Err(err)) => Ok(err),
            other => Err(format!("relay {code}: {other:?}").into()),
        }
    };
    assert!(matches!(
        outcome(4060)?,
        PushError::RegistrationRejected { .. }
    ));
    assert!(matches!(
        outcome(4061)?,
        PushError::PlatformUnavailable { .. }
    ));
    assert!(matches!(outcome(4062)?, PushError::Stale { .. }));
    assert!(matches!(outcome(4063)?, PushError::NotSupported { .. }));
    assert!(matches!(
        outcome(4064)?,
        PushError::RegistrationLimit { .. }
    ));
    assert!(matches!(
        outcome(5003)?,
        PushError::VerifierUnavailable { .. }
    ));
    assert!(matches!(
        outcome(5004)?,
        PushError::KeyStateUnavailable { .. }
    ));
    assert!(matches!(
        outcome(5000)?,
        PushError::RelayFailed { code: 5000, .. }
    ));
    assert!(matches!(
        outcome(4001)?,
        PushError::RelayRefused { code: 4001, .. }
    ));
    assert!(matches!(outcome(0)?, PushError::Unreachable { .. }));
    for code in [4060, 4061, 4062, 4063, 4064, 4001] {
        assert!(!outcome(code)?.retryable(), "{code} is not retryable");
    }
    for code in [5003, 5004, 5000, 0] {
        assert!(outcome(code)?.retryable(), "{code} is retryable");
    }
    assert!(
        !outcome(4060)?.to_string().contains('\n'),
        "the relay's text is sanitized"
    );
    assert!(
        registrar.registered.is_empty(),
        "no refused relay is recorded"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Criterion 11: clock-bounded timestamps
// ---------------------------------------------------------------------------

/// A clock that reads tokio's (pausable) time, starting mid-second.
struct TokioClock {
    start: tokio::time::Instant,
    base_millis: u64,
}

impl Clock for TokioClock {
    fn now_secs(&self) -> u64 {
        self.now_millis() / 1000
    }
    fn now_millis(&self) -> u64 {
        let elapsed = u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.base_millis.saturating_add(elapsed)
    }
}

/// Five messages to one relay within one second of each other each carry the
/// clock's second at signing: strictly increasing, and never ahead of the
/// clock when the relay receives them.
#[tokio::test(start_paused = true)]
async fn timestamps_strictly_increase_and_never_exceed_clock() -> TestResult {
    let clock: Arc<dyn Clock> = Arc::new(TokioClock {
        start: tokio::time::Instant::now(),
        base_millis: 1_700_000_000_400,
    });
    let (sink, mut rx) = publisher(Arc::clone(&clock), accept_all());
    let mut registrar = registrar(sink, Arc::clone(&clock)).await?;
    let relay = PushRelay::direct(RELAY_A)?;
    for round in 0..5u8 {
        if round % 2 == 0 {
            registrar
                .register(&[target(RELAY_A, &[[round; 32]])?])
                .await?;
        } else {
            registrar.deregister(std::slice::from_ref(&relay)).await?;
        }
    }
    let mut last = None;
    for round in 0..5u8 {
        let published = rx.try_recv()?;
        let timestamp = if round % 2 == 0 {
            PushRegistration::from_msgpack(&published.blob)?.timestamp
        } else {
            PushDeregistration::from_msgpack(&published.blob)?.timestamp
        };
        assert!(
            timestamp <= published.clock_secs,
            "timestamp {timestamp} is ahead of the clock {}",
            published.clock_secs
        );
        assert!(
            last.is_none_or(|last| timestamp > last),
            "round {round} is not newer"
        );
        last = Some(timestamp);
    }
    Ok(())
}

/// A clock whose second the test sets.
struct StepClock(Arc<AtomicU64>);

impl Clock for StepClock {
    fn now_secs(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
    fn now_millis(&self) -> u64 {
        self.now_secs().saturating_mul(1000)
    }
}

/// A clock that stands before the last timestamp sent fails with
/// `ClockBehind`, a retryable error, and publishes nothing.
#[tokio::test]
async fn clock_behind_last_timestamp_is_refused() -> TestResult {
    let seconds = Arc::new(AtomicU64::new(1_700_000_100));
    let clock: Arc<dyn Clock> = Arc::new(StepClock(Arc::clone(&seconds)));
    let (sink, mut rx) = publisher(Arc::clone(&clock), accept_all());
    let mut registrar = registrar(sink, clock).await?;
    registrar.register(&[target(RELAY_A, &[[1; 32]])?]).await?;
    expect_publishes(&mut rx, 1).await?;
    seconds.store(1_700_000_050, Ordering::SeqCst);
    let results = registrar.register(&[target(RELAY_A, &[[2; 32]])?]).await?;
    let outcome = results.get(RELAY_A).ok_or("no result")?;
    assert!(
        matches!(outcome, Err(err @ PushError::ClockBehind { .. }) if err.retryable()),
        "{outcome:?}"
    );
    expect_quiet(&mut rx).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Criterion 13: a failed routing-ID query publishes nothing
// ---------------------------------------------------------------------------

/// A poisoned context fails the routing-ID query; `reconcile` returns the
/// error and publishes nothing, not even for the healthy context's relay.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn routes_failure_publishes_nothing() -> TestResult {
    let sup = supervisor(true);
    create_context(&sup, CTX_A, PSEUDONYM_A, &[RELAY_A]).await?;
    create_context(&sup, CTX_B, PSEUDONYM_B, &[RELAY_B]).await?;
    sup.test_poison_context(&hex::encode(CTX_B)).await;
    let (sink, mut rx) = publisher(system_clock(), accept_all());
    let mut registrar = registrar(sink, system_clock()).await?;

    let result = registrar.reconcile(&sup).await;
    assert!(
        matches!(&result, Err(err @ PushError::Routes(_)) if err.retryable()),
        "{result:?}"
    );
    expect_quiet(&mut rx).await?;
    assert!(registrar.registered.is_empty());
    Ok(())
}

// ---------------------------------------------------------------------------
// Criterion 12: P-256 only
// ---------------------------------------------------------------------------

/// An Ed25519 handle and a P-256 key-agreement handle are both refused.
#[tokio::test]
async fn non_p256_handle_refused() -> TestResult {
    let custody = Arc::new(InMemoryKeyCustody::new());
    for key_type in [KeyType::Ed25519, KeyType::HpkeP256] {
        let handle = custody.generate_keypair(key_type).await?;
        let refused =
            PushSigningKey::for_testing(DID(REGISTRANT.to_owned()), Arc::clone(&custody), handle)
                .await;
        assert!(
            matches!(refused, Err(PushError::SigningKeyNotP256)),
            "{key_type:?} must be refused"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Trigger task: backoff, no retry of 4xxx, shutdown, fail-closed start
// ---------------------------------------------------------------------------

/// The ADR-004 delays: 1, 2, 4, 8, 16, then 30 seconds.
#[test]
fn backoff_follows_adr_004() {
    let delays: Vec<u64> = (0..8).map(|n| backoff_delay(n).as_secs()).collect();
    assert_eq!(delays, vec![1, 2, 4, 8, 16, 30, 30, 30]);
}

/// A relay answering 5003 twice is retried after 1 s and then 2 s, and the
/// third attempt's success ends the retries.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trigger_retries_retryable_failure_with_backoff() -> TestResult {
    let sup = supervisor(true);
    create_context(&sup, CTX_A, PSEUDONYM_A, &[RELAY_A]).await?;
    let answer: Answer = Box::new(|_, attempt| {
        if attempt < 2 {
            Err(PushPublishError::Rejected {
                code: code::PUSH_VERIFIER_UNAVAILABLE,
                msg: String::new(),
            })
        } else {
            Ok(())
        }
    });
    let (sink, mut rx) = publisher(system_clock(), answer);
    let registrar = registrar(sink, system_clock()).await?;
    let shutdown = CancellationToken::new();
    let task = registrar.spawn_trigger(Arc::clone(&sup), shutdown.clone())?;

    let attempts = expect_publishes(&mut rx, 3).await?;
    let first_gap = attempts[1].at.duration_since(attempts[0].at);
    let second_gap = attempts[2].at.duration_since(attempts[1].at);
    assert!(
        first_gap >= Duration::from_secs(1),
        "first retry after {first_gap:?}"
    );
    assert!(
        second_gap >= Duration::from_secs(2),
        "second retry after {second_gap:?}"
    );

    shutdown.cancel();
    tokio::time::timeout(ARRIVAL, task.into_join_handle()).await??;
    Ok(())
}

/// A 4060 is never retried, and a stopped task refuses commands.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trigger_does_not_retry_4xxx_and_stops_on_shutdown() -> TestResult {
    let sup = supervisor(true);
    create_context(&sup, CTX_A, PSEUDONYM_A, &[RELAY_A]).await?;
    let answer: Answer = Box::new(|_, _| {
        Err(PushPublishError::Rejected {
            code: code::PUSH_REGISTRATION_REJECTED,
            msg: String::new(),
        })
    });
    let (sink, mut rx) = publisher(system_clock(), answer);
    let registrar = registrar(sink, system_clock()).await?;
    let shutdown = CancellationToken::new();
    let task = registrar.spawn_trigger(Arc::clone(&sup), shutdown.clone())?;

    tokio::time::timeout(ARRIVAL, rx.recv())
        .await?
        .ok_or("publisher dropped")?;
    // The first retry would come after 1 s.
    match tokio::time::timeout(Duration::from_millis(2500), rx.recv()).await {
        Err(_) | Ok(None) => {}
        Ok(Some(_)) => return Err("a 4060 was retried".into()),
    }

    shutdown.cancel();
    let commands = task.commands.clone();
    tokio::time::timeout(ARRIVAL, task.into_join_handle()).await??;
    let (reply, _answer) = oneshot::channel();
    let refused = commands
        .send(RegistrarCommand::RefreshToken {
            token: NEW_TOKEN.to_vec(),
            reply,
        })
        .await;
    assert!(refused.is_err(), "the stopped task takes no command");
    Ok(())
}

/// The task runs a token refresh between reconciles.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trigger_task_runs_token_refresh() -> TestResult {
    let sup = supervisor(true);
    create_context(&sup, CTX_A, PSEUDONYM_A, &[RELAY_A]).await?;
    let (sink, mut rx) = publisher(system_clock(), accept_all());
    let registrar = registrar(sink, system_clock()).await?;
    let shutdown = CancellationToken::new();
    let task = registrar.spawn_trigger(Arc::clone(&sup), shutdown.clone())?;
    expect_publishes(&mut rx, 1).await?;

    let refresh = task.refresh_token(NEW_TOKEN.to_vec()).await?;
    assert!(refresh.deregistered.get(RELAY_A).is_some_and(Result::is_ok));
    assert!(refresh.registered.get(RELAY_A).is_some_and(Result::is_ok));
    expect_publishes(&mut rx, 2).await?;

    shutdown.cancel();
    tokio::time::timeout(ARRIVAL, task.into_join_handle()).await??;
    Ok(())
}

/// A supervisor with no context-event channel gets no trigger task.
#[tokio::test]
async fn spawn_trigger_without_events_fails_closed() -> TestResult {
    let (sink, _rx) = publisher(system_clock(), accept_all());
    let registrar = registrar(sink, system_clock()).await?;
    let result = registrar.spawn_trigger(supervisor(false), CancellationToken::new());
    assert!(matches!(result, Err(PushError::EventsUnavailable)));
    Ok(())
}
