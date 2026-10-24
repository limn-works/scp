//! Tests for the push registrar (PUSH-014). The relay-backed tests live in
//! `scp-transport`'s `native::push_publisher`.

use std::error::Error;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

use scp_clock::TestClock;
use scp_platform::KeyType;
use scp_platform::in_memory::InMemoryStorage;
use scp_platform::testing::InMemoryKeyCustody;
use scp_protocol::context::membership::KeyPackage;

use super::*;
use crate::context::ContextHandle;
use crate::context::supervisor::faulty_storage::FaultyStorage;

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
const CTX_C: [u8; 32] = [0xC0; 32];
const PSEUDONYM_C: [u8; 32] = [0xC1; 32];
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

type Ledger = Arc<ProtocolRepository<InMemoryStorage>>;

fn ledger() -> Ledger {
    Arc::new(ProtocolRepository::new_for_testing(InMemoryStorage::new()))
}

async fn registrar(
    publisher: Arc<dyn PushRelayPublisher>,
    clock: Arc<dyn Clock>,
) -> Result<PushRegistrar<InMemoryKeyCustody, InMemoryStorage>, Box<dyn Error>> {
    registrar_on(publisher, clock, ledger()).await
}

async fn registrar_on<S: Storage>(
    publisher: Arc<dyn PushRelayPublisher>,
    clock: Arc<dyn Clock>,
    storage: Arc<ProtocolRepository<S>>,
) -> Result<PushRegistrar<InMemoryKeyCustody, S>, Box<dyn Error>> {
    let signing_key = signing_key().await?;
    Ok(PushRegistrar::new(PushRegistrarConfig {
        signing_key,
        publisher,
        clock,
        platform: PushPlatform::Apns,
        token: PushToken::new(TOKEN.to_vec()),
        storage,
    })
    .await?)
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

/// A supervisor with real context actors and a context-event channel.
fn supervisor() -> Arc<Supervisor> {
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
        Some(tokio::sync::broadcast::channel(256).0),
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

/// Runs one task command through the registrar's command handler, without
/// the task, and returns the command's reply. No backoff retry or route
/// change can run between two such calls.
async fn run_command<S: Storage>(
    registrar: &mut PushRegistrar<InMemoryKeyCustody, S>,
    sup: &Supervisor,
    command: impl FnOnce(oneshot::Sender<Result<RelayOutcomes, PushError>>) -> RegistrarCommand,
) -> Result<RelayOutcomes, Box<dyn Error>> {
    let (reply, answer) = oneshot::channel();
    registrar.handle_command(command(reply), sup).await;
    Ok(answer.await??)
}

/// Every publish already in the channel. A publish is recorded before the
/// registrar awaits it, so after an operation returns its publishes are all
/// here.
fn drain(rx: &mut mpsc::UnboundedReceiver<Published>) -> Vec<Published> {
    let mut got = Vec::new();
    while let Ok(next) = rx.try_recv() {
        got.push(next);
    }
    got
}

// ---------------------------------------------------------------------------
// Criterion 2: re-registration on join, nothing on an unchanged set
// ---------------------------------------------------------------------------

/// A join that sets this device's pseudonym in a context on relay A changes
/// relay A's routing IDs only: the trigger task sends relay A one
/// registration with the new pseudonym and sends relay B nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn join_triggers_exactly_one_reregistration_on_affected_relay() -> TestResult {
    let sup = supervisor();
    let handle_a = create_context(&sup, CTX_A, PSEUDONYM_A, &[RELAY_A]).await?;
    create_context(&sup, CTX_B, PSEUDONYM_B, &[RELAY_B]).await?;
    let (sink, mut rx) = publisher(system_clock(), accept_all());
    let registrar = registrar(sink, system_clock()).await?;
    let public_key = *registrar.signing_key.public_key();
    let shutdown = CancellationToken::new();
    let task = registrar.spawn_trigger(Arc::clone(&sup), shutdown.clone());

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
    let sup = supervisor();
    let handle_a = create_context(&sup, CTX_A, PSEUDONYM_A, &[RELAY_A]).await?;
    create_context(&sup, CTX_B, PSEUDONYM_B, &[RELAY_B]).await?;
    let (sink, mut rx) = publisher(system_clock(), accept_all());
    let registrar = registrar(sink, system_clock()).await?;
    let shutdown = CancellationToken::new();
    let task = registrar.spawn_trigger(Arc::clone(&sup), shutdown.clone());
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

/// A context created after the task started reaches the registrar through
/// the route watch alone: its relay gets exactly one registration, holding
/// the context's pseudonym, and the other relay nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn context_created_after_start_registers_once() -> TestResult {
    let sup = supervisor();
    create_context(&sup, CTX_A, PSEUDONYM_A, &[RELAY_A]).await?;
    let (sink, mut rx) = publisher(system_clock(), accept_all());
    let registrar = registrar(sink, system_clock()).await?;
    let public_key = *registrar.signing_key.public_key();
    let shutdown = CancellationToken::new();
    let task = registrar.spawn_trigger(Arc::clone(&sup), shutdown.clone());
    expect_publishes(&mut rx, 1).await?;

    create_context(&sup, CTX_B, PSEUDONYM_B, &[RELAY_B]).await?;
    let after = expect_publishes(&mut rx, 1).await?;
    assert_eq!(after[0].relay_url, RELAY_B, "only the new context's relay");
    let registration = verified_registration(&after[0], &public_key)?;
    assert!(registration.routing_ids.contains(&PSEUDONYM_B));

    shutdown.cancel();
    tokio::time::timeout(ARRIVAL, task.into_join_handle()).await??;
    Ok(())
}

/// `discard_joined_context` after the task started removes the device's
/// last context on relay A, and relay A gets a deregistration.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn discard_joined_context_after_start_deregisters() -> TestResult {
    let sup = supervisor();
    create_context(&sup, CTX_A, PSEUDONYM_A, &[RELAY_A]).await?;
    create_context(&sup, CTX_B, PSEUDONYM_B, &[RELAY_B]).await?;
    let (sink, mut rx) = publisher(system_clock(), accept_all());
    let registrar = registrar(sink, system_clock()).await?;
    let public_key = *registrar.signing_key.public_key();
    let shutdown = CancellationToken::new();
    let task = registrar.spawn_trigger(Arc::clone(&sup), shutdown.clone());
    expect_publishes(&mut rx, 2).await?;

    assert!(sup.discard_joined_context(&hex::encode(CTX_A)).await?);
    let after = expect_publishes(&mut rx, 1).await?;
    assert_eq!(after[0].relay_url, RELAY_A);
    let deregistration = verified_deregistration(&after[0], &public_key)?;
    assert_eq!(deregistration.token, TOKEN);

    shutdown.cancel();
    tokio::time::timeout(ARRIVAL, task.into_join_handle()).await??;
    Ok(())
}

// ---------------------------------------------------------------------------
// Criterion 3: no context ID on the wire or in the preimage
// ---------------------------------------------------------------------------

/// The registration and its preimage carry the context's routing ID and the
/// device's pseudonym, never the context ID in raw or hex form.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn preimage_contains_no_context_id() -> TestResult {
    let sup = supervisor();
    create_context(&sup, CTX_A, PSEUDONYM_A, &[RELAY_A]).await?;
    let (sink, mut rx) = publisher(system_clock(), accept_all());
    let mut registrar = registrar(sink, system_clock()).await?;
    let public_key = *registrar.signing_key.public_key();

    let results = registrar.reconcile(&sup).await?;
    assert!(
        results.registered.get(RELAY_A).is_some_and(Result::is_ok),
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
// Criterion 5: bridge_target and tier 3
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
// Criteria 6 and 7: deregistration, last context, token refresh
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
    assert_eq!(registrar.accepted.len(), 2);

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
    assert!(registrar.accepted.is_empty(), "both relays are forgotten");
    Ok(())
}

/// When the device's last context on relay A goes away, the trigger task
/// sends relay A a deregistration and no registration, and relay B nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn leaving_last_context_on_relay_deregisters() -> TestResult {
    let sup = supervisor();
    create_context(&sup, CTX_A, PSEUDONYM_A, &[RELAY_A]).await?;
    create_context(&sup, CTX_B, PSEUDONYM_B, &[RELAY_B]).await?;
    let (sink, mut rx) = publisher(system_clock(), accept_all());
    let registrar = registrar(sink, system_clock()).await?;
    let public_key = *registrar.signing_key.public_key();
    let shutdown = CancellationToken::new();
    let task = registrar.spawn_trigger(Arc::clone(&sup), shutdown.clone());
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

    let refresh = registrar
        .refresh_token(PushToken::new(NEW_TOKEN.to_vec()))
        .await?;
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
        registrar.refresh_token(PushToken::new(Vec::new())).await,
        Err(PushError::Message(PushMessageError::EmptyToken))
    ));
    assert_eq!(
        registrar.token.as_bytes(),
        NEW_TOKEN,
        "a refused refresh keeps the token"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Input validation: one relay named twice
// ---------------------------------------------------------------------------

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
// Criterion 8: wire codes
// ---------------------------------------------------------------------------

/// Each relay code maps to its own variant; 4062, 5003, 5004, other 5xxx
/// codes and an unreachable relay are retryable, and 4060, 4061, 4063 and
/// 4064 are not.
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
    for code in [4060, 4061, 4063, 4064, 4001] {
        assert!(!outcome(code)?.retryable(), "{code} is not retryable");
        assert!(outcome(code)?.is_terminal_refusal(), "{code} is terminal");
    }
    for code in [4062, 5003, 5004, 5000, 0] {
        assert!(outcome(code)?.retryable(), "{code} is retryable");
        assert!(
            !outcome(code)?.is_terminal_refusal(),
            "{code} is not terminal"
        );
    }
    assert!(
        !outcome(4060)?.to_string().contains('\n'),
        "the relay's text is sanitized"
    );
    assert!(
        registrar.accepted.is_empty(),
        "no refused relay is recorded"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Criterion 9: clock-bounded timestamps
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

/// An entry that is within the skew window stays when another relay's send
/// prunes the map: after the clock steps back 5 s, a message to the first
/// relay is refused with `ClockBehind` rather than sent with a timestamp at
/// or below one the relay holds.
#[tokio::test]
async fn clock_step_back_within_skew_window_is_refused() -> TestResult {
    const T: u64 = 1_700_000_100;
    let seconds = Arc::new(AtomicU64::new(T));
    let clock: Arc<dyn Clock> = Arc::new(StepClock(Arc::clone(&seconds)));
    let (sink, mut rx) = publisher(Arc::clone(&clock), accept_all());
    let mut registrar = registrar(sink, clock).await?;
    registrar.register(&[target(RELAY_A, &[[1; 32]])?]).await?;
    seconds.store(T + 1, Ordering::SeqCst);
    registrar.register(&[target(RELAY_B, &[[1; 32]])?]).await?;
    expect_publishes(&mut rx, 2).await?;

    seconds.store(T - 4, Ordering::SeqCst);
    let results = registrar.register(&[target(RELAY_A, &[[2; 32]])?]).await?;
    let outcome = results.get(RELAY_A).ok_or("no result")?;
    assert!(
        matches!(outcome, Err(PushError::ClockBehind { now, last }) if *now == T - 4 && *last == T),
        "{outcome:?}"
    );
    expect_quiet(&mut rx).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Criterion 11: a failed routing-ID query publishes nothing
// ---------------------------------------------------------------------------

/// A poisoned context fails the routing-ID query; `reconcile` returns the
/// error and publishes nothing, not even for the healthy context's relay.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn routes_failure_publishes_nothing() -> TestResult {
    let sup = supervisor();
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
    assert!(registrar.accepted.is_empty());
    Ok(())
}

// ---------------------------------------------------------------------------
// Criterion 10: P-256 only
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
    let sup = supervisor();
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
    let task = registrar.spawn_trigger(Arc::clone(&sup), shutdown.clone());

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
    let sup = supervisor();
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
    let task = registrar.spawn_trigger(Arc::clone(&sup), shutdown.clone());

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
            token: PushToken::new(NEW_TOKEN.to_vec()),
            reply,
        })
        .await;
    assert!(refused.is_err(), "the stopped task takes no command");
    Ok(())
}

/// The task runs a token refresh between reconciles.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trigger_task_runs_token_refresh() -> TestResult {
    let sup = supervisor();
    create_context(&sup, CTX_A, PSEUDONYM_A, &[RELAY_A]).await?;
    let (sink, mut rx) = publisher(system_clock(), accept_all());
    let registrar = registrar(sink, system_clock()).await?;
    let shutdown = CancellationToken::new();
    let task = registrar.spawn_trigger(Arc::clone(&sup), shutdown.clone());
    expect_publishes(&mut rx, 1).await?;

    let refresh = task
        .refresh_token(PushToken::new(NEW_TOKEN.to_vec()))
        .await?;
    assert!(refresh.deregistered.get(RELAY_A).is_some_and(Result::is_ok));
    assert!(refresh.registered.get(RELAY_A).is_some_and(Result::is_ok));
    expect_publishes(&mut rx, 2).await?;

    shutdown.cancel();
    tokio::time::timeout(ARRIVAL, task.into_join_handle()).await??;
    Ok(())
}

/// A token refresh whose new-token registration fails once with 5003 is
/// retried by the task after the backoff, with no other trigger.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refresh_retries_a_retryable_registration_failure() -> TestResult {
    let sup = supervisor();
    create_context(&sup, CTX_A, PSEUDONYM_A, &[RELAY_A]).await?;
    // Attempt 0 is the start registration, 1 the old token's
    // deregistration, 2 the new token's registration.
    let answer: Answer = Box::new(|_, attempt| {
        if attempt == 2 {
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
    let public_key = *registrar.signing_key.public_key();
    let shutdown = CancellationToken::new();
    let task = registrar.spawn_trigger(Arc::clone(&sup), shutdown.clone());
    expect_publishes(&mut rx, 1).await?;

    let refresh = task
        .refresh_token(PushToken::new(NEW_TOKEN.to_vec()))
        .await?;
    assert!(
        matches!(
            refresh.registered.get(RELAY_A),
            Some(Err(PushError::VerifierUnavailable { .. }))
        ),
        "{refresh:?}"
    );
    let sent = expect_publishes(&mut rx, 3).await?;
    assert_eq!(verified_deregistration(&sent[0], &public_key)?.token, TOKEN);
    assert_eq!(
        verified_registration(&sent[1], &public_key)?.token,
        NEW_TOKEN
    );
    let retry = verified_registration(&sent[2], &public_key)?;
    assert_eq!(retry.token, NEW_TOKEN, "the retry registers the new token");
    assert!(
        sent[2].at.duration_since(sent[1].at) >= Duration::from_secs(1),
        "the retry waits for the backoff"
    );

    shutdown.cancel();
    tokio::time::timeout(ARRIVAL, task.into_join_handle()).await??;
    Ok(())
}

// ---------------------------------------------------------------------------
// ADR-004: a 4xxx refusal is not sent again
// ---------------------------------------------------------------------------

/// Relay A answers 4063 and relay B 5003. The task's backoff retries reach
/// relay B only; relay A receives exactly one message.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_relay_is_not_retried_with_a_retryable_one() -> TestResult {
    let sup = supervisor();
    create_context(&sup, CTX_A, PSEUDONYM_A, &[RELAY_A]).await?;
    create_context(&sup, CTX_B, PSEUDONYM_B, &[RELAY_B]).await?;
    let answer: Answer = Box::new(|url, _| {
        let code = if url == RELAY_A {
            code::PUSH_NOT_SUPPORTED
        } else {
            code::PUSH_VERIFIER_UNAVAILABLE
        };
        Err(PushPublishError::Rejected {
            code,
            msg: String::new(),
        })
    });
    let (sink, mut rx) = publisher(system_clock(), answer);
    let registrar = registrar(sink, system_clock()).await?;
    let shutdown = CancellationToken::new();
    let task = registrar.spawn_trigger(Arc::clone(&sup), shutdown.clone());

    // Retries come after 1 s and 3 s; watch past the second one.
    let mut seen = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_millis(3_800);
    while let Ok(Some(next)) = tokio::time::timeout_at(deadline, rx.recv()).await {
        seen.push(next.relay_url);
    }
    let at = |url: &str| seen.iter().filter(|seen| *seen == url).count();
    assert_eq!(
        at(RELAY_A),
        1,
        "the 4063 relay is sent one message: {seen:?}"
    );
    assert!(at(RELAY_B) >= 3, "the 5003 relay is retried: {seen:?}");

    shutdown.cancel();
    tokio::time::timeout(ARRIVAL, task.into_join_handle()).await??;
    Ok(())
}

/// A relay that answers 4062 once gets a new registration after the 1 s
/// backoff, signed with a larger `timestamp`, and accepts it. The retry is a
/// new request, so ADR-004's rule against resending a `4xxx` request as-is
/// does not stop it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_registration_is_retried_with_a_newer_timestamp() -> TestResult {
    let sup = supervisor();
    create_context(&sup, CTX_A, PSEUDONYM_A, &[RELAY_A]).await?;
    let answer: Answer = Box::new(|_, attempt| {
        if attempt == 0 {
            Err(PushPublishError::Rejected {
                code: code::PUSH_REGISTRATION_STALE,
                msg: String::new(),
            })
        } else {
            Ok(())
        }
    });
    let (sink, mut rx) = publisher(system_clock(), answer);
    let registrar = registrar(sink, system_clock()).await?;
    let public_key = *registrar.signing_key.public_key();
    let shutdown = CancellationToken::new();
    let task = registrar.spawn_trigger(Arc::clone(&sup), shutdown.clone());

    let sent = expect_publishes(&mut rx, 2).await?;
    let refused = verified_registration(&sent[0], &public_key)?;
    let retry = verified_registration(&sent[1], &public_key)?;
    assert_eq!(sent[1].relay_url, RELAY_A);
    assert_eq!(retry.routing_ids, refused.routing_ids, "the same set");
    assert!(
        retry.timestamp > refused.timestamp,
        "the retry carries a newer timestamp: {} then {}",
        refused.timestamp,
        retry.timestamp
    );
    assert!(
        sent[1].at.duration_since(sent[0].at) >= Duration::from_secs(1),
        "the retry waits for the backoff"
    );

    shutdown.cancel();
    tokio::time::timeout(ARRIVAL, task.into_join_handle()).await??;
    Ok(())
}

/// The device clock's second at the start of each `4062` bound test.
const T0: u64 = 1_700_000_000;
/// The device-clock step between two attempts in the `4062` bound tests: the
/// ADR-004 backoff's 30 s cap, at which a relay that keeps answering `4062`
/// is retried.
const RETRY_STEP: u64 = 30;
/// More attempts than the bound allows at [`RETRY_STEP`], so a registrar that
/// never stops fails the test instead of looping.
const MAX_ATTEMPTS: u64 = 2 * STALE_RUN_BOUND_SECS / RETRY_STEP;

fn stale_answer() -> Result<(), PushPublishError> {
    Err(PushPublishError::Rejected {
        code: code::PUSH_REGISTRATION_STALE,
        msg: "timestamp outside the skew window".to_owned(),
    })
}

/// Which `4062` outcome one attempt produced.
enum StaleStep {
    /// A retryable `Stale`, which arms the task's backoff.
    Retry,
    /// The terminal `StaleBeyondSkew`, with its span.
    Bound(u64),
}

/// Classifies the outcome of one attempt on relay A. Each attempt must be one
/// publish; a retryable `Stale` must arm the task's backoff and the terminal
/// refusal must not.
fn stale_step(
    outcome: RelayOutcomes,
    deregistration: bool,
    rx: &mut mpsc::UnboundedReceiver<Published>,
) -> Result<StaleStep, Box<dyn Error>> {
    let sent = drain(rx);
    if sent.len() != 1 || sent[0].relay_url != RELAY_A {
        return Err(format!("one publish to relay A per attempt, got {}", sent.len()).into());
    }
    let results = if deregistration {
        &outcome.deregistered
    } else {
        &outcome.registered
    };
    let step = match results.get(RELAY_A) {
        Some(Err(err @ PushError::Stale { .. })) if err.retryable() => StaleStep::Retry,
        Some(Err(err @ PushError::StaleBeyondSkew { span_secs, .. }))
            if !err.retryable() && err.is_terminal_refusal() =>
        {
            StaleStep::Bound(*span_secs)
        }
        other => return Err(format!("unexpected outcome at relay A: {other:?}").into()),
    };
    let retry = log_outcome("test", &Ok(outcome));
    assert_eq!(
        retry,
        matches!(step, StaleStep::Retry),
        "a 4062 inside the bound arms the backoff, the bound's refusal does not"
    );
    Ok(step)
}

/// Reconciles every [`RETRY_STEP`] seconds of `clock` until relay A's
/// outcome is the terminal `StaleBeyondSkew`, and returns how many retryable
/// `Stale` outcomes came first.
async fn reconcile_until_bound<S: Storage>(
    registrar: &mut PushRegistrar<InMemoryKeyCustody, S>,
    sup: &Supervisor,
    clock: &TestClock,
    rx: &mut mpsc::UnboundedReceiver<Published>,
    deregistration: bool,
) -> Result<u64, Box<dyn Error>> {
    let first = clock.now_secs();
    let mut retries = 0;
    for _ in 0..MAX_ATTEMPTS {
        match stale_step(registrar.reconcile(sup).await?, deregistration, rx)? {
            StaleStep::Retry => {
                assert!(
                    clock.now_secs() - first <= STALE_RUN_BOUND_SECS,
                    "a 4062 {} s after the first is still retried",
                    clock.now_secs() - first
                );
                retries += 1;
            }
            StaleStep::Bound(span_secs) => {
                assert_eq!(span_secs, clock.now_secs() - first);
                assert!(span_secs > STALE_RUN_BOUND_SECS, "{span_secs}");
                return Ok(retries);
            }
        }
        clock.advance(RETRY_STEP);
    }
    Err(format!("the relay was still sent a message after {MAX_ATTEMPTS} attempts of 4062").into())
}

/// The device clock runs 400 s behind relay A's, so relay A answers `4062`
/// to every registration. Each attempt, 30 s apart on the device clock, is
/// one registration and a retryable `Stale` while the run spans at most
/// `STALE_RUN_BOUND_SECS`; the first `4062` past that becomes the
/// terminal `StaleBeyondSkew`, and later reconciles send relay A nothing. A
/// `register` command clears the refusal and relay A is sent the
/// registration again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn always_stale_relay_stops_getting_registrations_after_skew_bound() -> TestResult {
    let sup = supervisor();
    create_context(&sup, CTX_A, PSEUDONYM_A, &[RELAY_A]).await?;
    let clock = Arc::new(TestClock::new(T0));
    let dyn_clock: Arc<dyn Clock> = Arc::clone(&clock) as Arc<dyn Clock>;
    let (sink, mut rx) = publisher(Arc::clone(&dyn_clock), Box::new(|_, _| stale_answer()));
    let mut registrar = registrar(sink, dyn_clock).await?;

    let retries = reconcile_until_bound(&mut registrar, &sup, &clock, &mut rx, false).await?;
    assert_eq!(
        retries,
        STALE_RUN_BOUND_SECS / RETRY_STEP + 1,
        "every 4062 from T0 to T0 + twice the skew window is retried"
    );
    for _ in 0..3 {
        clock.advance(RETRY_STEP);
        let outcome = registrar.reconcile(&sup).await?;
        assert!(outcome.registered.is_empty(), "{outcome:?}");
        assert!(outcome.deregistered.is_empty(), "{outcome:?}");
        assert!(drain(&mut rx).is_empty(), "relay A is sent nothing more");
    }

    clock.advance(RETRY_STEP);
    let outcome = run_command(&mut registrar, &sup, |reply| RegistrarCommand::Register {
        reply,
    })
    .await?;
    assert!(
        matches!(stale_step(outcome, false, &mut rx)?, StaleStep::Retry),
        "a register command sends relay A the registration again, in a new run"
    );
    Ok(())
}

/// Relay A accepted the registration, the device then leaves its context
/// there, and relay A answers `4062` to every deregistration. The
/// deregistrations stop at the same bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn always_stale_relay_stops_getting_deregistrations_after_skew_bound() -> TestResult {
    let sup = supervisor();
    create_context(&sup, CTX_A, PSEUDONYM_A, &[RELAY_A]).await?;
    let clock = Arc::new(TestClock::new(T0));
    let dyn_clock: Arc<dyn Clock> = Arc::clone(&clock) as Arc<dyn Clock>;
    let answer: Answer = Box::new(|_, attempt| if attempt == 0 { Ok(()) } else { stale_answer() });
    let (sink, mut rx) = publisher(Arc::clone(&dyn_clock), answer);
    let mut registrar = registrar(sink, dyn_clock).await?;
    let first = registrar.reconcile(&sup).await?;
    assert!(
        first.registered.get(RELAY_A).is_some_and(Result::is_ok),
        "{first:?}"
    );
    assert_eq!(drain(&mut rx).len(), 1);

    assert!(sup.despawn_actor(&hex::encode(CTX_A)).await);
    clock.advance(RETRY_STEP);
    let retries = reconcile_until_bound(&mut registrar, &sup, &clock, &mut rx, true).await?;
    assert_eq!(retries, STALE_RUN_BOUND_SECS / RETRY_STEP + 1);
    for _ in 0..3 {
        clock.advance(RETRY_STEP);
        let outcome = registrar.reconcile(&sup).await?;
        assert!(outcome.deregistered.is_empty(), "{outcome:?}");
        assert!(drain(&mut rx).is_empty(), "relay A is sent nothing more");
    }
    Ok(())
}

/// Relay A holds a `timestamp` floor `ahead_secs` ahead of the device clock,
/// for example from before a restart, and answers `4062` until the device
/// clock passes it. The registration retried after that is accepted, inside
/// the bound, and leaves no refusal and no open run. Returns how many
/// retryable `4062` answers came first.
async fn register_past_floor(ahead_secs: u64) -> Result<u64, Box<dyn Error>> {
    let floor = T0 + ahead_secs;
    let sup = supervisor();
    create_context(&sup, CTX_A, PSEUDONYM_A, &[RELAY_A]).await?;
    let clock = Arc::new(TestClock::new(T0));
    let dyn_clock: Arc<dyn Clock> = Arc::clone(&clock) as Arc<dyn Clock>;
    let relay_clock = Arc::clone(&clock);
    let answer: Answer = Box::new(move |_, _| {
        if relay_clock.now_secs() <= floor {
            stale_answer()
        } else {
            Ok(())
        }
    });
    let (sink, mut rx) = publisher(Arc::clone(&dyn_clock), answer);
    let mut registrar = registrar(sink, dyn_clock).await?;
    let public_key = *registrar.signing_key.public_key();

    let mut retries = 0;
    let accepted = loop {
        let outcome = registrar.reconcile(&sup).await?;
        if outcome.registered.get(RELAY_A).is_some_and(Result::is_ok) {
            break drain(&mut rx);
        }
        assert!(
            matches!(stale_step(outcome, false, &mut rx)?, StaleStep::Retry),
            "a 4062 below the floor is retried"
        );
        retries += 1;
        assert!(retries < MAX_ATTEMPTS, "the floor never cleared");
        clock.advance(RETRY_STEP);
    };
    assert_eq!(accepted.len(), 1);
    let registration = verified_registration(&accepted[0], &public_key)?;
    assert!(registration.timestamp > floor);
    assert!(registrar.refused.is_empty() && registrar.stale_runs.is_empty());
    assert!(registrar.accepted.contains_key(RELAY_A));

    clock.advance(RETRY_STEP);
    let outcome = registrar.reconcile(&sup).await?;
    assert!(outcome.registered.is_empty(), "{outcome:?}");
    assert!(
        drain(&mut rx).is_empty(),
        "the accepted set is not sent again"
    );
    Ok(retries)
}

/// A floor 100 s ahead clears after four `4062` answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_floor_that_clears_inside_the_bound_registers() -> TestResult {
    assert_eq!(
        register_past_floor(100).await?,
        4,
        "4062 at T0, +30, +60 and +90"
    );
    Ok(())
}

/// A floor 350 s ahead, which a relay whose clock runs up to the skew window
/// ahead of the device's can hold, clears after more than the skew window of
/// the device clock: twelve `4062` answers, at T0 to T0 + 330, then the
/// registration at T0 + 360 is accepted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_floor_beyond_one_skew_window_still_registers() -> TestResult {
    assert_eq!(register_past_floor(350).await?, 12);
    Ok(())
}

/// The registrar's key for relay A under the first token.
fn relay_a_key() -> RelayKey {
    (
        RELAY_A.to_owned(),
        token_hash(&PushToken::new(TOKEN.to_vec())),
    )
}

/// A registrar on a [`TestClock`] at [`T0`] whose relay answers each publish
/// with `answer`, and the device's context on relay A.
async fn clocked_registrar(
    answer: Answer,
) -> Result<
    (
        Arc<Supervisor>,
        Arc<TestClock>,
        PushRegistrar<InMemoryKeyCustody, InMemoryStorage>,
        mpsc::UnboundedReceiver<Published>,
    ),
    Box<dyn Error>,
> {
    let sup = supervisor();
    create_context(&sup, CTX_A, PSEUDONYM_A, &[RELAY_A]).await?;
    let clock = Arc::new(TestClock::new(T0));
    let dyn_clock: Arc<dyn Clock> = Arc::clone(&clock) as Arc<dyn Clock>;
    let (sink, rx) = publisher(Arc::clone(&dyn_clock), answer);
    let registrar = registrar(sink, dyn_clock).await?;
    Ok((sup, clock, registrar, rx))
}

/// Relay A answers `4062` at T0, is unreachable at T0 + 200 and answers
/// `4062` again past the bound. The unreachable attempt gave no answer, so
/// it neither ends nor restarts the run, and the last `4062` is the terminal
/// `StaleBeyondSkew` over the whole span.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unreachable_relay_neither_ends_nor_restarts_a_stale_run() -> TestResult {
    let answer: Answer = Box::new(|_, attempt| {
        if attempt == 1 {
            Err(PushPublishError::Unreachable {
                reason: "connection refused".to_owned(),
            })
        } else {
            stale_answer()
        }
    });
    let (sup, clock, mut registrar, mut rx) = clocked_registrar(answer).await?;
    assert!(matches!(
        stale_step(registrar.reconcile(&sup).await?, false, &mut rx)?,
        StaleStep::Retry
    ));

    clock.set(T0 + 200);
    let outcome = registrar.reconcile(&sup).await?;
    assert!(
        matches!(
            outcome.registered.get(RELAY_A),
            Some(Err(PushError::Unreachable { .. }))
        ),
        "{outcome:?}"
    );
    assert_eq!(drain(&mut rx).len(), 1);

    clock.set(T0 + STALE_RUN_BOUND_SECS + RETRY_STEP);
    match stale_step(registrar.reconcile(&sup).await?, false, &mut rx)? {
        StaleStep::Bound(span_secs) => {
            assert_eq!(span_secs, STALE_RUN_BOUND_SECS + RETRY_STEP);
        }
        StaleStep::Retry => return Err("the unreachable attempt restarted the run".into()),
    }
    Ok(())
}

/// Relay A answers `4062` at T0, `5003` at T0 + 200 and `4062` again past
/// the bound measured from T0. The `5003` answered the request, so it ended
/// the run, and the last `4062` starts a new run and is retried.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn other_relay_answer_ends_a_stale_run() -> TestResult {
    let answer: Answer = Box::new(|_, attempt| {
        if attempt == 1 {
            Err(PushPublishError::Rejected {
                code: code::PUSH_VERIFIER_UNAVAILABLE,
                msg: String::new(),
            })
        } else {
            stale_answer()
        }
    });
    let (sup, clock, mut registrar, mut rx) = clocked_registrar(answer).await?;
    assert!(matches!(
        stale_step(registrar.reconcile(&sup).await?, false, &mut rx)?,
        StaleStep::Retry
    ));

    clock.set(T0 + 200);
    let outcome = registrar.reconcile(&sup).await?;
    assert!(
        matches!(
            outcome.registered.get(RELAY_A),
            Some(Err(PushError::VerifierUnavailable { .. }))
        ),
        "{outcome:?}"
    );
    assert_eq!(drain(&mut rx).len(), 1);
    assert!(registrar.stale_runs.is_empty(), "the 5003 ended the run");

    let late = T0 + STALE_RUN_BOUND_SECS + RETRY_STEP;
    clock.set(late);
    assert!(
        matches!(
            stale_step(registrar.reconcile(&sup).await?, false, &mut rx)?,
            StaleStep::Retry
        ),
        "a 4062 after the 5003 starts a new run"
    );
    assert_eq!(
        registrar
            .stale_runs
            .get(&relay_a_key())
            .map(|run| run.first_secs),
        Some(late)
    );
    Ok(())
}

/// Relay A refuses the registration with `4060`. A `register` command clears
/// only the refusals the skew bound recorded, so relay A is not sent the
/// refused registration again (ADR-004).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn register_command_keeps_a_code_refusal() -> TestResult {
    let answer: Answer = Box::new(|_, attempt| {
        if attempt == 0 {
            Err(PushPublishError::Rejected {
                code: code::PUSH_REGISTRATION_REJECTED,
                msg: String::new(),
            })
        } else {
            Ok(())
        }
    });
    let (sup, clock, mut registrar, mut rx) = clocked_registrar(answer).await?;
    let outcome = registrar.reconcile(&sup).await?;
    assert!(
        outcome
            .registered
            .get(RELAY_A)
            .is_some_and(|result| result.as_ref().is_err_and(PushError::is_terminal_refusal)),
        "{outcome:?}"
    );
    assert_eq!(drain(&mut rx).len(), 1);

    clock.advance(RETRY_STEP);
    let outcome = run_command(&mut registrar, &sup, |reply| RegistrarCommand::Register {
        reply,
    })
    .await?;
    assert!(outcome.registered.is_empty(), "{outcome:?}");
    assert!(
        drain(&mut rx).is_empty(),
        "a register command does not resend a 4060-refused registration"
    );
    Ok(())
}

/// Relay A answers `4062` from T0. A `register` command at T0 + 200 sends the
/// registration again in a new run, so a `4062` past the bound measured from
/// T0 is still retried: the run now starts at T0 + 200.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn register_command_restarts_an_open_stale_run() -> TestResult {
    let (sup, clock, mut registrar, mut rx) =
        clocked_registrar(Box::new(|_, _| stale_answer())).await?;
    assert!(matches!(
        stale_step(registrar.reconcile(&sup).await?, false, &mut rx)?,
        StaleStep::Retry
    ));

    clock.set(T0 + 200);
    let outcome = run_command(&mut registrar, &sup, |reply| RegistrarCommand::Register {
        reply,
    })
    .await?;
    assert!(matches!(
        stale_step(outcome, false, &mut rx)?,
        StaleStep::Retry
    ));

    clock.set(T0 + STALE_RUN_BOUND_SECS + RETRY_STEP);
    assert!(
        matches!(
            stale_step(registrar.reconcile(&sup).await?, false, &mut rx)?,
            StaleStep::Retry
        ),
        "the run restarted at the register command"
    );
    assert_eq!(
        registrar
            .stale_runs
            .get(&relay_a_key())
            .map(|run| run.first_secs),
        Some(T0 + 200)
    );
    Ok(())
}

/// Relay A refuses the deregistration of the first token past the skew
/// bound. A token refresh does not send that deregistration again, nor does
/// a later reconcile, and the refusal stays; a `deregister_all` command
/// clears it and sends relay A the deregistration of the first token.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deregistration_skew_refusal_survives_refresh_until_deregister_all() -> TestResult {
    let answer: Answer = Box::new(|_, attempt| if attempt == 0 { Ok(()) } else { stale_answer() });
    let (sup, clock, mut registrar, mut rx) = clocked_registrar(answer).await?;
    let public_key = *registrar.signing_key.public_key();
    let first = registrar.reconcile(&sup).await?;
    assert!(
        first.registered.get(RELAY_A).is_some_and(Result::is_ok),
        "{first:?}"
    );
    assert_eq!(drain(&mut rx).len(), 1);
    assert!(sup.despawn_actor(&hex::encode(CTX_A)).await);
    clock.advance(RETRY_STEP);
    reconcile_until_bound(&mut registrar, &sup, &clock, &mut rx, true).await?;
    let skew_refusal = |registrar: &PushRegistrar<InMemoryKeyCustody, InMemoryStorage>| {
        registrar
            .refused
            .get(&relay_a_key())
            .is_some_and(|refusal| {
                refusal.request == Request::Deregistration
                    && refusal.cause == RefusalCause::StaleBeyondSkew
            })
    };
    assert!(skew_refusal(&registrar));

    clock.advance(RETRY_STEP);
    let outcome = registrar
        .refresh_token(PushToken::new(NEW_TOKEN.to_vec()))
        .await?;
    assert!(outcome.deregistered.is_empty(), "{outcome:?}");
    assert!(outcome.registered.is_empty(), "{outcome:?}");
    assert!(
        drain(&mut rx).is_empty(),
        "the refresh does not resend the refused deregistration"
    );
    assert!(
        skew_refusal(&registrar),
        "the token change keeps the refusal"
    );

    clock.advance(RETRY_STEP);
    let outcome = registrar.reconcile(&sup).await?;
    assert!(outcome.deregistered.is_empty(), "{outcome:?}");
    assert!(drain(&mut rx).is_empty());

    clock.advance(RETRY_STEP);
    let outcome = run_command(&mut registrar, &sup, |reply| {
        RegistrarCommand::DeregisterAll { reply }
    })
    .await?;
    assert!(
        matches!(
            outcome.deregistered.get(RELAY_A),
            Some(Err(PushError::Stale { .. }))
        ),
        "deregister_all sends the deregistration again, in a new run: {outcome:?}"
    );
    let sent = drain(&mut rx);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].relay_url, RELAY_A);
    assert_eq!(verified_deregistration(&sent[0], &public_key)?.token, TOKEN);
    Ok(())
}

// ---------------------------------------------------------------------------
// The relay ledger
// ---------------------------------------------------------------------------

/// A registration whose OK was lost leaves the relay in the ledger, so
/// leaving the last context on it still sends the deregistration.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lost_ok_then_leaving_last_context_still_deregisters() -> TestResult {
    let sup = supervisor();
    create_context(&sup, CTX_A, PSEUDONYM_A, &[RELAY_A]).await?;
    // The relay stores the registration, but its OK never arrives.
    let answer: Answer = Box::new(|_, attempt| {
        if attempt == 0 {
            Err(PushPublishError::Unreachable {
                reason: "connection lost before the OK".to_owned(),
            })
        } else {
            Ok(())
        }
    });
    let (sink, mut rx) = publisher(system_clock(), answer);
    let mut registrar = registrar(sink, system_clock()).await?;
    let public_key = *registrar.signing_key.public_key();
    let first = registrar.reconcile(&sup).await?;
    assert!(
        matches!(
            first.registered.get(RELAY_A),
            Some(Err(PushError::Unreachable { .. }))
        ),
        "{first:?}"
    );
    expect_publishes(&mut rx, 1).await?;

    assert!(sup.despawn_actor(&hex::encode(CTX_A)).await);
    let second = registrar.reconcile(&sup).await?;
    assert!(
        second.deregistered.get(RELAY_A).is_some_and(Result::is_ok),
        "{second:?}"
    );
    let sent = expect_publishes(&mut rx, 1).await?;
    assert_eq!(sent[0].relay_url, RELAY_A);
    assert_eq!(verified_deregistration(&sent[0], &public_key)?.token, TOKEN);
    assert!(
        registrar.storage.load_push_relays().await?.is_empty(),
        "the accepted deregistration clears the ledger"
    );
    Ok(())
}

/// Relay A removes the registration on `deregister_all` but its OK is lost.
/// `register` then registers relay A again rather than skipping it as
/// unchanged, and relay A accepts the registration. Both commands run
/// through the registrar's command handler without the task, so no backoff
/// retry of the failed deregistration can come between them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lost_deregistration_ok_then_register_reregisters() -> TestResult {
    let sup = supervisor();
    create_context(&sup, CTX_A, PSEUDONYM_A, &[RELAY_A]).await?;
    // Attempt 0 is the start registration and attempt 1 the deregistration,
    // which the relay applies but whose OK never arrives.
    let answer: Answer = Box::new(|_, attempt| {
        if attempt == 1 {
            Err(PushPublishError::Unreachable {
                reason: "connection lost before the OK".to_owned(),
            })
        } else {
            Ok(())
        }
    });
    let (sink, mut rx) = publisher(system_clock(), answer);
    let mut registrar = registrar(sink, system_clock()).await?;
    let public_key = *registrar.signing_key.public_key();
    let first = registrar.reconcile(&sup).await?;
    assert!(
        first.registered.get(RELAY_A).is_some_and(Result::is_ok),
        "{first:?}"
    );
    let start = expect_publishes(&mut rx, 1).await?;
    let registered = verified_registration(&start[0], &public_key)?;

    let outcome = run_command(&mut registrar, &sup, |reply| {
        RegistrarCommand::DeregisterAll { reply }
    })
    .await?;
    assert!(
        matches!(
            outcome.deregistered.get(RELAY_A),
            Some(Err(PushError::Unreachable { .. }))
        ),
        "{outcome:?}"
    );
    let sent = expect_publishes(&mut rx, 1).await?;
    assert_eq!(sent[0].relay_url, RELAY_A);
    verified_deregistration(&sent[0], &public_key)?;

    let outcome = run_command(&mut registrar, &sup, |reply| RegistrarCommand::Register {
        reply,
    })
    .await?;
    assert!(
        outcome.registered.get(RELAY_A).is_some_and(Result::is_ok),
        "relay A is registered again: {outcome:?}"
    );
    let sent = expect_publishes(&mut rx, 1).await?;
    assert_eq!(sent[0].relay_url, RELAY_A);
    let again = verified_registration(&sent[0], &public_key)?;
    assert_eq!(again.routing_ids, registered.routing_ids);
    Ok(())
}

/// Relay A leaves the wanted set, its deregistration's OK is lost, and the
/// same routing-ID set comes back. `reconcile` registers relay A again
/// rather than skipping it as unchanged.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lost_deregistration_ok_then_same_set_returns_reregisters() -> TestResult {
    let sup = supervisor();
    create_context(&sup, CTX_A, PSEUDONYM_A, &[RELAY_A]).await?;
    let answer: Answer = Box::new(|_, attempt| {
        if attempt == 1 {
            Err(PushPublishError::Unreachable {
                reason: "connection lost before the OK".to_owned(),
            })
        } else {
            Ok(())
        }
    });
    let (sink, mut rx) = publisher(system_clock(), answer);
    let mut registrar = registrar(sink, system_clock()).await?;
    let public_key = *registrar.signing_key.public_key();
    let first = registrar.reconcile(&sup).await?;
    assert!(
        first.registered.get(RELAY_A).is_some_and(Result::is_ok),
        "{first:?}"
    );
    let start = expect_publishes(&mut rx, 1).await?;
    let registered = verified_registration(&start[0], &public_key)?;

    assert!(sup.despawn_actor(&hex::encode(CTX_A)).await);
    let left = registrar.reconcile(&sup).await?;
    assert!(
        matches!(
            left.deregistered.get(RELAY_A),
            Some(Err(PushError::Unreachable { .. }))
        ),
        "{left:?}"
    );
    expect_publishes(&mut rx, 1).await?;

    create_context(&sup, CTX_A, PSEUDONYM_A, &[RELAY_A]).await?;
    let back = registrar.reconcile(&sup).await?;
    assert!(
        back.registered.get(RELAY_A).is_some_and(Result::is_ok),
        "relay A is registered again: {back:?}"
    );
    let sent = expect_publishes(&mut rx, 1).await?;
    assert_eq!(sent[0].relay_url, RELAY_A);
    let again = verified_registration(&sent[0], &public_key)?;
    assert_eq!(again.routing_ids, registered.routing_ids, "the same set");
    Ok(())
}

/// A new registrar over the same storage, whose supervisor has no context
/// on relay A, deregisters at relay A.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restarted_registrar_deregisters_a_recorded_relay() -> TestResult {
    let storage = ledger();
    let (sink, mut rx) = publisher(system_clock(), accept_all());
    let mut first = registrar_on(Arc::clone(&sink), system_clock(), Arc::clone(&storage)).await?;
    first.register(&[target(RELAY_A, &[[1; 32]])?]).await?;
    expect_publishes(&mut rx, 1).await?;
    drop(first);

    let sup = supervisor();
    create_context(&sup, CTX_B, PSEUDONYM_B, &[RELAY_B]).await?;
    let mut second = registrar_on(sink, system_clock(), Arc::clone(&storage)).await?;
    let public_key = *second.signing_key.public_key();
    let outcome = second.reconcile(&sup).await?;
    assert!(
        outcome.deregistered.get(RELAY_A).is_some_and(Result::is_ok),
        "{outcome:?}"
    );
    assert!(
        outcome.registered.get(RELAY_B).is_some_and(Result::is_ok),
        "{outcome:?}"
    );
    let sent = expect_publishes(&mut rx, 2).await?;
    let at_a = sent
        .iter()
        .find(|p| p.relay_url == RELAY_A)
        .ok_or("nothing reached relay A")?;
    assert_eq!(verified_deregistration(at_a, &public_key)?.token, TOKEN);
    let recorded: Vec<String> = storage
        .load_push_relays()
        .await?
        .into_iter()
        .map(|record| record.relay_url)
        .collect();
    assert_eq!(recorded, vec![RELAY_B.to_owned()]);
    Ok(())
}

/// A relay whose ledger write fails is not published to: the record comes
/// before the first publish.
#[tokio::test]
async fn ledger_write_failure_publishes_nothing() -> TestResult {
    let faulty = FaultyStorage::new(Arc::new(InMemoryStorage::new()));
    faulty.fail_store_prefix("push_relay/");
    let storage = Arc::new(ProtocolRepository::new_for_testing(faulty));
    let (sink, mut rx) = publisher(system_clock(), accept_all());
    let mut registrar = registrar_on(sink, system_clock(), storage).await?;
    let results = registrar.register(&[target(RELAY_A, &[[1; 32]])?]).await?;
    let outcome = results.get(RELAY_A).ok_or("no result")?;
    assert!(
        matches!(outcome, Err(err @ PushError::Ledger(_)) if err.retryable()),
        "{outcome:?}"
    );
    expect_quiet(&mut rx).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// deregister_all and register commands
// ---------------------------------------------------------------------------

/// `deregister_all` deregisters every relay and clears the ledger, a route
/// change then publishes nothing, and `register` registers again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deregister_all_stops_registering_until_register() -> TestResult {
    let sup = supervisor();
    create_context(&sup, CTX_A, PSEUDONYM_A, &[RELAY_A]).await?;
    create_context(&sup, CTX_B, PSEUDONYM_B, &[RELAY_B]).await?;
    let storage = ledger();
    let (sink, mut rx) = publisher(system_clock(), accept_all());
    let registrar = registrar_on(sink, system_clock(), Arc::clone(&storage)).await?;
    let public_key = *registrar.signing_key.public_key();
    let shutdown = CancellationToken::new();
    let task = registrar.spawn_trigger(Arc::clone(&sup), shutdown.clone());
    expect_publishes(&mut rx, 2).await?;

    let outcome = task.deregister_all().await?;
    assert_eq!(outcome.deregistered.len(), 2, "{outcome:?}");
    assert!(
        outcome.deregistered.values().all(Result::is_ok),
        "{outcome:?}"
    );
    assert!(outcome.registered.is_empty(), "{outcome:?}");
    let sent = expect_publishes(&mut rx, 2).await?;
    assert_eq!(
        relay_urls(&sent),
        BTreeSet::from([RELAY_A.to_owned(), RELAY_B.to_owned()])
    );
    for published in &sent {
        verified_deregistration(published, &public_key)?;
    }
    assert!(
        storage.load_push_relays().await?.is_empty(),
        "the ledger is clear"
    );

    create_context(&sup, CTX_C, PSEUDONYM_C, &[RELAY_A]).await?;
    expect_quiet(&mut rx).await?;

    let outcome = task.register().await?;
    assert_eq!(outcome.registered.len(), 2, "{outcome:?}");
    let sent = expect_publishes(&mut rx, 2).await?;
    let at_a = sent
        .iter()
        .find(|p| p.relay_url == RELAY_A)
        .ok_or("relay A is not registered again")?;
    let registration = verified_registration(at_a, &public_key)?;
    assert!(registration.routing_ids.contains(&PSEUDONYM_A));
    assert!(registration.routing_ids.contains(&PSEUDONYM_C));

    shutdown.cancel();
    tokio::time::timeout(ARRIVAL, task.into_join_handle()).await??;
    Ok(())
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

/// `WebPush` is refused at construction with a typed error.
#[tokio::test]
async fn webpush_platform_is_refused() -> TestResult {
    let (sink, _rx) = publisher(system_clock(), accept_all());
    let refused = PushRegistrar::new(PushRegistrarConfig {
        signing_key: signing_key().await?,
        publisher: sink,
        clock: system_clock(),
        platform: PushPlatform::WebPush,
        token: PushToken::new(TOKEN.to_vec()),
        storage: ledger(),
    })
    .await;
    assert!(matches!(refused, Err(PushError::WebPushUnsupported)));
    Ok(())
}

// ---------------------------------------------------------------------------
// Shutdown during a stalled publish
// ---------------------------------------------------------------------------

/// Accepts the first publish and leaves every later one pending forever.
struct StallingPublisher {
    tx: mpsc::UnboundedSender<String>,
    attempts: AtomicUsize,
}

impl PushRelayPublisher for StallingPublisher {
    fn publish<'a>(
        &'a self,
        relay_url: &'a str,
        _routing_id: [u8; 32],
        _blob: Vec<u8>,
    ) -> BoxFuture<'a, Result<(), PushPublishError>> {
        let attempt = self.attempts.fetch_add(1, Ordering::SeqCst);
        // A send error means the test stopped reading; nothing to record.
        if self.tx.send(relay_url.to_owned()).is_err() {
            tracing::debug!("stalling publisher: receiver closed");
        }
        Box::pin(async move {
            if attempt == 0 {
                Ok(())
            } else {
                std::future::pending().await
            }
        })
    }
}

/// Cancelling the shutdown token while a command's publish never completes
/// ends the task, and the command's caller gets `RegistrarStopped`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_during_stalled_command_ends_task() -> TestResult {
    let sup = supervisor();
    create_context(&sup, CTX_A, PSEUDONYM_A, &[RELAY_A]).await?;
    let (tx, mut rx) = mpsc::unbounded_channel();
    let sink = Arc::new(StallingPublisher {
        tx,
        attempts: AtomicUsize::new(0),
    });
    let registrar = registrar(sink, system_clock()).await?;
    let shutdown = CancellationToken::new();
    let task = Arc::new(registrar.spawn_trigger(Arc::clone(&sup), shutdown.clone()));
    tokio::time::timeout(ARRIVAL, rx.recv())
        .await?
        .ok_or("publisher dropped")?;

    let commander = Arc::clone(&task);
    let refresh = tokio::spawn(async move {
        commander
            .refresh_token(PushToken::new(NEW_TOKEN.to_vec()))
            .await
    });
    // The refresh's deregistration reached the publisher and stalls there.
    tokio::time::timeout(ARRIVAL, rx.recv())
        .await?
        .ok_or("publisher dropped")?;

    shutdown.cancel();
    let refreshed = tokio::time::timeout(ARRIVAL, refresh).await??;
    assert!(
        matches!(refreshed, Err(PushError::RegistrarStopped)),
        "{refreshed:?}"
    );
    let task = Arc::try_unwrap(task).map_err(|_| "the task handle is still shared")?;
    tokio::time::timeout(ARRIVAL, task.into_join_handle()).await??;
    Ok(())
}
