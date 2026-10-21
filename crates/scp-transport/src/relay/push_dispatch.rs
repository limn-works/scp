//! The relay push dispatcher (spec §10.7.1 step 5 and `PushDeregistration`;
//! PUSH-008).
//!
//! After a relay stores a blob, it calls [`notify`] with the blob's routing ID.
//! With push enabled, the dispatcher looks up every registration that lists
//! the routing ID and queues one [`PushJob`] per distinct (platform, token) on
//! a bounded queue of [`PUSH_QUEUE_CAPACITY`] jobs. The publish never waits on
//! a send: a full or closed queue drops the job, counts it, and logs without
//! the token.
//!
//! One drain task per relay, started by [`spawn_drain`] with the relay's
//! background tasks and stopped by the relay's shutdown token, sends the jobs
//! in order through the configured [`PushSender`] and applies each outcome to
//! the registration store:
//!
//! - `Delivered` resets the token's consecutive invalid-token count.
//! - `InvalidToken` adds one to it; at
//!   [`INVALID_TOKEN_REMOVAL_THRESHOLD`](super::push_store::INVALID_TOKEN_REMOVAL_THRESHOLD)
//!   the store removes every registration holding the token, in the same
//!   transaction.
//! - `Transient` and `ConfigError` leave the count unchanged.
//!
//! The count is per token, because §10.7.1 removes registrations "after 3
//! consecutive delivery failures for the same token".
//!
//! Every listener of one relay (WebSocket, QUIC, UDP, WebTransport) holds a
//! clone of the relay's [`PushRole`], and every clone shares one dispatcher,
//! so a publish on any transport reaches the one queue and the one drain.
//!
//! A build without the `push-store` feature has no push service, and its
//! [`notify`] is a no-op that completes at once.

#[cfg(feature = "push-store")]
pub use enabled::*;

/// Queues nothing, because a build without `push-store` has no push service.
///
/// The only [`PushRole`](super::push_gate::PushRole) of such a build is
/// `Disabled`. The returned future is already complete; the signature matches
/// the `push-store` build so every transport calls it the same way.
#[cfg(not(feature = "push-store"))]
pub fn notify(push: &super::push_gate::PushRole, _routing_id: &[u8; 32]) -> std::future::Ready<()> {
    match push {
        super::push_gate::PushRole::Disabled => std::future::ready(()),
    }
}

/// Starts nothing, because a build without `push-store` has no push queue.
///
/// The signature matches the `push-store` build.
#[cfg(not(feature = "push-store"))]
#[must_use]
pub fn spawn_drain(
    push: &super::push_gate::PushRole,
    _shutdown: tokio_util::sync::CancellationToken,
) -> Option<tokio::task::JoinHandle<()>> {
    match push {
        super::push_gate::PushRole::Disabled => None,
    }
}

#[cfg(feature = "push-store")]
mod enabled {
    use std::collections::HashSet;
    use std::fmt;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use scp_protocol::discovery::push::PushPlatform;
    use tokio::sync::{Mutex, mpsc};
    use tokio::task::JoinHandle;
    use tokio_util::sync::CancellationToken;
    use zeroize::Zeroizing;

    use super::super::push::PushSendOutcome;
    use super::super::push_gate::{PushRole, PushServiceConfig};
    use super::super::push_store::{InvalidTokenOutcome, PushRegistrationStore, PushStoreError};

    /// The most push jobs a relay holds before it drops new ones (§10.7.1
    /// step 5; PUSH-008 indicator: 10,000).
    pub const PUSH_QUEUE_CAPACITY: usize = 10_000;

    /// One wake to send: the platform and the token, and nothing else.
    ///
    /// A job carries no routing ID, blob or registrant identifier, so a job
    /// that leaks (through a log, a panic message, or memory) ties no token
    /// to a context or an identity. The token sits in a zeroizing buffer and
    /// `Debug` prints only its length.
    pub struct PushJob {
        platform: PushPlatform,
        token: Zeroizing<Vec<u8>>,
    }

    impl PushJob {
        /// The platform whose sender wakes the token.
        #[must_use]
        pub const fn platform(&self) -> PushPlatform {
            self.platform
        }

        /// The token bytes as the registration carried them.
        #[must_use]
        pub fn token(&self) -> &[u8] {
            &self.token
        }
    }

    impl fmt::Debug for PushJob {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PushJob")
                .field("platform", &self.platform)
                .field("token_len", &self.token.len())
                .finish()
        }
    }

    /// What one [`PushDispatcher::enqueue_for`] did.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct EnqueueReport {
        /// Jobs queued.
        pub enqueued: usize,
        /// Jobs dropped because the queue held [`PUSH_QUEUE_CAPACITY`] jobs.
        pub dropped_full: usize,
        /// Jobs dropped because the queue was closed.
        pub dropped_closed: usize,
    }

    /// A snapshot of the dispatcher's counters since it was built.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct PushDispatchStats {
        /// Jobs queued.
        pub enqueued: u64,
        /// Jobs dropped because the queue was full.
        pub dropped_full: u64,
        /// Jobs dropped because the queue was closed.
        pub dropped_closed: u64,
        /// Stored blobs for which the registration lookup failed, so no job
        /// was queued.
        pub lookup_failed: u64,
        /// Sends the push service accepted.
        pub delivered: u64,
        /// Sends the push service answered with an invalid-token response.
        pub invalid_token: u64,
        /// Sends that failed transiently.
        pub transient: u64,
        /// Sends the push service refused for the relay's own credentials.
        pub config_error: u64,
        /// Jobs for a platform the relay holds no sender for.
        pub no_sender: u64,
        /// Registrations removed after consecutive invalid-token responses.
        pub removed: u64,
        /// Outcomes the store failed to record.
        pub store_failed: u64,
    }

    #[derive(Debug, Default)]
    struct Counters {
        enqueued: AtomicU64,
        dropped_full: AtomicU64,
        dropped_closed: AtomicU64,
        lookup_failed: AtomicU64,
        delivered: AtomicU64,
        invalid_token: AtomicU64,
        transient: AtomicU64,
        config_error: AtomicU64,
        no_sender: AtomicU64,
        removed: AtomicU64,
        store_failed: AtomicU64,
    }

    fn bump(counter: &AtomicU64, by: u64) {
        counter.fetch_add(by, Ordering::Relaxed);
    }

    struct Inner {
        tx: mpsc::Sender<PushJob>,
        /// The drain holds this lock for its lifetime, so at most one drain
        /// reads the queue at a time; a second drain waits for the first to
        /// stop, which lets a relay restart on the same configuration.
        rx: Arc<Mutex<mpsc::Receiver<PushJob>>>,
        counters: Counters,
    }

    /// The relay's push queue and its counters. Clones share one queue.
    ///
    /// [`PushServiceConfig::new`] builds one; every clone of the config and
    /// of the [`PushRole`] holding it shares it.
    #[derive(Clone)]
    pub struct PushDispatcher {
        inner: Arc<Inner>,
    }

    impl fmt::Debug for PushDispatcher {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PushDispatcher")
                .field("stats", &self.stats())
                .finish_non_exhaustive()
        }
    }

    impl PushDispatcher {
        /// A dispatcher whose queue holds [`PUSH_QUEUE_CAPACITY`] jobs.
        pub(crate) fn new() -> Self {
            Self::with_capacity(PUSH_QUEUE_CAPACITY)
        }

        /// A dispatcher whose queue holds `capacity` jobs. The tests use a
        /// small queue to fill it; production uses [`Self::new`].
        pub(crate) fn with_capacity(capacity: usize) -> Self {
            let (tx, rx) = mpsc::channel(capacity);
            Self {
                inner: Arc::new(Inner {
                    tx,
                    rx: Arc::new(Mutex::new(rx)),
                    counters: Counters::default(),
                }),
            }
        }

        /// The counters since the dispatcher was built.
        #[must_use]
        pub fn stats(&self) -> PushDispatchStats {
            let c = &self.inner.counters;
            let get = |a: &AtomicU64| a.load(Ordering::Relaxed);
            PushDispatchStats {
                enqueued: get(&c.enqueued),
                dropped_full: get(&c.dropped_full),
                dropped_closed: get(&c.dropped_closed),
                lookup_failed: get(&c.lookup_failed),
                delivered: get(&c.delivered),
                invalid_token: get(&c.invalid_token),
                transient: get(&c.transient),
                config_error: get(&c.config_error),
                no_sender: get(&c.no_sender),
                removed: get(&c.removed),
                store_failed: get(&c.store_failed),
            }
        }

        /// Queues one job per distinct (platform, token) among the
        /// registrations in `store` that list `routing_id`, without waiting.
        /// A job the full or closed queue refuses is dropped, counted and
        /// logged without its token.
        ///
        /// # Errors
        ///
        /// [`PushStoreError::Storage`] when the registration lookup fails;
        /// nothing is queued.
        pub async fn enqueue_for(
            &self,
            store: &PushRegistrationStore,
            routing_id: &[u8; 32],
        ) -> Result<EnqueueReport, PushStoreError> {
            let records = store.tokens_for_routing_id(routing_id).await?;
            let mut report = EnqueueReport::default();
            let mut seen: HashSet<(PushPlatform, &[u8])> = HashSet::with_capacity(records.len());
            let counters = &self.inner.counters;
            for record in &records {
                if !seen.insert((record.platform, record.token.as_slice())) {
                    continue;
                }
                let job = PushJob {
                    platform: record.platform,
                    token: Zeroizing::new(record.token.clone()),
                };
                match self.inner.tx.try_send(job) {
                    Ok(()) => {
                        report.enqueued += 1;
                        bump(&counters.enqueued, 1);
                    }
                    Err(mpsc::error::TrySendError::Full(job)) => {
                        report.dropped_full += 1;
                        bump(&counters.dropped_full, 1);
                        tracing::warn!(
                            platform = ?job.platform,
                            capacity = self.inner.tx.max_capacity(),
                            "push queue full; wake dropped"
                        );
                    }
                    Err(mpsc::error::TrySendError::Closed(job)) => {
                        report.dropped_closed += 1;
                        bump(&counters.dropped_closed, 1);
                        tracing::warn!(platform = ?job.platform, "push queue closed; wake dropped");
                    }
                }
            }
            Ok(report)
        }

        /// Sends one job through `service`'s sender for its platform and
        /// applies the outcome to `service`'s store. The outcome's counter
        /// moves after the store write, so a counter a reader sees already
        /// includes the write.
        async fn process(&self, service: &PushServiceConfig, job: PushJob) {
            let counters = &self.inner.counters;
            let platform = job.platform;
            let Some(sender) = service.sender_for(platform) else {
                bump(&counters.no_sender, 1);
                tracing::warn!(platform = ?platform, "no push sender for platform; wake dropped");
                return;
            };
            let outcome = sender.send_registered(job.token()).await;
            let store = &service.store;
            match outcome {
                PushSendOutcome::Delivered => {
                    if let Err(e) = store.clear_invalid_tokens(platform, job.token()).await {
                        bump(&counters.store_failed, 1);
                        tracing::warn!(
                            platform = ?platform,
                            error = %e,
                            "could not reset a push token's invalid-token count"
                        );
                    }
                    bump(&counters.delivered, 1);
                }
                PushSendOutcome::InvalidToken => {
                    match store.record_invalid_token(platform, job.token()).await {
                        Ok(InvalidTokenOutcome::Removed { registrations }) => {
                            bump(
                                &counters.removed,
                                u64::try_from(registrations).unwrap_or(u64::MAX),
                            );
                            tracing::info!(
                                platform = ?platform,
                                registrations,
                                "removed push registrations after consecutive invalid-token responses"
                            );
                        }
                        Ok(InvalidTokenOutcome::Counted { failures }) => {
                            tracing::debug!(platform = ?platform, failures, "push token answered invalid");
                        }
                        Ok(InvalidTokenOutcome::NotRegistered) => {
                            tracing::debug!(
                                platform = ?platform,
                                "push token answered invalid after its registrations were removed"
                            );
                        }
                        Err(e) => {
                            bump(&counters.store_failed, 1);
                            tracing::warn!(
                                platform = ?platform,
                                error = %e,
                                "could not count a push token's invalid-token response"
                            );
                        }
                    }
                    bump(&counters.invalid_token, 1);
                }
                PushSendOutcome::Transient => bump(&counters.transient, 1),
                PushSendOutcome::ConfigError => {
                    bump(&counters.config_error, 1);
                    tracing::warn!(
                        platform = ?platform,
                        "push service refused the relay's credentials; registration kept"
                    );
                }
            }
        }

        /// Reads the queue until `shutdown` is cancelled, one job at a time,
        /// so the outcomes for one token reach the store in send order.
        async fn drain(self, service: PushServiceConfig, shutdown: CancellationToken) {
            let mut rx = tokio::select! {
                biased;
                () = shutdown.cancelled() => return,
                rx = Arc::clone(&self.inner.rx).lock_owned() => rx,
            };
            // The guard lives until the loop ends, so a second drain of this
            // queue waits instead of reading beside this one.
            self.serve(&service, &mut rx, &shutdown).await;
        }

        async fn serve(
            &self,
            service: &PushServiceConfig,
            rx: &mut mpsc::Receiver<PushJob>,
            shutdown: &CancellationToken,
        ) {
            loop {
                let job = tokio::select! {
                    biased;
                    () = shutdown.cancelled() => return,
                    job = rx.recv() => job,
                };
                // The dispatcher holds a sender, so the queue never closes
                // while this task runs; `None` cannot occur, and stopping is
                // the only sound reading of it.
                let Some(job) = job else { return };
                tokio::select! {
                    biased;
                    () = shutdown.cancelled() => return,
                    () = self.process(service, job) => {}
                }
            }
        }
    }

    /// Queues one wake per distinct (platform, token) registered for
    /// `routing_id`, after the relay stored a blob there (§10.7.1 step 5).
    ///
    /// It waits on the registration lookup, never on a send. With push
    /// disabled it does nothing. A failed lookup queues nothing; it is counted
    /// in [`PushDispatchStats::lookup_failed`] and logged without a token, and
    /// the publish still succeeds, because the blob is already stored and a
    /// wake is advisory (the device pulls on its next connection).
    pub async fn notify(push: &PushRole, routing_id: &[u8; 32]) {
        let PushRole::Enabled(service) = push else {
            return;
        };
        let dispatcher = service.dispatcher();
        if let Err(e) = dispatcher.enqueue_for(&service.store, routing_id).await {
            bump(&dispatcher.inner.counters.lookup_failed, 1);
            tracing::warn!(error = %e, "push registration lookup failed; no wake queued");
        }
    }

    /// Starts the drain task for `push`'s queue, stopped by `shutdown`.
    /// Returns `None` with push disabled.
    ///
    /// A relay calls it once per start, with its other background tasks. A
    /// drain started while another drain of the same queue runs waits for
    /// that one to stop.
    #[must_use]
    pub fn spawn_drain(push: &PushRole, shutdown: CancellationToken) -> Option<JoinHandle<()>> {
        let PushRole::Enabled(service) = push else {
            return None;
        };
        let dispatcher = service.dispatcher().clone();
        let service = service.clone();
        Some(tokio::spawn(dispatcher.drain(service, shutdown)))
    }

    #[cfg(test)]
    mod tests {
        use std::sync::Arc;

        use scp_crypto::p256::{P256SecretKey, sign_prehash_rfc6979};
        use scp_did::DID;
        use scp_identity::push_verify::TestPushVerifier;
        use scp_protocol::discovery::push::{
            PushPlatform, PushRegistration, push_registration_signing_bytes,
        };
        use sha2::{Digest, Sha256};
        use tempfile::TempDir;
        use tokio_util::sync::CancellationToken;

        use super::super::super::push::{ApnsSender, FcmSender, PushSender};
        use super::super::super::push_gate::{
            PushPublishGate, PushRole, PushServiceConfig, gate_publish, test_relay_url,
        };
        use super::super::super::push_store::PushRegistrationStore;
        use super::super::super::push_test_server::{ClosedOrigin, TestServer};
        use super::{PushDispatcher, PushJob, notify, spawn_drain};

        type TestResult = Result<(), Box<dyn std::error::Error>>;

        const RID: [u8; 32] = [0x11; 32];
        /// The URL `test_relay_url()` serves, which every registration signs.
        const RELAY_URL: &str = "ws://127.0.0.1:9000/scp/v1";
        const REGISTRANT_A: &str = "did:dht:push-a";
        const REGISTRANT_B: &str = "did:dht:push-b";

        fn key(seed: u8) -> Result<P256SecretKey, Box<dyn std::error::Error>> {
            Ok(P256SecretKey::from_scalar_bytes(&[seed; 32])?)
        }

        /// The signature-checking test verifier of PUSH-005, holding `key(1)`
        /// for registrant A and `key(2)` for registrant B.
        fn verifier() -> Result<Arc<TestPushVerifier>, Box<dyn std::error::Error>> {
            Ok(Arc::new(TestPushVerifier::new([
                (DID::from(REGISTRANT_A), key(1)?.public_key()),
                (DID::from(REGISTRANT_B), key(2)?.public_key()),
            ])))
        }

        /// A push service over a fresh SQLite store (the shipped arm, so
        /// these tests run with and without `testing`) with `senders` and a
        /// queue of `capacity` jobs.
        fn service(
            senders: Vec<PushSender>,
            capacity: usize,
        ) -> Result<(PushServiceConfig, TempDir), Box<dyn std::error::Error>> {
            let dir = tempfile::tempdir()?;
            let store = PushRegistrationStore::open_sqlite(&dir.path().join("push.db"))?;
            let service = PushServiceConfig::with_queue_capacity(
                store,
                verifier()?,
                Arc::from(senders),
                capacity,
            );
            Ok((service, dir))
        }

        /// The shipped APNs and FCM senders, aimed at a port nothing listens
        /// on. The gate refuses a registration for a platform without a
        /// sender; these tests start no drain, so neither sender sends.
        fn production_senders()
        -> Result<(Vec<PushSender>, ClosedOrigin), Box<dyn std::error::Error>> {
            let closed = TestServer::closed_origin();
            let clock: Arc<dyn scp_clock::Clock> = Arc::new(scp_clock::SystemClock);
            let apns = ApnsSender::build(
                super::super::super::push_apns::tests::config(),
                closed.origin().to_owned(),
                clock.clone(),
            )?;
            let fcm = FcmSender::build(
                super::super::super::push_fcm::tests::config(),
                closed.origin(),
                format!("{}/token", closed.origin()),
                clock,
            )?;
            Ok((vec![PushSender::Apns(apns), PushSender::Fcm(fcm)], closed))
        }

        /// Registers `token` on `platform` for [`RID`] the way a client does:
        /// a signed `PushRegistration` published to the relay's reserved push
        /// routing ID, which the gate verifies with the test verifier before
        /// it writes the store.
        async fn register(
            push: &PushRole,
            registrant: &str,
            platform: PushPlatform,
            token: &[u8],
        ) -> TestResult {
            let signer = if registrant == REGISTRANT_A {
                key(1)?
            } else {
                key(2)?
            };
            let now = scp_clock::Clock::now_secs(&scp_clock::SystemClock);
            let mut msg = PushRegistration {
                registrant: DID::from(registrant),
                platform,
                token: token.to_vec(),
                routing_ids: vec![RID],
                timestamp: now,
                signature: [0; 64],
            };
            let digest: [u8; 32] =
                Sha256::digest(push_registration_signing_bytes(&msg, RELAY_URL)?).into();
            msg.signature = sign_prehash_rfc6979(&signer, &digest)?;
            let blob = rmp_serde::to_vec_named(&msg)?;
            let relay_url = test_relay_url();
            let reserved = relay_url.current().push_routing_id();
            let decision = gate_publish(&relay_url, push, &reserved, &blob, now).await;
            if decision != PushPublishGate::Accepted {
                return Err(format!("registration not accepted: {decision:?}").into());
            }
            Ok(())
        }

        /// A job holds the platform and the token and nothing else: the
        /// destructuring names every field with no `..`, so a field added to
        /// the job stops this test compiling.
        #[test]
        fn push_job_holds_only_platform_and_token() {
            let job = PushJob {
                platform: PushPlatform::Fcm,
                token: zeroize::Zeroizing::new(b"secret-token".to_vec()),
            };
            let shown = format!("{job:?}");
            assert!(!shown.contains("secret-token"), "{shown}");
            assert!(shown.contains("token_len: 12"), "{shown}");
            let PushJob { platform, token } = job;
            assert_eq!(platform, PushPlatform::Fcm);
            assert_eq!(token.as_slice(), b"secret-token");
        }

        /// Two registrants holding one token make one job; the same bytes on
        /// another platform are another token and make another job.
        #[tokio::test]
        async fn enqueue_makes_one_job_per_distinct_token() -> TestResult {
            let (senders, _closed) = production_senders()?;
            let (service, _dir) = service(senders, 16)?;
            let push = PushRole::Enabled(service.clone());
            register(&push, REGISTRANT_A, PushPlatform::Apns, b"t1").await?;
            register(&push, REGISTRANT_B, PushPlatform::Apns, b"t1").await?;
            register(&push, REGISTRANT_A, PushPlatform::Fcm, b"t1").await?;
            register(&push, REGISTRANT_A, PushPlatform::Apns, b"t2").await?;
            let dispatcher = service.dispatcher();
            let report = dispatcher.enqueue_for(&service.store, &RID).await?;
            assert_eq!(report.enqueued, 3);
            let mut rx = dispatcher.inner.rx.lock().await;
            let mut jobs = Vec::new();
            while let Ok(job) = rx.try_recv() {
                jobs.push((job.platform(), job.token().to_vec()));
            }
            drop(rx);
            jobs.sort_by_key(|(p, t)| (p.tag_byte(), t.clone()));
            assert_eq!(
                jobs,
                vec![
                    (PushPlatform::Apns, b"t1".to_vec()),
                    (PushPlatform::Apns, b"t2".to_vec()),
                    (PushPlatform::Fcm, b"t1".to_vec()),
                ]
            );
            assert_eq!(
                dispatcher
                    .enqueue_for(&service.store, &[0; 32])
                    .await?
                    .enqueued,
                0
            );
            Ok(())
        }

        /// A full queue drops the job and counts it; `notify` returns, so the
        /// caller's publish succeeds.
        #[tokio::test]
        async fn full_queue_drops_and_counts() -> TestResult {
            let (senders, _closed) = production_senders()?;
            let (service, _dir) = service(senders, 1)?;
            let push = PushRole::Enabled(service.clone());
            register(&push, REGISTRANT_A, PushPlatform::Apns, b"t1").await?;
            notify(&push, &RID).await;
            notify(&push, &RID).await;
            let stats = service.dispatcher().stats();
            assert_eq!((stats.enqueued, stats.dropped_full), (1, 1));
            Ok(())
        }

        /// A failed registration lookup queues nothing and is counted, and
        /// `notify` still returns, so the caller's publish succeeds.
        #[tokio::test]
        async fn failed_lookup_is_counted() -> TestResult {
            let (senders, _closed) = production_senders()?;
            let (service, dir) = service(senders, 4)?;
            let push = PushRole::Enabled(service.clone());
            register(&push, REGISTRANT_A, PushPlatform::Apns, b"t1").await?;
            // Drop the routing index from beside the store: its next lookup
            // fails.
            rusqlite::Connection::open(dir.path().join("push.db"))?
                .execute_batch("DROP TABLE push_routing_index;")?;
            assert!(service.store.tokens_for_routing_id(&RID).await.is_err());
            notify(&push, &RID).await;
            let stats = service.dispatcher().stats();
            assert_eq!((stats.lookup_failed, stats.enqueued), (1, 0));
            Ok(())
        }

        /// The production queue holds exactly 10,000 jobs.
        #[tokio::test]
        async fn production_queue_holds_ten_thousand_jobs() {
            let dispatcher = PushDispatcher::new();
            assert_eq!(dispatcher.inner.tx.max_capacity(), 10_000);
        }

        /// With push disabled, `notify` queues nothing and no drain starts.
        #[tokio::test]
        async fn disabled_role_queues_nothing() {
            notify(&PushRole::Disabled, &RID).await;
            assert!(spawn_drain(&PushRole::Disabled, CancellationToken::new()).is_none());
        }

        /// Drain tests: the recording sender compiles only under `testing`.
        #[cfg(feature = "testing")]
        mod drain {
            use std::sync::Arc;
            use std::time::Duration;

            use scp_protocol::discovery::push::PushPlatform;
            use tokio_util::sync::CancellationToken;

            use super::super::super::super::push::{PushSendOutcome, PushSender, RecordingSender};
            use super::super::super::super::push_gate::{PushRole, PushServiceConfig};
            use super::super::{PushDispatcher, notify, spawn_drain};
            use super::{REGISTRANT_A, REGISTRANT_B, RID, TestResult, register, service, verifier};

            async fn wait_for_sends(sender: &RecordingSender, n: usize) -> TestResult {
                for _ in 0..1000 {
                    if sender.sent().await.len() >= n {
                        return Ok(());
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                Err(format!("expected {n} sends, saw {}", sender.sent().await.len()).into())
            }

            /// Waits until the drain has applied `n` outcomes to the store.
            async fn wait_for_outcomes(dispatcher: &PushDispatcher, n: u64) -> TestResult {
                for _ in 0..1000 {
                    let s = dispatcher.stats();
                    let applied = s.delivered + s.invalid_token + s.transient + s.config_error;
                    // Each outcome is counted after its store write.
                    if applied >= n {
                        return Ok(());
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                Err(format!("expected {n} outcomes, saw {:?}", dispatcher.stats()).into())
            }

            /// Runs `outcomes` through the drain for one APNs token two
            /// registrants hold, one publish per outcome, and returns the
            /// service afterwards.
            async fn run_outcomes(
                outcomes: &[PushSendOutcome],
            ) -> Result<(PushServiceConfig, tempfile::TempDir), Box<dyn std::error::Error>>
            {
                let sender = RecordingSender::new(PushPlatform::Apns, outcomes.iter().copied());
                let (service, dir) = service(vec![PushSender::Recording(sender.clone())], 16)?;
                let push = PushRole::Enabled(service.clone());
                register(&push, REGISTRANT_A, PushPlatform::Apns, b"t1").await?;
                register(&push, REGISTRANT_B, PushPlatform::Apns, b"t1").await?;
                let shutdown = CancellationToken::new();
                let drain = spawn_drain(&push, shutdown.clone()).ok_or("push enabled")?;
                for i in 1..=outcomes.len() {
                    notify(&push, &RID).await;
                    wait_for_sends(&sender, i).await?;
                    wait_for_outcomes(service.dispatcher(), u64::try_from(i)?).await?;
                }
                shutdown.cancel();
                drain.await?;
                assert_eq!(
                    sender.sent().await,
                    vec![b"t1".to_vec(); outcomes.len()],
                    "one send per publish, of the raw token"
                );
                Ok((service, dir))
            }

            /// Three `InvalidToken` outcomes in a row remove every
            /// registration holding the token.
            #[tokio::test]
            async fn three_invalid_tokens_remove_the_registrations() -> TestResult {
                use PushSendOutcome::InvalidToken;
                let (service, _dir) =
                    run_outcomes(&[InvalidToken, InvalidToken, InvalidToken]).await?;
                assert!(service.store.tokens_for_routing_id(&RID).await?.is_empty());
                assert_eq!(
                    service
                        .store
                        .invalid_token_failures(PushPlatform::Apns, b"t1")
                        .await?,
                    None
                );
                let stats = service.dispatcher().stats();
                assert_eq!((stats.invalid_token, stats.removed), (3, 2));
                Ok(())
            }

            /// Two `InvalidToken` outcomes leave the registrations in place:
            /// the removal happens at the third, not before.
            #[tokio::test]
            async fn two_invalid_tokens_keep_the_registrations() -> TestResult {
                use PushSendOutcome::InvalidToken;
                let (service, _dir) = run_outcomes(&[InvalidToken, InvalidToken]).await?;
                assert_eq!(service.store.tokens_for_routing_id(&RID).await?.len(), 2);
                assert_eq!(
                    service
                        .store
                        .invalid_token_failures(PushPlatform::Apns, b"t1")
                        .await?,
                    Some(2)
                );
                assert_eq!(service.dispatcher().stats().removed, 0);
                Ok(())
            }

            /// `InvalidToken`, `InvalidToken`, `Delivered`, `InvalidToken`
            /// leaves the registrations in place with a count of one.
            #[tokio::test]
            async fn delivered_resets_the_count() -> TestResult {
                use PushSendOutcome::{Delivered, InvalidToken};
                let (service, _dir) =
                    run_outcomes(&[InvalidToken, InvalidToken, Delivered, InvalidToken]).await?;
                assert_eq!(service.store.tokens_for_routing_id(&RID).await?.len(), 2);
                assert_eq!(
                    service
                        .store
                        .invalid_token_failures(PushPlatform::Apns, b"t1")
                        .await?,
                    Some(1)
                );
                assert_eq!(service.dispatcher().stats().removed, 0);
                Ok(())
            }

            /// `Transient` and `ConfigError` never change the count, in
            /// either direction: they neither add to it nor reset it.
            #[tokio::test]
            async fn transient_and_config_error_leave_the_count() -> TestResult {
                use PushSendOutcome::{ConfigError, InvalidToken, Transient};
                let (service, _dir) = run_outcomes(&[
                    InvalidToken,
                    Transient,
                    ConfigError,
                    Transient,
                    InvalidToken,
                    ConfigError,
                ])
                .await?;
                assert_eq!(service.store.tokens_for_routing_id(&RID).await?.len(), 2);
                assert_eq!(
                    service
                        .store
                        .invalid_token_failures(PushPlatform::Apns, b"t1")
                        .await?,
                    Some(2)
                );
                let stats = service.dispatcher().stats();
                assert_eq!((stats.transient, stats.config_error), (2, 2));
                Ok(())
            }

            /// A job for a platform with no configured sender is dropped and
            /// counted, and changes nothing in the store. The gate refuses a
            /// registration for a platform without a sender, so the case
            /// arises when a relay restarts on the same store without the
            /// sender a stored registration needs.
            #[tokio::test]
            async fn job_without_a_sender_is_counted() -> TestResult {
                let fcm = RecordingSender::new(PushPlatform::Fcm, []);
                let (before, _dir) = service(vec![PushSender::Recording(fcm.clone())], 16)?;
                register(
                    &PushRole::Enabled(before.clone()),
                    REGISTRANT_A,
                    PushPlatform::Fcm,
                    b"t1",
                )
                .await?;
                let sender = RecordingSender::new(PushPlatform::Apns, []);
                let service = PushServiceConfig::new(
                    before.store.clone(),
                    verifier()?,
                    Arc::from(vec![PushSender::Recording(sender.clone())]),
                );
                let push = PushRole::Enabled(service.clone());
                let shutdown = CancellationToken::new();
                let drain = spawn_drain(&push, shutdown.clone()).ok_or("push enabled")?;
                notify(&push, &RID).await;
                for _ in 0..1000 {
                    if service.dispatcher().stats().no_sender == 1 {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                assert_eq!(service.dispatcher().stats().no_sender, 1);
                assert!(sender.sent().await.is_empty());
                assert!(fcm.sent().await.is_empty());
                assert_eq!(
                    service
                        .store
                        .invalid_token_failures(PushPlatform::Fcm, b"t1")
                        .await?,
                    Some(0)
                );
                shutdown.cancel();
                drain.await?;
                Ok(())
            }

            /// The drain stops on the shutdown token, and a second drain of
            /// the same queue (a restart on the same configuration) takes
            /// over.
            #[tokio::test]
            async fn drain_stops_on_shutdown_and_restarts() -> TestResult {
                use PushSendOutcome::Delivered;
                let sender = RecordingSender::new(PushPlatform::Apns, [Delivered, Delivered]);
                let (service, _dir) = service(vec![PushSender::Recording(sender.clone())], 16)?;
                let push = PushRole::Enabled(service);
                register(&push, REGISTRANT_A, PushPlatform::Apns, b"t1").await?;

                let first = CancellationToken::new();
                let drain = spawn_drain(&push, first.clone()).ok_or("push enabled")?;
                notify(&push, &RID).await;
                wait_for_sends(&sender, 1).await?;
                first.cancel();
                tokio::time::timeout(Duration::from_secs(5), drain).await??;

                let second = CancellationToken::new();
                let drain = spawn_drain(&push, second.clone()).ok_or("push enabled")?;
                notify(&push, &RID).await;
                wait_for_sends(&sender, 2).await?;
                second.cancel();
                tokio::time::timeout(Duration::from_secs(5), drain).await??;
                Ok(())
            }
        }
    }
}
