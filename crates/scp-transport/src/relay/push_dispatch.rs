//! The relay push dispatcher (spec §10.7.1 step 5 and `PushDeregistration`;
//! PUSH-008).
//!
//! After a relay stores a blob, delivers it to subscribers and answers the
//! publisher, it calls [`notify`] with the blob's routing ID. `notify` never
//! waits: it puts the routing ID on a bounded intake and returns, so no
//! publish waits on a lookup or a send.
//!
//! With push enabled, the relay's `PushService` runs two kinds of task, all
//! started by `PushService::start` and all stopped when the last clone of the
//! service is dropped:
//!
//! - **One lookup task** reads the intake, reads the (platform, token) pairs
//!   registered for each routing ID in one query on the blocking pool, and
//!   queues one job per token on that platform's queue.
//! - **One drain per configured sender**, each reading its own platform's
//!   queue, so a push service that stops answering stalls only its own
//!   platform. The APNs and FCM drains send one job at a time, and after a
//!   `Transient` outcome back off before their next send to that service.
//!   The `WebPush` drain differs, because each registrant chooses its own
//!   endpoint (PUSH-022 lane rule). It runs up to
//!   `WEBPUSH_CONCURRENT_SENDS` sends at once, of which at most
//!   `WEBPUSH_SENDS_PER_ORIGIN` go to one endpoint origin and at most
//!   `WEBPUSH_SENDS_PER_TICKET` wake one routing ID, and at most one sends to
//!   one token. A job that a cap holds back, or whose origin the `WebPush`
//!   sender is backing off, waits in the drain until it may start, in a
//!   queue keyed by what holds it back, so a finished send re-examines only
//!   the jobs it may free. A send the sender defers, because its origin
//!   began backing off or the relay's endpoint lookup pool was full, gives
//!   back its slots at once and waits the same way until the back-off ends
//!   or a lookup permit frees; no send sleeps holding a slot. A waiting job
//!   is never dropped, and neither a back-off nor a full lookup pool
//!   consumes it or counts against its origin or token. So origins that stop
//!   answering, or one routing ID's many tokens, hold at most their caps'
//!   share of the sends and delay no wake to another origin or routing ID,
//!   and one token's outcomes reach the store in order. Each drain applies
//!   the outcome to the registration store:
//!   - `Delivered` resets the token's consecutive failure count.
//!   - `InvalidToken` and `Unreachable` add one to it; at
//!     `INVALID_TOKEN_REMOVAL_THRESHOLD` (in `push_store`, a module the
//!     `push-store` feature compiles) the store removes every registration
//!     holding the token, in the same transaction.
//!   - `Transient` and `ConfigError` leave the count unchanged.
//!
//! The count is per token, because §10.7.1 removes registrations "after 3
//! consecutive delivery failures for the same token". A reset the store fails
//! to write is carried by the drain and folded into the token's next count
//! (`CountFrom::Zero`), so a lost reset never joins two runs of failures.
//! The drain carries that reset in memory only, so before the lookup queues
//! its first job it clears every stored count, retrying with back-off until
//! the clear lands. Every job comes from the lookup, so no outcome reaches
//! the store before the clear. A restart therefore costs a token at most the
//! failures counted before it, and never turns a stale count into a removal.
//!
//! # Bounds
//!
//! The intake and every platform queue hold at most `PUSH_QUEUE_CAPACITY`
//! entries; a `WebPush` job waiting in its drain still counts against its
//! queue. A wake that does not fit is dropped, and the publish still
//! succeeds (PUSH-008 AC2): a wake is advisory, and a device whose wake was
//! dropped pulls on its next wake or connection (§10.7).
//! The intake holds each routing ID at most once, and
//! a platform queue holds each token at most once. One routing ID holds at
//! most `MAX_WAKES_PER_PUBLISH` jobs queued or in flight at a time, so the
//! wakes for one routing ID, however many tokens are registered on it, leave
//! room in every queue for other routing IDs' wakes. §10.7.1 step 4 bounds
//! registrations only per identity (16, rejected with `4064`); a
//! per-routing-ID registration bound would need a rejection code ADR-004 does
//! not define, so the bound sits on the wakes queued instead. When a routing
//! ID holds more tokens than its free share, the lookup samples them at
//! random on each publish, so the tokens that sort first starve no other.
//!
//! Dropped wakes and failed store writes are logged without tokens, at most
//! one line per kind per minute, each line carrying the total so far and the
//! number of occurrences it stands for.
//!
//! Every listener of one relay (WebSocket, QUIC, UDP, WebTransport) holds a
//! clone of the relay's [`PushRole`](super::push_gate::PushRole), so a publish
//! on any transport reaches the one service. The only way to hold a service
//! is `PushService::start`, which starts its tasks, so no relay can hold a
//! push service whose drains are not running.
//!
//! A build without the `push-store` feature has no push service, and its
//! [`notify`] does nothing.

#[cfg(feature = "push-store")]
pub use enabled::*;

/// Does nothing, because a build without `push-store` has no push service.
///
/// The only [`PushRole`](super::push_gate::PushRole) of such a build is
/// `Disabled`; the signature matches the `push-store` build so every
/// transport calls it the same way.
#[cfg(not(feature = "push-store"))]
pub const fn notify(push: &super::push_gate::PushRole, _routing_id: &[u8; 32]) {
    match push {
        super::push_gate::PushRole::Disabled => {}
    }
}

#[cfg(feature = "push-store")]
mod enabled {
    use std::cmp::Reverse;
    use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
    use std::fmt;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
    use std::time::{Duration, Instant};

    use futures::StreamExt as _;
    use futures::stream::FuturesUnordered;
    use scp_protocol::discovery::push::PushPlatform;
    use sha2::{Digest, Sha256};
    use tokio::sync::mpsc;
    use tokio_util::sync::{CancellationToken, DropGuard};
    use zeroize::Zeroizing;

    use super::super::push::{PushSendOutcome, PushSender, SendAttempt, SendDeferral};
    use super::super::push_gate::{PushRole, PushServiceConfig};
    use super::super::push_store::{
        CountFrom, InvalidTokenOutcome, PushRegistrationStore, RoutingId, WakeToken,
    };
    use crate::backoff::ReconnectBackoff;

    /// The most entries the intake and each platform queue hold before new
    /// ones are dropped (§10.7.1 step 5; PUSH-008 indicator: 10,000).
    pub const PUSH_QUEUE_CAPACITY: usize = 10_000;

    /// The most jobs one routing ID holds queued or in flight at a time
    /// (indicator: a tenth of [`PUSH_QUEUE_CAPACITY`]). The module
    /// documentation, section Bounds, gives the clauses behind it.
    pub const MAX_WAKES_PER_PUBLISH: usize = 1_000;

    /// The shortest gap between two log lines of one kind (indicator: 60 s).
    const LOG_INTERVAL: Duration = Duration::from_secs(60);

    /// The first back-off after a `Transient` outcome (indicator: 1 s). It
    /// doubles on each further `Transient`, with up to 25% jitter.
    const TRANSIENT_BACKOFF_MIN: Duration = Duration::from_secs(1);

    /// The longest back-off after `Transient` outcomes (indicator: 60 s).
    const TRANSIENT_BACKOFF_MAX: Duration = Duration::from_secs(60);

    /// The most `WebPush` sends the `WebPush` drain runs at once (indicator:
    /// 32).
    pub const WEBPUSH_CONCURRENT_SENDS: usize = 32;

    /// The most `WebPush` sends in flight to one endpoint origin (PUSH-022
    /// lane rule; indicator: 4). An origin that stops answering holds at most
    /// these, each for at most the sender's request deadline.
    pub const WEBPUSH_SENDS_PER_ORIGIN: usize = 4;

    /// The most `WebPush` sends in flight that wake one routing ID (PUSH-022
    /// lane rule; indicator: 2). The tokens registered on one routing ID,
    /// whatever origins they name, hold at most these.
    pub const WEBPUSH_SENDS_PER_TICKET: usize = 2;

    /// A push service that could not start.
    #[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
    #[non_exhaustive]
    pub enum PushServiceError {
        /// [`PushService::start`] ran outside a tokio runtime, so it had
        /// nowhere to run its lookup and drains.
        #[error("the push service must start inside a tokio runtime")]
        NoRuntime,
        /// Two configured senders wake the same platform, so the service
        /// could not tell which one a token's wakes go through.
        #[error("two push senders are configured for {platform:?}")]
        DuplicateSender {
            /// The platform named twice.
            platform: PushPlatform,
        },
    }

    /// A SHA-256 of a token's platform tag and bytes: how a queue and a
    /// drain recognise a token without holding a second copy of it.
    type TokenKey = [u8; 32];

    fn token_key(platform: PushPlatform, token: &[u8]) -> TokenKey {
        let mut hasher = Sha256::new();
        hasher.update([platform.tag_byte()]);
        hasher.update(token);
        hasher.finalize().into()
    }

    fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        // Every critical section below leaves its value consistent at each
        // step, so a panic elsewhere while holding the lock leaves nothing
        // to repair.
        mutex.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// One wake to send: the platform, the token, and an opaque share of its
    /// routing ID's job count, and nothing else.
    ///
    /// A job carries no routing ID, blob or registrant identifier, so a job
    /// that leaks (through a log, a panic message, or memory) ties no token
    /// to a context or an identity. The token sits in a zeroizing buffer and
    /// `Debug` prints only its length.
    struct PushJob {
        platform: PushPlatform,
        token: Zeroizing<Vec<u8>>,
        /// Held until the send finishes; the lookup counts a routing ID's
        /// live jobs by the clones of its ticket.
        ticket: Arc<()>,
    }

    impl fmt::Debug for PushJob {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PushJob")
                .field("platform", &self.platform)
                .field("token_len", &self.token.len())
                .finish_non_exhaustive()
        }
    }

    /// What a rate-limited log call decided to write.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct LogLine {
        /// Occurrences of this kind since the service started.
        total: u64,
        /// Occurrences since the last line written, not counting this one.
        suppressed: u64,
    }

    /// A count of one kind of event that allows a log line at most once per
    /// [`LOG_INTERVAL`].
    #[derive(Debug, Default)]
    struct RateLimitedLog {
        total: AtomicU64,
        window: Mutex<LogWindow>,
    }

    #[derive(Debug, Default)]
    struct LogWindow {
        last: Option<Instant>,
        suppressed: u64,
    }

    impl RateLimitedLog {
        /// Counts one event; returns the line to write, if one is due.
        fn hit(&self) -> Option<LogLine> {
            self.hit_at(Instant::now())
        }

        fn hit_at(&self, now: Instant) -> Option<LogLine> {
            let total = self.total.fetch_add(1, Ordering::Relaxed).saturating_add(1);
            let mut window = lock(&self.window);
            let due = window
                .last
                .is_none_or(|last| now.saturating_duration_since(last) >= LOG_INTERVAL);
            let line = if due {
                window.last = Some(now);
                let suppressed = std::mem::take(&mut window.suppressed);
                Some(LogLine { total, suppressed })
            } else {
                window.suppressed = window.suppressed.saturating_add(1);
                None
            };
            drop(window);
            line
        }

        #[cfg(test)]
        fn total(&self) -> u64 {
            self.total.load(Ordering::Relaxed)
        }
    }

    /// One rate-limited log per kind of dropped wake or failed write.
    #[derive(Debug, Default)]
    struct Logs {
        intake_full: RateLimitedLog,
        intake_closed: RateLimitedLog,
        queue_full: RateLimitedLog,
        queue_closed: RateLimitedLog,
        no_sender: RateLimitedLog,
        lookup_failed: RateLimitedLog,
        clear_failed: RateLimitedLog,
        store_failed: RateLimitedLog,
        config_error: RateLimitedLog,
    }

    /// The sizes the service runs with. Production uses
    /// [`Limits::PRODUCTION`]; the tests shrink them to fill a queue.
    #[derive(Debug, Clone, Copy)]
    struct Limits {
        queue_capacity: usize,
        wakes_per_publish: usize,
    }

    impl Limits {
        const PRODUCTION: Self = Self {
            queue_capacity: PUSH_QUEUE_CAPACITY,
            wakes_per_publish: MAX_WAKES_PER_PUBLISH,
        };
    }

    /// The relay's running push service: the configuration it was started
    /// with, the intake [`notify`] writes to, and the tasks that read it.
    /// Clones share one service; dropping the last clone stops its tasks.
    #[derive(Clone)]
    pub struct PushService {
        inner: Arc<Inner>,
    }

    struct Inner {
        config: PushServiceConfig,
        intake: mpsc::Sender<RoutingId>,
        /// The routing IDs on the intake, so one routing ID holds at most one
        /// intake slot however often it is published to.
        pending: Arc<Mutex<HashSet<RoutingId>>>,
        logs: Arc<Logs>,
        /// Cancels the lookup and every drain when the last clone drops.
        _stop: DropGuard,
    }

    impl fmt::Debug for PushService {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PushService")
                .field("config", &self.inner.config)
                .finish_non_exhaustive()
        }
    }

    impl PushService {
        /// Starts a push service on `config`: one lookup task and one drain
        /// per configured sender, on the current tokio runtime.
        ///
        /// # Errors
        ///
        /// - [`PushServiceError::NoRuntime`] outside a tokio runtime.
        /// - [`PushServiceError::DuplicateSender`] when two senders wake the
        ///   same platform.
        pub fn start(config: PushServiceConfig) -> Result<Self, PushServiceError> {
            Self::start_with(config, Limits::PRODUCTION)
        }

        /// As [`Self::start`], with queues of `queue_capacity` entries and at
        /// most `wakes_per_publish` jobs per routing ID, so a test can fill a
        /// queue.
        #[cfg(test)]
        pub(crate) fn start_with_limits(
            config: PushServiceConfig,
            queue_capacity: usize,
            wakes_per_publish: usize,
        ) -> Result<Self, PushServiceError> {
            Self::start_with(
                config,
                Limits {
                    queue_capacity,
                    wakes_per_publish,
                },
            )
        }

        fn start_with(config: PushServiceConfig, limits: Limits) -> Result<Self, PushServiceError> {
            let runtime =
                tokio::runtime::Handle::try_current().map_err(|_| PushServiceError::NoRuntime)?;
            let mut platforms = HashSet::new();
            for sender in config.senders.iter() {
                if !platforms.insert(sender.platform()) {
                    return Err(PushServiceError::DuplicateSender {
                        platform: sender.platform(),
                    });
                }
            }
            let stop = CancellationToken::new();
            let logs = Arc::new(Logs::default());
            let mut lanes = Vec::with_capacity(config.senders.len());
            for (index, sender) in config.senders.iter().enumerate() {
                let (tx, rx) = mpsc::channel(limits.queue_capacity);
                let queued = Arc::new(Mutex::new(HashSet::new()));
                runtime.spawn(
                    Drain {
                        senders: Arc::clone(&config.senders),
                        index,
                        store: config.store.clone(),
                        queued: Arc::clone(&queued),
                        logs: Arc::clone(&logs),
                        stop: stop.clone(),
                        pending_resets: HashSet::new(),
                    }
                    .run(rx),
                );
                lanes.push(Lane {
                    platform: sender.platform(),
                    tx,
                    queued,
                });
            }
            let (intake, intake_rx) = mpsc::channel(limits.queue_capacity);
            let pending = Arc::new(Mutex::new(HashSet::new()));
            runtime.spawn(
                Lookup {
                    store: config.store.clone(),
                    lanes,
                    pending: Arc::clone(&pending),
                    logs: Arc::clone(&logs),
                    limits,
                    tickets: HashMap::new(),
                }
                .run(intake_rx, stop.clone()),
            );
            Ok(Self {
                inner: Arc::new(Inner {
                    config,
                    intake,
                    pending,
                    logs,
                    _stop: stop.drop_guard(),
                }),
            })
        }

        /// The configuration the service was started with.
        #[must_use]
        pub fn config(&self) -> &PushServiceConfig {
            &self.inner.config
        }

        fn notify(&self, routing_id: &RoutingId) {
            let inner = &self.inner;
            let mut pending = lock(&inner.pending);
            if pending.contains(routing_id) {
                // Already waiting for the lookup, which reads the store when
                // it reaches the routing ID and so sees this blob too.
                return;
            }
            let refused = match inner.intake.try_send(*routing_id) {
                Ok(()) => {
                    pending.insert(*routing_id);
                    return;
                }
                Err(mpsc::error::TrySendError::Full(_)) => &inner.logs.intake_full,
                Err(mpsc::error::TrySendError::Closed(_)) => &inner.logs.intake_closed,
            };
            drop(pending);
            if let Some(line) = refused.hit() {
                tracing::warn!(
                    total = line.total,
                    suppressed = line.suppressed,
                    capacity = inner.intake.max_capacity(),
                    closed = inner.intake.is_closed(),
                    "push intake refused a routing ID; wake dropped"
                );
            }
        }
    }

    /// Asks the relay's push service to wake every device registered for
    /// `routing_id`, after the relay stored a blob there, delivered it and
    /// answered the publisher (§10.7.1 step 5).
    ///
    /// It never waits and never fails: it puts the routing ID on the
    /// service's intake, or drops the wake and logs it when the intake is
    /// full (module documentation, section Bounds). With push disabled it
    /// does nothing.
    pub fn notify(push: &PushRole, routing_id: &RoutingId) {
        if let PushRole::Enabled(service) = push {
            service.notify(routing_id);
        }
    }

    /// One platform's queue, as the lookup writes it.
    struct Lane {
        platform: PushPlatform,
        tx: mpsc::Sender<PushJob>,
        /// The tokens on the queue, so one token holds at most one slot.
        queued: Arc<Mutex<HashSet<TokenKey>>>,
    }

    /// The lookup task: routing IDs in, jobs out.
    struct Lookup {
        store: PushRegistrationStore,
        lanes: Vec<Lane>,
        pending: Arc<Mutex<HashSet<RoutingId>>>,
        logs: Arc<Logs>,
        limits: Limits,
        /// One ticket per routing ID with live jobs; each live job holds a
        /// clone, so a ticket's strong count less the map's is its routing
        /// ID's live jobs.
        tickets: HashMap<RoutingId, Arc<()>>,
    }

    impl Lookup {
        async fn run(mut self, mut intake: mpsc::Receiver<RoutingId>, stop: CancellationToken) {
            if !self.clear_stale_counts(&stop).await {
                return;
            }
            loop {
                let routing_id = tokio::select! {
                    biased;
                    () = stop.cancelled() => return,
                    next = intake.recv() => next,
                };
                // The service holds the intake's sender, so `None` means the
                // service is gone; stopping is the only sound reading.
                let Some(routing_id) = routing_id else { return };
                // Removed before the lookup, so a blob stored while the
                // lookup runs queues the routing ID again.
                lock(&self.pending).remove(&routing_id);
                tokio::select! {
                    biased;
                    () = stop.cancelled() => return,
                    () = self.lookup_once(&routing_id) => {}
                }
            }
        }

        /// Clears every stored invalid-token count before the first job, so a
        /// reset a drain carried before a restart cannot leave a stale count
        /// that the next `InvalidToken` turns into a removal. Retries with
        /// back-off until the clear lands, queuing no job meanwhile; wakes
        /// published meanwhile wait on the intake or are dropped when it is
        /// full. `false` when the service stopped first.
        async fn clear_stale_counts(&self, stop: &CancellationToken) -> bool {
            let mut backoff = ReconnectBackoff::new(TRANSIENT_BACKOFF_MIN, TRANSIENT_BACKOFF_MAX);
            loop {
                let cleared = tokio::select! {
                    biased;
                    () = stop.cancelled() => return false,
                    cleared = self.store.clear_all_invalid_tokens() => cleared,
                };
                match cleared {
                    Ok(()) => return true,
                    Err(e) => {
                        if let Some(line) = self.logs.clear_failed.hit() {
                            tracing::warn!(
                                total = line.total,
                                suppressed = line.suppressed,
                                error = %e,
                                "could not clear stored invalid-token counts; push wakes held until the clear lands"
                            );
                        }
                    }
                }
                tokio::select! {
                    biased;
                    () = stop.cancelled() => return false,
                    () = tokio::time::sleep(backoff.next_delay()) => {}
                }
            }
        }

        /// Queues one job per token registered for `routing_id`, up to the
        /// routing ID's free share of `wakes_per_publish`.
        async fn lookup_once(&mut self, routing_id: &RoutingId) {
            let ticket = Arc::clone(self.tickets.entry(*routing_id).or_default());
            // Less the map's clone and this one.
            let live = Arc::strong_count(&ticket).saturating_sub(2);
            let room = self.limits.wakes_per_publish.saturating_sub(live);
            if room == 0 {
                tracing::debug!("routing ID already holds its share of push jobs; wake coalesced");
                return;
            }
            let tokens = match self.store.wake_tokens(routing_id, room).await {
                Ok(tokens) => tokens,
                Err(e) => {
                    if let Some(line) = self.logs.lookup_failed.hit() {
                        tracing::warn!(
                            total = line.total,
                            suppressed = line.suppressed,
                            error = %e,
                            "push registration lookup failed; wake dropped"
                        );
                    }
                    return;
                }
            };
            for WakeToken { platform, token } in tokens {
                self.queue(platform, token, &ticket);
            }
            drop(ticket);
            self.prune_tickets();
        }

        fn queue(&self, platform: PushPlatform, token: Zeroizing<Vec<u8>>, ticket: &Arc<()>) {
            let Some(lane) = self.lanes.iter().find(|lane| lane.platform == platform) else {
                if let Some(line) = self.logs.no_sender.hit() {
                    tracing::warn!(
                        platform = ?platform,
                        total = line.total,
                        suppressed = line.suppressed,
                        "no push sender for platform; wake dropped"
                    );
                }
                return;
            };
            let key = token_key(platform, &token);
            let mut queued = lock(&lane.queued);
            if queued.contains(&key) {
                // Already queued; that job wakes the device.
                return;
            }
            // `queued` also holds the jobs a `WebPush` drain keeps waiting,
            // so this bounds them with the queue.
            let refused = if queued.len() >= lane.tx.max_capacity() {
                &self.logs.queue_full
            } else {
                let job = PushJob {
                    platform,
                    token,
                    ticket: Arc::clone(ticket),
                };
                match lane.tx.try_send(job) {
                    Ok(()) => {
                        queued.insert(key);
                        return;
                    }
                    Err(mpsc::error::TrySendError::Full(_)) => &self.logs.queue_full,
                    Err(mpsc::error::TrySendError::Closed(_)) => &self.logs.queue_closed,
                }
            };
            drop(queued);
            if let Some(line) = refused.hit() {
                tracing::warn!(
                    platform = ?platform,
                    total = line.total,
                    suppressed = line.suppressed,
                    capacity = lane.tx.max_capacity(),
                    closed = lane.tx.is_closed(),
                    "push queue refused a job; wake dropped"
                );
            }
        }

        /// Forgets the tickets no job holds once the map outgrows twice the
        /// jobs that can be live, so it never grows past that.
        fn prune_tickets(&mut self) {
            let most_live = self
                .limits
                .queue_capacity
                .saturating_add(1)
                .saturating_mul(self.lanes.len().max(1));
            if self.tickets.len() > most_live.saturating_mul(2) {
                self.tickets.retain(|_, t| Arc::strong_count(t) > 1);
            }
        }
    }

    /// One platform's drain: jobs in, sends out, outcomes into the store.
    struct Drain {
        senders: Arc<[PushSender]>,
        index: usize,
        store: PushRegistrationStore,
        /// The tokens on this platform's queue or, for `WebPush`, waiting in
        /// the drain; a token leaves when its send starts.
        queued: Arc<Mutex<HashSet<TokenKey>>>,
        logs: Arc<Logs>,
        stop: CancellationToken,
        /// Tokens whose last outcome was `Delivered` but whose count reset
        /// the store failed to write. At most [`PUSH_QUEUE_CAPACITY`].
        pending_resets: HashSet<TokenKey>,
    }

    /// A `WebPush` job in the drain, with what its caps are keyed by.
    struct Held {
        key: TokenKey,
        job: PushJob,
        /// The endpoint origin; `None` when the token does not decode, whose
        /// send sends nothing.
        origin: Option<String>,
        /// Whether a freed lookup permit restarted this send from the lookup
        /// wait, which the drain owes a restart of another held send when
        /// this one ends, since the send may end without taking the permit.
        granted: bool,
    }

    impl Held {
        /// The routing ID's ticket, by address: one per routing ID while any
        /// of its jobs lives.
        fn ticket(&self) -> usize {
            Arc::as_ptr(&self.job.ticket).addr()
        }

        /// The group this job waits in: its routing ID's jobs to its origin.
        fn group(&self) -> Group {
            (self.ticket(), self.origin.clone())
        }

        /// The keys whose caps this job counts against while in flight.
        fn gates(&self) -> impl Iterator<Item = Gate> + use<> {
            [
                Some(Gate::Token(self.key)),
                Some(Gate::Ticket(self.ticket())),
                self.origin.clone().map(Gate::Origin),
            ]
            .into_iter()
            .flatten()
        }
    }

    /// A key whose cap, or whose origin's back-off, can keep a held `WebPush`
    /// job from starting. Each blocked group of jobs waits in the list of the
    /// key that blocks its oldest job, so a finished send re-examines only the
    /// lists of the keys it frees.
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    enum Gate {
        /// The token's own send is in flight.
        Token(TokenKey),
        /// The routing ID holds [`WEBPUSH_SENDS_PER_TICKET`] sends.
        Ticket(usize),
        /// The origin holds [`WEBPUSH_SENDS_PER_ORIGIN`] sends or is backing
        /// off.
        Origin(String),
    }

    /// Why a held `WebPush` job may not start now.
    enum Block {
        /// The drain runs [`WEBPUSH_CONCURRENT_SENDS`] sends.
        Sends,
        /// A key's cap.
        Cap(Gate),
        /// The origin is backing off until then.
        Backoff(String, tokio::time::Instant),
    }

    /// When an origin's back-off ends, while it is backing off.
    type RetryAt<'a> = &'a dyn Fn(&str) -> Option<tokio::time::Instant>;

    /// The `WebPush` drain's sends in flight, counted by what caps them.
    #[derive(Default)]
    struct InFlight {
        sends: usize,
        tokens: HashSet<TokenKey>,
        origins: HashMap<String, usize>,
        tickets: HashMap<usize, usize>,
    }

    impl InFlight {
        /// What keeps `held` from starting now: its token's send, its routing
        /// ID's cap, its origin's cap or back-off, then the drain-wide cap.
        fn block(&self, held: &Held, retry_at: RetryAt<'_>) -> Option<Block> {
            if self.tokens.contains(&held.key) {
                return Some(Block::Cap(Gate::Token(held.key)));
            }
            let ticket = held.ticket();
            if self.tickets.get(&ticket).copied().unwrap_or(0) >= WEBPUSH_SENDS_PER_TICKET {
                return Some(Block::Cap(Gate::Ticket(ticket)));
            }
            if let Some(origin) = &held.origin {
                if self.origins.get(origin).copied().unwrap_or(0) >= WEBPUSH_SENDS_PER_ORIGIN {
                    return Some(Block::Cap(Gate::Origin(origin.clone())));
                }
                if let Some(until) = retry_at(origin) {
                    return Some(Block::Backoff(origin.clone(), until));
                }
            }
            self.full().then_some(Block::Sends)
        }

        const fn full(&self) -> bool {
            self.sends >= WEBPUSH_CONCURRENT_SENDS
        }

        fn add(&mut self, held: &Held) {
            self.sends += 1;
            self.tokens.insert(held.key);
            *self.tickets.entry(held.ticket()).or_default() += 1;
            if let Some(origin) = &held.origin {
                *self.origins.entry(origin.clone()).or_default() += 1;
            }
        }

        fn remove(&mut self, held: &Held) {
            self.sends = self.sends.saturating_sub(1);
            self.tokens.remove(&held.key);
            let ticket = held.ticket();
            if let Some(count) = self.tickets.get_mut(&ticket) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.tickets.remove(&ticket);
                }
            }
            if let Some(origin) = &held.origin
                && let Some(count) = self.origins.get_mut(origin)
            {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.origins.remove(origin);
                }
            }
        }
    }

    /// A routing ID's held jobs to one endpoint origin: its ticket's address
    /// and the origin. The jobs of one group share every key but their
    /// tokens, so they wait together, oldest first.
    type Group = (usize, Option<String>);

    /// What a waiting group waits on.
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    enum List {
        /// A key whose cap or back-off blocks the group's oldest job.
        Key(Gate),
        /// Only a drain-wide slot.
        Sends,
    }

    /// The `WebPush` jobs the drain holds.
    ///
    /// A blocked job waits in its group, behind the group's older jobs, and
    /// each non-empty group waits in exactly one list: that of the key whose
    /// cap or back-off blocks the group's oldest job, or `Sends` when only
    /// the drain-wide cap does. A job whose send found the endpoint lookup
    /// pool full waits in `lookup` instead. A list keeps the order its groups
    /// began waiting on it, and a new group sharing a key with a non-empty
    /// list joins the back of that list.
    ///
    /// A list is examined again only when its key frees: a send holding the
    /// key ends, the origin's back-off ends (`timers`), or, for a list whose
    /// head group waits only on a drain-wide slot (listed in `stalled`), a
    /// drain-wide slot frees. Each examination starts the head group's oldest
    /// job, moves the whole group to the list of what now blocks it, or ends
    /// the pass over that list. Moving a group costs the same whatever its
    /// length, so the cost of one event grows with the jobs it starts and the
    /// groups it moves, never with the jobs held.
    #[derive(Default)]
    struct Waiting {
        /// The non-empty groups, each oldest job first.
        groups: HashMap<Group, VecDeque<Held>>,
        /// The non-empty lists; each group in `groups` is in exactly one.
        lists: HashMap<List, VecDeque<Group>>,
        lookup: VecDeque<Held>,
        /// The keys whose list's head group waits only on a drain-wide slot,
        /// in the order they stalled; `stalled_set` holds the same keys.
        stalled: VecDeque<Gate>,
        stalled_set: HashSet<Gate>,
        /// Origin back-off ends to re-examine at, earliest first. `timer_at`
        /// holds each origin's earliest pending end; a heap entry that no
        /// longer matches it is stale and skipped.
        timers: BinaryHeap<Reverse<(tokio::time::Instant, String)>>,
        timer_at: HashMap<String, tokio::time::Instant>,
        /// Jobs examined so far, for the cost bound the tests check.
        #[cfg(test)]
        examined: usize,
    }

    impl Waiting {
        /// Takes in a job that is not waiting: queues it behind its group's
        /// jobs when the group waits, starts it into `ready` when nothing
        /// blocks it, and otherwise opens its group in the list of a key it
        /// shares with a waiting group, or of what blocks it.
        fn arrive(
            &mut self,
            held: Held,
            in_flight: &mut InFlight,
            retry_at: RetryAt<'_>,
            ready: &mut Vec<Held>,
        ) {
            #[cfg(test)]
            {
                self.examined += 1;
            }
            let group = held.group();
            if let Some(jobs) = self.groups.get_mut(&group) {
                jobs.push_back(held);
                return;
            }
            // `lists` holds no empty list.
            if let Some(gate) = held
                .gates()
                .find(|gate| self.lists.contains_key(&List::Key(gate.clone())))
            {
                self.groups.insert(group.clone(), VecDeque::from([held]));
                self.lists
                    .entry(List::Key(gate))
                    .or_default()
                    .push_back(group);
                return;
            }
            match in_flight.block(&held, retry_at) {
                None => Self::start(held, in_flight, ready),
                Some(block) => {
                    self.groups.insert(group.clone(), VecDeque::from([held]));
                    self.park(group, block);
                }
            }
        }

        /// Holds a job whose send was deferred and that is no longer in
        /// flight: until a lookup permit frees, or as a new arrival, which
        /// waits out its origin's back-off.
        fn hold(
            &mut self,
            held: Held,
            deferral: SendDeferral,
            in_flight: &mut InFlight,
            retry_at: RetryAt<'_>,
            ready: &mut Vec<Held>,
        ) {
            match deferral {
                SendDeferral::LookupPoolFull => self.lookup.push_back(held),
                SendDeferral::BackingOff(_) => self.arrive(held, in_flight, retry_at, ready),
            }
        }

        fn start(held: Held, in_flight: &mut InFlight, ready: &mut Vec<Held>) {
            in_flight.add(&held);
            ready.push(held);
        }

        /// Puts `group`, which is in no list, at the back of the list of what
        /// blocks its oldest job.
        fn park(&mut self, group: Group, block: Block) {
            let list = match block {
                Block::Sends => List::Sends,
                Block::Cap(gate) => List::Key(gate),
                Block::Backoff(origin, until) => {
                    self.schedule(&origin, until);
                    List::Key(Gate::Origin(origin))
                }
            };
            self.lists.entry(list).or_default().push_back(group);
        }

        /// Re-examines `origin`'s list at `until`, unless an earlier
        /// re-examination is pending, which schedules the next one itself.
        fn schedule(&mut self, origin: &str, until: tokio::time::Instant) {
            if self.timer_at.get(origin).is_some_and(|at| *at <= until) {
                return;
            }
            self.timer_at.insert(origin.to_owned(), until);
            self.timers.push(Reverse((until, origin.to_owned())));
        }

        fn stall(&mut self, gate: Gate) {
            if self.stalled_set.insert(gate.clone()) {
                self.stalled.push_back(gate);
            }
        }

        /// Takes the head group off `list`, dropping the list once empty.
        fn pop_group(&mut self, list: &List) -> Option<Group> {
            let groups = self.lists.get_mut(list)?;
            let group = groups.pop_front();
            if groups.is_empty() {
                self.lists.remove(list);
            }
            group
        }

        /// Starts the oldest jobs of the head groups of `list`, or moves a
        /// head group on to the list of what now blocks it, until the head
        /// group waits on `list`'s own key or on a drain-wide slot.
        fn pass(
            &mut self,
            list: &List,
            in_flight: &mut InFlight,
            retry_at: RetryAt<'_>,
            ready: &mut Vec<Held>,
        ) {
            loop {
                let Some(group) = self.lists.get(list).and_then(VecDeque::front) else {
                    return;
                };
                let Some(head) = self.groups.get(group).and_then(VecDeque::front) else {
                    // `groups` holds no empty group, so this does not happen;
                    // if it ever does, the list moves on rather than stop.
                    self.pop_group(list);
                    continue;
                };
                let block = in_flight.block(head, retry_at);
                #[cfg(test)]
                {
                    self.examined += 1;
                }
                match (list, &block) {
                    (List::Sends, Some(Block::Sends)) => return,
                    (List::Key(own), Some(Block::Sends)) => {
                        self.stall(own.clone());
                        return;
                    }
                    (List::Key(own), Some(Block::Cap(blocking))) if blocking == own => return,
                    (List::Key(Gate::Origin(own)), Some(Block::Backoff(origin, until)))
                        if own == origin =>
                    {
                        self.schedule(origin, *until);
                        return;
                    }
                    _ => {}
                }
                let Some(group) = self.pop_group(list) else {
                    return;
                };
                match block {
                    None => {
                        let Some(jobs) = self.groups.get_mut(&group) else {
                            continue;
                        };
                        if let Some(next) = jobs.pop_front() {
                            Self::start(next, in_flight, ready);
                        }
                        if jobs.is_empty() {
                            self.groups.remove(&group);
                        } else {
                            // The group's next job is examined at once, still
                            // at the head of this list.
                            self.lists
                                .entry(list.clone())
                                .or_default()
                                .push_front(group);
                        }
                    }
                    Some(block) => self.park(group, block),
                }
            }
        }

        /// Re-examines what a send that is no longer in flight frees: the
        /// lists of its `gates`, then, while a drain-wide slot is free, the
        /// stalled lists and `Sends`.
        fn freed(
            &mut self,
            gates: impl IntoIterator<Item = Gate>,
            in_flight: &mut InFlight,
            retry_at: RetryAt<'_>,
            ready: &mut Vec<Held>,
        ) {
            for gate in gates {
                self.pass(&List::Key(gate), in_flight, retry_at, ready);
            }
            while !in_flight.full()
                && let Some(gate) = self.stalled.pop_front()
            {
                self.stalled_set.remove(&gate);
                self.pass(&List::Key(gate), in_flight, retry_at, ready);
            }
            if !in_flight.full() {
                self.pass(&List::Sends, in_flight, retry_at, ready);
            }
        }

        /// When the earliest pending back-off re-examination is due.
        fn next_timer(&self) -> Option<tokio::time::Instant> {
            self.timers.peek().map(|Reverse((at, _))| *at)
        }

        /// Re-examines the list of every origin whose back-off ended by
        /// `now`.
        fn timers_due(
            &mut self,
            now: tokio::time::Instant,
            in_flight: &mut InFlight,
            retry_at: RetryAt<'_>,
            ready: &mut Vec<Held>,
        ) {
            while self.next_timer().is_some_and(|at| at <= now)
                && let Some(Reverse((at, origin))) = self.timers.pop()
            {
                if self.timer_at.get(&origin) == Some(&at) {
                    self.timer_at.remove(&origin);
                    self.pass(&List::Key(Gate::Origin(origin)), in_flight, retry_at, ready);
                }
            }
        }

        /// How many jobs wait, in every group and in `lookup`.
        #[cfg(test)]
        fn held(&self) -> usize {
            self.groups.values().map(VecDeque::len).sum::<usize>() + self.lookup.len()
        }

        /// Whether a job waits on a lookup permit.
        fn awaits_lookup(&self) -> bool {
            !self.lookup.is_empty()
        }

        /// Starts the oldest jobs that wait on a lookup permit, one per
        /// permit free in the pool, so a freed permit restarts one held send
        /// rather than every one. A job a cap or a back-off holds leaves the
        /// lookup wait for that wait and takes none of the permits, so the
        /// next job is tried in its place. Each started job is marked
        /// `granted`; when its send ends, taking a permit or not, the drain
        /// calls this again with the permits free then (see
        /// [`Drain::run_concurrent`]). A started job whose send finds the
        /// pool full again comes back here without any request made.
        fn lookup_freed(
            &mut self,
            permits: usize,
            in_flight: &mut InFlight,
            retry_at: RetryAt<'_>,
            ready: &mut Vec<Held>,
        ) {
            let mut started = 0;
            while started < permits {
                let Some(held) = self.lookup.pop_front() else {
                    return;
                };
                let before = ready.len();
                self.arrive(held, in_flight, retry_at, ready);
                if ready.len() > before
                    && let Some(granted) = ready.last_mut()
                {
                    granted.granted = true;
                    started += 1;
                }
            }
        }
    }

    /// Sends `held`'s job through `sender`.
    async fn send_held(sender: &PushSender, held: Held) -> (Held, SendAttempt) {
        let attempt = sender.send_registered(&held.job.token).await;
        (held, attempt)
    }

    /// What the `WebPush` drain does next.
    enum Step {
        Job(Option<PushJob>),
        Sent(Held, SendAttempt),
        BackoffEnded,
        /// A lookup permit freed; this many are free now.
        LookupFreed(usize),
    }

    impl Drain {
        async fn run(mut self, rx: mpsc::Receiver<PushJob>) {
            let senders = Arc::clone(&self.senders);
            let Some(sender) = senders.get(self.index) else {
                // `start_with` takes `index` from enumerating this same
                // slice, so this cannot happen; if it ever does, say so
                // rather than leave a platform silently without a drain.
                tracing::error!(
                    index = self.index,
                    senders = senders.len(),
                    "push drain has no sender at its index; platform not woken"
                );
                return;
            };
            if sender.platform() == PushPlatform::WebPush {
                self.run_concurrent(sender, rx).await;
            } else {
                self.run_serial(sender, rx).await;
            }
        }

        /// The APNs and FCM drain: one send at a time, and a platform-wide
        /// back-off after `Transient`. APNs and FCM sends never defer; a
        /// deferred send is held here and sent again once its reason ends.
        async fn run_serial(&mut self, sender: &PushSender, mut rx: mpsc::Receiver<PushJob>) {
            let mut backoff = ReconnectBackoff::new(TRANSIENT_BACKOFF_MIN, TRANSIENT_BACKOFF_MAX);
            loop {
                let job = tokio::select! {
                    biased;
                    () = self.stop.cancelled() => return,
                    job = rx.recv() => job,
                };
                // The lookup holds the queue's sender until it stops, so
                // `None` means the service is gone.
                let Some(job) = job else { return };
                let key = token_key(job.platform, &job.token);
                lock(&self.queued).remove(&key);
                let outcome = loop {
                    let attempt = tokio::select! {
                        biased;
                        () = self.stop.cancelled() => return,
                        attempt = sender.send_registered(&job.token) => attempt,
                    };
                    match attempt {
                        SendAttempt::Sent(outcome) => break outcome,
                        SendAttempt::Deferred(SendDeferral::BackingOff(until)) => {
                            tokio::select! {
                                biased;
                                () = self.stop.cancelled() => return,
                                () = tokio::time::sleep_until(until) => {}
                            }
                        }
                        SendAttempt::Deferred(SendDeferral::LookupPoolFull) => {
                            tokio::select! {
                                biased;
                                () = self.stop.cancelled() => return,
                                _ = sender.lookup_permit_freed() => {}
                            }
                        }
                    }
                };
                if !self.apply(job.platform, key, &job.token, outcome).await {
                    return;
                }
                let PushJob { ticket, .. } = job;
                drop(ticket);
                if outcome == PushSendOutcome::Transient {
                    if !self.pause(backoff.next_delay()).await {
                        return;
                    }
                } else {
                    backoff.reset();
                }
            }
        }

        /// The `WebPush` drain: up to [`WEBPUSH_CONCURRENT_SENDS`] sends at
        /// once, at most [`WEBPUSH_SENDS_PER_ORIGIN`] to one endpoint origin,
        /// at most [`WEBPUSH_SENDS_PER_TICKET`] for one routing ID, and one
        /// per token, with no drain-wide back-off.
        ///
        /// The drain reads every job as it arrives. A job a cap holds back,
        /// or whose origin the sender is backing off, waits in [`Waiting`]
        /// and keeps its token in `queued`, so the lookup still coalesces a
        /// further wake for that token into it and counts it against the
        /// queue's capacity. A send the sender defers (its origin began
        /// backing off, or the lookup pool was full) gives up its slots at
        /// once and is held the same way, unless a newer job for its token
        /// is already queued, which then wakes the device instead. Outcomes
        /// are applied on this task, one at a time, and a token never has two
        /// sends in flight, so one token's outcomes reach the store in send
        /// order.
        async fn run_concurrent(&mut self, sender: &PushSender, mut rx: mpsc::Receiver<PushJob>) {
            let mut sends = FuturesUnordered::new();
            let mut in_flight = InFlight::default();
            let mut waiting = Waiting::default();
            let retry_at = |origin: &str| sender.origin_retry_at(origin);
            loop {
                let next_timer = waiting.next_timer();
                let step = tokio::select! {
                    biased;
                    () = self.stop.cancelled() => return,
                    Some((done, attempt)) = sends.next(), if !sends.is_empty() => {
                        Step::Sent(done, attempt)
                    }
                    job = rx.recv() => Step::Job(job),
                    () = tokio::time::sleep_until(
                        next_timer.unwrap_or_else(tokio::time::Instant::now)
                    ), if next_timer.is_some() => Step::BackoffEnded,
                    permits = sender.lookup_permit_freed(), if waiting.awaits_lookup() => {
                        Step::LookupFreed(permits)
                    }
                };
                let mut ready = Vec::new();
                // Whether a send a freed lookup permit restarted has ended.
                let mut granted = false;
                match step {
                    // The lookup holds the queue's sender until it stops, so
                    // `None` means the service is gone.
                    Step::Job(None) => return,
                    Step::Job(Some(job)) => {
                        let held = Held {
                            key: token_key(job.platform, &job.token),
                            origin: sender.origin_of(&job.token),
                            job,
                            granted: false,
                        };
                        waiting.arrive(held, &mut in_flight, &retry_at, &mut ready);
                    }
                    Step::Sent(mut done, SendAttempt::Sent(outcome)) => {
                        in_flight.remove(&done);
                        granted = std::mem::take(&mut done.granted);
                        if !self
                            .apply(done.job.platform, done.key, &done.job.token, outcome)
                            .await
                        {
                            return;
                        }
                        waiting.freed(done.gates(), &mut in_flight, &retry_at, &mut ready);
                        drop(done);
                    }
                    Step::Sent(mut done, SendAttempt::Deferred(deferral)) => {
                        in_flight.remove(&done);
                        granted = std::mem::take(&mut done.granted);
                        let gates: Vec<Gate> = done.gates().collect();
                        self.hold_deferred(
                            done,
                            deferral,
                            &mut waiting,
                            &mut in_flight,
                            &retry_at,
                            &mut ready,
                        );
                        waiting.freed(gates, &mut in_flight, &retry_at, &mut ready);
                    }
                    Step::BackoffEnded => waiting.timers_due(
                        tokio::time::Instant::now(),
                        &mut in_flight,
                        &retry_at,
                        &mut ready,
                    ),
                    Step::LookupFreed(permits) => {
                        waiting.lookup_freed(permits, &mut in_flight, &retry_at, &mut ready);
                    }
                }
                // A restarted send that ended may never have taken a lookup
                // permit: it reused a pooled connection, or was deferred
                // first. No permit drop then signals `freed`, so the drain
                // hands its grant on itself, to as many held sends as permits
                // are free now. A send that did take one hands it on here
                // and through `freed`; an extra restart that finds the pool
                // full comes back without any request made.
                if granted
                    && waiting.awaits_lookup()
                    && let Some(free) = sender.free_lookup_permits()
                {
                    waiting.lookup_freed(free, &mut in_flight, &retry_at, &mut ready);
                }
                if !ready.is_empty() {
                    let mut queued = lock(&self.queued);
                    for held in &ready {
                        // A wake for the token from now on queues another job.
                        queued.remove(&held.key);
                    }
                }
                for held in ready {
                    sends.push(send_held(sender, held));
                }
            }
        }

        /// Holds `done`, whose send was deferred and is no longer in flight,
        /// unless a newer job for its token is queued or waiting, which then
        /// wakes the device instead. Checked before anything freed starts, so
        /// a newer job that starts now is still seen as queued.
        fn hold_deferred(
            &self,
            done: Held,
            deferral: SendDeferral,
            waiting: &mut Waiting,
            in_flight: &mut InFlight,
            retry_at: RetryAt<'_>,
            ready: &mut Vec<Held>,
        ) {
            if !lock(&self.queued).insert(done.key) {
                return;
            }
            waiting.hold(done, deferral, in_flight, retry_at, ready);
        }

        /// Sleeps for `delay`; `false` when the service stopped meanwhile.
        async fn pause(&self, delay: Duration) -> bool {
            tokio::select! {
                biased;
                () = self.stop.cancelled() => false,
                () = tokio::time::sleep(delay) => true,
            }
        }

        fn store_failed(&self, platform: PushPlatform, error: &dyn fmt::Display) {
            if let Some(line) = self.logs.store_failed.hit() {
                tracing::warn!(
                    platform = ?platform,
                    total = line.total,
                    suppressed = line.suppressed,
                    error = %error,
                    "could not record a push outcome in the registration store"
                );
            }
        }

        /// Applies `outcome` for `token` to the store. `false` when the
        /// service stopped meanwhile.
        async fn apply(
            &mut self,
            platform: PushPlatform,
            key: TokenKey,
            token: &[u8],
            outcome: PushSendOutcome,
        ) -> bool {
            match outcome {
                PushSendOutcome::Delivered => {
                    match self.store.clear_invalid_tokens(platform, token).await {
                        Ok(_) => {
                            self.pending_resets.remove(&key);
                        }
                        Err(e) => {
                            self.store_failed(platform, &e);
                            if self.pending_resets.len() < PUSH_QUEUE_CAPACITY
                                || self.pending_resets.contains(&key)
                            {
                                self.pending_resets.insert(key);
                            } else {
                                return self.retry_reset(platform, token).await;
                            }
                        }
                    }
                }
                // Spec 10 §10.7.1 counts an unreachable `WebPush` push
                // service as it counts an invalid token.
                PushSendOutcome::InvalidToken | PushSendOutcome::Unreachable => {
                    let count_from = if self.pending_resets.contains(&key) {
                        CountFrom::Zero
                    } else {
                        CountFrom::Stored
                    };
                    match self
                        .store
                        .record_invalid_token(platform, token, count_from)
                        .await
                    {
                        Ok(counted) => {
                            self.pending_resets.remove(&key);
                            log_invalid(platform, counted);
                        }
                        // The pending reset, if any, stays for the next count.
                        Err(e) => self.store_failed(platform, &e),
                    }
                }
                PushSendOutcome::Transient => {}
                PushSendOutcome::ConfigError => {
                    if let Some(line) = self.logs.config_error.hit() {
                        if platform == PushPlatform::WebPush {
                            // The registrant chooses a `WebPush` endpoint, so
                            // its 400, 401 or 413 says nothing about the
                            // relay's credentials.
                            tracing::warn!(
                                platform = ?platform,
                                total = line.total,
                                suppressed = line.suppressed,
                                "an endpoint refused the request; registration kept"
                            );
                        } else {
                            tracing::warn!(
                                platform = ?platform,
                                total = line.total,
                                suppressed = line.suppressed,
                                "push service refused the relay's credentials; registration kept"
                            );
                        }
                    }
                }
            }
            true
        }

        /// Writes a reset the drain has no room to carry, retrying with
        /// back-off until it lands. `false` when the service stopped first.
        async fn retry_reset(&self, platform: PushPlatform, token: &[u8]) -> bool {
            let mut backoff = ReconnectBackoff::new(TRANSIENT_BACKOFF_MIN, TRANSIENT_BACKOFF_MAX);
            loop {
                if !self.pause(backoff.next_delay()).await {
                    return false;
                }
                match self.store.clear_invalid_tokens(platform, token).await {
                    Ok(_) => return true,
                    Err(e) => self.store_failed(platform, &e),
                }
            }
        }
    }

    fn log_invalid(platform: PushPlatform, counted: InvalidTokenOutcome) {
        match counted {
            InvalidTokenOutcome::Removed { registrations } => tracing::info!(
                platform = ?platform,
                registrations,
                "removed push registrations after consecutive delivery failures"
            ),
            InvalidTokenOutcome::Counted { failures } => {
                tracing::debug!(platform = ?platform, failures, "push delivery failure counted");
            }
            InvalidTokenOutcome::NotRegistered => tracing::debug!(
                platform = ?platform,
                "push delivery failed after the token's registrations were removed"
            ),
        }
    }

    #[cfg(test)]
    mod tests {
        use std::time::Instant;

        use scp_crypto::p256::{P256SecretKey, sign_prehash_rfc6979};
        use scp_did::DID;
        use scp_identity::push_verify::TestPushVerifier;
        use scp_protocol::discovery::push::{PushRegistration, push_registration_signing_bytes};
        use tempfile::TempDir;

        use super::super::super::push::ApnsSender;
        use super::super::super::push_endpoint::parse_endpoint;
        use super::super::super::push_gate::{PushPublishGate, gate_publish, test_relay_url};
        use super::super::super::push_store::MAX_REGISTRATIONS_PER_REGISTRANT;
        use super::super::super::push_test_server::hung_host;
        use super::super::super::push_test_server::{Reply, TestServer, TlsTestServer};
        use super::super::super::push_webpush::tests::{
            held, requests_reach, sender_for as webpush_sender_for,
            sender_with_deadline as webpush_sender_with_deadline, subscribe,
        };
        use super::*;

        type TestResult = Result<(), Box<dyn std::error::Error>>;

        const RID: RoutingId = [0x11; 32];
        const REGISTRANT_A: &str = "did:dht:push-a";
        const REGISTRANT_B: &str = "did:dht:push-b";
        /// Every registrant the test verifier holds; registrant `i` signs
        /// with `key(i + 1)`.
        const REGISTRANTS: [&str; 4] = [
            REGISTRANT_A,
            REGISTRANT_B,
            "did:dht:push-c",
            "did:dht:push-d",
        ];

        fn key(seed: u8) -> Result<P256SecretKey, Box<dyn std::error::Error>> {
            Ok(P256SecretKey::from_scalar_bytes(&[seed; 32])?)
        }

        /// The signature-checking test verifier of PUSH-005, holding
        /// `key(i + 1)` for `REGISTRANTS[i]`.
        fn verifier() -> Result<Arc<TestPushVerifier>, Box<dyn std::error::Error>> {
            let mut keys = Vec::with_capacity(REGISTRANTS.len());
            for (seed, registrant) in (1..).zip(REGISTRANTS) {
                keys.push((DID::from(registrant), key(seed)?.public_key()));
            }
            Ok(Arc::new(TestPushVerifier::new(keys)))
        }

        /// A configuration over a fresh SQLite store (the shipped arm) with
        /// `senders`.
        fn config(
            senders: Vec<PushSender>,
        ) -> Result<(PushServiceConfig, TempDir), Box<dyn std::error::Error>> {
            let dir = tempfile::tempdir()?;
            let store = PushRegistrationStore::open_sqlite(&dir.path().join("push.db"))?;
            let config = PushServiceConfig {
                store,
                verifier: verifier()?,
                senders: Arc::from(senders),
            };
            Ok((config, dir))
        }

        /// A shipped APNs sender aimed at a port nothing listens on; it is
        /// never asked to send.
        fn closed_apns() -> Result<PushSender, Box<dyn std::error::Error>> {
            let closed = TestServer::closed_origin();
            Ok(PushSender::Apns(ApnsSender::build(
                super::super::super::push_apns::tests::config(),
                closed.origin().to_owned(),
                Arc::new(scp_clock::SystemClock),
            )?))
        }

        /// Registers `token` on `platform` for `routing_ids` the way a client
        /// does: a signed `PushRegistration` published to the relay's
        /// reserved push routing ID, which the gate verifies with the test
        /// verifier before it writes the store.
        async fn register(
            push: &PushRole,
            registrant: &str,
            platform: PushPlatform,
            token: &[u8],
            routing_ids: &[RoutingId],
        ) -> TestResult {
            let seed = (1..)
                .zip(REGISTRANTS)
                .find_map(|(seed, known)| (known == registrant).then_some(seed))
                .ok_or("the test verifier does not hold this registrant")?;
            let signer = key(seed)?;
            let now = scp_clock::Clock::now_secs(&scp_clock::SystemClock);
            let mut msg = PushRegistration {
                registrant: DID::from(registrant),
                platform,
                token: token.to_vec(),
                routing_ids: routing_ids.to_vec(),
                timestamp: now,
                signature: [0; 64],
            };
            let relay_url = test_relay_url();
            let reserved_urls = relay_url.current();
            let [current] = reserved_urls.as_slice() else {
                return Err("the test relay reserves one URL".into());
            };
            let digest: [u8; 32] =
                Sha256::digest(push_registration_signing_bytes(&msg, current.push_relay())?).into();
            msg.signature = sign_prehash_rfc6979(&signer, &digest)?;
            let blob = rmp_serde::to_vec_named(&msg)?;
            let reserved = current.push_routing_id();
            let decision = gate_publish(&relay_url, push, &reserved, &blob, now).await;
            if decision != PushPublishGate::Accepted {
                return Err(format!("registration not accepted: {decision:?}").into());
            }
            Ok(())
        }

        /// Waits up to 5 s until `log` has counted `n` events.
        async fn wait_for_log(log: &RateLimitedLog, n: u64) -> TestResult {
            for _ in 0..1000 {
                if log.total() >= n {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Err(format!("expected {n} logged events, saw {}", log.total()).into())
        }

        /// Entries on a queue whose sender is `tx`.
        fn queued<T>(tx: &mpsc::Sender<T>) -> usize {
            tx.max_capacity() - tx.capacity()
        }

        /// A job holds the platform, the token and the opaque ticket, and
        /// nothing else: the destructuring names every field with no `..`,
        /// so a field added to the job stops this test compiling.
        #[test]
        fn push_job_holds_only_platform_token_and_ticket() {
            let job = PushJob {
                platform: PushPlatform::Fcm,
                token: Zeroizing::new(b"secret-token".to_vec()),
                ticket: Arc::new(()),
            };
            let shown = format!("{job:?}");
            assert!(!shown.contains("secret-token"), "{shown}");
            assert!(shown.contains("token_len: 12"), "{shown}");
            let PushJob {
                platform,
                token,
                ticket,
            } = job;
            assert_eq!(platform, PushPlatform::Fcm);
            assert_eq!(token.as_slice(), b"secret-token");
            assert_eq!(*ticket, ());
        }

        /// Outside a tokio runtime the service refuses to start, with a typed
        /// error, instead of returning a service whose drains never run.
        #[test]
        fn start_outside_a_runtime_fails() -> TestResult {
            let (config, _dir) = config(Vec::new())?;
            assert_eq!(
                PushService::start(config).err(),
                Some(PushServiceError::NoRuntime)
            );
            Ok(())
        }

        /// Two senders for one platform are refused at start.
        #[tokio::test]
        async fn start_rejects_two_senders_for_one_platform() -> TestResult {
            let (config, _dir) = config(vec![closed_apns()?, closed_apns()?])?;
            assert_eq!(
                PushService::start(config).err(),
                Some(PushServiceError::DuplicateSender {
                    platform: PushPlatform::Apns
                })
            );
            Ok(())
        }

        /// Dropping the last clone of the service stops its lookup task: the
        /// intake's receiver goes away.
        #[tokio::test]
        async fn dropping_the_service_stops_its_tasks() -> TestResult {
            let (config, _dir) = config(vec![closed_apns()?])?;
            let service = PushService::start(config)?;
            let probe = service.inner.intake.clone();
            let clone = service.clone();
            drop(service);
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert!(!probe.is_closed(), "a live clone's tasks stopped");
            drop(clone);
            for _ in 0..1000 {
                if probe.is_closed() {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Err("the lookup task outlived the service".into())
        }

        /// The production queues hold 10,000 entries and one routing ID's
        /// share is a tenth of that.
        #[tokio::test]
        async fn production_limits() -> TestResult {
            assert_eq!(PUSH_QUEUE_CAPACITY, 10_000);
            const { assert!(MAX_WAKES_PER_PUBLISH * 10 <= PUSH_QUEUE_CAPACITY) };
            let (config, _dir) = config(Vec::new())?;
            let service = PushService::start(config)?;
            assert_eq!(service.inner.intake.max_capacity(), PUSH_QUEUE_CAPACITY);
            Ok(())
        }

        /// A routing ID waiting on the intake holds one slot however often
        /// it is published to. The calls run back to back on one thread, so
        /// the lookup task cannot run between them.
        #[tokio::test]
        async fn notify_holds_a_routing_id_once_on_the_intake() -> TestResult {
            let (config, _dir) = config(Vec::new())?;
            let service = PushService::start_with_limits(config, 4, 4)?;
            let push = PushRole::Enabled(service.clone());
            notify(&push, &RID);
            notify(&push, &RID);
            notify(&push, &RID);
            assert_eq!(queued(&service.inner.intake), 1);
            notify(&push, &[0x22; 32]);
            assert_eq!(queued(&service.inner.intake), 2);
            Ok(())
        }

        /// A full intake drops the wake and logs it; `notify` returns, so
        /// the caller's publish succeeds.
        #[tokio::test]
        async fn full_intake_drops_and_logs() -> TestResult {
            let (config, _dir) = config(Vec::new())?;
            let service = PushService::start_with_limits(config, 1, 4)?;
            let push = PushRole::Enabled(service.clone());
            notify(&push, &RID);
            notify(&push, &[0x22; 32]);
            assert_eq!(service.inner.logs.intake_full.total(), 1);
            Ok(())
        }

        /// A failed registration lookup queues nothing and is logged.
        #[tokio::test]
        async fn failed_lookup_is_logged() -> TestResult {
            let (config, dir) = config(vec![closed_apns()?])?;
            let service = PushService::start(config)?;
            let push = PushRole::Enabled(service.clone());
            register(&push, REGISTRANT_A, PushPlatform::Apns, b"t1", &[RID]).await?;
            // Drop the routing index from beside the store: its next lookup
            // fails.
            rusqlite::Connection::open(dir.path().join("push.db"))?
                .execute_batch("DROP TABLE push_routing_index;")?;
            notify(&push, &RID);
            wait_for_log(&service.inner.logs.lookup_failed, 1).await
        }

        /// One line per interval: the first event writes, the next ones in
        /// the interval are counted, and the first event after it writes
        /// the total and the number it stands for.
        #[test]
        fn rate_limited_log_writes_one_line_per_interval() {
            let log = RateLimitedLog::default();
            let t0 = Instant::now();
            assert_eq!(
                log.hit_at(t0),
                Some(LogLine {
                    total: 1,
                    suppressed: 0
                })
            );
            assert_eq!(log.hit_at(t0 + Duration::from_secs(1)), None);
            assert_eq!(log.hit_at(t0 + Duration::from_secs(59)), None);
            assert_eq!(
                log.hit_at(t0 + LOG_INTERVAL),
                Some(LogLine {
                    total: 4,
                    suppressed: 2
                })
            );
            assert_eq!(log.hit_at(t0 + LOG_INTERVAL), None);
            assert_eq!(log.total(), 5);
        }

        /// With push disabled, `notify` does nothing.
        #[test]
        fn disabled_role_does_nothing() {
            notify(&PushRole::Disabled, &RID);
        }

        /// Polls `server` up to `within` until it has recorded `n` requests.
        async fn wait_for_requests(
            server: &TlsTestServer,
            n: usize,
            within: Duration,
        ) -> TestResult {
            let deadline = Instant::now() + within;
            while Instant::now() < deadline {
                if server.requests().await.len() >= n {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Err(format!(
                "expected {n} requests within {within:?}, saw {}",
                server.requests().await.len()
            )
            .into())
        }

        /// PUSH-022 lane rule, end to end through the real `WebPush` sender:
        /// an endpoint origin that never answers delays no wake to another
        /// origin. The hung send is in flight before the second wake is
        /// published, and the second is delivered well inside the sender's
        /// 10 s request timeout, which a one-at-a-time drain would wait out.
        #[tokio::test]
        async fn a_hung_webpush_origin_does_not_delay_another() -> TestResult {
            const HUNG: RoutingId = [0x48; 32];
            const GOOD: RoutingId = [0x47; 32];
            let server = TlsTestServer::start_routed(vec![
                ("/hung", vec![Reply::hang()]),
                ("/ok", vec![Reply::empty(201)]),
            ])
            .await;
            let sender = webpush_sender_for(&server, true, Arc::new(scp_clock::SystemClock))?;
            let (config, _dir) = config(vec![PushSender::WebPush(sender)])?;
            let push = PushRole::Enabled(PushService::start(config)?);
            let (_, hung) = subscribe(server.endpoint("hung.example.net", "/hung"))?;
            let (_, good) = subscribe(server.endpoint("push.example.net", "/ok"))?;
            register(
                &push,
                REGISTRANT_A,
                PushPlatform::WebPush,
                &hung.encode(),
                &[HUNG],
            )
            .await?;
            register(
                &push,
                REGISTRANT_A,
                PushPlatform::WebPush,
                &good.encode(),
                &[GOOD],
            )
            .await?;

            notify(&push, &HUNG);
            wait_for_requests(&server, 1, Duration::from_secs(5)).await?;
            notify(&push, &GOOD);
            wait_for_requests(&server, 2, Duration::from_secs(3)).await?;
            let paths: Vec<String> = server
                .requests()
                .await
                .into_iter()
                .map(|r| r.path)
                .collect();
            assert_eq!(paths, ["/hung", "/ok"]);
            Ok(())
        }

        /// A push service whose one sender is a real `WebPush` sender reaching
        /// `server`, with `deadline` as its request deadline.
        fn webpush_service(
            server: &TlsTestServer,
            deadline: Duration,
        ) -> Result<(PushRole, PushService, TempDir), Box<dyn std::error::Error>> {
            let sender = webpush_sender_with_deadline(
                server,
                true,
                Arc::new(scp_clock::SystemClock),
                deadline,
            )?;
            let (config, dir) = config(vec![PushSender::WebPush(sender)])?;
            let service = PushService::start(config)?;
            Ok((PushRole::Enabled(service.clone()), service, dir))
        }

        /// The `n`th of the routing IDs the many-token tests register on.
        fn routing_id(n: u8) -> RoutingId {
            let mut id = [0x60; 32];
            id[0] = n;
            id
        }

        /// Registers each `(token, routing ID)` on `WebPush`, filling each
        /// registrant up to its cap before the next.
        async fn register_webpush(push: &PushRole, tokens: &[(Vec<u8>, RoutingId)]) -> TestResult {
            for (i, (token, id)) in tokens.iter().enumerate() {
                let registrant = REGISTRANTS
                    .get(i / MAX_REGISTRATIONS_PER_REGISTRANT)
                    .ok_or("more tokens than the test registrants may hold")?;
                register(push, registrant, PushPlatform::WebPush, token, &[*id]).await?;
            }
            Ok(())
        }

        /// Waits up to 10 s until `token`'s stored failure count is `want`.
        async fn webpush_count_reaches(
            store: &PushRegistrationStore,
            token: &[u8],
            want: Option<u32>,
        ) -> TestResult {
            let mut now = None;
            for _ in 0..2000 {
                now = store
                    .invalid_token_failures(PushPlatform::WebPush, token)
                    .await?;
                if now == want {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Err(format!("the count stayed {now:?}, not {want:?}").into())
        }

        /// The paths `server` has seen, in arrival order.
        async fn paths(server: &TlsTestServer) -> Vec<String> {
            server
                .requests()
                .await
                .into_iter()
                .map(|r| r.path)
                .collect()
        }

        /// One `WebPush` token two registrants hold on `RID`, aimed at
        /// `server`'s `/x`.
        async fn shared_webpush_token(
            push: &PushRole,
            server: &TlsTestServer,
        ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            let (_, subscription) = subscribe(server.endpoint("push.example.net", "/x"))?;
            let token = subscription.encode();
            register(push, REGISTRANT_A, PushPlatform::WebPush, &token, &[RID]).await?;
            register(push, REGISTRANT_B, PushPlatform::WebPush, &token, &[RID]).await?;
            Ok(token)
        }

        /// When the service's `WebPush` sender's back-off of `server`'s
        /// `push.example.net` origin ends.
        fn webpush_retry_at(
            service: &PushService,
            server: &TlsTestServer,
        ) -> Result<Option<tokio::time::Instant>, Box<dyn std::error::Error>> {
            let aud = parse_endpoint(&server.endpoint("push.example.net", "/"))?
                .aud()
                .to_owned();
            let Some(PushSender::WebPush(sender)) = service.config().senders.first() else {
                return Err("the service has no WebPush sender".into());
            };
            Ok(sender.retry_at(&aud))
        }

        /// Lets the wake that `notify` queued go out on the paused clock. It
        /// sleeps until the origin's back-off ends, the instant the service's
        /// own back-off timer fires, then holds the clock still until `sent`
        /// finishes, so no deadline passes while the send crosses loopback.
        async fn wake_until<T>(
            service: &PushService,
            server: &TlsTestServer,
            sent: impl Future<Output = T>,
        ) -> Result<T, Box<dyn std::error::Error>> {
            let backoff_end = webpush_retry_at(service, server)?;
            if let Some(until) = backoff_end {
                tokio::time::sleep_until(until).await;
            }
            held(sent).await
        }

        /// Finishes once `token`'s stored failure count is `want`.
        async fn count_is(
            store: &PushRegistrationStore,
            token: &[u8],
            want: Option<u32>,
        ) -> TestResult {
            while store
                .invalid_token_failures(PushPlatform::WebPush, token)
                .await?
                != want
            {
                tokio::task::yield_now().await;
            }
            Ok(())
        }

        /// R2, spec 10 §10.7.1: three sends in a row that the push service
        /// leaves unanswered past the deadline remove every registration
        /// holding the token, through the real `WebPush` sender. Each wake
        /// after the first waits out the origin's back-off and is then sent.
        /// The clock is paused and held until each request has arrived, so
        /// each deadline passes with its request at the server.
        #[tokio::test(start_paused = true)]
        async fn three_webpush_timeouts_remove_the_registrations() -> TestResult {
            let server =
                TlsTestServer::start_routed(vec![("/x", (0..3).map(|_| Reply::hang()).collect())])
                    .await;
            let (push, service, _dir) = webpush_service(&server, Duration::from_millis(300))?;
            let token = shared_webpush_token(&push, &server).await?;
            let store = &service.config().store;
            for (sent, count) in [(1, Some(1)), (2, Some(2))] {
                notify(&push, &RID);
                wake_until(&service, &server, requests_reach(&server, sent)).await?;
                webpush_count_reaches(store, &token, count).await?;
            }
            assert_eq!(store.tokens_for_routing_id(&RID).await?.len(), 2);
            notify(&push, &RID);
            wake_until(&service, &server, requests_reach(&server, 3)).await?;
            webpush_count_reaches(store, &token, None).await?;
            assert!(store.tokens_for_routing_id(&RID).await?.is_empty());
            assert_eq!(server.requests().await.len(), 3);
            Ok(())
        }

        /// R2: a 201 between two timeouts resets the count, so the second
        /// timeout leaves it at one, not two. The clock is paused and held
        /// until each request has arrived, and until the 201 is applied.
        #[tokio::test(start_paused = true)]
        async fn a_webpush_delivery_resets_the_timeout_count() -> TestResult {
            let server = TlsTestServer::start_routed(vec![(
                "/x",
                vec![Reply::hang(), Reply::empty(201), Reply::hang()],
            )])
            .await;
            let (push, service, _dir) = webpush_service(&server, Duration::from_millis(300))?;
            let token = shared_webpush_token(&push, &server).await?;
            let store = &service.config().store;
            notify(&push, &RID);
            wake_until(&service, &server, requests_reach(&server, 1)).await?;
            webpush_count_reaches(store, &token, Some(1)).await?;
            notify(&push, &RID);
            wake_until(&service, &server, count_is(store, &token, Some(0))).await??;
            notify(&push, &RID);
            wake_until(&service, &server, requests_reach(&server, 3)).await?;
            webpush_count_reaches(store, &token, Some(1)).await?;
            assert_eq!(store.tokens_for_routing_id(&RID).await?.len(), 2);
            Ok(())
        }

        /// R2: a 429 and a 5xx neither add to the count nor reset it: after
        /// two timeouts they leave it at two, and the registrations stay.
        /// The clock is paused and held until each timed-out request has
        /// arrived, and until each 429 or 5xx has stepped the back-off.
        #[tokio::test(start_paused = true)]
        async fn webpush_throttling_and_server_errors_never_remove() -> TestResult {
            let server = TlsTestServer::start_routed(vec![(
                "/x",
                vec![
                    Reply::hang(),
                    Reply::hang(),
                    Reply::empty(429),
                    Reply::empty(503),
                ],
            )])
            .await;
            let (push, service, _dir) = webpush_service(&server, Duration::from_millis(300))?;
            let token = shared_webpush_token(&push, &server).await?;
            let store = &service.config().store;
            for (sent, count) in [(1, Some(1)), (2, Some(2))] {
                notify(&push, &RID);
                wake_until(&service, &server, requests_reach(&server, sent)).await?;
                webpush_count_reaches(store, &token, count).await?;
            }
            for _ in [429, 503] {
                notify(&push, &RID);
                // `wake_until` holds the clock from the back-off's end, when
                // the origin has none, until the `Transient` answer takes the
                // next back-off step.
                wake_until(&service, &server, async {
                    while webpush_retry_at(&service, &server)?.is_none() {
                        tokio::task::yield_now().await;
                    }
                    TestResult::Ok(())
                })
                .await??;
            }
            assert_eq!(server.requests().await.len(), 4);
            assert_eq!(
                store
                    .invalid_token_failures(PushPlatform::WebPush, &token)
                    .await?,
                Some(2)
            );
            assert_eq!(store.tokens_for_routing_id(&RID).await?.len(), 2);
            Ok(())
        }

        /// L3: 36 tokens on one hung origin, each on its own routing ID, hold
        /// at most `WEBPUSH_SENDS_PER_ORIGIN` sends, and a wake to another
        /// origin is delivered well inside the 5 s request deadline.
        #[tokio::test]
        async fn hung_tokens_on_one_origin_leave_room_for_another() -> TestResult {
            const GOOD: RoutingId = [0x47; 32];
            let server = TlsTestServer::start_routed(vec![
                ("/hung", (0..40).map(|_| Reply::hang()).collect()),
                ("/ok", vec![Reply::empty(201)]),
            ])
            .await;
            let sender = webpush_sender_for(&server, true, Arc::new(scp_clock::SystemClock))?;
            let (config, _dir) = config(vec![PushSender::WebPush(sender)])?;
            let push = PushRole::Enabled(PushService::start(config)?);
            let mut tokens = Vec::new();
            for n in 0..36 {
                let (_, hung) = subscribe(server.endpoint("hung.example.net", "/hung"))?;
                tokens.push((hung.encode(), routing_id(n)));
            }
            let (_, good) = subscribe(server.endpoint("push.example.net", "/ok"))?;
            tokens.push((good.encode(), GOOD));
            register_webpush(&push, &tokens).await?;

            for n in 0..36 {
                notify(&push, &routing_id(n));
            }
            wait_for_requests(&server, WEBPUSH_SENDS_PER_ORIGIN, Duration::from_secs(5)).await?;
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert_eq!(paths(&server).await, ["/hung"; WEBPUSH_SENDS_PER_ORIGIN]);

            notify(&push, &GOOD);
            wait_for_requests(
                &server,
                WEBPUSH_SENDS_PER_ORIGIN + 1,
                Duration::from_secs(2),
            )
            .await?;
            assert_eq!(paths(&server).await.last().map(String::as_str), Some("/ok"));
            Ok(())
        }

        /// L3: 36 tokens on one routing ID, each on its own hung origin and
        /// held by three registrants, hold at most `WEBPUSH_SENDS_PER_TICKET`
        /// sends, and another routing ID's wake is delivered well inside the
        /// 5 s request deadline.
        #[tokio::test]
        async fn hung_tokens_on_one_routing_id_leave_room_for_another() -> TestResult {
            const HUNG: RoutingId = [0x48; 32];
            const GOOD: RoutingId = [0x47; 32];
            let server = TlsTestServer::start_routed(vec![
                ("/hung", (0..40).map(|_| Reply::hang()).collect()),
                ("/ok", vec![Reply::empty(201)]),
            ])
            .await;
            let sender = webpush_sender_for(&server, true, Arc::new(scp_clock::SystemClock))?;
            let (config, _dir) = config(vec![PushSender::WebPush(sender)])?;
            let push = PushRole::Enabled(PushService::start(config)?);
            let mut tokens = Vec::new();
            for n in 0..36 {
                let (_, hung) = subscribe(server.endpoint(&hung_host(n), "/hung"))?;
                tokens.push((hung.encode(), HUNG));
            }
            let (_, good) = subscribe(server.endpoint("push.example.net", "/ok"))?;
            tokens.push((good.encode(), GOOD));
            register_webpush(&push, &tokens).await?;

            notify(&push, &HUNG);
            wait_for_requests(&server, WEBPUSH_SENDS_PER_TICKET, Duration::from_secs(5)).await?;
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert_eq!(paths(&server).await, ["/hung"; WEBPUSH_SENDS_PER_TICKET]);

            notify(&push, &GOOD);
            wait_for_requests(
                &server,
                WEBPUSH_SENDS_PER_TICKET + 1,
                Duration::from_secs(2),
            )
            .await?;
            assert_eq!(paths(&server).await.last().map(String::as_str), Some("/ok"));
            Ok(())
        }

        /// B2: wakes to origins that are backing off wait in the drain and
        /// hold no send. Eight origins answer 429 and back off; a wake to
        /// each of their 32 tokens then fills no send slot, so a wake to a
        /// ninth origin is sent before any of them, and all 32 are sent once
        /// the back-offs end.
        #[tokio::test]
        async fn wakes_during_a_backoff_hold_no_send() -> TestResult {
            const ORIGINS: usize = 8;
            const PER_ORIGIN: usize = WEBPUSH_CONCURRENT_SENDS / ORIGINS;
            const GOOD: RoutingId = [0x47; 32];
            let busy = (0..ORIGINS)
                .map(|_| Reply::empty(429))
                .chain((0..WEBPUSH_CONCURRENT_SENDS).map(|_| Reply::empty(201)))
                .collect();
            let server = TlsTestServer::start_routed(vec![
                ("/busy", busy),
                ("/ok", vec![Reply::empty(201)]),
            ])
            .await;
            let sender = webpush_sender_for(&server, true, Arc::new(scp_clock::SystemClock))?;
            let (config, _dir) = config(vec![PushSender::WebPush(sender)])?;
            let push = PushRole::Enabled(PushService::start(config)?);
            let mut tokens = Vec::new();
            for n in 0..u8::try_from(WEBPUSH_CONCURRENT_SENDS)? {
                let origin = hung_host(usize::from(n) / PER_ORIGIN);
                let (_, busy) = subscribe(server.endpoint(&origin, "/busy"))?;
                tokens.push((busy.encode(), routing_id(n)));
            }
            let (_, good) = subscribe(server.endpoint("push.example.net", "/ok"))?;
            tokens.push((good.encode(), GOOD));
            register_webpush(&push, &tokens).await?;

            // One 429 per origin starts each origin's back-off.
            for origin in 0..u8::try_from(ORIGINS)? {
                notify(&push, &routing_id(origin * u8::try_from(PER_ORIGIN)?));
            }
            wait_for_requests(&server, ORIGINS, Duration::from_secs(5)).await?;
            tokio::time::sleep(Duration::from_millis(100)).await;

            for n in 0..u8::try_from(WEBPUSH_CONCURRENT_SENDS)? {
                notify(&push, &routing_id(n));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            notify(&push, &GOOD);
            let all = ORIGINS + 1 + WEBPUSH_CONCURRENT_SENDS;
            wait_for_requests(&server, all, Duration::from_secs(10)).await?;
            let seen = paths(&server).await;
            let good_at = seen.iter().position(|path| path == "/ok");
            assert_eq!(
                good_at,
                Some(ORIGINS),
                "a backing-off wake held a send: /ok was request #{good_at:?}"
            );
            Ok(())
        }

        /// A `WebPush` job for token `n` on `ticket` and `origin`.
        fn held_job(n: usize, ticket: &Arc<()>, origin: &str) -> Held {
            let token = format!("token-{n:04}").into_bytes();
            Held {
                key: token_key(PushPlatform::WebPush, &token),
                job: PushJob {
                    platform: PushPlatform::WebPush,
                    token: Zeroizing::new(token),
                    ticket: Arc::clone(ticket),
                },
                origin: Some(origin.to_owned()),
                granted: false,
            }
        }

        fn token_of(held: &Held) -> String {
            String::from_utf8_lossy(&held.job.token).into_owned()
        }

        /// A thousand jobs held on one routing ID start in arrival order, and
        /// each finished send examines a bounded number of held jobs, not
        /// every one: the whole run examines at most three jobs per send. A
        /// drain that rescans every held job on each finished send examines
        /// about half a million.
        #[test]
        fn held_jobs_on_one_ticket_start_in_order_at_bounded_cost() {
            const HELD: usize = 1_000;
            let total = HELD + WEBPUSH_SENDS_PER_TICKET;
            let ticket = Arc::new(());
            let no_backoff = |_: &str| None;
            let mut waiting = Waiting::default();
            let mut in_flight = InFlight::default();
            let mut ready = Vec::new();
            for n in 0..total {
                let job = held_job(n, &ticket, "https://push.example.net");
                waiting.arrive(job, &mut in_flight, &no_backoff, &mut ready);
            }
            assert_eq!(ready.len(), WEBPUSH_SENDS_PER_TICKET);
            assert_eq!(waiting.held(), HELD);
            let mut running: VecDeque<Held> = std::mem::take(&mut ready).into();
            let mut order = Vec::new();
            while let Some(done) = running.pop_front() {
                order.push(token_of(&done));
                in_flight.remove(&done);
                waiting.freed(done.gates(), &mut in_flight, &no_backoff, &mut ready);
                running.extend(std::mem::take(&mut ready));
            }
            let expected: Vec<String> = (0..total).map(|n| format!("token-{n:04}")).collect();
            assert_eq!(order, expected);
            assert_eq!(waiting.held(), 0);
            assert!(
                waiting.examined <= 3 * total,
                "{} examinations for {total} jobs",
                waiting.examined
            );
        }

        /// One routing ID holds two sends to one origin, its cap, and 200
        /// jobs to a second origin that other routing IDs saturate. When one
        /// of its sends ends, the drain examines a bounded number of jobs, not
        /// the 200, and when the second origin frees, its jobs start in
        /// arrival order. A drain that moves each job from the routing ID's
        /// queue to the origin's on that event examines every one of them.
        #[test]
        fn a_routing_id_blocked_on_two_keys_moves_at_bounded_cost() -> TestResult {
            const HELD: usize = 200;
            let busy = "https://busy.example.net";
            let other = "https://other.example.net";
            let no_backoff = |_: &str| None;
            let mut waiting = Waiting::default();
            let mut in_flight = InFlight::default();
            let mut ready = Vec::new();
            let saturating: Vec<Arc<()>> = (0..WEBPUSH_SENDS_PER_ORIGIN)
                .map(|_| Arc::new(()))
                .collect();
            for (n, ticket) in saturating.iter().enumerate() {
                let job = held_job(10_000 + n, ticket, busy);
                waiting.arrive(job, &mut in_flight, &no_backoff, &mut ready);
            }
            let ticket = Arc::new(());
            for n in 0..WEBPUSH_SENDS_PER_TICKET {
                let job = held_job(20_000 + n, &ticket, other);
                waiting.arrive(job, &mut in_flight, &no_backoff, &mut ready);
            }
            let mut running: Vec<Held> = std::mem::take(&mut ready);
            assert_eq!(
                running.len(),
                WEBPUSH_SENDS_PER_ORIGIN + WEBPUSH_SENDS_PER_TICKET
            );
            for n in 0..HELD {
                waiting.arrive(
                    held_job(n, &ticket, busy),
                    &mut in_flight,
                    &no_backoff,
                    &mut ready,
                );
            }
            assert!(ready.is_empty());
            assert_eq!(waiting.held(), HELD);

            // One of the routing ID's sends to the other origin ends.
            let Some(at) = running
                .iter()
                .position(|held| Arc::ptr_eq(&held.job.ticket, &ticket))
            else {
                return Err("the routing ID has no send in flight".into());
            };
            let done = running.swap_remove(at);
            in_flight.remove(&done);
            let before = waiting.examined;
            waiting.freed(done.gates(), &mut in_flight, &no_backoff, &mut ready);
            assert!(ready.is_empty(), "a job started past the saturated origin");
            assert!(
                waiting.examined - before <= 3,
                "{} examinations for one finished send",
                waiting.examined - before
            );

            // The saturated origin's sends end one by one; the routing ID's
            // jobs start in arrival order.
            let mut order = Vec::new();
            let mut events = 0_usize;
            let before = waiting.examined;
            while let Some(done) = running.pop() {
                events += 1;
                in_flight.remove(&done);
                waiting.freed(done.gates(), &mut in_flight, &no_backoff, &mut ready);
                for started in std::mem::take(&mut ready) {
                    order.push(token_of(&started));
                    running.push(started);
                }
            }
            let expected: Vec<String> = (0..HELD).map(|n| format!("token-{n:04}")).collect();
            assert_eq!(order, expected);
            assert_eq!(waiting.held(), 0);
            assert!(
                waiting.examined - before <= 4 * events,
                "{} examinations for {events} finished sends",
                waiting.examined - before
            );
            Ok(())
        }

        /// Thirty-two jobs wait on a full endpoint lookup pool. One freed
        /// permit restarts the oldest of them, so one send signs and seals,
        /// not thirty-two; the next freed permit restarts the next.
        #[test]
        fn one_freed_lookup_permit_restarts_one_held_send() {
            const HELD: usize = 32;
            let no_backoff = |_: &str| None;
            let mut waiting = Waiting::default();
            let mut in_flight = InFlight::default();
            let mut ready = Vec::new();
            let tickets: Vec<Arc<()>> = (0..HELD).map(|_| Arc::new(())).collect();
            for (n, ticket) in tickets.iter().enumerate() {
                let origin = format!("https://push-{n}.example.net");
                waiting.hold(
                    held_job(n, ticket, &origin),
                    SendDeferral::LookupPoolFull,
                    &mut in_flight,
                    &no_backoff,
                    &mut ready,
                );
            }
            assert!(ready.is_empty());
            assert_eq!(waiting.held(), HELD);
            waiting.lookup_freed(1, &mut in_flight, &no_backoff, &mut ready);
            let started: Vec<String> = ready.iter().map(token_of).collect();
            assert_eq!(started, ["token-0000"]);
            assert_eq!(waiting.held(), HELD - 1);
            ready.clear();
            waiting.lookup_freed(1, &mut in_flight, &no_backoff, &mut ready);
            let started: Vec<String> = ready.iter().map(token_of).collect();
            assert_eq!(started, ["token-0001"]);
            assert!(waiting.awaits_lookup());
        }

        /// A freed lookup permit is not spent on a held job its origin's cap
        /// holds: that job moves to its origin's wait, and the permit starts
        /// the next held job, to another origin.
        #[test]
        fn a_freed_lookup_permit_passes_over_a_capped_job() {
            let capped = "https://capped.example.net";
            let other = "https://other.example.net";
            let no_backoff = |_: &str| None;
            let mut waiting = Waiting::default();
            let mut in_flight = InFlight::default();
            let mut ready = Vec::new();
            let tickets: Vec<Arc<()>> = (0..WEBPUSH_SENDS_PER_ORIGIN + 3)
                .map(|_| Arc::new(()))
                .collect();
            for (n, ticket) in tickets.iter().take(WEBPUSH_SENDS_PER_ORIGIN).enumerate() {
                waiting.arrive(
                    held_job(n, ticket, capped),
                    &mut in_flight,
                    &no_backoff,
                    &mut ready,
                );
            }
            assert_eq!(ready.len(), WEBPUSH_SENDS_PER_ORIGIN);
            ready.clear();
            let n = WEBPUSH_SENDS_PER_ORIGIN;
            for (n, origin) in [(n, capped), (n + 1, capped), (n + 2, other)] {
                let ticket = &tickets[n];
                waiting.hold(
                    held_job(n, ticket, origin),
                    SendDeferral::LookupPoolFull,
                    &mut in_flight,
                    &no_backoff,
                    &mut ready,
                );
            }
            waiting.lookup_freed(1, &mut in_flight, &no_backoff, &mut ready);
            let started: Vec<String> = ready.iter().map(token_of).collect();
            assert_eq!(started, [format!("token-{:04}", n + 2)]);
            assert!(ready.iter().all(|held| held.granted));
            assert!(!waiting.awaits_lookup());
            assert_eq!(waiting.held(), 2);
        }

        /// Four sends to one origin are in flight when the origin begins
        /// backing off, and each comes back deferred. They hold no send slot
        /// and no origin slot during the back-off, a job to another origin
        /// starts at once, and all four start, in order, when it ends.
        #[tokio::test]
        async fn deferred_sends_hold_no_slot_during_a_backoff() {
            let origin = "https://push.example.net";
            let until = tokio::time::Instant::now() + Duration::from_secs(1);
            let backing_off = std::cell::Cell::new(false);
            let retry_at = |o: &str| (backing_off.get() && o == origin).then_some(until);
            let mut waiting = Waiting::default();
            let mut in_flight = InFlight::default();
            let mut ready = Vec::new();
            let tickets: Vec<Arc<()>> = (0..WEBPUSH_SENDS_PER_ORIGIN)
                .map(|_| Arc::new(()))
                .collect();
            for (n, ticket) in tickets.iter().enumerate() {
                waiting.arrive(
                    held_job(n, ticket, origin),
                    &mut in_flight,
                    &retry_at,
                    &mut ready,
                );
            }
            assert_eq!(ready.len(), WEBPUSH_SENDS_PER_ORIGIN);
            assert_eq!(
                in_flight.origins.get(origin),
                Some(&WEBPUSH_SENDS_PER_ORIGIN)
            );

            backing_off.set(true);
            let mut started = Vec::new();
            for done in std::mem::take(&mut ready) {
                in_flight.remove(&done);
                let gates: Vec<Gate> = done.gates().collect();
                waiting.hold(
                    done,
                    SendDeferral::BackingOff(until),
                    &mut in_flight,
                    &retry_at,
                    &mut ready,
                );
                waiting.freed(gates, &mut in_flight, &retry_at, &mut ready);
                started.append(&mut ready);
            }
            assert!(
                started.is_empty(),
                "a deferred send restarted during the back-off"
            );
            assert_eq!(in_flight.sends, 0);
            assert_eq!(
                in_flight.origins.get(origin),
                None,
                "an origin slot is held"
            );
            assert_eq!(waiting.next_timer(), Some(until));

            let other = Arc::new(());
            let elsewhere = held_job(9, &other, "https://other.example.net");
            waiting.arrive(elsewhere, &mut in_flight, &retry_at, &mut ready);
            assert_eq!(ready.len(), 1, "another origin waited on the back-off");

            backing_off.set(false);
            let mut after = Vec::new();
            waiting.timers_due(until, &mut in_flight, &retry_at, &mut after);
            let order: Vec<String> = after.iter().map(token_of).collect();
            let expected: Vec<String> = (0..WEBPUSH_SENDS_PER_ORIGIN)
                .map(|n| format!("token-{n:04}"))
                .collect();
            assert_eq!(order, expected);
            assert_eq!(waiting.next_timer(), None);
        }

        /// A full endpoint lookup pool holds a wake to a healthy origin
        /// without consuming it or backing the origin off, and the wake is
        /// sent once a lookup permit frees, with no further publish.
        #[tokio::test]
        async fn a_full_lookup_pool_holds_a_wake_without_a_backoff() -> TestResult {
            let server = TlsTestServer::start_routed(vec![("/ok", vec![Reply::empty(201)])]).await;
            let (push, service, _dir) = webpush_service(&server, Duration::from_secs(5))?;
            let (_, good) = subscribe(server.endpoint("push.example.net", "/ok"))?;
            let token = good.encode();
            register(&push, REGISTRANT_A, PushPlatform::WebPush, &token, &[RID]).await?;
            let Some(PushSender::WebPush(sender)) = service.config().senders.first() else {
                return Err("the service has no WebPush sender".into());
            };
            let aud = crate::relay::push_endpoint::parse_endpoint(
                &server.endpoint("push.example.net", "/"),
            )?
            .aud()
            .to_owned();

            let held = sender.exhaust_lookup_permits()?;
            notify(&push, &RID);
            tokio::time::sleep(Duration::from_millis(300)).await;
            assert!(server.requests().await.is_empty());
            assert_eq!(
                sender.retry_at(&aud),
                None,
                "a full lookup pool backed off a healthy origin"
            );
            assert_eq!(
                service
                    .config()
                    .store
                    .invalid_token_failures(PushPlatform::WebPush, &token)
                    .await?,
                Some(0),
                "a full lookup pool counted against the token"
            );
            drop(held);
            wait_for_requests(&server, 1, Duration::from_secs(5)).await?;
            assert_eq!(paths(&server).await, ["/ok"]);
            Ok(())
        }

        /// Drain tests: the recording sender compiles only under `testing`.
        #[cfg(feature = "testing")]
        mod drain {
            use super::super::super::super::push::{RecordingGate, RecordingSender};
            use super::*;

            async fn wait_for_sends(sender: &RecordingSender, n: usize) -> TestResult {
                for _ in 0..1000 {
                    if sender.sent().await.len() >= n {
                        return Ok(());
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                Err(format!("expected {n} sends, saw {}", sender.sent().await.len()).into())
            }

            /// Waits up to 5 s until `token`'s stored count is not `not`, and
            /// returns it.
            async fn failures_once_not(
                store: &PushRegistrationStore,
                token: &[u8],
                not: Option<u32>,
            ) -> Result<Option<u32>, Box<dyn std::error::Error>> {
                for _ in 0..1000 {
                    if let Ok(now) = store
                        .invalid_token_failures(PushPlatform::Apns, token)
                        .await
                        && now != not
                    {
                        return Ok(now);
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                Err(format!("the count stayed {not:?}").into())
            }

            fn recording(sender: &RecordingSender) -> PushSender {
                PushSender::Recording(sender.clone())
            }

            /// A thousand `WebPush` jobs held on one routing ID behind its
            /// two sends in flight are all sent, in arrival order.
            #[tokio::test]
            async fn a_thousand_held_jobs_on_one_ticket_are_sent_in_order() -> TestResult {
                const HELD: usize = 1_000;
                let total = HELD + WEBPUSH_SENDS_PER_TICKET;
                let (sender, gate) = RecordingSender::gated(
                    PushPlatform::WebPush,
                    vec![PushSendOutcome::Delivered; total],
                );
                let dir = tempfile::tempdir()?;
                let (tx, rx) = mpsc::channel(PUSH_QUEUE_CAPACITY);
                let queued = Arc::new(Mutex::new(HashSet::new()));
                let stop = CancellationToken::new();
                let drain = Drain {
                    senders: Arc::from(vec![recording(&sender)]),
                    index: 0,
                    store: PushRegistrationStore::open_sqlite(&dir.path().join("push.db"))?,
                    queued: Arc::clone(&queued),
                    logs: Arc::new(Logs::default()),
                    stop: stop.clone(),
                    pending_resets: HashSet::new(),
                };
                let task = tokio::spawn(drain.run(rx));
                let ticket = Arc::new(());
                let tokens: Vec<Vec<u8>> = (0..total)
                    .map(|n| format!("token-{n:04}").into_bytes())
                    .collect();
                for token in &tokens {
                    lock(&queued).insert(token_key(PushPlatform::WebPush, token));
                    tx.send(PushJob {
                        platform: PushPlatform::WebPush,
                        token: Zeroizing::new(token.clone()),
                        ticket: Arc::clone(&ticket),
                    })
                    .await?;
                }
                for _ in 0..1000 {
                    if tx.capacity() == tx.max_capacity() && lock(&queued).len() == HELD {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                assert_eq!(lock(&queued).len(), HELD, "the drain did not hold the jobs");
                assert_eq!(sender.sent().await.len(), WEBPUSH_SENDS_PER_TICKET);
                gate.admit(total);
                wait_for_sends(&sender, total).await?;
                assert_eq!(sender.sent().await, tokens);
                stop.cancel();
                task.await?;
                Ok(())
            }

            /// Twenty `WebPush` jobs wait on a full lookup pool, and one
            /// permit frees, once. Each restarted send takes no permit, as a
            /// send over a pooled connection resolves nothing, so no further
            /// permit drop signals the drain; each send that ends hands its
            /// restart on to the next held job, and all twenty are sent.
            #[tokio::test]
            async fn one_freed_lookup_permit_reaches_every_held_job() -> TestResult {
                const HELD: usize = 20;
                let (sender, pool) = RecordingSender::with_lookup_pool(
                    PushPlatform::WebPush,
                    vec![PushSendOutcome::Delivered; HELD],
                );
                let dir = tempfile::tempdir()?;
                let (tx, rx) = mpsc::channel(PUSH_QUEUE_CAPACITY);
                let queued = Arc::new(Mutex::new(HashSet::new()));
                let stop = CancellationToken::new();
                let drain = Drain {
                    senders: Arc::from(vec![recording(&sender)]),
                    index: 0,
                    store: PushRegistrationStore::open_sqlite(&dir.path().join("push.db"))?,
                    queued: Arc::clone(&queued),
                    logs: Arc::new(Logs::default()),
                    stop: stop.clone(),
                    pending_resets: HashSet::new(),
                };
                let task = tokio::spawn(drain.run(rx));
                let tokens: Vec<Vec<u8>> = (0..HELD)
                    .map(|n| format!("token-{n:04}").into_bytes())
                    .collect();
                for token in &tokens {
                    lock(&queued).insert(token_key(PushPlatform::WebPush, token));
                    tx.send(PushJob {
                        platform: PushPlatform::WebPush,
                        token: Zeroizing::new(token.clone()),
                        ticket: Arc::new(()),
                    })
                    .await?;
                }
                for _ in 0..1000 {
                    if tx.capacity() == tx.max_capacity() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
                assert_eq!(lock(&queued).len(), HELD, "the drain did not hold the jobs");
                assert!(sender.sent().await.is_empty());
                pool.free(1);
                wait_for_sends(&sender, HELD).await?;
                let mut sent = sender.sent().await;
                sent.sort();
                assert_eq!(sent, tokens);
                stop.cancel();
                task.await?;
                Ok(())
            }

            /// Runs `outcomes` through the APNs drain for one token two
            /// registrants hold, one publish per outcome, each publish after
            /// the previous send, and returns the service.
            async fn run_outcomes(
                outcomes: &[PushSendOutcome],
            ) -> Result<(PushService, TempDir), Box<dyn std::error::Error>> {
                let sender = RecordingSender::new(PushPlatform::Apns, outcomes.iter().copied());
                let (config, dir) = config(vec![recording(&sender)])?;
                let service = PushService::start(config)?;
                let push = PushRole::Enabled(service.clone());
                register(&push, REGISTRANT_A, PushPlatform::Apns, b"t1", &[RID]).await?;
                register(&push, REGISTRANT_B, PushPlatform::Apns, b"t1", &[RID]).await?;
                for i in 1..=outcomes.len() {
                    notify(&push, &RID);
                    wait_for_sends(&sender, i).await?;
                }
                assert_eq!(
                    sender.sent().await,
                    vec![b"t1".to_vec(); outcomes.len()],
                    "one send per publish, of the raw token"
                );
                Ok((service, dir))
            }

            /// Two registrants holding one token make one job; the same bytes
            /// on another platform are another token and make another job.
            #[tokio::test]
            async fn one_job_per_distinct_token() -> TestResult {
                use PushSendOutcome::Delivered;
                let apns = RecordingSender::new(PushPlatform::Apns, [Delivered, Delivered]);
                let fcm = RecordingSender::new(PushPlatform::Fcm, [Delivered]);
                let (config, _dir) = config(vec![recording(&apns), recording(&fcm)])?;
                let push = PushRole::Enabled(PushService::start(config)?);
                register(&push, REGISTRANT_A, PushPlatform::Apns, b"t1", &[RID]).await?;
                register(&push, REGISTRANT_B, PushPlatform::Apns, b"t1", &[RID]).await?;
                register(&push, REGISTRANT_A, PushPlatform::Fcm, b"t1", &[RID]).await?;
                register(&push, REGISTRANT_A, PushPlatform::Apns, b"t2", &[RID]).await?;
                notify(&push, &RID);
                wait_for_sends(&apns, 2).await?;
                wait_for_sends(&fcm, 1).await?;
                tokio::time::sleep(Duration::from_millis(100)).await;
                let mut sent = apns.sent().await;
                sent.sort();
                assert_eq!(sent, vec![b"t1".to_vec(), b"t2".to_vec()]);
                assert_eq!(fcm.sent().await, vec![b"t1".to_vec()]);
                Ok(())
            }

            /// Three `InvalidToken` outcomes in a row remove every
            /// registration holding the token.
            #[tokio::test]
            async fn three_invalid_tokens_remove_the_registrations() -> TestResult {
                use PushSendOutcome::InvalidToken;
                let (service, _dir) =
                    run_outcomes(&[InvalidToken, InvalidToken, InvalidToken]).await?;
                let store = &service.config().store;
                assert_eq!(failures_once_not(store, b"t1", Some(2)).await?, None);
                assert!(store.tokens_for_routing_id(&RID).await?.is_empty());
                Ok(())
            }

            /// Two `InvalidToken` outcomes leave the registrations in place:
            /// the removal happens at the third, not before.
            #[tokio::test]
            async fn two_invalid_tokens_keep_the_registrations() -> TestResult {
                use PushSendOutcome::InvalidToken;
                let (service, _dir) = run_outcomes(&[InvalidToken, InvalidToken]).await?;
                let store = &service.config().store;
                assert_eq!(failures_once_not(store, b"t1", Some(1)).await?, Some(2));
                assert_eq!(store.tokens_for_routing_id(&RID).await?.len(), 2);
                Ok(())
            }

            /// `InvalidToken`, `InvalidToken`, `Delivered`, `InvalidToken`
            /// leaves the registrations in place with a count of one.
            #[tokio::test]
            async fn delivered_resets_the_count() -> TestResult {
                use PushSendOutcome::{Delivered, InvalidToken};
                let (service, _dir) =
                    run_outcomes(&[InvalidToken, InvalidToken, Delivered, InvalidToken]).await?;
                let store = &service.config().store;
                assert_eq!(failures_once_not(store, b"t1", Some(0)).await?, Some(1));
                assert_eq!(store.tokens_for_routing_id(&RID).await?.len(), 2);
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
                wait_for_log(&service.inner.logs.config_error, 2).await?;
                let store = &service.config().store;
                assert_eq!(
                    store
                        .invalid_token_failures(PushPlatform::Apns, b"t1")
                        .await?,
                    Some(2)
                );
                assert_eq!(store.tokens_for_routing_id(&RID).await?.len(), 2);
                Ok(())
            }

            /// When the reset after a `Delivered` fails to write, the next
            /// `InvalidToken` still starts a new run: the count is one, not
            /// the stale two plus one, and the registrations stay.
            #[tokio::test]
            async fn a_failed_reset_still_breaks_the_run() -> TestResult {
                use PushSendOutcome::{Delivered, InvalidToken};
                let sender = RecordingSender::new(
                    PushPlatform::Apns,
                    [InvalidToken, InvalidToken, Delivered, InvalidToken],
                );
                let (config, dir) = config(vec![recording(&sender)])?;
                let service = PushService::start(config)?;
                let push = PushRole::Enabled(service.clone());
                let store = service.config().store.clone();
                register(&push, REGISTRANT_A, PushPlatform::Apns, b"t1", &[RID]).await?;
                for i in 1..=2 {
                    notify(&push, &RID);
                    wait_for_sends(&sender, i).await?;
                }
                assert_eq!(failures_once_not(&store, b"t1", Some(1)).await?, Some(2));

                // Move the count table aside: the reset after the delivery
                // fails.
                let beside = rusqlite::Connection::open(dir.path().join("push.db"))?;
                beside.execute_batch("ALTER TABLE push_token_failures RENAME TO held_aside;")?;
                notify(&push, &RID);
                wait_for_sends(&sender, 3).await?;
                wait_for_log(&service.inner.logs.store_failed, 1).await?;
                beside.execute_batch("ALTER TABLE held_aside RENAME TO push_token_failures;")?;
                assert_eq!(
                    store
                        .invalid_token_failures(PushPlatform::Apns, b"t1")
                        .await?,
                    Some(2),
                    "the stale count is back in place"
                );

                notify(&push, &RID);
                wait_for_sends(&sender, 4).await?;
                assert_eq!(failures_once_not(&store, b"t1", Some(2)).await?, Some(1));
                assert_eq!(store.tokens_for_routing_id(&RID).await?.len(), 1);
                Ok(())
            }

            /// The drain carries a failed reset in memory only, so a restart
            /// loses it. Two `InvalidToken`, a `Delivered` whose reset fails,
            /// a restart on the same store, then one `InvalidToken` leave the
            /// registration in place with a count of one, because the started
            /// service cleared the stale count of two before its first job.
            #[tokio::test]
            async fn a_restart_never_removes_on_a_stale_count() -> TestResult {
                use PushSendOutcome::{Delivered, InvalidToken};
                let sender = RecordingSender::new(
                    PushPlatform::Apns,
                    [InvalidToken, InvalidToken, Delivered],
                );
                let (config, dir) = config(vec![recording(&sender)])?;
                let store = config.store.clone();
                let service = PushService::start(config.clone())?;
                let push = PushRole::Enabled(service.clone());
                register(&push, REGISTRANT_A, PushPlatform::Apns, b"t1", &[RID]).await?;
                for i in 1..=2 {
                    notify(&push, &RID);
                    wait_for_sends(&sender, i).await?;
                }
                assert_eq!(failures_once_not(&store, b"t1", Some(1)).await?, Some(2));

                // Move the count table aside: the reset after the delivery
                // fails, and the drain carries it in memory.
                let beside = rusqlite::Connection::open(dir.path().join("push.db"))?;
                beside.execute_batch("ALTER TABLE push_token_failures RENAME TO held_aside;")?;
                notify(&push, &RID);
                wait_for_sends(&sender, 3).await?;
                wait_for_log(&service.inner.logs.store_failed, 1).await?;
                beside.execute_batch("ALTER TABLE held_aside RENAME TO push_token_failures;")?;
                assert_eq!(
                    store
                        .invalid_token_failures(PushPlatform::Apns, b"t1")
                        .await?,
                    Some(2),
                    "the stale count is back in place"
                );

                // Restart: the carried reset is gone with the old service.
                drop(push);
                drop(service);
                let after = RecordingSender::new(PushPlatform::Apns, [InvalidToken]);
                let restarted = PushService::start(PushServiceConfig {
                    senders: Arc::from(vec![recording(&after)]),
                    ..config
                })?;
                notify(&PushRole::Enabled(restarted.clone()), &RID);
                wait_for_sends(&after, 1).await?;
                assert_eq!(failures_once_not(&store, b"t1", Some(0)).await?, Some(1));
                assert_eq!(store.tokens_for_routing_id(&RID).await?.len(), 1);
                Ok(())
            }

            /// A service whose clear of the stored counts fails queues no
            /// job and sends no wake; it logs the failure and retries, and
            /// the wake published meanwhile goes out once the clear lands.
            #[tokio::test]
            async fn a_failed_clear_holds_wakes_until_it_lands() -> TestResult {
                use PushSendOutcome::Delivered;
                let sender = RecordingSender::new(PushPlatform::Apns, [Delivered]);
                let (config, dir) = config(vec![recording(&sender)])?;
                let registering = PushRole::Enabled(PushService::start(config.clone())?);
                register(
                    &registering,
                    REGISTRANT_A,
                    PushPlatform::Apns,
                    b"t1",
                    &[RID],
                )
                .await?;
                drop(registering);

                let beside = rusqlite::Connection::open(dir.path().join("push.db"))?;
                beside.execute_batch("ALTER TABLE push_token_failures RENAME TO held_aside;")?;
                let service = PushService::start(config)?;
                notify(&PushRole::Enabled(service.clone()), &RID);
                wait_for_log(&service.inner.logs.clear_failed, 1).await?;
                tokio::time::sleep(Duration::from_millis(100)).await;
                assert!(sender.sent().await.is_empty(), "no wake before the clear");

                beside.execute_batch("ALTER TABLE held_aside RENAME TO push_token_failures;")?;
                wait_for_sends(&sender, 1).await?;
                assert_eq!(sender.sent().await, vec![b"t1".to_vec()]);
                Ok(())
            }

            /// A job for a platform with no configured sender is dropped and
            /// logged, and changes nothing in the store. The gate refuses a
            /// registration for a platform without a sender, so the case
            /// arises when a relay restarts on the same store without the
            /// sender a stored registration needs.
            #[tokio::test]
            async fn job_without_a_sender_is_logged() -> TestResult {
                let fcm = RecordingSender::new(PushPlatform::Fcm, []);
                let (before, _dir) = config(vec![recording(&fcm)])?;
                let registering = PushRole::Enabled(PushService::start(before.clone())?);
                register(&registering, REGISTRANT_A, PushPlatform::Fcm, b"t1", &[RID]).await?;
                drop(registering);

                let apns = RecordingSender::new(PushPlatform::Apns, []);
                let service = PushService::start(PushServiceConfig {
                    senders: Arc::from(vec![recording(&apns)]),
                    ..before
                })?;
                notify(&PushRole::Enabled(service.clone()), &RID);
                wait_for_log(&service.inner.logs.no_sender, 1).await?;
                assert!(apns.sent().await.is_empty());
                assert!(fcm.sent().await.is_empty());
                assert_eq!(
                    service
                        .config()
                        .store
                        .invalid_token_failures(PushPlatform::Fcm, b"t1")
                        .await?,
                    Some(0)
                );
                Ok(())
            }

            /// A push service that never answers holds only its own
            /// platform: FCM wakes keep going while every APNs send hangs.
            #[tokio::test]
            async fn a_hung_platform_does_not_stall_the_other() -> TestResult {
                use PushSendOutcome::Delivered;
                let (apns, gate) = RecordingSender::gated(PushPlatform::Apns, [Delivered; 2]);
                let fcm = RecordingSender::new(PushPlatform::Fcm, [Delivered; 2]);
                let (config, _dir) = config(vec![recording(&apns), recording(&fcm)])?;
                let push = PushRole::Enabled(PushService::start(config)?);
                register(&push, REGISTRANT_A, PushPlatform::Apns, b"apns", &[RID]).await?;
                register(&push, REGISTRANT_A, PushPlatform::Fcm, b"fcm", &[RID]).await?;

                notify(&push, &RID);
                wait_for_sends(&apns, 1).await?;
                wait_for_sends(&fcm, 1).await?;
                notify(&push, &RID);
                wait_for_sends(&fcm, 2).await?;
                assert_eq!(apns.sent().await.len(), 1, "the APNs send is still held");

                gate.admit(2);
                wait_for_sends(&apns, 2).await
            }

            /// After a `Transient` outcome the drain waits at least the first
            /// back-off before its next send to that service, while the
            /// other platform's drain sends at once.
            #[tokio::test]
            async fn transient_backs_off_only_its_own_platform() -> TestResult {
                use PushSendOutcome::{Delivered, Transient};
                let apns = RecordingSender::new(PushPlatform::Apns, [Transient, Delivered]);
                let fcm = RecordingSender::new(PushPlatform::Fcm, [Delivered; 2]);
                let (config, _dir) = config(vec![recording(&apns), recording(&fcm)])?;
                let push = PushRole::Enabled(PushService::start(config)?);
                register(&push, REGISTRANT_A, PushPlatform::Apns, b"apns", &[RID]).await?;
                register(&push, REGISTRANT_A, PushPlatform::Fcm, b"fcm", &[RID]).await?;

                notify(&push, &RID);
                wait_for_sends(&apns, 1).await?;
                let first = Instant::now();
                wait_for_sends(&fcm, 1).await?;
                notify(&push, &RID);
                wait_for_sends(&fcm, 2).await?;
                assert_eq!(
                    apns.sent().await.len(),
                    1,
                    "APNs sent again without backing off"
                );
                assert!(
                    first.elapsed() < Duration::from_millis(900),
                    "FCM waited {:?} on the APNs back-off",
                    first.elapsed()
                );

                wait_for_sends(&apns, 2).await?;
                let gap = first.elapsed();
                assert!(
                    gap >= TRANSIENT_BACKOFF_MIN.saturating_sub(Duration::from_millis(50)),
                    "the next APNs send came {gap:?} after a Transient"
                );
                Ok(())
            }

            /// The `WebPush` drain sends concurrently, but never two sends of
            /// one token at once: while a token's send is held, a second wake
            /// for it waits and a third joins the second, and another token's
            /// wake is sent at once. Once the held send finishes, the waiting
            /// job is sent, so the token's two outcomes reach the store in
            /// order.
            #[tokio::test]
            async fn webpush_sends_one_token_at_a_time() -> TestResult {
                use PushSendOutcome::InvalidToken;
                const T: RoutingId = [0x54; 32];
                const U: RoutingId = [0x55; 32];
                let (webpush, gate) =
                    RecordingSender::gated(PushPlatform::WebPush, [InvalidToken; 8]);
                let (config, _dir) = config(vec![recording(&webpush)])?;
                let service = PushService::start(config)?;
                let push = PushRole::Enabled(service.clone());
                let (_, t) = subscribe("https://push.example.net/t".to_owned())?;
                let (_, u) = subscribe("https://push.example.net/u".to_owned())?;
                let (t, u) = (t.encode(), u.encode());
                register(&push, REGISTRANT_A, PushPlatform::WebPush, &t, &[T]).await?;
                register(&push, REGISTRANT_A, PushPlatform::WebPush, &u, &[U]).await?;

                notify(&push, &T);
                wait_for_sends(&webpush, 1).await?;
                for _ in 0..2 {
                    notify(&push, &T);
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                notify(&push, &U);
                wait_for_sends(&webpush, 2).await?;
                tokio::time::sleep(Duration::from_millis(100)).await;
                assert_eq!(
                    webpush.sent().await,
                    vec![t.clone(), u.clone()],
                    "a second send of the held token started"
                );

                gate.admit(8);
                wait_for_sends(&webpush, 3).await?;
                tokio::time::sleep(Duration::from_millis(100)).await;
                assert_eq!(webpush.sent().await, vec![t.clone(), u, t.clone()]);
                let store = &service.config().store;
                for _ in 0..1000 {
                    if store
                        .invalid_token_failures(PushPlatform::WebPush, &t)
                        .await?
                        == Some(2)
                    {
                        return Ok(());
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                Err("the token's two outcomes were not both counted".into())
            }

            /// Publishes to a routing ID with many tokens leave room for
            /// another routing ID's wake: with queues of four and a share of
            /// two, five tokens on A published three times hold two slots,
            /// and B's wake is queued and sent.
            #[tokio::test]
            async fn a_flood_on_one_routing_id_leaves_room_for_another() -> TestResult {
                const A: RoutingId = [0xA0; 32];
                const B: RoutingId = [0xB0; 32];
                const C: RoutingId = [0xC0; 32];
                let (apns, gate): (RecordingSender, RecordingGate) =
                    RecordingSender::gated(PushPlatform::Apns, [PushSendOutcome::Delivered; 16]);
                let (config, _dir) = config(vec![recording(&apns)])?;
                let service = PushService::start_with_limits(config, 4, 2)?;
                let push = PushRole::Enabled(service.clone());
                register(&push, REGISTRANT_A, PushPlatform::Apns, b"c0", &[C]).await?;
                for token in [b"a1", b"a2", b"a3", b"a4", b"a5"] {
                    register(&push, REGISTRANT_A, PushPlatform::Apns, token, &[A]).await?;
                }
                register(&push, REGISTRANT_B, PushPlatform::Apns, b"b1", &[B]).await?;

                // Hold the drain on C's send, so nothing leaves the queue.
                notify(&push, &C);
                wait_for_sends(&apns, 1).await?;
                for _ in 0..3 {
                    notify(&push, &A);
                    tokio::time::sleep(Duration::from_millis(30)).await;
                }
                notify(&push, &B);
                tokio::time::sleep(Duration::from_millis(100)).await;
                assert_eq!(
                    service.inner.logs.queue_full.total(),
                    0,
                    "a wake was dropped"
                );

                gate.admit(16);
                wait_for_sends(&apns, 4).await?;
                tokio::time::sleep(Duration::from_millis(100)).await;
                let sent = apns.sent().await;
                assert_eq!(sent.len(), 4, "C, two of A's, and B: {sent:?}");
                assert!(sent.contains(&b"b1".to_vec()), "B was never woken");
                let from_a = sent.iter().filter(|t| t.starts_with(b"a")).count();
                assert_eq!(from_a, 2);
                Ok(())
            }

            /// A full platform queue drops the job and logs it, and `notify`
            /// returns at once, so the caller's publish succeeds.
            #[tokio::test]
            async fn full_queue_drops_and_logs() -> TestResult {
                const B: RoutingId = [0xB0; 32];
                let (apns, gate) =
                    RecordingSender::gated(PushPlatform::Apns, [PushSendOutcome::Delivered; 4]);
                let (config, _dir) = config(vec![recording(&apns)])?;
                let service = PushService::start_with_limits(config, 1, 8)?;
                let push = PushRole::Enabled(service.clone());
                register(&push, REGISTRANT_A, PushPlatform::Apns, b"t0", &[RID]).await?;
                register(&push, REGISTRANT_A, PushPlatform::Apns, b"t1", &[B]).await?;
                register(&push, REGISTRANT_A, PushPlatform::Apns, b"t2", &[B]).await?;
                notify(&push, &RID);
                wait_for_sends(&apns, 1).await?;
                notify(&push, &B);
                wait_for_log(&service.inner.logs.queue_full, 1).await?;
                gate.admit(4);
                wait_for_sends(&apns, 2).await
            }
        }
    }
}

/// A push service over a fresh SQLite store, with a recording APNs sender
/// or a real `WebPush` sender, for the transports' end-to-end wake tests.
#[cfg(all(test, feature = "push-store", feature = "testing"))]
pub(crate) mod wake_harness {
    use std::sync::Arc;
    use std::time::Duration;

    use scp_crypto::p256::{P256SecretKey, sign_prehash_rfc6979};
    use scp_did::DID;
    use scp_identity::push_verify::TestPushVerifier;
    use scp_protocol::discovery::push::{
        PushPlatform, PushRegistration, push_registration_signing_bytes,
    };
    use sha2::{Digest, Sha256};
    use tempfile::TempDir;

    use super::PushService;
    use crate::relay::push::{PushSendOutcome, PushSender, RecordingSender, WebPushSender};
    use crate::relay::push_gate::{
        PushPublishGate, PushRole, PushServiceConfig, gate_publish, test_relay_url,
    };
    use crate::relay::push_store::PushRegistrationStore;

    type Error = Box<dyn std::error::Error>;

    const REGISTRANT: &str = "did:dht:wake-harness";
    /// The token every harness registers.
    const TOKEN: &[u8] = b"wake-harness-token";

    /// A running push service whose one sender is a recording APNs sender,
    /// over a fresh SQLite store holding one registration of [`TOKEN`].
    pub struct WakeHarness {
        /// The role to give the relay under test.
        pub push: PushRole,
        sender: RecordingSender,
        _dir: TempDir,
    }

    impl WakeHarness {
        /// Starts the service and registers [`TOKEN`] for `routing_ids`
        /// through the push gate, as a client's PUBLISH would.
        pub async fn start(routing_ids: &[[u8; 32]]) -> Result<Self, Error> {
            let sender = RecordingSender::new(PushPlatform::Apns, [PushSendOutcome::Delivered; 64]);
            let (push, dir) = registered(
                PushSender::Recording(sender.clone()),
                PushPlatform::Apns,
                TOKEN,
                routing_ids,
            )
            .await?;
            Ok(Self {
                push,
                sender,
                _dir: dir,
            })
        }

        /// Wakes sent so far.
        pub async fn wakes(&self) -> usize {
            self.sender.sent().await.len()
        }

        /// Waits up to 5 s for `n` wakes of [`TOKEN`].
        pub async fn wait_for_wakes(&self, n: usize) -> Result<(), Error> {
            for _ in 0..1000 {
                let sent = self.sender.sent().await;
                if sent.len() >= n {
                    if sent.iter().any(|t| t.as_slice() != TOKEN) {
                        return Err("a wake went to a token never registered".into());
                    }
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Err(format!("expected {n} wakes, saw {}", self.wakes().await).into())
        }
    }

    /// A running push service whose one sender is `sender`, holding a
    /// `WebPush` registration of `token` for `routing_ids` made through the
    /// push gate. The returned directory holds the store.
    pub async fn webpush(
        sender: WebPushSender,
        token: &[u8],
        routing_ids: &[[u8; 32]],
    ) -> Result<(PushRole, TempDir), Error> {
        registered(
            PushSender::WebPush(sender),
            PushPlatform::WebPush,
            token,
            routing_ids,
        )
        .await
    }

    /// Starts a service whose one sender is `sender`, and registers `token`
    /// on `platform` for `routing_ids` through the push gate, as a client's
    /// PUBLISH would, signed by a key the `TestPushVerifier` holds.
    async fn registered(
        sender: PushSender,
        platform: PushPlatform,
        token: &[u8],
        routing_ids: &[[u8; 32]],
    ) -> Result<(PushRole, TempDir), Error> {
        let dir = tempfile::tempdir()?;
        let signer = P256SecretKey::from_scalar_bytes(&[0x5A; 32])?;
        let service = PushService::start(PushServiceConfig {
            store: PushRegistrationStore::open_sqlite(&dir.path().join("push.db"))?,
            verifier: Arc::new(TestPushVerifier::new([(
                DID::from(REGISTRANT),
                signer.public_key(),
            )])),
            senders: Arc::from(vec![sender]),
        })?;
        let push = PushRole::Enabled(service);
        let now = scp_clock::Clock::now_secs(&scp_clock::SystemClock);
        let mut msg = PushRegistration {
            registrant: DID::from(REGISTRANT),
            platform,
            token: token.to_vec(),
            routing_ids: routing_ids.to_vec(),
            timestamp: now,
            signature: [0; 64],
        };
        let relay_url = test_relay_url();
        let reserved_urls = relay_url.current();
        let [current] = reserved_urls.as_slice() else {
            return Err("the test relay reserves one URL".into());
        };
        let digest: [u8; 32] =
            Sha256::digest(push_registration_signing_bytes(&msg, current.push_relay())?).into();
        msg.signature = sign_prehash_rfc6979(&signer, &digest)?;
        let reserved = current.push_routing_id();
        let blob = rmp_serde::to_vec_named(&msg)?;
        let decision = gate_publish(&relay_url, &push, &reserved, &blob, now).await;
        if decision != PushPublishGate::Accepted {
            return Err(format!("registration not accepted: {decision:?}").into());
        }
        Ok((push, dir))
    }
}
