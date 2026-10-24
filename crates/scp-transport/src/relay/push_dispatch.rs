//! The relay push dispatcher (spec §10.7.1 step 5 and `PushDeregistration`;
//! PUSH-008).
//!
//! After a relay stores a blob, delivers it to subscribers and answers the
//! publisher, it calls [`notify`] with the blob's routing ID. `notify` never
//! waits: it puts the routing ID on a bounded intake and returns, so no
//! publish waits on a lookup or a send.
//!
//! With push enabled, the relay's `PushService` runs two kinds of task, all
//! started by `PushService::start`. `PushService::stop` stops them gracefully
//! and waits for them; dropping the last clone of the service stops them
//! without waiting:
//!
//! - **One lookup task** reads the intake, reads the (platform, token) pairs
//!   registered for each routing ID in one query on the blocking pool, and
//!   queues one job per token on that platform's queue.
//! - **One drain per configured sender**, each reading its own platform's
//!   queue, so a push service that stops answering stalls only its own
//!   platform. Each drain passes every job through its platform's per-token
//!   rate limit (section Rate limit below) and checks that a registration
//!   still holds the job's token before it sends (§10.7.1 step 6,
//!   **Registration check**): a job carries the token the lookup read, and a
//!   token deregistered or removed since then is not sent to. After a
//!   `Transient` outcome a drain backs off before its next send to that
//!   service. Each drain applies the outcome to the registration store:
//!   - `Delivered` resets the token's consecutive invalid-token count.
//!   - `InvalidToken` adds one to it; at `INVALID_TOKEN_REMOVAL_THRESHOLD`
//!     (in `push_store`, a module the `push-store` feature compiles) the
//!     store removes every registration holding the token, in the same
//!     transaction.
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
//! # Rate limit
//!
//! §10.7.1 step 6 allows at most one push per 30 s per device token, and
//! defers a wake inside that window instead of dropping it (PUSH-009). Each
//! drain owns one `PushWakeLimiter` (in `rate_limit`) for its platform and
//! consults it for every job it reads:
//! - A token with no window open is sent at once, which opens its window.
//! - A token inside its window holds the job as its one pending wake, and
//!   any later job for that token joins it. The drain sends the pending wake
//!   when the window closes, because it sleeps until the oldest window's
//!   close whenever no job is waiting. A drain backing off after a
//!   `Transient` outcome reads no due wake until the back-off ends, so a
//!   pending wake goes out at its window's close or the back-off's end,
//!   whichever is later.
//! - A push that ends `Transient`, or a job discarded before its send,
//!   opens no window: the drain releases the token's window unless the token
//!   holds a pending wake (§10.7.1 step 6, **Window**).
//! - The limiter keys a token by the same SHA-256 of the platform tag and
//!   token the queues use, and holds the token's bytes only inside a pending
//!   job, which zeroizes them when it is sent, joined or dropped.
//!
//! The limiter holds at most one pending wake per token and refuses none, so
//! the rate limit drops no wake while the relay runs (§10.7.1 step 6, **Held
//! wakes and the bounds**). A pending job keeps its routing ID's ticket, so
//! it counts toward `MAX_WAKES_PER_PUBLISH` as a job in flight.
//!
//! The limiter lives in the drain's memory. `PushService::stop` makes each
//! drain finish the send in flight and send every pending wake before it
//! exits, whether or not its window closed, and waits until they are out. A
//! crash, or a process that exits without awaiting `stop`, loses them
//! (§10.7.1 step 6, **Stop and crash**). A
//! restarted relay starts with no windows open (§10.7.1 step 6, **State**).
//! The limiter forgets a token once its window closes with nothing pending,
//! so it holds an entry only for each token whose window is open.
//!
//! # Bounds
//!
//! The intake and every platform queue hold at most `PUSH_QUEUE_CAPACITY`
//! entries. A wake that does not fit is dropped, and the publish still
//! succeeds (PUSH-008 AC2): a wake is advisory, and a device whose wake was
//! dropped pulls on its next wake or connection (§10.7.1 step 5,
//! **Best-effort delivery**). The intake holds each routing ID at most once, and
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
//! push service whose drains are not running. A relay's
//! `ShutdownHandle::shutdown_gracefully` calls `PushService::stop`.
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
    use std::collections::{HashMap, HashSet};
    use std::fmt;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
    use std::time::{Duration, Instant};

    use scp_protocol::discovery::push::PushPlatform;
    use sha2::{Digest, Sha256};
    use tokio::sync::mpsc;
    use tokio::task::JoinHandle;
    use tokio_util::sync::{CancellationToken, DropGuard};
    use zeroize::{Zeroize, Zeroizing};

    use super::super::push::{PushSendOutcome, PushSender};
    use super::super::push_gate::{PushRole, PushServiceConfig};
    use super::super::push_store::{
        CountFrom, InvalidTokenOutcome, PushRegistrationStore, RoutingId, WakeToken,
    };
    use super::super::rate_limit::{PUSH_WAKE_WINDOW, PushWakeLimiter, WakeAdmission};
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

    /// A push service that could not start, or could not stop gracefully.
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
        /// [`PushService::stop`] found tasks that ended in a panic, so the
        /// pending wakes a panicked drain held were lost unsent.
        #[error("{tasks} push service task(s) panicked before the graceful stop")]
        TaskPanicked {
            /// The tasks that panicked.
            tasks: usize,
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
    ///
    /// `T` is the token's buffer. Every production job holds a `Vec<u8>`; a
    /// test holds a buffer it can read after the wipe, and being generic
    /// lets `zeroize` reach the token only through `Zeroize`, never through
    /// a `Vec` method such as `clear` that frees no bytes.
    struct PushJob<T: Zeroize = Vec<u8>> {
        platform: PushPlatform,
        token: Zeroizing<T>,
        /// Held, never read, until the job drops; the lookup counts a routing ID's
        /// live jobs by the clones of its ticket.
        _ticket: Arc<()>,
    }

    /// Zeroizes the token, so the rate limiter can hold a pending job in
    /// [`Zeroizing`] and wipe its token whenever it drops the job.
    impl<T: Zeroize> Zeroize for PushJob<T> {
        fn zeroize(&mut self) {
            self.token.zeroize();
        }
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
        registration_check_failed: RateLimitedLog,
        task_panicked: RateLimitedLog,
    }

    /// The sizes the service runs with. Production uses
    /// [`Limits::PRODUCTION`]; the tests shrink them to fill a queue, and
    /// the tests of behaviour other than the rate limit shorten its window.
    #[derive(Debug, Clone, Copy)]
    struct Limits {
        queue_capacity: usize,
        wakes_per_publish: usize,
        /// The shortest time between two pushes to one token (§10.7.1
        /// step 6).
        wake_window: Duration,
    }

    impl Limits {
        const PRODUCTION: Self = Self {
            queue_capacity: PUSH_QUEUE_CAPACITY,
            wakes_per_publish: MAX_WAKES_PER_PUBLISH,
            wake_window: PUSH_WAKE_WINDOW,
        };
    }

    /// The relay's running push service: the configuration it was started
    /// with, the intake [`notify`] writes to, and the tasks that read it.
    ///
    /// Clones share one service. [`PushService::stop`] stops its tasks
    /// gracefully and waits for them. Dropping the last clone stops them the
    /// same way but waits for nothing, so a process that exits next loses
    /// the pending wakes its drains had not yet sent.
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
        /// Stops the lookup and every drain.
        stop: CancellationToken,
        /// The lookup and every drain, which [`PushService::stop`] waits for.
        tasks: tokio::sync::Mutex<Vec<JoinHandle<()>>>,
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

        /// As [`Self::start`], with queues of `queue_capacity` entries, at
        /// most `wakes_per_publish` jobs per routing ID, and one push per
        /// `wake_window` per token, so a test can fill a queue or send one
        /// token several wakes without waiting out the production window.
        #[cfg(test)]
        pub(crate) fn start_with_limits(
            config: PushServiceConfig,
            queue_capacity: usize,
            wakes_per_publish: usize,
            wake_window: Duration,
        ) -> Result<Self, PushServiceError> {
            Self::start_with(
                config,
                Limits {
                    queue_capacity,
                    wakes_per_publish,
                    wake_window,
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
            let mut tasks = Vec::with_capacity(config.senders.len().saturating_add(1));
            for (index, sender) in config.senders.iter().enumerate() {
                let (tx, rx) = mpsc::channel(limits.queue_capacity);
                let queued = Arc::new(Mutex::new(HashSet::new()));
                tasks.push(
                    runtime.spawn(
                        Drain {
                            senders: Arc::clone(&config.senders),
                            index,
                            store: config.store.clone(),
                            queued: Arc::clone(&queued),
                            logs: Arc::clone(&logs),
                            stop: stop.clone(),
                            pending_resets: HashSet::new(),
                            limiter: PushWakeLimiter::new(limits.wake_window),
                        }
                        .drain(rx),
                    ),
                );
                lanes.push(Lane {
                    platform: sender.platform(),
                    tx,
                    queued,
                });
            }
            let (intake, intake_rx) = mpsc::channel(limits.queue_capacity);
            let pending = Arc::new(Mutex::new(HashSet::new()));
            tasks.push(
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
                ),
            );
            Ok(Self {
                inner: Arc::new(Inner {
                    config,
                    intake,
                    pending,
                    logs,
                    stop: stop.clone(),
                    tasks: tokio::sync::Mutex::new(tasks),
                    _stop: stop.drop_guard(),
                }),
            })
        }

        /// Stops the service gracefully and waits until its tasks exit: the
        /// lookup queues nothing more, and each drain finishes the send in
        /// flight, sends every pending wake whether or not its window closed,
        /// and exits (§10.7.1 step 6, **Stop and crash**). A wake still on a
        /// queue is not sent. Each send is bounded by its sender's request
        /// timeout, so the wait is too.
        ///
        /// A later or concurrent call waits for the first to finish and then
        /// returns `Ok`. A wake notified after the stop is dropped.
        ///
        /// # Errors
        ///
        /// [`PushServiceError::TaskPanicked`] when a task ended in a panic,
        /// so the pending wakes a panicked drain held were lost.
        pub async fn stop(&self) -> Result<(), PushServiceError> {
            self.inner.stop.cancel();
            let mut tasks = self.inner.tasks.lock().await;
            let mut panicked = 0_usize;
            for task in tasks.drain(..) {
                if task.await.is_err() {
                    panicked = panicked.saturating_add(1);
                }
            }
            drop(tasks);
            if panicked == 0 {
                Ok(())
            } else {
                if let Some(line) = self.inner.logs.task_panicked.hit() {
                    tracing::error!(
                        tasks = panicked,
                        total = line.total,
                        "push service tasks panicked before the graceful stop; their pending wakes were lost"
                    );
                }
                Err(PushServiceError::TaskPanicked { tasks: panicked })
            }
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
            if !queued.insert(key) {
                // Already on the queue; that job wakes the device.
                return;
            }
            let job = PushJob {
                platform,
                token,
                _ticket: Arc::clone(ticket),
            };
            let refused = match lane.tx.try_send(job) {
                Ok(()) => return,
                Err(mpsc::error::TrySendError::Full(_)) => &self.logs.queue_full,
                Err(mpsc::error::TrySendError::Closed(_)) => &self.logs.queue_closed,
            };
            queued.remove(&key);
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

    /// One platform's drain: jobs in, through the rate limit, sends out,
    /// outcomes into the store.
    struct Drain {
        senders: Arc<[PushSender]>,
        index: usize,
        store: PushRegistrationStore,
        queued: Arc<Mutex<HashSet<TokenKey>>>,
        logs: Arc<Logs>,
        stop: CancellationToken,
        /// Tokens whose last outcome was `Delivered` but whose count reset
        /// the store failed to write. At most [`PUSH_QUEUE_CAPACITY`].
        pending_resets: HashSet<TokenKey>,
        /// The platform's per-token rate limit (§10.7.1 step 6), holding each
        /// deferred job until its token's window closes. A graceful stop
        /// sends every job it holds; a drain dropped without one zeroizes
        /// every pending job's token unsent.
        limiter: PushWakeLimiter<PushJob>,
    }

    impl Drain {
        async fn drain(mut self, mut rx: mpsc::Receiver<PushJob>) {
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
            let mut backoff = ReconnectBackoff::new(TRANSIENT_BACKOFF_MIN, TRANSIENT_BACKOFF_MAX);
            // `None` means the service stopped. A send in flight finishes
            // first, so a stop never cuts one off; each send is bounded by
            // the sender's request timeout.
            while let Some(job) = self.next_job(&mut rx).await {
                let Some(job) = self.registered(job).await else {
                    continue;
                };
                let outcome = sender.send_registered(&job.token).await;
                self.settle(job, outcome).await;
                if outcome == PushSendOutcome::Transient {
                    if !self.pause(backoff.next_delay()).await {
                        break;
                    }
                } else {
                    backoff.reset();
                }
            }
            // A graceful stop sends every pending wake (§10.7.1 step 6,
            // **Stop and crash**), with no back-off between sends.
            for job in self.limiter.take_pending() {
                let Some(job) = self.registered(job).await else {
                    continue;
                };
                let outcome = sender.send_registered(&job.token).await;
                self.settle(job, outcome).await;
            }
        }

        /// `job` when a registration still holds its token (§10.7.1 step 6,
        /// **Registration check**). Otherwise the job drops, which zeroizes
        /// its token and releases its routing ID's ticket, and the token's
        /// window is released, because no push went out (§10.7.1 step 6,
        /// **Window**). A store failure drops the job too: a token the store
        /// cannot vouch for may have been deregistered.
        async fn registered(&mut self, job: Zeroizing<PushJob>) -> Option<Zeroizing<PushJob>> {
            let platform = job.platform;
            match self.store.holds_token(platform, &job.token).await {
                Ok(true) => return Some(job),
                Ok(false) => tracing::debug!(
                    platform = ?platform,
                    "push token lost its registration before its send; wake discarded"
                ),
                Err(e) => {
                    if let Some(line) = self.logs.registration_check_failed.hit() {
                        tracing::warn!(
                            platform = ?platform,
                            total = line.total,
                            suppressed = line.suppressed,
                            error = %e,
                            "could not check a push token's registration; wake dropped"
                        );
                    }
                }
            }
            self.limiter.release(&token_key(platform, &job.token));
            None
        }

        /// Records a sent `job`'s `outcome`: a `Transient` push opens no
        /// window (§10.7.1 step 6, **Window**), so the token's window is
        /// released, and the outcome goes to the store. The job drops on
        /// return, which zeroizes its token and releases its routing ID's
        /// ticket.
        async fn settle(&mut self, job: Zeroizing<PushJob>, outcome: PushSendOutcome) {
            let key = token_key(job.platform, &job.token);
            if outcome == PushSendOutcome::Transient {
                self.limiter.release(&key);
            }
            self.apply(job.platform, key, &job.token, outcome).await;
        }

        /// The next job to send under the rate limit (§10.7.1 step 6): a
        /// pending job whose token's window closed, or a job from the queue
        /// whose token has no window open. A job from the queue whose token
        /// has a window open becomes that token's pending job, or joins the
        /// one it already has, and the drain reads on. `None` when the
        /// service stopped.
        ///
        /// While no job is waiting, the drain sleeps until the oldest window
        /// closes, so a pending job goes out when its window closes and a
        /// token with nothing pending is forgotten then.
        async fn next_job(
            &mut self,
            rx: &mut mpsc::Receiver<PushJob>,
        ) -> Option<Zeroizing<PushJob>> {
            loop {
                if let Some(job) = self.limiter.take_due(tokio::time::Instant::now()) {
                    return Some(job);
                }
                let due = self.limiter.next_due();
                let job = tokio::select! {
                    biased;
                    () = self.stop.cancelled() => return None,
                    () = sleep_until(due) => continue,
                    // The lookup holds the queue's sender until it stops, so
                    // `None` means the service is gone.
                    job = rx.recv() => job?,
                };
                let key = token_key(job.platform, &job.token);
                lock(&self.queued).remove(&key);
                let admitted =
                    self.limiter
                        .admit(key, Zeroizing::new(job), tokio::time::Instant::now());
                match admitted {
                    WakeAdmission::SendNow(job) => return Some(job),
                    WakeAdmission::Deferred | WakeAdmission::Joined => {}
                }
            }
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

        /// Applies `outcome` for `token` to the store.
        async fn apply(
            &mut self,
            platform: PushPlatform,
            key: TokenKey,
            token: &[u8],
            outcome: PushSendOutcome,
        ) {
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
                                self.retry_reset(platform, token).await;
                            }
                        }
                    }
                }
                PushSendOutcome::InvalidToken => {
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

        /// Writes a reset the drain has no room to carry, retrying with
        /// back-off until it lands or the service stops. A reset lost to the
        /// stop costs nothing: the next start clears every count.
        async fn retry_reset(&self, platform: PushPlatform, token: &[u8]) {
            let mut backoff = ReconnectBackoff::new(TRANSIENT_BACKOFF_MIN, TRANSIENT_BACKOFF_MAX);
            loop {
                if !self.pause(backoff.next_delay()).await {
                    return;
                }
                match self.store.clear_invalid_tokens(platform, token).await {
                    Ok(_) => return,
                    Err(e) => self.store_failed(platform, &e),
                }
            }
        }
    }

    /// Sleeps until `due`, or forever when `due` is `None`.
    async fn sleep_until(due: Option<tokio::time::Instant>) {
        match due {
            Some(due) => tokio::time::sleep_until(due).await,
            None => std::future::pending().await,
        }
    }

    fn log_invalid(platform: PushPlatform, counted: InvalidTokenOutcome) {
        match counted {
            InvalidTokenOutcome::Removed { registrations } => tracing::info!(
                platform = ?platform,
                registrations,
                "removed push registrations after consecutive invalid-token responses"
            ),
            InvalidTokenOutcome::Counted { failures } => {
                tracing::debug!(platform = ?platform, failures, "push token answered invalid");
            }
            InvalidTokenOutcome::NotRegistered => tracing::debug!(
                platform = ?platform,
                "push token answered invalid after its registrations were removed"
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
        use super::super::super::push_gate::{PushPublishGate, gate_publish, test_relay_url};
        use super::super::super::push_test_server::TestServer;
        use super::*;

        type TestResult = Result<(), Box<dyn std::error::Error>>;

        const RID: RoutingId = [0x11; 32];
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
                _ticket: Arc::new(()),
            };
            let shown = format!("{job:?}");
            assert!(!shown.contains("secret-token"), "{shown}");
            assert!(shown.contains("token_len: 12"), "{shown}");
            let PushJob {
                platform,
                token,
                _ticket: ticket,
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
            let service = PushService::start_with_limits(config, 4, 4, PUSH_WAKE_WINDOW)?;
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
            let service = PushService::start_with_limits(config, 1, 4, PUSH_WAKE_WINDOW)?;
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

        /// A token buffer whose bytes the test reads after the job wipes it.
        struct SharedToken(Arc<Mutex<Vec<u8>>>);

        impl Zeroize for SharedToken {
            fn zeroize(&mut self) {
                lock(&self.0).as_mut_slice().zeroize();
            }
        }

        /// Zeroizing a job overwrites every byte of its token, so the rate
        /// limiter's `Zeroizing<PushJob>` wipes the token of every job it
        /// drops. The test reads the token's bytes after the wipe, so a
        /// `zeroize` that only shortens or forgets the token fails it.
        #[test]
        fn zeroizing_a_job_wipes_its_token() {
            let bytes = Arc::new(Mutex::new(b"secret-token".to_vec()));
            let mut job = PushJob {
                platform: PushPlatform::Apns,
                token: Zeroizing::new(SharedToken(Arc::clone(&bytes))),
                _ticket: Arc::new(()),
            };
            job.zeroize();
            assert_eq!(*lock(&bytes), vec![0; 12], "token bytes left");
        }

        /// With push disabled, `notify` does nothing.
        #[test]
        fn disabled_role_does_nothing() {
            notify(&PushRole::Disabled, &RID);
        }

        /// Drain tests: the recording sender compiles only under `testing`.
        #[cfg(feature = "testing")]
        mod drain {
            use super::super::super::super::push::{RecordingGate, RecordingSender};
            use super::*;

            /// A service with the production queues and a zero rate-limit
            /// window, for the PUSH-008 tests that send one token several
            /// wakes in a row and test something other than the rate limit.
            fn start_unlimited(config: PushServiceConfig) -> Result<PushService, PushServiceError> {
                PushService::start_with_limits(
                    config,
                    PUSH_QUEUE_CAPACITY,
                    MAX_WAKES_PER_PUBLISH,
                    Duration::ZERO,
                )
            }

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

            /// Runs `outcomes` through the APNs drain for one token two
            /// registrants hold, one publish per outcome, each publish after
            /// the previous send, and returns the service.
            async fn run_outcomes(
                outcomes: &[PushSendOutcome],
            ) -> Result<(PushService, TempDir), Box<dyn std::error::Error>> {
                let sender = RecordingSender::new(PushPlatform::Apns, outcomes.iter().copied());
                let (config, dir) = config(vec![recording(&sender)])?;
                let service = start_unlimited(config)?;
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
                let service = start_unlimited(config)?;
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
                let service = start_unlimited(config.clone())?;
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
                let restarted = start_unlimited(PushServiceConfig {
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
                let push = PushRole::Enabled(start_unlimited(config)?);
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
                let push = PushRole::Enabled(start_unlimited(config)?);
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
                let service = PushService::start_with_limits(config, 4, 2, PUSH_WAKE_WINDOW)?;
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
                let service = PushService::start_with_limits(config, 1, 8, PUSH_WAKE_WINDOW)?;
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

            /// The per-token rate limit of §10.7.1 step 6 (PUSH-009), on the
            /// production service and its 30 s window, under paused tokio
            /// time.
            mod rate_limit {
                use tokio::time::Instant;

                use super::*;

                const RID2: RoutingId = [0x22; 32];

                /// The production service with one recording APNs sender,
                /// `t1` registered on `RID` and `t2` on `RID2`.
                async fn limited()
                -> Result<(PushRole, RecordingSender, TempDir), Box<dyn std::error::Error>>
                {
                    let (_, push, sender, dir) =
                        limited_with([PushSendOutcome::Delivered; 16]).await?;
                    Ok((push, sender, dir))
                }

                /// As [`limited`], with the sender answering `outcomes` in
                /// order, and the service itself returned too.
                async fn limited_with(
                    outcomes: impl IntoIterator<Item = PushSendOutcome>,
                ) -> Result<
                    (PushService, PushRole, RecordingSender, TempDir),
                    Box<dyn std::error::Error>,
                > {
                    let sender = RecordingSender::new(PushPlatform::Apns, outcomes);
                    let (config, dir) = config(vec![recording(&sender)])?;
                    let service = PushService::start(config)?;
                    let push = PushRole::Enabled(service.clone());
                    register(&push, REGISTRANT_A, PushPlatform::Apns, b"t1", &[RID]).await?;
                    register(&push, REGISTRANT_A, PushPlatform::Apns, b"t2", &[RID2]).await?;
                    Ok((service, push, sender, dir))
                }

                /// Deregisters `token` from registrant A, as a signed
                /// `PushDeregistration` does.
                async fn deregister(service: &PushService, token: &[u8]) -> TestResult {
                    let key = crate::relay::push_store::PushRegistrationKey {
                        registrant: REGISTRANT_A.to_owned(),
                        platform: PushPlatform::Apns,
                        token: token.to_vec(),
                    };
                    let later = scp_clock::Clock::now_secs(&scp_clock::SystemClock) + 60;
                    assert!(service.config().store.deregister(&key, later).await?);
                    Ok(())
                }

                /// Publishes to `routing_id` and returns once its first wake
                /// went out, with the time it saw the wake: no earlier than
                /// the send that opened the token's window.
                async fn first_wake(
                    push: &PushRole,
                    sender: &RecordingSender,
                    routing_id: &RoutingId,
                ) -> Result<Instant, Box<dyn std::error::Error>> {
                    notify(push, routing_id);
                    wait_for_sends(sender, 1).await?;
                    Ok(Instant::now())
                }

                /// Two publishes 1 s apart to one token's routing ID make one
                /// send at once and a second when the window closes, not
                /// before.
                #[tokio::test(start_paused = true)]
                async fn second_publish_in_the_window_is_sent_when_it_closes() -> TestResult {
                    let (push, sender, _dir) = limited().await?;
                    let t0 = first_wake(&push, &sender, &RID).await?;
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    notify(&push, &RID);
                    tokio::time::sleep_until(t0 + Duration::from_millis(29_900)).await;
                    assert_eq!(sender.sent().await.len(), 1, "sent inside the window");
                    wait_for_sends(&sender, 2).await?;
                    assert!(
                        Instant::now() <= t0 + PUSH_WAKE_WINDOW + Duration::from_millis(100),
                        "the deferred wake went out {:?} after the first",
                        Instant::now() - t0
                    );
                    assert_eq!(sender.sent().await, vec![b"t1".to_vec(); 2]);
                    Ok(())
                }

                /// Five publishes inside one window make one send at once and
                /// exactly one deferred send.
                #[tokio::test(start_paused = true)]
                async fn five_publishes_in_one_window_make_one_deferred_send() -> TestResult {
                    let (push, sender, _dir) = limited().await?;
                    let t0 = first_wake(&push, &sender, &RID).await?;
                    for _ in 0..4 {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        notify(&push, &RID);
                    }
                    tokio::time::sleep_until(t0 + Duration::from_millis(29_900)).await;
                    assert_eq!(sender.sent().await.len(), 1, "sent inside the window");
                    tokio::time::sleep_until(t0 + Duration::from_secs(120)).await;
                    assert_eq!(sender.sent().await, vec![b"t1".to_vec(); 2]);
                    Ok(())
                }

                /// A publish 30 s after the first is sent at once.
                #[tokio::test(start_paused = true)]
                async fn publish_after_the_window_is_sent_at_once() -> TestResult {
                    let (push, sender, _dir) = limited().await?;
                    let t0 = first_wake(&push, &sender, &RID).await?;
                    tokio::time::sleep_until(t0 + PUSH_WAKE_WINDOW).await;
                    notify(&push, &RID);
                    wait_for_sends(&sender, 2).await?;
                    assert!(
                        Instant::now() <= t0 + PUSH_WAKE_WINDOW + Duration::from_millis(100),
                        "the second wake went out {:?} after the first",
                        Instant::now() - t0
                    );
                    Ok(())
                }

                /// One token's window does not hold another token's wake.
                #[tokio::test(start_paused = true)]
                async fn two_tokens_are_limited_independently() -> TestResult {
                    let (push, sender, _dir) = limited().await?;
                    let t0 = first_wake(&push, &sender, &RID).await?;
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    notify(&push, &RID2);
                    wait_for_sends(&sender, 2).await?;
                    assert!(
                        Instant::now() <= t0 + Duration::from_secs(2),
                        "t2 waited {:?} on t1's window",
                        Instant::now() - t0
                    );
                    assert_eq!(sender.sent().await, vec![b"t1".to_vec(), b"t2".to_vec()]);
                    Ok(())
                }

                /// A graceful stop sends the pending wake before the window
                /// closes, and `stop` returns only after it went out
                /// (§10.7.1 step 6, **Stop and crash**).
                #[tokio::test(start_paused = true)]
                async fn graceful_stop_sends_the_pending_wake() -> TestResult {
                    let (service, push, sender, _dir) =
                        limited_with([PushSendOutcome::Delivered; 16]).await?;
                    let t0 = first_wake(&push, &sender, &RID).await?;
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    notify(&push, &RID);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    assert_eq!(sender.sent().await.len(), 1, "sent inside the window");
                    service.stop().await?;
                    assert_eq!(
                        sender.sent().await,
                        vec![b"t1".to_vec(); 2],
                        "the pending wake was not sent on the stop"
                    );
                    assert!(
                        Instant::now() < t0 + PUSH_WAKE_WINDOW,
                        "the stop waited out the window"
                    );
                    // A second stop waits for nothing.
                    service.stop().await?;
                    Ok(())
                }

                /// A `Transient` push opens no window: after one at t0, a
                /// publish at t0 + 2 s is sent once the back-off (at most
                /// 1.25 s) has ended, not when a window would close at
                /// t0 + 30 s (§10.7.1 step 6, **Window**).
                #[tokio::test(start_paused = true)]
                async fn transient_push_opens_no_window() -> TestResult {
                    let (_service, push, sender, _dir) =
                        limited_with([PushSendOutcome::Transient, PushSendOutcome::Delivered])
                            .await?;
                    let t0 = first_wake(&push, &sender, &RID).await?;
                    tokio::time::sleep_until(t0 + Duration::from_secs(2)).await;
                    notify(&push, &RID);
                    wait_for_sends(&sender, 2).await?;
                    assert!(
                        Instant::now() <= t0 + Duration::from_millis(2_100),
                        "the wake after a transient failure went out {:?} after it",
                        Instant::now() - t0
                    );
                    Ok(())
                }

                /// A pending wake whose window closes while the drain backs
                /// off after a `Transient` push goes out when the back-off
                /// ends: `t1`'s window closes at t0 + 30 s, `t2` fails
                /// transiently at t0 + 29.5 s, and its 1 s to 1.25 s back-off
                /// ends after the close (§10.7.1 step 6, **Deferral**).
                #[tokio::test(start_paused = true)]
                async fn pending_wake_waits_out_the_back_off() -> TestResult {
                    let (_service, push, sender, _dir) = limited_with([
                        PushSendOutcome::Delivered,
                        PushSendOutcome::Transient,
                        PushSendOutcome::Delivered,
                    ])
                    .await?;
                    let t0 = first_wake(&push, &sender, &RID).await?;
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    notify(&push, &RID);
                    tokio::time::sleep_until(t0 + Duration::from_millis(29_500)).await;
                    notify(&push, &RID2);
                    wait_for_sends(&sender, 2).await?;
                    tokio::time::sleep_until(t0 + Duration::from_millis(30_300)).await;
                    assert_eq!(sender.sent().await.len(), 2, "sent during the back-off");
                    wait_for_sends(&sender, 3).await?;
                    let at = Instant::now() - t0;
                    assert!(
                        at >= Duration::from_millis(30_500) && at <= Duration::from_millis(30_900),
                        "the pending wake went out {at:?} after the first"
                    );
                    assert_eq!(
                        sender.sent().await,
                        vec![b"t1".to_vec(), b"t2".to_vec(), b"t1".to_vec()]
                    );
                    Ok(())
                }

                /// A wake held for a token that is deregistered before its
                /// window closes is not sent (§10.7.1 step 6, **Registration
                /// check**).
                #[tokio::test(start_paused = true)]
                async fn held_wake_for_a_deregistered_token_is_not_sent() -> TestResult {
                    let (service, push, sender, _dir) =
                        limited_with([PushSendOutcome::Delivered; 16]).await?;
                    first_wake(&push, &sender, &RID).await?;
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    notify(&push, &RID);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    deregister(&service, b"t1").await?;
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    assert_eq!(
                        sender.sent().await,
                        vec![b"t1".to_vec()],
                        "sent to a deregistered token"
                    );
                    // The stop has nothing left to send either.
                    service.stop().await?;
                    assert_eq!(sender.sent().await.len(), 1);
                    Ok(())
                }

                /// A held wake whose registration check fails in the store
                /// is not sent, even by a graceful stop: a token the store
                /// cannot vouch for may have been deregistered (§10.7.1
                /// step 6, **Registration check**).
                #[tokio::test]
                async fn held_wake_is_not_sent_when_the_store_check_fails() -> TestResult {
                    let (service, push, sender, dir) =
                        limited_with([PushSendOutcome::Delivered; 16]).await?;
                    first_wake(&push, &sender, &RID).await?;
                    notify(&push, &RID);
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    assert_eq!(sender.sent().await.len(), 1, "sent inside the window");
                    // Break the store under the drain: every check now fails.
                    rusqlite::Connection::open(dir.path().join("push.db"))?
                        .execute_batch("DROP TABLE push_registrations;")?;
                    service.stop().await?;
                    assert_eq!(
                        sender.sent().await,
                        vec![b"t1".to_vec()],
                        "sent a wake the store could not vouch for"
                    );
                    Ok(())
                }

                /// A job on the queue whose token is deregistered before the
                /// drain reads it is not sent; the job queued beside it for
                /// a token still registered is (§10.7.1 step 6,
                /// **Registration check**).
                #[tokio::test]
                async fn queued_job_for_a_deregistered_token_is_not_sent() -> TestResult {
                    let (service, push, sender, _dir) =
                        limited_with([PushSendOutcome::Delivered; 16]).await?;
                    let config = service.config().clone();
                    drop(push);
                    service.stop().await?;
                    let (tx, rx) = mpsc::channel(4);
                    for token in [b"t1", b"t2"] {
                        tx.send(PushJob {
                            platform: PushPlatform::Apns,
                            token: Zeroizing::new(token.to_vec()),
                            _ticket: Arc::new(()),
                        })
                        .await?;
                    }
                    deregister(&service, b"t1").await?;
                    drop(tx);
                    Drain {
                        senders: Arc::from(vec![recording(&sender)]),
                        index: 0,
                        store: config.store,
                        queued: Arc::default(),
                        logs: Arc::default(),
                        stop: CancellationToken::new(),
                        pending_resets: HashSet::new(),
                        limiter: PushWakeLimiter::new(PUSH_WAKE_WINDOW),
                    }
                    .drain(rx)
                    .await;
                    assert_eq!(sender.sent().await, vec![b"t2".to_vec()]);
                    Ok(())
                }
            }
        }
    }
}

/// A push service with a recording APNs sender over a fresh SQLite store,
/// for the transports' end-to-end wake tests.
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
    use crate::relay::push::{PushSendOutcome, PushSender, RecordingSender};
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
            let dir = tempfile::tempdir()?;
            let signer = P256SecretKey::from_scalar_bytes(&[0x5A; 32])?;
            let sender = RecordingSender::new(PushPlatform::Apns, [PushSendOutcome::Delivered; 64]);
            let service = PushService::start(PushServiceConfig {
                store: PushRegistrationStore::open_sqlite(&dir.path().join("push.db"))?,
                verifier: Arc::new(TestPushVerifier::new([(
                    DID::from(REGISTRANT),
                    signer.public_key(),
                )])),
                senders: Arc::from(vec![PushSender::Recording(sender.clone())]),
            })?;
            let push = PushRole::Enabled(service);
            let now = scp_clock::Clock::now_secs(&scp_clock::SystemClock);
            let mut msg = PushRegistration {
                registrant: DID::from(REGISTRANT),
                platform: PushPlatform::Apns,
                token: TOKEN.to_vec(),
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
}
