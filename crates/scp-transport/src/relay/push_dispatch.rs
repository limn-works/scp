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
//!   platform. After a `Transient` outcome a drain backs off before its next
//!   send to that service. Each drain applies the outcome to the
//!   registration store:
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
//! # Bounds
//!
//! The intake and every platform queue hold at most `PUSH_QUEUE_CAPACITY`
//! entries. A wake that does not fit is dropped, and the publish still
//! succeeds (PUSH-008 AC2): a wake is advisory, and a device whose wake was
//! dropped pulls on its next wake or connection (§10.7, as the PUSH-009 rate
//! limit also relies on). The intake holds each routing ID at most once, and
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
    use std::collections::{HashMap, HashSet};
    use std::fmt;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
    use std::time::{Duration, Instant};

    use scp_protocol::discovery::push::PushPlatform;
    use sha2::{Digest, Sha256};
    use tokio::sync::mpsc;
    use tokio_util::sync::{CancellationToken, DropGuard};
    use zeroize::Zeroizing;

    use super::super::push::{PushSendOutcome, PushSender};
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
            if !queued.insert(key) {
                // Already on the queue; that job wakes the device.
                return;
            }
            let job = PushJob {
                platform,
                token,
                ticket: Arc::clone(ticket),
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

    /// One platform's drain: jobs in, sends out, outcomes into the store.
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
    }

    impl Drain {
        async fn run(mut self, mut rx: mpsc::Receiver<PushJob>) {
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
                let outcome = tokio::select! {
                    biased;
                    () = self.stop.cancelled() => return,
                    outcome = sender.send_registered(&job.token) => outcome,
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
