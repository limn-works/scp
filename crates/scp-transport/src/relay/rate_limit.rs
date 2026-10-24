//! Shared rate limiting and connection tracking across all transport handlers.
//!
//! All transports share a single publish rate limiter and connection tracker
//! so that a client cannot bypass limits by connecting through multiple
//! transports (spec §10.14.3, ADR-037 AC3).
//!
//! The subscribe rate limiter is per-connection (not shared) per ADR-004.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

// ---------------------------------------------------------------------------
// Token bucket (shared algorithm)
// ---------------------------------------------------------------------------

/// Single token-bucket implementation used by both publish and subscribe limiters.
///
/// Tokens are replenished lazily on each `check()` call rather than via a
/// background task. The bucket capacity equals `rate_per_second` to allow
/// short bursts up to the per-second rate.
#[derive(Debug)]
pub(crate) struct TokenBucket {
    /// Remaining tokens in this bucket.
    tokens: f64,
    /// Last time tokens were refilled.
    last_refill: Instant,
    /// Tokens replenished per second.
    rate_per_second: f64,
    /// Maximum bucket capacity.
    capacity: f64,
}

impl TokenBucket {
    /// Creates a new token bucket with the given rate and capacity, starting full.
    pub(crate) fn new(rate_per_second: f64, capacity: f64) -> Self {
        Self {
            tokens: capacity,
            last_refill: Instant::now(),
            rate_per_second,
            capacity,
        }
    }

    /// Checks whether a single token is available. Returns `true` if the
    /// operation should proceed, `false` if rate-limited.
    pub(crate) fn check(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = elapsed
            .mul_add(self.rate_per_second, self.tokens)
            .min(self.capacity);
        self.last_refill = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Publish rate limiter (shared across transports)
// ---------------------------------------------------------------------------

/// Shared rate limiter state mapping IP addresses to their token buckets.
///
/// Shared across WebSocket, QUIC, and UDP/DTLS handlers so that one IP
/// cannot exceed its publish rate by distributing requests across transports.
///
/// The rate is fixed at construction time to ensure consistent behavior
/// regardless of which transport checks first.
#[derive(Clone)]
pub struct PublishRateLimiter {
    inner: Arc<tokio::sync::Mutex<HashMap<IpAddr, TokenBucket>>>,
    /// Fixed rate per second (set once, used by all transports).
    rate: u32,
}

impl PublishRateLimiter {
    /// Creates a new empty publish rate limiter with the given per-IP rate.
    #[must_use]
    pub fn new(rate_per_second: u32) -> Self {
        Self {
            inner: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            rate: rate_per_second,
        }
    }

    /// Checks whether a publish is allowed under the per-IP token-bucket rate
    /// limit. Returns `true` if the publish should proceed, `false` if rate-limited.
    #[allow(clippy::significant_drop_tightening)]
    pub async fn check(&self, ip: IpAddr) -> bool {
        let mut limiter = self.inner.lock().await;
        let rate = f64::from(self.rate);
        let bucket = limiter
            .entry(ip)
            .or_insert_with(|| TokenBucket::new(rate, rate));
        bucket.check()
    }

    /// Runs the background cleanup task that periodically evicts stale buckets.
    ///
    /// Buckets that haven't been refilled within `cutoff` are removed to
    /// prevent unbounded `HashMap` growth. Run this once for the shared
    /// `PublishRateLimiter` instance.
    pub async fn cleanup_loop(
        &self,
        interval: Duration,
        cutoff: Duration,
        token: CancellationToken,
    ) {
        let mut ticker = tokio::time::interval(interval);

        loop {
            tokio::select! {
                biased;
                () = token.cancelled() => break,
                _ = ticker.tick() => {}
            }

            let now = Instant::now();
            let mut limiter = self.inner.lock().await;
            let before = limiter.len();
            limiter.retain(|_ip, bucket| now.duration_since(bucket.last_refill) < cutoff);
            let evicted = before - limiter.len();
            if evicted > 0 {
                tracing::debug!(
                    evicted,
                    remaining = limiter.len(),
                    "rate limiter cleanup complete"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Subscribe rate limiter (per-connection, NOT shared)
// ---------------------------------------------------------------------------

/// Per-connection token-bucket rate limiter for subscribe operations.
///
/// Unlike the publish rate limiter (which is per-IP and shared across
/// connections), the subscribe rate limiter is per-connection per ADR-004.
/// Each connection owns its own bucket — no shared state required.
pub struct SubscribeRateLimiter {
    bucket: TokenBucket,
}

impl SubscribeRateLimiter {
    /// Creates a new subscribe rate limiter with the given per-minute rate.
    #[must_use]
    pub fn new(rate_per_minute: u32) -> Self {
        let capacity = f64::from(rate_per_minute);
        Self {
            bucket: TokenBucket::new(capacity / 60.0, capacity),
        }
    }

    /// Checks whether a subscribe operation is allowed. Returns `true` if the
    /// operation should proceed, `false` if rate-limited.
    pub fn check(&mut self) -> bool {
        self.bucket.check()
    }
}

// ---------------------------------------------------------------------------
// Connection tracker (shared across transports)
// ---------------------------------------------------------------------------

/// Error returned when a connection is rejected due to per-IP limits.
#[derive(Debug)]
pub struct ConnectionLimitExceeded {
    /// The IP address that hit the limit.
    pub ip: IpAddr,
    /// Current connection count for this IP.
    pub current: usize,
    /// Maximum allowed per IP.
    pub max: usize,
}

impl std::fmt::Display for ConnectionLimitExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "connection limit exceeded for {}: {}/{} connections",
            self.ip, self.current, self.max
        )
    }
}

/// Per-IP connection counter, shared across all transport listeners.
///
/// Ensures a single IP cannot hold more than `max_per_ip` connections across
/// all transports combined (WebSocket + QUIC + UDP/DTLS).
pub type ConnectionTracker = Arc<RwLock<HashMap<IpAddr, usize>>>;

/// Creates a new empty connection tracker.
#[must_use]
pub fn new_connection_tracker() -> ConnectionTracker {
    Arc::new(RwLock::new(HashMap::new()))
}

/// Atomically checks the per-IP limit (and optionally the total connection
/// limit) and registers the connection.
///
/// Returns `Ok(())` if the connection is allowed, or a
/// [`ConnectionLimitExceeded`] error if the per-IP budget or the total
/// connection budget is exhausted. Both checks and the increment happen
/// under a single write lock to prevent TOCTOU races.
///
/// Pass `Some(max_total)` to enforce a global connection cap alongside the
/// per-IP cap. Pass `None` to skip the total check (the caller may enforce
/// it separately or not at all).
///
/// # Errors
///
/// Returns [`ConnectionLimitExceeded`] if the per-IP or total connection
/// limit would be exceeded.
pub async fn register_connection(
    tracker: &ConnectionTracker,
    ip: IpAddr,
    max_per_ip: usize,
    max_total: Option<usize>,
) -> Result<(), ConnectionLimitExceeded> {
    let mut t = tracker.write().await;
    register_connection_inner(&mut t, ip, max_per_ip, max_total)
}

/// Inner implementation: operates on an already-locked tracker.
fn register_connection_inner(
    t: &mut HashMap<IpAddr, usize>,
    ip: IpAddr,
    max_per_ip: usize,
    max_total: Option<usize>,
) -> Result<(), ConnectionLimitExceeded> {
    // Check total connection limit.
    if let Some(limit) = max_total {
        let total: usize = t.values().sum();
        if total >= limit {
            return Err(ConnectionLimitExceeded {
                ip,
                current: total,
                max: limit,
            });
        }
    }

    let count = t.entry(ip).or_insert(0);
    if *count >= max_per_ip {
        Err(ConnectionLimitExceeded {
            ip,
            current: *count,
            max: max_per_ip,
        })
    } else {
        *count += 1;
        Ok(())
    }
}

/// Decrements the per-IP connection count. Removes the entry if it reaches 0.
pub async fn unregister_connection(tracker: &ConnectionTracker, ip: IpAddr) {
    let mut t = tracker.write().await;
    if let Some(count) = t.get_mut(&ip) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            t.remove(&ip);
        }
    }
}

// ---------------------------------------------------------------------------
// Push wake limiter (spec §10.7.1 step 6; PUSH-009)
// ---------------------------------------------------------------------------

#[cfg(feature = "push-store")]
pub(crate) use push_wake::{PUSH_WAKE_WINDOW, PushWakeLimiter, WakeAdmission};

/// The per-token push rate limit of spec §10.7.1 step 6: at most one push
/// per [`PUSH_WAKE_WINDOW`] per device token, with a wake inside the window
/// deferred to the window's close instead of dropped.
///
/// The limiter is a plain data structure that reads no clock: its caller
/// passes `now` and drives it from one task (the push dispatcher's drain for
/// one platform), sending each wake [`PushWakeLimiter::admit`] or
/// [`PushWakeLimiter::take_due`] hands back and sleeping until
/// [`PushWakeLimiter::next_due`] in between. It holds at most one pending
/// wake per token and refuses none, so it never drops a wake; a graceful stop
/// sends what [`PushWakeLimiter::take_pending`] returns (§10.7.1 step 6,
/// **Stop and crash**). Its state lives in memory only, so a relay restart
/// clears it (§10.7.1 step 6, **State**).
#[cfg(feature = "push-store")]
mod push_wake {
    use std::collections::{HashMap, VecDeque};
    use std::time::Duration;

    use tokio::time::Instant;
    use zeroize::{Zeroize, Zeroizing};

    /// The shortest time between two pushes to one device token (§10.7.1
    /// step 6).
    pub const PUSH_WAKE_WINDOW: Duration = Duration::from_secs(30);

    /// A SHA-256 hash that identifies one token, so the limiter holds no
    /// token bytes except inside a pending wake.
    pub type WakeKey = [u8; 32];

    /// What [`PushWakeLimiter::admit`] did with a wake.
    #[derive(Debug)]
    pub enum WakeAdmission<W: Zeroize> {
        /// The token had no push inside the window, so the caller sends this
        /// wake now; the token's window starts at the `now` passed in.
        SendNow(Zeroizing<W>),
        /// The token had a push inside the window, so the limiter holds this
        /// wake as the token's one pending wake until the window closes.
        Deferred,
        /// The token already had a pending wake, which stands for this one
        /// too, so the limiter zeroized and dropped this one.
        Joined,
    }

    /// One token's window: when its last push went out, and the wake held
    /// for the window's close, if any.
    struct Entry<W: Zeroize> {
        sent_at: Instant,
        pending: Option<Zeroizing<W>>,
    }

    /// The per-token limiter. `W` is the wake the caller sends, which holds
    /// the token; the limiter holds a pending `W` in [`Zeroizing`], so every
    /// pending wake it drops (joined, or with the limiter itself when its task
    /// ends without a graceful stop) is zeroized first.
    pub struct PushWakeLimiter<W: Zeroize> {
        window: Duration,
        entries: HashMap<WakeKey, Entry<W>>,
        /// One record per window started, oldest first: the token's key and
        /// the window's `sent_at`. A record whose `sent_at` differs from its
        /// entry's is stale (`admit` started a newer window after this one
        /// closed) and `take_due` discards it.
        windows: VecDeque<(WakeKey, Instant)>,
        /// Entries holding a pending wake.
        pending: usize,
    }

    impl<W: Zeroize> std::fmt::Debug for PushWakeLimiter<W> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("PushWakeLimiter")
                .field("window", &self.window)
                .field("entries", &self.entries.len())
                .field("pending", &self.pending)
                .finish_non_exhaustive()
        }
    }

    impl<W: Zeroize> PushWakeLimiter<W> {
        /// A limiter with no entries, allowing one push per `window` per
        /// token.
        pub fn new(window: Duration) -> Self {
            Self {
                window,
                entries: HashMap::new(),
                windows: VecDeque::new(),
                pending: 0,
            }
        }

        /// When the window that started at `sent_at` closes; `None` when the
        /// clock cannot represent that instant, so the window never closes
        /// before the limiter is dropped.
        fn closes(&self, sent_at: Instant) -> Option<Instant> {
            sent_at.checked_add(self.window)
        }

        fn open_at(&self, sent_at: Instant, now: Instant) -> bool {
            self.closes(sent_at).is_none_or(|closes| now < closes)
        }

        /// A window start no earlier than the newest record, so the records
        /// stay in order even when a caller passes an earlier `now`.
        fn start(&self, now: Instant) -> Instant {
            self.windows
                .back()
                .map_or(now, |&(_, newest)| newest.max(now))
        }

        /// Decides what happens to `wake`, a wake for the token `key`
        /// identifies, at `now`.
        pub fn admit(
            &mut self,
            key: WakeKey,
            wake: Zeroizing<W>,
            now: Instant,
        ) -> WakeAdmission<W> {
            let start = self.start(now);
            let Some(entry) = self.entries.get(&key) else {
                self.entries.insert(
                    key,
                    Entry {
                        sent_at: start,
                        pending: None,
                    },
                );
                self.windows.push_back((key, start));
                return WakeAdmission::SendNow(wake);
            };
            if entry.pending.is_some() {
                // The pending wake goes out when the window closes, or at
                // the next `take_due` when it closed already.
                return WakeAdmission::Joined;
            }
            if !self.open_at(entry.sent_at, now) {
                // The window closed and nothing is pending: start a new one.
                // The old record is now stale.
                if let Some(entry) = self.entries.get_mut(&key) {
                    entry.sent_at = start;
                }
                self.windows.push_back((key, start));
                return WakeAdmission::SendNow(wake);
            }
            if let Some(entry) = self.entries.get_mut(&key) {
                entry.pending = Some(wake);
                self.pending = self.pending.saturating_add(1);
            }
            WakeAdmission::Deferred
        }

        /// When the oldest window closes, so the caller knows when to call
        /// [`Self::take_due`] next; `None` when no window is open.
        pub fn next_due(&self) -> Option<Instant> {
            self.windows
                .front()
                .and_then(|&(_, sent_at)| self.closes(sent_at))
        }

        /// Closes every window that closed by `now`. Returns the first
        /// pending wake among them, for the caller to send now, and starts
        /// that token's next window at `now`; forgets every token whose
        /// window closed with no wake pending. `None` when no closed window
        /// holds a pending wake.
        pub fn take_due(&mut self, now: Instant) -> Option<Zeroizing<W>> {
            while let Some(&(key, sent_at)) = self.windows.front() {
                if self.open_at(sent_at, now) {
                    return None;
                }
                self.windows.pop_front();
                let start = self.start(now);
                let Some(entry) = self.entries.get_mut(&key) else {
                    continue;
                };
                if entry.sent_at != sent_at {
                    // Stale: a newer record for this token follows.
                    continue;
                }
                if let Some(wake) = entry.pending.take() {
                    entry.sent_at = start;
                    self.windows.push_back((key, start));
                    self.pending = self.pending.saturating_sub(1);
                    return Some(wake);
                }
                self.entries.remove(&key);
            }
            None
        }

        /// Forgets `key`'s window unless the token holds a pending wake, for a
        /// push that did not reach the push service's answer: a transient
        /// failure, or a wake discarded before its send. Such a push opens no
        /// window (§10.7.1 step 6, **Window**), so the token's next wake goes
        /// out at once. The window's record goes stale, and `take_due`
        /// discards it.
        pub fn release(&mut self, key: &WakeKey) {
            if self.entries.get(key).is_some_and(|e| e.pending.is_none()) {
                self.entries.remove(key);
            }
        }

        /// Takes every pending wake, whether or not its window closed, and
        /// forgets every token: what a graceful stop sends (§10.7.1 step 6,
        /// **Stop and crash**).
        pub fn take_pending(&mut self) -> Vec<Zeroizing<W>> {
            self.windows.clear();
            self.pending = 0;
            self.entries
                .drain()
                .filter_map(|(_, entry)| entry.pending)
                .collect()
        }

        /// Tokens the limiter holds an entry for.
        #[cfg(test)]
        pub fn entries(&self) -> usize {
            self.entries.len()
        }

        /// Pending wakes the limiter holds.
        #[cfg(test)]
        pub const fn pending(&self) -> usize {
            self.pending
        }
    }

    #[cfg(test)]
    mod tests {
        use std::sync::{Arc, Mutex, PoisonError};

        use super::*;

        const WINDOW: Duration = PUSH_WAKE_WINDOW;

        /// A wake whose token sits in a buffer the test reads after the
        /// limiter drops the wake, so the test sees whether it was zeroized.
        struct Probe(Arc<Mutex<Vec<u8>>>);

        impl Zeroize for Probe {
            fn zeroize(&mut self) {
                self.0
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .as_mut_slice()
                    .zeroize();
            }
        }

        fn probe(token: &[u8]) -> (Zeroizing<Probe>, Arc<Mutex<Vec<u8>>>) {
            let buffer = Arc::new(Mutex::new(token.to_vec()));
            (Zeroizing::new(Probe(Arc::clone(&buffer))), buffer)
        }

        fn bytes(buffer: &Arc<Mutex<Vec<u8>>>) -> Vec<u8> {
            buffer
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }

        fn limiter() -> PushWakeLimiter<Probe> {
            PushWakeLimiter::new(WINDOW)
        }

        const fn key(n: u8) -> WakeKey {
            [n; 32]
        }

        fn secs(n: u64) -> Duration {
            Duration::from_secs(n)
        }

        /// The first wake for a token goes out at once; a wake 1 s later is
        /// held, and goes out when the 30 s window closes, not before.
        #[test]
        fn second_wake_inside_the_window_is_deferred_to_its_close() {
            let t0 = Instant::now();
            let mut limiter = limiter();
            assert!(matches!(
                limiter.admit(key(1), probe(b"t1").0, t0),
                WakeAdmission::SendNow(_)
            ));
            assert!(matches!(
                limiter.admit(key(1), probe(b"t1").0, t0 + secs(1)),
                WakeAdmission::Deferred
            ));
            assert_eq!(limiter.next_due(), Some(t0 + WINDOW));
            assert!(limiter.take_due(t0 + secs(29)).is_none());
            assert!(limiter.take_due(t0 + WINDOW).is_some());
            assert!(limiter.take_due(t0 + WINDOW).is_none());
        }

        /// Five wakes inside one window make one immediate send and one
        /// deferred send; the other three join the pending one.
        #[test]
        fn five_wakes_in_one_window_defer_one() {
            let t0 = Instant::now();
            let mut limiter = limiter();
            let mut sent = 0;
            for i in 0..5 {
                let admission = limiter.admit(key(1), probe(b"t1").0, t0 + secs(i));
                if matches!(admission, WakeAdmission::SendNow(_)) {
                    sent += 1;
                }
            }
            assert_eq!(sent, 1);
            assert_eq!(limiter.pending(), 1);
            let mut deferred = 0;
            while limiter.take_due(t0 + secs(120)).is_some() {
                deferred += 1;
            }
            assert_eq!(deferred, 1);
        }

        /// A wake exactly 30 s after the first goes out at once, even when
        /// no `take_due` ran in between to close the first window.
        #[test]
        fn wake_at_the_window_close_goes_out_at_once() {
            let t0 = Instant::now();
            let mut limiter = limiter();
            assert!(matches!(
                limiter.admit(key(1), probe(b"t1").0, t0),
                WakeAdmission::SendNow(_)
            ));
            assert!(matches!(
                limiter.admit(key(1), probe(b"t1").0, t0 + WINDOW),
                WakeAdmission::SendNow(_)
            ));
            // The first window's record is stale and yields nothing.
            assert!(limiter.take_due(t0 + WINDOW).is_none());
            assert_eq!(limiter.entries(), 1);
            assert!(matches!(
                limiter.admit(key(1), probe(b"t1").0, t0 + WINDOW + secs(1)),
                WakeAdmission::Deferred
            ));
        }

        /// One token's window does not hold another token's wake.
        #[test]
        fn tokens_are_limited_independently() {
            let t0 = Instant::now();
            let mut limiter = limiter();
            assert!(matches!(
                limiter.admit(key(1), probe(b"t1").0, t0),
                WakeAdmission::SendNow(_)
            ));
            assert!(matches!(
                limiter.admit(key(2), probe(b"t2").0, t0 + secs(1)),
                WakeAdmission::SendNow(_)
            ));
        }

        /// Entries last one window: after it closes, a limiter that held 100
        /// tokens holds none, and a token whose deferred wake went out holds
        /// one entry until its second window closes.
        #[test]
        fn entries_are_pruned_when_their_window_closes() {
            let t0 = Instant::now();
            let mut limiter = limiter();
            for n in 0..100 {
                let _ = limiter.admit(key(n), probe(b"t").0, t0);
            }
            let _ = limiter.admit(key(7), probe(b"t").0, t0 + secs(1));
            assert_eq!(limiter.entries(), 100);
            assert!(limiter.take_due(t0 + WINDOW).is_some());
            assert!(limiter.take_due(t0 + WINDOW).is_none());
            assert_eq!(limiter.entries(), 1, "only the re-armed token is left");
            assert!(limiter.take_due(t0 + WINDOW + WINDOW).is_none());
            assert_eq!(limiter.entries(), 0);
            assert_eq!(limiter.next_due(), None);
        }

        /// The limiter holds a pending wake for every token whose window is
        /// open, however many there are: none is refused.
        #[test]
        fn every_token_holds_a_pending_wake() {
            let t0 = Instant::now();
            let mut limiter = limiter();
            for n in 0..=255 {
                let _ = limiter.admit(key(n), probe(b"t").0, t0);
            }
            for n in 0..=255 {
                assert!(
                    matches!(
                        limiter.admit(key(n), probe(b"t").0, t0 + secs(1)),
                        WakeAdmission::Deferred
                    ),
                    "token {n} refused"
                );
            }
            assert_eq!(limiter.pending(), 256);
        }

        /// A released window lets the token's next wake out at once, and
        /// its record is discarded when it would have closed.
        #[test]
        fn released_window_sends_the_next_wake_at_once() {
            let t0 = Instant::now();
            let mut limiter = limiter();
            let _ = limiter.admit(key(1), probe(b"t1").0, t0);
            limiter.release(&key(1));
            assert_eq!(limiter.entries(), 0);
            assert!(matches!(
                limiter.admit(key(1), probe(b"t1").0, t0 + secs(2)),
                WakeAdmission::SendNow(_)
            ));
            assert!(matches!(
                limiter.admit(key(1), probe(b"t1").0, t0 + secs(3)),
                WakeAdmission::Deferred
            ));
            // The released record closes first and is stale.
            assert!(limiter.take_due(t0 + WINDOW).is_none());
            assert!(limiter.take_due(t0 + secs(32)).is_some());
        }

        /// Releasing a token that holds a pending wake keeps its window, so
        /// the pending wake still waits for the window's close.
        #[test]
        fn release_keeps_a_window_with_a_pending_wake() {
            let t0 = Instant::now();
            let mut limiter = limiter();
            let _ = limiter.admit(key(1), probe(b"t1").0, t0);
            let _ = limiter.admit(key(1), probe(b"t1").0, t0 + secs(1));
            limiter.release(&key(1));
            assert_eq!(limiter.pending(), 1);
            assert!(limiter.take_due(t0 + secs(29)).is_none());
            assert!(limiter.take_due(t0 + WINDOW).is_some());
        }

        /// `take_pending` returns every pending wake before its window
        /// closes, holding its token intact for the send, and leaves the
        /// limiter empty.
        #[test]
        fn take_pending_returns_every_pending_wake() {
            let t0 = Instant::now();
            let mut limiter = limiter();
            for n in 1..=3 {
                let _ = limiter.admit(key(n), probe(b"t").0, t0);
            }
            let (held, buffer) = probe(b"held");
            let _ = limiter.admit(key(1), held, t0 + secs(1));
            let _ = limiter.admit(key(2), probe(b"t").0, t0 + secs(1));
            let taken = limiter.take_pending();
            assert_eq!(taken.len(), 2);
            assert_eq!(bytes(&buffer), b"held".to_vec());
            assert_eq!(limiter.entries(), 0);
            assert_eq!(limiter.pending(), 0);
            assert_eq!(limiter.next_due(), None);
            drop(taken);
            assert_eq!(bytes(&buffer), vec![0; 4]);
        }

        /// A wake that joins a pending one is zeroized.
        #[test]
        fn joined_wake_is_zeroized() {
            let t0 = Instant::now();
            let mut limiter = limiter();
            let _ = limiter.admit(key(1), probe(b"t").0, t0);
            let _ = limiter.admit(key(1), probe(b"t").0, t0 + secs(1));
            let (joined, buffer) = probe(b"joined");
            assert!(matches!(
                limiter.admit(key(1), joined, t0 + secs(2)),
                WakeAdmission::Joined
            ));
            assert_eq!(bytes(&buffer), vec![0; 6]);
        }

        /// Dropping the limiter, as a drain whose task ends without a
        /// graceful stop does, drops its pending wake unsent and zeroizes
        /// the token it held.
        #[test]
        fn dropping_the_limiter_zeroizes_its_pending_wake() {
            let t0 = Instant::now();
            let mut limiter = limiter();
            let _ = limiter.admit(key(1), probe(b"t1").0, t0);
            let (pending, buffer) = probe(b"pending-token");
            assert!(matches!(
                limiter.admit(key(1), pending, t0 + secs(1)),
                WakeAdmission::Deferred
            ));
            assert_eq!(bytes(&buffer), b"pending-token".to_vec());
            drop(limiter);
            assert_eq!(bytes(&buffer), vec![0; 13]);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn shared_publish_rate_limiter_limits_across_callers() {
        let limiter = PublishRateLimiter::new(2);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Rate of 2 per second — start with 2 tokens.
        assert!(limiter.check(ip).await);
        assert!(limiter.check(ip).await);
        // Budget exhausted — third call should fail.
        assert!(!limiter.check(ip).await);
    }

    #[tokio::test]
    async fn shared_connection_tracker_cross_transport() {
        let tracker = new_connection_tracker();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let max_per_ip = 3;

        // Register 3 connections (simulating WS, QUIC, UDP each registering one).
        assert!(
            register_connection(&tracker, ip, max_per_ip, None)
                .await
                .is_ok()
        );
        assert!(
            register_connection(&tracker, ip, max_per_ip, None)
                .await
                .is_ok()
        );
        assert!(
            register_connection(&tracker, ip, max_per_ip, None)
                .await
                .is_ok()
        );

        // 4th connection from same IP should be rejected regardless of transport.
        let err = register_connection(&tracker, ip, max_per_ip, None)
            .await
            .unwrap_err();
        assert_eq!(err.current, 3);
        assert_eq!(err.max, 3);

        // Unregister one — now another should succeed.
        unregister_connection(&tracker, ip).await;
        assert!(
            register_connection(&tracker, ip, max_per_ip, None)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn subscribe_rate_limiter_basic() {
        let mut limiter = SubscribeRateLimiter::new(60); // 60/min = 1/sec
        // Should have full capacity initially.
        for _ in 0..60 {
            assert!(limiter.check());
        }
        // Budget exhausted.
        assert!(!limiter.check());
    }

    #[tokio::test]
    async fn unregister_removes_entry_at_zero() {
        let tracker = new_connection_tracker();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        register_connection(&tracker, ip, 10, None).await.unwrap();
        unregister_connection(&tracker, ip).await;

        assert!(!tracker.read().await.contains_key(&ip));
    }
}
