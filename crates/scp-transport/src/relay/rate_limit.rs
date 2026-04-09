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
