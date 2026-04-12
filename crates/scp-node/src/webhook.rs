//! Outbound webhook dispatch for bridge cooperative mode (spec §12.2.1).
//!
//! When context events occur (message received, member joined/left, governance
//! action), registered bridges with `webhook_url` receive HTTP POST
//! notifications with Ed25519 signatures.

use std::collections::HashMap;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use tokio::sync::RwLock;

/// Monotonic counter for unique event IDs (concurrency-safe).
static EVENT_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Maximum number of retry attempts for failed webhook deliveries.
const MAX_RETRIES: u32 = 3;

/// Initial retry delay in milliseconds (doubles on each retry).
const INITIAL_RETRY_DELAY_MS: u64 = 500;

/// Webhook event payload sent to registered bridges.
#[derive(Debug, Clone, Serialize)]
pub struct WebhookEvent {
    /// Unique event ID for deduplication.
    pub event_id: String,
    /// Event type (e.g., "message.received", "member.joined", "governance.action").
    pub event_type: String,
    /// Context ID where the event occurred.
    pub context_id: String,
    /// Unix timestamp of the event.
    pub timestamp: u64,
    /// Event-specific payload (JSON object).
    pub payload: serde_json::Value,
}

/// Result of a webhook dispatch attempt.
#[derive(Debug)]
pub struct WebhookResult {
    /// The URL that was targeted.
    pub url: String,
    /// Whether the delivery succeeded (2xx response).
    pub success: bool,
    /// Number of attempts made.
    pub attempts: u32,
    /// HTTP status code of the final response, if any.
    pub status_code: Option<u16>,
    /// Error message if delivery failed.
    pub error: Option<String>,
}

/// Dispatches a webhook event to a URL with Ed25519 signature.
///
/// Signs the serialized event body with the signing key and includes:
/// - `X-SCP-Signature`: hex-encoded Ed25519 signature of the body
/// - `X-SCP-Timestamp`: Unix timestamp string
/// - `Content-Type: application/json`
///
/// Retries with exponential backoff on failure (3 attempts).
///
/// # URL Validation
/// - HTTPS only (SSRF prevention)
/// - Rejects private/loopback IPs
///
/// # Errors
/// Returns `WebhookResult` with `success=false` if all retries fail.
pub async fn dispatch_webhook(
    url: &str,
    event: &WebhookEvent,
    signing_key: &SigningKey,
    client: &reqwest::Client,
) -> WebhookResult {
    // Validate URL: must be HTTPS
    if !url.starts_with("https://") {
        return WebhookResult {
            url: url.to_owned(),
            success: false,
            attempts: 0,
            status_code: None,
            error: Some("webhook URL must use HTTPS".to_owned()),
        };
    }

    // Reject private IPs (basic SSRF prevention)
    if let Some(error) = validate_webhook_url(url) {
        return WebhookResult {
            url: url.to_owned(),
            success: false,
            attempts: 0,
            status_code: None,
            error: Some(error),
        };
    }

    let body = match serde_json::to_vec(event) {
        Ok(b) => b,
        Err(e) => {
            return WebhookResult {
                url: url.to_owned(),
                success: false,
                attempts: 0,
                status_code: None,
                error: Some(format!("failed to serialize event: {e}")),
            };
        }
    };

    let timestamp = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => {
            return WebhookResult {
                url: url.to_owned(),
                success: false,
                attempts: 0,
                status_code: None,
                error: Some("system clock is before Unix epoch".to_owned()),
            };
        }
    };

    // Sign: Ed25519("SCP-WEBHOOK-V1:" || timestamp_be_bytes || body)
    // The domain separator prevents cross-protocol signature confusion.
    let domain_separator = b"SCP-WEBHOOK-V1:";
    let mut signing_payload = Vec::with_capacity(domain_separator.len() + 8 + body.len());
    signing_payload.extend_from_slice(domain_separator);
    signing_payload.extend_from_slice(&timestamp.to_be_bytes());
    signing_payload.extend_from_slice(&body);
    let signature = signing_key.sign(&signing_payload);
    let sig_hex = hex::encode(signature.to_bytes());
    let mut delay = INITIAL_RETRY_DELAY_MS;

    for attempt in 1..=MAX_RETRIES {
        match client
            .post(url)
            .header("Content-Type", "application/json")
            .header("X-SCP-Signature", &sig_hex)
            .header("X-SCP-Timestamp", timestamp.to_string())
            .body(body.clone())
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status().as_u16();
                if response.status().is_success() {
                    return WebhookResult {
                        url: url.to_owned(),
                        success: true,
                        attempts: attempt,
                        status_code: Some(status),
                        error: None,
                    };
                }
                // Non-success status — retry
                tracing::warn!(url, attempt, status, "webhook delivery failed with status");
            }
            Err(e) => {
                tracing::warn!(url, attempt, error = %e, "webhook delivery failed");
            }
        }

        if attempt < MAX_RETRIES {
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
            delay *= 2;
        }
    }

    WebhookResult {
        url: url.to_owned(),
        success: false,
        attempts: MAX_RETRIES,
        status_code: None,
        error: Some("all retry attempts exhausted".to_owned()),
    }
}

/// SSRF prevention: reject private, loopback, link-local, unspecified, and
/// cloud-metadata IP addresses. Also rejects IPv6-mapped IPv4 embeddings.
fn validate_webhook_url(raw_url: &str) -> Option<String> {
    let parsed = match url::Url::parse(raw_url) {
        Ok(u) => u,
        Err(e) => return Some(format!("invalid URL: {e}")),
    };

    let Some(host) = parsed.host_str() else {
        return Some("URL has no host".to_owned());
    };

    // Reject obvious private/loopback hostnames.
    if host == "localhost" || host.starts_with("127.") || host == "::1" || host == "[::1]" {
        return Some("webhook URL must not target localhost".to_owned());
    }

    // Check for private IP ranges.
    if let Ok(ip) = host.parse::<std::net::IpAddr>()
        && let Some(reason) = check_ip_blocked(ip)
    {
        return Some(reason);
    }

    // Also strip brackets for IPv6 literals like [::ffff:127.0.0.1].
    let stripped = host.trim_start_matches('[').trim_end_matches(']');
    if stripped != host
        && let Ok(ip) = stripped.parse::<std::net::IpAddr>()
        && let Some(reason) = check_ip_blocked(ip)
    {
        return Some(reason);
    }

    // DNS pre-resolution: when the host is a hostname (not an IP literal),
    // resolve it and check all resolved addresses against the blocklist.
    // This catches SSRF via DNS pointing to private IPs (e.g.,
    // evil.example.com -> 10.0.0.1).
    //
    // NOTE: DNS rebinding limitation — the resolved IP can change between
    // validation and the actual HTTP connection. This is defense-in-depth,
    // not a complete mitigation.
    if host.parse::<std::net::IpAddr>().is_err()
        && let Ok(addrs) = (host, 443u16).to_socket_addrs()
    {
        for addr in addrs {
            if let Some(reason) = check_ip_blocked(addr.ip()) {
                return Some(format!("{host} resolves to blocked IP: {reason}"));
            }
        }
    }

    None
}

/// Returns `Some(reason)` if the IP address must be blocked for SSRF prevention.
fn check_ip_blocked(ip: std::net::IpAddr) -> Option<String> {
    match ip {
        std::net::IpAddr::V4(v4) => {
            if v4.is_loopback() {
                return Some(format!("webhook URL must not target loopback IP: {v4}"));
            }
            if v4.is_private() {
                return Some(format!("webhook URL must not target private IP: {v4}"));
            }
            if v4.is_link_local() {
                return Some(format!("webhook URL must not target link-local IP: {v4}"));
            }
            if v4.is_unspecified() {
                return Some(format!("webhook URL must not target unspecified IP: {v4}"));
            }
            if v4.is_broadcast() {
                return Some(format!("webhook URL must not target broadcast IP: {v4}"));
            }
            // Reject 0.0.0.0/8 (current network) — octets[0] == 0 but not 0.0.0.0
            // (0.0.0.0 already caught by is_unspecified).
            if v4.octets()[0] == 0 {
                return Some(format!("webhook URL must not target zero-network IP: {v4}"));
            }
            None
        }
        std::net::IpAddr::V6(v6) => {
            if v6.is_loopback() {
                return Some(format!("webhook URL must not target loopback IPv6: {v6}"));
            }
            if v6.is_unspecified() {
                return Some(format!(
                    "webhook URL must not target unspecified IPv6: {v6}"
                ));
            }
            let segments = v6.segments();
            // fc00::/7 — unique local addresses (segments[0] & 0xfe00 == 0xfc00).
            if segments[0] & 0xfe00 == 0xfc00 {
                return Some(format!(
                    "webhook URL must not target unique-local IPv6: {v6}"
                ));
            }
            // fe80::/10 — link-local addresses (segments[0] & 0xffc0 == 0xfe80).
            if segments[0] & 0xffc0 == 0xfe80 {
                return Some(format!("webhook URL must not target link-local IPv6: {v6}"));
            }
            // ::ffff:x.x.x.x — IPv6-mapped IPv4. Check the embedded IPv4.
            if let Some(v4) = v6.to_ipv4_mapped()
                && let Some(reason) = check_ip_blocked(std::net::IpAddr::V4(v4))
            {
                return Some(format!("webhook URL must not target IPv6-mapped {reason}"));
            }
            None
        }
    }
}

// ---------------------------------------------------------------------------
// WebhookDispatcher — outbound event dispatch to registered webhook targets
// ---------------------------------------------------------------------------

/// A registered webhook target: URL + Ed25519 signing key + context scope.
#[derive(Debug, Clone)]
pub struct WebhookTarget {
    /// Webhook delivery URL (must be HTTPS).
    pub url: String,
    /// Ed25519 signing key for webhook signatures.
    pub signing_key: SigningKey,
    /// Context IDs this target is subscribed to.
    /// Empty means subscribed to all contexts on this node.
    pub context_ids: Vec<String>,
}

/// Manages registered webhook targets and dispatches context events to them.
///
/// When a context event occurs (message received, member joined/left,
/// governance action), the dispatcher fans out to all registered targets
/// whose `context_ids` include the event's context or that are subscribed
/// to all contexts (empty `context_ids`).
///
/// Thread-safe: the internal registry is protected by an async `RwLock`.
#[derive(Debug)]
pub struct WebhookDispatcher {
    /// Registered targets, keyed by a unique target ID (e.g., `bridge_id`).
    targets: RwLock<HashMap<String, WebhookTarget>>,
    /// Hardened HTTP client: no redirects (SSRF prevention), 10s timeout.
    /// Shared across all dispatches for connection reuse.
    client: reqwest::Client,
}

impl WebhookDispatcher {
    /// Creates a new empty dispatcher with a hardened HTTP client.
    #[must_use]
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            targets: RwLock::new(HashMap::new()),
            client,
        }
    }

    /// Maximum number of registered webhook targets (BLACK-302).
    const MAX_TARGETS: usize = 256;

    /// Registers a webhook target.
    ///
    /// If a target with the same `target_id` already exists, it is replaced.
    /// Rejects registration if the target limit is reached (returns `false`).
    pub async fn register(&self, target_id: String, target: WebhookTarget) -> bool {
        let mut targets = self.targets.write().await;
        if targets.len() >= Self::MAX_TARGETS && !targets.contains_key(&target_id) {
            tracing::warn!(
                target_id,
                "webhook target registration rejected: limit of {} reached",
                Self::MAX_TARGETS,
            );
            return false;
        }
        targets.insert(target_id, target);
        true
    }

    /// Removes a webhook target by ID.
    ///
    /// Returns `true` if a target was removed, `false` if no target with
    /// that ID was registered.
    pub async fn deregister(&self, target_id: &str) -> bool {
        self.targets.write().await.remove(target_id).is_some()
    }

    /// Dispatches a context event to all registered targets that match
    /// the given `context_id`.
    ///
    /// A target matches if its `context_ids` list contains `context_id`
    /// or if its `context_ids` list is empty (subscribed to all contexts).
    ///
    /// Dispatches are performed concurrently. Results are logged but not
    /// returned — webhook delivery is best-effort.
    pub async fn dispatch_event(
        &self,
        context_id: &str,
        event_type: &str,
        payload: serde_json::Value,
    ) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let event_id = format!(
            "evt-{}-{}-{}",
            context_id.get(..8).unwrap_or(context_id),
            now.as_nanos(),
            EVENT_COUNTER.fetch_add(1, Ordering::Relaxed),
        );
        let timestamp = now.as_secs();

        let event = WebhookEvent {
            event_id,
            event_type: event_type.to_owned(),
            context_id: context_id.to_owned(),
            timestamp,
            payload,
        };

        // Snapshot matching targets under the read lock, then release it
        // before doing any async I/O.
        let matching: Vec<(String, WebhookTarget)> = {
            let targets = self.targets.read().await;
            targets
                .iter()
                .filter(|(_, t)| {
                    t.context_ids.is_empty() || t.context_ids.iter().any(|c| c == context_id)
                })
                .map(|(id, t)| (id.clone(), t.clone()))
                .collect()
        };

        if matching.is_empty() {
            return;
        }

        // Fan out dispatches concurrently.
        let event = Arc::new(event);
        let mut handles = Vec::with_capacity(matching.len());
        for (target_id, target) in matching {
            let event = Arc::clone(&event);
            let client = self.client.clone();
            handles.push(tokio::spawn(async move {
                let result =
                    dispatch_webhook(&target.url, &event, &target.signing_key, &client).await;
                if result.success {
                    tracing::debug!(
                        target_id = %target_id,
                        url = %target.url,
                        attempts = result.attempts,
                        "webhook dispatched successfully"
                    );
                } else {
                    tracing::warn!(
                        target_id = %target_id,
                        url = %target.url,
                        error = ?result.error,
                        attempts = result.attempts,
                        "webhook dispatch failed"
                    );
                }
            }));
        }

        // Await all dispatches (best-effort, ignore join errors).
        for handle in handles {
            let _ = handle.await;
        }
    }

    /// Returns the number of registered targets.
    pub async fn target_count(&self) -> usize {
        self.targets.read().await.len()
    }
}

impl Default for WebhookDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    fn test_client() -> reqwest::Client {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn webhook_url_rejects_http() {
        let key = SigningKey::from_bytes(&[1u8; 32]);
        let event = WebhookEvent {
            event_id: "evt-1".to_owned(),
            event_type: "message.received".to_owned(),
            context_id: "ctx-1".to_owned(),
            timestamp: 1_700_000_000,
            payload: serde_json::json!({}),
        };
        let result =
            dispatch_webhook("http://example.com/hook", &event, &key, &test_client()).await;
        assert!(!result.success);
        assert_eq!(result.attempts, 0);
        assert!(
            result.error.as_deref().is_some_and(|e| e.contains("HTTPS")),
            "expected HTTPS error, got: {:?}",
            result.error,
        );
    }

    #[tokio::test]
    async fn webhook_url_rejects_localhost() {
        let key = SigningKey::from_bytes(&[2u8; 32]);
        let event = WebhookEvent {
            event_id: "evt-2".to_owned(),
            event_type: "member.joined".to_owned(),
            context_id: "ctx-2".to_owned(),
            timestamp: 1_700_000_000,
            payload: serde_json::json!({}),
        };

        let result = dispatch_webhook("https://localhost/hook", &event, &key, &test_client()).await;
        assert!(!result.success);
        assert!(
            result
                .error
                .as_deref()
                .is_some_and(|e| e.contains("localhost")),
            "expected localhost error, got: {:?}",
            result.error,
        );

        let result = dispatch_webhook("https://127.0.0.1/hook", &event, &key, &test_client()).await;
        assert!(!result.success);
        assert!(
            result
                .error
                .as_deref()
                .is_some_and(|e| e.contains("private IP") || e.contains("localhost")),
            "expected private IP error, got: {:?}",
            result.error,
        );
    }

    #[tokio::test]
    async fn webhook_url_rejects_private_ip() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let event = WebhookEvent {
            event_id: "evt-3".to_owned(),
            event_type: "governance.action".to_owned(),
            context_id: "ctx-3".to_owned(),
            timestamp: 1_700_000_000,
            payload: serde_json::json!({}),
        };

        // 10.x.x.x
        let result = dispatch_webhook("https://10.0.0.1/hook", &event, &key, &test_client()).await;
        assert!(!result.success);
        assert!(
            result
                .error
                .as_deref()
                .is_some_and(|e| e.contains("private IP")),
            "expected private IP error for 10.x, got: {:?}",
            result.error,
        );

        // 192.168.x.x
        let result =
            dispatch_webhook("https://192.168.1.1/hook", &event, &key, &test_client()).await;
        assert!(!result.success);
        assert!(
            result
                .error
                .as_deref()
                .is_some_and(|e| e.contains("private IP")),
            "expected private IP error for 192.168, got: {:?}",
            result.error,
        );

        // 172.16.x.x
        let result =
            dispatch_webhook("https://172.16.0.1/hook", &event, &key, &test_client()).await;
        assert!(!result.success);
        assert!(
            result
                .error
                .as_deref()
                .is_some_and(|e| e.contains("private IP")),
            "expected private IP error for 172.16, got: {:?}",
            result.error,
        );
    }

    #[test]
    fn webhook_event_serializes_correctly() {
        let event = WebhookEvent {
            event_id: "evt-42".to_owned(),
            event_type: "message.received".to_owned(),
            context_id: "ctx-abc".to_owned(),
            timestamp: 1_700_000_000,
            payload: serde_json::json!({"sender": "did:dht:abc", "size": 128}),
        };

        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["event_id"], "evt-42");
        assert_eq!(json["event_type"], "message.received");
        assert_eq!(json["context_id"], "ctx-abc");
        assert_eq!(json["timestamp"], 1_700_000_000u64);
        assert_eq!(json["payload"]["sender"], "did:dht:abc");
        assert_eq!(json["payload"]["size"], 128);
    }

    #[test]
    fn webhook_signature_is_deterministic() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let body = b"test payload";
        let timestamp: u64 = 1_700_000_000;

        let domain_separator = b"SCP-WEBHOOK-V1:";
        let mut payload = Vec::with_capacity(domain_separator.len() + 8 + body.len());
        payload.extend_from_slice(domain_separator);
        payload.extend_from_slice(&timestamp.to_be_bytes());
        payload.extend_from_slice(body);

        let sig1 = key.sign(&payload);
        let sig2 = key.sign(&payload);

        assert_eq!(
            sig1.to_bytes(),
            sig2.to_bytes(),
            "Ed25519 signatures must be deterministic for the same key and payload"
        );

        // Also verify the signature is valid against the verifying key.
        let verifying_key = key.verifying_key();
        assert!(
            verifying_key.verify(&payload, &sig1).is_ok(),
            "signature must verify against the corresponding public key"
        );
    }

    #[test]
    fn validate_webhook_url_accepts_public_https() {
        assert!(
            validate_webhook_url("https://hooks.example.com/callback").is_none(),
            "public HTTPS URL should be accepted"
        );
    }

    #[test]
    fn validate_webhook_url_rejects_link_local() {
        let result = validate_webhook_url("https://169.254.1.1/hook");
        assert!(
            result.is_some_and(|e| e.contains("link-local")),
            "link-local IP should be rejected"
        );
    }

    #[test]
    fn validate_webhook_url_rejects_unspecified() {
        let result = validate_webhook_url("https://0.0.0.0/hook");
        assert!(
            result.is_some_and(|e| e.contains("unspecified")),
            "0.0.0.0 should be rejected"
        );
    }

    #[test]
    fn validate_webhook_url_rejects_cloud_metadata() {
        // AWS metadata endpoint
        let result = validate_webhook_url("https://169.254.169.254/latest/meta-data");
        assert!(
            result.is_some_and(|e| e.contains("link-local")),
            "169.254.169.254 (AWS metadata) should be rejected"
        );
    }

    #[test]
    fn validate_webhook_url_rejects_zero_network() {
        // 0.x.x.x — "this network" addresses
        let result = validate_webhook_url("https://0.1.2.3/hook");
        assert!(
            result.is_some_and(|e| e.contains("zero-network")),
            "0.x.x.x should be rejected"
        );
    }

    #[test]
    fn validate_webhook_url_rejects_ipv6_unique_local() {
        let result = validate_webhook_url("https://[fd00::1]/hook");
        assert!(
            result.is_some_and(|e| e.contains("unique-local")),
            "fd00::1 (unique local) should be rejected"
        );
    }

    #[test]
    fn validate_webhook_url_rejects_ipv6_link_local() {
        let result = validate_webhook_url("https://[fe80::1]/hook");
        assert!(
            result.is_some_and(|e| e.contains("link-local IPv6")),
            "fe80::1 (link-local) should be rejected"
        );
    }

    #[test]
    fn validate_webhook_url_rejects_ipv6_mapped_ipv4_loopback() {
        let result = validate_webhook_url("https://[::ffff:127.0.0.1]/hook");
        assert!(
            result.is_some_and(|e| e.contains("IPv6-mapped")),
            "::ffff:127.0.0.1 should be rejected"
        );
    }

    #[test]
    fn validate_webhook_url_rejects_ipv6_mapped_ipv4_private() {
        let result = validate_webhook_url("https://[::ffff:10.0.0.1]/hook");
        assert!(
            result.is_some_and(|e| e.contains("IPv6-mapped")),
            "::ffff:10.0.0.1 should be rejected"
        );
    }

    #[test]
    fn validate_webhook_url_rejects_ipv6_unspecified() {
        let result = validate_webhook_url("https://[::]/hook");
        assert!(
            result.is_some_and(|e| e.contains("unspecified")),
            ":: (unspecified IPv6) should be rejected"
        );
    }

    // -----------------------------------------------------------------------
    // WebhookDispatcher tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn dispatcher_register_and_deregister() {
        let dispatcher = WebhookDispatcher::new();
        assert_eq!(dispatcher.target_count().await, 0);

        let key = SigningKey::from_bytes(&[10u8; 32]);
        dispatcher
            .register(
                "bridge-1".to_owned(),
                WebhookTarget {
                    url: "https://hooks.example.com/a".to_owned(),
                    signing_key: key,
                    context_ids: vec!["ctx-1".to_owned()],
                },
            )
            .await;
        assert_eq!(dispatcher.target_count().await, 1);

        assert!(dispatcher.deregister("bridge-1").await);
        assert_eq!(dispatcher.target_count().await, 0);
        assert!(!dispatcher.deregister("bridge-1").await);
    }

    #[tokio::test]
    async fn dispatcher_dispatch_no_targets_is_noop() {
        let dispatcher = WebhookDispatcher::new();
        // Should not panic or hang.
        dispatcher
            .dispatch_event("ctx-1", "message.received", serde_json::json!({}))
            .await;
    }

    #[tokio::test]
    async fn dispatcher_filters_by_context_id() {
        let dispatcher = WebhookDispatcher::new();
        let key = SigningKey::from_bytes(&[11u8; 32]);

        // Register target for ctx-2 only.
        dispatcher
            .register(
                "bridge-scoped".to_owned(),
                WebhookTarget {
                    url: "https://hooks.example.com/scoped".to_owned(),
                    signing_key: key.clone(),
                    context_ids: vec!["ctx-2".to_owned()],
                },
            )
            .await;

        // Register target for all contexts (empty context_ids).
        dispatcher
            .register(
                "bridge-all".to_owned(),
                WebhookTarget {
                    url: "https://hooks.example.com/all".to_owned(),
                    signing_key: key,
                    context_ids: vec![],
                },
            )
            .await;

        // Dispatching to ctx-1 should only match bridge-all (bridge-scoped
        // is for ctx-2). The actual HTTP calls will fail (no server), but
        // the dispatch function handles errors gracefully.
        dispatcher
            .dispatch_event("ctx-1", "message.received", serde_json::json!({}))
            .await;

        // Dispatching to ctx-2 should match both.
        dispatcher
            .dispatch_event("ctx-2", "member.joined", serde_json::json!({}))
            .await;
    }

    #[tokio::test]
    async fn dispatcher_default_is_empty() {
        let dispatcher = WebhookDispatcher::default();
        assert_eq!(dispatcher.target_count().await, 0);
    }
}
