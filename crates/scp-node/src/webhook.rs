//! Outbound webhook dispatch for bridge cooperative mode (spec §12.2.1).
//!
//! When context events occur (message received, member joined/left, governance
//! action), registered bridges with `webhook_url` receive HTTP POST
//! notifications with Ed25519 signatures.

use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;

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

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Sign: Ed25519(timestamp_be_bytes || body)
    let mut signing_payload = Vec::with_capacity(8 + body.len());
    signing_payload.extend_from_slice(&timestamp.to_be_bytes());
    signing_payload.extend_from_slice(&body);
    let signature = signing_key.sign(&signing_payload);
    let sig_hex = hex::encode(signature.to_bytes());

    let client = reqwest::Client::new();
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

/// Basic SSRF prevention: reject private/loopback IP addresses.
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
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v4) => {
                if v4.is_private() || v4.is_loopback() || v4.is_link_local() {
                    return Some(format!("webhook URL must not target private IP: {v4}"));
                }
            }
            std::net::IpAddr::V6(v6) => {
                if v6.is_loopback() {
                    return Some(format!("webhook URL must not target loopback IPv6: {v6}"));
                }
            }
        }
    }

    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

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
        let result = dispatch_webhook("http://example.com/hook", &event, &key).await;
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

        let result = dispatch_webhook("https://localhost/hook", &event, &key).await;
        assert!(!result.success);
        assert!(
            result
                .error
                .as_deref()
                .is_some_and(|e| e.contains("localhost")),
            "expected localhost error, got: {:?}",
            result.error,
        );

        let result = dispatch_webhook("https://127.0.0.1/hook", &event, &key).await;
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
        let result = dispatch_webhook("https://10.0.0.1/hook", &event, &key).await;
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
        let result = dispatch_webhook("https://192.168.1.1/hook", &event, &key).await;
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
        let result = dispatch_webhook("https://172.16.0.1/hook", &event, &key).await;
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

        let mut payload = Vec::with_capacity(8 + body.len());
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
            result.is_some_and(|e| e.contains("private IP")),
            "link-local IP should be rejected"
        );
    }
}
