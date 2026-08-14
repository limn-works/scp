//! DNS subdomain-based TLS provisioning for zero-config self-hosted nodes.
//!
//! Provides [`ScpDnsProvider`], a [`TlsProvider`](crate::TlsProvider) that
//! automatically provisions TLS certificates via the Limn DNS API at
//! `dns.ctx.network`. The flow:
//!
//! 1. Derive a stable, deterministic subdomain from the node's DID
//!    (SHA-256 → first 8 hex chars → `<hash>.scp.ctx.network`).
//! 2. Register the subdomain + public IP with the DNS API
//!    (`POST https://dns.ctx.network/register`).
//! 3. The API creates an A record and handles the Let's Encrypt DNS-01
//!    challenge, returning the signed certificate.
//! 4. The node uses the returned certificate for TLS.
//!
//! **Fallback:** If the DNS API is unreachable (network partition, service
//! outage, Limn disappears), the provider falls back to a self-signed
//! certificate — the protocol still works (relays are untrusted dumb pipes;
//! MLS provides real confidentiality).
//!
//! **Trust model:** Limn sees the node's public IP, node ID, and DID
//! (minimal metadata). The DID is sent so the API can bind the subdomain
//! to a specific identity and verify ownership on re-registration. Limn
//! cannot read messages (MLS/sender keys). DNS hijack risk is mitigated
//! by MLS — the relay is untrusted by design. The service is optional;
//! nodes can use their own domain via `.domain()`.
//!
//! See issue #642 and spec section 18.6.3.

use std::net::IpAddr;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use zeroize::Zeroizing;

use crate::tls::{CertificateData, TlsError};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default DNS API base URL.
const DEFAULT_DNS_API_URL: &str = "https://dns.ctx.network";

/// Default base domain for auto-provisioned subdomains.
const DEFAULT_BASE_DOMAIN: &str = "scp.ctx.network";

/// HTTP request timeout for DNS API calls.
const DNS_API_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum number of registration retries before falling back to self-signed.
const MAX_REGISTRATION_RETRIES: u32 = 3;

/// Delay between registration retries.
const RETRY_DELAY: Duration = Duration::from_secs(2);

// ---------------------------------------------------------------------------
// DNS API request/response types
// ---------------------------------------------------------------------------

/// Registration request sent to the DNS API.
#[derive(Debug, serde::Serialize)]
struct RegisterRequest<'a> {
    /// Deterministic node ID derived from the DID (first 8 hex chars of SHA-256).
    node_id: &'a str,
    /// The node's full DID string. The DNS API uses this to verify ownership
    /// of the derived node ID (the node ID alone is a truncated hash — the
    /// full DID is needed for the API to bind the subdomain to this identity).
    did: &'a str,
    /// Node's public IP address.
    ip: IpAddr,
    /// Port the node listens on for HTTPS.
    port: u16,
}

/// Registration response from the DNS API.
#[derive(Debug, serde::Deserialize)]
struct RegisterResponse {
    /// The fully qualified domain name assigned to the node.
    domain: String,
    /// PEM-encoded certificate chain (leaf + intermediates).
    certificate_chain_pem: String,
    /// PEM-encoded private key.
    private_key_pem: String,
}

/// Error response from the DNS API.
#[derive(Debug, serde::Deserialize)]
struct ErrorResponse {
    /// Human-readable error message.
    error: String,
}

// ---------------------------------------------------------------------------
// DnsProviderConfig — deferred construction for the builder
// ---------------------------------------------------------------------------

/// Configuration for deferred [`ScpDnsProvider`] construction.
///
/// [`NodeConfig::dns_provider`](crate::NodeConfig::dns_provider) carries this
/// config and the build engine creates the actual [`ScpDnsProvider`] during
/// [`Node::start`](crate::Node::start) after the DID is resolved. This solves
/// the chicken-and-egg problem: the DNS provider needs the DID to derive the
/// subdomain, but the DID is not known until identity resolution completes.
///
/// # Usage
///
/// ```ignore
/// let config = DnsProviderConfig::new(public_ip, 8443);
/// let node = Node::start(NodeConfig {
///     dns_provider: Some(config),
///     dht: DhtMode::Production,
///     ..NodeConfig::defaults(
///         Reach::Domain { domain: "placeholder.scp.ctx.network".to_owned() },
///         IdentitySource::Generate { custody, did_method },
///         storage,
///         BlobStorageBackend::sqlite(&blob_db)?, // durable backend for a public node
///     )
/// })
/// .await?;
/// ```
#[derive(Debug, Clone)]
pub struct DnsProviderConfig {
    /// Node's public IP address.
    pub public_ip: IpAddr,
    /// Port the node listens on for HTTPS.
    pub port: u16,
    /// Base domain override (default: `scp.ctx.network`).
    pub base_domain: Option<String>,
    /// DNS API URL override (default: `https://dns.ctx.network`).
    pub api_url: Option<String>,
}

impl DnsProviderConfig {
    /// Create a new config with the given public IP and port.
    #[must_use]
    pub const fn new(public_ip: IpAddr, port: u16) -> Self {
        Self {
            public_ip,
            port,
            base_domain: None,
            api_url: None,
        }
    }

    /// Override the base domain (default: `scp.ctx.network`).
    #[must_use]
    pub fn with_base_domain(mut self, domain: &str) -> Self {
        self.base_domain = Some(domain.to_owned());
        self
    }

    /// Override the DNS API URL (default: `https://dns.ctx.network`).
    #[must_use]
    pub fn with_api_url(mut self, url: &str) -> Self {
        self.api_url = Some(url.to_owned());
        self
    }

    /// Build the [`ScpDnsProvider`] and derived domain from the resolved DID.
    ///
    /// Returns `(provider, domain)` where `domain` is the fully qualified
    /// subdomain (e.g., `a3f8b2c1.scp.ctx.network`).
    #[must_use]
    pub fn build(self, did: &str) -> (ScpDnsProvider, String) {
        let mut provider = ScpDnsProvider::new(did, self.public_ip, self.port);
        if let Some(base) = self.base_domain {
            provider = provider.with_base_domain(&base);
        }
        if let Some(url) = self.api_url {
            provider = provider.with_api_url(&url);
        }
        let domain = provider.subdomain();
        (provider, domain)
    }
}

// ---------------------------------------------------------------------------
// ScpDnsProvider
// ---------------------------------------------------------------------------

/// DNS subdomain-based TLS provider for zero-config self-hosted nodes.
///
/// Implements [`TlsProvider`](crate::TlsProvider) by registering with the
/// Limn DNS API to obtain a subdomain and Let's Encrypt certificate. Falls
/// back to self-signed on failure.
///
/// # Construction
///
/// Use [`ScpDnsProvider::new`] for defaults, or the builder methods for
/// customization:
///
/// ```ignore
/// let provider = ScpDnsProvider::new("did:dht:abc123", ip, 8443)
///     .with_base_domain("custom.example.com")
///     .with_api_url("https://dns.custom.example.com");
/// ```
pub struct ScpDnsProvider {
    /// DID string used to derive the deterministic node ID.
    did: String,
    /// Node's public IP address, reported to the DNS API.
    public_ip: IpAddr,
    /// Port the node listens on for HTTPS.
    port: u16,
    /// Base domain for subdomain generation (default: `scp.ctx.network`).
    base_domain: String,
    /// DNS API base URL (default: `https://dns.ctx.network`).
    api_url: String,
    /// The assigned domain after successful registration. Cached for
    /// subsequent calls to `provision()` (avoids redundant API calls).
    assigned_domain: RwLock<Option<String>>,
    /// Cached certificate data from a successful registration.
    cached_cert: RwLock<Option<CertificateData>>,
}

impl std::fmt::Debug for ScpDnsProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScpDnsProvider")
            .field("did", &self.did)
            .field("public_ip", &self.public_ip)
            .field("port", &self.port)
            .field("base_domain", &self.base_domain)
            .field("api_url", &self.api_url)
            .finish_non_exhaustive()
    }
}

impl ScpDnsProvider {
    /// Create a new DNS provider for the given DID, public IP, and port.
    ///
    /// Uses the default DNS API at `dns.ctx.network` and base domain
    /// `scp.ctx.network`.
    #[must_use]
    pub fn new(did: &str, public_ip: IpAddr, port: u16) -> Self {
        Self {
            did: did.to_owned(),
            public_ip,
            port,
            base_domain: DEFAULT_BASE_DOMAIN.to_owned(),
            api_url: DEFAULT_DNS_API_URL.to_owned(),
            assigned_domain: RwLock::new(None),
            cached_cert: RwLock::new(None),
        }
    }

    /// Override the base domain (default: `scp.ctx.network`).
    #[must_use]
    pub fn with_base_domain(mut self, domain: &str) -> Self {
        domain.clone_into(&mut self.base_domain);
        self
    }

    /// Override the DNS API URL (default: `https://dns.ctx.network`).
    #[must_use]
    pub fn with_api_url(mut self, url: &str) -> Self {
        url.clone_into(&mut self.api_url);
        self
    }

    /// Derive a stable, deterministic node ID from the DID.
    ///
    /// Uses SHA-256 of the DID string, taking the first 8 hex characters.
    /// This gives 32 bits of collision resistance — sufficient for DNS
    /// subdomains where collisions are handled by the API (which checks
    /// for DID ownership).
    #[must_use]
    pub fn node_id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.did.as_bytes());
        let hash = hasher.finalize();
        hex::encode(&hash[..4])
    }

    /// Returns the fully qualified domain name for this node.
    ///
    /// Format: `<node_id>.<base_domain>` (e.g., `a3f8b2c1.scp.ctx.network`).
    #[must_use]
    pub fn subdomain(&self) -> String {
        format!("{}.{}", self.node_id(), self.base_domain)
    }

    /// Register with the DNS API and obtain a TLS certificate.
    ///
    /// Retries up to [`MAX_REGISTRATION_RETRIES`] times on transient failures.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError::Acme`] if registration fails after all retries.
    async fn register(&self) -> Result<CertificateData, TlsError> {
        let node_id = self.node_id();
        let register_url = format!("{}/register", self.api_url);

        let client = reqwest::Client::builder()
            .timeout(DNS_API_TIMEOUT)
            .build()
            .map_err(|e| TlsError::Acme(format!("failed to build HTTP client: {e}")))?;

        let request_body = RegisterRequest {
            node_id: &node_id,
            did: &self.did,
            ip: self.public_ip,
            port: self.port,
        };

        let mut last_error = String::new();

        for attempt in 0..MAX_REGISTRATION_RETRIES {
            if attempt > 0 {
                tracing::debug!(
                    attempt = attempt + 1,
                    max = MAX_REGISTRATION_RETRIES,
                    "retrying DNS API registration"
                );
                tokio::time::sleep(RETRY_DELAY).await;
            }

            let result = client.post(&register_url).json(&request_body).send().await;

            match result {
                Ok(response) => {
                    let status = response.status();

                    if status.is_success() {
                        let body: RegisterResponse = response.json().await.map_err(|e| {
                            TlsError::Acme(format!("failed to parse DNS API success response: {e}"))
                        })?;

                        tracing::info!(
                            domain = %body.domain,
                            node_id = %node_id,
                            "registered with DNS API, certificate received"
                        );

                        // Cache the assigned domain.
                        {
                            let mut guard = self.assigned_domain.write().await;
                            *guard = Some(body.domain);
                        }

                        let cert_data = CertificateData {
                            certificate_chain_pem: body.certificate_chain_pem,
                            private_key_pem: Zeroizing::new(body.private_key_pem),
                        };

                        // Cache the certificate.
                        {
                            let mut guard = self.cached_cert.write().await;
                            *guard = Some(cert_data.clone());
                        }

                        return Ok(cert_data);
                    }

                    // Non-success status — parse error body if possible.
                    let error_msg = match response.json::<ErrorResponse>().await {
                        Ok(err_body) => err_body.error,
                        Err(_) => format!("HTTP {status}"),
                    };

                    // 429 (rate limited) and 5xx are transient — retry.
                    // 4xx (except 429) are permanent — fail immediately.
                    if status.as_u16() == 429 || status.is_server_error() {
                        last_error = error_msg;
                        continue;
                    }

                    return Err(TlsError::Acme(format!(
                        "DNS API registration failed: {error_msg}"
                    )));
                }
                Err(e) => {
                    // Network error — transient, retry.
                    last_error = format!("network error: {e}");
                }
            }
        }

        Err(TlsError::Acme(format!(
            "DNS API registration failed after {MAX_REGISTRATION_RETRIES} attempts: {last_error}"
        )))
    }

    /// Provision a TLS certificate, falling back to self-signed on failure.
    ///
    /// 1. If a cached certificate exists and is not near expiry, return it.
    /// 2. Otherwise, attempt registration with the DNS API.
    /// 3. On DNS API failure, generate a self-signed certificate as fallback.
    async fn provision_with_fallback(&self) -> Result<CertificateData, TlsError> {
        // Check cache first.
        {
            let guard = self.cached_cert.read().await;
            if let Some(ref cert) = *guard {
                match cert.needs_renewal() {
                    Ok(false) => {
                        tracing::debug!("using cached DNS-provisioned certificate");
                        return Ok(cert.clone());
                    }
                    Ok(true) => {
                        tracing::info!("cached certificate needs renewal, re-registering");
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "failed to check cached certificate expiry, re-registering"
                        );
                    }
                }
            }
        }

        // Attempt DNS API registration.
        match self.register().await {
            Ok(cert) => Ok(cert),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "DNS API registration failed, falling back to self-signed certificate"
                );

                // Fallback: generate self-signed for the subdomain.
                let domain = self.subdomain();
                let cert = crate::tls::generate_self_signed(&domain)?;

                // Cache the self-signed cert so subsequent calls don't
                // regenerate (it's still valid for 365 days).
                {
                    let mut guard = self.cached_cert.write().await;
                    *guard = Some(cert.clone());
                }

                Ok(cert)
            }
        }
    }

    /// Returns the assigned domain, if registration has completed.
    ///
    /// Returns `None` before the first successful `provision()` call.
    pub async fn assigned_domain(&self) -> Option<String> {
        self.assigned_domain.read().await.clone()
    }
}

/// [`TlsProvider`](crate::TlsProvider) implementation for [`ScpDnsProvider`].
///
/// Does not require an HTTP-01 challenge listener — the DNS API handles
/// DNS-01 challenges server-side.
impl crate::TlsProvider for ScpDnsProvider {
    fn provision(
        &self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<CertificateData, TlsError>> + Send + '_>,
    > {
        Box::pin(self.provision_with_fallback())
    }

    // No challenge listener needed — DNS-01 is handled by the API.
    // Default `challenges()` and `needs_challenge_listener()` are correct.
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::significant_drop_tightening
)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn node_id_is_deterministic() {
        let provider = ScpDnsProvider::new("did:dht:abc123", IpAddr::V4(Ipv4Addr::LOCALHOST), 8443);
        let id1 = provider.node_id();
        let id2 = provider.node_id();
        assert_eq!(id1, id2, "node_id must be deterministic");
        assert_eq!(id1.len(), 8, "node_id should be 8 hex chars");
    }

    #[test]
    fn different_dids_produce_different_node_ids() {
        let p1 = ScpDnsProvider::new("did:dht:abc123", IpAddr::V4(Ipv4Addr::LOCALHOST), 8443);
        let p2 = ScpDnsProvider::new("did:dht:xyz789", IpAddr::V4(Ipv4Addr::LOCALHOST), 8443);
        assert_ne!(
            p1.node_id(),
            p2.node_id(),
            "different DIDs should produce different node IDs"
        );
    }

    #[test]
    fn subdomain_format() {
        let provider = ScpDnsProvider::new("did:dht:abc123", IpAddr::V4(Ipv4Addr::LOCALHOST), 8443);
        let subdomain = provider.subdomain();
        assert!(
            subdomain.ends_with(".scp.ctx.network"),
            "subdomain should end with base domain, got: {subdomain}"
        );
        assert!(
            subdomain.starts_with(&provider.node_id()),
            "subdomain should start with node_id"
        );
    }

    #[test]
    fn custom_base_domain() {
        let provider = ScpDnsProvider::new("did:dht:abc123", IpAddr::V4(Ipv4Addr::LOCALHOST), 8443)
            .with_base_domain("custom.example.com");
        let subdomain = provider.subdomain();
        assert!(
            subdomain.ends_with(".custom.example.com"),
            "custom base domain should be used, got: {subdomain}"
        );
    }

    #[test]
    fn custom_api_url() {
        let provider = ScpDnsProvider::new("did:dht:abc123", IpAddr::V4(Ipv4Addr::LOCALHOST), 8443)
            .with_api_url("https://custom.dns.example.com");
        assert_eq!(provider.api_url, "https://custom.dns.example.com");
    }

    #[test]
    fn node_id_is_valid_hex() {
        let provider = ScpDnsProvider::new("did:dht:abc123", IpAddr::V4(Ipv4Addr::LOCALHOST), 8443);
        let id = provider.node_id();
        assert!(
            id.chars().all(|c| c.is_ascii_hexdigit()),
            "node_id should be valid hex, got: {id}"
        );
    }

    #[test]
    fn node_id_is_lowercase_hex() {
        let provider = ScpDnsProvider::new("did:dht:ABCdef", IpAddr::V4(Ipv4Addr::LOCALHOST), 8443);
        let id = provider.node_id();
        assert_eq!(
            id,
            id.to_lowercase(),
            "node_id should be lowercase hex, got: {id}"
        );
    }

    #[test]
    fn debug_does_not_leak_secrets() {
        let provider = ScpDnsProvider::new("did:dht:secret", IpAddr::V4(Ipv4Addr::LOCALHOST), 8443);
        let debug = format!("{provider:?}");
        assert!(
            debug.contains("ScpDnsProvider"),
            "debug should contain struct name"
        );
        assert!(
            debug.contains("did:dht:secret"),
            "debug should contain DID (public)"
        );
    }

    #[tokio::test]
    async fn provision_falls_back_to_self_signed_when_api_unreachable() {
        // Use a non-routable API URL that will fail immediately.
        let provider = ScpDnsProvider::new(
            "did:dht:test-fallback",
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            8443,
        )
        .with_api_url("http://192.0.2.1:1"); // TEST-NET-1, non-routable

        // provision_with_fallback() should succeed via self-signed fallback.
        let cert = provider.provision_with_fallback().await.unwrap();
        assert!(
            cert.certificate_chain_pem.contains("BEGIN CERTIFICATE"),
            "fallback should produce a valid certificate"
        );
        assert!(
            cert.private_key_pem.contains("BEGIN PRIVATE KEY"),
            "fallback should produce a valid private key"
        );
    }

    #[tokio::test]
    async fn cached_cert_is_returned_on_second_call() {
        // Use a non-routable API so we get self-signed, then verify cache.
        let provider =
            ScpDnsProvider::new("did:dht:test-cache", IpAddr::V4(Ipv4Addr::LOCALHOST), 8443)
                .with_api_url("http://192.0.2.1:1");

        let cert1 = provider.provision_with_fallback().await.unwrap();
        let cert2 = provider.provision_with_fallback().await.unwrap();

        // Same certificate should be returned from cache.
        assert_eq!(
            cert1.certificate_chain_pem, cert2.certificate_chain_pem,
            "second call should return cached certificate"
        );
    }

    #[test]
    fn needs_challenge_listener_is_false() {
        use crate::TlsProvider;

        let provider = ScpDnsProvider::new("did:dht:abc123", IpAddr::V4(Ipv4Addr::LOCALHOST), 8443);
        assert!(
            !provider.needs_challenge_listener(),
            "DNS provider should not need HTTP-01 challenge listener"
        );
    }
}
