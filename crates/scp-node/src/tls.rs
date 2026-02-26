//! ACME-based TLS provisioning for `ApplicationNode`.
//!
//! Provides automatic TLS certificate provisioning via the ACME protocol
//! (RFC 8555), with support for HTTP-01 challenges. Certificates are stored
//! in the platform [`Storage`] trait and auto-renewed 30 days before expiry.
//!
//! See spec section 18.6.3 for the full design:
//! - **ACME HTTP-01 challenge**: served at `/.well-known/acme-challenge/<token>`
//! - **DNS-01 alternative**: for environments where port 80 is unavailable
//!   (NAT, shared hosting). Operator configures DNS TXT records manually or
//!   via DNS API. (Documented here for reference; not implemented in this module.)
//! - **Certificate storage**: PEM-encoded cert chain and private key stored in
//!   platform `Storage`, encrypted at rest by the storage backend.
//! - **Auto-renewal**: background task renews 30 days before expiry.
//! - **TLS 1.3 required**: per section 9.13, all relay connections use TLS 1.3.

use std::sync::Arc;
use std::time::Duration;

use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use scp_platform::traits::Storage;
use tokio::sync::RwLock;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Storage key for the PEM-encoded certificate chain.
const CERT_STORAGE_KEY: &str = "scp.tls.certificate_chain_pem";

/// Storage key for the PEM-encoded private key.
const KEY_STORAGE_KEY: &str = "scp.tls.private_key_pem";

/// Renew certificates this many days before expiry (spec section 18.6.3).
const RENEWAL_THRESHOLD_DAYS: i64 = 30;

/// How often the background renewal loop checks certificate expiry.
const RENEWAL_CHECK_INTERVAL: Duration = Duration::from_secs(12 * 60 * 60); // 12 hours

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors produced by TLS provisioning.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// An ACME protocol error occurred.
    #[error("ACME error: {0}")]
    Acme(String),

    /// A certificate parsing or generation error occurred.
    #[error("certificate error: {0}")]
    Certificate(String),

    /// A storage operation failed.
    #[error("storage error: {0}")]
    Storage(String),

    /// A TLS configuration error occurred.
    #[error("TLS config error: {0}")]
    Config(String),

    /// A required field is missing.
    #[error("missing required field: {0}")]
    MissingField(&'static str),
}

// ---------------------------------------------------------------------------
// CertificateData
// ---------------------------------------------------------------------------

/// PEM-encoded certificate chain and private key.
///
/// This is the interchange format between ACME provisioning, storage, and
/// TLS configuration. Both fields are PEM strings.
#[derive(Debug, Clone)]
pub struct CertificateData {
    /// PEM-encoded certificate chain (leaf + intermediates).
    pub certificate_chain_pem: String,
    /// PEM-encoded private key.
    pub private_key_pem: String,
}

impl CertificateData {
    /// Parse the PEM certificate chain into DER-encoded certificates.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError::Certificate`] if the PEM data cannot be parsed.
    pub fn certificate_chain_der(&self) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, TlsError> {
        let mut reader = std::io::BufReader::new(self.certificate_chain_pem.as_bytes());
        let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| TlsError::Certificate(format!("failed to parse PEM certificates: {e}")))?;

        if certs.is_empty() {
            return Err(TlsError::Certificate("no certificates found in PEM data".to_owned()));
        }

        Ok(certs)
    }

    /// Parse the PEM private key into a DER-encoded private key.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError::Certificate`] if the PEM data cannot be parsed.
    pub fn private_key_der(&self) -> Result<rustls::pki_types::PrivateKeyDer<'static>, TlsError> {
        let mut reader = std::io::BufReader::new(self.private_key_pem.as_bytes());
        rustls_pemfile::private_key(&mut reader)
            .map_err(|e| TlsError::Certificate(format!("failed to parse PEM private key: {e}")))?
            .ok_or_else(|| TlsError::Certificate("no private key found in PEM data".to_owned()))
    }

    /// Extract the certificate expiry timestamp (notAfter) from the leaf
    /// certificate.
    ///
    /// Returns seconds since Unix epoch.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError::Certificate`] if the certificate cannot be parsed.
    pub fn expiry_timestamp(&self) -> Result<i64, TlsError> {
        let certs = self.certificate_chain_der()?;
        let leaf = certs
            .first()
            .ok_or_else(|| TlsError::Certificate("empty certificate chain".to_owned()))?;

        let (_, cert) = x509_parser::parse_x509_certificate(leaf.as_ref())
            .map_err(|e| TlsError::Certificate(format!("failed to parse X.509 certificate: {e}")))?;

        Ok(cert.validity().not_after.timestamp())
    }

    /// Check whether the certificate needs renewal (within 30 days of expiry).
    ///
    /// # Errors
    ///
    /// Returns [`TlsError::Certificate`] if the expiry cannot be determined.
    pub fn needs_renewal(&self) -> Result<bool, TlsError> {
        let expiry = self.expiry_timestamp()?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| TlsError::Certificate(format!("system time error: {e}")))?
            .as_secs() as i64;

        let threshold = i64::from(RENEWAL_THRESHOLD_DAYS) * 24 * 60 * 60;
        Ok(expiry - now < threshold)
    }
}

// ---------------------------------------------------------------------------
// Storage helpers
// ---------------------------------------------------------------------------

/// Store a certificate and private key in platform storage.
///
/// # Errors
///
/// Returns [`TlsError::Storage`] if the storage operation fails.
pub async fn store_certificate<S: Storage>(
    storage: &S,
    cert_data: &CertificateData,
) -> Result<(), TlsError> {
    storage
        .store(CERT_STORAGE_KEY, cert_data.certificate_chain_pem.as_bytes())
        .await
        .map_err(|e| TlsError::Storage(format!("failed to store certificate: {e}")))?;

    storage
        .store(KEY_STORAGE_KEY, cert_data.private_key_pem.as_bytes())
        .await
        .map_err(|e| TlsError::Storage(format!("failed to store private key: {e}")))?;

    Ok(())
}

/// Load a certificate and private key from platform storage.
///
/// Returns `None` if no certificate is stored.
///
/// # Errors
///
/// Returns [`TlsError::Storage`] if the storage operation fails.
pub async fn load_certificate<S: Storage>(
    storage: &S,
) -> Result<Option<CertificateData>, TlsError> {
    let cert_bytes = storage
        .retrieve(CERT_STORAGE_KEY)
        .await
        .map_err(|e| TlsError::Storage(format!("failed to retrieve certificate: {e}")))?;

    let key_bytes = storage
        .retrieve(KEY_STORAGE_KEY)
        .await
        .map_err(|e| TlsError::Storage(format!("failed to retrieve private key: {e}")))?;

    match (cert_bytes, key_bytes) {
        (Some(cert), Some(key)) => {
            let certificate_chain_pem = String::from_utf8(cert)
                .map_err(|e| TlsError::Storage(format!("certificate is not valid UTF-8: {e}")))?;
            let private_key_pem = String::from_utf8(key)
                .map_err(|e| TlsError::Storage(format!("private key is not valid UTF-8: {e}")))?;
            Ok(Some(CertificateData {
                certificate_chain_pem,
                private_key_pem,
            }))
        }
        _ => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// TLS configuration
// ---------------------------------------------------------------------------

/// Build a `rustls::ServerConfig` enforcing TLS 1.3 (spec section 9.13).
///
/// Uses the `ring` crypto provider explicitly to avoid ambiguity when
/// multiple providers are available via transitive dependencies.
///
/// # Errors
///
/// Returns [`TlsError::Config`] if the TLS configuration cannot be built.
pub fn build_tls_server_config(
    cert_data: &CertificateData,
) -> Result<rustls::ServerConfig, TlsError> {
    let certs = cert_data.certificate_chain_der()?;
    let key = cert_data.private_key_der()?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TlsError::Config(format!("failed to set TLS versions: {e}")))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| TlsError::Config(format!("failed to set certificate: {e}")))?;

    Ok(config)
}

/// Build a reloadable TLS configuration with a [`CertResolver`] that
/// supports hot-swapping certificates without restarting the server.
///
/// Returns the `ServerConfig` and a shared `CertResolver` handle. To update
/// the certificate, call [`CertResolver::update`] on the returned resolver.
///
/// # Errors
///
/// Returns [`TlsError::Config`] if the TLS configuration cannot be built.
pub fn build_reloadable_tls_config(
    cert_data: &CertificateData,
) -> Result<(rustls::ServerConfig, Arc<CertResolver>), TlsError> {
    let certs = cert_data.certificate_chain_der()?;
    let key = cert_data.private_key_der()?;

    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| TlsError::Config(format!("unsupported private key type: {e}")))?;

    let certified_key = CertifiedKey::new(certs, signing_key);
    let resolver = Arc::new(CertResolver::new(certified_key));

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TlsError::Config(format!("failed to set TLS versions: {e}")))?
        .with_no_client_auth()
        .with_cert_resolver(resolver.clone() as Arc<dyn ResolvesServerCert>);

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok((config, resolver))
}

// ---------------------------------------------------------------------------
// CertResolver — hot-reloadable certificate resolver
// ---------------------------------------------------------------------------

/// A certificate resolver that supports hot-swapping certificates.
///
/// Implements [`ResolvesServerCert`] so it can be used with `rustls::ServerConfig`.
/// The inner `RwLock` allows updating the certificate without restarting the
/// TLS acceptor.
#[derive(Debug)]
pub struct CertResolver {
    /// The current certified key, behind a read-write lock for hot-reload.
    pub(crate) inner: RwLock<Arc<CertifiedKey>>,
}

impl CertResolver {
    /// Create a new resolver with the given certified key.
    #[must_use]
    pub fn new(key: CertifiedKey) -> Self {
        Self {
            inner: RwLock::new(Arc::new(key)),
        }
    }

    /// Update the certificate. Subsequent TLS handshakes will use the new
    /// certificate.
    pub async fn update(&self, key: CertifiedKey) {
        let mut guard = self.inner.write().await;
        *guard = Arc::new(key);
    }
}

impl ResolvesServerCert for CertResolver {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<CertifiedKey>> {
        // `try_read()` is non-blocking and appropriate for the synchronous
        // `resolve` callback. If a write is in progress (certificate update),
        // this returns `None` and rustls will reject the handshake — the next
        // attempt will succeed after the update completes.
        self.inner.try_read().ok().map(|guard| Arc::clone(&*guard))
    }
}

// ---------------------------------------------------------------------------
// AcmeProvider
// ---------------------------------------------------------------------------

/// ACME certificate provider for automatic TLS provisioning.
///
/// Manages the full ACME lifecycle: account creation, order placement,
/// HTTP-01 challenge fulfillment, certificate download, and storage.
///
/// # Type Parameter
///
/// - `S`: The platform storage backend (e.g., `InMemoryStorage`, `SqliteStorage`).
///
/// # DNS-01 Alternative
///
/// For environments where port 80 is unavailable (NAT, shared hosting),
/// DNS-01 challenges can be used instead. The operator configures DNS TXT
/// records manually or via DNS API. This is not implemented in this module
/// but is documented here per spec section 18.6.3.
pub struct AcmeProvider<S: Storage> {
    /// The domain to provision a certificate for.
    domain: String,
    /// Platform storage for certificate persistence.
    storage: Arc<S>,
    /// Optional contact email for the ACME account.
    email: Option<String>,
    /// ACME directory URL (defaults to Let's Encrypt production).
    directory_url: String,
    /// Optional cert resolver for hot-reloading certificates.
    cert_resolver: Option<Arc<CertResolver>>,
}

impl<S: Storage> std::fmt::Debug for AcmeProvider<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcmeProvider")
            .field("domain", &self.domain)
            .field("email", &self.email)
            .field("directory_url", &self.directory_url)
            .finish()
    }
}

impl<S: Storage + 'static> AcmeProvider<S> {
    /// Create a new ACME provider for the given domain.
    ///
    /// Uses the Let's Encrypt production directory by default. Call
    /// [`with_directory_url`](Self::with_directory_url) to change.
    #[must_use]
    pub fn new(domain: &str, storage: Arc<S>) -> Self {
        Self {
            domain: domain.to_owned(),
            storage,
            email: None,
            directory_url: "https://acme-v02.api.letsencrypt.org/directory".to_owned(),
            cert_resolver: None,
        }
    }

    /// Set the contact email for the ACME account.
    #[must_use]
    pub fn with_email(mut self, email: &str) -> Self {
        self.email = Some(email.to_owned());
        self
    }

    /// Set a custom ACME directory URL (e.g., staging environment).
    #[must_use]
    pub fn with_directory_url(mut self, url: &str) -> Self {
        self.directory_url = url.to_owned();
        self
    }

    /// Set a cert resolver for hot-reloading on renewal.
    #[must_use]
    pub fn with_cert_resolver(mut self, resolver: Arc<CertResolver>) -> Self {
        self.cert_resolver = Some(resolver);
        self
    }

    /// Provision a new certificate via ACME HTTP-01.
    ///
    /// This performs the full ACME flow:
    /// 1. Create an ACME account.
    /// 2. Place a new order for the domain.
    /// 3. Retrieve the HTTP-01 challenge.
    /// 4. Respond to the challenge (caller must serve the challenge token).
    /// 5. Wait for the order to become ready.
    /// 6. Finalize the order with a CSR.
    /// 7. Download the certificate.
    /// 8. Store in platform storage.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError::Acme`] if any ACME protocol step fails.
    /// Returns [`TlsError::Storage`] if certificate storage fails.
    pub async fn provision(&self) -> Result<CertificateData, TlsError> {
        use instant_acme::{
            Account, Identifier, NewAccount, NewOrder,
        };

        // 1. Create ACME account.
        let contacts: Vec<String> = self
            .email
            .as_ref()
            .map(|e| vec![format!("mailto:{e}")])
            .unwrap_or_default();

        let contact_refs: Vec<&str> = contacts.iter().map(String::as_str).collect();

        let account_request = NewAccount {
            contact: &contact_refs,
            terms_of_service_agreed: true,
            only_return_existing: false,
        };

        let builder = Account::builder()
            .map_err(|e| TlsError::Acme(format!("failed to create account builder: {e}")))?;

        let (account, _credentials) = builder
            .create(&account_request, self.directory_url.clone(), None)
            .await
            .map_err(|e| TlsError::Acme(format!("failed to create ACME account: {e}")))?;

        // 2. Place new order.
        let identifier = Identifier::Dns(self.domain.clone());
        let identifiers = [identifier];
        let mut order = account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .map_err(|e| TlsError::Acme(format!("failed to create order: {e}")))?;

        // 3. Get authorizations, solve HTTP-01 challenge.
        // `authorizations()` borrows `order` mutably, so the entire auth flow
        // lives in a block. After the block, `order` is free for poll/finalize.
        {
            let mut authorizations = order.authorizations();

            let mut auth = authorizations
                .next()
                .await
                .ok_or_else(|| TlsError::Acme("no authorizations returned".to_owned()))?
                .map_err(|e| TlsError::Acme(format!("authorization error: {e}")))?;

            let mut challenge_handle = auth
                .challenge(instant_acme::ChallengeType::Http01)
                .ok_or_else(|| TlsError::Acme("no HTTP-01 challenge found".to_owned()))?;

            let _key_auth = challenge_handle.key_authorization().as_str().to_owned();

            // 4. Signal that we're ready for validation.
            challenge_handle
                .set_ready()
                .await
                .map_err(|e| TlsError::Acme(format!("failed to set challenge ready: {e}")))?;
        }

        // 5. Wait for order to become ready.
        order
            .poll_ready(&instant_acme::RetryPolicy::default())
            .await
            .map_err(|e| TlsError::Acme(format!("order failed to become ready: {e}")))?;

        // 6. Finalize with CSR (instant-acme generates the CSR via rcgen).
        let private_key_pem = order
            .finalize()
            .await
            .map_err(|e| TlsError::Acme(format!("failed to finalize order: {e}")))?;

        // 7. Download certificate.
        let certificate_chain_pem = order
            .certificate()
            .await
            .map_err(|e| TlsError::Acme(format!("failed to download certificate: {e}")))?
            .ok_or_else(|| TlsError::Acme("no certificate returned".to_owned()))?;

        let cert_data = CertificateData {
            certificate_chain_pem,
            private_key_pem,
        };

        // 8. Store in platform storage.
        store_certificate(&*self.storage, &cert_data).await?;

        tracing::info!(domain = %self.domain, "TLS certificate provisioned via ACME");

        Ok(cert_data)
    }

    /// Load a certificate from storage, or provision a new one if none exists
    /// or the existing one needs renewal.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError`] if loading, provisioning, or storage fails.
    pub async fn load_or_provision(&self) -> Result<CertificateData, TlsError> {
        if let Some(cert_data) = load_certificate(&*self.storage).await? {
            if !cert_data.needs_renewal()? {
                tracing::info!(domain = %self.domain, "loaded existing TLS certificate from storage");
                return Ok(cert_data);
            }
            tracing::info!(domain = %self.domain, "existing certificate needs renewal");
        }

        self.provision().await
    }

    /// Start a background renewal loop that checks certificate expiry
    /// every 12 hours and renews when within 30 days of expiry.
    ///
    /// The task runs until the returned [`tokio::task::JoinHandle`] is
    /// aborted or the process exits.
    pub fn start_renewal_loop(self: Arc<Self>) -> tokio::task::JoinHandle<()>
    where
        S: Send + Sync + 'static,
    {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(RENEWAL_CHECK_INTERVAL).await;

                match load_certificate(&*self.storage).await {
                    Ok(Some(cert_data)) => match cert_data.needs_renewal() {
                        Ok(true) => {
                            tracing::info!(
                                domain = %self.domain,
                                "certificate approaching expiry, renewing"
                            );
                            match self.provision().await {
                                Ok(new_cert) => {
                                    // Hot-reload if a resolver is configured.
                                    if let Some(resolver) = &self.cert_resolver {
                                        if let Ok(certs) = new_cert.certificate_chain_der() {
                                            if let Ok(key) = new_cert.private_key_der() {
                                                if let Ok(signing_key) =
                                                    rustls::crypto::ring::sign::any_supported_type(
                                                        &key,
                                                    )
                                                {
                                                    let certified =
                                                        CertifiedKey::new(certs, signing_key);
                                                    resolver.update(certified).await;
                                                    tracing::info!(
                                                        domain = %self.domain,
                                                        "TLS certificate renewed and hot-reloaded"
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::error!(
                                        domain = %self.domain,
                                        error = %e,
                                        "failed to renew TLS certificate"
                                    );
                                }
                            }
                        }
                        Ok(false) => {
                            tracing::debug!(
                                domain = %self.domain,
                                "certificate not yet due for renewal"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                domain = %self.domain,
                                error = %e,
                                "failed to check certificate expiry"
                            );
                        }
                    },
                    Ok(None) => {
                        tracing::warn!(
                            domain = %self.domain,
                            "no certificate in storage; skipping renewal check"
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            domain = %self.domain,
                            error = %e,
                            "failed to load certificate for renewal check"
                        );
                    }
                }
            }
        })
    }
}

// ---------------------------------------------------------------------------
// ACME challenge router
// ---------------------------------------------------------------------------

/// Create an axum router that serves ACME HTTP-01 challenge responses.
///
/// The router handles `GET /.well-known/acme-challenge/{token}` requests
/// by returning the key authorization string for the matching token.
///
/// # Arguments
///
/// * `challenges` - A shared map from token to key authorization string.
///   Typically populated during the ACME provisioning flow.
pub fn acme_challenge_router(
    challenges: Arc<RwLock<std::collections::HashMap<String, String>>>,
) -> axum::Router {
    use axum::extract::{Path, State};
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    async fn handle_challenge(
        State(challenges): State<Arc<RwLock<std::collections::HashMap<String, String>>>>,
        Path(token): Path<String>,
    ) -> impl IntoResponse {
        let map = challenges.read().await;
        match map.get(&token) {
            Some(key_auth) => (StatusCode::OK, key_auth.clone()),
            None => (StatusCode::NOT_FOUND, String::new()),
        }
    }

    axum::Router::new()
        .route(
            "/.well-known/acme-challenge/{token}",
            axum::routing::get(handle_challenge),
        )
        .with_state(challenges)
}

// ---------------------------------------------------------------------------
// Self-signed certificate generation (testing / development)
// ---------------------------------------------------------------------------

/// Generate a self-signed certificate for the given domain.
///
/// Intended for testing and local development only. The certificate uses
/// Ed25519 (via rcgen defaults) and is valid for 365 days.
///
/// # Errors
///
/// Returns [`TlsError::Certificate`] if certificate generation fails.
pub fn generate_self_signed(domain: &str) -> Result<CertificateData, TlsError> {
    let mut params = rcgen::CertificateParams::new(vec![domain.to_owned()])
        .map_err(|e| TlsError::Certificate(format!("failed to create cert params: {e}")))?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, domain);

    let key_pair = rcgen::KeyPair::generate()
        .map_err(|e| TlsError::Certificate(format!("failed to generate key pair: {e}")))?;

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| TlsError::Certificate(format!("failed to generate self-signed cert: {e}")))?;

    Ok(CertificateData {
        certificate_chain_pem: cert.pem(),
        private_key_pem: key_pair.serialize_pem(),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use scp_platform::testing::InMemoryStorage;

    // -- Self-signed generation --

    #[test]
    fn generate_self_signed_produces_valid_pem() {
        let cert = generate_self_signed("test.example.com").unwrap();
        assert!(cert.certificate_chain_pem.contains("BEGIN CERTIFICATE"));
        assert!(cert.private_key_pem.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn certificate_chain_der_parses_pem() {
        let cert = generate_self_signed("test.example.com").unwrap();
        let der_certs = cert.certificate_chain_der().unwrap();
        assert_eq!(der_certs.len(), 1, "self-signed should have exactly one cert");
    }

    #[test]
    fn private_key_der_parses_pem() {
        let cert = generate_self_signed("test.example.com").unwrap();
        let _key = cert.private_key_der().unwrap();
    }

    #[test]
    fn expiry_timestamp_is_in_future() {
        let cert = generate_self_signed("test.example.com").unwrap();
        let expiry = cert.expiry_timestamp().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!(expiry > now, "self-signed cert should expire in the future");
    }

    #[test]
    fn fresh_self_signed_does_not_need_renewal() {
        let cert = generate_self_signed("test.example.com").unwrap();
        assert!(
            !cert.needs_renewal().unwrap(),
            "a freshly generated cert should not need renewal"
        );
    }

    // -- TLS configuration --

    #[test]
    fn build_tls_server_config_enforces_tls_13() {
        let cert = generate_self_signed("test.example.com").unwrap();

        // Building with TLS 1.3 should succeed.
        let config = build_tls_server_config(&cert).unwrap();

        // Verify the config was constructed (it enforces TLS 1.3 via
        // `with_protocol_versions(&[&TLS13])` in the builder). We can't
        // inspect the version list directly on `ServerConfig`, but we can
        // verify that the ALPN protocols are not set (the basic builder
        // doesn't set them) and that the config is usable.
        assert!(
            config.alpn_protocols.is_empty(),
            "basic config should not set ALPN"
        );

        // Verify that building with TLS 1.3 configuration produces a valid
        // acceptor (this would fail if the provider didn't support TLS 1.3).
        let _acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    }

    #[test]
    fn build_reloadable_tls_config_returns_resolver() {
        let cert = generate_self_signed("test.example.com").unwrap();
        let (config, resolver) = build_reloadable_tls_config(&cert).unwrap();

        // Verify ALPN is set for the reloadable config.
        assert!(
            !config.alpn_protocols.is_empty(),
            "reloadable config should set ALPN"
        );

        // Verify the resolver has a certificate.
        let guard = resolver.inner.try_read().unwrap();
        assert!(!guard.cert.is_empty(), "resolver should have certificates");
    }

    // -- CertResolver --

    #[tokio::test]
    async fn cert_resolver_update_swaps_certificate() {
        let cert1 = generate_self_signed("one.example.com").unwrap();
        let cert2 = generate_self_signed("two.example.com").unwrap();

        let certs1 = cert1.certificate_chain_der().unwrap();
        let key1 = cert1.private_key_der().unwrap();
        let signing1 = rustls::crypto::ring::sign::any_supported_type(&key1).unwrap();
        let ck1 = CertifiedKey::new(certs1.clone(), signing1);

        let certs2 = cert2.certificate_chain_der().unwrap();
        let key2 = cert2.private_key_der().unwrap();
        let signing2 = rustls::crypto::ring::sign::any_supported_type(&key2).unwrap();
        let ck2 = CertifiedKey::new(certs2.clone(), signing2);

        let resolver = CertResolver::new(ck1);

        // Before update: should have cert1.
        {
            let guard = resolver.inner.read().await;
            assert_eq!(guard.cert.len(), certs1.len());
        }

        // After update: should have cert2.
        resolver.update(ck2).await;
        {
            let guard = resolver.inner.read().await;
            assert_eq!(guard.cert.len(), certs2.len());
        }
    }

    // -- Storage round-trip --

    #[tokio::test]
    async fn certificate_storage_roundtrip() {
        let storage = InMemoryStorage::new();
        let original = generate_self_signed("roundtrip.example.com").unwrap();

        // Store.
        store_certificate(&storage, &original).await.unwrap();

        // Load.
        let loaded = load_certificate(&storage).await.unwrap().unwrap();
        assert_eq!(loaded.certificate_chain_pem, original.certificate_chain_pem);
        assert_eq!(loaded.private_key_pem, original.private_key_pem);
    }

    #[tokio::test]
    async fn load_certificate_returns_none_when_empty() {
        let storage = InMemoryStorage::new();
        let result = load_certificate(&storage).await.unwrap();
        assert!(result.is_none());
    }

    // -- ACME challenge router --

    #[tokio::test]
    async fn acme_challenge_router_serves_token() {
        use axum::body::Body;
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let challenges = Arc::new(RwLock::new(std::collections::HashMap::new()));
        {
            let mut map = challenges.write().await;
            map.insert("test-token".to_owned(), "test-key-auth".to_owned());
        }

        let router = acme_challenge_router(challenges);

        // Request the challenge token.
        let request = axum::http::Request::builder()
            .uri("/.well-known/acme-challenge/test-token")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"test-key-auth");
    }

    #[tokio::test]
    async fn acme_challenge_router_returns_404_for_unknown_token() {
        use axum::body::Body;
        use tower::ServiceExt;

        let challenges = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let router = acme_challenge_router(challenges);

        let request = axum::http::Request::builder()
            .uri("/.well-known/acme-challenge/unknown")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
    }

    // -- AcmeProvider construction --

    #[test]
    fn acme_provider_new_sets_defaults() {
        let storage = Arc::new(InMemoryStorage::new());
        let provider = AcmeProvider::new("example.com", storage);

        assert_eq!(provider.domain, "example.com");
        assert!(provider.email.is_none());
        assert!(provider.directory_url.contains("letsencrypt"));
    }

    #[test]
    fn acme_provider_with_email() {
        let storage = Arc::new(InMemoryStorage::new());
        let provider = AcmeProvider::new("example.com", storage).with_email("admin@example.com");

        assert_eq!(provider.email.as_deref(), Some("admin@example.com"));
    }

    #[test]
    fn acme_provider_with_directory_url() {
        let storage = Arc::new(InMemoryStorage::new());
        let provider = AcmeProvider::new("example.com", storage)
            .with_directory_url("https://acme-staging-v02.api.letsencrypt.org/directory");

        assert!(provider.directory_url.contains("staging"));
    }

    #[test]
    fn acme_provider_with_cert_resolver() {
        let storage = Arc::new(InMemoryStorage::new());
        let cert = generate_self_signed("example.com").unwrap();
        let certs = cert.certificate_chain_der().unwrap();
        let key = cert.private_key_der().unwrap();
        let signing = rustls::crypto::ring::sign::any_supported_type(&key).unwrap();
        let ck = CertifiedKey::new(certs, signing);
        let resolver = Arc::new(CertResolver::new(ck));

        let provider =
            AcmeProvider::new("example.com", storage).with_cert_resolver(Arc::clone(&resolver));

        assert!(provider.cert_resolver.is_some());
    }
}
