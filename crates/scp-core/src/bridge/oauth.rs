//! OAuth 2.0 reference binding for bridge credential management.
//!
//! Implements the OAuth 2.0 Authorization Code + PKCE flow specified in
//! §12.11.3 for bridges that authenticate via OAuth (approximately 80% of
//! major platforms). The implementation is transport-independent: HTTP
//! operations are abstracted behind the [`OAuthHttpClient`] trait so that
//! `scp-core` does not depend on any specific HTTP library.
//!
//! # Architecture
//!
//! - [`OAuthConfig`] -- Static OAuth endpoint and client configuration.
//! - [`OAuthHttpClient`] -- Async trait for HTTP operations (token exchange,
//!   refresh, revocation).
//! - [`OAuthCredentialManager`] -- Orchestrates the full OAuth lifecycle
//!   (PKCE generation, authorization URL, token exchange, refresh with
//!   exponential backoff, revocation per RFC 7009).
//! - [`PkceChallenge`] -- PKCE S256 code verifier and challenge pair.
//! - [`OAuthTokenResponse`] -- Deserialized token endpoint response.
//!
//! # Scope Minimization (§12.11.3)
//!
//! OAuth scopes are mode-aware:
//! - [`BridgeMode::Relay`] -- read-only scopes.
//! - [`BridgeMode::Puppet`] -- read + write scopes.
//! - [`BridgeMode::Api`] -- platform-determined scopes.
//! - [`BridgeMode::Cooperative`] -- typically no OAuth needed.
//!
//! See spec §12.11.3 and ADR-023 in `.docs/adrs/phase-5.md`.

use std::fmt;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::BridgeMode;
use super::credentials::{
    BridgeCredentialStore, CredentialError, CredentialType,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default refresh threshold: refresh when 80% of token lifetime elapsed.
const DEFAULT_REFRESH_THRESHOLD_PERCENT: u64 = 80;

/// Initial backoff delay for token refresh retries.
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);

/// Maximum backoff delay for token refresh retries.
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// Maximum number of retry attempts for token refresh.
const MAX_RETRIES: u32 = 5;

/// PKCE code verifier length in bytes (before base64url encoding).
/// RFC 7636 recommends 32 bytes minimum; we use 32 bytes (produces 43
/// base64url characters, within the 43-128 range).
const PKCE_VERIFIER_LENGTH: usize = 32;

// ---------------------------------------------------------------------------
// OAuthError
// ---------------------------------------------------------------------------

/// Errors produced by OAuth operations.
#[derive(Debug, thiserror::Error)]
pub enum OAuthError {
    /// Token exchange or refresh HTTP request failed.
    #[error("OAuth HTTP request failed: {reason}")]
    HttpError {
        /// Description of the failure.
        reason: String,
    },

    /// Token endpoint returned an error response.
    #[error("OAuth token endpoint error: {error} ({error_description})")]
    TokenEndpointError {
        /// OAuth error code (e.g., `invalid_grant`).
        error: String,
        /// Human-readable error description.
        error_description: String,
    },

    /// Token refresh failed after all retry attempts.
    #[error("token refresh exhausted {retries} retries: {last_error}")]
    RefreshExhausted {
        /// Number of retries attempted.
        retries: u32,
        /// The last error encountered.
        last_error: String,
    },

    /// Credential store operation failed.
    #[error("credential store error: {0}")]
    CredentialError(#[from] CredentialError),

    /// Token revocation failed.
    #[error("token revocation failed: {reason}")]
    RevocationError {
        /// Description of the failure.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// OAuthConfig
// ---------------------------------------------------------------------------

/// Static OAuth 2.0 endpoint and client configuration for a bridge.
///
/// Captures the platform-specific OAuth parameters needed to execute the
/// Authorization Code + PKCE flow (§12.11.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthConfig {
    /// OAuth client ID issued by the platform.
    pub client_id: String,

    /// Redirect URI registered with the platform for the callback.
    pub redirect_uri: String,

    /// Platform's token endpoint URL (for code exchange and refresh).
    pub token_endpoint: String,

    /// Platform's authorization endpoint URL (for user redirect).
    pub authorization_endpoint: String,

    /// Platform's token revocation endpoint URL (RFC 7009).
    ///
    /// `None` if the platform does not support RFC 7009 revocation.
    pub revocation_endpoint: Option<String>,

    /// OAuth scopes to request.
    ///
    /// These should be set according to scope minimization rules
    /// (§12.11.3): Relay mode → read-only, Puppet mode → read+write.
    pub scopes: Vec<String>,
}

impl OAuthConfig {
    /// Returns the scopes as a space-separated string suitable for OAuth
    /// URL parameters.
    #[must_use]
    pub fn scope_string(&self) -> String {
        self.scopes.join(" ")
    }
}

// ---------------------------------------------------------------------------
// PkceChallenge
// ---------------------------------------------------------------------------

/// PKCE S256 code verifier and challenge pair (RFC 7636).
///
/// The code verifier is a cryptographically random string; the code
/// challenge is its SHA-256 hash, base64url-encoded without padding.
#[derive(Debug, Clone)]
pub struct PkceChallenge {
    /// The code verifier (base64url-encoded random bytes).
    pub code_verifier: String,

    /// The S256 code challenge (base64url(SHA-256(code_verifier))).
    pub code_challenge: String,
}

/// Generates a PKCE S256 code verifier and challenge pair.
///
/// Uses `OsRng` for cryptographically secure random bytes. The verifier
/// is 32 random bytes base64url-encoded (43 characters), and the challenge
/// is `base64url(SHA-256(verifier))`.
#[must_use]
pub fn generate_pkce() -> PkceChallenge {
    let mut verifier_bytes = [0u8; PKCE_VERIFIER_LENGTH];
    OsRng.fill_bytes(&mut verifier_bytes);

    let code_verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);

    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let digest = hasher.finalize();
    let code_challenge = URL_SAFE_NO_PAD.encode(digest);

    PkceChallenge {
        code_verifier,
        code_challenge,
    }
}

// ---------------------------------------------------------------------------
// OAuthTokenResponse
// ---------------------------------------------------------------------------

/// Deserialized response from an OAuth 2.0 token endpoint.
///
/// Returned by [`OAuthHttpClient::exchange_code`] and
/// [`OAuthHttpClient::refresh_token`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthTokenResponse {
    /// The access token issued by the platform.
    pub access_token: String,

    /// The refresh token, if the platform issued one.
    pub refresh_token: Option<String>,

    /// Lifetime of the access token in seconds.
    ///
    /// `None` if the platform does not include `expires_in` (treated as
    /// non-expiring — refresh is caller's responsibility).
    pub expires_in: Option<u64>,

    /// Token type (typically `"Bearer"`).
    pub token_type: Option<String>,
}

// ---------------------------------------------------------------------------
// OAuthHttpClient trait
// ---------------------------------------------------------------------------

/// Async trait abstracting the HTTP operations required for the OAuth 2.0
/// Authorization Code + PKCE flow.
///
/// Implementations provide the actual HTTP calls (e.g., via `reqwest`,
/// `hyper`, or a test mock). This keeps `scp-core` transport-independent
/// per the protocol's transport independence tenet.
pub trait OAuthHttpClient: Send + Sync {
    /// Exchange an authorization code for tokens at the token endpoint.
    ///
    /// Sends a POST request with `grant_type=authorization_code`,
    /// `code`, `redirect_uri`, `client_id`, `code_verifier`.
    fn exchange_code(
        &self,
        config: &OAuthConfig,
        authorization_code: &str,
        code_verifier: &str,
    ) -> impl std::future::Future<Output = Result<OAuthTokenResponse, OAuthError>> + Send;

    /// Refresh an access token using a refresh token.
    ///
    /// Sends a POST request with `grant_type=refresh_token`,
    /// `refresh_token`, `client_id`.
    fn refresh_token(
        &self,
        config: &OAuthConfig,
        refresh_token: &str,
    ) -> impl std::future::Future<Output = Result<OAuthTokenResponse, OAuthError>> + Send;

    /// Revoke a token at the platform's RFC 7009 revocation endpoint.
    ///
    /// Sends a POST request with `token` and `token_type_hint`.
    /// `token_type_hint` is either `"access_token"` or `"refresh_token"`.
    fn revoke_token(
        &self,
        revocation_endpoint: &str,
        token: &str,
        token_type_hint: &str,
    ) -> impl std::future::Future<Output = Result<(), OAuthError>> + Send;
}

// ---------------------------------------------------------------------------
// Authorization URL construction
// ---------------------------------------------------------------------------

/// Builds the OAuth 2.0 authorization URL for user redirect.
///
/// Constructs a URL with:
/// - `response_type=code`
/// - `client_id`
/// - `redirect_uri`
/// - `scope` (space-separated)
/// - `code_challenge` (S256)
/// - `code_challenge_method=S256`
/// - Optional `state` parameter for CSRF protection.
///
/// Callers should redirect the user's browser to this URL to initiate the
/// OAuth flow.
#[must_use]
pub fn build_authorization_url(
    config: &OAuthConfig,
    pkce: &PkceChallenge,
    state: Option<&str>,
) -> String {
    let mut url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&code_challenge={}&code_challenge_method=S256",
        config.authorization_endpoint,
        percent_encode(&config.client_id),
        percent_encode(&config.redirect_uri),
        percent_encode(&config.scope_string()),
        percent_encode(&pkce.code_challenge),
    );

    if let Some(state_val) = state {
        url.push_str("&state=");
        url.push_str(&percent_encode(state_val));
    }

    url
}

/// Minimal percent-encoding for OAuth URL parameters.
///
/// Encodes characters that are not unreserved per RFC 3986
/// (ALPHA / DIGIT / "-" / "." / "_" / "~").
fn percent_encode(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                use std::fmt::Write;
                let _ = write!(encoded, "%{byte:02X}");
            }
        }
    }
    encoded
}

// ---------------------------------------------------------------------------
// Scope helpers
// ---------------------------------------------------------------------------

/// Returns recommended read-only scopes for Relay mode bridges.
///
/// These are generic OAuth scope names; platform-specific implementations
/// should override with the platform's actual scope identifiers.
#[must_use]
pub fn relay_mode_scopes() -> Vec<String> {
    vec![
        "read:messages".to_owned(),
        "read:users".to_owned(),
    ]
}

/// Returns recommended read+write scopes for Puppet mode bridges.
///
/// These are generic OAuth scope names; platform-specific implementations
/// should override with the platform's actual scope identifiers.
#[must_use]
pub fn puppet_mode_scopes() -> Vec<String> {
    vec![
        "read:messages".to_owned(),
        "write:messages".to_owned(),
        "read:users".to_owned(),
    ]
}

/// Returns recommended scopes for the given bridge mode.
///
/// - [`BridgeMode::Relay`] → read-only scopes.
/// - [`BridgeMode::Puppet`] → read+write scopes.
/// - [`BridgeMode::Api`] → empty (platform-specific, must be provided).
/// - [`BridgeMode::Cooperative`] → empty (typically no OAuth needed).
#[must_use]
pub fn scopes_for_mode(mode: &BridgeMode) -> Vec<String> {
    match mode {
        BridgeMode::Relay => relay_mode_scopes(),
        BridgeMode::Puppet => puppet_mode_scopes(),
        BridgeMode::Api | BridgeMode::Cooperative => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// OAuthCredentialManager
// ---------------------------------------------------------------------------

/// Orchestrates the full OAuth 2.0 lifecycle for a bridge connector.
///
/// Combines an [`OAuthHttpClient`] for HTTP operations with a
/// [`BridgeCredentialStore`] for encrypted token persistence. Provides:
///
/// - Authorization URL generation with PKCE.
/// - Authorization code exchange with automatic token storage.
/// - Token refresh with exponential backoff (initial 1s, max 60s, 5 retries).
/// - Token revocation per RFC 7009 with credential store cleanup.
/// - Expiry tracking with configurable refresh threshold (default 80%).
///
/// See spec §12.11.3 and ADR-023.
pub struct OAuthCredentialManager<H: OAuthHttpClient, S: BridgeCredentialStore> {
    /// OAuth endpoint and client configuration.
    pub config: OAuthConfig,

    /// HTTP client for token endpoint calls.
    http_client: H,

    /// Encrypted credential store for token persistence.
    credential_store: S,

    /// Percentage of token lifetime at which to trigger refresh (0-100).
    refresh_threshold_percent: u64,
}

impl<H: OAuthHttpClient, S: BridgeCredentialStore> OAuthCredentialManager<H, S> {
    /// Creates a new `OAuthCredentialManager`.
    ///
    /// # Arguments
    ///
    /// - `config` -- OAuth endpoint and client configuration.
    /// - `http_client` -- HTTP client for token endpoint calls.
    /// - `credential_store` -- Encrypted credential store for token persistence.
    #[must_use]
    pub const fn new(config: OAuthConfig, http_client: H, credential_store: S) -> Self {
        Self {
            config,
            http_client,
            credential_store,
            refresh_threshold_percent: DEFAULT_REFRESH_THRESHOLD_PERCENT,
        }
    }

    /// Sets the refresh threshold percentage.
    ///
    /// The access token will be refreshed when this percentage of its
    /// lifetime has elapsed. Default is 80%.
    #[must_use]
    pub fn with_refresh_threshold(mut self, percent: u64) -> Self {
        self.refresh_threshold_percent = percent.min(100);
        self
    }

    /// Generates a PKCE challenge and builds the authorization URL.
    ///
    /// Returns `(authorization_url, pkce_challenge)`. The caller should:
    /// 1. Redirect the user to `authorization_url`.
    /// 2. Retain `pkce_challenge.code_verifier` for the code exchange step.
    #[must_use]
    pub fn start_authorization(&self, state: Option<&str>) -> (String, PkceChallenge) {
        let pkce = generate_pkce();
        let url = build_authorization_url(&self.config, &pkce, state);
        (url, pkce)
    }

    /// Exchanges an authorization code for tokens and stores them.
    ///
    /// Calls the token endpoint via [`OAuthHttpClient::exchange_code`],
    /// then stores both the access token and refresh token (if present)
    /// via [`BridgeCredentialStore::provision`].
    ///
    /// # Errors
    ///
    /// Returns [`OAuthError::HttpError`] or [`OAuthError::TokenEndpointError`]
    /// if the token exchange fails. Returns [`OAuthError::CredentialError`]
    /// if token storage fails.
    pub async fn exchange_code(
        &self,
        bridge_id: &str,
        authorization_code: &str,
        code_verifier: &str,
        operator_key_material: &[u8],
    ) -> Result<OAuthTokenResponse, OAuthError> {
        let response = self
            .http_client
            .exchange_code(&self.config, authorization_code, code_verifier)
            .await?;

        // Store access token.
        self.credential_store
            .provision(
                bridge_id,
                CredentialType::OAuthAccessToken,
                response.access_token.as_bytes(),
                operator_key_material,
            )
            .await?;

        // Store refresh token if present.
        if let Some(ref refresh_token) = response.refresh_token {
            self.credential_store
                .provision(
                    bridge_id,
                    CredentialType::OAuthRefreshToken,
                    refresh_token.as_bytes(),
                    operator_key_material,
                )
                .await?;
        }

        Ok(response)
    }

    /// Refreshes the access token using the stored refresh token.
    ///
    /// Retrieves the refresh token from the credential store, calls the
    /// token endpoint, and rotates the stored access token. If the platform
    /// issues a new refresh token, that is also rotated.
    ///
    /// On failure, retries with exponential backoff (initial 1s, max 60s,
    /// up to 5 retries) per §12.11.3.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthError::RefreshExhausted`] if all retries fail.
    /// Returns [`OAuthError::CredentialError`] if the refresh token is
    /// not found or the credential store operation fails.
    pub async fn refresh_access_token(
        &self,
        bridge_id: &str,
        operator_key_material: &[u8],
    ) -> Result<OAuthTokenResponse, OAuthError> {
        // Retrieve the stored refresh token.
        let refresh_token_bytes = self
            .credential_store
            .retrieve(
                bridge_id,
                &CredentialType::OAuthRefreshToken,
                operator_key_material,
            )
            .await?;

        let refresh_token = String::from_utf8(refresh_token_bytes.to_vec()).map_err(|e| {
            OAuthError::HttpError {
                reason: format!("stored refresh token is not valid UTF-8: {e}"),
            }
        })?;

        // Retry with exponential backoff.
        let mut last_error = String::new();
        let mut backoff = INITIAL_BACKOFF;

        for attempt in 0..=MAX_RETRIES {
            match self
                .http_client
                .refresh_token(&self.config, &refresh_token)
                .await
            {
                Ok(response) => {
                    // Rotate the stored access token.
                    self.credential_store
                        .rotate(
                            bridge_id,
                            &CredentialType::OAuthAccessToken,
                            response.access_token.as_bytes(),
                            operator_key_material,
                        )
                        .await?;

                    // Rotate refresh token if a new one was issued.
                    if let Some(ref new_refresh) = response.refresh_token {
                        self.credential_store
                            .rotate(
                                bridge_id,
                                &CredentialType::OAuthRefreshToken,
                                new_refresh.as_bytes(),
                                operator_key_material,
                            )
                            .await?;
                    }

                    return Ok(response);
                }
                Err(e) => {
                    last_error = e.to_string();
                    if attempt < MAX_RETRIES {
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(MAX_BACKOFF);
                    }
                }
            }
        }

        Err(OAuthError::RefreshExhausted {
            retries: MAX_RETRIES,
            last_error,
        })
    }

    /// Returns whether the access token should be refreshed based on its
    /// expiry and the configured refresh threshold.
    ///
    /// Returns `true` if the configured percentage of the token's lifetime
    /// has elapsed. Returns `false` if:
    /// - `issued_at` or `expires_in` is `None` (no expiry tracking).
    /// - The token has not yet reached the refresh threshold.
    #[must_use]
    pub const fn should_refresh(&self, issued_at: Option<u64>, expires_in: Option<u64>, now: u64) -> bool {
        match (issued_at, expires_in) {
            (Some(issued), Some(lifetime)) if lifetime > 0 => {
                let threshold_secs = lifetime * self.refresh_threshold_percent / 100;
                let elapsed = now.saturating_sub(issued);
                elapsed >= threshold_secs
            }
            _ => false,
        }
    }

    /// Revokes all OAuth tokens for a bridge and destroys local copies.
    ///
    /// Per §12.11.3 and RFC 7009:
    /// 1. Calls the platform's revocation endpoint for both access and
    ///    refresh tokens (if a revocation endpoint is configured).
    /// 2. Calls [`BridgeCredentialStore::revoke`] to overwrite local
    ///    token material with zeros and delete credential records.
    ///
    /// Revocation endpoint errors are logged but do not prevent local
    /// credential destruction — the local cleanup always proceeds.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthError::CredentialError`] if local credential
    /// destruction fails.
    pub async fn revoke_tokens(
        &self,
        bridge_id: &str,
        operator_key_material: &[u8],
    ) -> Result<(), OAuthError> {
        // Call platform revocation endpoint if configured.
        if let Some(ref revocation_endpoint) = self.config.revocation_endpoint {
            // Attempt to retrieve and revoke access token (best-effort).
            if let Some(token) = self
                .credential_store
                .retrieve(bridge_id, &CredentialType::OAuthAccessToken, operator_key_material)
                .await
                .ok()
                .and_then(|b| String::from_utf8(b.to_vec()).ok())
            {
                let _ = self.http_client.revoke_token(revocation_endpoint, &token, "access_token").await;
            }

            // Attempt to retrieve and revoke refresh token (best-effort).
            if let Some(token) = self
                .credential_store
                .retrieve(bridge_id, &CredentialType::OAuthRefreshToken, operator_key_material)
                .await
                .ok()
                .and_then(|b| String::from_utf8(b.to_vec()).ok())
            {
                let _ = self.http_client.revoke_token(revocation_endpoint, &token, "refresh_token").await;
            }
        }

        // Destroy local credential material (overwrite + delete).
        self.credential_store.revoke(bridge_id).await?;

        Ok(())
    }
}

impl<H: OAuthHttpClient, S: BridgeCredentialStore> fmt::Debug for OAuthCredentialManager<H, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthCredentialManager")
            .field("config", &self.config)
            .field("refresh_threshold_percent", &self.refresh_threshold_percent)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::significant_drop_tightening)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use tokio::sync::Mutex;

    use super::*;
    use crate::bridge::credentials::InMemoryCredentialStore;

    /// Shared operator key material for tests.
    const TEST_OPERATOR_KEY: &[u8; 32] = b"operator-key-material-32-bytes!!";

    // -------------------------------------------------------------------
    // PKCE tests
    // -------------------------------------------------------------------

    #[test]
    fn generate_pkce_produces_valid_s256_challenge() {
        let pkce = generate_pkce();

        // Verifier should be base64url-encoded (43 chars for 32 bytes).
        assert_eq!(pkce.code_verifier.len(), 43);

        // Challenge should be base64url(SHA-256(verifier)).
        let mut hasher = Sha256::new();
        hasher.update(pkce.code_verifier.as_bytes());
        let expected_challenge = URL_SAFE_NO_PAD.encode(hasher.finalize());

        assert_eq!(pkce.code_challenge, expected_challenge);
    }

    #[test]
    fn generate_pkce_produces_unique_verifiers() {
        let pkce1 = generate_pkce();
        let pkce2 = generate_pkce();

        assert_ne!(
            pkce1.code_verifier, pkce2.code_verifier,
            "successive PKCE generations must produce unique verifiers"
        );
    }

    #[test]
    fn pkce_challenge_method_is_s256() {
        let pkce = generate_pkce();

        // Verify that re-hashing the verifier produces the challenge
        // (confirming S256 method).
        let mut hasher = Sha256::new();
        hasher.update(pkce.code_verifier.as_bytes());
        let digest = hasher.finalize();
        let recomputed = URL_SAFE_NO_PAD.encode(digest);

        assert_eq!(pkce.code_challenge, recomputed);
    }

    // -------------------------------------------------------------------
    // Authorization URL tests
    // -------------------------------------------------------------------

    fn test_config() -> OAuthConfig {
        OAuthConfig {
            client_id: "my-client-id".to_owned(),
            redirect_uri: "https://bridge.example.com/callback".to_owned(),
            token_endpoint: "https://platform.example.com/oauth/token".to_owned(),
            authorization_endpoint: "https://platform.example.com/oauth/authorize".to_owned(),
            revocation_endpoint: Some("https://platform.example.com/oauth/revoke".to_owned()),
            scopes: vec!["read:messages".to_owned(), "read:users".to_owned()],
        }
    }

    #[test]
    fn build_authorization_url_contains_required_parameters() {
        let config = test_config();
        let pkce = generate_pkce();
        let url = build_authorization_url(&config, &pkce, None);

        assert!(url.starts_with(&config.authorization_endpoint));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("client_id=my-client-id"));
        assert!(url.contains(&format!("code_challenge={}", pkce.code_challenge)));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("redirect_uri="));
        assert!(url.contains("scope="));
    }

    #[test]
    fn build_authorization_url_includes_state_when_provided() {
        let config = test_config();
        let pkce = generate_pkce();
        let url = build_authorization_url(&config, &pkce, Some("csrf-token-123"));

        assert!(url.contains("state=csrf-token-123"));
    }

    #[test]
    fn build_authorization_url_omits_state_when_none() {
        let config = test_config();
        let pkce = generate_pkce();
        let url = build_authorization_url(&config, &pkce, None);

        assert!(!url.contains("state="));
    }

    // -------------------------------------------------------------------
    // Scope tests
    // -------------------------------------------------------------------

    #[test]
    fn relay_mode_scopes_are_read_only() {
        let scopes = scopes_for_mode(&BridgeMode::Relay);
        assert!(scopes.iter().all(|s| s.starts_with("read:")));
    }

    #[test]
    fn puppet_mode_scopes_include_write() {
        let scopes = scopes_for_mode(&BridgeMode::Puppet);
        assert!(scopes.iter().any(|s| s.starts_with("write:")));
        assert!(scopes.iter().any(|s| s.starts_with("read:")));
    }

    #[test]
    fn api_mode_scopes_are_empty() {
        let scopes = scopes_for_mode(&BridgeMode::Api);
        assert!(scopes.is_empty());
    }

    #[test]
    fn cooperative_mode_scopes_are_empty() {
        let scopes = scopes_for_mode(&BridgeMode::Cooperative);
        assert!(scopes.is_empty());
    }

    // -------------------------------------------------------------------
    // Percent-encoding tests
    // -------------------------------------------------------------------

    #[test]
    fn percent_encode_preserves_unreserved_characters() {
        assert_eq!(percent_encode("abc123"), "abc123");
        assert_eq!(percent_encode("a-b.c_d~e"), "a-b.c_d~e");
    }

    #[test]
    fn percent_encode_encodes_special_characters() {
        assert_eq!(percent_encode("a b"), "a%20b");
        assert_eq!(percent_encode("a+b"), "a%2Bb");
        assert_eq!(percent_encode("a=b&c=d"), "a%3Db%26c%3Dd");
    }

    // -------------------------------------------------------------------
    // Mock HTTP client for integration tests
    // -------------------------------------------------------------------

    /// Mock HTTP client that records calls and returns configured responses.
    struct MockOAuthHttpClient {
        exchange_response: Mutex<Option<Result<OAuthTokenResponse, OAuthError>>>,
        refresh_response: Mutex<Vec<Result<OAuthTokenResponse, OAuthError>>>,
        revoke_calls: Mutex<Vec<(String, String, String)>>,
        refresh_call_count: AtomicU32,
    }

    impl MockOAuthHttpClient {
        fn new() -> Self {
            Self {
                exchange_response: Mutex::new(None),
                refresh_response: Mutex::new(Vec::new()),
                revoke_calls: Mutex::new(Vec::new()),
                refresh_call_count: AtomicU32::new(0),
            }
        }

        async fn set_exchange_response(&self, response: Result<OAuthTokenResponse, OAuthError>) {
            *self.exchange_response.lock().await = Some(response);
        }

        async fn set_refresh_responses(&self, responses: Vec<Result<OAuthTokenResponse, OAuthError>>) {
            *self.refresh_response.lock().await = responses;
        }
    }

    impl OAuthHttpClient for MockOAuthHttpClient {
        async fn exchange_code(
            &self,
            _config: &OAuthConfig,
            _authorization_code: &str,
            _code_verifier: &str,
        ) -> Result<OAuthTokenResponse, OAuthError> {
            self.exchange_response
                .lock()
                .await
                .take()
                .unwrap_or_else(|| Err(OAuthError::HttpError {
                    reason: "no mock response configured".to_owned(),
                }))
        }

        async fn refresh_token(
            &self,
            _config: &OAuthConfig,
            _refresh_token: &str,
        ) -> Result<OAuthTokenResponse, OAuthError> {
            let idx = self.refresh_call_count.fetch_add(1, Ordering::SeqCst) as usize;
            let responses = self.refresh_response.lock().await;
            if idx < responses.len() {
                match &responses[idx] {
                    Ok(r) => Ok(r.clone()),
                    Err(e) => Err(OAuthError::HttpError {
                        reason: e.to_string(),
                    }),
                }
            } else {
                Err(OAuthError::HttpError {
                    reason: "no more mock responses".to_owned(),
                })
            }
        }

        async fn revoke_token(
            &self,
            revocation_endpoint: &str,
            token: &str,
            token_type_hint: &str,
        ) -> Result<(), OAuthError> {
            self.revoke_calls.lock().await.push((
                revocation_endpoint.to_owned(),
                token.to_owned(),
                token_type_hint.to_owned(),
            ));
            Ok(())
        }
    }

    // -------------------------------------------------------------------
    // OAuthCredentialManager integration tests
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn exchange_code_stores_tokens() {
        let mock = MockOAuthHttpClient::new();
        mock.set_exchange_response(Ok(OAuthTokenResponse {
            access_token: "access-abc".to_owned(),
            refresh_token: Some("refresh-xyz".to_owned()),
            expires_in: Some(3600),
            token_type: Some("Bearer".to_owned()),
        }))
        .await;

        let store = InMemoryCredentialStore::new();
        let manager = OAuthCredentialManager::new(test_config(), mock, store);

        let response = manager
            .exchange_code("bridge-001", "auth-code", "verifier", TEST_OPERATOR_KEY)
            .await
            .expect("exchange_code");

        assert_eq!(response.access_token, "access-abc");
        assert_eq!(response.refresh_token.as_deref(), Some("refresh-xyz"));

        // Verify tokens are stored.
        let access = manager
            .credential_store
            .retrieve(
                "bridge-001",
                &CredentialType::OAuthAccessToken,
                TEST_OPERATOR_KEY,
            )
            .await
            .expect("retrieve access token");
        assert_eq!(access.as_slice(), b"access-abc");

        let refresh = manager
            .credential_store
            .retrieve(
                "bridge-001",
                &CredentialType::OAuthRefreshToken,
                TEST_OPERATOR_KEY,
            )
            .await
            .expect("retrieve refresh token");
        assert_eq!(refresh.as_slice(), b"refresh-xyz");
    }

    #[tokio::test]
    async fn exchange_code_without_refresh_token_stores_only_access() {
        let mock = MockOAuthHttpClient::new();
        mock.set_exchange_response(Ok(OAuthTokenResponse {
            access_token: "access-only".to_owned(),
            refresh_token: None,
            expires_in: Some(3600),
            token_type: Some("Bearer".to_owned()),
        }))
        .await;

        let store = InMemoryCredentialStore::new();
        let manager = OAuthCredentialManager::new(test_config(), mock, store);

        manager
            .exchange_code("bridge-001", "auth-code", "verifier", TEST_OPERATOR_KEY)
            .await
            .expect("exchange_code");

        // Access token should be stored.
        let access = manager
            .credential_store
            .retrieve(
                "bridge-001",
                &CredentialType::OAuthAccessToken,
                TEST_OPERATOR_KEY,
            )
            .await;
        assert!(access.is_ok());

        // Refresh token should NOT be stored.
        let refresh = manager
            .credential_store
            .retrieve(
                "bridge-001",
                &CredentialType::OAuthRefreshToken,
                TEST_OPERATOR_KEY,
            )
            .await;
        assert!(matches!(refresh, Err(CredentialError::NotFound { .. })));
    }

    #[tokio::test]
    async fn refresh_access_token_rotates_stored_token() {
        let mock = MockOAuthHttpClient::new();

        // First, set up exchange response.
        mock.set_exchange_response(Ok(OAuthTokenResponse {
            access_token: "old-access".to_owned(),
            refresh_token: Some("refresh-token".to_owned()),
            expires_in: Some(3600),
            token_type: Some("Bearer".to_owned()),
        }))
        .await;

        // Set up refresh response.
        mock.set_refresh_responses(vec![Ok(OAuthTokenResponse {
            access_token: "new-access".to_owned(),
            refresh_token: None,
            expires_in: Some(3600),
            token_type: Some("Bearer".to_owned()),
        })])
        .await;

        let store = InMemoryCredentialStore::new();
        let manager = OAuthCredentialManager::new(test_config(), mock, store);

        // Exchange code first to populate store.
        manager
            .exchange_code("bridge-001", "auth-code", "verifier", TEST_OPERATOR_KEY)
            .await
            .expect("exchange_code");

        // Refresh.
        let response = manager
            .refresh_access_token("bridge-001", TEST_OPERATOR_KEY)
            .await
            .expect("refresh");

        assert_eq!(response.access_token, "new-access");

        // Verify stored access token was rotated.
        let access = manager
            .credential_store
            .retrieve(
                "bridge-001",
                &CredentialType::OAuthAccessToken,
                TEST_OPERATOR_KEY,
            )
            .await
            .expect("retrieve rotated access token");
        assert_eq!(access.as_slice(), b"new-access");
    }

    #[tokio::test]
    async fn refresh_with_new_refresh_token_rotates_both() {
        let mock = MockOAuthHttpClient::new();

        mock.set_exchange_response(Ok(OAuthTokenResponse {
            access_token: "old-access".to_owned(),
            refresh_token: Some("old-refresh".to_owned()),
            expires_in: Some(3600),
            token_type: Some("Bearer".to_owned()),
        }))
        .await;

        mock.set_refresh_responses(vec![Ok(OAuthTokenResponse {
            access_token: "new-access".to_owned(),
            refresh_token: Some("new-refresh".to_owned()),
            expires_in: Some(3600),
            token_type: Some("Bearer".to_owned()),
        })])
        .await;

        let store = InMemoryCredentialStore::new();
        let manager = OAuthCredentialManager::new(test_config(), mock, store);

        manager
            .exchange_code("bridge-001", "auth-code", "verifier", TEST_OPERATOR_KEY)
            .await
            .expect("exchange_code");

        manager
            .refresh_access_token("bridge-001", TEST_OPERATOR_KEY)
            .await
            .expect("refresh");

        // Both tokens should be rotated.
        let access = manager
            .credential_store
            .retrieve(
                "bridge-001",
                &CredentialType::OAuthAccessToken,
                TEST_OPERATOR_KEY,
            )
            .await
            .expect("retrieve");
        assert_eq!(access.as_slice(), b"new-access");

        let refresh = manager
            .credential_store
            .retrieve(
                "bridge-001",
                &CredentialType::OAuthRefreshToken,
                TEST_OPERATOR_KEY,
            )
            .await
            .expect("retrieve");
        assert_eq!(refresh.as_slice(), b"new-refresh");
    }

    #[tokio::test]
    async fn revoke_tokens_calls_revocation_endpoint_and_destroys_local() {
        let mock = MockOAuthHttpClient::new();

        mock.set_exchange_response(Ok(OAuthTokenResponse {
            access_token: "access-to-revoke".to_owned(),
            refresh_token: Some("refresh-to-revoke".to_owned()),
            expires_in: Some(3600),
            token_type: Some("Bearer".to_owned()),
        }))
        .await;

        let store = InMemoryCredentialStore::new();
        let manager = OAuthCredentialManager::new(test_config(), mock, store);

        manager
            .exchange_code("bridge-001", "auth-code", "verifier", TEST_OPERATOR_KEY)
            .await
            .expect("exchange_code");

        manager
            .revoke_tokens("bridge-001", TEST_OPERATOR_KEY)
            .await
            .expect("revoke_tokens");

        // Verify revocation endpoint was called for both tokens.
        {
            let calls = manager.http_client.revoke_calls.lock().await;
            assert_eq!(calls.len(), 2);
            assert_eq!(calls[0].1, "access-to-revoke");
            assert_eq!(calls[0].2, "access_token");
            assert_eq!(calls[1].1, "refresh-to-revoke");
            assert_eq!(calls[1].2, "refresh_token");
        }

        // Verify local credentials are destroyed.
        let result = manager
            .credential_store
            .retrieve(
                "bridge-001",
                &CredentialType::OAuthAccessToken,
                TEST_OPERATOR_KEY,
            )
            .await;
        assert!(matches!(result, Err(CredentialError::NotFound { .. })));
    }

    #[tokio::test]
    async fn revoke_tokens_without_revocation_endpoint_still_destroys_local() {
        let mock = MockOAuthHttpClient::new();

        mock.set_exchange_response(Ok(OAuthTokenResponse {
            access_token: "access-token".to_owned(),
            refresh_token: Some("refresh-token".to_owned()),
            expires_in: Some(3600),
            token_type: Some("Bearer".to_owned()),
        }))
        .await;

        let mut config = test_config();
        config.revocation_endpoint = None;

        let store = InMemoryCredentialStore::new();
        let manager = OAuthCredentialManager::new(config, mock, store);

        manager
            .exchange_code("bridge-001", "auth-code", "verifier", TEST_OPERATOR_KEY)
            .await
            .expect("exchange_code");

        manager
            .revoke_tokens("bridge-001", TEST_OPERATOR_KEY)
            .await
            .expect("revoke_tokens");

        // No revocation calls should have been made.
        {
            let calls = manager.http_client.revoke_calls.lock().await;
            assert!(calls.is_empty());
        }

        // Local credentials should still be destroyed.
        let result = manager
            .credential_store
            .retrieve(
                "bridge-001",
                &CredentialType::OAuthAccessToken,
                TEST_OPERATOR_KEY,
            )
            .await;
        assert!(matches!(result, Err(CredentialError::NotFound { .. })));
    }

    // -------------------------------------------------------------------
    // should_refresh tests
    // -------------------------------------------------------------------

    #[test]
    fn should_refresh_returns_true_when_threshold_exceeded() {
        let mock = MockOAuthHttpClient::new();
        let store = InMemoryCredentialStore::new();
        let manager = OAuthCredentialManager::new(test_config(), mock, store);

        // Token issued at t=1000, expires_in=3600, threshold=80% (2880s).
        // At t=3881 (2881s elapsed), should refresh.
        assert!(manager.should_refresh(Some(1000), Some(3600), 3881));
    }

    #[test]
    fn should_refresh_returns_false_before_threshold() {
        let mock = MockOAuthHttpClient::new();
        let store = InMemoryCredentialStore::new();
        let manager = OAuthCredentialManager::new(test_config(), mock, store);

        // Token issued at t=1000, expires_in=3600, threshold=80% (2880s).
        // At t=3879 (2879s elapsed), should NOT refresh.
        assert!(!manager.should_refresh(Some(1000), Some(3600), 3879));
    }

    #[test]
    fn should_refresh_returns_false_with_no_expiry() {
        let mock = MockOAuthHttpClient::new();
        let store = InMemoryCredentialStore::new();
        let manager = OAuthCredentialManager::new(test_config(), mock, store);

        assert!(!manager.should_refresh(Some(1000), None, 5000));
        assert!(!manager.should_refresh(None, Some(3600), 5000));
        assert!(!manager.should_refresh(None, None, 5000));
    }

    #[test]
    fn should_refresh_custom_threshold() {
        let mock = MockOAuthHttpClient::new();
        let store = InMemoryCredentialStore::new();
        let manager = OAuthCredentialManager::new(test_config(), mock, store)
            .with_refresh_threshold(50);

        // 50% of 3600 = 1800. At t=2801 (1801s elapsed), should refresh.
        assert!(manager.should_refresh(Some(1000), Some(3600), 2801));
        // At t=2799 (1799s elapsed), should NOT refresh.
        assert!(!manager.should_refresh(Some(1000), Some(3600), 2799));
    }

    // -------------------------------------------------------------------
    // OAuthConfig tests
    // -------------------------------------------------------------------

    #[test]
    fn scope_string_joins_with_spaces() {
        let config = test_config();
        assert_eq!(config.scope_string(), "read:messages read:users");
    }

    #[test]
    fn oauth_config_serialization_roundtrip() {
        let config = test_config();
        let json = serde_json::to_string(&config).expect("serialize");
        let restored: OAuthConfig = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(restored.client_id, config.client_id);
        assert_eq!(restored.redirect_uri, config.redirect_uri);
        assert_eq!(restored.token_endpoint, config.token_endpoint);
        assert_eq!(
            restored.authorization_endpoint,
            config.authorization_endpoint
        );
        assert_eq!(restored.revocation_endpoint, config.revocation_endpoint);
        assert_eq!(restored.scopes, config.scopes);
    }
}
