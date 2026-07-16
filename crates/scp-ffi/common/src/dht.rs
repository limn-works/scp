//! Shared DHT client for the FFI bridges (`PyO3`, `napi-rs`, `UniFFI`).
//!
//! One shipped DHT backend — the real Mainline [`PkarrDhtClient`] — is compiled
//! unconditionally via `scp-dht/production-dht`. The in-memory arm is a
//! §17.17.3 resolve nullifier and is compiled only under this crate's `testing`
//! feature; a shipped (non-`testing`) build resolves [`FfiDhtClient`] to a
//! Pkarr-only type, so the nullifier is not even nameable (ADR-062 §Decision 1).
//!
//! Construction fails **closed**: [`ClientDhtConfig::into_client`] builds a real
//! Pkarr client from caller-supplied gateways and returns [`DhtInitError`] when
//! that cannot be satisfied — it never substitutes an in-memory or no-op client
//! (M3). The in-memory arm is reachable only by test seams that construct
//! `FfiDhtClient::InMemory(..)` directly.

use scp_dht::{DhtClient, DhtError, DhtRecord, PkarrDhtClient};

#[cfg(feature = "testing")]
use scp_dht::InMemoryDhtClient;

/// The DHT client the FFI bridges run over.
///
/// `Pkarr` (the real Mainline DHT client) is compiled unconditionally — it is
/// the single shipped backend. `InMemory` is a **§17.17.3 nullifier** compiled
/// only under the `testing` feature; it is never reachable on a shipped path.
pub enum FfiDhtClient {
    /// Real Mainline DHT client (BEP44 signed mutable items). The only backend
    /// present in a shipped build.
    Pkarr(PkarrDhtClient),
    /// In-memory test double (nullifier). Compiled only under `testing`;
    /// constructed exclusively by test seams, never by [`ClientDhtConfig`].
    #[cfg(feature = "testing")]
    InMemory(InMemoryDhtClient),
}

impl std::fmt::Debug for FfiDhtClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pkarr(_) => f.write_str("FfiDhtClient::Pkarr"),
            #[cfg(feature = "testing")]
            Self::InMemory(_) => f.write_str("FfiDhtClient::InMemory"),
        }
    }
}

// Trait uses RPITIT with explicit `+ Send`; the two arms return distinct future
// types, so the delegation is wrapped in a single async block that awaits the
// selected arm (unifying the future type). `manual_async_fn` is expected here.
#[allow(clippy::manual_async_fn)]
impl DhtClient for FfiDhtClient {
    fn publish(
        &self,
        public_key: &[u8; 32],
        signature: &[u8; 64],
        value: &[u8],
        seq: u64,
    ) -> impl Future<Output = Result<(), DhtError>> + Send {
        async move {
            match self {
                Self::Pkarr(client) => client.publish(public_key, signature, value, seq).await,
                #[cfg(feature = "testing")]
                Self::InMemory(client) => client.publish(public_key, signature, value, seq).await,
            }
        }
    }

    fn resolve(
        &self,
        public_key: &[u8; 32],
    ) -> impl Future<Output = Result<Option<DhtRecord>, DhtError>> + Send {
        async move {
            match self {
                Self::Pkarr(client) => client.resolve(public_key).await,
                #[cfg(feature = "testing")]
                Self::InMemory(client) => client.resolve(public_key).await,
            }
        }
    }
}

/// Caller-supplied parameters for building the production DHT client.
///
/// DHT is a single-real-backend capability (Axis-A = 1), so there is no runtime
/// *backend* choice — only its *parameters*. `gateways` are optional HTTP
/// gateway URLs used for BEP44 resolution fallback behind restrictive firewalls;
/// an empty list uses direct Mainline DHT only.
#[derive(Debug, Clone, Default)]
pub struct ClientDhtConfig {
    /// HTTP gateway URLs (e.g. `https://dns.example`) for resolution fallback.
    /// Each must be an `http`/`https` URL; malformed entries fail closed.
    pub gateways: Vec<String>,
}

/// Builds the shipped [`FfiDhtClient`] for the FFI bridges, **failing closed**.
///
/// A single cfg-gated definition shared by all three bridges (`PyO3`, `napi-rs`,
/// `UniFFI`) — each maps [`DhtInitError`] to its own bridge error type. A shipped
/// (non-`testing`) build constructs the real Mainline Pkarr client via
/// [`ClientDhtConfig::into_client`]; a malformed gateway or a Mainline build
/// failure surfaces as a typed [`DhtInitError`], never an in-memory or no-op
/// substitute (ADR-062 §Decision 1 / spec §17.17.3). The in-memory arm is
/// compiled only under the `testing` feature (A5: the single activation path)
/// and is reachable only through this test seam.
///
/// # Errors
///
/// Returns [`DhtInitError`] when the production Pkarr client cannot be built
/// (never in a `testing` build, where the in-memory seam is infallible).
#[cfg(not(feature = "testing"))]
pub fn build_ffi_dht_client() -> Result<FfiDhtClient, DhtInitError> {
    ClientDhtConfig::default().into_client()
}

/// Test seam: builds the in-memory [`FfiDhtClient`].
///
/// Bridge tests never touch the network. Shares the fallible production
/// signature above so every bridge caller uses `?`/`map_err` uniformly across
/// both cfg arms.
///
/// # Errors
///
/// Never errors in a `testing` build (the in-memory seam is infallible); the
/// `Result` return matches the production arm's signature.
#[cfg(feature = "testing")]
#[allow(clippy::unnecessary_wraps)]
pub fn build_ffi_dht_client() -> Result<FfiDhtClient, DhtInitError> {
    Ok(FfiDhtClient::InMemory(InMemoryDhtClient::new()))
}

impl ClientDhtConfig {
    /// Builds the real [`PkarrDhtClient`], **failing closed**.
    ///
    /// Returns [`DhtInitError`] when a gateway URL is malformed or the Mainline
    /// DHT client cannot be created. It never falls back to an in-memory or
    /// no-op client — a missing production DHT surfaces as a typed error, not a
    /// silent nullifier (§17.17.3, M3).
    ///
    /// # Errors
    ///
    /// - [`DhtInitError::InvalidGateway`] — a gateway URL is not a valid
    ///   `http`/`https` URL.
    /// - [`DhtInitError::Pkarr`] — the Mainline DHT client could not be built.
    pub fn into_client(self) -> Result<FfiDhtClient, DhtInitError> {
        let mut builder = PkarrDhtClient::builder();
        for gateway in self.gateways {
            // Normalize IDENTICALLY to the node/self-host `build_pkarr_client`:
            // trim surrounding whitespace, skip empty entries, then validate the
            // trimmed value against the ONE shared gateway-URL contract
            // (`scp_dht::validate_gateway_url`) and register the trimmed value.
            // Both callers therefore accept/reject exactly the same inputs (a
            // whitespace-padded gateway is trimmed-then-accepted here just as it
            // is on the node path — never accepted by one and rejected by the
            // other). Both still fail closed on a malformed URL.
            let gateway = gateway.trim();
            if gateway.is_empty() {
                continue;
            }
            scp_dht::validate_gateway_url(gateway).map_err(|e| DhtInitError::InvalidGateway {
                url: e.url,
                reason: e.reason,
            })?;
            builder = builder.gateway_url(gateway);
        }
        let client = builder.build().map_err(DhtInitError::Pkarr)?;
        Ok(FfiDhtClient::Pkarr(client))
    }
}

/// Error building the production DHT client from a [`ClientDhtConfig`].
#[derive(Debug, thiserror::Error)]
pub enum DhtInitError {
    /// A supplied gateway URL was malformed.
    #[error("invalid DHT gateway URL {url:?}: {reason}")]
    InvalidGateway {
        /// The offending URL.
        url: String,
        /// Why it was rejected.
        reason: String,
    },
    /// The Mainline DHT (Pkarr) client could not be created.
    #[error("failed to build production DHT client: {0}")]
    Pkarr(#[source] DhtError),
}
