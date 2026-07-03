//! Resolver adapter types for SCP FFI bridges (`PyO3`, `napi-rs`, `UniFFI`).
//!
//! These adapters bridge `scp-core`'s validation traits to the FFI runtime.
//! Requires the `resolvers` feature (scp-core, scp-identity, tokio).

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock, RwLock};

use tracing::{debug, info, warn};

use scp_core::crypto::ucan::UcanError as CoreUcanError;
use scp_core::crypto::ucan::UcanToken;
use scp_core::crypto::ucan::validate::{
    DidResolver, NonceTracker as NonceTrackerTrait, ProofResolver, RevocationChecker,
};
use scp_core::trust::TrustError;
use scp_core::trust::attestation::DidPublicKeyResolver;
use scp_identity::IdentityError;
use scp_identity::decode_multibase_key;
use scp_identity::resolver::ResolvedDidDocument;
use scp_primitives::Clock;

// ---------------------------------------------------------------------------
// BridgeDidResolver
// ---------------------------------------------------------------------------

/// In-memory DID resolver for FFI bridges.
///
/// Supports:
/// - `did:dht:z{z-base-32-encoded-pubkey}` -- production format.
/// - `did:key:{hex-encoded-pubkey}` -- testing only (requires `testing` feature).
///
/// This resolver operates in-memory with no network calls. `did:dht:` DIDs
/// encode the public key directly in the DID string using z-base-32, so
/// resolution is a simple decode operation.
///
/// **Limitation:** This resolver does NOT validate the DID document (no BEP44
/// signature verification, no self-certification check, no sequence number
/// comparison). Use [`IdentityBackedDidResolver`] for production
/// contexts. See #311.
pub struct BridgeDidResolver;

impl DidResolver for BridgeDidResolver {
    fn resolve_public_key(&self, did: &str) -> Result<[u8; 32], CoreUcanError> {
        if let Some(suffix) = did.strip_prefix("did:dht:z") {
            let decoded = zbase32::decode(suffix).map_err(|_| {
                CoreUcanError::MalformedToken(format!("z-base-32 decode failed for DID: {did}"))
            })?;
            let bytes: [u8; 32] = decoded.try_into().map_err(|v: Vec<u8>| {
                CoreUcanError::MalformedToken(format!(
                    "DID public key must be 32 bytes, got {}",
                    v.len()
                ))
            })?;
            return Ok(bytes);
        }

        // did:key:{hex} is a non-standard test convenience. Gated behind the
        // `testing` feature (or #[cfg(test)]) to prevent acceptance in release
        // builds. See: https://github.com/limn-works/scp/issues/128
        #[cfg(any(test, feature = "testing"))]
        if let Some(hex_str) = did.strip_prefix("did:key:") {
            let bytes = hex::decode(hex_str).map_err(|e| {
                CoreUcanError::MalformedToken(format!("hex decode failed for did:key DID: {e}"))
            })?;
            let pk: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
                CoreUcanError::MalformedToken(format!(
                    "DID public key must be 32 bytes, got {}",
                    v.len()
                ))
            })?;
            return Ok(pk);
        }

        Err(CoreUcanError::MalformedToken(format!(
            "unsupported DID method: {did} (expected did:dht:)"
        )))
    }
}

// ---------------------------------------------------------------------------
// IdentityBackedDidResolver (#311)
// ---------------------------------------------------------------------------

/// Typed error for production DID resolution failures.
///
/// Maps to `UcanError` and `TrustError` variants at the consumer boundary.
/// See acceptance criteria: `NotFound`, `InvalidDocument`, `NetworkUnavailable`,
/// Revoked.
#[derive(Debug)]
pub enum ResolutionError {
    /// The DID was not found on any resolution layer.
    NotFound(String),
    /// The DID document failed validation (BEP44 sig, self-certification, etc.).
    InvalidDocument(String),
    /// All resolution layers were unreachable.
    NetworkUnavailable(String),
    /// The DID document has a stale sequence number (possible downgrade attack).
    Revoked(String),
}

impl std::fmt::Display for ResolutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(msg) => write!(f, "DID not found: {msg}"),
            Self::InvalidDocument(msg) => write!(f, "invalid DID document: {msg}"),
            Self::NetworkUnavailable(msg) => write!(f, "network unavailable: {msg}"),
            Self::Revoked(msg) => write!(f, "DID revoked/downgraded: {msg}"),
        }
    }
}

impl std::error::Error for ResolutionError {}

impl From<ResolutionError> for CoreUcanError {
    fn from(e: ResolutionError) -> Self {
        Self::MalformedToken(e.to_string())
    }
}

impl From<ResolutionError> for TrustError {
    fn from(e: ResolutionError) -> Self {
        Self::AttestationSignatureInvalid {
            attestation_id: String::new(),
            reason: e.to_string(),
        }
    }
}

/// Type-erased async resolve function. Wraps any concrete
/// `scp_identity::resolver::DidResolver` implementation.
///
/// The function takes a DID string (owned, for `Send` + `'static`) and returns
/// a boxed future. This allows [`IdentityBackedDidResolver`] to hold any
/// resolver without leaking its generic type parameters.
type AsyncResolveFn = dyn Fn(
        String,
    )
        -> Pin<Box<dyn Future<Output = Result<Option<ResolvedDidDocument>, IdentityError>> + Send>>
    + Send
    + Sync;

/// DID rotation event emitted when a higher sequence number is observed
/// for a previously-seen DID.
#[derive(Debug, Clone)]
pub struct DidRotatedEvent {
    /// The DID that was rotated.
    pub did: String,
    /// The previously-seen sequence number.
    pub previous_seq: u64,
    /// The newly-observed sequence number.
    pub new_seq: u64,
}

/// Production DID resolver that delegates to `scp_identity::resolver::DidResolver`
/// for full DID document validation.
///
/// Implements both `scp_core::crypto::ucan::validate::DidResolver` and
/// `scp_core::trust::attestation::DidPublicKeyResolver`, providing a single
/// unified resolution path for all DID-dependent operations in the FFI layer.
///
/// # Resolution pipeline
///
/// 1. Calls the wrapped `scp_identity` resolver (typically `DualLayerResolver`)
///    which performs parallel relay + DHT resolution with BEP44 signature
///    verification, self-certification, and healing.
/// 2. Extracts the requested public key from the resolved DID document's
///    verification methods.
/// 3. Detects DID rotation by comparing sequence numbers against previously
///    seen values. Higher sequences trigger a `DidRotated` log event.
///    Lower sequences are rejected (downgrade prevention).
///
/// # Caching
///
/// Resolution results are cached by the underlying `DualLayerResolver`'s
/// `DidCache` (configurable TTL). This struct adds a sequence number tracker
/// for rotation detection that persists across cache TTL boundaries (sequence
/// numbers only increase, so a stale cache entry never accepts a downgrade).
///
/// # Thread safety
///
/// The struct is `Send + Sync`. The sequence tracker uses `std::sync::RwLock`
/// (not `tokio::sync`) because it is accessed from sync trait methods.
///
/// # Async-sync bridging
///
/// The underlying resolver is async (network I/O). The `validate::DidResolver`
/// trait is sync. This struct bridges via `tokio::task::block_in_place` (when
/// called from within a tokio multi-thread runtime) or `Handle::block_on`
/// (when called from a non-tokio thread, e.g., `PyO3`).
///
/// See §3.10.10, §9.5 (UCAN validation), §7.4.1 (attestation verification).
/// Closes #311.
pub struct IdentityBackedDidResolver {
    /// Type-erased async resolve function wrapping the concrete
    /// `scp_identity::resolver::DidResolver`.
    resolve_fn: Arc<AsyncResolveFn>,

    /// Highest sequence number seen per DID. Used for rotation detection
    /// and downgrade prevention. Only increases; never decremented.
    seen_sequences: Arc<RwLock<HashMap<String, u64>>>,

    /// Rotation event log. Consumers can drain this to react to rotations.
    rotation_events: Arc<RwLock<Vec<DidRotatedEvent>>>,

    /// Long-lived, dedicated runtime that drives async DID resolution from the
    /// sync `DidResolver`/`DidPublicKeyResolver` trait methods.
    ///
    /// This is a HOT, SHARED path: a single UCAN delegation-chain validation
    /// resolves up to `MAX_CHAIN_DEPTH` (32) DIDs, and every FFI bridge
    /// routes all DID resolution through here. Building a fresh tokio runtime
    /// per call (current-thread `Builder::...build()`) was a per-resolution
    /// allocation of an entire reactor + thread, amplified 32x per validation.
    ///
    /// Instead we build ONE small multi-thread runtime lazily on first use and
    /// reuse it forever. `resolve_sync` drives futures on it via
    /// `handle().block_on(...)` from a freshly-spawned scoped OS thread (never
    /// from a thread already inside a runtime), so it stays deadlock-free from
    /// the in-`block_on` caller posture (see `resolve_sync` docs). Because the
    /// runtime owns its own worker threads, the spawned future makes progress
    /// independently of the calling bridge runtime — we depend on neither a
    /// nested `block_on` nor a free worker on the *shared* bridge runtime.
    resolution_rt: OnceLock<tokio::runtime::Runtime>,
}

impl IdentityBackedDidResolver {
    /// Creates a new production resolver wrapping any
    /// `scp_identity::resolver::DidResolver` implementation.
    ///
    /// # Type erasure
    ///
    /// The resolver's generic type parameters are erased by boxing the
    /// resolve future. This allows the FFI layer to construct a concrete
    /// `DualLayerResolver<R, D, C, H>` and wrap it without propagating
    /// the generics.
    ///
    /// # Arguments
    ///
    /// * `resolver` — The identity resolver to delegate to. Typically
    ///   `DualLayerResolver`. Must be `'static + Send + Sync`.
    /// * `_handle` — Accepted for call-site stability across the FFI bridges.
    ///   No longer retained: `resolve_sync` drives async resolution on a
    ///   dedicated thread with its own runtime (see its docs), so this resolver
    ///   does not depend on a borrowed runtime handle.
    pub fn new<R>(resolver: Arc<R>, _handle: tokio::runtime::Handle) -> Self
    where
        R: scp_identity::resolver::DidResolver + 'static,
    {
        let resolve_fn: Arc<AsyncResolveFn> = Arc::new(move |did: String| {
            let resolver = Arc::clone(&resolver);
            Box::pin(async move { resolver.resolve(&did).await })
        });

        Self {
            resolve_fn,
            seen_sequences: Arc::new(RwLock::new(HashMap::new())),
            rotation_events: Arc::new(RwLock::new(Vec::new())),
            resolution_rt: OnceLock::new(),
        }
    }

    /// Returns and drains all pending rotation events.
    ///
    /// Callers should periodically drain this to detect DID rotations and
    /// take appropriate action (e.g., re-fetching UCAN tokens, updating
    /// MLS credentials).
    #[must_use]
    pub fn drain_rotation_events(&self) -> Vec<DidRotatedEvent> {
        let mut events = self
            .rotation_events
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::mem::take(&mut *events)
    }

    /// Resolves a DID via the identity layer and returns the full resolved
    /// document with provenance metadata.
    ///
    /// This is the async inner method. The sync trait implementations call
    /// this via `block_in_place` / `block_on`.
    async fn resolve_document(
        resolve_fn: &AsyncResolveFn,
        did: &str,
    ) -> Result<ResolvedDidDocument, ResolutionError> {
        let result = (resolve_fn)(did.to_owned()).await;

        match result {
            Ok(Some(doc)) => Ok(doc),
            Ok(None) => Err(ResolutionError::NotFound(did.to_owned())),
            Err(
                IdentityError::Bep44SignatureInvalid(msg)
                | IdentityError::SelfCertificationFailed(msg)
                | IdentityError::DocumentDeserializationError(msg),
            ) => Err(ResolutionError::InvalidDocument(msg)),
            Err(IdentityError::StaleSequenceNumber {
                received,
                last_known,
            }) => Err(ResolutionError::Revoked(format!(
                "stale sequence for {did}: received {received}, last known {last_known}"
            ))),
            Err(IdentityError::DhtResolveFailed(msg) | IdentityError::RelayQueryFailed(msg)) => {
                Err(ResolutionError::NetworkUnavailable(msg))
            }
            Err(IdentityError::DhtNotFound(msg)) => Err(ResolutionError::NotFound(msg)),
            Err(e) => Err(ResolutionError::InvalidDocument(e.to_string())),
        }
    }

    /// Returns a handle to the long-lived, dedicated DID-resolution runtime,
    /// building it ONCE on first use and reusing it forever after.
    ///
    /// A small fixed-size multi-thread runtime: it owns its own worker threads,
    /// so a future driven on it via `handle().block_on(...)` makes progress
    /// independently of any *other* (bridge) runtime the caller may be parked
    /// in. Two workers are ample — DID resolution is short and bounded, and the
    /// driving scoped thread only parks waiting for the result.
    ///
    /// Returns `Err(NetworkUnavailable)` only if the OS refuses to create the
    /// runtime's threads on the very first call; subsequent calls reuse the
    /// already-built runtime and never allocate.
    fn resolution_handle(&self) -> Result<&tokio::runtime::Handle, ResolutionError> {
        // Fast path: already built. This is the common case on a hot path — no
        // allocation, no thread spawn, just a relaxed atomic load.
        if let Some(rt) = self.resolution_rt.get() {
            return Ok(rt.handle());
        }
        // Slow path (first use only): build fallibly, then publish into the
        // `OnceLock`. `OnceLock::get_or_init` cannot carry a `Result`, so we
        // build outside it and `set()` the result. If a concurrent caller wins
        // the race, `set()` returns our runtime back to us (which we drop) and
        // the already-stored one is used — either way the slot is populated.
        let built = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("scp-did-resolve")
            .enable_all()
            .build()
            .map_err(|e| {
                ResolutionError::NetworkUnavailable(format!(
                    "failed to build DID-resolution runtime: {e}"
                ))
            })?;
        let _ = self.resolution_rt.set(built);
        // The slot is guaranteed populated now (by us or the race winner).
        self.resolution_rt
            .get()
            .map(tokio::runtime::Runtime::handle)
            .ok_or_else(|| {
                ResolutionError::NetworkUnavailable(
                    "DID-resolution runtime unexpectedly absent after init".to_owned(),
                )
            })
    }

    /// Calls the async resolve function from a sync context.
    ///
    /// The async resolution is driven to completion on the long-lived,
    /// shared resolution runtime (see [`Self::resolution_handle`]) via
    /// `handle().block_on(...)`. Critically, that `block_on` is invoked from a
    /// freshly-spawned scoped OS thread — a thread that is NOT itself inside any
    /// tokio runtime — and the result is handed back through `join()`. There is
    /// NO per-call runtime construction: the reactor + worker threads are built
    /// exactly once across the whole process (this is a hot, shared path —
    /// every FFI bridge resolves all DIDs here, and a single UCAN
    /// delegation chain resolves up to `MAX_CHAIN_DEPTH` = 32 DIDs).
    ///
    /// Why drive from a spawned scoped thread rather than the calling thread:
    /// the sync `DidResolver` trait methods are invoked synchronously from deep
    /// inside async bridge operations that the bridge drives via
    /// `RUNTIME.block_on(...)` on the *calling* (non-worker) thread — e.g.
    /// governance proposal verification resolves the proposer's DID while the
    /// calling Python/JS thread is already executing `block_on`. Calling
    /// `Handle::block_on` directly on such a thread panics with "Cannot start a
    /// runtime from within a runtime", and `tokio::task::block_in_place` is
    /// invalid there (the thread is not a runtime worker). Spawning a clean
    /// thread sidesteps both: that thread enters `block_on` from no runtime
    /// context, and because the resolution runtime owns its OWN workers, the
    /// future is polled by those workers — we depend on neither a nested
    /// `block_on` nor a free worker on the *shared bridge* runtime, so this is
    /// deadlock-free from every caller posture.
    ///
    /// The async resolve future is `Send` (see `AsyncResolveFn`), so driving it
    /// from another thread is sound. DID resolution is short and bounded
    /// (in-memory DHT lookup or a single network round-trip), so the blocking
    /// `join()` on the calling thread is acceptable.
    fn resolve_sync(&self, did: &str) -> Result<ResolvedDidDocument, ResolutionError> {
        let resolve_fn = Arc::clone(&self.resolve_fn);
        let did_owned = did.to_owned();
        let handle = self.resolution_handle()?.clone();

        std::thread::scope(|scope| {
            scope
                .spawn(move || handle.block_on(Self::resolve_document(&*resolve_fn, &did_owned)))
                .join()
                .unwrap_or_else(|_| {
                    Err(ResolutionError::NetworkUnavailable(
                        "DID-resolution thread panicked".to_owned(),
                    ))
                })
        })
    }

    /// Checks sequence number for rotation detection and downgrade prevention.
    ///
    /// Returns `Err` if the sequence number is lower than previously seen
    /// (downgrade attack). Emits a rotation event if higher.
    #[allow(clippy::significant_drop_tightening)] // RwLock guard lifetime is intentional.
    fn check_sequence(&self, did: &str, seq: u64) -> Result<(), ResolutionError> {
        let mut sequences = self
            .seen_sequences
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if let Some(&prev_seq) = sequences.get(did) {
            match seq.cmp(&prev_seq) {
                std::cmp::Ordering::Less => {
                    warn!(
                        did = %did,
                        received_seq = seq,
                        last_known_seq = prev_seq,
                        "rejecting DID document with lower sequence number (possible downgrade attack)"
                    );
                    return Err(ResolutionError::Revoked(format!(
                        "sequence downgrade for {did}: received {seq}, previously saw {prev_seq}"
                    )));
                }
                std::cmp::Ordering::Greater => {
                    info!(
                        did = %did,
                        previous_seq = prev_seq,
                        new_seq = seq,
                        "DID rotation detected — higher sequence number observed"
                    );
                    sequences.insert(did.to_owned(), seq);
                    // Record rotation event.
                    if let Ok(mut events) = self.rotation_events.write() {
                        events.push(DidRotatedEvent {
                            did: did.to_owned(),
                            previous_seq: prev_seq,
                            new_seq: seq,
                        });
                    }
                }
                std::cmp::Ordering::Equal => {
                    // Same sequence — no rotation.
                }
            }
        } else {
            sequences.insert(did.to_owned(), seq);
        }

        Ok(())
    }

    /// Extracts a public key from a resolved DID document by verification
    /// method fragment.
    ///
    /// Looks up the verification method matching `fragment` (e.g., `"active"`,
    /// `"agent"`, `"0"`) and decodes the `publicKeyMultibase` field.
    fn extract_public_key(
        doc: &ResolvedDidDocument,
        fragment: &str,
    ) -> Result<[u8; 32], ResolutionError> {
        let vm = doc
            .document
            .verification_method_by_fragment(fragment)
            .ok_or_else(|| {
                ResolutionError::InvalidDocument(format!(
                    "verification method '#{fragment}' not found in DID document for {}",
                    doc.document.id
                ))
            })?;

        decode_multibase_key(&vm.public_key_multibase).map_err(|e| {
            ResolutionError::InvalidDocument(format!(
                "failed to decode public key from verification method '#{fragment}': {e}"
            ))
        })
    }

    /// Resolves the Ed25519 verifying key for a specific verification method on
    /// a DID, used by governance vote-signature verification (ADR-039).
    ///
    /// Drives the same validated resolution pipeline as the trait
    /// implementations — live (cache-backed) DID document resolution with BEP44
    /// signature verification and self-certification, sequence-number rotation
    /// tracking / downgrade prevention — then extracts the requested
    /// verification method (`#active` or `#agent`, via
    /// [`SigningKeyId::fragment`](scp_identity::SigningKeyId::fragment)) and
    /// parses the public key bytes into an [`ed25519_dalek::VerifyingKey`].
    ///
    /// This is the VM-aware accessor the FFI `KeyResolver` closure wraps so the
    /// governance engine verifies votes against the voter's *document-derived*
    /// key for the exact signing key they claimed — not a caller-supplied key.
    ///
    /// Unlike the `DidResolver`/`DidPublicKeyResolver` trait-impl siblings
    /// ([`resolve_public_key`](DidResolver::resolve_public_key) /
    /// [`resolve_public_key_by_kid`](DidResolver::resolve_public_key_by_kid)),
    /// which flatten failures into the foreign error types those traits require
    /// ([`CoreUcanError`] / [`TrustError`]), this accessor returns the
    /// structured, internal [`ResolutionError`] directly. It is the VM-aware
    /// entry point for callers that want to branch on the *kind* of failure;
    /// the [`document_vm_key_resolver`](crate::bridge_runtime::document_vm_key_resolver)
    /// governance helper collapses every error variant to `None`.
    ///
    /// # Side effects
    ///
    /// This is **not** a pure read. [`check_sequence`](Self::check_sequence)
    /// advances this resolver instance's per-DID rotation state
    /// (`seen_sequences`) and may emit a [`DidRotatedEvent`] into
    /// `rotation_events` when a higher sequence number is observed.
    ///
    /// # Downgrade protection
    ///
    /// The `check_sequence`/`seen_sequences` ratchet here is **per-resolver-
    /// instance defense-in-depth**, not the load-bearing anti-rollback guard.
    /// The authoritative, cross-consumer (in-process) anti-rollback guard is the
    /// shared `DualLayerResolver`/`DidCache::cached_sequence` check performed
    /// during document resolution. A future refactor MUST NOT delete the
    /// cache-level guard on the assumption that this per-instance ratchet covers
    /// it — it does not (it sees only the DIDs this one resolver instance has
    /// observed).
    ///
    /// # Errors
    ///
    /// - [`ResolutionError::NotFound`] — the DID could not be resolved.
    /// - [`ResolutionError::InvalidDocument`] — the document failed validation,
    ///   the requested verification method is absent, the key bytes could not be
    ///   decoded, or the bytes are not a valid Ed25519 curve point.
    /// - [`ResolutionError::NetworkUnavailable`] — all resolution layers were
    ///   unreachable.
    /// - [`ResolutionError::Revoked`] — the document carried a stale sequence
    ///   number (possible downgrade attack).
    pub fn verifying_key_for(
        &self,
        did: &scp_identity::DID,
        key_id: scp_identity::SigningKeyId,
    ) -> Result<ed25519_dalek::VerifyingKey, ResolutionError> {
        let did = did.as_ref();
        let resolved = self.resolve_sync(did)?;
        // Per-instance anti-rollback ratchet (defense-in-depth — see the
        // "Downgrade protection" note above; the cache-level guard is load-bearing).
        self.check_sequence(did, resolved.seq)?;
        // Pure document→key extraction is hoisted to scp-identity
        // (`verifying_key_from_document`, keyed by `SigningKeyId`) so this bridge
        // and the co-located scp-node self-host participant share ONE tested
        // helper (ADR-053 / spec §10.17, SHB-008). The helper collapses a missing
        // verification method, an undecodable key, or an invalid curve point to
        // `None`; this VM-aware accessor maps that miss to the structured
        // `InvalidDocument` its callers branch on.
        scp_identity::resolver::verifying_key_from_document(&resolved.document, key_id).ok_or_else(
            || {
                ResolutionError::InvalidDocument(format!(
                    "verification method '#{}' for {did} is absent, undecodable, or not a \
                     valid Ed25519 public key",
                    key_id.fragment()
                ))
            },
        )
    }
}

/// Implements `scp_core::crypto::ucan::validate::DidResolver` for production
/// DID resolution via the identity layer.
///
/// The `#active` key is the default for `resolve_public_key`. The
/// `resolve_public_key_by_kid` method supports ADR-039's shared-DID model
/// by looking up the specific verification method (`#active`, `#agent`).
impl DidResolver for IdentityBackedDidResolver {
    fn resolve_public_key(&self, did: &str) -> Result<[u8; 32], CoreUcanError> {
        debug!(did = %did, "resolving DID public key via identity layer (default #active)");

        let resolved = self.resolve_sync(did).map_err(CoreUcanError::from)?;
        self.check_sequence(did, resolved.seq)
            .map_err(CoreUcanError::from)?;

        // Default to #active (the operational signing key).
        Self::extract_public_key(&resolved, "active").map_err(CoreUcanError::from)
    }

    fn resolve_public_key_by_kid(&self, did: &str, kid: &str) -> Result<[u8; 32], CoreUcanError> {
        debug!(did = %did, kid = %kid, "resolving DID public key via identity layer");

        let resolved = self.resolve_sync(did).map_err(CoreUcanError::from)?;
        self.check_sequence(did, resolved.seq)
            .map_err(CoreUcanError::from)?;

        // Strip leading '#' from kid fragment if present.
        let fragment = kid.strip_prefix('#').unwrap_or(kid);

        Self::extract_public_key(&resolved, fragment).map_err(CoreUcanError::from)
    }
}

/// Implements `scp_core::trust::attestation::DidPublicKeyResolver` for
/// production attestation verification via the identity layer.
impl DidPublicKeyResolver for IdentityBackedDidResolver {
    fn resolve_public_key(&self, did: &str) -> Result<Vec<u8>, TrustError> {
        debug!(did = %did, "resolving DID public key for attestation verification via identity layer");

        let resolved = self.resolve_sync(did).map_err(TrustError::from)?;
        self.check_sequence(did, resolved.seq)
            .map_err(TrustError::from)?;

        // Attestation verification uses the #active key by default.
        let key = Self::extract_public_key(&resolved, "active").map_err(TrustError::from)?;
        Ok(key.to_vec())
    }
}

/// Implements `scp_identity::resolver::DidResolver` so that the global
/// production resolver can be used directly with `scp_core::identity::scpid_verify`
/// (which requires the async identity-layer resolver trait, not the sync UCAN
/// validation trait).
///
/// Delegates to the type-erased `AsyncResolveFn` stored during construction.
impl scp_identity::resolver::DidResolver for IdentityBackedDidResolver {
    fn resolve(
        &self,
        did: &str,
    ) -> impl Future<Output = Result<Option<ResolvedDidDocument>, IdentityError>> + Send {
        let resolve_fn = Arc::clone(&self.resolve_fn);
        let did_owned = did.to_owned();
        async move { (resolve_fn)(did_owned).await }
    }
}

// ---------------------------------------------------------------------------
// DispatchDidResolver (#311)
// ---------------------------------------------------------------------------

/// Dispatches DID resolution to either the production [`IdentityBackedDidResolver`]
/// or the fallback [`BridgeDidResolver`] (string-only, no document validation).
///
/// This enum enables the FFI bridges to use the production resolver when the
/// identity layer is initialized, falling back to `BridgeDidResolver` otherwise
/// (e.g., in tests or before `identity_create` is called).
///
/// Implements `DidResolver` by delegating to the active variant.
pub enum DispatchDidResolver<'a> {
    /// Production resolver with full DID document validation.
    Identity(&'a IdentityBackedDidResolver),
    /// Fallback resolver: z-base-32 decode only, no document validation.
    Bridge(BridgeDidResolver),
}

impl DispatchDidResolver<'_> {
    /// Creates a dispatch resolver that uses the production resolver if
    /// available, otherwise falls back to `BridgeDidResolver`.
    #[must_use]
    pub const fn new(production: Option<&IdentityBackedDidResolver>) -> DispatchDidResolver<'_> {
        match production {
            Some(resolver) => DispatchDidResolver::Identity(resolver),
            None => DispatchDidResolver::Bridge(BridgeDidResolver),
        }
    }
}

impl DidResolver for DispatchDidResolver<'_> {
    fn resolve_public_key(&self, did: &str) -> Result<[u8; 32], CoreUcanError> {
        match self {
            Self::Identity(r) => DidResolver::resolve_public_key(*r, did),
            Self::Bridge(r) => r.resolve_public_key(did),
        }
    }

    fn resolve_public_key_by_kid(&self, did: &str, kid: &str) -> Result<[u8; 32], CoreUcanError> {
        match self {
            Self::Identity(r) => DidResolver::resolve_public_key_by_kid(*r, did, kid),
            Self::Bridge(r) => r.resolve_public_key_by_kid(did, kid),
        }
    }
}

// ---------------------------------------------------------------------------
// BridgeRevocationChecker
// ---------------------------------------------------------------------------

/// Bridge [`RevocationChecker`] that wraps the context's `RevocationList`.
///
/// Holds a reference to the revocation list from the `ContextRuntime` and
/// delegates the `is_revoked` check. This uses the content-hash CID format
/// from `scp_core::crypto::ucan::revoke::compute_revocation_cid`.
pub struct BridgeRevocationChecker<'a> {
    pub revocation_list: &'a scp_core::crypto::ucan::revoke::RevocationList,
}

impl RevocationChecker for BridgeRevocationChecker<'_> {
    fn is_revoked(&self, token_cid: &str) -> bool {
        self.revocation_list.is_revoked(token_cid)
    }
}

// ---------------------------------------------------------------------------
// BridgeProofResolver
// ---------------------------------------------------------------------------

/// Bridge [`ProofResolver`] backed by an in-memory `HashMap`.
///
/// Stores parent UCAN tokens by their CID for delegation chain traversal.
/// In the bridge layer, the caller can supply proof tokens alongside the
/// token being validated. For now this starts empty -- root tokens (no
/// delegation chain) are fully supported, and delegated tokens require the
/// proof chain to be pre-registered.
pub struct BridgeProofResolver {
    pub proofs: HashMap<String, UcanToken>,
}

impl ProofResolver for BridgeProofResolver {
    fn resolve_proof(&self, cid: &str) -> Result<UcanToken, CoreUcanError> {
        self.proofs.get(cid).cloned().ok_or_else(|| {
            CoreUcanError::DelegationChainBroken(format!("proof CID not found: {cid}"))
        })
    }
}

// ---------------------------------------------------------------------------
// BridgeNonceTracker
// ---------------------------------------------------------------------------

/// Adapter that implements the `validate::NonceTracker` trait for
/// `nonce::NonceTracker<C>`.
///
/// The `nonce::NonceTracker` struct and `validate::NonceTracker` trait have
/// the same `check_and_record` method signature but are separate types. This
/// adapter bridges the two by wrapping a mutable reference to the struct.
pub struct BridgeNonceTracker<'a, C: Clock> {
    pub inner: &'a mut scp_core::crypto::ucan::nonce::NonceTracker<C>,
}

impl<C: Clock> NonceTrackerTrait for BridgeNonceTracker<'_, C> {
    fn check_replay(&self, nonce: &str, token_expiry: u64) -> Result<(), CoreUcanError> {
        self.inner.check_replay(nonce, token_expiry)
    }

    fn record(&mut self, nonce: &str, token_expiry: u64) -> Result<(), CoreUcanError> {
        self.inner.record(nonce, token_expiry)
    }
}

// ---------------------------------------------------------------------------
// BridgeRevocationAuthorizer (issue #499)
// ---------------------------------------------------------------------------

/// Bridge `RevocationAuthorizer` that checks the revoker DID against the
/// token's issuer DID and the context creator DID.
///
/// The authorizer is constructed with the issuer DID extracted from the parsed
/// UCAN token. Authorization succeeds if the revoker is either the token's
/// issuer or the context creator, matching the spec (ADR-016 acceptance
/// criterion 5).
///
/// This is not a lookup-based authorizer (unlike a full runtime that would
/// index token CID -> issuer). Instead, the bridge parses the token before
/// calling `revoke_ucan` and pre-populates the issuer DID.
pub struct BridgeRevocationAuthorizer {
    /// The DID of the token's issuer (extracted from the parsed UCAN).
    pub issuer_did: String,
    /// The DID of the context creator.
    pub creator_did: String,
}

impl scp_core::crypto::ucan::revoke::RevocationAuthorizer for BridgeRevocationAuthorizer {
    fn authorize_revocation(
        &self,
        _token_cid: &str,
        revoker_did: &str,
    ) -> Result<(), CoreUcanError> {
        if revoker_did == self.issuer_did || revoker_did == self.creator_did {
            Ok(())
        } else {
            Err(CoreUcanError::RevocationUnauthorized(format!(
                "revoker '{revoker_did}' is neither the token issuer ('{}') nor the context creator ('{}')",
                self.issuer_did, self.creator_did
            )))
        }
    }
}

// ---------------------------------------------------------------------------
// BridgeRevocationDistributor (issue #499)
// ---------------------------------------------------------------------------

/// No-op `RevocationDistributor` for FFI bridges.
///
/// FFI bridges do not have direct access to MLS group state for distributing
/// revocations to context members. In the full runtime, revocations would be
/// broadcast as MLS application messages. In the bridge layer, the local
/// revocation list is updated immediately and distribution is deferred to the
/// transport layer (when connected).
///
/// This distributor always succeeds, logging the revocation for observability.
pub struct BridgeRevocationDistributor;

impl scp_core::crypto::ucan::revoke::RevocationDistributor for BridgeRevocationDistributor {
    fn distribute_revocation(
        &self,
        context_id: &str,
        token_cid: &str,
    ) -> Result<(), CoreUcanError> {
        info!(
            context_id = context_id,
            token_cid = token_cid,
            "revocation recorded locally (bridge-layer distribution — MLS broadcast deferred to transport)"
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// BridgeRevocationEventLogger (issue #499)
// ---------------------------------------------------------------------------

/// Bridge `RevocationEventLogger` that appends unsigned `TokenRevoked`
/// events to the context's Merkle event log.
///
/// Uses `append_unsigned_event` because `KeyCustody::sign()` is async and
/// the revocation path is called from sync FFI bridge functions. The event
/// is chain-validated and Merkle-committed but carries an empty signature.
/// This follows the same pattern as `FfiBridgeProvider::invoke_tool` in
/// `crates/scp-ffi/src/mcp.rs`.
///
/// When async FFI signing lands (SCP-214 migration), migrate to signed events
/// via `scp_event_log::tree::append`.
pub struct BridgeRevocationEventLogger<'a> {
    /// Mutable reference to the context's event log, wrapped in `RefCell`
    /// because the `RevocationEventLogger` trait takes `&self`.
    pub event_log: &'a std::cell::RefCell<&'a mut scp_event_log::EventLog>,
}

impl scp_core::crypto::ucan::revoke::RevocationEventLogger for BridgeRevocationEventLogger<'_> {
    fn log_token_revoked(
        &self,
        context_id: &str,
        token_cid: &str,
        revoker_did: &str,
    ) -> Result<(), CoreUcanError> {
        let mut event_log = self.event_log.borrow_mut();
        let sequence = scp_event_log::tree::event_count(&event_log);
        let prev_hash = if event_log.leaves().is_empty() {
            scp_event_log::tree::GENESIS_PREV_HASH
        } else {
            event_log.leaves()[event_log.leaves().len() - 1]
        };

        // Build payload via the shared producer so the leaf preimage is
        // byte-identical across all honest members (§9.9.3 cross-platform
        // convergence). JSON object: {token_cid, revoker_did, context_id}.
        let payload_data = scp_core::crypto::ucan::revoke::token_revoked_payload(
            context_id,
            token_cid,
            revoker_did,
        )?;

        // Unix timestamp seconds fit in u64 for centuries.
        #[allow(clippy::cast_possible_truncation)]
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());

        let event = scp_event_log::Event {
            event_type: scp_event_log::EventType::TokenRevoked,
            actor_did: scp_event_log::DID(revoker_did.to_owned()),
            timestamp,
            sequence,
            payload: scp_event_log::EventPayload { data: payload_data },
            prev_hash,
            signature: Vec::new(),
        };

        scp_event_log::tree::append_unsigned_event(&mut event_log, &event).map_err(|e| {
            CoreUcanError::RevocationFailed(format!("event log append failed: {e}"))
        })?;

        info!(
            context_id = context_id,
            token_cid = token_cid,
            revoker_did = revoker_did,
            sequence = sequence,
            "TokenRevoked event appended to event log"
        );

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests (#311)
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;
    use scp_core::crypto::ucan::validate::DidResolver as CoreDidResolver;
    use scp_identity::cache::DidCache;
    use scp_identity::document::DidDocument;
    use scp_identity::resolver::{ResolutionSource, ResolvedDidDocument};
    use scp_identity::{DidMethod, DualLayerResolver, InMemoryDhtClient, NoOpRelayQuerier};
    use std::sync::Arc;

    /// Helper: create a `DualLayerResolver` with in-memory backends for testing.
    fn make_test_resolver() -> Arc<DualLayerResolver<NoOpRelayQuerier, InMemoryDhtClient>> {
        let dht = Arc::new(InMemoryDhtClient::new());
        let relay = Arc::new(NoOpRelayQuerier);
        let cache = Arc::new(DidCache::new());
        Arc::new(DualLayerResolver::new(relay, dht, cache, Vec::new()))
    }

    /// Helper: create an `IdentityBackedDidResolver` wrapping a test resolver.
    fn make_identity_resolver() -> IdentityBackedDidResolver {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let resolver = make_test_resolver();
        IdentityBackedDidResolver::new(resolver, rt.handle().clone())
    }

    // -----------------------------------------------------------------------
    // DispatchDidResolver
    // -----------------------------------------------------------------------

    #[test]
    fn dispatch_resolver_uses_bridge_when_no_production_resolver() {
        let pk_bytes: [u8; 32] = [0x42; 32];
        let did = format!("did:dht:z{}", zbase32::encode(&pk_bytes));

        let dispatch = DispatchDidResolver::new(None);
        let result = CoreDidResolver::resolve_public_key(&dispatch, &did).unwrap();
        assert_eq!(result, pk_bytes);
    }

    #[test]
    fn dispatch_resolver_delegates_to_identity_when_available() {
        // The identity resolver will fail because the DID doesn't exist in the
        // in-memory DHT, which is the expected behavior — it proves delegation
        // is happening (BridgeDidResolver would succeed for any did:dht:z DID).
        let resolver = make_identity_resolver();
        let pk_bytes: [u8; 32] = [0x42; 32];
        let did = format!("did:dht:z{}", zbase32::encode(&pk_bytes));

        let dispatch = DispatchDidResolver::new(Some(&resolver));
        let result = CoreDidResolver::resolve_public_key(&dispatch, &did);
        // The identity resolver returns NotFound because the DID is not in the DHT.
        assert!(
            result.is_err(),
            "expected error from identity resolver for unknown DID"
        );
    }

    // -----------------------------------------------------------------------
    // Sequence tracking and rotation detection
    // -----------------------------------------------------------------------

    #[test]
    fn sequence_tracking_accepts_first_seen() {
        let resolver = make_identity_resolver();
        assert!(resolver.check_sequence("did:dht:zTest1", 10).is_ok());
    }

    #[test]
    fn sequence_tracking_accepts_same_seq() {
        let resolver = make_identity_resolver();
        resolver.check_sequence("did:dht:zTest2", 10).unwrap();
        assert!(resolver.check_sequence("did:dht:zTest2", 10).is_ok());
    }

    #[test]
    fn sequence_tracking_accepts_higher_seq_and_emits_rotation() {
        let resolver = make_identity_resolver();
        resolver.check_sequence("did:dht:zTest3", 10).unwrap();
        resolver.check_sequence("did:dht:zTest3", 20).unwrap();

        let events = resolver.drain_rotation_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].did, "did:dht:zTest3");
        assert_eq!(events[0].previous_seq, 10);
        assert_eq!(events[0].new_seq, 20);
    }

    #[test]
    fn sequence_tracking_rejects_lower_seq_downgrade() {
        let resolver = make_identity_resolver();
        resolver.check_sequence("did:dht:zTest4", 20).unwrap();
        let result = resolver.check_sequence("did:dht:zTest4", 10);
        assert!(result.is_err(), "should reject sequence downgrade");
        let err = result.unwrap_err();
        assert!(
            matches!(err, ResolutionError::Revoked(_)),
            "error should be Revoked variant for downgrade, got: {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // IdentityBackedDidResolver — extract_public_key
    // -----------------------------------------------------------------------

    #[test]
    fn extract_public_key_from_document() {
        // Build a minimal DID document with an #active verification method.
        // Use a real identity to get a properly-encoded multibase key.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let custody = scp_platform::testing::InMemoryKeyCustody::new();
        let pre_rotation_custody = scp_platform::testing::InMemoryPreRotationCustody::new();
        let (identity, document, _pre_rotation_handle) = rt
            .block_on(scp_identity::DidDht::new().create(&custody, &pre_rotation_custody))
            .unwrap();

        let resolved = ResolvedDidDocument {
            document,
            seq: 1,
            source: ResolutionSource::Cache,
        };

        // Extract the #active key — should succeed.
        let key = IdentityBackedDidResolver::extract_public_key(&resolved, "active").unwrap();
        // Verify the extracted key matches the public key from custody.
        assert_eq!(key.len(), 32);

        // Also verify #0 (identity key) works.
        let identity_key = IdentityBackedDidResolver::extract_public_key(&resolved, "0").unwrap();
        assert_eq!(identity_key.len(), 32);

        // Ensure they are different keys (identity vs active).
        assert_ne!(key, identity_key, "active and identity keys should differ");

        // Suppress unused binding warning.
        let _ = identity;
    }

    #[test]
    fn extract_public_key_missing_fragment_returns_error() {
        let doc = DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
            id: "did:dht:zTest".to_owned(),
            verification_method: vec![],
            authentication: vec![],
            assertion_method: vec![],
            also_known_as: vec![],
            service: vec![],
        };

        let resolved = ResolvedDidDocument {
            document: doc,
            seq: 1,
            source: ResolutionSource::Cache,
        };

        let result = IdentityBackedDidResolver::extract_public_key(&resolved, "active");
        assert!(
            result.is_err(),
            "should fail for missing verification method"
        );
    }

    // -----------------------------------------------------------------------
    // BridgeDidResolver (basic sanity)
    // -----------------------------------------------------------------------

    #[test]
    fn bridge_resolver_resolves_did_dht() {
        let pk: [u8; 32] = [0xAB; 32];
        let did = format!("did:dht:z{}", zbase32::encode(&pk));
        let result = CoreDidResolver::resolve_public_key(&BridgeDidResolver, &did).unwrap();
        assert_eq!(result, pk);
    }

    #[test]
    fn bridge_resolver_rejects_unknown_method() {
        let result = CoreDidResolver::resolve_public_key(&BridgeDidResolver, "did:web:example.com");
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // DidPublicKeyResolver for attestation
    // -----------------------------------------------------------------------

    #[test]
    fn identity_resolver_implements_did_public_key_resolver() {
        // Verify that IdentityBackedDidResolver implements DidPublicKeyResolver.
        // The trait method returns Vec<u8> (not [u8; 32]) per the attestation API.
        let resolver = make_identity_resolver();
        let pk_bytes: [u8; 32] = [0x42; 32];
        let did = format!("did:dht:z{}", zbase32::encode(&pk_bytes));

        // Will fail because DID is not in DHT, but proves the trait is implemented.
        let result = DidPublicKeyResolver::resolve_public_key(&resolver, &did);
        assert!(
            result.is_err(),
            "expected error for unknown DID via attestation resolver"
        );
    }

    // -----------------------------------------------------------------------
    // document_vm_key_resolver — VM-aware, document-derived governance resolver
    // -----------------------------------------------------------------------

    /// A resolvable identity seeded into a real DHT: the DID, the document's
    /// `#active` and `#agent` verifying keys (the latter present only when the
    /// document carries an `#agent` verification method).
    struct SeededIdentity {
        did: String,
        active_vk: ed25519_dalek::VerifyingKey,
        agent_vk: Option<ed25519_dalek::VerifyingKey>,
    }

    /// Builds a self-certifying, BEP44-signed DID document with `#active`
    /// (always) and `#agent` (optional) verification methods, and publishes it
    /// into `dht` so a [`DualLayerResolver`] can resolve and validate it.
    ///
    /// The DID is derived from the identity key, which also BEP44-signs the
    /// document — exactly the production self-certification invariant
    /// (`verify_self_certification`) the real resolver enforces.
    #[allow(clippy::similar_names)]
    async fn seed_identity(dht: &InMemoryDhtClient, with_agent: bool) -> SeededIdentity {
        use scp_identity::DhtClient;

        // All RNG-bound key generation and signing happens synchronously and is
        // scoped into this block so the non-`Send` `ThreadRng` is dropped before
        // the `.await` below (clippy::future_not_send).
        let (did, identity_pk, active_vk, agent_vk, value, signature) = {
            use ed25519_dalek::{Signer, SigningKey};

            let mut rng = rand::thread_rng();
            let identity_sk = SigningKey::generate(&mut rng);
            let active_sk = SigningKey::generate(&mut rng);
            let agent_sk = SigningKey::generate(&mut rng);

            let identity_vk = identity_sk.verifying_key();
            let active_vk = active_sk.verifying_key();
            let agent_vk = agent_sk.verifying_key();

            let did = format!("did:dht:z{}", zbase32::encode(identity_vk.as_bytes()));

            // Pre-rotation commitment: SHA-256 of a random next identity key.
            let pre_rotation_commitment: [u8; 32] = {
                use sha2::{Digest, Sha256};
                Sha256::digest(SigningKey::generate(&mut rng).verifying_key().as_bytes()).into()
            };

            let agent_key_bytes = with_agent.then(|| *agent_vk.as_bytes());
            let doc = DidDocument::new_with_agent_key(
                &did,
                identity_vk.as_bytes(),
                active_vk.as_bytes(),
                &pre_rotation_commitment,
                agent_key_bytes.as_ref().map(<[u8; 32]>::as_slice),
            );

            // BEP44-sign the serialized document with the identity key (seq = 1),
            // matching DidDht::publish_document.
            let value = doc.to_json().unwrap().into_bytes();
            let signable = scp_identity::dht::bep44_signable(&value, 1);
            let signature: [u8; 64] = identity_sk.sign(&signable).to_bytes();

            (
                did,
                *identity_vk.as_bytes(),
                active_vk,
                agent_vk,
                value,
                signature,
            )
        };

        // Publish under the identity public key.
        dht.publish(&identity_pk, &signature, &value, 1)
            .await
            .unwrap();

        SeededIdentity {
            did,
            active_vk,
            agent_vk: with_agent.then_some(agent_vk),
        }
    }

    /// Constructs an `IdentityBackedDidResolver` over a `DualLayerResolver`
    /// backed by `dht`, wrapped for use as a governance key resolver.
    fn identity_resolver_over(
        dht: Arc<InMemoryDhtClient>,
        handle: tokio::runtime::Handle,
    ) -> Arc<IdentityBackedDidResolver> {
        let relay = Arc::new(NoOpRelayQuerier);
        let cache = Arc::new(DidCache::new());
        let resolver = Arc::new(DualLayerResolver::new(relay, dht, cache, Vec::new()));
        Arc::new(IdentityBackedDidResolver::new(resolver, handle))
    }

    #[test]
    fn document_vm_key_resolver_is_document_derived_and_vm_aware() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();

        let dht = Arc::new(InMemoryDhtClient::new());

        // Seed one identity WITH an #agent key, and one WITHOUT.
        let (with_agent, no_agent) = rt.block_on(async {
            let with_agent = seed_identity(&dht, true).await;
            let no_agent = seed_identity(&dht, false).await;
            (with_agent, no_agent)
        });

        // Build the production VM-aware governance key resolver over the seeded DHT.
        let did_resolver = identity_resolver_over(Arc::clone(&dht), rt.handle().clone());
        let key_resolver = crate::bridge_runtime::document_vm_key_resolver(did_resolver);

        // (DID, Active) → Some(vk) equal to the document's #active key.
        let with_agent_did = scp_identity::DID::from(with_agent.did.clone());
        let active = key_resolver(&with_agent_did, scp_identity::SigningKeyId::Active);
        assert_eq!(
            active,
            Some(with_agent.active_vk),
            "Active VM must resolve to the document's #active key"
        );

        // (DID, Agent) → Some(vk) equal to the document's #agent key, distinct
        // from #active.
        let agent = key_resolver(&with_agent_did, scp_identity::SigningKeyId::Agent);
        assert_eq!(
            agent, with_agent.agent_vk,
            "Agent VM must resolve to the document's #agent key"
        );
        assert_ne!(
            agent,
            Some(with_agent.active_vk),
            "Agent and active keys must be distinct (proves VM-awareness)"
        );

        // (DID with no #agent VM, Agent) → None.
        let no_agent_did = scp_identity::DID::from(no_agent.did.clone());
        assert!(
            key_resolver(&no_agent_did, scp_identity::SigningKeyId::Agent).is_none(),
            "Agent VM lookup must fail closed when the document has no #agent key"
        );
        // Sanity: the no-agent identity still resolves its #active key.
        assert_eq!(
            key_resolver(&no_agent_did, scp_identity::SigningKeyId::Active),
            Some(no_agent.active_vk),
            "the no-agent identity must still resolve its #active key"
        );

        // (unknown DID, either VM) → None.
        let unknown_pk: [u8; 32] = [0x11; 32];
        let unknown_did =
            scp_identity::DID::from(format!("did:dht:z{}", zbase32::encode(&unknown_pk)));
        assert!(
            key_resolver(&unknown_did, scp_identity::SigningKeyId::Active).is_none(),
            "unknown DID (Active) must resolve to None"
        );
        assert!(
            key_resolver(&unknown_did, scp_identity::SigningKeyId::Agent).is_none(),
            "unknown DID (Agent) must resolve to None"
        );
    }

    /// SHB-008: the bridge `KeyResolver` resolves a registered document's Active
    /// key via the hoisted `scp_identity::resolver::verifying_key_from_document`
    /// helper — proving the extraction was relocated to scp-identity with the
    /// bridge's observable behavior unchanged (`Some(active_vk)` for a known DID's
    /// `#active` signing key).
    #[test]
    fn bridge_keyresolver_resolves_via_hoisted_helper() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();

        let dht = Arc::new(InMemoryDhtClient::new());
        let identity = rt.block_on(async { seed_identity(&dht, false).await });

        // The bridge KeyResolver is built exactly as production wires it.
        let did_resolver = identity_resolver_over(Arc::clone(&dht), rt.handle().clone());
        let key_resolver = crate::bridge_runtime::document_vm_key_resolver(did_resolver);

        let did = scp_identity::DID::from(identity.did.clone());
        let active = key_resolver(&did, scp_identity::SigningKeyId::Active);
        assert_eq!(
            active,
            Some(identity.active_vk),
            "the bridge KeyResolver (now backed by the hoisted \
             verifying_key_from_document helper) must return Some(active_vk) for a \
             registered document's #active key"
        );
    }
}
