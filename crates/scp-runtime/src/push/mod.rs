//! The push registrar, which registers this device's push token with relays.
//!
//! Spec: `10-infrastructure-and-self-hosting.md` §10.7.1,
//! `22-human-readable-addressing.md` §22.11.4, ADR-004 **Push registration
//! interception**. The registrar's reconcile reads the routing IDs grouped by
//! relay from
//! [`Supervisor::push_routing_ids`], compares each relay's set with the set it
//! last sent there, and publishes a signed `PushRegistration` to each relay
//! whose set changed and a signed `PushDeregistration` to each relay that left
//! the map (§10.7.1 **Re-registration**). Each message's preimage comes from
//! [`push_registration_signing_bytes`] or [`push_deregistration_signing_bytes`]
//! with that relay's canonical URL, and the registrar signs the SHA-256 of the
//! preimage through [`KeyCustody::sign`] with a [`PushSigningKey`].
//!
//! Before its first publish to a relay, the registrar records the relay in a
//! durable ledger ([`crate::store::push`]), and it deletes the record only
//! when the relay accepts a deregistration of that token or refuses in a way
//! that shows it holds nothing (`4061`, `4063`). A reconcile deregisters every
//! recorded relay that no longer hosts a context of this device, so a lost OK
//! or a restart never leaves a registration behind.
//!
//! A relay that refused a request with a `4xxx` code is not sent the same
//! request again (ADR-004): the registrar records the refusal and skips the
//! relay until its routing-ID set or the token changes. `4062` is the one
//! `4xxx` code it retries, after the backoff: the relay refused the
//! `timestamp`, and the retry is a new request, signed with the clock's
//! second at that time, which is above every `timestamp` sent before. The
//! retries end once one relay has answered `4062` to every message of one
//! request for more than [`PUSH_TIMESTAMP_SKEW_SECS`] of the device clock:
//! a timestamp floor the relay holds clears inside that span, so a relay
//! still refusing after it is refusing the device clock itself, and the
//! registrar records the refusal as it records any other (§10.7.1
//! **Freshness**).
//!
//! [`PushRegistrar::spawn_trigger`] moves the registrar into one task, which
//! serializes every reconcile and command. The task reconciles at start and
//! whenever [`Supervisor::push_routes_changed`] reports that the routing IDs
//! may have changed, retries a retryable failure with the ADR-004 backoff, and
//! stops on its shutdown token.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures::future::BoxFuture;
use scp_clock::Clock;
use scp_crypto::p256::{COMPRESSED_POINT_LEN, P256PublicKey, SIGNATURE_LEN, verify_prehash_strict};
use scp_did::DID;
use scp_platform::traits::Storage;
use scp_platform::{KeyCustody, KeyHandle, PlatformError, PushToken};
use scp_protocol::context::ContextError;
use scp_protocol::discovery::push::{
    PUSH_TIMESTAMP_SKEW_SECS, PushDeregistration, PushMessageError, PushPlatform, PushRegistration,
    PushRelay, push_deregistration_signing_bytes, push_registration_signing_bytes,
};
use scp_relay_client::{code, sanitize_relay_text};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::context::supervisor::Supervisor;
use crate::store::push::PushRelayRecord;
use crate::store::{ProtocolRepository, StoreError};

#[cfg(test)]
mod tests;

/// The ADR-004 client backoff, in seconds: 1, 2, 4, 8 and 16, then 30 for every
/// later attempt.
const BACKOFF_SECS: [u64; 6] = [1, 2, 4, 8, 16, 30];

/// How many times [`PushRegistrar`] waits for the clock to reach a new second
/// before it reports [`PushError::ClockBehind`]. One wait suffices on a clock
/// that advances; the bound stops a stalled clock from holding the registrar.
const MAX_SECOND_WAITS: u32 = 3;

/// Capacity of the command channel into the trigger task. Each command waits
/// for its reply, so a caller holds at most one slot.
const COMMAND_CAPACITY: usize = 4;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a push registration or deregistration failed.
///
/// The relay's ADR-004 codes 4060-4064, 5003 and 5004 each have their own
/// variant. [`PushError::retryable`] separates the failures a later attempt
/// can heal from the ones it cannot.
#[derive(Debug, thiserror::Error)]
pub enum PushError {
    /// The custody handle does not hold a P-256 signing key, or the key under
    /// it changed. §10.7.1 step 3 verifies a P-256 signature only.
    #[error("push signing key is not a P-256 signing key")]
    SigningKeyNotP256,
    /// Key custody failed to return the public key or to sign.
    #[error("key custody failed: {0}")]
    Custody(#[source] PlatformError),
    /// Key custody returned a signature that is not a 64-byte low-`s`
    /// signature verifying under the signing key.
    #[error("key custody returned an invalid P-256 signature")]
    CustodySignatureInvalid,
    /// The relay is a tier 3 entry, which needs the §10.7.1 **Tier 3
    /// envelope** this registrar does not build. Nothing was published to it.
    #[error("relay {relay_url} is a tier 3 entry; tier 3 registration is not supported")]
    Tier3Unsupported {
        /// The relay's canonical URL.
        relay_url: String,
    },
    /// The message could not be built, encoded or given a preimage.
    #[error("push message: {0}")]
    Message(#[from] PushMessageError),
    /// The routing-ID query failed, so nothing was published.
    #[error("push routing-ID query failed: {0}")]
    Routes(#[source] ContextError),
    /// The platform is `WebPush`, whose subscription is per relay (§10.7.1,
    /// the `WebPush` paragraph), so one token cannot go to every relay. PUSH-024 owns
    /// `WebPush` registration.
    #[error("WebPush registration is per relay; this registrar sends one token to every relay")]
    WebPushUnsupported,
    /// The relay ledger could not be read or written. A registration whose
    /// ledger write failed is not published.
    #[error("push relay ledger: {0}")]
    Ledger(#[source] StoreError),
    /// The publisher has no path that carries a push message to the relay.
    #[error("the publisher cannot send push messages: {reason}")]
    PublisherUnsupported {
        /// Why the publisher cannot send.
        reason: String,
    },
    /// One call named the same relay twice.
    #[error("relay {relay_url} is named more than once")]
    DuplicateRelay {
        /// The relay's canonical URL.
        relay_url: String,
    },
    /// The clock reads at or before the last timestamp sent for this
    /// registration key and did not pass it while the registrar waited
    /// (§10.7.1 **Freshness**).
    #[error("clock reads {now}, not after the last push timestamp {last}")]
    ClockBehind {
        /// The clock's current second.
        now: u64,
        /// The last timestamp sent for the registration key.
        last: u64,
    },
    /// `4060` `PUSH_REGISTRATION_REJECTED`.
    #[error("relay rejected the push message (4060): {msg}")]
    RegistrationRejected {
        /// The relay's sanitized text.
        msg: String,
    },
    /// `4061` `PUSH_PLATFORM_UNAVAILABLE`.
    #[error("relay cannot send to this push platform (4061): {msg}")]
    PlatformUnavailable {
        /// The relay's sanitized text.
        msg: String,
    },
    /// `4062` `PUSH_REGISTRATION_STALE`.
    #[error("relay found the push timestamp stale (4062): {msg}")]
    Stale {
        /// The relay's sanitized text.
        msg: String,
    },
    /// The relay answered `4062` to every message of one request for more
    /// than [`PUSH_TIMESTAMP_SKEW_SECS`] of the device clock, measured from
    /// the first of those answers. A floor the relay holds (the last
    /// `timestamp` it accepted) clears inside that span, so this relay is
    /// refusing the device clock, which is outside the relay's skew window
    /// (§10.7.1 **Freshness**). The registrar does not send the request
    /// again until the routing-ID set or the token changes or a
    /// [`PushRegistrarTask::register`] command arrives.
    #[error(
        "relay refused every push timestamp as stale (4062) for {span_secs} s of the device clock: {msg}"
    )]
    StaleBeyondSkew {
        /// The relay's sanitized text of the last `4062`.
        msg: String,
        /// Device-clock seconds from the first `4062` of the run to the last.
        span_secs: u64,
    },
    /// `4063` `PUSH_NOT_SUPPORTED`.
    #[error("relay does not offer push (4063): {msg}")]
    NotSupported {
        /// The relay's sanitized text.
        msg: String,
    },
    /// `4064` `PUSH_REGISTRATION_LIMIT`.
    #[error("relay's push registration limit is reached (4064): {msg}")]
    RegistrationLimit {
        /// The relay's sanitized text.
        msg: String,
    },
    /// `5003` `PUSH_VERIFIER_UNAVAILABLE`.
    #[error("relay's push verifier is unavailable (5003): {msg}")]
    VerifierUnavailable {
        /// The relay's sanitized text.
        msg: String,
    },
    /// `5004` `PUSH_KEY_STATE_UNAVAILABLE`.
    #[error("relay cannot read the registrant's key state (5004): {msg}")]
    KeyStateUnavailable {
        /// The relay's sanitized text.
        msg: String,
    },
    /// Any other `4xxx` code, or a code outside both ranges.
    #[error("relay refused the push message ({code}): {msg}")]
    RelayRefused {
        /// The relay's code.
        code: u16,
        /// The relay's sanitized text.
        msg: String,
    },
    /// Any other `5xxx` code.
    #[error("relay failed the push message ({code}): {msg}")]
    RelayFailed {
        /// The relay's code.
        code: u16,
        /// The relay's sanitized text.
        msg: String,
    },
    /// The relay could not be reached, or gave no answer.
    #[error("relay unreachable: {reason}")]
    Unreachable {
        /// Why the publish did not reach the relay.
        reason: String,
    },
    /// The trigger task that owns the registrar has stopped.
    #[error("the push registrar task has stopped")]
    RegistrarStopped,
}

impl PushError {
    /// Whether a later attempt of the same operation can succeed without any
    /// change on this device: `5003`, `5004`, every other `5xxx` code, an
    /// unreachable relay, a clock behind the last timestamp, a failed
    /// routing-ID query, a failed ledger read or write, and `4062`. ADR-004
    /// has a client never resend a `4xxx` request as-is, so `4060`, `4061`,
    /// `4063` and `4064` are not retryable. A `4062` refused the message's
    /// `timestamp` only, and every attempt signs a new message whose
    /// `timestamp` is the clock's second at that time and above every one
    /// sent before (§10.7.1 **Freshness**), so the retry is a new request.
    #[must_use]
    pub const fn retryable(&self) -> bool {
        matches!(
            self,
            Self::VerifierUnavailable { .. }
                | Self::KeyStateUnavailable { .. }
                | Self::Stale { .. }
                | Self::RelayFailed { .. }
                | Self::Unreachable { .. }
                | Self::ClockBehind { .. }
                | Self::Routes(_)
                | Self::Ledger(_)
        )
    }

    /// Whether the relay, or the publisher, refused the request for good: a
    /// `4xxx` code other than `4062`, a run of `4062` answers longer than the
    /// skew window ([`Self::StaleBeyondSkew`]), or a publisher with no push
    /// path. The registrar does not send that relay the same request again
    /// (ADR-004). A single `4062` is not terminal: it refused the
    /// `timestamp`, and [`Self::retryable`] has the registrar send a new
    /// message with a newer one after the backoff.
    #[must_use]
    pub const fn is_terminal_refusal(&self) -> bool {
        matches!(
            self,
            Self::RegistrationRejected { .. }
                | Self::PlatformUnavailable { .. }
                | Self::NotSupported { .. }
                | Self::RegistrationLimit { .. }
                | Self::StaleBeyondSkew { .. }
                | Self::RelayRefused { .. }
                | Self::PublisherUnsupported { .. }
        )
    }

    /// Whether the refusal shows that the relay holds no registration of this
    /// token: `4061`, the relay cannot send to the platform, and `4063`, the
    /// relay offers no push.
    #[must_use]
    pub const fn relay_holds_nothing(&self) -> bool {
        matches!(
            self,
            Self::PlatformUnavailable { .. } | Self::NotSupported { .. }
        )
    }

    /// The typed error for a relay `ERR` with `code` and `msg`.
    fn from_relay(code: u16, msg: &str) -> Self {
        let msg = sanitize_relay_text(msg);
        match code {
            code::PUSH_REGISTRATION_REJECTED => Self::RegistrationRejected { msg },
            code::PUSH_PLATFORM_UNAVAILABLE => Self::PlatformUnavailable { msg },
            code::PUSH_REGISTRATION_STALE => Self::Stale { msg },
            code::PUSH_NOT_SUPPORTED => Self::NotSupported { msg },
            code::PUSH_REGISTRATION_LIMIT => Self::RegistrationLimit { msg },
            code::PUSH_VERIFIER_UNAVAILABLE => Self::VerifierUnavailable { msg },
            code::PUSH_KEY_STATE_UNAVAILABLE => Self::KeyStateUnavailable { msg },
            other if code::is_server_error(other) => Self::RelayFailed { code: other, msg },
            other => Self::RelayRefused { code: other, msg },
        }
    }
}

impl From<PushPublishError> for PushError {
    fn from(err: PushPublishError) -> Self {
        match err {
            PushPublishError::Rejected { code, msg } => Self::from_relay(code, &msg),
            PushPublishError::Unreachable { reason } => Self::Unreachable {
                reason: sanitize_relay_text(&reason),
            },
            PushPublishError::Unsupported { reason } => Self::PublisherUnsupported {
                reason: sanitize_relay_text(&reason),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Publisher
// ---------------------------------------------------------------------------

/// Why a [`PushRelayPublisher`] did not deliver a push message.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PushPublishError {
    /// The relay answered `ERR` with an ADR-004 code.
    #[error("relay error {code}: {msg}")]
    Rejected {
        /// The relay's code.
        code: u16,
        /// The relay's text.
        msg: String,
    },
    /// The relay is not connected, or the publish failed before an answer.
    #[error("relay unreachable: {reason}")]
    Unreachable {
        /// Why the publish did not reach the relay.
        reason: String,
    },
    /// The publisher has no path that carries a push message, so no later
    /// attempt can succeed.
    #[error("publisher cannot send push messages: {reason}")]
    Unsupported {
        /// Why the publisher cannot send.
        reason: String,
    },
}

/// Publishes one push message to one relay: a PUBLISH of `blob` at
/// `routing_id` on the connection to the relay whose canonical URL is
/// `relay_url`, returning once the relay answers.
pub trait PushRelayPublisher: Send + Sync {
    /// Publishes `blob` at `routing_id` on `relay_url`.
    ///
    /// # Errors
    ///
    /// [`PushPublishError::Rejected`] with the relay's code when the relay
    /// answers `ERR`; [`PushPublishError::Unreachable`] when no connection to
    /// the relay exists or the publish gets no answer;
    /// [`PushPublishError::Unsupported`] when the connection has no path for
    /// a push message.
    fn publish<'a>(
        &'a self,
        relay_url: &'a str,
        routing_id: [u8; 32],
        blob: Vec<u8>,
    ) -> BoxFuture<'a, Result<(), PushPublishError>>;
}

// ---------------------------------------------------------------------------
// Signing key
// ---------------------------------------------------------------------------

/// The key a [`PushRegistrar`] signs with: a custody handle that holds a
/// P-256 signing key, and the identifier registered with it.
///
/// §10.7.1 step 3 has the relay verify the signature with the P-256 key the
/// registrant's key state lists `Current` in the `#active` role. This type has
/// no constructor outside `testing`: PUSH-036 adds the one that takes the
/// device's `#active` handle.
pub struct PushSigningKey<C: KeyCustody> {
    registrant: DID,
    custody: Arc<C>,
    handle: KeyHandle,
    public_key: P256PublicKey,
}

impl<C: KeyCustody> PushSigningKey<C> {
    /// A signing key over `handle` in `custody`, registered as `registrant`,
    /// for tests that register the key's public key with a test verifier.
    ///
    /// # Errors
    ///
    /// [`PushError::SigningKeyNotP256`] when `handle` does not hold a P-256
    /// signing key; [`PushError::Custody`] when custody cannot read it.
    #[cfg(any(test, feature = "testing"))]
    pub async fn for_testing(
        registrant: DID,
        custody: Arc<C>,
        handle: KeyHandle,
    ) -> Result<Self, PushError> {
        let public_key = p256_signing_public_key(custody.as_ref(), &handle).await?;
        Ok(Self {
            registrant,
            custody,
            handle,
            public_key,
        })
    }

    /// The identifier the messages name as `registrant`.
    #[must_use]
    pub const fn registrant(&self) -> &DID {
        &self.registrant
    }

    /// The P-256 public key the signatures verify under.
    #[must_use]
    pub const fn public_key(&self) -> &P256PublicKey {
        &self.public_key
    }

    /// Signs SHA-256(`preimage`) and checks the result before returning it.
    ///
    /// The handle is checked again on every call, because custody owns the
    /// key under it; a signature that does not verify under the stored key is
    /// refused, so the registrar never publishes a message the relay would
    /// reject as forged.
    async fn sign_preimage(&self, preimage: &[u8]) -> Result<[u8; SIGNATURE_LEN], PushError> {
        let current = p256_signing_public_key(self.custody.as_ref(), &self.handle).await?;
        if current != self.public_key {
            return Err(PushError::SigningKeyNotP256);
        }
        let digest: [u8; 32] = Sha256::digest(preimage).into();
        let signature = self
            .custody
            .sign(&self.handle, &digest)
            .await
            .map_err(PushError::Custody)?;
        let signature: [u8; SIGNATURE_LEN] = signature
            .as_bytes()
            .try_into()
            .map_err(|_| PushError::CustodySignatureInvalid)?;
        verify_prehash_strict(&self.public_key, &digest, &signature)
            .map_err(|_| PushError::CustodySignatureInvalid)?;
        Ok(signature)
    }
}

/// The P-256 public key under `handle`. A P-256 signing handle returns the
/// 33-byte compressed point; an Ed25519 handle returns 32 bytes and a P-256
/// key-agreement handle 65, so the length alone refuses both.
async fn p256_signing_public_key<C: KeyCustody>(
    custody: &C,
    handle: &KeyHandle,
) -> Result<P256PublicKey, PushError> {
    let public_key = custody
        .public_key(handle)
        .await
        .map_err(PushError::Custody)?;
    if public_key.as_bytes().len() != COMPRESSED_POINT_LEN {
        return Err(PushError::SigningKeyNotP256);
    }
    P256PublicKey::from_sec1(public_key.as_bytes()).map_err(|_| PushError::SigningKeyNotP256)
}

// ---------------------------------------------------------------------------
// Registrar
// ---------------------------------------------------------------------------

/// One relay and the routing IDs to register there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushTarget {
    /// The relay entry the message is signed for and published to.
    pub relay: PushRelay,
    /// The routing IDs to wake this device for (§22.11.4). Never empty.
    pub routing_ids: BTreeSet<[u8; 32]>,
}

/// The per-relay outcome of one operation, keyed by canonical relay URL. One
/// relay's failure does not stop the others.
pub type RelayResults = BTreeMap<String, Result<(), PushError>>;

/// The per-relay outcomes of an operation that can deregister and register.
///
/// [`PushRegistrar::refresh_token`], the registrar's crate-internal
/// `reconcile` and the task commands return it. One relay can appear in both maps, for example an
/// old token's deregistration and the new token's registration.
#[derive(Debug, Default)]
pub struct RelayOutcomes {
    /// Each `PushDeregistration`, per relay.
    pub deregistered: RelayResults,
    /// Each `PushRegistration`, per relay.
    pub registered: RelayResults,
}

impl RelayOutcomes {
    /// Every failed relay with its error, deregistrations first.
    fn failures(&self) -> impl Iterator<Item = (&String, &PushError)> {
        self.deregistered
            .iter()
            .chain(&self.registered)
            .filter_map(|(url, outcome)| outcome.as_ref().err().map(|err| (url, err)))
    }
}

/// Construction parameters for [`PushRegistrar`].
pub struct PushRegistrarConfig<C: KeyCustody, S: Storage> {
    /// The key every message is signed with.
    pub signing_key: PushSigningKey<C>,
    /// Delivers each message to its relay.
    pub publisher: Arc<dyn PushRelayPublisher>,
    /// The clock every `timestamp` is read from.
    pub clock: Arc<dyn Clock>,
    /// The push platform the token belongs to. `WebPush` is refused.
    pub platform: PushPlatform,
    /// The platform's device token. Never empty.
    pub token: PushToken,
    /// The store that holds the relay ledger, so a relay that may hold a
    /// registration is deregistered after a lost OK or a restart.
    pub storage: Arc<ProtocolRepository<S>>,
}

/// SHA-256 of a token: the token's identity in in-memory keys, so no map key
/// holds the token bytes.
type TokenHash = [u8; 32];

fn token_hash(token: &PushToken) -> TokenHash {
    Sha256::digest(token.as_bytes()).into()
}

/// One relay key of the registrar's per-relay maps: the canonical relay URL
/// and the token hash.
type RelayKey = (String, TokenHash);

/// A request the registrar sends one relay for one token.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Request {
    /// A registration of this routing-ID set.
    Registration(BTreeSet<[u8; 32]>),
    /// A deregistration.
    Deregistration,
}

/// Why a relay's refusal is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RefusalCause {
    /// A `4xxx` code other than `4062`, or a publisher with no push path.
    Code,
    /// A run of `4062` answers longer than the skew window. A
    /// [`PushRegistrarTask::register`] command also clears this one, because
    /// the device clock may have been corrected since.
    StaleBeyondSkew,
}

/// A request a relay refused for good (ADR-004), which the registrar does not
/// send again.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Refusal {
    request: Request,
    cause: RefusalCause,
}

/// A run of consecutive `4062` answers from one relay to one request.
#[derive(Debug, Clone, PartialEq, Eq)]
struct StaleRun {
    request: Request,
    /// The device clock's second at the first `4062` of the run.
    first_secs: u64,
}

/// Whether [`PushRegistrar::forget_stale_refusals`] also drops the refusals
/// recorded as [`RefusalCause::StaleBeyondSkew`] and every `4062` run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StaleBound {
    /// Keep them while their request is still the one the registrar sends.
    Keep,
    /// Drop them: a [`PushRegistrarTask::register`] command.
    Clear,
}

/// A signed message ready to publish.
struct Prepared {
    relay_url: String,
    push_routing_id: [u8; 32],
    blob: Vec<u8>,
}

/// Registers this device's push token with relays (§10.7.1).
///
/// Every method takes `&mut self`, so one owner serializes the operations;
/// [`Self::spawn_trigger`] makes that owner a task.
pub struct PushRegistrar<C: KeyCustody, S: Storage> {
    signing_key: PushSigningKey<C>,
    publisher: Arc<dyn PushRelayPublisher>,
    clock: Arc<dyn Clock>,
    platform: PushPlatform,
    token: PushToken,
    storage: Arc<ProtocolRepository<S>>,
    /// Per canonical relay URL, the registration the relay accepted last for
    /// `token`, while no deregistration of `token` has been sent to the relay
    /// since. [`Self::deregister_token`] removes the entry before it publishes
    /// a deregistration of `token`, because a relay can apply a
    /// deregistration whose OK is lost; an entry here therefore never claims
    /// a registration that a deregistration may have removed.
    accepted: BTreeMap<String, PushTarget>,
    /// The durable relay ledger as loaded and written, per (canonical relay
    /// URL, token hash): every relay that may hold a registration.
    ledger: BTreeMap<(String, TokenHash), PushRelayRecord>,
    /// Per (canonical relay URL, token hash), the request the relay refused
    /// for good.
    refused: BTreeMap<RelayKey, Refusal>,
    /// Per (canonical relay URL, token hash), the run of consecutive `4062`
    /// answers to the request the registrar sends there. A relay answer
    /// other than `4062` ends the run; an unreachable relay gives no answer
    /// and leaves it.
    stale_runs: BTreeMap<RelayKey, StaleRun>,
    /// Per (canonical relay URL, token hash), the last `timestamp` sent.
    last_timestamp: HashMap<(String, TokenHash), u64>,
    /// Whether a reconcile registers the current routes. A
    /// [`PushRegistrarTask::deregister_all`] clears it and a
    /// [`PushRegistrarTask::register`] sets it.
    enabled: bool,
}

impl<C: KeyCustody, S: Storage> PushRegistrar<C, S> {
    /// Builds a registrar over the relay ledger in `config.storage`. It has
    /// registered nothing in this process; the first reconcile deregisters
    /// every recorded relay that hosts no context of this device.
    ///
    /// # Errors
    ///
    /// [`PushError::Message`] with [`PushMessageError::EmptyToken`] when
    /// `config.token` is empty; [`PushError::WebPushUnsupported`] when
    /// `config.platform` is `WebPush`; [`PushError::Ledger`] when the ledger
    /// cannot be read.
    pub async fn new(config: PushRegistrarConfig<C, S>) -> Result<Self, PushError> {
        if config.token.is_empty() {
            return Err(PushMessageError::EmptyToken.into());
        }
        if config.platform == PushPlatform::WebPush {
            return Err(PushError::WebPushUnsupported);
        }
        let ledger = config
            .storage
            .load_push_relays()
            .await
            .map_err(PushError::Ledger)?
            .into_iter()
            .map(|record| {
                (
                    (record.relay_url.clone(), token_hash(&record.token)),
                    record,
                )
            })
            .collect();
        Ok(Self {
            signing_key: config.signing_key,
            publisher: config.publisher,
            clock: config.clock,
            platform: config.platform,
            token: config.token,
            storage: config.storage,
            accepted: BTreeMap::new(),
            ledger,
            refused: BTreeMap::new(),
            stale_runs: BTreeMap::new(),
            last_timestamp: HashMap::new(),
            enabled: true,
        })
    }

    /// Publishes a signed `PushRegistration` of each target's routing IDs to
    /// its relay, concurrently, and records each one the relay accepts. Each
    /// relay is written to the ledger before its message is published.
    ///
    /// A tier 3 relay gets [`PushError::Tier3Unsupported`] and nothing is
    /// published to it; a relay whose ledger write fails gets
    /// [`PushError::Ledger`] and nothing is published to it.
    ///
    /// # Errors
    ///
    /// [`PushError::DuplicateRelay`] when two targets name one relay; nothing
    /// is published. Every other failure is that relay's entry in the result.
    pub async fn register(&mut self, targets: &[PushTarget]) -> Result<RelayResults, PushError> {
        refuse_duplicates(targets.iter().map(|target| &target.relay))?;
        let mut results = RelayResults::new();
        let mut prepared = Vec::with_capacity(targets.len());
        for target in targets {
            match self.prepare_registration(target).await {
                Ok(message) => prepared.push(message),
                Err(err) => {
                    results.insert(target.relay.canonical_url().to_owned(), Err(err));
                }
            }
        }
        for (relay_url, outcome) in self.publish_all(prepared).await {
            let outcome = match targets
                .iter()
                .find(|target| target.relay.canonical_url() == relay_url)
            {
                Some(target) => self.settle_registration(target, outcome).await,
                None => outcome,
            };
            results.insert(relay_url, outcome);
        }
        Ok(results)
    }

    /// Publishes a signed `PushDeregistration` of the current token to each
    /// relay, concurrently. Each relay that accepts it is removed from the
    /// ledger.
    ///
    /// # Errors
    ///
    /// [`PushError::DuplicateRelay`] when two entries name one relay; nothing
    /// is published. Every other failure is that relay's entry in the result.
    pub async fn deregister(&mut self, relays: &[PushRelay]) -> Result<RelayResults, PushError> {
        let token = self.token.clone();
        self.deregister_token(relays, self.platform, &token).await
    }

    /// Replaces the device token (§10.7.1 **Token refresh**): each relay the
    /// ledger lists for the old token gets a `PushDeregistration` of it, and
    /// then each relay that had accepted a registration gets a
    /// `PushRegistration` of the same routing IDs for `new_token`. The
    /// registration is sent whatever the deregistration's outcome, because
    /// the relay's 3-failure rule removes an old token never deregistered. A
    /// relay whose step failed keeps its ledger record, so the next reconcile
    /// sends it again.
    ///
    /// # Errors
    ///
    /// [`PushError::Message`] with [`PushMessageError::EmptyToken`] when
    /// `new_token` is empty; nothing is published and the token is kept.
    pub async fn refresh_token(
        &mut self,
        new_token: PushToken,
    ) -> Result<RelayOutcomes, PushError> {
        if new_token.is_empty() {
            return Err(PushMessageError::EmptyToken.into());
        }
        let old_token = std::mem::replace(&mut self.token, new_token);
        let old_hash = token_hash(&old_token);
        let previous = std::mem::take(&mut self.accepted);
        let mut outcomes = RelayOutcomes::default();
        let mut relays = Vec::new();
        for ((relay_url, _), record) in self
            .ledger
            .iter()
            .filter(|((_, hash), _)| *hash == old_hash)
        {
            match PushRelay::direct(relay_url) {
                Ok(relay) => relays.push((relay, record.platform)),
                Err(err) => {
                    outcomes
                        .deregistered
                        .insert(relay_url.clone(), Err(err.into()));
                }
            }
        }
        for (platform, group) in by_platform(relays) {
            for (relay_url, outcome) in self.deregister_token(&group, platform, &old_token).await? {
                merge_outcome(&mut outcomes.deregistered, relay_url, outcome);
            }
        }
        let targets: Vec<PushTarget> = previous.into_values().collect();
        outcomes.registered = self.register(&targets).await?;
        Ok(outcomes)
    }

    /// Brings every relay in line with the supervisor's current routing IDs
    /// (§10.7.1 **Re-registration**):
    ///
    /// 1. a `PushDeregistration` to each relay the ledger lists for an old
    ///    token, or that hosts no context of this device;
    /// 2. a `PushRegistration` to each relay whose routing-ID set differs from
    ///    the one it accepted last.
    ///
    /// A relay whose set did not change gets nothing, and neither does a
    /// relay that refused the same request for good. While the registrar is
    /// disabled ([`PushRegistrarTask::deregister_all`]) no routing ID is
    /// wanted, so every recorded relay is deregistered.
    ///
    /// # Errors
    ///
    /// [`PushError::Routes`] when the routing-ID query fails; nothing is
    /// published, because a registration built from a partial set would drop
    /// the wakes of the missing contexts, and a deregistration built from it
    /// would drop every wake on the relay.
    pub(crate) async fn reconcile(
        &mut self,
        supervisor: &Supervisor,
    ) -> Result<RelayOutcomes, PushError> {
        self.reconcile_with(supervisor, StaleBound::Keep).await
    }

    /// [`Self::reconcile`], which with [`StaleBound::Clear`] first drops every
    /// refusal recorded as [`RefusalCause::StaleBeyondSkew`] and every `4062`
    /// run, so each such relay is sent its request again with a full window.
    async fn reconcile_with(
        &mut self,
        supervisor: &Supervisor,
        stale_bound: StaleBound,
    ) -> Result<RelayOutcomes, PushError> {
        let current = if self.enabled {
            Box::pin(supervisor.push_routing_ids())
                .await
                .map_err(PushError::Routes)?
        } else {
            BTreeMap::new()
        };
        let wanted: BTreeMap<String, BTreeSet<[u8; 32]>> = current
            .into_iter()
            .filter(|(_, routing_ids)| !routing_ids.is_empty())
            .collect();
        self.forget_stale_refusals(&wanted, stale_bound);
        let current_hash = token_hash(&self.token);
        let mut outcomes = RelayOutcomes::default();

        // Deregistrations first, so on one relay an old token's
        // deregistration precedes the new token's registration (§10.7.1
        // **Token refresh**).
        let mut stale = BTreeMap::<TokenHash, (PushToken, Vec<(PushRelay, PushPlatform)>)>::new();
        for ((relay_url, hash), record) in &self.ledger {
            let still_wanted = *hash == current_hash && wanted.contains_key(relay_url);
            let refused = self
                .refused
                .get(&(relay_url.clone(), *hash))
                .is_some_and(|refusal| refusal.request == Request::Deregistration);
            if still_wanted || refused {
                continue;
            }
            match PushRelay::direct(relay_url) {
                Ok(relay) => stale
                    .entry(*hash)
                    .or_insert_with(|| (record.token.clone(), Vec::new()))
                    .1
                    .push((relay, record.platform)),
                Err(err) => {
                    outcomes
                        .deregistered
                        .insert(relay_url.clone(), Err(err.into()));
                }
            }
        }
        for (token, relays) in stale.into_values() {
            for (platform, group) in by_platform(relays) {
                for (relay_url, outcome) in self.deregister_token(&group, platform, &token).await? {
                    merge_outcome(&mut outcomes.deregistered, relay_url, outcome);
                }
            }
        }

        let mut changed = Vec::new();
        for (relay_url, routing_ids) in wanted {
            let unchanged = self
                .accepted
                .get(&relay_url)
                .is_some_and(|accepted| accepted.routing_ids == routing_ids);
            let refused = self
                .refused
                .get(&(relay_url.clone(), current_hash))
                .is_some_and(|refusal| {
                    matches!(&refusal.request, Request::Registration(ids) if *ids == routing_ids)
                });
            if unchanged || refused {
                continue;
            }
            match PushRelay::direct(&relay_url) {
                Ok(relay) => changed.push(PushTarget { relay, routing_ids }),
                Err(err) => {
                    outcomes.registered.insert(relay_url, Err(err.into()));
                }
            }
        }
        outcomes.registered.extend(self.register(&changed).await?);
        Ok(outcomes)
    }

    /// Moves the registrar into a task that reconciles at start, on every
    /// [`Supervisor::push_routes_changed`] change and after every command,
    /// retries a retryable failure with the ADR-004 backoff, and stops when
    /// `shutdown` is cancelled, also in the middle of a command.
    pub fn spawn_trigger(
        self,
        supervisor: Arc<Supervisor>,
        shutdown: CancellationToken,
    ) -> PushRegistrarTask
    where
        C: 'static,
        S: 'static,
    {
        let routes = supervisor.push_routes_changed();
        let (commands_tx, commands) = mpsc::channel(COMMAND_CAPACITY);
        let triggers = Triggers {
            routes,
            commands,
            shutdown,
        };
        let join = tokio::spawn(self.run(supervisor, triggers));
        PushRegistrarTask {
            commands: commands_tx,
            join,
        }
    }

    /// Drops every refusal and every `4062` run whose request the registrar
    /// would no longer send: a registration's once the relay's wanted set or
    /// the token changed, and a deregistration's once the ledger no longer
    /// lists the pair or the relay is wanted again under the current token.
    /// With [`StaleBound::Clear`] it also drops every
    /// [`RefusalCause::StaleBeyondSkew`] refusal and every `4062` run.
    fn forget_stale_refusals(
        &mut self,
        wanted: &BTreeMap<String, BTreeSet<[u8; 32]>>,
        stale_bound: StaleBound,
    ) {
        let current_hash = token_hash(&self.token);
        let ledger = &self.ledger;
        let still_sent = |key: &RelayKey, request: &Request| match request {
            Request::Registration(routing_ids) => {
                key.1 == current_hash && wanted.get(&key.0) == Some(routing_ids)
            }
            Request::Deregistration => {
                ledger.contains_key(key) && (key.1 != current_hash || !wanted.contains_key(&key.0))
            }
        };
        let clear = stale_bound == StaleBound::Clear;
        self.refused.retain(|key, refusal| {
            still_sent(key, &refusal.request)
                && !(clear && refusal.cause == RefusalCause::StaleBeyondSkew)
        });
        self.stale_runs
            .retain(|key, run| !clear && still_sent(key, &run.request));
    }

    /// Settles a failed publish of `request` on `key`. A `4062` extends the
    /// key's run and becomes [`PushError::StaleBeyondSkew`] once the run spans
    /// more than [`PUSH_TIMESTAMP_SKEW_SECS`] of the device clock; any other
    /// relay answer ends the run, and an unreachable relay leaves it. A
    /// terminal refusal is recorded so the request is not sent again.
    fn settle_failure(&mut self, key: RelayKey, request: Request, err: PushError) -> PushError {
        let err = match err {
            PushError::Stale { msg } => self.extend_stale_run(&key, &request, msg),
            err @ PushError::Unreachable { .. } => err,
            err => {
                self.stale_runs.remove(&key);
                err
            }
        };
        if err.is_terminal_refusal() {
            let cause = if matches!(err, PushError::StaleBeyondSkew { .. }) {
                RefusalCause::StaleBeyondSkew
            } else {
                RefusalCause::Code
            };
            self.refused.insert(key, Refusal { request, cause });
        }
        err
    }

    /// Adds one `4062` to the run of `request` on `key`, starting a new run
    /// when none is open for that request.
    fn extend_stale_run(&mut self, key: &RelayKey, request: &Request, msg: String) -> PushError {
        let now = self.clock.now_secs();
        match self.stale_runs.get(key) {
            Some(run) if run.request == *request => {
                let span_secs = now.saturating_sub(run.first_secs);
                if span_secs > PUSH_TIMESTAMP_SKEW_SECS {
                    self.stale_runs.remove(key);
                    return PushError::StaleBeyondSkew { msg, span_secs };
                }
            }
            _ => {
                self.stale_runs.insert(
                    key.clone(),
                    StaleRun {
                        request: request.clone(),
                        first_secs: now,
                    },
                );
            }
        }
        PushError::Stale { msg }
    }

    /// Writes (`relay_url`, current token) to the ledger unless it is there.
    async fn record_relay(&mut self, relay_url: &str) -> Result<(), PushError> {
        let key = (relay_url.to_owned(), token_hash(&self.token));
        if self.ledger.contains_key(&key) {
            return Ok(());
        }
        let record = PushRelayRecord {
            relay_url: relay_url.to_owned(),
            platform: self.platform,
            token: self.token.clone(),
        };
        self.storage
            .store_push_relay(&record)
            .await
            .map_err(PushError::Ledger)?;
        self.ledger.insert(key, record);
        Ok(())
    }

    /// Deletes (`relay_url`, `token`) from the ledger.
    async fn forget_relay(&mut self, relay_url: &str, token: &PushToken) -> Result<(), PushError> {
        self.storage
            .delete_push_relay(relay_url, token)
            .await
            .map_err(PushError::Ledger)?;
        self.ledger
            .remove(&(relay_url.to_owned(), token_hash(token)));
        Ok(())
    }

    /// Applies one registration outcome: an accepted set is recorded, a
    /// refusal for good is remembered, and a refusal that shows the relay
    /// holds nothing removes the relay from the ledger.
    async fn settle_registration(
        &mut self,
        target: &PushTarget,
        outcome: Result<(), PushError>,
    ) -> Result<(), PushError> {
        let relay_url = target.relay.canonical_url().to_owned();
        let key = (relay_url.clone(), token_hash(&self.token));
        match outcome {
            Ok(()) => {
                self.refused.remove(&key);
                self.stale_runs.remove(&key);
                self.accepted.insert(relay_url, target.clone());
                Ok(())
            }
            Err(err) => {
                let err = self.settle_failure(
                    key,
                    Request::Registration(target.routing_ids.clone()),
                    err,
                );
                if err.relay_holds_nothing() {
                    self.accepted.remove(&relay_url);
                    let token = self.token.clone();
                    self.forget_after_refusal(&relay_url, &token, &err).await;
                }
                Err(err)
            }
        }
    }

    /// Applies one deregistration outcome of `token`: an accepted
    /// deregistration removes the relay from the ledger, and the ledger
    /// delete's failure becomes the relay's outcome, so the deregistration is
    /// retried. `accepted` is not touched here: [`Self::deregister_token`]
    /// cleared the relay's entry before the publish.
    async fn settle_deregistration(
        &mut self,
        relay_url: &str,
        token: &PushToken,
        outcome: Result<(), PushError>,
    ) -> Result<(), PushError> {
        let key = (relay_url.to_owned(), token_hash(token));
        match outcome {
            Ok(()) => {
                self.refused.remove(&key);
                self.stale_runs.remove(&key);
                self.forget_relay(relay_url, token).await
            }
            Err(err) => {
                let err = self.settle_failure(key, Request::Deregistration, err);
                if err.relay_holds_nothing() {
                    self.forget_after_refusal(relay_url, token, &err).await;
                }
                Err(err)
            }
        }
    }

    /// Removes a relay that showed it holds nothing from the ledger. The
    /// relay's refusal stays the outcome; a failed delete leaves the record,
    /// which only costs a later deregistration the relay accepts, and is
    /// logged.
    async fn forget_after_refusal(
        &mut self,
        relay_url: &str,
        token: &PushToken,
        refusal: &PushError,
    ) {
        if let Err(err) = self.forget_relay(relay_url, token).await {
            tracing::warn!(
                relay_url = %relay_url,
                refusal = %refusal,
                error = %err,
                "push registrar: the relay holds no registration, but its ledger record stays"
            );
        }
    }

    async fn prepare_registration(&mut self, target: &PushTarget) -> Result<Prepared, PushError> {
        refuse_tier3(&target.relay)?;
        let relay_url = target.relay.canonical_url().to_owned();
        self.record_relay(&relay_url).await?;
        let token = self.token.clone();
        let timestamp = self.next_timestamp(&relay_url, &token).await?;
        let mut message = PushRegistration {
            registrant: self.signing_key.registrant().clone(),
            platform: self.platform,
            token: token.as_bytes().to_vec(),
            routing_ids: target.routing_ids.iter().copied().collect(),
            timestamp,
            signature: [0; SIGNATURE_LEN],
        };
        let preimage = push_registration_signing_bytes(&message, &target.relay)?;
        message.signature = self.signing_key.sign_preimage(&preimage).await?;
        Ok(Prepared {
            relay_url,
            push_routing_id: target.relay.push_routing_id(),
            blob: message.to_msgpack()?,
        })
    }

    async fn prepare_deregistration(
        &mut self,
        relay: &PushRelay,
        platform: PushPlatform,
        token: &PushToken,
    ) -> Result<Prepared, PushError> {
        refuse_tier3(relay)?;
        let relay_url = relay.canonical_url().to_owned();
        let timestamp = self.next_timestamp(&relay_url, token).await?;
        let mut message = PushDeregistration {
            registrant: self.signing_key.registrant().clone(),
            platform,
            token: token.as_bytes().to_vec(),
            timestamp,
            signature: [0; SIGNATURE_LEN],
        };
        let preimage = push_deregistration_signing_bytes(&message, relay)?;
        message.signature = self.signing_key.sign_preimage(&preimage).await?;
        Ok(Prepared {
            relay_url,
            push_routing_id: relay.push_routing_id(),
            blob: message.to_msgpack()?,
        })
    }

    /// Publishes a signed `PushDeregistration` of `token` to each relay,
    /// concurrently, and settles each outcome.
    ///
    /// When `token` is the current token, each relay's `accepted` entry is
    /// removed before its message is published, whatever the outcome: a
    /// relay can remove the registration and lose the OK, and a kept entry
    /// would make the next reconcile skip the relay as unchanged while it
    /// holds nothing.
    async fn deregister_token(
        &mut self,
        relays: &[PushRelay],
        platform: PushPlatform,
        token: &PushToken,
    ) -> Result<RelayResults, PushError> {
        refuse_duplicates(relays.iter())?;
        let mut results = RelayResults::new();
        let mut prepared = Vec::with_capacity(relays.len());
        let current = *token == self.token;
        for relay in relays {
            if current {
                self.accepted.remove(relay.canonical_url());
            }
            match self.prepare_deregistration(relay, platform, token).await {
                Ok(message) => prepared.push(message),
                Err(err) => {
                    results.insert(relay.canonical_url().to_owned(), Err(err));
                }
            }
        }
        for (relay_url, outcome) in self.publish_all(prepared).await {
            let outcome = self.settle_deregistration(&relay_url, token, outcome).await;
            results.insert(relay_url, outcome);
        }
        Ok(results)
    }

    /// Publishes every prepared message concurrently.
    async fn publish_all(&self, prepared: Vec<Prepared>) -> Vec<(String, Result<(), PushError>)> {
        futures::future::join_all(prepared.into_iter().map(|message| async move {
            let Prepared {
                relay_url,
                push_routing_id,
                blob,
            } = message;
            let outcome = self
                .publisher
                .publish(&relay_url, push_routing_id, blob)
                .await
                .map_err(PushError::from);
            (relay_url, outcome)
        }))
        .await
    }

    /// The `timestamp` for the next message on (`relay_url`, `token`): the
    /// clock's current second, once that second is after the last one sent
    /// for the key (§10.7.1 **Freshness**). When the clock still reads the
    /// last second, the registrar waits for the next one; it never sends a
    /// second ahead of its clock, which the relay's skew check would refuse.
    ///
    /// An entry is pruned only once it is more than the skew window behind
    /// the clock: the relay refuses a timestamp that old in any case, so the
    /// entry no longer stops a clock that stepped back from sending a
    /// timestamp at or below one the relay holds.
    async fn next_timestamp(
        &mut self,
        relay_url: &str,
        token: &PushToken,
    ) -> Result<u64, PushError> {
        let key = (relay_url.to_owned(), token_hash(token));
        let mut waits = 0;
        loop {
            let now = self.clock.now_secs();
            match self.last_timestamp.get(&key).copied() {
                Some(last) if now < last || (now == last && waits >= MAX_SECOND_WAITS) => {
                    return Err(PushError::ClockBehind { now, last });
                }
                Some(last) if now == last => {
                    waits += 1;
                    let into_second = self.clock.now_millis() % 1000;
                    tokio::time::sleep(Duration::from_millis(1000 - into_second)).await;
                }
                _ => {
                    self.last_timestamp
                        .retain(|_, last| last.saturating_add(PUSH_TIMESTAMP_SKEW_SECS) >= now);
                    self.last_timestamp.insert(key, now);
                    return Ok(now);
                }
            }
        }
    }

    async fn run(mut self, supervisor: Arc<Supervisor>, mut triggers: Triggers) {
        let mut pending = true;
        let mut backoff = Backoff::default();
        let mut commands_open = true;
        loop {
            if pending {
                pending = false;
                triggers.drain();
                let failed = tokio::select! {
                    biased;
                    () = triggers.shutdown.cancelled() => return,
                    failed = self.reconcile_and_log(&supervisor) => failed,
                };
                backoff.settle(failed);
            }
            tokio::select! {
                biased;
                () = triggers.shutdown.cancelled() => return,
                () = backoff.wait() => pending = true,
                command = triggers.commands.recv(), if commands_open => match command {
                    Some(command) => {
                        let failed = tokio::select! {
                            biased;
                            () = triggers.shutdown.cancelled() => return,
                            failed = self.handle_command(command, &supervisor) => failed,
                        };
                        // A command can leave relays out of line (a refresh
                        // re-registers only accepted relays, a step can
                        // fail), and `reconcile` is diff-based: retry after
                        // the backoff when a relay failed retryably, else
                        // reconcile now.
                        if failed {
                            backoff.settle(true);
                        } else {
                            pending = true;
                        }
                    }
                    None => commands_open = false,
                },
                changed = triggers.routes.changed() => {
                    if changed.is_err() {
                        tracing::warn!("push registrar: the supervisor's route watch closed; stopping");
                        return;
                    }
                    pending = true;
                }
            }
        }
    }

    /// Runs one reconcile and logs every failure. Returns whether a retryable
    /// failure calls for a retry.
    async fn reconcile_and_log(&mut self, supervisor: &Supervisor) -> bool {
        let outcome = self.reconcile(supervisor).await;
        log_outcome("reconcile", &outcome)
    }

    /// Runs one command and answers it. Returns whether a relay failed
    /// retryably.
    async fn handle_command(&mut self, command: RegistrarCommand, supervisor: &Supervisor) -> bool {
        let (outcome, reply) = match command {
            RegistrarCommand::RefreshToken { token, reply } => {
                (self.refresh_token(token).await, reply)
            }
            RegistrarCommand::DeregisterAll { reply } => {
                self.enabled = false;
                (self.reconcile(supervisor).await, reply)
            }
            RegistrarCommand::Register { reply } => {
                self.enabled = true;
                (
                    self.reconcile_with(supervisor, StaleBound::Clear).await,
                    reply,
                )
            }
        };
        let failed = log_outcome("command", &outcome);
        if reply.send(outcome).is_err() {
            tracing::debug!("push registrar: the command's caller went away");
        }
        failed
    }
}

/// Logs every failure in `outcome`. Returns whether one is retryable.
fn log_outcome(operation: &str, outcome: &Result<RelayOutcomes, PushError>) -> bool {
    match outcome {
        Err(err) => {
            tracing::warn!(operation, error = %err, retryable = err.retryable(), "push registrar: operation failed");
            err.retryable()
        }
        Ok(outcomes) => {
            let mut retry = false;
            for (relay_url, err) in outcomes.failures() {
                tracing::warn!(
                    operation,
                    relay_url = %relay_url,
                    error = %err,
                    retryable = err.retryable(),
                    "push registrar: relay did not take the push message"
                );
                retry |= err.retryable();
            }
            retry
        }
    }
}

/// Inserts `outcome` for `relay_url`, keeping an earlier failure: one relay
/// can get two deregistrations in one operation (one per recorded token), and
/// its entry reports the failure when either failed.
fn merge_outcome(results: &mut RelayResults, relay_url: String, outcome: Result<(), PushError>) {
    match results.get(&relay_url) {
        Some(Err(_)) => {}
        _ => {
            results.insert(relay_url, outcome);
        }
    }
}

/// Groups `relays` by platform, one group per platform, each naming a relay
/// once.
fn by_platform(relays: Vec<(PushRelay, PushPlatform)>) -> Vec<(PushPlatform, Vec<PushRelay>)> {
    let mut groups: Vec<(PushPlatform, Vec<PushRelay>)> = Vec::new();
    for (relay, platform) in relays {
        match groups.iter_mut().find(|(p, _)| *p == platform) {
            Some((_, group)) => group.push(relay),
            None => groups.push((platform, vec![relay])),
        }
    }
    groups
}

/// The ADR-004 retry timer of the registrar task.
#[derive(Default)]
struct Backoff {
    failures: usize,
    retry: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl Backoff {
    /// Arms the next retry after a retryable failure; clears the timer and
    /// the failure count after a clean pass.
    fn settle(&mut self, failed: bool) {
        if failed {
            self.retry = Some(Box::pin(tokio::time::sleep(backoff_delay(self.failures))));
            self.failures = self.failures.saturating_add(1);
        } else {
            self.retry = None;
            self.failures = 0;
        }
    }

    /// Completes when the armed retry is due; never when none is armed. The
    /// timer is consumed, so the retry fires once.
    async fn wait(&mut self) {
        match self.retry.as_mut() {
            Some(sleep) => {
                sleep.as_mut().await;
                self.retry = None;
            }
            None => std::future::pending().await,
        }
    }
}

/// The trigger sources of the registrar task.
struct Triggers {
    routes: watch::Receiver<u64>,
    commands: mpsc::Receiver<RegistrarCommand>,
    shutdown: CancellationToken,
}

impl Triggers {
    /// Marks the route watch seen. The reconcile that follows reads the
    /// routes after this point, so it covers every earlier change; a change
    /// during it starts another reconcile.
    fn drain(&mut self) {
        self.routes.borrow_and_update();
    }
}

/// A command to the registrar task.
enum RegistrarCommand {
    RefreshToken {
        token: PushToken,
        reply: oneshot::Sender<Result<RelayOutcomes, PushError>>,
    },
    DeregisterAll {
        reply: oneshot::Sender<Result<RelayOutcomes, PushError>>,
    },
    Register {
        reply: oneshot::Sender<Result<RelayOutcomes, PushError>>,
    },
}

/// The running trigger task of a [`PushRegistrar`].
pub struct PushRegistrarTask {
    commands: mpsc::Sender<RegistrarCommand>,
    join: JoinHandle<()>,
}

impl PushRegistrarTask {
    /// [`PushRegistrar::refresh_token`], run by the task between reconciles.
    ///
    /// # Errors
    ///
    /// [`PushError::RegistrarStopped`] when the task has stopped, and every
    /// error of [`PushRegistrar::refresh_token`].
    pub async fn refresh_token(&self, token: PushToken) -> Result<RelayOutcomes, PushError> {
        self.send(|reply| RegistrarCommand::RefreshToken { token, reply })
            .await
    }

    /// Deregisters the token at every relay the ledger lists and stops
    /// registering: until [`Self::register`], every reconcile wants no
    /// routing ID, so a relay whose deregistration failed is sent it again
    /// and a relay that accepts it leaves the ledger.
    ///
    /// # Errors
    ///
    /// [`PushError::RegistrarStopped`] when the task has stopped. Each
    /// relay's failure is its entry in the result.
    pub async fn deregister_all(&self) -> Result<RelayOutcomes, PushError> {
        self.send(|reply| RegistrarCommand::DeregisterAll { reply })
            .await
    }

    /// Resumes registering after [`Self::deregister_all`] and reconciles at
    /// once. A registrar starts registering, so this is needed only after a
    /// [`Self::deregister_all`]. It also drops every refusal recorded as
    /// [`PushError::StaleBeyondSkew`], so those relays are sent their request
    /// again, for example after the device clock was corrected.
    ///
    /// # Errors
    ///
    /// [`PushError::RegistrarStopped`] when the task has stopped, and
    /// [`PushError::Routes`] when the routing-ID query fails. Each relay's
    /// failure is its entry in the result.
    pub async fn register(&self) -> Result<RelayOutcomes, PushError> {
        self.send(|reply| RegistrarCommand::Register { reply })
            .await
    }

    async fn send(
        &self,
        command: impl FnOnce(oneshot::Sender<Result<RelayOutcomes, PushError>>) -> RegistrarCommand,
    ) -> Result<RelayOutcomes, PushError> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(command(reply))
            .await
            .map_err(|_| PushError::RegistrarStopped)?;
        answer.await.map_err(|_| PushError::RegistrarStopped)?
    }

    /// The task's join handle, for awaiting its stop after shutdown.
    #[must_use]
    pub fn into_join_handle(self) -> JoinHandle<()> {
        self.join
    }
}

/// The ADR-004 delay before retry number `failures + 1`.
fn backoff_delay(failures: usize) -> Duration {
    let index = failures.min(BACKOFF_SECS.len() - 1);
    Duration::from_secs(BACKOFF_SECS[index])
}

fn refuse_tier3(relay: &PushRelay) -> Result<(), PushError> {
    if relay.bridge_target().is_some() {
        return Err(PushError::Tier3Unsupported {
            relay_url: relay.canonical_url().to_owned(),
        });
    }
    Ok(())
}

fn refuse_duplicates<'a>(relays: impl Iterator<Item = &'a PushRelay>) -> Result<(), PushError> {
    let mut seen = BTreeSet::new();
    for relay in relays {
        if !seen.insert(relay.canonical_url()) {
            return Err(PushError::DuplicateRelay {
                relay_url: relay.canonical_url().to_owned(),
            });
        }
    }
    Ok(())
}
