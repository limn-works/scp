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
//! [`PushRegistrar::spawn_trigger`] moves the registrar into one task, which
//! serializes every reconcile and token refresh. The task reconciles at start,
//! whenever [`Supervisor::push_routes_changed`] reports an added or removed
//! context actor, and on member, close, expiry and tombstone events. It retries
//! a retryable failure with the ADR-004 backoff and stops on its shutdown
//! token.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures::future::BoxFuture;
use scp_clock::Clock;
use scp_crypto::p256::{COMPRESSED_POINT_LEN, P256PublicKey, SIGNATURE_LEN, verify_prehash_strict};
use scp_did::DID;
use scp_platform::{KeyCustody, KeyHandle, PlatformError};
use scp_protocol::context::ContextError;
use scp_protocol::context::membership::ContextEvent;
use scp_protocol::discovery::push::{
    PushDeregistration, PushMessageError, PushPlatform, PushRegistration, PushRelay,
    push_deregistration_signing_bytes, push_registration_signing_bytes,
};
use scp_relay_client::{code, sanitize_relay_text};
use sha2::{Digest, Sha256};
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::context::supervisor::Supervisor;

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
    /// The supervisor has no context-event channel, so the trigger task would
    /// miss close, expiry and tombstone changes.
    #[error("the supervisor has no context-event channel")]
    EventsUnavailable,
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
    /// unreachable relay, a clock behind the last timestamp, and a failed
    /// routing-ID query. ADR-004 has a client never retry a `4xxx` code as-is,
    /// so `4060`-`4064` are not retryable.
    #[must_use]
    pub const fn retryable(&self) -> bool {
        matches!(
            self,
            Self::VerifierUnavailable { .. }
                | Self::KeyStateUnavailable { .. }
                | Self::RelayFailed { .. }
                | Self::Unreachable { .. }
                | Self::ClockBehind { .. }
                | Self::Routes(_)
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
    /// the relay exists or the publish gets no answer.
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

/// The per-relay outcomes of [`PushRegistrar::refresh_token`]. Both maps hold
/// the same relays: every relay that held a registration of the old token.
#[derive(Debug)]
pub struct TokenRefresh {
    /// The `PushDeregistration` of the old token, per relay.
    pub deregistered: RelayResults,
    /// The `PushRegistration` of the new token, per relay.
    pub registered: RelayResults,
}

/// Construction parameters for [`PushRegistrar`].
pub struct PushRegistrarConfig<C: KeyCustody> {
    /// The key every message is signed with.
    pub signing_key: PushSigningKey<C>,
    /// Delivers each message to its relay.
    pub publisher: Arc<dyn PushRelayPublisher>,
    /// The clock every `timestamp` is read from.
    pub clock: Arc<dyn Clock>,
    /// The push platform the token belongs to.
    pub platform: PushPlatform,
    /// The platform's device token. Never empty.
    pub token: Vec<u8>,
}

/// What a relay holds for this device's current token.
struct Registered {
    relay: PushRelay,
    routing_ids: BTreeSet<[u8; 32]>,
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
/// [`Self::spawn_trigger`] makes that owner a task. The registrar persists
/// nothing: after a restart it registers every relay again.
pub struct PushRegistrar<C: KeyCustody> {
    signing_key: PushSigningKey<C>,
    publisher: Arc<dyn PushRelayPublisher>,
    clock: Arc<dyn Clock>,
    platform: PushPlatform,
    token: Vec<u8>,
    /// Per canonical relay URL, the registration the relay accepted last for
    /// `token`.
    registered: BTreeMap<String, Registered>,
    /// Per (canonical relay URL, token), the last `timestamp` sent. An entry
    /// below the clock constrains nothing and is pruned.
    last_timestamp: HashMap<(String, Vec<u8>), u64>,
}

impl<C: KeyCustody> PushRegistrar<C> {
    /// Builds a registrar that has registered nothing.
    ///
    /// # Errors
    ///
    /// [`PushError::Message`] with [`PushMessageError::EmptyToken`] when
    /// `config.token` is empty.
    pub fn new(config: PushRegistrarConfig<C>) -> Result<Self, PushError> {
        if config.token.is_empty() {
            return Err(PushMessageError::EmptyToken.into());
        }
        Ok(Self {
            signing_key: config.signing_key,
            publisher: config.publisher,
            clock: config.clock,
            platform: config.platform,
            token: config.token,
            registered: BTreeMap::new(),
            last_timestamp: HashMap::new(),
        })
    }

    /// Publishes a signed `PushRegistration` of each target's routing IDs to
    /// its relay, concurrently, and records each one the relay accepts.
    ///
    /// A tier 3 relay gets [`PushError::Tier3Unsupported`] and nothing is
    /// published to it.
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
            if outcome.is_ok()
                && let Some(target) = targets
                    .iter()
                    .find(|target| target.relay.canonical_url() == relay_url)
            {
                self.registered.insert(
                    relay_url.clone(),
                    Registered {
                        relay: target.relay.clone(),
                        routing_ids: target.routing_ids.clone(),
                    },
                );
            }
            results.insert(relay_url, outcome);
        }
        Ok(results)
    }

    /// Publishes a signed `PushDeregistration` of the current token to each
    /// relay, concurrently, and forgets each registration the relay removes.
    ///
    /// # Errors
    ///
    /// [`PushError::DuplicateRelay`] when two entries name one relay; nothing
    /// is published. Every other failure is that relay's entry in the result.
    pub async fn deregister(&mut self, relays: &[PushRelay]) -> Result<RelayResults, PushError> {
        let token = self.token.clone();
        let results = self.deregister_token(relays, &token).await?;
        for (relay_url, outcome) in &results {
            if outcome.is_ok() {
                self.registered.remove(relay_url);
            }
        }
        Ok(results)
    }

    /// Replaces the device token (§10.7.1 **Token refresh**): each relay that
    /// holds a registration gets a `PushDeregistration` for the old token and
    /// then a `PushRegistration` of the same routing IDs for `new_token`. The
    /// registration is sent whatever the deregistration's outcome, because
    /// the relay's 3-failure rule removes an old token never deregistered.
    ///
    /// # Errors
    ///
    /// [`PushError::Message`] with [`PushMessageError::EmptyToken`] when
    /// `new_token` is empty; nothing is published and the token is kept.
    pub async fn refresh_token(&mut self, new_token: Vec<u8>) -> Result<TokenRefresh, PushError> {
        if new_token.is_empty() {
            return Err(PushMessageError::EmptyToken.into());
        }
        let old_token = std::mem::replace(&mut self.token, new_token);
        // Forget every registration first: if a step below fails, the next
        // reconcile registers each relay again under the new token.
        let previous = std::mem::take(&mut self.registered);
        let relays: Vec<PushRelay> = previous.values().map(|r| r.relay.clone()).collect();
        let deregistered = self.deregister_token(&relays, &old_token).await?;
        let targets: Vec<PushTarget> = previous
            .into_values()
            .map(|r| PushTarget {
                relay: r.relay,
                routing_ids: r.routing_ids,
            })
            .collect();
        let registered = self.register(&targets).await?;
        Ok(TokenRefresh {
            deregistered,
            registered,
        })
    }

    /// Brings every relay's registration in line with the supervisor's
    /// current routing IDs: a `PushRegistration` to each relay whose set
    /// differs from the one it accepted last, and a `PushDeregistration` to
    /// each relay that holds a registration and no longer hosts a context of
    /// this device (§10.7.1 **Re-registration**). A relay whose set did not
    /// change gets nothing.
    ///
    /// # Errors
    ///
    /// [`PushError::Routes`] when the routing-ID query fails; nothing is
    /// published, because a registration built from a partial set would drop
    /// the wakes of the missing contexts.
    pub(crate) async fn reconcile(
        &mut self,
        supervisor: &Supervisor,
    ) -> Result<RelayResults, PushError> {
        let current = Box::pin(supervisor.push_routing_ids())
            .await
            .map_err(PushError::Routes)?;
        let mut results = RelayResults::new();
        let gone: Vec<PushRelay> = self
            .registered
            .iter()
            .filter(|(url, _)| current.get(*url).is_none_or(BTreeSet::is_empty))
            .map(|(_, registered)| registered.relay.clone())
            .collect();
        let mut changed = Vec::new();
        for (relay_url, routing_ids) in current {
            if routing_ids.is_empty()
                || self
                    .registered
                    .get(&relay_url)
                    .is_some_and(|registered| registered.routing_ids == routing_ids)
            {
                continue;
            }
            match PushRelay::direct(&relay_url) {
                Ok(relay) => changed.push(PushTarget { relay, routing_ids }),
                Err(err) => {
                    results.insert(relay_url, Err(err.into()));
                }
            }
        }
        results.extend(self.register(&changed).await?);
        results.extend(self.deregister(&gone).await?);
        Ok(results)
    }

    /// Moves the registrar into a task that reconciles at start and on every
    /// trigger, retries a retryable failure with the ADR-004 backoff, and
    /// stops when `shutdown` is cancelled.
    ///
    /// # Errors
    ///
    /// [`PushError::EventsUnavailable`] when the supervisor has no
    /// context-event channel; no task is spawned.
    pub fn spawn_trigger(
        self,
        supervisor: Arc<Supervisor>,
        shutdown: CancellationToken,
    ) -> Result<PushRegistrarTask, PushError>
    where
        C: 'static,
    {
        let events = supervisor
            .subscribe_events()
            .ok_or(PushError::EventsUnavailable)?;
        let routes = supervisor.push_routes_changed();
        let (commands_tx, commands) = mpsc::channel(COMMAND_CAPACITY);
        let triggers = Triggers {
            events,
            routes,
            commands,
            shutdown,
        };
        let join = tokio::spawn(self.run(supervisor, triggers));
        Ok(PushRegistrarTask {
            commands: commands_tx,
            join,
        })
    }

    async fn prepare_registration(&mut self, target: &PushTarget) -> Result<Prepared, PushError> {
        refuse_tier3(&target.relay)?;
        let relay_url = target.relay.canonical_url().to_owned();
        let token = self.token.clone();
        let timestamp = self.next_timestamp(&relay_url, &token).await?;
        let mut message = PushRegistration {
            registrant: self.signing_key.registrant().clone(),
            platform: self.platform,
            token,
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
        token: &[u8],
    ) -> Result<Prepared, PushError> {
        refuse_tier3(relay)?;
        let relay_url = relay.canonical_url().to_owned();
        let timestamp = self.next_timestamp(&relay_url, token).await?;
        let mut message = PushDeregistration {
            registrant: self.signing_key.registrant().clone(),
            platform: self.platform,
            token: token.to_vec(),
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

    async fn deregister_token(
        &mut self,
        relays: &[PushRelay],
        token: &[u8],
    ) -> Result<RelayResults, PushError> {
        refuse_duplicates(relays.iter())?;
        let mut results = RelayResults::new();
        let mut prepared = Vec::with_capacity(relays.len());
        for relay in relays {
            match self.prepare_deregistration(relay, token).await {
                Ok(message) => prepared.push(message),
                Err(err) => {
                    results.insert(relay.canonical_url().to_owned(), Err(err));
                }
            }
        }
        results.extend(self.publish_all(prepared).await);
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
    async fn next_timestamp(&mut self, relay_url: &str, token: &[u8]) -> Result<u64, PushError> {
        let key = (relay_url.to_owned(), token.to_vec());
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
                    self.last_timestamp.retain(|_, last| *last >= now);
                    self.last_timestamp.insert(key, now);
                    return Ok(now);
                }
            }
        }
    }

    async fn run(mut self, supervisor: Arc<Supervisor>, mut triggers: Triggers) {
        let mut pending = true;
        let mut failures = 0usize;
        let mut retry: Option<Pin<Box<tokio::time::Sleep>>> = None;
        let mut commands_open = true;
        loop {
            if pending {
                pending = false;
                retry = None;
                triggers.drain();
                let failed = tokio::select! {
                    biased;
                    () = triggers.shutdown.cancelled() => return,
                    failed = self.reconcile_and_log(&supervisor) => failed,
                };
                if failed {
                    retry = Some(Box::pin(tokio::time::sleep(backoff_delay(failures))));
                    failures = failures.saturating_add(1);
                } else {
                    failures = 0;
                }
            }
            tokio::select! {
                biased;
                () = triggers.shutdown.cancelled() => return,
                () = wait_for_retry(&mut retry) => pending = true,
                command = triggers.commands.recv(), if commands_open => match command {
                    Some(command) => self.handle_command(command).await,
                    None => commands_open = false,
                },
                changed = triggers.routes.changed() => {
                    if changed.is_err() {
                        tracing::warn!("push registrar: the supervisor's route watch closed; stopping");
                        return;
                    }
                    pending = true;
                }
                event = triggers.events.recv() => match event {
                    Ok((_, event)) => pending |= is_route_hint(&event),
                    Err(broadcast::error::RecvError::Lagged(_)) => pending = true,
                    Err(broadcast::error::RecvError::Closed) => {
                        tracing::warn!("push registrar: the context-event channel closed; stopping");
                        return;
                    }
                },
            }
        }
    }

    /// Runs one reconcile and logs every failure. Returns whether a retryable
    /// failure calls for a retry.
    async fn reconcile_and_log(&mut self, supervisor: &Supervisor) -> bool {
        match self.reconcile(supervisor).await {
            Err(err) => {
                tracing::warn!(error = %err, retryable = err.retryable(), "push registrar: reconcile failed");
                err.retryable()
            }
            Ok(results) => {
                let mut retry = false;
                for (relay_url, outcome) in &results {
                    if let Err(err) = outcome {
                        tracing::warn!(
                            relay_url = %relay_url,
                            error = %err,
                            retryable = err.retryable(),
                            "push registrar: relay did not take the push message"
                        );
                        retry |= err.retryable();
                    }
                }
                retry
            }
        }
    }

    async fn handle_command(&mut self, command: RegistrarCommand) {
        match command {
            RegistrarCommand::RefreshToken { token, reply } => {
                let outcome = self.refresh_token(token).await;
                if reply.send(outcome).is_err() {
                    tracing::debug!("push registrar: token refresh caller went away");
                }
            }
        }
    }
}

/// The trigger sources of the registrar task.
struct Triggers {
    events: broadcast::Receiver<(String, ContextEvent)>,
    routes: watch::Receiver<u64>,
    commands: mpsc::Receiver<RegistrarCommand>,
    shutdown: CancellationToken,
}

impl Triggers {
    /// Marks every queued trigger seen. The reconcile that follows reads the
    /// routes after this point, so it covers each of them; a trigger that
    /// arrives during it starts another reconcile.
    fn drain(&mut self) {
        self.routes.borrow_and_update();
        while let Ok(_) | Err(broadcast::error::TryRecvError::Lagged(_)) = self.events.try_recv() {}
    }
}

/// A command to the registrar task.
enum RegistrarCommand {
    RefreshToken {
        token: Vec<u8>,
        reply: oneshot::Sender<Result<TokenRefresh, PushError>>,
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
    pub async fn refresh_token(&self, token: Vec<u8>) -> Result<TokenRefresh, PushError> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(RegistrarCommand::RefreshToken { token, reply })
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

/// Whether `event` can change this device's routing IDs without adding or
/// removing a context actor: a join or leave (a join can set this device's
/// pseudonym), and a close, expiry or tombstone (the actor stays and adds no
/// routes). A member event that changes nothing costs one routing-ID query
/// and publishes nothing, because [`PushRegistrar::reconcile`] compares sets.
const fn is_route_hint(event: &ContextEvent) -> bool {
    matches!(
        event,
        ContextEvent::MemberJoined { .. }
            | ContextEvent::MemberLeft { .. }
            | ContextEvent::SystemClose { .. }
            | ContextEvent::Expired
            | ContextEvent::ContextTombstoned { .. }
    )
}

/// The ADR-004 delay before retry number `failures + 1`.
fn backoff_delay(failures: usize) -> Duration {
    let index = failures.min(BACKOFF_SECS.len() - 1);
    Duration::from_secs(BACKOFF_SECS[index])
}

async fn wait_for_retry(retry: &mut Option<Pin<Box<tokio::time::Sleep>>>) {
    match retry {
        Some(sleep) => sleep.as_mut().await,
        None => std::future::pending().await,
    }
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
