//! Relay interception of push registration and deregistration (spec §10.7.1,
//! ADR-004 "Push registration interception", PUSH-007).
//!
//! Every PUBLISH whose `routing_id` is the relay's reserved push routing ID,
//! `SHA-256("scp-push-registration" || canonical relay_url)` or, for a tier 3
//! entry, `SHA-256("scp-push-bridge:" || canonical bridge_url ||
//! bridge_target)` (§9.18.2), goes
//! through [`gate_publish`] and never reaches blob storage or a subscriber,
//! whatever the result (§10.7.1 "No blob storage"):
//!
//! - [`PushRole::Disabled`] answers `4063` `PUSH_NOT_SUPPORTED`.
//! - `PushRole::Enabled` (built with the `push-store` feature) decodes the blob as a `PushRegistration` or a
//!   `PushDeregistration` (§22.11.4), refuses a platform with no configured
//!   sender (`4061`), applies the §10.7.1 freshness checks (`4062`), verifies
//!   the signature through the injected
//!   [`PushSignatureVerifier`](scp_identity::push_verify::PushSignatureVerifier)
//!   with the relay's own canonical URL and the `bridge_target` its reserved
//!   routing ID came from (`4060`, `5003`, `5004`), and only then
//!   changes the registration store. Any rejection leaves the store unchanged.
//!
//! A PUBLISH to any other routing ID passes through as
//! [`PushPublishGate::NotPush`]. No response message and no log line carries a
//! push token.

use std::collections::VecDeque;
use std::sync::Arc;
#[cfg(feature = "push-store")]
use std::time::Duration;

use tokio::sync::watch;

use scp_did::BridgeTarget;
#[cfg(feature = "push-store")]
use scp_identity::push_verify::{PushMessage, PushSignatureVerifier};
#[cfg(feature = "push-store")]
use scp_protocol::discovery::push::{PushDeregistration, PushPlatform, PushRegistration};
use scp_protocol::discovery::push::{PushMessageError, PushRelay};
use scp_relay_client::{RelayMessage, code};

#[cfg(feature = "push-store")]
use super::push::PushSender;
#[cfg(feature = "push-store")]
use super::push_dispatch::PushService;
#[cfg(feature = "push-store")]
use super::push_store::{PushRegistrationKey, PushRegistrationRecord, PushRegistrationStore};

/// The push timestamp skew window, in seconds (§9.18.13): a relay rejects a
/// push message whose `timestamp` differs from its clock by more than this.
pub const PUSH_TIMESTAMP_SKEW_SECS: u64 = 300;

/// How long the relay waits for one verifier call before answering `5004`
/// `PUSH_KEY_STATE_UNAVAILABLE` (ADR-004; indicator: 10 s).
#[cfg(feature = "push-store")]
pub const PUSH_VERIFY_TIMEOUT: Duration = Duration::from_secs(10);

/// The relay's own [`PushRelay`] (its URL in §9.18.2 canonical form and the
/// tier 3 `bridge_target` it is reached with) and the reserved push routing
/// ID derived from both (§10.7.1 step 2).
///
/// [`RelayUrl::new`] builds the relay with [`PushRelay::direct`], which holds
/// no target, so the ID is the `"scp-push-registration"` form. The conversion
/// from an `SCPRelay` entry goes through `PushRelay::from`, which keeps the
/// entry's target, so the ID is the tier 3 form when a target is present.
/// Either way the relay hands the verifier the one [`PushRelay`] its reserved
/// routing ID came from (§10.7.1 step 3), and no conversion drops the target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayUrl {
    relay: PushRelay,
    push_routing_id: [u8; 32],
}

impl RelayUrl {
    /// Canonicalizes `url` and derives the relay's reserved push routing ID,
    /// the `"scp-push-registration"` form, for a relay reached with no tier 3
    /// target.
    ///
    /// # Errors
    ///
    /// [`PushMessageError::InvalidRelayUrl`] when `url` has no §9.18.2
    /// canonical form.
    pub fn new(url: &str) -> Result<Self, PushMessageError> {
        Ok(Self::from(PushRelay::direct(url)?))
    }

    /// The relay entry the reserved routing ID was derived from, which the
    /// relay passes to the verifier (§10.7.1 step 3).
    #[must_use]
    pub const fn push_relay(&self) -> &PushRelay {
        &self.relay
    }

    /// The §9.18.2 canonical URL.
    #[must_use]
    pub fn canonical(&self) -> &str {
        self.relay.canonical_url()
    }

    /// The tier 3 `bridge_target` the reserved routing ID was derived with,
    /// or `None` for the `"scp-push-registration"` form.
    #[must_use]
    pub const fn bridge_target(&self) -> Option<BridgeTarget> {
        self.relay.bridge_target()
    }

    /// The reserved push routing ID: `SHA-256("scp-push-bridge:" ||
    /// canonical URL || bridge_target)` with a target, otherwise
    /// `SHA-256("scp-push-registration" || canonical URL)`.
    #[must_use]
    pub const fn push_routing_id(&self) -> [u8; 32] {
        self.push_routing_id
    }
}

impl From<PushRelay> for RelayUrl {
    /// Holds `relay` and derives its reserved push routing ID once.
    fn from(relay: PushRelay) -> Self {
        let push_routing_id = relay.push_routing_id();
        Self {
            relay,
            push_routing_id,
        }
    }
}

impl From<&scp_did::RelayService> for RelayUrl {
    /// The relay URL of an `SCPRelay` entry, with the entry's `bridgeTarget`.
    /// The entry holds its §9.18.2 canonical URL by construction, so the
    /// conversion cannot fail.
    fn from(relay: &scp_did::RelayService) -> Self {
        Self::from(PushRelay::from(relay))
    }
}

/// Whether a relay offers push (§10.7.1).
///
/// The default is [`PushRole::Disabled`], the fail-safe value in the same way
/// as `BridgeRole::Disabled` (ADR-052, construction standard M2 and M4): a
/// relay stores no push token until push is explicitly enabled.
#[derive(Debug, Clone, Default)]
pub enum PushRole {
    /// The relay offers no push and rejects every PUBLISH to its reserved push
    /// routing ID with `4063` `PUSH_NOT_SUPPORTED`.
    #[default]
    Disabled,
    /// The relay verifies and stores push registrations and wakes the
    /// registered devices through its running push service (PUSH-008).
    /// Compiled only with the `push-store` feature, which carries the
    /// registration store.
    #[cfg(feature = "push-store")]
    Enabled(PushService),
}

/// What a push-enabled relay needs: the store, the verifier, and the senders.
///
/// Every field is required and none has a default (ADR-062, capability
/// injection). It holds no runtime state: [`PushService::start`] takes it and
/// starts the queues and tasks that wake devices (ADR-052, configuration in,
/// runtime object out).
#[cfg(feature = "push-store")]
#[derive(Debug, Clone)]
pub struct PushServiceConfig {
    /// The registration store (PUSH-006).
    pub store: PushRegistrationStore,
    /// The signature verifier (PUSH-005). Production startup wires
    /// `KelPushVerifier`.
    pub verifier: Arc<dyn PushSignatureVerifier>,
    /// One sender per platform the relay wakes (PUSH-010, PUSH-011). A
    /// message for a platform with no sender here is refused with `4061`.
    pub senders: Arc<[PushSender]>,
}

#[cfg(feature = "push-store")]
impl PushServiceConfig {
    /// The configured sender for `platform`, if any.
    #[must_use]
    pub fn sender_for(&self, platform: PushPlatform) -> Option<&PushSender> {
        self.senders.iter().find(|s| s.platform() == platform)
    }
}

/// What [`gate_publish`] decided for one PUBLISH.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushPublishGate {
    /// The PUBLISH is not addressed to the reserved push routing ID; the relay
    /// handles it as an ordinary blob.
    NotPush,
    /// The relay accepted the registration or deregistration. It answers `OK`
    /// with no `blob_id`, because it stored no blob (ADR-004).
    Accepted,
    /// The relay rejected the message with `code` and changed nothing.
    Rejected {
        /// The ADR-004 wire code.
        code: u16,
        /// A message for the client. It never carries a token.
        msg: String,
    },
}

impl PushPublishGate {
    fn rejected(code: u16, msg: impl Into<String>) -> Self {
        Self::Rejected {
            code,
            msg: msg.into(),
        }
    }

    /// The relay's answer to the PUBLISH, or `None` for
    /// [`PushPublishGate::NotPush`], which the caller handles as an ordinary
    /// blob. An accepted message gets `OK` with no `blob_id`, because the relay
    /// stored no blob (ADR-004).
    #[must_use]
    pub fn reply(self, ref_id: Option<&str>) -> Option<RelayMessage> {
        let ref_id = ref_id.map(str::to_owned);
        match self {
            Self::NotPush => None,
            Self::Accepted => Some(RelayMessage::Ok {
                ref_id,
                blob_id: None,
            }),
            Self::Rejected { code, msg } => Some(RelayMessage::Err { ref_id, code, msg }),
        }
    }
}

/// The most previous reserved push routing IDs a [`LiveRelayUrl`] remembers.
///
/// A relay whose URL changes keeps refusing a PUBLISH to the routing ID of each of
/// its last 64 previous URLs. A routing ID older than that is forgotten, and a
/// PUBLISH to it is stored as an ordinary blob. The bound keeps an unbounded run
/// of URL changes from growing the list.
pub const MAX_RETIRED_PUSH_ROUTING_IDS: usize = 64;

#[derive(Debug)]
struct UrlState {
    current: RelayUrl,
    /// Routing IDs of previous URLs, oldest first, never the current one.
    retired: VecDeque<[u8; 32]>,
}

/// The relay's current URL, shared by every transport listener and updated in
/// place when the URL changes (§10.7.1 step 2).
///
/// Every listener of one relay (WebSocket, QUIC, UDP/DTLS, WebTransport) holds
/// a clone of the same handle and reads it on each PUBLISH, so a
/// [`set`](Self::set) moves every listener's reserved push routing ID, and the
/// URL it rebuilds the signature preimage with (§10.7.1 step 3), at once. The
/// handle is built from a [`RelayUrl`], so a relay always has a URL and no
/// listener runs push interception without one.
///
/// **A PUBLISH during a switch.** The gate reads the URL once per PUBLISH, so
/// one PUBLISH sees either the old URL or the new one, never a mix. After a
/// switch, a PUBLISH to the routing ID of one of the last
/// [`MAX_RETIRED_PUSH_ROUTING_IDS`] previous URLs is still intercepted and is
/// not stored as a blob: a relay without push answers `4063`, and a relay
/// with push answers `4060`, because the relay no longer holds the URL the
/// message was signed for, and the client re-registers against the new one.
/// Stored registrations are keyed by (identity, platform, token) and list
/// context routing IDs, so a URL change leaves every one in place.
#[derive(Debug, Clone)]
pub struct LiveRelayUrl(Arc<watch::Sender<UrlState>>);

/// Where a PUBLISH routing ID falls against the relay's URL history.
enum Reservation {
    /// The current URL's reserved routing ID, with that URL, from which the
    /// relay rebuilds the message's preimage (§10.7.1 step 3).
    #[cfg(feature = "push-store")]
    Current(RelayUrl),
    /// The current URL's reserved routing ID. A build without push rebuilds no
    /// preimage, so it carries no URL.
    #[cfg(not(feature = "push-store"))]
    Current,
    /// A previous URL's reserved routing ID.
    Retired,
    /// Any other routing ID.
    Other,
}

impl LiveRelayUrl {
    /// A handle whose current URL is `url`, with no previous URLs.
    #[must_use]
    pub fn new(url: RelayUrl) -> Self {
        Self(Arc::new(watch::Sender::new(UrlState {
            current: url,
            retired: VecDeque::new(),
        })))
    }

    /// The current URL.
    #[must_use]
    pub fn current(&self) -> RelayUrl {
        self.0.borrow().current.clone()
    }

    /// Makes `url` the current URL of every listener holding this handle.
    ///
    /// The previous URL's routing ID joins the retired list and `url`'s own
    /// routing ID leaves it, so a URL that comes back is current again.
    /// Setting the current URL changes nothing.
    pub fn set(&self, url: RelayUrl) {
        self.0.send_if_modified(|state| {
            if state.current == url {
                return false;
            }
            let new_id = url.push_routing_id;
            let old = std::mem::replace(&mut state.current, url);
            state.retired.retain(|id| *id != new_id);
            state.retired.push_back(old.push_routing_id);
            while state.retired.len() > MAX_RETIRED_PUSH_ROUTING_IDS {
                state.retired.pop_front();
            }
            true
        });
    }

    fn reservation(&self, routing_id: &[u8; 32]) -> Reservation {
        let state = self.0.borrow();
        if *routing_id == state.current.push_routing_id {
            #[cfg(feature = "push-store")]
            let current = Reservation::Current(state.current.clone());
            #[cfg(not(feature = "push-store"))]
            let current = Reservation::Current;
            current
        } else if state.retired.contains(routing_id) {
            Reservation::Retired
        } else {
            Reservation::Other
        }
    }
}

/// The answer of a relay that offers no push service (§10.7.1, ADR-004).
fn not_supported() -> PushPublishGate {
    PushPublishGate::rejected(
        code::PUSH_NOT_SUPPORTED,
        "this relay offers no push service",
    )
}

/// The answer of a push-enabled relay to a previous URL's routing ID.
#[cfg(feature = "push-store")]
fn retired_url() -> PushPublishGate {
    PushPublishGate::rejected(
        code::PUSH_REGISTRATION_REJECTED,
        "push message is addressed to a previous URL of this relay",
    )
}

/// Decides a PUBLISH of `blob` to `routing_id` (§10.7.1, ADR-004).
///
/// `relay_url` is the relay's live URL, read once for this PUBLISH. `now` is
/// the relay's clock in Unix seconds. A previous URL's routing ID is refused
/// as [`LiveRelayUrl`] describes.
///
/// The caller runs it after the rate-limit, size and TTL checks and before any
/// blob store, and stores nothing and delivers nothing unless it returns
/// [`PushPublishGate::NotPush`].
#[cfg(feature = "push-store")]
pub async fn gate_publish(
    relay_url: &LiveRelayUrl,
    push: &PushRole,
    routing_id: &[u8; 32],
    blob: &[u8],
    now: u64,
) -> PushPublishGate {
    match (push, relay_url.reservation(routing_id)) {
        (_, Reservation::Other) => PushPublishGate::NotPush,
        (PushRole::Disabled, _) => not_supported(),
        (PushRole::Enabled(_), Reservation::Retired) => retired_url(),
        (PushRole::Enabled(service), Reservation::Current(url)) => {
            match handle(service.config(), &url, blob, now).await {
                Ok(()) => PushPublishGate::Accepted,
                Err(rejection) => rejection,
            }
        }
    }
}

/// Decides a PUBLISH to `routing_id` (§10.7.1, ADR-004).
///
/// A build without the `push-store` feature offers no push service: its only
/// [`PushRole`] is `Disabled`, so the decision needs no I/O and the returned
/// future is already complete. The reserved push routing ID gets `4063` and
/// every other routing ID is [`PushPublishGate::NotPush`]. The signature
/// matches the `push-store` build so every transport calls it the same way.
///
/// The caller runs it after the rate-limit, size and TTL checks and before any
/// blob store, and stores nothing and delivers nothing unless it returns
/// [`PushPublishGate::NotPush`].
#[cfg(not(feature = "push-store"))]
pub fn gate_publish(
    relay_url: &LiveRelayUrl,
    push: &PushRole,
    routing_id: &[u8; 32],
    _blob: &[u8],
    _now: u64,
) -> std::future::Ready<PushPublishGate> {
    std::future::ready(match (push, relay_url.reservation(routing_id)) {
        (_, Reservation::Other) => PushPublishGate::NotPush,
        (PushRole::Disabled, Reservation::Current | Reservation::Retired) => not_supported(),
    })
}

/// A decoded push message, owned.
#[cfg(feature = "push-store")]
enum Decoded {
    Registration(PushRegistration),
    Deregistration(PushDeregistration),
}

#[cfg(feature = "push-store")]
impl Decoded {
    /// Decodes `blob` as a `PushRegistration`, or else as a
    /// `PushDeregistration` (§22.11.4).
    ///
    /// The two messages share every field but `routing_ids`, which only a
    /// registration carries, so a blob that decodes as a registration is one.
    /// A registration that decodes but breaks a field rule (an empty
    /// `routing_ids` list) is rejected, never re-read as a deregistration.
    fn from_msgpack(blob: &[u8]) -> Result<Self, PushMessageError> {
        match PushRegistration::from_msgpack(blob) {
            Ok(r) => Ok(Self::Registration(r)),
            Err(PushMessageError::Decode(_)) => {
                PushDeregistration::from_msgpack(blob).map(Self::Deregistration)
            }
            Err(e) => Err(e),
        }
    }

    const fn message(&self) -> PushMessage<'_> {
        match self {
            Self::Registration(m) => PushMessage::Registration(m),
            Self::Deregistration(m) => PushMessage::Deregistration(m),
        }
    }

    const fn platform(&self) -> PushPlatform {
        match self {
            Self::Registration(m) => m.platform,
            Self::Deregistration(m) => m.platform,
        }
    }

    const fn timestamp(&self) -> u64 {
        match self {
            Self::Registration(m) => m.timestamp,
            Self::Deregistration(m) => m.timestamp,
        }
    }

    fn key(&self) -> PushRegistrationKey {
        let (registrant, platform, token) = match self {
            Self::Registration(m) => (&m.registrant, m.platform, &m.token),
            Self::Deregistration(m) => (&m.registrant, m.platform, &m.token),
        };
        PushRegistrationKey {
            registrant: registrant.0.clone(),
            platform,
            token: token.clone(),
        }
    }
}

/// The enabled arm of [`gate_publish`]: decode, platform, freshness, verify,
/// then the one store write.
#[cfg(feature = "push-store")]
async fn handle(
    service: &PushServiceConfig,
    relay_url: &RelayUrl,
    blob: &[u8],
    now: u64,
) -> Result<(), PushPublishGate> {
    let decoded = Decoded::from_msgpack(blob).map_err(|_| {
        PushPublishGate::rejected(
            code::PUSH_REGISTRATION_REJECTED,
            "push message does not decode or breaks a field rule",
        )
    })?;

    let platform = decoded.platform();
    if service.sender_for(platform).is_none() {
        return Err(PushPublishGate::rejected(
            code::PUSH_PLATFORM_UNAVAILABLE,
            format!("this relay has no {platform} sender"),
        ));
    }

    // Freshness runs before verification (§10.7.1 "Freshness").
    let timestamp = decoded.timestamp();
    if now.abs_diff(timestamp) > PUSH_TIMESTAMP_SKEW_SECS {
        return Err(PushPublishGate::rejected(
            code::PUSH_REGISTRATION_STALE,
            "push message timestamp is outside the skew window",
        ));
    }
    let key = decoded.key();
    let last_accepted = service
        .store
        .accepted_timestamp(&key)
        .await
        .map_err(|e| PushPublishGate::rejected(e.wire_code(), e.to_string()))?;
    if last_accepted.is_some_and(|last| timestamp <= last) {
        return Err(PushPublishGate::rejected(
            code::PUSH_REGISTRATION_STALE,
            "push message timestamp is not newer than the last accepted one",
        ));
    }

    // Verification with the relay's own canonical URL, the one its reserved
    // routing ID came from, never a client-supplied URL (§10.7.1 step 3).
    let verified = tokio::time::timeout(
        PUSH_VERIFY_TIMEOUT,
        service
            .verifier
            .verify(decoded.message(), relay_url.push_relay()),
    )
    .await
    .map_err(|_| {
        PushPublishGate::rejected(
            code::PUSH_KEY_STATE_UNAVAILABLE,
            "push signature verification timed out",
        )
    })?
    .map_err(|e| PushPublishGate::rejected(e.wire_code(), e.to_string()))?;
    if verified.0 != key.registrant {
        return Err(PushPublishGate::rejected(
            code::PUSH_REGISTRATION_REJECTED,
            "push verifier returned another identifier",
        ));
    }

    let written = match decoded {
        Decoded::Registration(m) => service
            .store
            .upsert(PushRegistrationRecord {
                registrant: key.registrant,
                platform: m.platform,
                token: m.token,
                routing_ids: m.routing_ids,
                timestamp: m.timestamp,
            })
            .await
            .map(|_| ()),
        Decoded::Deregistration(m) => service
            .store
            .deregister(&key, m.timestamp)
            .await
            .map(|_| ()),
    };
    written.map_err(|e| PushPublishGate::rejected(e.wire_code(), e.to_string()))
}

/// A running push service with a SQLite store under `dir`, the production
/// `KelPushVerifier`, and no senders, for transport tests that need a valid
/// `PushRole::Enabled`. Call it inside a tokio runtime.
#[cfg(all(test, feature = "push-store"))]
#[allow(clippy::unwrap_used)]
pub(crate) fn kel_service_for_tests(dir: &std::path::Path) -> PushService {
    PushService::start(PushServiceConfig {
        store: PushRegistrationStore::open_sqlite(&dir.join("push.db")).unwrap(),
        verifier: Arc::new(scp_identity::push_verify::KelPushVerifier),
        senders: Arc::from(Vec::new()),
    })
    .unwrap()
}

/// A live handle on `ws://127.0.0.1:9000/scp/v1`, the URL of the default bind
/// address, for transport tests that do not exercise push.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) fn test_relay_url() -> LiveRelayUrl {
    LiveRelayUrl::new(RelayUrl::new("ws://127.0.0.1:9000/scp/v1").unwrap())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use scp_protocol::discovery::push::push_registration_routing_id;

    use super::*;

    #[test]
    fn relay_url_from_relay_service_matches_relay_url_new() {
        let service = scp_did::RelayService::direct(
            scp_did::RelayEndpoint::new("WSS://Relay.Example:443/scp/v1").unwrap(),
        );
        assert_eq!(
            RelayUrl::from(&service),
            RelayUrl::new("wss://relay.example/scp/v1").unwrap()
        );
    }

    const BRIDGE_URL: &str = "wss://bridge.example.com/scp/v1";

    fn bridge_entry(target: [u8; 32]) -> scp_did::RelayService {
        scp_did::RelayService::bridge(
            scp_did::BridgeEndpoint::new(BRIDGE_URL).unwrap(),
            BridgeTarget::new(target).unwrap(),
        )
    }

    /// A bridge entry keeps its canonical URL and its target, and reserves
    /// the tier 3 ID; a direct entry and `RelayUrl::new` hold no target and
    /// reserve the `"scp-push-registration"` ID (§9.18.2).
    #[test]
    fn relay_url_from_a_bridge_entry_keeps_the_target_and_the_tier3_id() {
        let entry = bridge_entry([0xA1; 32]);
        let url = RelayUrl::from(&entry);
        assert_eq!(url.canonical(), BRIDGE_URL);
        assert_eq!(
            url.bridge_target(),
            Some(BridgeTarget::new([0xA1; 32]).unwrap())
        );
        assert_eq!(
            url.push_routing_id(),
            scp_protocol::discovery::push::tier3_push_routing_id(
                entry.endpoint(),
                BridgeTarget::new([0xA1; 32]).unwrap()
            )
        );
        assert_ne!(
            url.push_routing_id(),
            push_registration_routing_id(BRIDGE_URL).unwrap()
        );

        let direct = RelayUrl::from(&scp_did::RelayService::direct(
            scp_did::RelayEndpoint::new(BRIDGE_URL).unwrap(),
        ));
        assert_eq!(direct.bridge_target(), None);
        assert_eq!(direct, RelayUrl::new(BRIDGE_URL).unwrap());
        assert_eq!(
            direct.push_routing_id(),
            push_registration_routing_id(BRIDGE_URL).unwrap()
        );
        assert_ne!(url, direct);

        // The handle yields the one `PushRelay` the ID was derived from.
        assert_eq!(url.push_relay(), &PushRelay::from(&entry));
        assert_eq!(url.push_relay().push_routing_id(), url.push_routing_id());
        assert_eq!(direct.push_relay().bridge_target(), None);
    }

    /// Two entries behind one bridge URL are different relay URLs: setting
    /// one after the other moves the reservation and retires the first ID.
    #[test]
    fn set_keeps_the_target_when_only_the_target_changes() {
        let a = RelayUrl::from(&bridge_entry([0xA1; 32]));
        let b = RelayUrl::from(&bridge_entry([0xB2; 32]));
        let live = LiveRelayUrl::new(a.clone());
        live.set(b.clone());
        assert_eq!(live.current(), b);
        assert_eq!(live.current().bridge_target(), b.bridge_target());
        assert!(matches!(
            live.reservation(&a.push_routing_id()),
            Reservation::Retired
        ));
    }

    #[test]
    fn relay_url_canonicalizes_and_derives_the_reserved_routing_id() {
        let a = RelayUrl::new("WSS://Relay.Example:443/").unwrap();
        let b = RelayUrl::new("wss://relay.example").unwrap();
        assert_eq!(a, b);
        assert_eq!(a.canonical(), "wss://relay.example");
        assert_eq!(
            a.push_routing_id(),
            push_registration_routing_id("wss://relay.example").unwrap()
        );
        assert!(matches!(
            RelayUrl::new("https://relay.example"),
            Err(PushMessageError::InvalidRelayUrl(_))
        ));
    }

    #[tokio::test]
    async fn other_routing_ids_pass_through() {
        let url = LiveRelayUrl::new(RelayUrl::new("wss://relay.example").unwrap());
        assert_eq!(
            gate_publish(&url, &PushRole::Disabled, &[0xAA; 32], b"x", 0).await,
            PushPublishGate::NotPush
        );
    }

    #[tokio::test]
    async fn disabled_rejects_the_reserved_routing_id_with_4063() {
        let url = RelayUrl::new("wss://relay.example").unwrap();
        let live = LiveRelayUrl::new(url.clone());
        let gate = gate_publish(
            &live,
            &PushRole::Disabled,
            &url.push_routing_id(),
            b"anything",
            0,
        )
        .await;
        assert!(matches!(gate, PushPublishGate::Rejected { code: 4063, .. }));
        assert!(matches!(PushRole::default(), PushRole::Disabled));
    }

    #[tokio::test]
    async fn set_moves_the_reserved_routing_id_and_keeps_refusing_the_old_one() {
        let old = RelayUrl::new("ws://198.51.100.7:32891/scp/v1").unwrap();
        let new = RelayUrl::new("ws://203.0.113.42:8443/scp/v1").unwrap();
        let live = LiveRelayUrl::new(old.clone());
        let reader = live.clone();
        live.set(new.clone());
        assert_eq!(reader.current(), new);
        for id in [new.push_routing_id(), old.push_routing_id()] {
            let gate = gate_publish(&reader, &PushRole::Disabled, &id, b"x", 0).await;
            assert!(matches!(gate, PushPublishGate::Rejected { code: 4063, .. }));
        }
        // The old URL coming back makes it current and retires the new one.
        live.set(old.clone());
        assert_eq!(reader.current(), old);
        assert!(!matches!(
            reader.reservation(&old.push_routing_id()),
            Reservation::Retired | Reservation::Other
        ));
        assert!(matches!(
            reader.reservation(&new.push_routing_id()),
            Reservation::Retired
        ));
    }

    #[test]
    fn retired_routing_ids_are_bounded() {
        let url =
            |n: usize| RelayUrl::new(&format!("ws://198.51.100.7:{}/scp/v1", 1000 + n)).unwrap();
        let live = LiveRelayUrl::new(url(0));
        for n in 1..=MAX_RETIRED_PUSH_ROUTING_IDS + 1 {
            live.set(url(n));
        }
        assert_eq!(live.0.borrow().retired.len(), MAX_RETIRED_PUSH_ROUTING_IDS);
        assert!(matches!(
            live.reservation(&url(0).push_routing_id()),
            Reservation::Other
        ));
        assert!(matches!(
            live.reservation(&url(1).push_routing_id()),
            Reservation::Retired
        ));
    }

    #[cfg(feature = "push-store")]
    #[tokio::test]
    async fn enabled_rejects_a_retired_routing_id_with_4060() {
        let dir = tempfile::tempdir().unwrap();
        let service = kel_service_for_tests(dir.path());
        let old = RelayUrl::new("wss://old.relay.example").unwrap();
        let live = LiveRelayUrl::new(old.clone());
        live.set(RelayUrl::new("wss://new.relay.example").unwrap());
        let gate = gate_publish(
            &live,
            &PushRole::Enabled(service),
            &old.push_routing_id(),
            b"anything",
            0,
        )
        .await;
        assert!(matches!(gate, PushPublishGate::Rejected { code: 4060, .. }));
    }

    /// A push-enabled service with an APNs sender, a SQLite store under
    /// `dir`, and a `TestPushVerifier` holding `key`'s public key for
    /// `registrant`.
    #[cfg(feature = "push-store")]
    fn test_service(
        dir: &std::path::Path,
        registrant: &str,
        key: &scp_crypto::p256::P256SecretKey,
    ) -> PushServiceConfig {
        use crate::relay::push::{ApnsConfig, ApnsEnvironment, ApnsSender};
        let sender = ApnsSender::new(ApnsConfig {
            signing_key: scp_crypto::p256::P256SecretKey::from_scalar_bytes(&[3; 32]).unwrap(),
            key_id: "ABC123DEFG".to_owned(),
            team_id: "TEAM456XYZ".to_owned(),
            topic: "works.limn.app".to_owned(),
            environment: ApnsEnvironment::Sandbox,
        })
        .unwrap();
        PushServiceConfig {
            store: PushRegistrationStore::open_sqlite(&dir.join("push.db")).unwrap(),
            verifier: Arc::new(scp_identity::push_verify::TestPushVerifier::new([(
                scp_did::DID::from(registrant),
                key.public_key(),
            )])),
            senders: Arc::from(vec![PushSender::Apns(sender)]),
        }
    }

    #[cfg(feature = "push-store")]
    const GATE_REGISTRANT: &str = "did:dht:push-registrant";
    #[cfg(feature = "push-store")]
    const GATE_NOW: u64 = 1_700_000_000;

    #[cfg(feature = "push-store")]
    fn gate_key() -> scp_crypto::p256::P256SecretKey {
        scp_crypto::p256::P256SecretKey::from_scalar_bytes(&[7; 32]).unwrap()
    }

    /// A registration (`deregister` false) or deregistration for the APNs
    /// token `tok`, signed by `gate_key()` for `relay`.
    #[cfg(feature = "push-store")]
    fn signed_for(deregister: bool, relay: &PushRelay) -> Vec<u8> {
        use scp_protocol::discovery::push::{
            push_deregistration_signing_bytes, push_registration_signing_bytes,
        };
        use sha2::{Digest, Sha256};

        let sign = |preimage: Vec<u8>| {
            let digest: [u8; 32] = Sha256::digest(preimage).into();
            scp_crypto::p256::sign_prehash_rfc6979(&gate_key(), &digest).unwrap()
        };
        if deregister {
            let mut msg = PushDeregistration {
                registrant: scp_did::DID::from(GATE_REGISTRANT),
                platform: PushPlatform::Apns,
                token: b"tok".to_vec(),
                timestamp: GATE_NOW,
                signature: [0; 64],
            };
            msg.signature = sign(push_deregistration_signing_bytes(&msg, relay).unwrap());
            rmp_serde::to_vec_named(&msg).unwrap()
        } else {
            let mut msg = PushRegistration {
                registrant: scp_did::DID::from(GATE_REGISTRANT),
                platform: PushPlatform::Apns,
                token: b"tok".to_vec(),
                routing_ids: vec![[0x11; 32]],
                timestamp: GATE_NOW,
                signature: [0; 64],
            };
            msg.signature = sign(push_registration_signing_bytes(&msg, relay).unwrap());
            rmp_serde::to_vec_named(&msg).unwrap()
        }
    }

    /// Presents `blob` at the reserved routing ID of a fresh push-enabled
    /// relay whose handle holds `held`, and returns the gate's answer and the
    /// timestamp the store then holds for the token (`None` when the store
    /// is unchanged).
    #[cfg(feature = "push-store")]
    async fn present(held: &RelayUrl, blob: &[u8]) -> (PushPublishGate, Option<u64>) {
        let dir = tempfile::tempdir().unwrap();
        let service = test_service(dir.path(), GATE_REGISTRANT, &gate_key());
        let store = service.store.clone();
        let live = LiveRelayUrl::new(held.clone());
        let gate = gate_publish(
            &live,
            &PushRole::Enabled(service),
            &held.push_routing_id(),
            blob,
            GATE_NOW,
        )
        .await;
        let key = PushRegistrationKey {
            registrant: GATE_REGISTRANT.to_owned(),
            platform: PushPlatform::Apns,
            token: b"tok".to_vec(),
        };
        (gate, store.accepted_timestamp(&key).await.unwrap())
    }

    /// §10.7.1 step 3: the relay rebuilds the preimage with the target of the
    /// entry it holds, never one the client chose. A message signed for
    /// (bridge URL, target A) is accepted at a relay holding that entry, and
    /// rejected with `4060`, storing nothing, at a relay holding (bridge URL,
    /// target B) and at one holding the bridge URL with no target. A message
    /// signed with the absent sentinel is rejected with `4060` at the relay
    /// holding (bridge URL, target A). Each holds for a registration and a
    /// deregistration.
    #[cfg(feature = "push-store")]
    #[tokio::test]
    async fn enabled_rejects_a_message_signed_for_another_bridge_target_with_4060() {
        let held_a = RelayUrl::from(&bridge_entry([0xA1; 32]));
        let held_b = RelayUrl::from(&bridge_entry([0xB2; 32]));
        let held_none = RelayUrl::new(BRIDGE_URL).unwrap();
        for deregister in [false, true] {
            let for_a = signed_for(deregister, held_a.push_relay());
            let sentinel = signed_for(deregister, held_none.push_relay());

            let (gate, stored) = present(&held_a, &for_a).await;
            assert_eq!(gate, PushPublishGate::Accepted, "deregister {deregister}");
            assert_eq!(stored, Some(GATE_NOW), "deregister {deregister}");

            for (label, held, blob) in [
                ("A-signed at B", &held_b, &for_a),
                ("A-signed at no target", &held_none, &for_a),
                ("sentinel-signed at A", &held_a, &sentinel),
            ] {
                let (gate, stored) = present(held, blob).await;
                assert!(
                    matches!(gate, PushPublishGate::Rejected { code: 4060, .. }),
                    "{label}, deregister {deregister}: {gate:?}"
                );
                assert_eq!(stored, None, "{label}, deregister {deregister}");
            }
        }
    }

    #[test]
    fn reply_answers_every_push_decision_and_none_for_other_blobs() {
        assert_eq!(PushPublishGate::NotPush.reply(Some("r")), None);
        assert_eq!(
            PushPublishGate::Accepted.reply(Some("r")),
            Some(RelayMessage::Ok {
                ref_id: Some("r".to_owned()),
                blob_id: None,
            })
        );
        assert_eq!(
            PushPublishGate::rejected(4062, "stale").reply(None),
            Some(RelayMessage::Err {
                ref_id: None,
                code: 4062,
                msg: "stale".to_owned(),
            })
        );
    }
}
