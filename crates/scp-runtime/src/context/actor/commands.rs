//! Command types accepted by `ContextActor`. See plan §"ContextActor" and
//! ADR-049 §1.
//!
//! # Clippy allows, scoped per-file
//!
//! - `doc_markdown` / `too_long_first_doc_paragraph`: the module docs
//!   reference plan-section titles like `§"ContextActor"` and
//!   `§"Cross-context saga protocol"` that cannot be trivially rewritten
//!   to satisfy the lint without losing traceability to the plan.
//!   Inline backticks break the readable prose; wrapping every section
//!   reference is churn for no reader benefit.
#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//!
//! # Shape
//!
//! The outer [`ContextCommand`] enum is a discriminated union over 12
//! domain-grouped sub-enums, one per handler file in
//! [`crate::context::actor::handlers`]. Each sub-enum carries the
//! command-specific payload plus a `tokio::sync::oneshot::Sender` for the
//! reply — the actor processes a command to completion and sends the
//! typed result; the caller's oneshot receiver is the cancellation
//! vector (drop-the-receiver = discard the outcome without rolling back
//! committed state — see plan §"Cancel-safety check").
//!
//! # Variant surface
//!
//! Each sub-enum carries its real, domain-specific command variants;
//! there are no placeholder variants. The actor mailbox has no
//! `NotImplemented` scaffolding on the live dispatch path — the
//! state-owning [`ContextActor`](crate::context::actor::ContextActor)
//! routes every command through `dispatch_state` to its real handler.
//!
//! # Naming
//!
//! Sub-enum names follow the handler file name (`MessagingCommand` ↔
//! `handlers/messaging.rs`). This keeps the routing trivially
//! grep-findable: `ContextCommand::Messaging(MessagingCommand::Send { .. })`
//! ↔ `handlers::messaging::dispatch`.

use tokio::sync::oneshot;

use scp_protocol::context::ContextError;

/// Reply-channel type alias for
/// [`QueriesCommand::GetBroadcastKeyForLocalAuthor`]. The reply carries
/// the locally-controlled author's broadcast key (32 bytes, wrapped in
/// [`Zeroizing`](zeroize::Zeroizing) so the secret is zeroed on drop)
/// plus the author's current broadcast epoch. Factored out to satisfy
/// `clippy::type_complexity`.
type BroadcastKeyReply = oneshot::Sender<Result<(zeroize::Zeroizing<[u8; 32]>, u64), ContextError>>;

/// Re-export of the receive-path outcome classifier so FFI bridges can name
/// the [`DeliverIncomingReply`] payload type via
/// `scp_core::context::actor::commands::DeliverOutcome`.
pub use crate::context::messaging_helpers::DeliverOutcome;

/// Reply-channel type alias for
/// [`MessagingCommand::DeliverIncoming`]. The reply carries a
/// [`DeliverOutcome`] classifying the message: [`DeliverOutcome::Application`]
/// `(plaintext, sender_did)` for user content, [`DeliverOutcome::Heartbeat`]
/// for a §9.9.2 suppression-detection heartbeat (the bridge records it against
/// the transport monitor), or [`DeliverOutcome::Handled`] for MLS control /
/// management messages processed internally. Factored out to satisfy
/// `clippy::type_complexity`.
pub type DeliverIncomingReply = oneshot::Sender<Result<DeliverOutcome, ContextError>>;

/// Reply-channel type alias for [`MessagingCommand::DrainEvents`]. The
/// reply carries the drained `ContextEvent` vector — empty iff the
/// context is unknown (matches the legacy
/// [`Supervisor::drain_events`](crate::context::supervisor::Supervisor::drain_events)
/// "soft-default on unknown context" contract). Factored out to satisfy
/// `clippy::type_complexity`.
pub type DrainEventsReply =
    oneshot::Sender<Result<Vec<scp_protocol::context::membership::ContextEvent>, ContextError>>;

// ---------------------------------------------------------------------------
// Outer enum
// ---------------------------------------------------------------------------

/// Every command the `ContextActor` accepts. Routed by the actor's
/// dispatch loop to the matching handler module.
///
/// Variants correspond one-to-one with handler files under
/// [`crate::context::actor::handlers`]. The dispatch loop in
/// [`crate::context::actor::ContextActor::run`] matches on this enum.
pub enum ContextCommand {
    /// Messaging — send, deliver, decrypt (spec §9.8).
    Messaging(MessagingCommand),
    /// Lifecycle — create, join, leave, close (spec §5.3).
    Lifecycle(LifecycleCommand),
    /// Governance — the 28 actions enumerated in ADR-031.
    Governance(GovernanceCommand),
    /// Broadcast — per-author key rotation, subscriber admission,
    /// broadcast publish/subscribe.
    Broadcast(BroadcastCommand),
    /// Economy — velocity trackers, escalations, payments (spec §19).
    Economy(EconomyCommand),
    /// Trust recovery — epoch floor reconciliation, recovery proofs
    /// (spec §23.17).
    TrustRecovery(TrustRecoveryCommand),
    /// Standing — standing-pair get-or-create (single-context async
    /// creation, NOT a saga; spec §5.15.8).
    Standing(StandingCommand),
    /// TTL close — timer-driven close path (spec §5.8).
    TtlClose(TtlCloseCommand),
    /// Outlets — hard-rate-limit consume / refund plus outlet-economy
    /// reserve / settle helpers that FFI bridges call from their
    /// outlet-dispatch paths (spec §19, rate limits §6.2.0.2). NOT a saga
    /// initiator — the cross-context outlet-invocation saga runs
    /// supervisor-side, not over this mailbox.
    Outlets(OutletsCommand),
    /// Read-only queries. Handlers MUST NOT mutate state; the actor
    /// takes `&self.state` when dispatching this variant.
    Queries(QueriesCommand),
    /// Saga phase messages — supervisor-driven Prepare / Commit / Abort
    /// arriving at this actor as a saga participant.
    SagaPhase(SagaPhaseMessage),
    /// Supervisor-originated lifecycle control (Pause, Resume, Shutdown,
    /// PersistSync). See plan §"BridgeInstance actor integration" — the
    /// bridge's suspend/resume default trait methods send these.
    LifecycleControl(LifecycleControlCommand),
}

// ---------------------------------------------------------------------------
// Command sub-enums
// ---------------------------------------------------------------------------

/// Payload for [`MessagingCommand::SendMessage`]. Boxed inside the
/// variant so the enum's variant sizes stay uniform despite
/// [`ContextParams`](scp_protocol::context::params::ContextParams)
/// being ~1KB.
///
/// Every field is owned (`Vec<u8>`, `String`, `DID`, `ContextParams`)
/// rather than borrowed so the command can cross the actor mailbox
/// without lifetime juggling. The handler reconstructs an ephemeral
/// [`ContextHandle`](crate::context::ContextHandle) on the receive
/// side to match the legacy method's signature.
pub struct SendMessagePayload {
    /// Context identifier (plain string, matches the legacy API).
    pub context_id: String,
    /// Creation-time parameters used to rebuild an ephemeral
    /// [`ContextHandle`](crate::context::ContextHandle) on the handler
    /// side. Cloned from the caller's handle at dispatch time.
    pub params: scp_protocol::context::params::ContextParams,
    /// Sender DID.
    pub sender_did: scp_did::DID,
    /// Plaintext payload to encrypt and send.
    pub payload: Vec<u8>,
    /// Sender's Ed25519 signing key. `None` is rejected by the
    /// encrypted path — the inner envelope cannot be signed without
    /// it. Wrapped in [`SigningKeyBytes`] so the private key bytes
    /// zeroize on drop.
    pub signing_key: Option<SigningKeyBytes>,
    /// Which verification method this message is signed under
    /// (`#active` or `#agent`, ADR-039). Stamped into the inner
    /// envelope's `signing_key_id` so the recipient resolves the
    /// matching public key from the sender's DID document. Must agree
    /// with the key material in `signing_key`.
    pub signing_key_id: scp_did::SigningKeyId,
    /// Optional cross-context provenance metadata — attaches a
    /// signed `DataProvenance` envelope to the inner message.
    pub source_provenance: Option<scp_protocol::provenance::attach::SourceContextInfo>,
    /// Optional `Spend` UCAN for the economy layer's AND-composition
    /// check (spec §19.5). Parsed form; the FFI bridges parse the
    /// JWT once before dispatch.
    pub spending_ucan: Option<scp_protocol::crypto::ucan::UcanToken>,
}

/// See [`ContextCommand::Messaging`]. Real variants land in commit 8 of
/// the ADR-049 commit ladder (see `handlers/messaging.rs`). Variants
/// cover the hot-path send + deliver operations; sender-key rotation,
/// distribute/remove, sender-key request handling, and sender-key
/// management messages are served directly by the crypto provider —
/// `crypto/mls/provider.rs` methods (invoked internally by the runtime's
/// lifecycle/governance/blocking helpers) plus
/// `crypto/sender_keys/key_protocol.rs` free functions (additionally
/// re-exported to the FFI boundary via `scp-core`), not command variants
/// traversing the command-dispatch shim — until they migrate to
/// `MessagingCommand` variants in commits 10-11 per the plan row-6 scope.
pub enum MessagingCommand {
    /// Encrypts and transmits a message within an active context.
    ///
    /// Mirrors the legacy
    /// [`Supervisor::send_message`](crate::context::supervisor::Supervisor::send_message)
    /// signature exactly: the handler delegates to that method for
    /// byte-identical envelope construction, inner-signature signing,
    /// sender-key sealing, MLS encryption, and transport fan-out.
    ///
    /// # Owned payload fields
    ///
    /// Every field is owned (`Vec<u8>`, `String`, `DID`,
    /// `ContextParams`) rather than borrowed so the command can cross
    /// the actor mailbox without lifetime juggling. The handler
    /// reconstructs an ephemeral [`ContextHandle`](crate::context::ContextHandle) on the receive side
    /// to match the legacy method's signature.
    ///
    /// # Reply
    ///
    /// The reply channel carries the legacy method's `Result<(),
    /// ContextError>` outcome. Drop the receiver to cancel — the actor
    /// processes the send to completion (message flies on the wire)
    /// but the outcome is discarded.
    SendMessage {
        /// Boxed send-message payload — factored into a separate heap
        /// allocation so [`MessagingCommand`] / [`ContextCommand`]
        /// variant sizes stay uniform (ContextParams is ~1KB).
        /// Satisfies `clippy::large_enum_variant`.
        payload: Box<SendMessagePayload>,
        /// Oneshot reply channel. Kept outside the boxed payload so the
        /// actor's dispatch loop can consume `reply` by pattern-match
        /// without an additional heap dereference for the hot reply
        /// path.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Decrypts an incoming envelope from the relay and classifies it as
    /// application content, a §9.9.2 heartbeat, or an internally-handled
    /// management message.
    ///
    /// Mirrors the legacy
    /// [`messaging_helpers::deliver_incoming`](crate::context::messaging_helpers::deliver_incoming)
    /// signature. Used by the relay subscription loop; the return type
    /// matches the bridge's per-event dispatch pattern.
    ///
    /// # Reply
    ///
    /// `Ok(DeliverOutcome::Application((plaintext, sender_did)))` — application
    /// message; caller should forward to the language binding's receive channel.
    /// `Ok(DeliverOutcome::Heartbeat)` — §9.9.2 suppression-detection
    /// heartbeat; caller records it against the transport-layer monitor
    /// (`record_heartbeat_received`) and surfaces nothing to the application.
    /// `Ok(DeliverOutcome::Handled)` — MLS Commit / Proposal / checkpoint /
    /// announcement / buffered out-of-order message; processed internally, no
    /// plaintext to surface.
    /// `Err(..)` — decryption, signature verification, anti-replay, or
    /// access-key unwrap failure.
    DeliverIncoming {
        /// Context identifier.
        context_id: String,
        /// Encrypted envelope bytes (outer blob as received from the
        /// relay).
        envelope_bytes: Vec<u8>,
        /// Oneshot reply channel. See [`DeliverIncomingReply`].
        reply: DeliverIncomingReply,
    },

    /// Drain the per-context receive buffer.
    ///
    /// Mirrors the legacy
    /// [`Supervisor::drain_events`](crate::context::supervisor::Supervisor::drain_events)
    /// signature: empties the receive buffer and returns the drained
    /// events. The legacy method returns an empty `Vec` on unknown
    /// context; the dispatch shim preserves that contract by surfacing
    /// `Ok(Vec::new())` rather than `Err(ContextNotRegistered)`.
    ///
    /// # Mutation classification
    ///
    /// `drain_events` mutates the per-context state by emptying the
    /// receive buffer; it lives on the `MessagingCommand` enum because
    /// the receive buffer is the messaging path's downstream sink (the
    /// per-context buffer is fed by `deliver_incoming` and consumed by
    /// FFI receive polling). Routing it through the messaging dispatch
    /// keeps the receive-side state machine in one place.
    DrainEvents {
        /// Context identifier.
        context_id: String,
        /// Oneshot reply channel. See [`DrainEventsReply`].
        reply: DrainEventsReply,
    },

    /// Drain ONLY the [`ContextEvent::EquivocationDetected`](scp_protocol::context::membership::ContextEvent::EquivocationDetected)
    /// alerts from the per-context receive buffer, leaving every other
    /// buffered event in place and in order.
    ///
    /// The reconnection driver (FFI/SDK layer) needs the equivocation
    /// alerts surfaced during catch-up to populate its report, but the
    /// receive buffer is ALSO the SDK's only application-delivery queue.
    /// Using the total [`DrainEvents`](Self::DrainEvents) for that purpose
    /// would silently discard every message / `MemberJoined` / etc. that
    /// arrived during catch-up. This command partitions the buffer in the
    /// actor turn and returns only the alerts, preserving the application
    /// stream for the SDK's normal receive polling.
    ///
    /// # Mutation classification
    ///
    /// Mutating — like [`DrainEvents`](Self::DrainEvents) it edits the
    /// receive buffer (removes the alert subset). Routed through the
    /// messaging dispatch alongside the other receive-buffer mutations.
    DrainEquivocationAlerts {
        /// Context identifier.
        context_id: String,
        /// Oneshot reply channel. See [`DrainEventsReply`] — same type
        /// (a vector of `ContextEvent`), but the returned events are all
        /// `EquivocationDetected`.
        reply: DrainEventsReply,
    },

    /// Send the local member's pseudonym announcement (§9.10.4) to the
    /// other members of a context.
    ///
    /// Mirrors the legacy
    /// [`messaging_helpers::send_pseudonym_announcement`](crate::context::messaging_helpers::send_pseudonym_announcement)
    /// signature exactly: the handler delegates to that method which
    /// in turn wraps the announcement payload and routes it through
    /// `send_message`. Best-effort — the legacy method returns no
    /// error and silently swallows transport / serialization failures
    /// (only logs them); this dispatch surface preserves the same
    /// contract by replying `Ok(())` regardless of inner errors.
    SendPseudonymAnnouncement {
        /// Boxed owned payload — see [`SendPseudonymAnnouncementPayload`].
        payload: Box<SendPseudonymAnnouncementPayload>,
        /// Oneshot reply channel. Always replies `Ok(())` (matches the
        /// legacy method's no-error contract).
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Test-only: directly seed a peer's per-context pseudonym routing ID
    /// (§9.10.4) into the routing registry, bypassing the
    /// `PseudonymAnnouncement` MLS round-trip.
    ///
    /// Single-node integration tests host exactly one member's view of a
    /// context, so a peer added via governance never gets an opportunity to
    /// announce its pseudonym (there is no peer node to send the
    /// announcement). This command lets such tests populate the registry the
    /// same way a delivered announcement would, so multi-member encrypted
    /// `send_message` calls can exercise their real fan-out instead of failing
    /// closed with [`ContextError::PseudonymRegistryEmpty`].
    ///
    /// Gated behind the `testing` feature — never compiled into production
    /// builds, never reachable from any FFI bridge.
    #[cfg(feature = "testing")]
    SeedPeerPseudonym {
        /// Context identifier.
        context_id: String,
        /// The peer member whose routing ID is being recorded.
        member_did: scp_did::DID,
        /// The peer's per-context pseudonym routing ID.
        pseudonym: [u8; 32],
        /// Oneshot reply channel. Replies `Ok(())` once the registry is
        /// updated, or `Err` if the context is broadcast-routed.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Insert a member directly into the context's role state (`members` +
    /// role `assignments`), bypassing the MLS Welcome / governance round-trip.
    ///
    /// Single-node tests that need a multi-member context — e.g. to exercise
    /// exporter selection over a context whose membership map holds 2+ DIDs —
    /// cannot drive a genuine join: the bridge governance/key resolver only
    /// resolves DID-document-published identities, and in-memory test
    /// identities are never published. This seam records membership the same
    /// way an executed `AddMember` would for the two role-state fields export
    /// reads, without requiring a resolvable key or an MLS group operation.
    ///
    /// Gated behind the `testing` feature — never compiled into production
    /// builds, never reachable from any FFI bridge.
    #[cfg(feature = "testing")]
    TestInsertMember {
        /// Context identifier.
        context_id: String,
        /// The member DID to insert.
        member_did: scp_did::DID,
        /// The role name to assign (e.g. `"member"`).
        role: String,
        /// Oneshot reply channel. Replies `Ok(())` once role state is updated,
        /// or `Err` if the context is unknown / inactive.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Install a specific member's access key directly into the context's
    /// access key store (§9.17), bypassing the pull-based distribution protocol.
    ///
    /// The §9.17 access-key PULL protocol (`crypto::access_keys::wire`) lets a
    /// member acquire another member's access key via a signed HPKE request the
    /// key holder answers. A Welcome-joiner's actor spawns with an EMPTY access
    /// key store (its own random key is minted by the creator and delivered
    /// out-of-band; incumbents' keys likewise). The PRODUCTION wiring that runs
    /// that pull in the actor loop and distributes keys on join is deferred and
    /// tracked (§9.16 actor-loop pull = #2049; §9.17 production distribution =
    /// #2050; spec↔ADR reconciliation = #2051). This seam lets the full-stack
    /// test harness land an access key it obtained through the REAL pull
    /// (`request_access_key` → `handle_access_key_request` → `open_access_key_response`
    /// over the harness's simulated transport) into the joiner's actor store, so
    /// the joiner can wrap content CEKs for its peers on send exactly as the
    /// deferred production distribution eventually will.
    ///
    /// Gated behind the `testing` feature — never compiled into production
    /// builds, never reachable from any FFI bridge.
    ///
    /// # Expiry
    ///
    /// EXPIRES with #2050. When production §9.17 distribution lands, DELETE this
    /// variant, its handler
    /// [`handle_test_install_access_key`](crate::context::actor::handlers::messaging),
    /// the [`Supervisor::test_install_access_key`](crate::context::supervisor::Supervisor::test_install_access_key)
    /// mailbox entrypoint, and the harness
    /// `FullStackNode::pull_access_keys_from_creator` driver — then confirm the
    /// Python/TS bidirectional tripwires still pass on the *production*
    /// distribution path. Safe to carry until then: `testing`-gated, no FFI
    /// wrapper, reachable only by in-process `Arc<Supervisor>` callers (the
    /// full-stack harness), even in the `allow_in_memory_custody` build the
    /// tripwires use.
    #[cfg(feature = "testing")]
    TestInstallAccessKey {
        /// Context identifier (the raw string id the access-key store is keyed by).
        context_id: String,
        /// The member whose access key this is (the key's owner).
        member_did: String,
        /// The access key, recovered from a real §9.17 pull response.
        key: scp_protocol::crypto::access_keys::AccessKey,
        /// Oneshot reply channel. Replies `Ok(())` once the key is stored.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Record that a received envelope triggered degraded-mode (spec
    /// §13.6) for a context. Emits a `DegradedMode` event into the
    /// per-context receive buffer (and the supervisor's optional event
    /// broadcast channel).
    ///
    /// Mirrors the legacy
    /// [`Supervisor::report_degraded_mode`](crate::context::supervisor::Supervisor::report_degraded_mode)
    /// signature: a fire-and-forget side-effect on the messaging path's
    /// receive-buffer state. The reply channel carries `Ok(())` once the
    /// emit completes (or no-ops on `Match` / `IncompatibleMajor`
    /// envelopes); the handler never errors.
    ///
    /// Routing it through the messaging dispatch keeps every receive-
    /// buffer mutation in one place alongside `DeliverIncoming` and
    /// `DrainEvents`.
    ReportDegradedMode {
        /// Context identifier.
        context_id: String,
        /// Envelope-level version compatibility classification carried by
        /// the inbound message (spec §13.6). Only the
        /// [`VersionCompatibility::DegradedMode`](scp_protocol::envelope::VersionCompatibility)
        /// case triggers an event — the others are silent no-ops.
        compat: scp_protocol::envelope::VersionCompatibility,
        /// Sender-advertised feature flags the local peer cannot
        /// interpret. Surfaced verbatim on the emitted `DegradedMode`
        /// event so the application layer can decide whether to warn /
        /// abort.
        unsupported_features: Vec<String>,
        /// Oneshot reply channel. Always replies `Ok(())` — the legacy
        /// method has no error path.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Build (force) a signed local consistency checkpoint from the
    /// current event-log state (§9.9.3). Mutating — resets the
    /// checkpoint-events-since counter and pushes the checkpoint onto the
    /// retained checkpoint ring.
    ///
    /// Delegates to
    /// [`force_create_checkpoint_fields`](crate::context::queries_helpers::force_create_checkpoint_fields).
    /// Used by the reconnection driver's Phase 3 (`event_log_sync`) at the
    /// FFI/SDK layer: the driver builds its local checkpoint, sends it to
    /// peers via the send path, and compares peer checkpoints against local
    /// state. The caller supplies `sender_did` + `signing_key` exactly as
    /// the application send path does (the signing key is not actor-owned
    /// state — it lives at the FFI boundary).
    BuildLocalCheckpoint {
        /// Context identifier.
        context_id: String,
        /// Checkpoint author DID (a locally-controlled member).
        sender_did: scp_did::DID,
        /// Author's Ed25519 signing key. Wrapped in [`SigningKeyBytes`]
        /// so the private key zeroes on drop (mirrors the
        /// [`SendMessagePayload`] pattern).
        signing_key: SigningKeyBytes,
        /// Oneshot reply channel carrying the freshly-built signed
        /// checkpoint.
        reply: BuildLocalCheckpointReply,
    },

    /// Compare a remote consistency checkpoint against local event-log
    /// state for equivocation detection (§9.9.3, ADR-011 AC-8). Mutating
    /// — surfaces a divergence by minting an `EquivocationDetected` record
    /// into the receive buffer (and broadcasting it) when the comparison is
    /// `Divergent`. The record is NOT appended to the durable Merkle log: it
    /// is a receiver-local mint outside the sender-authenticated leaf
    /// sequence, so persisting it would let two honest receivers compute
    /// divergent roots and false-positive the very §9.9.3 detection it
    /// records (deduped per distinct divergent checkpoint per sender).
    ///
    /// Delegates to
    /// [`compare_remote_checkpoint`](crate::context::queries_helpers::compare_remote_checkpoint).
    /// The reply carries the typed
    /// [`CheckpointComparison`](scp_event_log::checkpoint::CheckpointComparison)
    /// (`Consistent` / `Behind` / `Ahead` / `Divergent`). The `Behind`
    /// arm is the post-offline catch-up seam — the consistency-proof
    /// catch-up integration point, specified separately. Used by the
    /// reconnection driver's Phase 3.
    CompareRemoteCheckpoint {
        /// Context identifier.
        context_id: String,
        /// The remote checkpoint to compare (boxed to keep the enum
        /// variant size uniform under `clippy::large_enum_variant`).
        remote: Box<scp_event_log::checkpoint::ConsistencyCheckpoint>,
        /// Oneshot reply channel carrying the comparison result.
        reply: CompareRemoteCheckpointReply,
    },

    /// Send a suppression-detection heartbeat (§9.9.2) to context peers.
    ///
    /// Delegates to
    /// [`send_heartbeat`](crate::context::messaging_helpers::send_heartbeat),
    /// which routes an EMPTY-payload [`MessageType::Heartbeat`](scp_protocol::envelope::inner::MessageType::Heartbeat)
    /// envelope through the regular encrypt-and-send path. Driven by the
    /// bridge/SDK subscribe-path scheduler (the §9.9.2 "the SDK sends
    /// heartbeats" boundary): the caller supplies `sender_did` + `signing_key`
    /// per-call exactly like [`SendMessage`](Self::SendMessage) and
    /// [`BuildLocalCheckpoint`](Self::BuildLocalCheckpoint), because the
    /// signing key is NOT actor-owned state — it lives at the FFI boundary.
    /// Routing the send through the actor serializes it with the context's
    /// other sends.
    ///
    /// Best-effort: replies `Ok(())` on success or the transport error if every
    /// fan-out send fails. The bridge scheduler logs failures but never tears
    /// down the subscription (a missed heartbeat is itself a suppression
    /// signal, surfaced by the receiver's gap detection).
    SendHeartbeat {
        /// Context identifier.
        context_id: String,
        /// Heartbeat author DID (a locally-controlled member).
        sender_did: scp_did::DID,
        /// Author's Ed25519 signing key. Wrapped in [`SigningKeyBytes`] so
        /// the private key zeroes on drop (mirrors the
        /// [`SendMessagePayload`] pattern).
        signing_key: SigningKeyBytes,
        /// Oneshot reply channel. `Ok(())` on success; transport error if
        /// every fan-out send fails.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },
}

/// Reply-channel type alias for
/// [`MessagingCommand::BuildLocalCheckpoint`]. Carries the freshly-built
/// signed checkpoint. Factored out to satisfy `clippy::type_complexity`.
pub type BuildLocalCheckpointReply =
    oneshot::Sender<Result<scp_event_log::checkpoint::ConsistencyCheckpoint, ContextError>>;

/// Reply-channel type alias for
/// [`MessagingCommand::CompareRemoteCheckpoint`]. Carries the typed
/// [`CheckpointComparison`](scp_event_log::checkpoint::CheckpointComparison).
/// Factored out to satisfy `clippy::type_complexity`.
pub type CompareRemoteCheckpointReply =
    oneshot::Sender<Result<scp_event_log::checkpoint::CheckpointComparison, ContextError>>;

/// Payload for [`MessagingCommand::SendPseudonymAnnouncement`]. Boxed
/// inside the variant so the enum's variant sizes stay uniform under
/// `clippy::large_enum_variant` despite carrying
/// [`ContextParams`](scp_protocol::context::params::ContextParams)
/// (~1KB) and a zeroizing signing key.
pub struct SendPseudonymAnnouncementPayload {
    /// Context identifier (plain string, matches the legacy API).
    pub context_id: String,
    /// Creation-time parameters used to rebuild an ephemeral
    /// [`ContextHandle`](crate::context::ContextHandle) on the handler
    /// side. Cloned from the caller's handle at dispatch time.
    pub params: scp_protocol::context::params::ContextParams,
    /// Sender DID (the announcing member).
    pub sender_did: scp_did::DID,
    /// Sender's Ed25519 signing key. Wrapped in [`SigningKeyBytes`] so
    /// the private key zeroes on drop (mirrors the
    /// [`SendMessagePayload`] pattern).
    pub signing_key: SigningKeyBytes,
}

/// Owned Ed25519 signing key bytes used inside
/// [`MessagingCommand::SendMessage`]. Wraps the 32-byte seed in
/// [`Zeroizing`](zeroize::Zeroizing) so the private key zeroes on drop
/// even if the command is dropped mid-mailbox without being dispatched
/// (cancellation path). The handler reconstructs
/// [`ed25519_dalek::SigningKey`] from the bytes on the receive side.
pub struct SigningKeyBytes(pub zeroize::Zeroizing<[u8; 32]>);

impl SigningKeyBytes {
    /// Construct from an [`ed25519_dalek::SigningKey`] borrowed from
    /// the caller. Copies the 32-byte seed so the caller's key can be
    /// dropped while the command is in flight.
    #[must_use]
    pub fn from_signing_key(sk: &ed25519_dalek::SigningKey) -> Self {
        Self(zeroize::Zeroizing::new(sk.to_bytes()))
    }

    /// Rebuild the [`ed25519_dalek::SigningKey`] on the handler side.
    /// The returned value is NOT wrapped in `Zeroizing`; callers take
    /// responsibility for zeroizing it after use (the command's own
    /// bytes zero on drop regardless).
    #[must_use]
    pub fn to_signing_key(&self) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&self.0)
    }
}

/// Reply-channel type alias for [`LifecycleCommand::CreateContext`]. The
/// reply carries the [`ContextHandle`](crate::context::ContextHandle) of
/// the freshly-created context. Factored out to satisfy
/// `clippy::type_complexity` given the crate-path-heavy return type.
pub type CreateContextReply = oneshot::Sender<
    Result<crate::context::ContextHandle, scp_protocol::context::builder::ContextCreationError>,
>;

/// Reply-channel type alias for [`LifecycleCommand::CloseContext`]. The
/// reply carries a [`CloseResult`](crate::context::ttl::CloseResult) so
/// the caller can observe summary-generation / key-destruction flags.
pub type CloseContextReply =
    oneshot::Sender<Result<crate::context::ttl::CloseResult, ContextError>>;

/// Reply-channel type alias for [`LifecycleCommand::ExportContext`].
///
/// The reply carries the UNSIGNED export building blocks captured from the
/// actor-owned state: the `ContextSnapshot` and the serialized Merkle
/// event-log data. The actor holds no custody/signing key, so the snapshot
/// signature is applied by the dispatcher
/// ([`Supervisor::export_context`](crate::context::supervisor::Supervisor::export_context))
/// via [`create_export`](crate::context::export_import::create_export) once
/// these blocks are returned — keeping the signature over the exact canonical
/// bytes a verifier recomputes (§23.16.8, ADR-050).
pub type ExportContextReply =
    oneshot::Sender<Result<(crate::context::state::ContextSnapshot, Vec<u8>), ContextError>>;

/// Reply-channel type alias for [`LifecycleCommand::ImportContext`]. The
/// reply carries the restored context's
/// [`ContextHandle`](crate::context::ContextHandle).
pub type ImportContextReply = oneshot::Sender<Result<crate::context::ContextHandle, ContextError>>;

/// Payload for [`LifecycleCommand::CreateContext`]. Boxed inside the
/// variant so the enum's variant sizes stay uniform despite
/// [`ContextParams`](scp_protocol::context::params::ContextParams)
/// being ~1KB.
pub struct CreateContextPayload {
    /// Context identifier (plain string; the `Supervisor::create_context`
    /// entry point derives the 32-byte hash internally).
    pub context_id: String,
    /// Creation-time parameters — governance model, ceiling, TTL,
    /// economic policy, etc.
    pub params: scp_protocol::context::params::ContextParams,
    /// Creator's DID. Becomes the sole `admin` assignment in the
    /// initial `ContextRoleState`.
    pub creator_did: scp_did::DID,
    /// Optional §9.10.4 pseudonym routing ID for the creator's
    /// local member. `None` on broadcast contexts (ignored).
    pub local_pseudonym: Option<[u8; 32]>,
}

/// Payload for [`LifecycleCommand::JoinContext`]. Boxed inside the
/// variant for the same reason as [`CreateContextPayload`].
pub struct JoinContextPayload {
    /// Context identifier string (matches the legacy API).
    pub context_id: String,
    /// Context params — used to rebuild an ephemeral
    /// [`ContextHandle`](crate::context::ContextHandle) on the
    /// handler side, matching the legacy method's borrow shape.
    pub params: scp_protocol::context::params::ContextParams,
    /// MLS key package identifying the joining member. Carries the
    /// member DID + TLS-serialized key-package bytes.
    pub key_package: scp_protocol::context::membership::KeyPackage,
    /// Optional spending UCAN for the join (§19.5).
    pub spending_ucan: Option<scp_protocol::crypto::ucan::UcanToken>,
    /// Optional §9.10.4 pseudonym routing ID for the joining
    /// member.
    pub local_pseudonym: Option<[u8; 32]>,
}

/// Payload for [`LifecycleCommand::LeaveContext`]. Boxed inside the
/// variant for the same reason as [`CreateContextPayload`].
pub struct LeaveContextPayload {
    /// Context identifier string.
    pub context_id: String,
    /// Context params — used to rebuild an ephemeral handle.
    pub params: scp_protocol::context::params::ContextParams,
    /// Caller DID (the initiator of the leave operation).
    pub caller_did: scp_did::DID,
    /// Target DID (the member to remove; may equal `caller_did`).
    pub member_did: scp_did::DID,
}

/// Payload for [`LifecycleCommand::CloseContext`]. Boxed inside the
/// variant for the same reason as [`CreateContextPayload`].
pub struct CloseContextPayload {
    /// Context identifier string.
    pub context_id: String,
    /// Context params — used to rebuild an ephemeral handle.
    pub params: scp_protocol::context::params::ContextParams,
    /// Initiator DID. Requires the `ContextClose` capability under
    /// `SingleAdmin` governance.
    pub initiator_did: scp_did::DID,
}

/// Payload for [`LifecycleCommand::RestoreContext`]. Boxed inside the
/// variant for the same reason as [`CreateContextPayload`] —
/// `ContextParams` is ~1KB.
pub struct RestoreContextPayload {
    /// Context identifier string.
    pub context_id: String,
    /// Context params — used to rebuild an ephemeral
    /// [`ContextHandle`](crate::context::ContextHandle) on the handler
    /// side. The legacy method takes the handle by reference; the
    /// command carries the underlying params so the dispatch layer can
    /// reconstruct the handle without lifetime juggling across the
    /// mailbox.
    pub params: scp_protocol::context::params::ContextParams,
}

/// See [`ContextCommand::Lifecycle`]. Real variants land in commit 9 of
/// the ADR-049 commit ladder (see `handlers/lifecycle.rs`). Variants
/// mirror the legacy
/// [`Supervisor`](crate::context::supervisor::Supervisor) lifecycle
/// surface one-to-one: the handler shim delegates to the legacy method
/// under the hood while the command shape fixes the post-refactor
/// dispatch envelope. Commit 12 deletes the shim; the handler bodies
/// keep their current shape (input types + reply channels) but route
/// state mutations to the actor's owned
/// [`PerContextState`](crate::context::actor::state::PerContextState).
///
/// **Create / join.** `CreateContext` / `JoinContext` route directly through
/// [`Supervisor::create_context`](crate::context::supervisor::Supervisor::create_context)
/// / [`Supervisor::join_context`](crate::context::supervisor::Supervisor::join_context).
/// Neither is a saga entry point: standing-pair creation is single-context
/// async creation (not a 2-phase saga; spec §5.15.8), and cross-identity
/// context migration was withdrawn (ADR-049 §4). The sole cross-context saga
/// is outlet invocation (§6.2.4), driven from the supervisor, not this enum.
pub enum LifecycleCommand {
    /// Creates a new MLS-backed (or broadcast-mode) context. Mirrors
    /// [`Supervisor::create_context`](crate::context::supervisor::Supervisor::create_context).
    ///
    /// Standing-pair creation also routes through `create_context` — it is
    /// single-context async creation (not a saga-prepare flow; spec §5.15.8),
    /// so the handler goes straight through the method.
    ///
    /// Boxed payload — [`ContextParams`](scp_protocol::context::params::ContextParams)
    /// is ~1KB, which would blow up every sibling variant under
    /// `clippy::large_enum_variant`. The handler unboxes on receipt.
    CreateContext {
        /// Boxed owned payload.
        payload: Box<CreateContextPayload>,
        /// Oneshot reply channel. See [`CreateContextReply`].
        reply: CreateContextReply,
    },

    /// Joins an existing context. Mirrors
    /// [`Supervisor::join_context`](crate::context::supervisor::Supervisor::join_context).
    ///
    /// The caller is the MLS `KeyPackage` owner (`key_package.owner_did`).
    /// `spending_ucan` is the optional UCAN for the economy layer's
    /// AND-composition check (spec §19.5); parsed by the FFI bridges
    /// before dispatch.
    ///
    /// Boxed for the same reason as [`Self::CreateContext`].
    JoinContext {
        /// Boxed owned payload.
        payload: Box<JoinContextPayload>,
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Removes a member from an active context. Mirrors
    /// [`Supervisor::leave_context`](crate::context::supervisor::Supervisor::leave_context).
    ///
    /// Self-removal (`caller_did == member_did`) is always permitted;
    /// removing another member requires the `MemberRemove` capability
    /// on the caller.
    LeaveContext {
        /// Boxed owned payload.
        payload: Box<LeaveContextPayload>,
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Initiates cooperative context closure. Mirrors
    /// [`lifecycle_helpers::close_context`](crate::context::lifecycle_helpers::close_context)
    /// (not `close_context_with_key` — the latter is an internal
    /// optimization for checkpoint generation; commit 9 exposes the
    /// public surface through the command enum).
    ///
    /// Only valid on `SingleAdmin` governance contexts; multi-admin
    /// contexts must route through the governance path
    /// (`GovernanceAction::CloseContext`).
    CloseContext {
        /// Boxed owned payload.
        payload: Box<CloseContextPayload>,
        /// Oneshot reply channel. See [`CloseContextReply`].
        reply: CloseContextReply,
    },

    /// Exports a snapshot of the context for cross-instance transfer.
    /// The actor captures the unsigned snapshot + event-log blocks via the
    /// `lifecycle_helpers::export_context_blocks` free function; the Ed25519
    /// snapshot signature is produced at the dispatch boundary in
    /// [`Supervisor::export_context`](crate::context::supervisor::Supervisor::export_context),
    /// which holds the custody sign closure (the actor holds no key).
    ExportContext {
        /// Context identifier string.
        context_id: String,
        /// Exporter DID — signs the export header.
        exporter_did: scp_did::DID,
        /// Oneshot reply channel. See [`ExportContextReply`].
        reply: ExportContextReply,
    },

    /// Imports a previously exported context. Mirrors
    /// [`Supervisor::import_context`](crate::context::supervisor::Supervisor::import_context).
    ///
    /// The per-instance authorization-state wipe policy (C3) is enforced
    /// by the legacy method; the command carries the raw export and
    /// expects the handler to pass it through verbatim.
    ImportContext {
        /// Fully-parsed context export — envelope has already been
        /// deserialized by the FFI bridge.
        export: Box<crate::context::export_import::ContextExport>,
        /// Ed25519 verification-method key for the snapshot's `creator_did`
        /// (§23.16.8 step 1, ADR-050). Resolved by the FFI bridge from the
        /// snapshot `creator_did` — NEVER the unauthenticated envelope
        /// `exporter_did`. The import path verifies the snapshot signature
        /// against this key before restoring any state (verify-before-init).
        verifying_key: Box<ed25519_dalek::VerifyingKey>,
        /// The importing member's derived per-context pseudonym routing ID
        /// (§9.10.4). Import is encrypted-only, so a real pseudonym is required
        /// for a usable import.
        ///
        /// Hard-failing on a missing pseudonym is the FFI boundary's
        /// responsibility: every native bridge derives this via
        /// `KeyCustody::derive_pseudonym` and returns an error rather than
        /// passing `None`. The runtime itself does NOT hard-fail on `None` — it
        /// maps `None` to the reserved zero sentinel (`[0u8; 32]`) through
        /// `build_routing`, a degraded-but-safe state (the sentinel is a
        /// reserved routing value the member cannot announce until a real
        /// pseudonym is set, and the send path never unions the shared routing
        /// ID into fan-out). A `None` therefore only arises from a non-FFI
        /// caller (e.g. a test fixture) and yields a routable-but-not-yet-
        /// announced member, not a silent shared-RID fallback.
        local_pseudonym: Option<[u8; 32]>,
        /// Oneshot reply channel. See [`ImportContextReply`].
        reply: ImportContextReply,
    },

    /// Restore a single previously-persisted context from storage.
    /// Mirrors
    /// [`Supervisor::restore_context`](crate::context::supervisor::Supervisor::restore_context).
    ///
    /// The legacy method loads a snapshot from the configured
    /// [`ContextPersistence`](crate::context::persistence::ContextPersistence)
    /// provider, validates / sanitizes consequence rules + cooldown
    /// state, restores the MLS crypto state, and reconstructs the
    /// per-context governance / membership / broadcast structures.
    /// Boxed payload — see [`RestoreContextPayload`].
    RestoreContext {
        /// Boxed owned payload.
        payload: Box<RestoreContextPayload>,
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Generate and store a per-member access key for explicit
    /// lifecycle management (§9.17.2 step 1). Mirrors
    /// [`queries_helpers::generate_context_access_key`](crate::context::queries_helpers::generate_context_access_key).
    ///
    /// Requires `ContextClose` capability on the caller. Overwrites any
    /// existing key for the same `(context_id, member_did)` pair.
    GenerateContextAccessKey {
        /// Context identifier string.
        context_id: String,
        /// Member DID receiving the key.
        member_did: String,
        /// Caller DID — must hold `ContextClose` capability.
        caller_did: String,
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Revoke (remove) a member's access key from the context's
    /// access key store (§9.17.2 step 3, ADR-038). Mirrors
    /// [`queries_helpers::revoke_context_access_key`](crate::context::queries_helpers::revoke_context_access_key).
    ///
    /// Requires `ContextClose` capability on the caller.
    RevokeContextAccessKey {
        /// Context identifier string.
        context_id: String,
        /// Member DID losing the key.
        member_did: String,
        /// Caller DID — must hold `ContextClose` capability.
        caller_did: String,
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Restore a member's access key by generating a fresh key at
    /// epoch 0 (§9.17.2 step 5, ADR-038 forward-only restoration).
    /// Mirrors
    /// [`restore_context_access_key`](crate::context::queries_helpers::restore_context_access_key).
    ///
    /// Requires `ContextClose` capability on the caller. Historical
    /// content from the revocation period remains permanently
    /// inaccessible (the old key was destroyed and is never
    /// re-distributed).
    RestoreContextAccessKey {
        /// Context identifier string.
        context_id: String,
        /// Member DID receiving the restored key.
        member_did: String,
        /// Caller DID — must hold `ContextClose` capability.
        caller_did: String,
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Sweep: best-effort flush of THIS actor's snapshot to the configured
    /// persistence provider.
    ///
    /// Dispatched per-actor by the supervisor's iterating sweep entry
    /// point
    /// [`lifecycle_helpers::flush_all_contexts`](crate::context::lifecycle_helpers::flush_all_contexts)
    /// (and its sync wrapper). The supervisor iterates
    /// `supervisor.actors` and sends one of these commands per actor;
    /// each actor flushes its own state with no cross-actor lock.
    ///
    /// Mirrors the per-context body of the legacy
    /// `flush_all_contexts_legacy` (which iterated the supervisor's
    /// `contexts` DashMap and took a per-context lock with the
    /// since-deleted `FLUSH_LOCK_BUDGET`).
    /// The actor path needs no separate lock budget — the actor's own
    /// dispatch loop serializes by construction, so the command sits in
    /// the mailbox until the actor is idle. The handler builds a snapshot
    /// from `&state` (and any broadcast context) and calls the
    /// persistence provider directly.
    ///
    /// Reply replies `Ok(())` regardless of per-context persist outcome;
    /// persist failures log via `tracing::warn!` inside the handler and
    /// increment `crate::metrics::record_persistence_failure()` so the
    /// legacy `_legacy` body's observable side effects are preserved.
    FlushSnapshot {
        /// Oneshot reply channel. Always replies `Ok(())` — best-effort
        /// flush contract.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Sweep: shut down THIS actor's per-context resources (best-effort
    /// local cleanup only).
    ///
    /// Dispatched per-actor by the supervisor's iterating sweep entry
    /// points
    /// [`lifecycle_helpers::shutdown_all_contexts`](crate::context::lifecycle_helpers::shutdown_all_contexts)
    /// (and its sync wrapper). The supervisor iterates
    /// `supervisor.actors` and sends one of these commands per actor.
    ///
    /// Mirrors the per-context body of the legacy
    /// `shutdown_all_contexts_legacy`. Destroys per-context sender keys,
    /// MLS groups, and event logs in that order (zeroize secrets before
    /// tearing down structure). Does NOT send leave messages or notify
    /// remote peers — used by `scp_ffi_common::BridgeInstance::shutdown`
    /// for process exit / test teardown.
    ///
    /// The handler operates on the actor's owned `&mut state` so the
    /// secrets are zeroed in place. Supervisor-level state (standing
    /// contexts, local DIDs, wrapping keys, task set) is cleared by the
    /// supervisor's iterating entry point AFTER the per-actor commands
    /// complete — that supervisor-scope cleanup is shared across
    /// contexts and lives outside any single actor's responsibility.
    ///
    /// Reply replies `Ok(())` regardless of per-resource destroy
    /// outcome; failures log via `tracing::debug!` (the resource may
    /// already be gone) inside the handler.
    ShutdownSelf {
        /// Oneshot reply channel. Always replies `Ok(())` — best-effort
        /// shutdown contract.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Sweep: report THIS actor's receive-buffer occupancy.
    ///
    /// Dispatched per-actor by the supervisor's gauge sweep
    /// [`update_context_gauges`](crate::context::manager_methods::update_context_gauges).
    /// The supervisor iterates [`actor_ids`](crate::context::supervisor::Supervisor::actor_ids)
    /// and sends one of these commands per actor, summing the replies to
    /// produce the `buffer_occupancy` gauge.
    ///
    /// Replaces the legacy gauge path that iterated the `contexts`
    /// DashMap and `try_lock`ed each `Arc<per-context-state Mutex>` to read
    /// `receive_buffer.len()` (ADR-049 Phase 2A finalization — DashMap
    /// removal). The actor owns its state, so the handler reads
    /// `state.receive_buffer.len()` directly with no cross-actor lock.
    ///
    /// Read-only: the handler returns an
    /// [`Outcome`](crate::context::actor::Outcome) with `mutated =
    /// false`.
    ReportBufferLen {
        /// Oneshot reply channel carrying this actor's receive-buffer
        /// length.
        reply: oneshot::Sender<usize>,
    },

    /// Clear the context's `EpochState.needs_reconnect` flag (spec
    /// §23.11). Mutating. Called by the reconnection driver at the
    /// FFI/SDK layer after a context completes the six-phase protocol
    /// successfully, so a subsequent restore does not re-drive the
    /// already-synced context. Always replies `Ok(())`.
    ClearNeedsReconnect {
        /// Context identifier.
        context_id: String,
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Issue an MLS Update proposal + self-Commit for post-compromise
    /// security (§9.12 step 2). Mutating — ratchets the group to a new
    /// epoch with fresh key material via
    /// [`MlsCryptoProvider::advance_epoch`](crate::crypto::mls::provider::MlsCryptoProvider::advance_epoch)
    /// (which calls `ratchet::propose_update_with_wrapping_key`,
    /// preserving the `scp_wrapping_key` leaf extension per §9.16.1).
    ///
    /// The reply carries the TLS-serialized MLS Commit bytes that the
    /// caller MUST distribute to all group members. Used by the
    /// reconnection driver's Phase 5 (`mls_update`).
    IssueMlsUpdate {
        /// Context identifier.
        context_id: String,
        /// Oneshot reply channel carrying the serialized MLS Commit
        /// bytes for distribution.
        reply: oneshot::Sender<Result<Vec<u8>, ContextError>>,
    },
}

/// Reply-channel type alias for
/// [`GovernanceCommand::ProposeGovernanceAction`]. The reply carries the
/// created proposal, the emitted engine events, and the optional
/// auto-execution result (present for `SingleAdmin` governance).
/// Factored out to satisfy `clippy::type_complexity`.
pub type ProposeGovernanceActionReply = oneshot::Sender<
    Result<
        (
            scp_protocol::context::governance::GovernanceProposal,
            Vec<scp_protocol::context::governance::GovernanceEvent>,
            Option<crate::context::state::GovernanceActionResult>,
        ),
        ContextError,
    >,
>;

/// Reply-channel type alias for
/// [`GovernanceCommand::ProposeGovernanceActionChecked`]. The reply
/// carries a full [`ProposalOutcome`](crate::context::state::ProposalOutcome) — proposal, status, optional
/// execution result. Factored out for the same reason as
/// [`ProposeGovernanceActionReply`].
pub type ProposeGovernanceActionCheckedReply =
    oneshot::Sender<Result<crate::context::state::ProposalOutcome, ContextError>>;

/// Reply-channel type alias for [`GovernanceCommand::VoteOnProposal`].
/// Mirrors the legacy method: `(ProposalStatus, Vec<GovernanceEvent>)`.
pub type VoteOnProposalReply = oneshot::Sender<
    Result<
        (
            scp_protocol::context::governance::ProposalStatus,
            Vec<scp_protocol::context::governance::GovernanceEvent>,
        ),
        ContextError,
    >,
>;

/// Payload for [`GovernanceCommand::ProposeGovernanceAction`] and
/// [`GovernanceCommand::ProposeGovernanceActionChecked`]. Boxed inside
/// each variant so the enum's variant sizes stay uniform under
/// `clippy::large_enum_variant` (GovernanceAction may embed large
/// sub-structs like outlet interfaces or ceiling modifications).
pub struct ProposeGovernanceActionPayload {
    /// Context identifier string.
    pub context_id: String,
    /// Proposer DID.
    pub proposer_did: scp_did::DID,
    /// Typed governance action — one of the 28 variants from ADR-031.
    pub action: scp_protocol::context::governance::GovernanceAction,
    /// Proposer's Ed25519 signing key. Wrapped in [`SigningKeyBytes`]
    /// so the private key zeroes on drop (mirrors the messaging path's
    /// command-level zeroize contract).
    pub signing_key: SigningKeyBytes,
    /// The invitee's TLS-serialized MLS `KeyPackage` for an `AddMember`
    /// auto-execute. Carried here — on the in-process actor command envelope,
    /// NOT on the signed/logged
    /// [`GovernanceAction`](scp_protocol::context::governance::GovernanceAction)
    /// wire type — by [`Supervisor::invite_member`](crate::context::supervisor::Supervisor::invite_member),
    /// which threads it to `execute_add_member` so the governance add performs a
    /// REAL MLS add (§5.12.3). `None` for every other proposal (the generic FFI
    /// governance path). The `KeyPackage` is the invitee's PUBLIC credential (no
    /// private key material).
    pub key_package: Option<Vec<u8>>,
}

/// Payload for [`GovernanceCommand::VoteOnProposal`],
/// [`GovernanceCommand::ApproveGovernanceProposal`], and
/// [`GovernanceCommand::RejectGovernanceProposal`]. Boxed so the outer
/// enum's variant sizes stay uniform — the signing key embeds a
/// [`Zeroizing<[u8; 32]>`](zeroize::Zeroizing) and the proposal-ID +
/// DID + context-id fields combine to ~150 bytes; boxing keeps the
/// variant payload size constant.
pub struct VoteOnProposalPayload {
    /// Context identifier string.
    pub context_id: String,
    /// Target proposal ID (32 bytes).
    pub proposal_id: scp_protocol::context::governance::ProposalId,
    /// Voter DID.
    pub voter_did: scp_did::DID,
    /// Voter's Ed25519 signing key (zeroized on drop via
    /// [`SigningKeyBytes`]).
    pub signing_key: SigningKeyBytes,
}

/// Payload for [`GovernanceCommand::ExecuteGovernanceAction`].
///
/// Carries only the *identifier* of an already-tracked proposal — never a
/// caller-supplied proposal, action, status, or executor DID (the executor is
/// resolved from the tracked proposal's `proposer_did`). The handler resolves
/// the authoritative proposal from the context
/// actor's own governance engine via `engine.get_proposal(proposal_id)` and
/// rejects anything that is not present and `Approved`. This closes the
/// direct-execute quorum-bypass: a caller cannot fabricate an `Approved`
/// proposal or substitute an action, because the runtime trusts only what its
/// own quorum-validated engine retained.
pub struct ExecuteGovernanceActionPayload {
    /// Context identifier string.
    pub context_id: String,
    /// Identifier of the proposal to execute. Looked up in the context
    /// actor's governance engine; must be tracked and `Approved`. The executor
    /// attribution for the `GovernanceActionExecuted` leaf is resolved from the
    /// tracked proposal's `proposer_did` (the direct-execute committing member),
    /// never from a caller-supplied DID — ADR-031 §8 / spec §7.3.1.
    pub proposal_id: scp_protocol::context::governance::ProposalId,
}

/// See [`ContextCommand::Governance`]. Real variants land in commit 10
/// of the ADR-049 commit ladder (see `handlers/governance.rs`).
/// Variants mirror the public surface of
/// [`crate::context::governance_helpers`] one-to-one: propose, vote,
/// approve/reject/withdraw, execute, read proposals, apply pending
/// ceiling / economic-policy changes, tombstone migrations, acknowledge
/// commit faults. ADR-031 defines 28 governance actions; those are the
/// payload discriminants of the single
/// [`GovernanceAction`](scp_protocol::context::governance::GovernanceAction)
/// enum carried by the propose variants — the command surface here
/// mirrors the manager methods that accept them, not the actions
/// themselves.
pub enum GovernanceCommand {
    /// Submits a governance proposal — unchecked variant. Mirrors
    /// [`Supervisor::propose_governance_action`](crate::context::supervisor::Supervisor::propose_governance_action).
    /// Accepts the proposer DID + action + signing key without a
    /// capability pre-check (the governance engine enforces eligibility
    /// internally). For `SingleAdmin` contexts the proposal is auto-
    /// approved and executed; for multi-admin models it enters
    /// `Pending`.
    ProposeGovernanceAction {
        /// Boxed owned payload.
        payload: Box<ProposeGovernanceActionPayload>,
        /// Oneshot reply channel. See
        /// [`ProposeGovernanceActionReply`].
        reply: ProposeGovernanceActionReply,
    },

    /// Submits a governance proposal — checked variant. Mirrors
    /// [`Supervisor::propose_governance_action_checked`](crate::context::supervisor::Supervisor::propose_governance_action_checked).
    /// Validates the proposer's `GovernancePropose` capability inside
    /// the same lock as the proposal submission (no TOCTOU).
    ProposeGovernanceActionChecked {
        /// Boxed owned payload (same shape as the unchecked variant).
        payload: Box<ProposeGovernanceActionPayload>,
        /// Oneshot reply channel. See
        /// [`ProposeGovernanceActionCheckedReply`].
        reply: ProposeGovernanceActionCheckedReply,
    },

    /// Casts a vote on a pending proposal. Mirrors
    /// [`Supervisor::vote_on_proposal`](crate::context::supervisor::Supervisor::vote_on_proposal).
    /// `approve == true` is an approval vote; `false` is rejection.
    VoteOnProposal {
        /// Boxed owned payload.
        payload: Box<VoteOnProposalPayload>,
        /// `true` for an approval vote, `false` for rejection. Kept
        /// outside the boxed payload for legibility at the dispatch
        /// site.
        approve: bool,
        /// Oneshot reply channel. See [`VoteOnProposalReply`].
        reply: VoteOnProposalReply,
    },

    /// Casts an approval vote with explicit capability pre-check.
    /// Mirrors [`governance_helpers::approve_governance_proposal`](crate::context::governance_helpers::approve_governance_proposal).
    /// The reply carries only the resulting status (the legacy method
    /// discards the event list by convention — see its implementation).
    ApproveGovernanceProposal {
        /// Boxed owned payload.
        payload: Box<VoteOnProposalPayload>,
        /// Oneshot reply channel.
        reply: oneshot::Sender<
            Result<scp_protocol::context::governance::ProposalStatus, ContextError>,
        >,
    },

    /// Casts a rejection vote with explicit capability pre-check.
    /// Mirrors [`governance_helpers::reject_governance_proposal`](crate::context::governance_helpers::reject_governance_proposal).
    RejectGovernanceProposal {
        /// Boxed owned payload.
        payload: Box<VoteOnProposalPayload>,
        /// Oneshot reply channel.
        reply: oneshot::Sender<
            Result<scp_protocol::context::governance::ProposalStatus, ContextError>,
        >,
    },

    /// Withdraws a previously cast vote. Mirrors
    /// [`Supervisor::withdraw_governance_vote`](crate::context::supervisor::Supervisor::withdraw_governance_vote).
    /// No signing key — withdrawal is the voter's privileged operation
    /// on their own vote per the governance engine's trait contract.
    WithdrawGovernanceVote {
        /// Context identifier string.
        context_id: String,
        /// Target proposal ID (32 bytes).
        proposal_id: scp_protocol::context::governance::ProposalId,
        /// Voter DID.
        voter_did: scp_did::DID,
        /// Oneshot reply channel.
        reply: oneshot::Sender<
            Result<scp_protocol::context::governance::ProposalStatus, ContextError>,
        >,
    },

    /// Executes an already-approved governance proposal. Mirrors
    /// [`governance_helpers::execute_governance_action`](crate::context::governance_helpers::execute_governance_action).
    /// Caller MUST pass a proposal whose status is
    /// [`ProposalStatus::Approved`](scp_protocol::context::governance::ProposalStatus);
    /// the legacy method enforces the gate.
    ExecuteGovernanceAction {
        /// Boxed owned payload (GovernanceProposal is ~several hundred
        /// bytes depending on the inner action).
        payload: Box<ExecuteGovernanceActionPayload>,
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<crate::context::state::GovernanceActionResult, ContextError>>,
    },

    /// Reads a single proposal by ID. Mirrors
    /// [`Supervisor::get_proposal`](crate::context::supervisor::Supervisor::get_proposal).
    GetProposal {
        /// Context identifier string.
        context_id: String,
        /// Target proposal ID.
        proposal_id: scp_protocol::context::governance::ProposalId,
        /// Oneshot reply channel.
        reply: oneshot::Sender<
            Result<scp_protocol::context::governance::GovernanceProposal, ContextError>,
        >,
    },

    /// Lists all proposals for a context. Mirrors
    /// [`Supervisor::list_proposals`](crate::context::supervisor::Supervisor::list_proposals).
    ListProposals {
        /// Context identifier string.
        context_id: String,
        /// Oneshot reply channel.
        reply: oneshot::Sender<
            Result<Vec<scp_protocol::context::governance::GovernanceProposal>, ContextError>,
        >,
    },

    /// Applies a pending ceiling modification whose notification period
    /// has expired. Mirrors
    /// [`governance_helpers::apply_pending_ceiling_modification`](crate::context::governance_helpers::apply_pending_ceiling_modification).
    /// Returns `true` iff a pending modification was applied.
    ApplyPendingCeilingModification {
        /// Context identifier string.
        context_id: String,
        /// Current timestamp (seconds). Caller supplies to keep the
        /// handler pure / deterministic across clock sources.
        current_timestamp: u64,
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<bool, ContextError>>,
    },

    /// Applies a pending economic-policy change whose notification
    /// period has expired. Mirrors
    /// [`governance_helpers::apply_pending_economic_policy_change`](crate::context::governance_helpers::apply_pending_economic_policy_change).
    /// Returns `true` iff a pending change was applied.
    ApplyPendingEconomicPolicyChange {
        /// Context identifier string.
        context_id: String,
        /// Current timestamp (seconds).
        current_timestamp: u64,
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<bool, ContextError>>,
    },

    /// Tombstones a migrated context after the grace period expires.
    /// Mirrors
    /// [`governance_helpers::tombstone_migrated_context`](crate::context::governance_helpers::tombstone_migrated_context).
    TombstoneMigratedContext {
        /// Context identifier string.
        context_id: String,
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Returns the migration state for a context if one exists. Mirrors
    /// [`governance_helpers::migration_state`](crate::context::governance_helpers::migration_state).
    ///
    /// This is read-only; the handler returns
    /// [`Outcome::ok`](crate::context::actor::Outcome::ok) and reports
    /// `mutated: false`.
    MigrationState {
        /// Context identifier string.
        context_id: String,
        /// Oneshot reply channel. `Ok(None)` iff the context is unknown
        /// or not migrating (matches the legacy contract).
        reply: oneshot::Sender<Result<Option<crate::context::state::MigrationState>, ContextError>>,
    },

    /// Acknowledges and clears a commit-fault marker for a context
    /// (PR #1606 C6). Mirrors
    /// [`governance_helpers::acknowledge_commit_fault`](crate::context::governance_helpers::acknowledge_commit_fault).
    AcknowledgeCommitFault {
        /// Context identifier string.
        context_id: String,
        /// Oneshot reply channel. Carries the cleared fault marker.
        reply: oneshot::Sender<Result<crate::context::state::CommitFaultMarker, ContextError>>,
    },

    /// Sweep: evaluate consequence rules for THIS actor's context, applying
    /// any triggered consequences (suspend / revoke / etc.) to membership.
    ///
    /// Dispatched per-actor by the supervisor's iterating sweep entry
    /// point
    /// [`governance_helpers::evaluate_periodic_consequences`](crate::context::governance_helpers::evaluate_periodic_consequences).
    /// The supervisor iterates `supervisor.actors` and sends one of these
    /// commands per actor; aggregate completion is implicit (the
    /// iterator waits for each reply in turn).
    ///
    /// Mirrors the legacy
    /// `evaluate_periodic_consequences_legacy` body (which iterated the
    /// supervisor's `contexts` DashMap and operated on a single
    /// context's state per call). The actor-shape handler operates on
    /// `&mut PerContextState` for the SINGLE actor — sweep iteration
    /// happens at the supervisor level.
    ///
    /// Reply replies `Ok(())` regardless of whether any consequences
    /// fired; the legacy method has no error path (per-rule enforcement
    /// failures log via `tracing::warn!` inside `enforce_triggered_consequences`).
    EvaluatePeriodicConsequences {
        /// Oneshot reply channel. Always replies `Ok(())` (matches the
        /// legacy method's no-error contract).
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Sweep: process THIS actor's pending MLS commit retry queue (PR
    /// #1606 C6).
    ///
    /// Dispatched per-actor by the supervisor's iterating sweep entry
    /// point
    /// [`governance_helpers::process_pending_commits`](crate::context::governance_helpers::process_pending_commits).
    /// The supervisor iterates `supervisor.actors` and sends one of
    /// these commands per actor.
    ///
    /// Mirrors the legacy `process_pending_commits_legacy` body.
    /// Iterates `state.pending_commits`, retries any commits whose
    /// `next_attempt_at <= now`, and either dequeues on success, updates
    /// retry count on transient failure, or marks the context fail-
    /// closed once the retry budget is exhausted. All transport sends
    /// happen with the actor's state lock RELEASED (the actor's
    /// `dispatch_state` arm releases its `&mut state` borrow for the
    /// transport call by snapshotting + reacquiring; see the handler
    /// for the phase split).
    ///
    /// Reply replies `Ok(())` regardless of per-commit outcomes; the
    /// legacy method has no error path (per-commit failures log via
    /// `tracing::warn!` and emit `CommitBroadcast*` receive-buffer
    /// events).
    ProcessPendingCommits {
        /// Oneshot reply channel. Always replies `Ok(())` (matches the
        /// legacy method's no-error contract).
        reply: oneshot::Sender<Result<(), ContextError>>,
    },
    // NOTE (ADR-049 Decision-1 / finding A3): the former `EvaluateTimeouts`
    // and `StartTimeoutTask` variants were retired. The governance-timeout
    // sweep is now ACTOR-OWNED — `ContextActor`'s `governance_timeout`
    // interval arm calls `handlers::governance::evaluate_governance_timeouts`
    // directly, with no supervisor-driven `task_set` spawn or mailbox hop.
}

/// Reply-channel type alias for [`BroadcastCommand::SubscribeBroadcast`].
/// Factored out to satisfy `clippy::type_complexity`.
pub type SubscribeBroadcastReply =
    oneshot::Sender<Result<scp_protocol::context::broadcast::SubscriptionResult, ContextError>>;

/// Reply-channel type alias for
/// [`BroadcastCommand::UnsubscribeBroadcast`]. Factored out to satisfy
/// `clippy::type_complexity`.
pub type UnsubscribeBroadcastReply =
    oneshot::Sender<Result<scp_protocol::context::broadcast::UnsubscribeResult, ContextError>>;

/// Reply-channel type alias for [`BroadcastCommand::PublishBroadcast`] and
/// [`BroadcastCommand::PublishBroadcastContent`]. Factored out to satisfy
/// `clippy::type_complexity`.
pub type PublishBroadcastReply =
    oneshot::Sender<Result<scp_protocol::crypto::sender_keys::BroadcastEnvelope, ContextError>>;

/// Reply-channel type alias for [`BroadcastCommand::ReserveBroadcastPublish`]
/// (phase 1 of the two-phase publish path). Returns the reservation id plus
/// the signing-payload digest the caller must sign. Factored out to satisfy
/// `clippy::type_complexity`.
pub type ReserveBroadcastPublishReply = oneshot::Sender<
    Result<crate::context::broadcast_helpers::BroadcastPublishReservationOutcome, ContextError>,
>;

/// Reply-channel type alias for
/// [`BroadcastCommand::BlockBroadcastSubscriber`]. Factored out to satisfy
/// `clippy::type_complexity`.
pub type BlockBroadcastSubscriberReply =
    oneshot::Sender<Result<scp_protocol::context::broadcast::BlockResult, ContextError>>;

/// Reply-channel type alias for
/// [`BroadcastCommand::HandleBroadcastKeyRequest`]. Factored out to
/// satisfy `clippy::type_complexity`.
pub type HandleBroadcastKeyRequestReply =
    oneshot::Sender<Result<scp_protocol::context::broadcast::KeyRequestDecision, ContextError>>;

/// Reply-channel type alias for
/// [`BroadcastCommand::BroadcastAdmission`]. Factored out to satisfy
/// `clippy::type_complexity`.
pub type BroadcastAdmissionReply = oneshot::Sender<
    Result<Option<scp_protocol::context::broadcast::BroadcastAdmission>, ContextError>,
>;

/// Payload for [`BroadcastCommand::SubscribeBroadcast`]. Boxed inside the
/// variant so the enum's variant sizes stay uniform despite carrying an
/// optional [`UcanToken`](scp_protocol::crypto::ucan::UcanToken) plus
/// context / DID strings.
pub struct SubscribeBroadcastPayload {
    /// Context identifier string.
    pub context_id: String,
    /// Subscriber DID.
    pub subscriber_did: scp_did::DID,
    /// Optional UCAN token — required for gated broadcast contexts.
    pub ucan: Option<scp_protocol::crypto::ucan::UcanToken>,
    /// Timestamp (seconds) at the point of subscription. The caller
    /// supplies this to keep the handler deterministic w.r.t. clock
    /// source (economy / nonce tracking reuse the timestamp).
    pub timestamp: u64,
}

/// Payload for [`BroadcastCommand::UnsubscribeBroadcast`]. Boxed for
/// variant-size uniformity.
pub struct UnsubscribeBroadcastPayload {
    /// Context identifier string.
    pub context_id: String,
    /// Subscriber DID.
    pub subscriber_did: scp_did::DID,
    /// Rotate per-author keys on unsubscribe so the departed subscriber
    /// cannot decrypt future broadcasts (forward secrecy). `false` is
    /// valid when the subscriber left voluntarily and re-subscribes
    /// immediately (key churn avoidance).
    pub rotate_keys: bool,
}

/// Payload for [`BroadcastCommand::PublishBroadcast`]. Boxed for
/// variant-size uniformity — payload `Vec<u8>` may be large.
///
/// # KeyCustody plumbing
///
/// Signing a broadcast envelope needs the caller's
/// [`KeyCustody`](scp_platform::KeyCustody) backend; the trait uses
/// RPITIT and is NOT `dyn`-safe, so it cannot cross the actor mailbox.
/// Instead:
///
/// - The command carries only the
///   [`KeyHandle`](scp_platform::KeyHandle) (an opaque reference that
///   IS `Send + Sync + Clone`).
/// - The custody-generic entry point
///   [`Supervisor::dispatch_broadcast_command_with_custody`](crate::context::supervisor::supervisor::Supervisor::dispatch_broadcast_command_with_custody)
///   drives the two-phase publish path: the actor reserves the
///   sequence via
///   [`broadcast_helpers::reserve_broadcast_publish`](crate::context::broadcast_helpers::reserve_broadcast_publish)
///   and returns the signing-payload digest, the supervisor signs with
///   the caller's custody OUTSIDE the actor, then the actor seals via
///   [`broadcast_helpers::apply_broadcast_publish`](crate::context::broadcast_helpers::apply_broadcast_publish).
/// - Dispatching this variant directly on the actor mailbox is
///   rejected with a typed error pointing at the custody-generic
///   entry point (see `handlers/broadcast.rs`).
pub struct PublishBroadcastPayload {
    /// Context identifier string.
    pub context_id: String,
    /// Author DID (registered in the broadcast context).
    pub author_did: scp_did::DID,
    /// Plaintext payload bytes.
    pub payload: Vec<u8>,
    /// Handle to the author's signing key inside the caller's custody
    /// backend. The key bytes themselves never cross the mailbox — see
    /// the struct-level docs for the custody plumbing contract.
    pub signing_key_handle: scp_platform::KeyHandle,
}

/// Payload for [`BroadcastCommand::PublishBroadcastContent`]. See
/// [`PublishBroadcastPayload`] for the custody plumbing rationale.
pub struct PublishBroadcastContentPayload {
    /// Context identifier string.
    pub context_id: String,
    /// Author DID.
    pub author_did: scp_did::DID,
    /// Structured broadcast content.
    pub content: scp_protocol::context::BroadcastContent,
    /// Handle to the author's signing key inside the caller's custody
    /// backend.
    pub signing_key_handle: scp_platform::KeyHandle,
}

/// Payload for [`BroadcastCommand::ReserveBroadcastPublish`] — phase 1 of
/// the two-phase publish path (ADR-049 §SequenceReservation). Custody-free:
/// the actor reserves the broadcast sequence and returns the signing-payload
/// digest; the caller signs it OUTSIDE the actor and applies the reservation
/// via [`BroadcastCommand::ApplyBroadcastPublish`].
pub struct ReserveBroadcastPublishPayload {
    /// Context identifier string.
    pub context_id: String,
    /// Author DID (registered in the broadcast context).
    pub author_did: scp_did::DID,
}

/// Payload for [`BroadcastCommand::ApplyBroadcastPublish`] — phase 2 of the
/// two-phase publish path. Carries the caller-produced signature plus the
/// reservation id and the plaintext payload. Custody-free: signing already
/// happened outside the actor.
pub struct ApplyBroadcastPublishPayload {
    /// Context identifier string.
    pub context_id: String,
    /// Reservation id returned by phase 1.
    pub reservation_id: crate::context::actor::state::BroadcastReservationId,
    /// Ed25519 signature (64 bytes) over the phase-1 signing payload.
    pub signature: Vec<u8>,
    /// Plaintext payload bytes to seal.
    pub payload: Vec<u8>,
}

/// Payload for [`BroadcastCommand::ReleaseBroadcastReservation`] — abort of
/// a two-phase publish whose apply will never arrive (the caller's signing
/// failed, or the caller is aborting). Releases the reserved sequence so it
/// is not burned. Custody-free.
pub struct ReleaseBroadcastReservationPayload {
    /// Context identifier string.
    pub context_id: String,
    /// Reservation id returned by phase 1.
    pub reservation_id: crate::context::actor::state::BroadcastReservationId,
}

/// Payload for
/// [`BroadcastCommand::BlockBroadcastSubscriber`] and
/// [`BroadcastCommand::UnblockBroadcastSubscriber`]. Boxed for
/// variant-size uniformity.
pub struct BroadcastBlockPayload {
    /// Context identifier string.
    pub context_id: String,
    /// Author DID executing the block/unblock.
    pub author_did: scp_did::DID,
    /// Subscriber DID being blocked/unblocked.
    pub subscriber_did: scp_did::DID,
}

/// See [`ContextCommand::Broadcast`]. Real variants cover every public
/// method on [`crate::context::broadcast_helpers`].
///
/// # Key-custody handoff
///
/// `PublishBroadcast` / `PublishBroadcastContent` each require the
/// caller's [`KeyCustody`](scp_platform::KeyCustody) backend to sign the
/// broadcast envelope — the custody trait uses RPITIT and cannot cross
/// an actor mailbox. The variants store only the
/// [`KeyHandle`](scp_platform::KeyHandle) and are dispatched through
/// the custody-generic
/// [`Supervisor::dispatch_broadcast_command_with_custody`](crate::context::supervisor::supervisor::Supervisor::dispatch_broadcast_command_with_custody),
/// which drives the custody-free two-phase
/// `ReserveBroadcastPublish` / `ApplyBroadcastPublish` mailbox commands
/// and signs with the caller's custody between the two phases, outside
/// the actor.
pub enum BroadcastCommand {
    /// Subscribe a DID to a broadcast context. Mirrors
    /// [`broadcast_helpers::subscribe_broadcast`](crate::context::broadcast_helpers::subscribe_broadcast).
    ///
    /// The validation-context-generic form of that helper carries a
    /// `ValidationContext<'_, D, N, R, P, S>` parameter. The
    /// `handle_subscribe_broadcast` handler builds a REAL `ValidationContext`
    /// from actor-owned state (`KeyResolverDidResolver`,
    /// `ContextRevocationChecker`, an owned snapshot of the per-context proof
    /// store, the context ceiling, and creator DID) and passes `Some(&mut ctx)`,
    /// so a gated context runs the full UCAN validation pipeline on the
    /// presented `messages:read` token (spec §5.14.4, §07:70). The payload's
    /// `ucan` field carries that token — `None` is valid only for an OPEN
    /// context, which the pipeline never invokes.
    SubscribeBroadcast {
        /// Boxed owned payload.
        payload: Box<SubscribeBroadcastPayload>,
        /// Oneshot reply channel. See [`SubscribeBroadcastReply`].
        reply: SubscribeBroadcastReply,
    },

    /// Unsubscribe a DID from a broadcast context. Mirrors
    /// [`broadcast_helpers::unsubscribe_broadcast`](crate::context::broadcast_helpers::unsubscribe_broadcast).
    UnsubscribeBroadcast {
        /// Boxed owned payload.
        payload: Box<UnsubscribeBroadcastPayload>,
        /// Oneshot reply channel. See [`UnsubscribeBroadcastReply`].
        reply: UnsubscribeBroadcastReply,
    },

    /// Publish raw bytes to a broadcast context. Dispatched via the
    /// custody-generic supervisor path, which drives the two-phase
    /// [`broadcast_helpers::reserve_broadcast_publish`](crate::context::broadcast_helpers::reserve_broadcast_publish)
    /// / [`broadcast_helpers::apply_broadcast_publish`](crate::context::broadcast_helpers::apply_broadcast_publish)
    /// pair — see the enum-level key-custody handoff docs.
    PublishBroadcast {
        /// Boxed owned payload.
        payload: Box<PublishBroadcastPayload>,
        /// Oneshot reply channel. See [`PublishBroadcastReply`].
        reply: PublishBroadcastReply,
    },

    /// Publish structured [`BroadcastContent`](scp_protocol::context::broadcast_content::BroadcastContent)
    /// to a broadcast context. Serializes the content, then follows the
    /// same custody-generic two-phase
    /// [`broadcast_helpers::reserve_broadcast_publish`](crate::context::broadcast_helpers::reserve_broadcast_publish)
    /// / [`broadcast_helpers::apply_broadcast_publish`](crate::context::broadcast_helpers::apply_broadcast_publish)
    /// path as [`Self::PublishBroadcast`].
    PublishBroadcastContent {
        /// Boxed owned payload.
        payload: Box<PublishBroadcastContentPayload>,
        /// Oneshot reply channel. See [`PublishBroadcastReply`].
        reply: PublishBroadcastReply,
    },

    /// Phase 1 of the two-phase publish path (ADR-049
    /// §SequenceReservation). Reserve the broadcast sequence and return
    /// the signing-payload digest. Custody-free — the caller signs
    /// outside the actor. Routed through the per-context actor mailbox.
    ReserveBroadcastPublish {
        /// Boxed owned payload.
        payload: Box<ReserveBroadcastPublishPayload>,
        /// Oneshot reply channel. See [`ReserveBroadcastPublishReply`].
        reply: ReserveBroadcastPublishReply,
    },

    /// Phase 2 of the two-phase publish path. Seal the reserved sequence
    /// with the caller-produced signature, emit the event, send on the
    /// transport, and append to the event log. Custody-free. Routed
    /// through the per-context actor mailbox.
    ApplyBroadcastPublish {
        /// Boxed owned payload.
        payload: Box<ApplyBroadcastPublishPayload>,
        /// Oneshot reply channel. See [`PublishBroadcastReply`].
        reply: PublishBroadcastReply,
    },

    /// Abort a two-phase publish whose apply will never arrive (signing
    /// failed, or the caller is aborting). Releases the reserved sequence
    /// so it is not burned. Custody-free. Routed through the per-context
    /// actor mailbox.
    ReleaseBroadcastReservation {
        /// Boxed owned payload.
        payload: Box<ReleaseBroadcastReservationPayload>,
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Block a subscriber from receiving future broadcasts from a
    /// specific author. Mirrors
    /// [`broadcast_helpers::block_broadcast_subscriber`](crate::context::broadcast_helpers::block_broadcast_subscriber).
    BlockBroadcastSubscriber {
        /// Boxed owned payload.
        payload: Box<BroadcastBlockPayload>,
        /// Oneshot reply channel. See [`BlockBroadcastSubscriberReply`].
        reply: BlockBroadcastSubscriberReply,
    },

    /// Unblock a previously blocked subscriber. Mirrors
    /// [`broadcast_helpers::unblock_broadcast_subscriber`](crate::context::broadcast_helpers::unblock_broadcast_subscriber).
    UnblockBroadcastSubscriber {
        /// Boxed owned payload.
        payload: Box<BroadcastBlockPayload>,
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Evaluate a subscriber's broadcast-key request. Mirrors
    /// [`broadcast_helpers::handle_broadcast_key_request`](crate::context::broadcast_helpers::handle_broadcast_key_request).
    ///
    /// Read-mostly (no per-context mutation) — handler reports
    /// `mutated: false`.
    HandleBroadcastKeyRequest {
        /// Context identifier string.
        context_id: String,
        /// Author DID (locally controlled) whose key is being requested.
        author_did: scp_did::DID,
        /// Requester DID.
        requester_did: scp_did::DID,
        /// Requester's X25519 wrapping public key. The broadcast key is
        /// HPKE-sealed to this key inside the protocol handler (§5.14.2) — the
        /// raw key never leaves the protocol layer.
        wrapping_pubkey: [u8; 32],
        /// Oneshot reply channel. See
        /// [`HandleBroadcastKeyRequestReply`].
        reply: HandleBroadcastKeyRequestReply,
    },

    /// Return the subscriber count for a broadcast context. Mirrors
    /// [`broadcast_helpers::broadcast_subscriber_count`](crate::context::broadcast_helpers::broadcast_subscriber_count).
    /// Read-only. `Ok(None)` iff the context is unknown or not broadcast.
    BroadcastSubscriberCount {
        /// Context identifier string.
        context_id: String,
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<Option<usize>, ContextError>>,
    },

    /// Membership predicate — `true` iff `did` is a subscriber. Mirrors
    /// [`broadcast_helpers::is_broadcast_subscriber`](crate::context::broadcast_helpers::is_broadcast_subscriber).
    /// Read-only.
    IsBroadcastSubscriber {
        /// Context identifier string.
        context_id: String,
        /// Candidate subscriber DID.
        did: String,
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<bool, ContextError>>,
    },

    /// Return the broadcast context's admission policy. Mirrors
    /// [`broadcast_helpers::broadcast_admission`](crate::context::broadcast_helpers::broadcast_admission).
    /// Read-only. `Ok(None)` iff the context is unknown or not broadcast.
    BroadcastAdmission {
        /// Context identifier string.
        context_id: String,
        /// Oneshot reply channel. See [`BroadcastAdmissionReply`].
        reply: BroadcastAdmissionReply,
    },
}

/// Reply-channel type alias for
/// [`EconomyCommand::VerifyPaymentReceipts`]. Factored out to satisfy
/// `clippy::type_complexity` given the deep crate-path return type.
pub type VerifyPaymentReceiptsReply = oneshot::Sender<
    Vec<
        Result<
            crate::economy::receipt::ReceiptVerification,
            crate::economy::receipt::ReceiptVerificationError,
        >,
    >,
>;

/// See [`ContextCommand::Economy`]. Real variants land in commit 10 of
/// the ADR-049 commit ladder (see `handlers/economy.rs`). The public
/// surface of [`crate::context::economy_helpers`] currently consists
/// of a single method, [`verify_payment_receipts`](crate::context::economy_helpers::verify_payment_receipts);
/// all other economy methods (`authorize_paid_action`,
/// `complete_paid_action`, `void_paid_action`,
/// `rollback_economy_ticket_inline_view`)
/// are `pub(super)` helpers invoked by the messaging path. Commit 12
/// rewires the sender-side pipeline to construct economy commands
/// internally rather than calling the helpers directly; commit 10
/// lands only the public surface.
pub enum EconomyCommand {
    /// Verifies a batch of payment receipts against the configured
    /// payment adapter. Mirrors
    /// [`economy_helpers::verify_payment_receipts`](crate::context::economy_helpers::verify_payment_receipts).
    ///
    /// Read-only — the handler returns
    /// [`Outcome::ok`](crate::context::actor::Outcome::ok) and reports
    /// `mutated: false`. Verification results come back vector-indexed
    /// with the input receipts; each entry is either a
    /// [`ReceiptVerification`](crate::economy::receipt::ReceiptVerification)
    /// or a
    /// [`ReceiptVerificationError`](crate::economy::receipt::ReceiptVerificationError).
    VerifyPaymentReceipts {
        /// Receipts to verify. Boxed vector so the variant payload stays
        /// pointer-sized.
        receipts: Box<Vec<crate::economy::adapter::PaymentReceipt>>,
        /// Oneshot reply channel. See [`VerifyPaymentReceiptsReply`].
        reply: VerifyPaymentReceiptsReply,
    },
}

/// Payload for [`TrustRecoveryCommand::CreateGovernanceCheckpoint`].
/// Boxed so the variant payload stays pointer-sized — the two 32-byte
/// Merkle/state hashes plus the creator signature push the total over
/// the `large_enum_variant` threshold.
pub struct CreateGovernanceCheckpointPayload {
    /// Context identifier string.
    pub context_id: String,
    /// Checkpoint sequence number (monotonic per context).
    pub checkpoint_seq: u64,
    /// Merkle root of the context event log at checkpoint time.
    pub merkle_root: [u8; 32],
    /// Total event count at checkpoint time.
    pub event_count: u64,
    /// Hash of the last event included in the checkpoint.
    pub last_event_hash: [u8; 32],
    /// Hash of the state snapshot accompanying the checkpoint.
    pub state_snapshot_hash: [u8; 32],
    /// Creator DID.
    pub creator_did: scp_did::DID,
    /// Creator's Ed25519 signature over the canonical checkpoint
    /// bytes (computed outside the handler — passed through verbatim).
    pub creator_signature: Vec<u8>,
}

/// Payload for [`TrustRecoveryCommand::RecoverySendNotification`].
/// Boxed so the outer variant payload stays pointer-sized. Owns the
/// payload bytes and the signing key so the command can cross the
/// actor mailbox without lifetime juggling.
pub struct RecoverySendNotificationPayload {
    /// Context identifier string.
    pub context_id: String,
    /// Sender DID.
    pub sender_did: String,
    /// Opaque recovery-notification payload bytes.
    pub payload: Vec<u8>,
    /// Recovery-step sequence number (0 = MLS epoch advance, 1 = UCAN
    /// revocation, 2 = key-package rotation, 3 = PSK rotation, 4 =
    /// contact notification — see spec §9.12).
    pub sequence: u64,
    /// Sender's Ed25519 signing key. Wrapped in [`SigningKeyBytes`] so
    /// the private key zeroes on drop.
    pub signing_key: SigningKeyBytes,
}

/// Payload for [`TrustRecoveryCommand::RecoveryNotifyContact`]. Boxed
/// for the same reason as [`RecoverySendNotificationPayload`].
pub struct RecoveryNotifyContactPayload {
    /// Recovering DID (the party running the recovery protocol).
    pub recovering_did: String,
    /// Contact DID (the party to notify through a shared context).
    pub contact_did: String,
    /// Opaque recovery-notification payload bytes.
    pub payload: Vec<u8>,
    /// Recovering DID's signing key (zeroized on drop).
    pub signing_key: SigningKeyBytes,
}

/// See [`ContextCommand::TrustRecovery`]. Real variants land in commit
/// 10 of the ADR-049 commit ladder (see `handlers/trust_recovery.rs`).
/// Variants mirror the public surface of
/// [`crate::context::trust_recovery_helpers`] one-to-one: attestation
/// verification, challenge issuance + verification, governance
/// checkpoints + cosignatures, compromise-recovery epoch advance, and
/// recovery notifications (spec §9.12).
pub enum TrustRecoveryCommand {
    /// Creates a governance-aware checkpoint for a context. Mirrors
    /// [`trust_recovery_helpers::create_governance_checkpoint`](crate::context::trust_recovery_helpers::create_governance_checkpoint).
    CreateGovernanceCheckpoint {
        /// Boxed owned payload.
        payload: Box<CreateGovernanceCheckpointPayload>,
        /// Oneshot reply channel.
        reply: oneshot::Sender<
            Result<scp_protocol::context::governance::ContextCheckpoint, ContextError>,
        >,
    },

    /// Adds a cosignature to an existing checkpoint and re-evaluates
    /// attestation status. Mirrors
    /// [`trust_recovery_helpers::add_checkpoint_cosignature`](crate::context::trust_recovery_helpers::add_checkpoint_cosignature).
    ///
    /// The caller supplies a mutable checkpoint (by owned value) and
    /// the cosignature; the handler applies the cosignature on success
    /// and returns both the attestation status and the updated
    /// checkpoint via the reply.
    AddCheckpointCosignature {
        /// Context identifier string.
        context_id: String,
        /// Target checkpoint (boxed — carries the full cosignature
        /// vector plus the Merkle/state hashes).
        checkpoint: Box<scp_protocol::context::governance::ContextCheckpoint>,
        /// Cosignature to add (boxed — wraps an Ed25519 signature +
        /// signer DID).
        cosignature: Box<scp_protocol::context::governance::CosignedCheckpoint>,
        /// Oneshot reply channel. Carries the updated checkpoint and
        /// its new attestation status.
        reply: oneshot::Sender<
            Result<
                (
                    scp_protocol::context::governance::ContextCheckpoint,
                    scp_protocol::context::governance::CheckpointAttestationStatus,
                ),
                ContextError,
            >,
        >,
    },

    /// Advances the MLS epoch for a context as part of compromise
    /// recovery (spec §9.12 step 2). Mirrors
    /// [`trust_recovery_helpers::recovery_advance_epoch`](crate::context::trust_recovery_helpers::recovery_advance_epoch).
    RecoveryAdvanceEpoch {
        /// Context identifier string.
        context_id: String,
        /// Oneshot reply channel. Carries the new epoch number.
        reply: oneshot::Sender<Result<u64, ContextError>>,
    },

    /// Sends a recovery notification directly through a named context
    /// (spec §9.12 step 5 — context already known). Mirrors
    /// [`trust_recovery_helpers::recovery_send_notification`](crate::context::trust_recovery_helpers::recovery_send_notification).
    RecoverySendNotification {
        /// Boxed owned payload (carries the signing key bytes).
        payload: Box<RecoverySendNotificationPayload>,
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Sends a recovery notification to a contact DID by finding a
    /// shared context. Mirrors
    /// [`trust_recovery_helpers::recovery_notify_contact`](crate::context::trust_recovery_helpers::recovery_notify_contact).
    RecoveryNotifyContact {
        /// Boxed owned payload (carries the signing key bytes).
        payload: Box<RecoveryNotifyContactPayload>,
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },
}

/// See [`ContextCommand::Standing`]. Real variants cover the public
/// methods on [`crate::context::standing_helpers`].
pub enum StandingCommand {
    /// Get-or-create a standing bilateral context between two identities
    /// (spec §5.12.6 — contact graph). Mirrors the supervisor's
    /// `Supervisor::standing_context` get-or-create method.
    ///
    /// Idempotent at the underlying-method level — a concurrent call
    /// returning `Active` or `Creating` surfaces the same context ID
    /// without error.
    ///
    /// # Not a saga
    ///
    /// The method internally calls
    /// [`Supervisor::create_context`](crate::context::supervisor::Supervisor::create_context).
    /// Standing-pair creation is single-context async creation (create +
    /// add_member + Welcome + consent-on-receipt; spec §5.15.8) routed
    /// directly through that path — NOT a 2-phase-commit saga FSM.
    StandingContext {
        /// Local identity DID.
        local_did: scp_did::DID,
        /// Remote peer DID.
        peer_did: scp_did::DID,
        /// Oneshot reply channel. `Ok(String)` carries the
        /// deterministic standing context ID; the underlying method
        /// returns the same ID whether the context already existed or
        /// was freshly created.
        reply: oneshot::Sender<Result<String, ContextError>>,
    },

    /// Returns the number of tracked standing contexts. Mirrors
    /// [`standing_helpers::standing_context_count`](crate::context::standing_helpers::standing_context_count).
    /// Read-only.
    StandingContextCount {
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<usize, ContextError>>,
    },

    /// Returns `true` iff a standing context exists for the given peer.
    /// Mirrors
    /// [`standing_helpers::has_standing_context`](crate::context::standing_helpers::has_standing_context).
    /// Read-only.
    HasStandingContext {
        /// Candidate peer DID.
        peer_did: scp_did::DID,
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<bool, ContextError>>,
    },

    /// Registers an existing context as a standing context. Mirrors
    /// [`standing_helpers::register_standing_context`](crate::context::standing_helpers::register_standing_context).
    /// Called during SDK init to restore the contact-graph index from a
    /// persisted snapshot.
    RegisterStandingContext {
        /// Peer DID whose context to register.
        peer_did: scp_did::DID,
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Reconnects transport for every standing context. Mirrors
    /// [`standing_helpers::reconnect_all_standing`](crate::context::standing_helpers::reconnect_all_standing).
    /// Returns the number of contexts that were successfully
    /// reconnected.
    ReconnectAllStanding {
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<usize, ContextError>>,
    },
}

/// Payload for TTL-close variants that carry a
/// [`ContextParams`](scp_protocol::context::params::ContextParams) —
/// specifically [`TtlCloseCommand::StartTtlTimer`],
/// [`TtlCloseCommand::ResetTtlTimer`],
/// [`TtlCloseCommand::ExecuteTtlClose`], and
/// [`TtlCloseCommand::FinalizeClose`]. Boxed inside each variant so
/// the enum's variant sizes stay uniform under
/// `clippy::large_enum_variant`.
pub struct TtlContextPayload {
    /// Context identifier string.
    pub context_id: String,
    /// Context params — used to rebuild the ephemeral handle the
    /// legacy TTL methods accept.
    pub params: scp_protocol::context::params::ContextParams,
}

/// Payload for [`TtlCloseCommand::StartTtlTimer`] and
/// [`TtlCloseCommand::ResetTtlTimer`] — adds a duration to the base
/// [`TtlContextPayload`] shape. Boxed inside the variant for the same
/// reason.
pub struct TtlTimerPayload {
    /// Context identifier string.
    pub context_id: String,
    /// Context params — for `StartTtlTimer` the TTL duration (`params.ttl`)
    /// supplies the convergent `creation + ttl` expiry deadline the handler
    /// falls back to when no explicit `deadline_override` is given.
    pub params: scp_protocol::context::params::ContextParams,
    /// The replacement/additional TTL duration for `ResetTtlTimer` — the agreed
    /// extension added to the EXISTING recorded deadline (`old_deadline +
    /// duration`, §7.3.1 convergent bilateral reset). Ignored by
    /// `StartTtlTimer`, which records an absolute `deadline_override` instead.
    pub duration: std::time::Duration,
    /// Absolute convergent expiry deadline to record for `StartTtlTimer`, as a
    /// [`ConvergentDeadline`](crate::context::ttl_close_helpers::ConvergentDeadline)
    /// — the transient arming-seam newtype, carried in-process across this
    /// (never-serialized) mailbox command, NEVER persisted (B2). `Some(d)`
    /// installs `d` verbatim — the restore/import paths pass the deadline derived
    /// from the SINGLE authoritative source (the event log) via
    /// `convergent_ttl_deadline`, so a prior extension survives and a
    /// `None`-remaining Active snapshot still re-arms (D1/D2). `None` (the
    /// initial-create / spawn-from-Welcome path) defers to the handler's
    /// create-base derivation. Every member computes the identical absolute
    /// deadline, so the `ContextExpired`/`ContextClosed` leaf timestamp is
    /// convergent-by-construction (§7.3.1, §9.9.3). Ignored by `ResetTtlTimer`.
    pub deadline_override: Option<crate::context::ttl_close_helpers::ConvergentDeadline>,
}

/// See [`ContextCommand::TtlClose`]. Real variants land in commit 9 of
/// the ADR-049 commit ladder (see `handlers/ttl_close.rs`). Variants
/// mirror the legacy
/// [`Supervisor`](crate::context::supervisor::Supervisor) TTL
/// surface one-to-one. The handler shim delegates to the legacy method
/// under the hood.
///
/// **TTL timer specifics (ADR-049 finding A3).** The TTL timer is an
/// ACTOR-OWNED `select!` arm in
/// [`ContextActor::run`](crate::context::actor::ContextActor): the arming
/// variants here (`StartTtlTimer` / `ResetTtlTimer` / `ExtendTtl`) record the
/// convergent `state.ttl.timer.deadline_unix_secs`, and the actor's
/// `reconcile_timers` derives a one-shot `sleep` from it and runs the expiry
/// pipeline on wake — no supervisor-spawned timer task.
pub enum TtlCloseCommand {
    // NOTE (ADR-049 Decision-1 / finding A3): the former `FireTimer`
    // variant was retired. TTL expiry is now driven by an ACTOR-OWNED
    // one-shot timer arm — `ContextActor::reconcile_timers` arms a `sleep`
    // against `state.ttl.timer.deadline_unix_secs` and `on_ttl_tick` runs
    // `ttl_close_helpers::handle_ttl_expiry` directly, with no
    // supervisor-driven `task_set` spawn or mailbox tick. The arming
    // variants below (`StartTtlTimer` / `ResetTtlTimer` / `ExtendTtl`)
    // still record the deadline the actor arm reconciles against.
    /// Records the TTL expiry deadline for the given context on actor-owned
    /// state via `ttl_close_helpers::start_ttl_timer` at `create_context` /
    /// `restore_context` time. The actor's `reconcile_timers` re-derives the
    /// one-shot expiry sleep from it.
    ///
    /// `Ok(())` once the deadline has been recorded.
    StartTtlTimer {
        /// Boxed owned payload — see [`TtlTimerPayload`].
        payload: Box<TtlTimerPayload>,
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Proposes a TTL extension on behalf of a specific member. Mirrors
    /// [`propose_ttl_extension`](crate::context::ttl_close_helpers::propose_ttl_extension).
    ///
    /// Reply is `Ok(true)` iff the extension reaches unanimous consent
    /// on this call; the caller then invokes
    /// [`Self::ResetTtlTimer`] with the new duration to install it.
    ///
    /// This variant does NOT carry `ContextParams`, so it is
    /// unboxed — the state mutation happens directly on the registered
    /// context, not through an ephemeral handle.
    ExtendTtl {
        /// Context identifier string.
        context_id: String,
        /// Consenting member DID.
        member_did: scp_did::DID,
        /// Proposed TTL duration.
        proposed_duration: std::time::Duration,
        /// Oneshot reply channel. `Ok(true)` iff unanimous consent was
        /// reached on this call.
        reply: oneshot::Sender<Result<bool, ContextError>>,
    },

    /// Resets the TTL timer to a new duration after a successful
    /// unanimous extension. Mirrors
    /// [`reset_ttl_timer`](crate::context::ttl_close_helpers::reset_ttl_timer).
    ResetTtlTimer {
        /// Boxed owned payload — see [`TtlTimerPayload`].
        payload: Box<TtlTimerPayload>,
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Executes a caller-initiated TTL expiry. Mirrors
    /// [`handle_ttl_expiry`](crate::context::ttl_close_helpers::handle_ttl_expiry).
    ///
    /// This is the EXPLICIT-expiry entry point (an FFI
    /// `context_handle_ttl_expiry` request); the AUTOMATIC path is driven
    /// off the actor-owned TTL timer arm in `ContextActor::run()`
    /// (`on_ttl_tick`), which reconciles a one-shot sleep against the
    /// deadline `StartTtlTimer` records — no supervisor-spawned timer task.
    /// Both paths run the same actor-owned expiry pipeline against the
    /// actor's real state.
    ExecuteTtlClose {
        /// Boxed owned payload — see [`TtlContextPayload`].
        payload: Box<TtlContextPayload>,
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Completes context closure after all members have processed the
    /// `ContextClosing` notification. Mirrors
    /// [`finalize_close`](crate::context::ttl_close_helpers::finalize_close).
    FinalizeClose {
        /// Boxed owned payload — see [`TtlContextPayload`].
        payload: Box<TtlContextPayload>,
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },
}

/// See [`ContextCommand::Outlets`]. Real variants cover every public
/// method on [`crate::context::outlets_helpers`] EXCEPT
/// [`Supervisor::invoke_outlet_with_economy`](crate::context::supervisor::Supervisor::invoke_outlet_with_economy)
/// — that method is the cross-context outlet-invocation entry and carries
/// a generic executor closure `F: FnOnce(Value) -> Fut` which cannot
/// cross the actor mailbox. The cross-context saga itself is wired (§6.2.4,
/// reached via
/// [`Supervisor::start_cross_context_outlet_invocation_saga`](crate::context::supervisor::Supervisor::start_cross_context_outlet_invocation_saga), whose
/// borrowed (non-`'static`) [`SagaSigningKeys`](crate::context::supervisor::SagaSigningKeys)
/// keep it off the `'static` mailbox); what remains
/// deferred is its FFI export, pending per-participant-set saga gating
/// (ADR-049 §3a).
///
/// The migrated variants are the hard-rate-limit consume / refund
/// helpers (async + sync + runtime-agnostic) that FFI bridges call from
/// their own outlet-dispatch paths. All 6 methods on
/// [`crate::context::outlets_helpers`] migrate here because they are the
/// supervisor-observable outlet surface.
pub enum OutletsCommand {
    /// Try to consume one hard-rate-limit token for the given
    /// `(context_id, did)` pair (async variant). Mirrors
    /// [`outlets_helpers::try_consume_hard_rate_limit`](crate::context::outlets_helpers::try_consume_hard_rate_limit).
    ///
    /// Reply carries `Ok(true)` iff a token was consumed or the context
    /// is unknown (pass-through contract on unknown contexts — matches
    /// the legacy method).
    TryConsumeHardRateLimit {
        /// Context identifier string.
        context_id: String,
        /// Sender DID.
        did: scp_did::DID,
        /// Current Unix time in seconds — caller supplies to keep the
        /// handler pure / deterministic.
        now_secs: u64,
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<bool, ContextError>>,
    },

    /// Refund one hard-rate-limit token (async variant). Mirrors
    /// [`outlets_helpers::refund_hard_rate_limit`](crate::context::outlets_helpers::refund_hard_rate_limit).
    /// No-op on unknown context.
    RefundHardRateLimit {
        /// Context identifier string.
        context_id: String,
        /// Sender DID.
        did: scp_did::DID,
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Phase 1 of the outlet economy pipeline — economy reserve on
    /// actor-owned state. Mirrors the first lock phase of the legacy
    /// `invoke_outlet_with_economy`: consume the hard rate limit, record
    /// the velocity entry, run the economy pre-check, deduct budget,
    /// authorize the payment escrow. Replies with a `Send`
    /// [`OutletEconomyReservation`](crate::context::outlets_helpers::OutletEconomyReservation)
    /// that the supervisor carries across the non-`Send` executor.
    ///
    /// See [`crate::context::outlets_helpers::reserve_outlet_economy`].
    ReserveOutletEconomy {
        /// Context identifier string.
        context_id: String,
        /// Invoker DID.
        invoker_did: scp_did::DID,
        /// Optional spending UCAN for paid actions (§19.5). Boxed so the
        /// variant payload stays pointer-sized.
        spending_ucan: Option<Box<scp_protocol::crypto::ucan::UcanToken>>,
        /// §7.3.8 validated-narrowed effective invocation caveats bundled with
        /// the revocation CID (the owned Class-S counter key) of the delegation
        /// that carried them, resolved by the FFI bridge (via
        /// `TokenNbCaveatResolver` + `compute_revocation_cid`) from the ONE
        /// VALIDATED INVOCATION UCAN — the token granting the `outlet_call:*` /
        /// `outlet_query:*` capability, captured at the bridge's
        /// `validate_outlet_invocation_ucan` site. NOT sourced from
        /// `spending_ucan` (a separate §19.5 economy token whose `nb` carries
        /// no invocation caveats). `narrow()` folds every parent's value-caveats
        /// into the leaf, so the leaf `nb` IS the effective narrowed set. The
        /// caveats and CID are bundled into one
        /// [`InvocationCaveatBinding`](crate::context::outlets_helpers::InvocationCaveatBinding)
        /// so "caveats present ⟹ cid present" holds by construction — a
        /// counter-bearing caveat can never reach the gate without its counter
        /// key. The bundle is an internal runtime-API param: the SDK-facing FFI
        /// export signature is unchanged, so an external caller cannot widen the
        /// caveat set without forging the invocation UCAN. `None` when the
        /// invocation UCAN carried no caveats. Boxed to keep the variant payload
        /// pointer-sized.
        caveat_binding: Option<Box<crate::context::outlets_helpers::InvocationCaveatBinding>>,
        /// The invocation input, checked against the caveat's `input_schema`
        /// by the §7.3.8 synchronous local gate. Boxed to keep the variant
        /// payload pointer-sized.
        input: Box<serde_json::Value>,
        /// Current Unix time in seconds — caller supplies to keep the
        /// handler deterministic.
        now_secs: u64,
        /// Oneshot reply channel carrying the Phase-1 reservation.
        reply: oneshot::Sender<
            Result<Box<crate::context::outlets_helpers::OutletEconomyReservation>, ContextError>,
        >,
    },

    /// Phase 3 of the outlet economy pipeline — settle on actor-owned
    /// state. On executor success runs post-invocation bookkeeping +
    /// consequence enforcement + payment capture; on executor failure
    /// voids the escrow and reverses budget / velocity / rate-limit.
    ///
    /// See [`crate::context::outlets_helpers::settle_outlet_economy_capture`]
    /// and [`crate::context::outlets_helpers::rollback_outlet_economy`].
    SettleOutletEconomy {
        /// Context identifier string.
        context_id: String,
        /// Invoker DID.
        invoker_did: scp_did::DID,
        /// Capture-or-rollback request carrying the in-flight ticket.
        /// Boxed so the variant payload stays pointer-sized.
        request: Box<crate::context::outlets_helpers::OutletSettleRequest>,
        /// Oneshot reply channel carrying the Phase-3 settle outcome
        /// (consequences + receipt + committed cost).
        reply: oneshot::Sender<
            Result<crate::context::outlets_helpers::OutletSettleOutcome, ContextError>,
        >,
    },

    /// Streaming open-time economy reserve on actor-owned state — the
    /// streaming-native counterpart of [`Self::ReserveOutletEconomy`].
    /// Consumes the hard rate limit, records the velocity entry, snapshots the
    /// economic policy, allocates the per-sender `base_sequence` (seq-authority
    /// B), and DEBITS the §5.4.5 open-time escrow hold
    /// (`cost_per_chunk × estimated_chunk_count`) under a fail-closed persist.
    /// Replies with a `Send`
    /// [`StreamEconomyReservation`](crate::context::outlets_helpers::StreamEconomyReservation)
    /// the supervisor carries across the off-mailbox stream pump.
    ///
    /// See [`crate::context::outlets_helpers::reserve_outlet_stream_economy`].
    ReserveOutletStreamEconomy {
        /// Context identifier string.
        context_id: String,
        /// Invoker DID.
        invoker_did: scp_did::DID,
        /// Per-Data-chunk cost. `Amount::new(0)` for Query / zero-cost outlets
        /// (short-circuits the escrow debit to a zero hold).
        cost_per_chunk: scp_protocol::economy::types::Amount,
        /// Declared estimated Data-chunk count — the escrow hold multiplier.
        estimated_chunk_count: u32,
        /// Optional §19.5 per-action ceiling AND-folded into the effective
        /// spendable balance when a spending UCAN caps per-action spend.
        max_per_action: Option<scp_protocol::economy::types::Amount>,
        /// Current Unix time in seconds — caller supplies to keep the handler
        /// deterministic.
        now_secs: u64,
        /// Oneshot reply channel carrying the streaming open reservation.
        reply: oneshot::Sender<
            Result<Box<crate::context::outlets_helpers::StreamEconomyReservation>, ContextError>,
        >,
    },

    /// Off-mailbox streaming §7.3.8 value-caveat counter reservation on
    /// actor-owned Class-S state — the streaming-pump counterpart of the
    /// unary `consume_caveat_counters` gate. The stream pump runs
    /// supervisor-side (it holds no `&mut` to actor-owned state) and routes
    /// its open-time per-kind `check_and_increment` back through this command
    /// via [`crate::context::outlets::stream_counter_adapter::ActorClassSCaveatCounterAdapter`].
    ///
    /// The handler runs [`crate::trust::CaveatCounters::try_consume`] against
    /// the owned `ClassSState.caveat_counters` record keyed by `ucan_cid`. An
    /// ADMITTED consume rides a fail-closed `commit_class_s_keep` (durable via
    /// the ADR-049 §9 snapshot); an EXHAUSTED consume mutates nothing and does
    /// NOT persist. The reply's outer `Result` carries the persist / transport
    /// infrastructure outcome; the inner `Result` carries the structured
    /// [`crate::trust::CounterExhausted`] so the pump maps the precise §7.3.8
    /// slug (`maxCalls` / `amountMaxCumulative` / `rateWindow`).
    ReserveStreamCaveatCounter {
        /// Context identifier string.
        context_id: String,
        /// The delegation CID keying the per-UCAN counter record.
        ucan_cid: String,
        /// Which §7.3.8 counter kind to consume.
        kind: scp_protocol::trust::CaveatKind,
        /// Amount to consume (per-kind semantics — ignored for `MaxCalls` /
        /// `RateWindow`, added to the cumulative used for `AmountCumulative`).
        amount: u64,
        /// The counter's cap.
        cap: u64,
        /// Sliding-window length in seconds (`RateWindow` only; `0` otherwise).
        window_secs: u32,
        /// Current Unix time in seconds — the supervisor-side adapter sources
        /// this from the injected clock, keeping the handler deterministic.
        now_secs: u64,
        /// Oneshot reply: outer `Result` = persist/transport infra outcome;
        /// inner `Result` = the structured admission decision.
        reply: oneshot::Sender<Result<Result<(), crate::trust::CounterExhausted>, ContextError>>,
    },

    /// Off-mailbox streaming §7.3.8 value-caveat counter RELEASE on actor-owned
    /// Class-S state — returns the unspent portion of a stream's open-time
    /// reservation to the counter at close-time settlement (SCP R4 HIGH-1), or
    /// rolls back an earlier-kind increment when a later kind rejects the open.
    ///
    /// The handler runs [`crate::trust::CaveatCounters::release`] (infallible /
    /// saturating at `0`) against the owned record keyed by `ucan_cid` under a
    /// fail-closed `commit_class_s_keep`. The reply carries only the persist /
    /// transport infrastructure outcome — release itself never rejects.
    ReleaseStreamCaveatCounter {
        /// Context identifier string.
        context_id: String,
        /// The delegation CID keying the per-UCAN counter record.
        ucan_cid: String,
        /// Which §7.3.8 counter kind to release.
        kind: scp_protocol::trust::CaveatKind,
        /// Amount to return to the counter (saturating at `0`).
        amount: u64,
        /// Oneshot reply carrying the persist / transport infra outcome.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Off-mailbox streaming §5.4.5 open-time escrow REVERSAL on actor-owned
    /// state — the actor-mailbox port of the reference
    /// `ContextManager::outlet_stream_reverse_spend`. Fired by
    /// [`crate::context::outlets::stream_settlement_adapter::ActorEscrowRefundSink`]
    /// from the [`StreamEscrowTicket`](crate::context::outlets::dispatch::StreamEscrowTicket)
    /// Drop-guard when an open-time escrow HOLD was debited against the
    /// invoker's `MemberBudgetTracker` but the pump never spawned (an
    /// early-return between the reserve debit and the spawn).
    ///
    /// The handler runs
    /// [`MemberBudgetTracker::reverse_spend`](scp_protocol::economy::budget::MemberBudgetTracker::reverse_spend)
    /// (infallible / saturating at `0`, so a double-refund — a Drop after an
    /// explicit settlement — is a safe no-op) against the owned budget tracker
    /// under a fail-closed `commit_class_s_keep`. The reply carries only the
    /// persist / transport infrastructure outcome; the refund itself never
    /// rejects.
    ReverseStreamEscrow {
        /// Context identifier string.
        context_id: String,
        /// The invoker whose budget hold is being refunded.
        member_did: scp_did::DID,
        /// The debited hold amount to return (saturating at `0`).
        amount: scp_protocol::economy::types::Amount,
        /// Oneshot reply carrying the persist / transport infra outcome.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Off-mailbox streaming §5.4.5 close-time economic SETTLEMENT on
    /// actor-owned state — the actor-mailbox port of the reference
    /// `ContextManager::outlet_stream_settle`. Fired by
    /// [`crate::context::outlets::stream_settlement_adapter::ActorStreamSettlementSink`]
    /// at stream close (terminal chunk delivered).
    ///
    /// The handler is generation-guarded (confused-deputy protection): if the
    /// reservation's `generation` no longer matches the live actor's
    /// `PerContextState::generation` — the original instance was despawned and a
    /// new one respawned for the same `context_id` between reserve and settle —
    /// it DROPS the settlement silently (touching no state; there is no external
    /// payment escrow to void, unlike the unary settle). On a match it (1)
    /// RELEASES the unspent R4 HIGH-1 cumulative-counter reserve, (2) REFUNDS
    /// the unspent escrow to the invoker's budget tracker, both under one
    /// fail-closed `commit_class_s_keep`, then (3) captures the §19.15.5
    /// `PaymentReceipt` for the exact billed amount off-persist. The no-actor
    /// fallback (context torn down mid-stream) is handled supervisor-side in
    /// [`Supervisor::settle_outlet_stream_via_actor`](crate::context::supervisor::Supervisor::settle_outlet_stream_via_actor)
    /// BEFORE this command is dispatched.
    SettleOutletStream {
        /// The close-time settlement inputs (boxed — the largest
        /// [`OutletsCommand`] payload).
        settlement: Box<crate::context::outlets::invoke::StreamSettlement>,
        /// Spawn-generation the reservation was made against. Compared to the
        /// live actor's `PerContextState::generation`; a mismatch DROPS.
        generation: u64,
        /// Oneshot reply carrying the captured receipt (`None` when nothing was
        /// billed / no adapter / capture failed / dropped on generation
        /// mismatch), or the dispatch / transport infra error.
        reply: oneshot::Sender<
            Result<Option<crate::economy::adapter::PaymentReceipt>, ContextError>,
        >,
    },
}

/// See [`ContextCommand::Queries`]. Pure-read variants — handlers MUST
/// NOT mutate `PerContextState` or any observable state reachable through
/// the view / deps. Each variant carries a typed oneshot reply channel;
/// the dispatch function sends the reply and returns
/// `Outcome { mutated: false }`.
///
/// Commit 7 lands the real read variants. The query handler takes the
/// `&PerContextState` + shared event-log provider directly, with no
/// intervening borrow adapter. Variants that mutate state (`drain_events`, access-key
/// management, `compare_remote_checkpoint`, etc.) are NOT migrated here —
/// they are carried by their own command families
/// (`MessagingCommand::DrainEvents` / `::CompareRemoteCheckpoint`, the
/// `LifecycleCommand` access-key variants) and reach the runtime through
/// the command-dispatch shim. Read-only Merkle proofs (`prove_event_*`)
/// are NOT commands at all: they are served directly by free functions in
/// `queries_helpers` (provider-backed), with no command variant.
pub enum QueriesCommand {
    /// Current lifecycle [`ContextState`](scp_protocol::context::ContextState)
    /// for this actor's context. Read-only — the handler reads the
    /// owned `state.handle` lifecycle field and replies without mutating
    /// any per-context state.
    ///
    /// Used by the standing get-or-create path
    /// ([`Supervisor::read_context_state`](crate::context::supervisor::supervisor::Supervisor))
    /// to distinguish a live (`Active` / `Creating`) context from a
    /// terminal one (`Closed` / `Expired` / …) when deciding whether to
    /// reuse the deterministic standing context id or create a fresh
    /// context. Close / TTL does NOT despawn the per-context actor, so
    /// `Supervisor::lookup(id).is_some()` proves only that an actor
    /// EXISTS — this query is the only way to observe the live-vs-terminal
    /// lifecycle distinction without a `per-context-state Mutex`.
    ///
    /// `Ok(state)` always — the actor only receives this command when it
    /// owns the named context, so the reply is unconditional. Unknown
    /// contexts never reach the actor: the supervisor helper resolves the
    /// no-actor case to `None` before dispatch (no actor → no mailbox →
    /// no reply).
    ReadContextState {
        /// Context identifier string (matches the routing shape of the
        /// other read variants; the actor owns exactly one context so the
        /// id is carried only for routing symmetry).
        context_id: String,
        /// Oneshot reply channel carrying the current lifecycle state.
        reply: oneshot::Sender<Result<scp_protocol::context::ContextState, ContextError>>,
    },
    /// Pseudonym routing ID for the local member (§9.10.4). Read-only.
    /// `Err(NotPseudonymousContext)` for a broadcast context, which carries
    /// no per-member pseudonym.
    LocalPseudonym {
        /// Context identifier string (matches the legacy API).
        context_id: String,
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<[u8; 32], ContextError>>,
    },
    /// Broadcast key + epoch for a locally-controlled author in a
    /// broadcast context. Read-only.
    GetBroadcastKeyForLocalAuthor {
        /// Context identifier string.
        context_id: String,
        /// Author DID to look up.
        author_did: String,
        /// Oneshot reply channel — `Zeroizing<[u8; 32]>` key + epoch.
        /// See [`BroadcastKeyReply`] for the typed alias.
        reply: BroadcastKeyReply,
    },
    /// Current member count for the context.
    MemberCount {
        /// Context identifier string.
        context_id: String,
        /// Oneshot reply channel. `Ok(None)` iff the context is unknown
        /// (matches the `Supervisor::member_count` contract).
        reply: oneshot::Sender<Result<Option<usize>, ContextError>>,
    },
    /// Membership predicate — `true` iff `did` is currently a member.
    IsMember {
        /// Context identifier string.
        context_id: String,
        /// Candidate member DID.
        did: String,
        /// Oneshot reply channel. `Ok(false)` iff the context is
        /// unknown (matches the legacy contract).
        reply: oneshot::Sender<Result<bool, ContextError>>,
    },
    /// All member DIDs for the context.
    MemberDids {
        /// Context identifier string.
        context_id: String,
        /// Oneshot reply channel. Empty vec iff the context is unknown
        /// (matches the legacy contract).
        reply: oneshot::Sender<Result<Vec<String>, ContextError>>,
    },
    /// Role assignment for a specific member.
    MemberRole {
        /// Context identifier string.
        context_id: String,
        /// Member DID.
        did: String,
        /// Oneshot reply channel. `Ok(None)` if the context is unknown
        /// or the member has no assignment.
        reply: oneshot::Sender<
            Result<Option<scp_protocol::context::roles::RoleAssignment>, ContextError>,
        >,
    },
    /// Configured `ContextParams`.
    ContextParams {
        /// Context identifier string.
        context_id: String,
        /// Oneshot reply channel. `Ok(None)` iff the context is unknown.
        reply: oneshot::Sender<
            Result<Option<scp_protocol::context::params::ContextParams>, ContextError>,
        >,
    },
    /// Role state snapshot (cloned).
    GetRoleState {
        /// Context identifier string.
        context_id: String,
        /// Oneshot reply channel. `Ok(None)` iff the context is unknown.
        reply: oneshot::Sender<
            Result<Option<scp_protocol::context::roles::ContextRoleState>, ContextError>,
        >,
    },
    /// Established-interface predicate (spec §6.2.0.1 / §6.2.4 target-side
    /// authorize-before-reserve). `true` iff this actor's context holds a
    /// bidirectionally-approved [`OutletInterface`](scp_protocol::context::outlets::interface::OutletInterface)
    /// whose `source_context` equals `source_context_hex`, `target_context`
    /// equals `target_context_hex`, and `outlet_id` equals `outlet_registration_id`.
    ///
    /// The supervisor consults the CALLER context's actor BEFORE reserving the
    /// `{caller, target}` participant-context set, so a caller cannot name a
    /// victim `target_context_id` it has no established interface with and
    /// thereby wedge the victim's saga slot (spec §6.2.4 "Target-context
    /// binding" rides the §6.2.0.1 standing consent — it does NOT create it).
    HasEstablishedOutletInterface {
        /// Context identifier string (routing; the actor owns exactly one
        /// context).
        context_id: String,
        /// Source (caller) context id, lowercase 64-hex of the raw 32-byte
        /// digest.
        source_context_hex: String,
        /// Target context id, lowercase 64-hex of the raw 32-byte digest.
        target_context_hex: String,
        /// Context-local outlet registration id (indexes the source registry).
        outlet_registration_id: String,
        /// Oneshot reply channel. `Ok(false)` iff the context is unknown or no
        /// matching both-approved interface exists.
        reply: oneshot::Sender<Result<bool, ContextError>>,
    },
    /// Pending MLS Commit retry queue (PR #1606 C6). Cloned vec.
    PendingCommits {
        /// Context identifier string.
        context_id: String,
        /// Oneshot reply channel. Empty vec iff the context is unknown.
        reply: oneshot::Sender<Result<Vec<crate::context::state::PendingCommit>, ContextError>>,
    },
    /// Active commit-fault marker. `Some` iff the context is in
    /// fail-close state (PR #1606 C6).
    CommitFault {
        /// Context identifier string.
        context_id: String,
        /// Oneshot reply channel. `Ok(None)` iff no fault or unknown.
        reply:
            oneshot::Sender<Result<Option<crate::context::state::CommitFaultMarker>, ContextError>>,
    },
    /// Merkle event-log entries for a context (ADR-011). Delegates to
    /// the shared `ContextEventLogProvider` — read-only.
    EventLogEntries {
        /// Canonical 32-byte context ID hash.
        context_id_bytes: [u8; 32],
        /// Oneshot reply channel. `Ok(None)` iff no log exists for the
        /// context.
        reply: oneshot::Sender<Result<Option<Vec<scp_event_log::Event>>, ContextError>>,
    },

    /// Local MLS epoch for the context (§9.12). Read-only.
    ///
    /// `Ok(Some(epoch))` for an encrypted (MLS) context; `Ok(None)` for a
    /// broadcast context, which carries no MLS epoch. Consumed by the
    /// reconnection driver's Phase 2 (`local_epoch`) at the FFI/SDK
    /// relay-client layer (ADR-029 reconnection-driver addendum) — the
    /// driver compares this against the target epoch observed from relay
    /// messages.
    LocalMlsEpoch {
        /// Context identifier string.
        context_id: String,
        /// Oneshot reply channel. `Ok(Some(epoch))` for MLS contexts,
        /// `Ok(None)` for broadcast contexts.
        reply: oneshot::Sender<Result<Option<u64>, ContextError>>,
    },

    /// Whether the context's `EpochState` is flagged `needs_reconnect`
    /// (spec §23.11). Read-only.
    ///
    /// The flag is set when a context's crypto state could not be restored
    /// on respawn (`broadcast_helpers`/`trust_recovery_helpers`). The
    /// reconnection driver consumes it at the FFI/SDK layer to decide which
    /// contexts to drive through the six-phase protocol, and clears it on
    /// success via [`LifecycleCommand::ClearNeedsReconnect`].
    NeedsReconnect {
        /// Context identifier string.
        context_id: String,
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<bool, ContextError>>,
    },
    /// Payment receipts captured in this context (spec §19.11). Read-only.
    ///
    /// Reads the actor-owned `state.payment_receipts` local buffer (NOT the
    /// durable Merkle log — `PaymentReceived` is per-payee, excluded from the
    /// canonical log per ADR-011 amendment exclusion taxonomy §2), applies the
    /// optional [`ReceiptFilter`](crate::economy::receipt::ReceiptFilter), and
    /// replies with the matching receipts. Empty `Vec` iff the context is
    /// unknown (soft default, matching the other read variants).
    PaymentHistory {
        /// Context identifier string.
        context_id: String,
        /// Optional filter (payer / payee / time range). `None` returns all.
        filter: Option<crate::economy::receipt::ReceiptFilter>,
        /// Oneshot reply channel carrying the matching receipts.
        reply: oneshot::Sender<Result<Vec<crate::economy::adapter::PaymentReceipt>, ContextError>>,
    },

    // -------------------------------------------------------------------
    // `#[cfg(feature = "testing")]` accessors. Pure reads.
    // -------------------------------------------------------------------
    /// Per-member access key (testing). `Ok(None)` iff the context is
    /// unknown or no key has been issued for the member.
    #[cfg(feature = "testing")]
    GetAccessKey {
        /// Context identifier string.
        context_id: String,
        /// Member DID.
        member_did: String,
        /// Oneshot reply channel.
        reply: oneshot::Sender<
            Result<Option<scp_protocol::crypto::access_keys::AccessKey>, ContextError>,
        >,
    },
    /// All access keys for a context (testing). Empty map iff the
    /// context is unknown.
    #[cfg(feature = "testing")]
    GetAllAccessKeys {
        /// Context identifier string.
        context_id: String,
        /// Oneshot reply channel.
        reply: oneshot::Sender<
            Result<
                std::collections::HashMap<String, scp_protocol::crypto::access_keys::AccessKey>,
                ContextError,
            >,
        >,
    },
    /// Remaining budget for a member (testing). Returns zero iff the
    /// context is unknown.
    #[cfg(feature = "testing")]
    RemainingBudgetForTest {
        /// Context identifier string.
        context_id: String,
        /// Member DID.
        member_did: scp_did::DID,
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<scp_protocol::economy::types::Amount, ContextError>>,
    },
    /// Velocity count for a member in the antispam window (testing).
    /// Returns zero iff the context is unknown.
    #[cfg(feature = "testing")]
    VelocityForTest {
        /// Context identifier string.
        context_id: String,
        /// Member DID.
        member_did: scp_did::DID,
        /// Current Unix time (seconds) — caller supplies to keep the
        /// handler pure / deterministic.
        now_secs: u64,
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<u64, ContextError>>,
    },
}

// ---------------------------------------------------------------------------
// Saga-phase carrier types (spec §6.2.4)
// ---------------------------------------------------------------------------

/// Output of the Prepare-A handler (spec §6.2.4 "Prepare", caller side).
///
/// Carries the `Send` reservation handles the caller-context actor staged but
/// did NOT apply: the escrow + outbound rate-limit reservation rolled into the
/// existing [`OutletEconomyReservation`](crate::context::outlets_helpers::OutletEconomyReservation).
/// The supervisor FSM (slice 5) holds this across the saga; the
/// [`OutletEconomyReservation`](crate::context::outlets_helpers::OutletEconomyReservation)'s
/// `#[must_use]` drop guard releases the held escrow/rate-limit on every
/// terminal non-commit path (abort, timeout, panic — spec §6.2.4 "Reservation
/// release on every terminal path"). On Commit-A the FSM settles it.
///
/// **Not `Clone` / not `Serialize`.** The reservation is a single-owner RAII
/// carrier — duplicating it would double-release the held ticket.
#[must_use = "a PreparedAFields carries a OutletEconomyReservation that must be settled or released"]
pub struct PreparedAFields {
    /// The staged escrow + outbound rate-limit reservation (RAII release on
    /// not-commit). Produced via the existing
    /// [`reserve_outlet_economy`](crate::context::outlets_helpers::reserve_outlet_economy)
    /// mechanism so Prepare-A reuses the single-context reserve/settle split.
    pub reservation: crate::context::outlets_helpers::OutletEconomyReservation,
}

impl std::fmt::Debug for PreparedAFields {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedAFields")
            .field("reservation", &self.reservation)
            .finish()
    }
}

/// Output of the Prepare-B handler (spec §6.2.4 "Prepare", target side).
///
/// Confirms that the target-context actor staged the eight-field
/// [`CrossContextOutletInvocationPrepared`](crate::context::supervisor::saga_prepared_state::CrossContextOutletInvocationPrepared)
/// into `saga_pending` (with B-recorded `recorded_timestamp_ms` /
/// `recorded_nonce` / `recorded_chain_depth`) and reserved the outlet session,
/// and surfaces the B-captured provenance values the supervisor needs to drive
/// the Commit phase (slice 4) — so the FSM does not have to re-read B's staged
/// slot to learn what B recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedBFields {
    /// B's own wall-clock value captured once at Prepare-B (spec §6.2.4
    /// "Recorded timestamp"). NOT the caller-asserted envelope `timestamp_ms`.
    pub recorded_timestamp_ms: u64,
    /// B's staged copy of the 16-byte wire nonce (spec §6.2.4 "Staged nonce").
    pub recorded_nonce: [u8; 16],
    /// B's re-derived inbound depth = `incoming chain_depth + 1` (spec §6.2.4
    /// "Chain-depth enforcement"). NOT the caller-asserted advisory depth.
    pub recorded_chain_depth: u8,
}

/// Carrier for a §6.2.4 saga POLICY rejection that rides the Prepare-phase
/// SUCCESS channel as typed data.
///
/// The §6.2.4 saga FSM produces canonical `SCP-SAGA-13xxx` reject discriminants.
/// 17 of the 20 Prepare-axis reject sites are raised inside a participant actor
/// and must cross the mailbox; the mailbox `send` reply channel hardcodes
/// `Result<T, ContextError>`, and the boundary lift cannot recover a numeric
/// code from a bare `ContextError` without parsing its message string. To carry
/// the code STRUCTURALLY (the agent-first API tenet — no string parse), a saga
/// POLICY reject is replied as `Ok(PrepareAOutcome::Rejected(SagaReject))` (NOT
/// `Err`), with the canonical discriminant on [`Self::code`].
///
/// The `Err(ContextError)` channel is reserved for codeless mailbox / transport
/// / Class-S-persist failures (a dropped receiver, a Prepare timeout, a journal
/// I/O fault). Those lift to the generic saga-abort code `13067`. Construct a
/// `SagaReject` via the
/// [`saga_reject!`](crate::context::actor::commands::saga_reject) macro so the
/// structural `code` and the `SCP-SAGA-{code}:` message prefix derive from ONE
/// code literal and cannot diverge.
#[derive(Debug)]
pub struct SagaReject {
    /// The canonical `SCP-SAGA-13xxx` discriminant of this reject, set
    /// STRUCTURALLY at the reject site (never parsed from the message). `None`
    /// for a reject that carries no saga code — it lifts to the generic
    /// saga-abort code `13067`.
    pub code: Option<u16>,
    /// The typed [`ContextError`] the reject carries (its `Display` still bears
    /// the canonical `SCP-SAGA-{code}:` prefix so existing message assertions
    /// and flattened log lines continue to disambiguate the terminal).
    pub error: ContextError,
}

/// A bare [`ContextError`] reaching the [`SagaReject`] boundary (a mailbox /
/// commit / journal `?`) carries NO saga code — it is a codeless infrastructure
/// failure, not a §6.2.4 policy reject. It lifts to the generic saga-abort code
/// `13067`. ONLY the `?`-propagated infrastructure paths route through this
/// conversion; every Prepare-axis POLICY reject is built via the
/// [`saga_reject!`](crate::context::actor::commands::saga_reject) macro with an
/// explicit `code`, so a real discriminant is never silently dropped to `None`.
impl From<ContextError> for SagaReject {
    fn from(error: ContextError) -> Self {
        Self { code: None, error }
    }
}

/// Outcome of the Prepare-A handler ([`SagaPhaseMessage::PrepareA`]). Carried on
/// the mailbox SUCCESS channel so a §6.2.4 saga POLICY reject can ride a typed
/// [`SagaReject`] (with its structural `SCP-SAGA-13xxx` code) rather than a bare
/// `Err(ContextError)` whose code would be recoverable only by parsing the
/// message. The `Err(ContextError)` channel carries ONLY codeless mailbox /
/// transport / Class-S-persist failures.
///
/// **Not `Clone`.** [`Self::Prepared`] carries the `#[must_use]`
/// [`PreparedAFields`] RAII reservation carrier.
///
/// The `Prepared` variant is large (it embeds the `OutletEconomyReservation`
/// carrier) while `Rejected` is small — but boxing `Prepared` is the WRONG
/// trade here: the value is created, sent over a `oneshot`, and immediately
/// destructured by the FSM (never stored in a collection or moved in bulk), so
/// the size asymmetry never materializes as a real cost; boxing would instead
/// add a pointless heap allocation + indirection on the hot success path and
/// complicate the `#[must_use]` carrier's move-by-value recovery destructure
/// (the lost-receiver balance path in `prepare_a`). The carrier MUST move by
/// value end-to-end to preserve its single-owner RAII drop-guard contract.
///
/// This is the MAILBOX REPLY PAYLOAD for the Prepare-A handler — distinct from
/// [`outcome::Outcome`](super::outcome::Outcome), the handler's Class-S
/// persistence accounting. Do not conflate the two.
#[allow(clippy::large_enum_variant)]
#[must_use = "a PrepareAOutcome::Prepared carries a OutletEconomyReservation that must be settled or released"]
#[derive(Debug)]
pub enum PrepareAOutcome {
    /// Prepare-A passed: the staged outbound reservation handles.
    Prepared(PreparedAFields),
    /// Prepare-A rejected by a §6.2.4 policy gate (capability, outbound caller,
    /// outbound §6.2.0.2 rate). Carries the structural `SCP-SAGA-13xxx` code.
    Rejected(SagaReject),
}

/// Outcome of the Prepare-B handler ([`SagaPhaseMessage::PrepareB`]). The target
/// side of [`PrepareAOutcome`]: a §6.2.4 policy reject rides a typed
/// [`SagaReject`] on the SUCCESS channel; the `Err(ContextError)` channel
/// carries only codeless mailbox / Class-S-persist failures.
///
/// Like [`PrepareAOutcome`], this is a MAILBOX REPLY PAYLOAD — not
/// [`outcome::Outcome`](super::outcome::Outcome), the handler's Class-S
/// persistence accounting.
#[derive(Debug)]
pub enum PrepareBOutcome {
    /// Prepare-B passed: B's captured provenance the FSM drives Commit with.
    Prepared(PreparedBFields),
    /// Prepare-B rejected by a §6.2.4 policy gate (confused-deputy, inbound
    /// policy, schema, freshness, chain-depth, inbound rate, target binding).
    /// Carries the structural `SCP-SAGA-13xxx` code.
    Rejected(SagaReject),
}

/// Build a [`SagaReject`] for a §6.2.4 Prepare-axis policy rejection from ONE
/// numeric `SCP-SAGA-13xxx` code literal.
///
/// The macro synthesizes BOTH the structural `code: Some($code)` field AND the
/// `SCP-SAGA-{code}: ` message prefix from the SAME `$code`, so a reject site
/// names its discriminant EXACTLY ONCE and the typed field and the formatted
/// string cannot drift apart. The chosen [`ContextError`] variant (per the
/// §6.2.4 reject inventory) is named explicitly so existing message-substring
/// and variant assertions still hold.
///
/// Forms (`$arg`s are positional `{}` substitutions in `$fmt`, exactly as the
/// original `format!` used):
/// - single-`String` tuple variant — the `$variant:ident` arm, used for any
///   `ContextError` variant whose payload is one `String` (`PermissionDenied`,
///   `InvalidState`, `ContextNotRegistered`, …):
///   `saga_reject!(13010, PermissionDenied, "… {}", arg)`
/// - `RateLimited` struct variant (distinct shape — its own arm):
///   `saga_reject!(13023, RateLimited { resource: r, retry_after_ms: ms }, "… {}", arg)`
macro_rules! saga_reject {
    ($code:literal, $variant:ident, $fmt:literal $(, $arg:expr)* $(,)?) => {
        $crate::context::actor::commands::SagaReject {
            code: ::core::option::Option::Some($code),
            error: ::scp_protocol::context::ContextError::$variant(
                ::std::format!(::core::concat!("SCP-SAGA-{}: ", $fmt), $code $(, $arg)*),
            ),
        }
    };
    ($code:literal, RateLimited { resource: $res:expr, retry_after_ms: $rms:expr }, $fmt:literal $(, $arg:expr)* $(,)?) => {
        $crate::context::actor::commands::SagaReject {
            code: ::core::option::Option::Some($code),
            error: ::scp_protocol::context::ContextError::RateLimited {
                resource: $res,
                message: ::std::format!(::core::concat!("SCP-SAGA-{}: ", $fmt), $code $(, $arg)*),
                retry_after_ms: $rms,
            },
        }
    };
}
pub(crate) use saga_reject;

/// Reply payload for [`SagaPhaseMessage::CommitBReserve`] (spec §6.2.4
/// "Commit", split-execution model). The Commit-B phase is two actor
/// round-trips with the non-`Send` outlet executor running supervisor-side in
/// between (the executor cannot cross the mailbox per ADR-049 §3). This is the
/// first round-trip's reply: it tells the supervisor FSM whether to run the
/// executor or short-circuit to the stored output.
///
/// **Not `Serialize` / `Clone`.** The `AlreadyCommitted` payload carries the
/// captured output bytes + the signed receipt; it is consumed once by the FSM.
#[derive(Debug)]
pub enum CommitBReserveOutcome {
    /// The staged prepared + session reservation are present and this
    /// `SagaId`'s `OutletInvoked` has NOT yet been appended. The FSM MUST now run
    /// the outlet executor supervisor-side, capture the output, and call
    /// [`SagaPhaseMessage::CommitBSettle`].
    ReadyToExecute,
    /// Idempotent replay (spec §6.2.4 "Crash recovery §17.16.4"): this
    /// `SagaId`'s `OutletInvoked` was already appended on a prior Commit-B. The
    /// outlet MUST NOT be re-invoked — the stored output + the original signed
    /// receipt are re-emitted verbatim. The FSM skips the executor and treats
    /// this as a Commit-B success.
    AlreadyCommitted {
        /// The original signed receipt bytes (JCS of
        /// [`CrossContextOutletReceipt`](scp_protocol::context::outlets::CrossContextOutletReceipt)).
        receipt: Vec<u8>,
        /// The captured outlet output bytes (the receipt's `output_jcs`).
        output_bytes: Vec<u8>,
        /// The `SagaId`-stable `OutletInvoked` event-log entry id.
        outlet_invoked_event_id: String,
    },
}

/// Reply payload for [`SagaPhaseMessage::CommitBSettle`] (spec §6.2.4
/// "Commit", target side). The second Commit-B round-trip's reply: the signed
/// receipt + the captured output the FSM forwards to Commit-A.
///
/// On a replayed `CommitBSettle` (output already captured for this `SagaId`)
/// the SAME stored bytes are returned — byte-for-byte identical receipt and
/// `outlet_invoked_event_id` — and the outlet is NOT re-invoked.
#[derive(Debug)]
pub struct CommitBSettleOutcome {
    /// The target's signed receipt bytes (JCS of
    /// [`CrossContextOutletReceipt`](scp_protocol::context::outlets::CrossContextOutletReceipt)).
    pub receipt: Vec<u8>,
    /// The captured outlet output bytes the FSM forwards to Commit-A.
    pub output_bytes: Vec<u8>,
    /// The `SagaId`-stable `OutletInvoked` event-log entry id.
    pub outlet_invoked_event_id: String,
}

/// Reply-channel type alias for [`SagaPhaseMessage::CommitBReserve`].
pub type CommitBReserveReply = oneshot::Sender<Result<CommitBReserveOutcome, ContextError>>;

/// Reply-channel type alias for [`SagaPhaseMessage::CommitBSettle`].
pub type CommitBSettleReply = oneshot::Sender<Result<CommitBSettleOutcome, ContextError>>;

/// See [`ContextCommand::SagaPhase`]. The per-phase messages the supervisor
/// FSM dispatches to a participant actor for a cross-context outlet-invocation
/// saga (spec §6.2.4). Each variant carries a typed `oneshot` reply.
///
/// Every arm has a real handler body AND is driven end-to-end by the supervisor
/// FSM: Prepare-A / Prepare-B, the split Commit
/// ([`Self::CommitBReserve`] / [`Self::CommitBSettle`] / [`Self::CommitA`]),
/// [`Self::Abort`], and [`Self::EmitDivergenceMarker`] are all dispatched by
/// `start_cross_context_outlet_invocation_saga`'s FSM over the two co-resident
/// participant actors. The dispatch `match` stays exhaustive so adding a phase
/// is a compile error.
#[non_exhaustive]
pub enum SagaPhaseMessage {
    /// Prepare-A — runs on the LOCAL caller-context actor. Validates the
    /// caller holds `outlet:interface` and is in `OutboundPolicy.allowed_callers`,
    /// stages (not applies) the outbound rate-limit decrement + escrow
    /// reservation of the outlet's REGISTERED per-invocation cost (resolved from
    /// the caller's economy policy / outlet registry by
    /// [`reserve_outlet_economy`](crate::context::outlets_helpers::reserve_outlet_economy),
    /// NOT any caller-asserted value), persists Class-S fail-closed, and replies
    /// the `Send` reservation handles.
    PrepareA {
        /// Durable saga identifier (the `xctx_caller_reservations` key). The
        /// caller-side Prepare-A stages a durable reversal record under this id
        /// so a `PreparingB`-window crash recovery (`Abort { None }`, keyed by
        /// the same `SagaId`) can reverse the reservation without the in-memory
        /// carrier (spec §6.2.4 "Reservation release on every terminal path").
        saga_id: crate::context::supervisor::saga_journal::SagaId,
        /// Caller context id (raw 32-byte digest) — the actor's own context.
        caller_context_id: [u8; 32],
        /// Caller DID — the channel-authenticated initiator (spec §6.2.4
        /// "Caller authentication"; the supervisor binds this, not the
        /// envelope).
        caller_did: scp_did::DID,
        /// Context-local outlet registration id being invoked at the target.
        outlet_registration_id: String,
        /// Oneshot reply channel. A §6.2.4 policy reject rides
        /// `Ok(PrepareAOutcome::Rejected(SagaReject))` (carrying the structural
        /// `SCP-SAGA-13xxx` code); the `Err(ContextError)` channel carries only
        /// codeless mailbox / Class-S-persist failures.
        reply: oneshot::Sender<Result<PrepareAOutcome, ContextError>>,
    },
    /// Prepare-B — runs on the LOCAL target-context actor. Resolves the UCAN
    /// proof and re-runs §7 validation re-bound to `caller_did` +
    /// `outlet_registration_id` (confused-deputy defense), validates inbound
    /// policy / schema-specificity floor / target-context binding / freshness /
    /// chain-depth, captures B-controlled provenance, stages the eight-field
    /// prepared into `saga_pending`, persists Class-S fail-closed, and replies.
    PrepareB {
        /// Durable saga identifier (the `saga_pending` key).
        saga_id: crate::context::supervisor::saga_journal::SagaId,
        /// Caller context id (raw 32-byte digest).
        caller_context_id: [u8; 32],
        /// Target context id (raw 32-byte digest) — MUST equal B's own context
        /// (spec §6.2.4 "Target-context binding").
        target_context_id: [u8; 32],
        /// Channel-authenticated caller DID (spec §6.2.4 "Caller
        /// authentication"). The confused-deputy re-bind audience.
        caller_did: scp_did::DID,
        /// Context-local outlet registration id (indexes B's own registry).
        outlet_registration_id: String,
        /// UCAN proof reference — an INDEX into B's own UCAN store, never the
        /// proof bytes (spec §6.2.4 normative (1)). `None` for an ungated outlet.
        ucan_proof_id: Option<String>,
        /// The invocation input — validated against the outlet's registered
        /// schema specificity floor (spec §9.2.1); never journaled.
        input: serde_json::Value,
        /// Caller-asserted chain depth — advisory/untrusted; used only for the
        /// `>= max_chain_depth` reject and as the `+1` base for B's re-derived
        /// `recorded_chain_depth` (spec §6.2.4 "Chain-depth enforcement").
        asserted_chain_depth: u8,
        /// Caller-asserted 16-byte envelope nonce — checked against B's TTL
        /// dedup cache, then staged on accept (spec §6.2.4 "Freshness").
        asserted_nonce: [u8; 16],
        /// Caller-asserted send-time (ms) — used ONLY for the §9.14 skew
        /// freshness check, never recorded (spec §6.2.4 "Recorded timestamp").
        asserted_timestamp_ms: u64,
        /// The channel-authenticated caller's ROLE in the caller context,
        /// resolved supervisor-side at initiation (NOT envelope-asserted). B
        /// enforces `InboundPolicy.allowed_source_roles` against this real role
        /// (spec §6.2.4 "Caller authentication" + InboundPolicy "source role").
        /// `None` ⇒ no explicit role assignment.
        caller_source_role: Option<String>,
        /// Oneshot reply channel. A §6.2.4 policy reject rides
        /// `Ok(PrepareBOutcome::Rejected(SagaReject))` (carrying the structural
        /// `SCP-SAGA-13xxx` code); the `Err(ContextError)` channel carries only
        /// codeless mailbox / Class-S-persist failures.
        reply: oneshot::Sender<Result<PrepareBOutcome, ContextError>>,
    },
    /// Commit-B (reserve half) — runs on the LOCAL target-context actor. The
    /// FIRST of the two Commit-B round-trips (spec §6.2.4 "Commit", split per
    /// ADR-049 §3: the non-`Send` executor cannot cross the mailbox, so it runs
    /// supervisor-side BETWEEN this reserve and the [`Self::CommitBSettle`]).
    ///
    /// Confirms the staged prepared + session reservation are present for this
    /// `SagaId`. Idempotency (§6.2.4 / §17.16.4): if this `SagaId`'s output was
    /// already captured (a replayed Commit), it replies
    /// [`CommitBReserveOutcome::AlreadyCommitted`] with the STORED output +
    /// receipt + event id and the FSM skips the executor — the outlet is NEVER
    /// re-invoked. Otherwise it replies [`CommitBReserveOutcome::ReadyToExecute`]
    /// and the FSM runs the executor, then calls [`Self::CommitBSettle`].
    ///
    /// Read-only — performs no mutation, so no Class-S persist here.
    CommitBReserve {
        /// Durable saga identifier (the `saga_pending` key).
        saga_id: crate::context::supervisor::saga_journal::SagaId,
        /// Oneshot reply channel. See [`CommitBReserveReply`].
        reply: CommitBReserveReply,
    },
    /// Commit-B (settle half) — runs on the LOCAL target-context actor. The
    /// SECOND of the two Commit-B round-trips (spec §6.2.4 "Commit", target
    /// side), called by the FSM with the executor's captured output.
    ///
    /// Durably captures the output keyed by `SagaId` (so a later replay
    /// re-emits it), `SagaId`-idempotently appends `OutletInvoked` → a stable
    /// `outlet_invoked_event_id`, signs the
    /// [`CrossContextOutletReceipt`](scp_protocol::context::outlets::CrossContextOutletReceipt)
    /// over the
    /// staged `recorded_nonce` / `recorded_chain_depth` / `recorded_timestamp_ms`
    /// plus `output_hash` plus the event id using `target_signing_key`, Class-S
    /// sync-persists fail-closed, and replies the receipt + output bytes. A
    /// replayed `CommitBSettle` (output already captured) re-emits the stored
    /// bytes verbatim and does NOT re-append or re-sign.
    CommitBSettle {
        /// Durable saga identifier.
        saga_id: crate::context::supervisor::saga_journal::SagaId,
        /// The outlet executor's captured output bytes (the FSM ran the executor
        /// supervisor-side between reserve and settle). Hashed into the
        /// receipt's `output_hash` and carried as the receipt's JCS output.
        output_bytes: Vec<u8>,
        /// The target context's Active Signing Key (§6.2.4 receipt signing).
        /// The actor holds NO signing key (ADR-049): the FSM resolves the key
        /// authorized for `target_context_id` and passes it per-call, exactly
        /// like [`MessagingCommand::SendHeartbeat`] /
        /// [`MessagingCommand::BuildLocalCheckpoint`]. Zeroizes on drop.
        target_signing_key: SigningKeyBytes,
        /// Oneshot reply channel. See [`CommitBSettleReply`].
        reply: CommitBSettleReply,
    },
    /// Commit-A — runs on the LOCAL caller-context actor. Settles the escrow
    /// reservation (§19.2.2), applies the staged outbound rate-limit decrement,
    /// and records `CrossContextOutletInvoked` referencing the target ctx id + the
    /// same `nonce` (spec §6.2.4 "Commit", caller side / "Dual event-log
    /// recording"). Class-S sync-persists fail-closed. Idempotent by `SagaId`:
    /// a replay re-acks without re-settling or re-appending.
    CommitA {
        /// Durable saga identifier.
        saga_id: crate::context::supervisor::saga_journal::SagaId,
        /// The caller-side escrow + outbound-rate-limit reservation staged at
        /// Prepare-A and held by the FSM across the saga. Commit-A settles
        /// (captures) it. Boxed to keep the variant size uniform under
        /// `clippy::large_enum_variant`. The `#[must_use]` carrier's drop guard
        /// releases on every terminal non-commit path; Commit-A consumes it.
        reservation: Box<PreparedAFields>,
        /// Caller context id (raw 32-byte digest) — the actor's own context;
        /// the `CrossContextOutletInvoked` actor field.
        caller_context_id: [u8; 32],
        /// Caller DID — the channel-authenticated initiator (the event actor).
        caller_did: scp_did::DID,
        /// Target context id (raw 32-byte digest) — referenced by the
        /// `CrossContextOutletInvoked` record so an auditor can join it to B's log.
        target_context_id: [u8; 32],
        /// The 16-byte correlation nonce — the SAME nonce B staged into
        /// `OutletInvoked`; the join key between the two records (§6.2.4 "Dual
        /// event-log recording").
        nonce: [u8; 16],
        /// The target's signed receipt bytes captured at Commit-B.
        receipt: Vec<u8>,
        /// The target's captured outlet output bytes.
        output_bytes: Vec<u8>,
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },
    /// Commit-A witness check — runs on the LOCAL caller-context actor. READ-ONLY
    /// (no mutation, no Class-S persist): reports whether this `SagaId` is already
    /// recorded in `xctx_committed_invocations` (the durable Commit-A idempotency
    /// witness). The FSM uses it to re-drive a Commit-A whose reply was lost AFTER
    /// the handler durably committed: the held Prepare-A reservation is gone (the
    /// command was delivered, the actor consumed the ticket), so a retry cannot
    /// re-send `CommitA` — but the witness lets the FSM resolve the saga to
    /// `Committed` instead of a spurious `NeedsRepair` (spec §17.16.4 "A re-acks
    /// its `CrossContextOutletInvoked` … as a no-op"; the witness IS that re-ack).
    CommitACheckWitness {
        /// Durable saga identifier (the `xctx_committed_invocations` key).
        saga_id: crate::context::supervisor::saga_journal::SagaId,
        /// Oneshot reply: `true` iff Commit-A is durably recorded for this saga.
        reply: oneshot::Sender<Result<bool, ContextError>>,
    },
    /// Abort — runs on EITHER side's local actor. RAII-releases the staged
    /// reservations (escrow / outbound-RL on A — carried back via
    /// `reservation`; outlet-session on B — the staged `saga_pending` slot), clears
    /// the saga slot, Class-S sync-persists fail-closed, and acks. Idempotent
    /// no-op if the saga is already terminal (slot absent and no reservation).
    Abort {
        /// Durable saga identifier.
        saga_id: crate::context::supervisor::saga_journal::SagaId,
        /// On the CALLER (A) side, the staged escrow + outbound-RL reservation
        /// the FSM holds, handed back so Abort can RAII-release it (rollback
        /// path). `None` on the TARGET (B) side, whose staged reservation lives
        /// in `saga_pending` (the outlet-session reservation is released by
        /// clearing the slot — B stages no `OutletEconomyTicket` at Prepare-B).
        /// Boxed under `clippy::large_enum_variant`.
        reservation: Option<Box<PreparedAFields>>,
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },
    /// Emit a signed `CrossContextDivergenceMarker` on a `NeedsRepair`
    /// outcome (spec §6.2.4 "Dual event-log recording") into the LOCAL event
    /// log. Used by the FSM (slice 6) when the two sides diverge. The actor
    /// holds no key, so the emitting side's Active Signing Key is passed
    /// per-call.
    EmitDivergenceMarker {
        /// Durable saga identifier.
        saga_id: crate::context::supervisor::saga_journal::SagaId,
        /// The 16-byte correlation nonce joining the two event-log records.
        nonce: [u8; 16],
        /// Which side committed (caller or target).
        committed_side: scp_protocol::context::outlets::cross_context_saga::CommittedSide,
        /// The committed-side event id.
        committed_event_id: String,
        /// CONVERGENT committer-assigned leaf timestamp (seconds) for the
        /// divergence-marker leaf: B's staged `recorded_timestamp_ms / 1000` —
        /// the same convergent instant the committed-side `OutletInvoked` leaf
        /// carries (spec §6.2.4 *Recorded timestamp*). Passed per-call so the
        /// marker leaf is byte-identical across honest members (§9.9.3), never a
        /// per-member actor-local clock read.
        committed_timestamp_secs: u64,
        /// The local (emitting) side's Active Signing Key. The actor holds no
        /// key (ADR-049); the FSM passes the key authorized for this context
        /// per-call. Zeroizes on drop.
        signing_key: SigningKeyBytes,
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },
}

/// See [`ContextCommand::LifecycleControl`]. The supervisor's suspend /
/// resume / shutdown path sends these; real variants land with the
/// BridgeInstance integration in commit 11. Commit 6 only carries the
/// two Pause / PersistSync variants that the
/// `BridgeInstanceCore` (in `scp_ffi_common::bridge_instance`)'s
/// default `suspend()` body calls, plus the terminal `Shutdown`.
pub enum LifecycleControlCommand {
    /// Supervisor asks the actor to quiesce: refuse new external
    /// commands but continue processing the current dispatch and any
    /// in-flight persists. The actor replies once the current dispatch
    /// finishes.
    Pause {
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },
    /// Supervisor asks the actor to synchronously flush its coalesced
    /// persist buffer. The actor replies once the snapshot write has
    /// durably completed.
    PersistSync {
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },
    /// Terminal command — the actor's dispatch loop exits after
    /// processing. `biased;` ordering in the `select!` guarantees this
    /// variant is dispatched before any timer or persistence arm fires
    /// on the same poll.
    Shutdown {
        /// Oneshot reply channel. The actor sends `Ok(())` after its
        /// final persist completes.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },
    /// Test-only fault-injection seam (ADR-049 §10 watchdog tests). The
    /// actor's dispatch loop turns this into a `panic!(sentinel)` so the
    /// supervisor watchdog's crash/poison/respawn + payload-redaction paths
    /// can be exercised deterministically. Gated behind the `testing`
    /// feature so it never exists in a production build, and handled in the
    /// actor's `dispatch_state` (in `actor/mod.rs`) — NOT in any
    /// `handlers/*.rs` module, so the handler panic-ban gate stays green.
    #[cfg(feature = "testing")]
    TestInducePanic {
        /// Sentinel string interpolated into the induced panic message. A
        /// security test asserts this sentinel NEVER appears in the
        /// watchdog's log output (the payload is intentionally discarded).
        sentinel: String,
    },
    /// Terminal command — the supervisor asks this actor to make way for
    /// an imported context with the same id. Running on its own owned
    /// `PerContextState`, the actor checks it is replaceable (lifecycle
    /// state `Closing | Closed | Expired | Tombstoned` — NEVER overwrite
    /// a live context), then atomically captures, tears down, restores,
    /// and validate/merges the per-sender MLS epoch floors (§23.17 Inv
    /// 3/4) against the incoming crypto bytes. On success it transitions
    /// its own lifecycle to a terminal claim and the dispatch loop exits,
    /// so the supervisor can despawn it and spawn the imported state.
    /// Because each actor processes one command at a time, this is the
    /// serialization point the legacy `write_lock`-guarded import gate
    /// provided.
    PrepareForReplace {
        /// The incoming export's MLS crypto bytes (empty = no incoming
        /// crypto state) — the only handler-side payload import needs.
        mls_state: Vec<u8>,
        /// `Ok(())` iff the context was replaceable AND crypto teardown +
        /// epoch-floor validate/merge succeeded. On failure the actor stays
        /// live (no terminal claim) and surfaces the reason: `MembershipFailed`
        /// (live / already-claimed by a prior `PrepareForReplace`),
        /// `SnapshotFloorRegression` (the §23.17 replay-guard rejection — a
        /// per-sender epoch floor regressed; the import caller MUST propagate
        /// it, never route it to a recovery/re-restore path), or
        /// `PersistenceFailed` (`restore_crypto_state` failed). The
        /// supervisor-side `dispatch_prepare_for_replace` additionally maps a
        /// dropped reply / unreachable actor to `ContextNotRegistered` — the
        /// ONLY error the import caller treats as a stale-handle retry.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

impl ContextCommand {
    /// Internal: whether this variant is the terminal
    /// [`LifecycleControlCommand::Shutdown`]. Used by the actor's
    /// dispatch loop to decide when to exit after dispatching.
    #[must_use]
    pub const fn is_shutdown(&self) -> bool {
        matches!(
            self,
            Self::LifecycleControl(LifecycleControlCommand::Shutdown { .. })
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_variant_is_shutdown() {
        let (tx, _rx) = oneshot::channel();
        let cmd = ContextCommand::LifecycleControl(LifecycleControlCommand::Shutdown { reply: tx });
        assert!(cmd.is_shutdown());
    }

    #[test]
    fn non_shutdown_variants_are_not_shutdown() {
        let (tx, _rx) = oneshot::channel();
        let cmd = ContextCommand::LifecycleControl(LifecycleControlCommand::Pause { reply: tx });
        assert!(!cmd.is_shutdown());

        let (tx, _rx) = oneshot::channel();
        let cmd = ContextCommand::Queries(QueriesCommand::MemberCount {
            context_id: "ctx".to_owned(),
            reply: tx,
        });
        assert!(!cmd.is_shutdown());
    }
}
