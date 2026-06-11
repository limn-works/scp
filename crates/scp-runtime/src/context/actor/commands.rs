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
//! # Minimal variant surface (this commit)
//!
//! Commit 6 lands the enum SHAPE. Each sub-enum carries one or two
//! placeholder variants whose handlers return
//! `ContextError::NotImplemented(..)` via
//! [`Outcome::err`](crate::context::actor::Outcome::err). Commits 7-11
//! extend each sub-enum with real variants as the corresponding handler
//! migrates off the legacy `ContextManager`; the dispatch loop shape is
//! stable from this commit forward.
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

/// Reply-channel type alias for
/// [`MessagingCommand::DeliverIncoming`]. The reply carries either
/// `Some((plaintext, sender_did))` for application messages, or `None`
/// for MLS control / management messages that were processed
/// internally. Factored out to satisfy `clippy::type_complexity`.
pub type DeliverIncomingReply = oneshot::Sender<Result<Option<(Vec<u8>, String)>, ContextError>>;

/// Reply-channel type alias for [`MessagingCommand::DrainEvents`]. The
/// reply carries the drained `ContextEvent` vector — empty iff the
/// context is unknown (matches the legacy
/// [`ContextManager::drain_events`](crate::context::supervisor::Supervisor::drain_events)
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
    /// Standing — saga initiator for standing-pair creation
    /// (spec §5.15.7).
    Standing(StandingCommand),
    /// TTL close — timer-driven close path (spec §5.8).
    TtlClose(TtlCloseCommand),
    /// Tools — saga initiator for cross-context tool invocation
    /// (spec §5.16).
    Tools(ToolsCommand),
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
// Placeholder sub-enums
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
    pub sender_did: scp_identity::DID,
    /// Plaintext payload to encrypt and send.
    pub payload: Vec<u8>,
    /// Sender's Ed25519 signing key. `None` is rejected by the
    /// encrypted path — the inner envelope cannot be signed without
    /// it. Wrapped in [`SigningKeyBytes`] so the private key bytes
    /// zeroize on drop.
    pub signing_key: Option<SigningKeyBytes>,
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
/// management messages all stay on the legacy `ContextManager` surface
/// until commits 10-11 per the plan row-6 scope.
pub enum MessagingCommand {
    /// Placeholder — reserved for Phase 2 actor-mailbox wiring of
    /// ADR-049 (post-review-round-1 plan). Used by the actor's
    /// `run()` skeleton dispatch as a no-op handshake target so the
    /// mailbox machinery exercises end-to-end without a real
    /// command. Handler replies
    /// [`ContextError::NotImplemented`](scp_protocol::context::ContextError::NotImplemented)
    /// and returns `Outcome::err`.
    Placeholder {
        /// Oneshot reply channel. Handler stub sends
        /// `Err(ContextError::NotImplemented(..))` back.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Encrypts and transmits a message within an active context.
    ///
    /// Mirrors the legacy
    /// [`ContextManager::send_message`](crate::context::supervisor::Supervisor::send_message)
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

    /// Decrypts an incoming envelope from the relay and delivers the
    /// plaintext + sender DID (or records a control-message side effect
    /// and returns `None`).
    ///
    /// Mirrors the legacy
    /// [`ContextManager::deliver_incoming`](crate::context::messaging_helpers::deliver_incoming)
    /// signature. Used by every FFI bridge's relay subscription loop;
    /// the return type matches the bridge's per-event dispatch pattern.
    ///
    /// # Reply
    ///
    /// `Ok(Some((plaintext, sender_did)))` — application message; caller
    /// should forward to the language binding's receive channel.
    /// `Ok(None)` — MLS Commit / Proposal / management message; processed
    /// internally, no plaintext to surface.
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
    /// [`ContextManager::drain_events`](crate::context::supervisor::Supervisor::drain_events)
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

    /// Send the local member's pseudonym announcement (§9.10.4) to the
    /// other members of a context.
    ///
    /// Mirrors the legacy
    /// [`ContextManager::send_pseudonym_announcement`](crate::context::messaging_helpers::send_pseudonym_announcement)
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
        member_did: scp_identity::DID,
        /// The peer's per-context pseudonym routing ID.
        pseudonym: [u8; 32],
        /// Oneshot reply channel. Replies `Ok(())` once the registry is
        /// updated, or `Err` if the context is broadcast-routed.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Record that a received envelope triggered degraded-mode (spec
    /// §13.6) for a context. Emits a `DegradedMode` event into the
    /// per-context receive buffer (and the supervisor's optional event
    /// broadcast channel).
    ///
    /// Mirrors the legacy
    /// [`ContextManager::report_degraded_mode`](crate::context::supervisor::Supervisor::report_degraded_mode)
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
}

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
    pub sender_did: scp_identity::DID,
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
    /// Context identifier (plain string; the legacy
    /// `ContextManager::create_context` derives the 32-byte hash
    /// internally).
    pub context_id: String,
    /// Creation-time parameters — governance model, ceiling, TTL,
    /// economic policy, etc.
    pub params: scp_protocol::context::params::ContextParams,
    /// Creator's DID. Becomes the sole `admin` assignment in the
    /// initial `ContextRoleState`.
    pub creator_did: scp_identity::DID,
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
    pub caller_did: scp_identity::DID,
    /// Target DID (the member to remove; may equal `caller_did`).
    pub member_did: scp_identity::DID,
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
    pub initiator_did: scp_identity::DID,
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
/// **Create-as-prepare.** `CreateContext` / `JoinContext` are legitimate
/// saga entry points in later commits (standing-pair creation,
/// migration). Commit 9 routes them through
/// [`ContextManager::create_context`](crate::context::supervisor::Supervisor::create_context)
/// / [`ContextManager::join_context`](crate::context::supervisor::Supervisor::join_context)
/// directly; saga wiring moves into this enum in commit 11.
pub enum LifecycleCommand {
    /// Placeholder — reserved for Phase 2 actor-mailbox wiring of
    /// ADR-049 (post-review-round-1 plan). Used by the actor's
    /// `run()` skeleton dispatch as a no-op handshake target so the
    /// mailbox machinery exercises end-to-end without a real
    /// command. Handler replies
    /// [`ContextError::NotImplemented`](scp_protocol::context::ContextError::NotImplemented)
    /// and returns `Outcome::err`.
    Placeholder {
        /// Oneshot reply channel. Handler stub sends
        /// `Err(ContextError::NotImplemented(..))` back.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Creates a new MLS-backed (or broadcast-mode) context. Mirrors
    /// [`ContextManager::create_context`](crate::context::supervisor::Supervisor::create_context).
    ///
    /// Saga-compatible: the same variant carries the
    /// `create_context`-for-standing-pair-prepare flow in commit 11; for
    /// commit 9 the handler goes straight through the legacy method.
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
    /// [`ContextManager::join_context`](crate::context::supervisor::Supervisor::join_context).
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
    /// [`ContextManager::leave_context`](crate::context::supervisor::Supervisor::leave_context).
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
    /// [`ContextManager::close_context`](crate::context::lifecycle_helpers::close_context)
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
        exporter_did: scp_identity::DID,
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
    /// [`ContextManager::restore_context`](crate::context::supervisor::Supervisor::restore_context).
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
    /// [`ContextManager::generate_context_access_key`](crate::context::queries_helpers::generate_context_access_key).
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
    /// [`ContextManager::revoke_context_access_key`](crate::context::queries_helpers::revoke_context_access_key).
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
    /// [`ContextManager::restore_context_access_key`](crate::context::queries_helpers::restore_context_access_key).
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
    /// `contexts` DashMap and took a per-context lock with
    /// [`FLUSH_LOCK_BUDGET`](crate::context::lifecycle_helpers::FLUSH_LOCK_BUDGET)).
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
    /// Read-only: the handler returns an [`Outcome`] with `mutated =
    /// false`.
    ReportBufferLen {
        /// Oneshot reply channel carrying this actor's receive-buffer
        /// length.
        reply: oneshot::Sender<usize>,
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
/// sub-structs like tool interfaces or ceiling modifications).
pub struct ProposeGovernanceActionPayload {
    /// Context identifier string.
    pub context_id: String,
    /// Proposer DID.
    pub proposer_did: scp_identity::DID,
    /// Typed governance action — one of the 28 variants from ADR-031.
    pub action: scp_protocol::context::governance::GovernanceAction,
    /// Proposer's Ed25519 signing key. Wrapped in [`SigningKeyBytes`]
    /// so the private key zeroes on drop (mirrors the messaging path's
    /// command-level zeroize contract).
    pub signing_key: SigningKeyBytes,
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
    pub voter_did: scp_identity::DID,
    /// Voter's Ed25519 signing key (zeroized on drop via
    /// [`SigningKeyBytes`]).
    pub signing_key: SigningKeyBytes,
}

/// Payload for [`GovernanceCommand::ExecuteGovernanceAction`]. Boxed
/// because [`scp_protocol::context::governance::GovernanceProposal`]
/// carries a complete
/// [`GovernanceAction`](scp_protocol::context::governance::GovernanceAction)
/// plus signatures; together the struct is well over the
/// `large_enum_variant` threshold.
pub struct ExecuteGovernanceActionPayload {
    /// Context identifier string.
    pub context_id: String,
    /// Fully-validated governance proposal (status ==
    /// [`ProposalStatus::Approved`](scp_protocol::context::governance::ProposalStatus)).
    pub proposal: scp_protocol::context::governance::GovernanceProposal,
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
    /// Placeholder — reserved for Phase 2 actor-mailbox wiring of
    /// ADR-049 (post-review-round-1 plan). Used as a no-op
    /// handshake target by mailbox tests so the end-to-end dispatch
    /// pipe is exercised without a real command. Handler replies
    /// [`ContextError::NotImplemented`](scp_protocol::context::ContextError::NotImplemented).
    Placeholder {
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Submits a governance proposal — unchecked variant. Mirrors
    /// [`ContextManager::propose_governance_action`](crate::context::supervisor::Supervisor::propose_governance_action).
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
    /// [`ContextManager::propose_governance_action_checked`](crate::context::supervisor::Supervisor::propose_governance_action_checked).
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
    /// [`ContextManager::vote_on_proposal`](crate::context::supervisor::Supervisor::vote_on_proposal).
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
    /// Mirrors [`ContextManager::approve_governance_proposal`](crate::context::governance_helpers::approve_governance_proposal).
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
    /// Mirrors [`ContextManager::reject_governance_proposal`](crate::context::governance_helpers::reject_governance_proposal).
    RejectGovernanceProposal {
        /// Boxed owned payload.
        payload: Box<VoteOnProposalPayload>,
        /// Oneshot reply channel.
        reply: oneshot::Sender<
            Result<scp_protocol::context::governance::ProposalStatus, ContextError>,
        >,
    },

    /// Withdraws a previously cast vote. Mirrors
    /// [`ContextManager::withdraw_governance_vote`](crate::context::supervisor::Supervisor::withdraw_governance_vote).
    /// No signing key — withdrawal is the voter's privileged operation
    /// on their own vote per the governance engine's trait contract.
    WithdrawGovernanceVote {
        /// Context identifier string.
        context_id: String,
        /// Target proposal ID (32 bytes).
        proposal_id: scp_protocol::context::governance::ProposalId,
        /// Voter DID.
        voter_did: scp_identity::DID,
        /// Oneshot reply channel.
        reply: oneshot::Sender<
            Result<scp_protocol::context::governance::ProposalStatus, ContextError>,
        >,
    },

    /// Executes an already-approved governance proposal. Mirrors
    /// [`ContextManager::execute_governance_action`](crate::context::governance_helpers::execute_governance_action).
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
    /// [`ContextManager::get_proposal`](crate::context::supervisor::Supervisor::get_proposal).
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
    /// [`ContextManager::list_proposals`](crate::context::supervisor::Supervisor::list_proposals).
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
    /// [`ContextManager::apply_pending_ceiling_modification`](crate::context::governance_helpers::apply_pending_ceiling_modification).
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
    /// [`ContextManager::apply_pending_economic_policy_change`](crate::context::governance_helpers::apply_pending_economic_policy_change).
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
    /// [`ContextManager::tombstone_migrated_context`](crate::context::governance_helpers::tombstone_migrated_context).
    TombstoneMigratedContext {
        /// Context identifier string.
        context_id: String,
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Returns the migration state for a context if one exists. Mirrors
    /// [`ContextManager::migration_state`](crate::context::governance_helpers::migration_state).
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
    /// [`ContextManager::acknowledge_commit_fault`](crate::context::governance_helpers::acknowledge_commit_fault).
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

    /// Sweep: run one tick of the governance timeout / consequence
    /// pipeline for THIS actor's context. Mirrors the per-context body of
    /// `start_governance_timeout_task_legacy` (Phase 1 through Phase 5).
    ///
    /// Dispatched per-actor by the supervisor's iterating sweep entry
    /// point
    /// [`governance_helpers::start_governance_timeout_task`](crate::context::governance_helpers::start_governance_timeout_task)
    /// which still owns timer spawn (the per-actor governance-timeout
    /// task lands in Phase 2B per ADR-049). For now, the spawn-time
    /// closure dispatches this command on each tick instead of
    /// reaching into the supervisor's `contexts` DashMap directly.
    ///
    /// Reply carries `Ok(continue_loop)` — `true` to keep ticking,
    /// `false` to stop (context closing or removed). Matches the
    /// legacy timer closure's `bool` return.
    EvaluateTimeouts {
        /// Oneshot reply channel. `Ok(true)` continues the timer loop;
        /// `Ok(false)` stops it.
        reply: oneshot::Sender<Result<bool, ContextError>>,
    },

    /// Install (or reinstall) THIS actor's governance-timeout interval
    /// task on actor-owned state.
    ///
    /// The handler spawns the 60-second interval loop onto the
    /// supervisor's tracked `task_set` via
    /// [`SupervisorHandle::tracked_spawn`](crate::context::supervisor::handle::SupervisorHandle::tracked_spawn)
    /// and stores its cancel `Notify` + `AbortHandle` on
    /// `state.governance.timeout_task`. On each wake the task resolves
    /// the owning actor through
    /// [`SupervisorHandle::lookup`](crate::context::supervisor::handle::SupervisorHandle::lookup)
    /// and mailboxes [`Self::EvaluateTimeouts`] — no `&Supervisor` /
    /// `contexts` DashMap reach, no stale-generation gate.
    ///
    /// Dispatched by the lifecycle bootstrap paths (`finalize_create`,
    /// `restore_context`, `import_context`) after actor spawn, since
    /// those hold only `&ActorDeps` (no `&mut state`).
    StartTimeoutTask {
        /// Oneshot reply channel. `Ok(())` once the interval task is
        /// installed.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },
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
    pub subscriber_did: scp_identity::DID,
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
    pub subscriber_did: scp_identity::DID,
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
/// The legacy
/// [`ContextManager::publish_broadcast`](crate::context::broadcast_helpers::publish_broadcast)
/// takes a `custody: &impl KeyCustody + &KeyHandle` pair; the
/// [`KeyCustody`](scp_platform::KeyCustody) trait uses RPITIT and is
/// NOT `dyn`-safe, so it cannot cross the actor mailbox. Instead:
///
/// - The command carries only the
///   [`KeyHandle`](scp_platform::KeyHandle) (an opaque reference that
///   IS `Send + Sync + Clone`).
/// - The shim-dispatch entry point
///   [`Supervisor::dispatch_broadcast_command`](crate::context::supervisor::supervisor::Supervisor::dispatch_broadcast_command)
///   is generic over the concrete custody type, and the shim extracts
///   the `KeyHandle` from the command and passes both to
///   [`ContextManager::publish_broadcast`](crate::context::broadcast_helpers::publish_broadcast).
/// - For the post-refactor actor loop (commit 12+), the custody is
///   available via the actor's bridge-instance reference; the actor
///   body resolves the custody from the instance and signs inline.
pub struct PublishBroadcastPayload {
    /// Context identifier string.
    pub context_id: String,
    /// Author DID (registered in the broadcast context).
    pub author_did: scp_identity::DID,
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
    pub author_did: scp_identity::DID,
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
    pub author_did: scp_identity::DID,
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
    pub author_did: scp_identity::DID,
    /// Subscriber DID being blocked/unblocked.
    pub subscriber_did: scp_identity::DID,
}

/// See [`ContextCommand::Broadcast`]. Real variants cover every public
/// method on [`crate::context::broadcast_helpers`] that is NOT the
/// saga-wired broadcast-hosting handshake. The handshake is spec-gapped
/// — see `.docs/adrs/DEFERRED-commit-11-saga-use-cases.md`.
///
/// # Key-custody handoff
///
/// `PublishBroadcast` / `PublishBroadcastContent` each require the
/// caller's [`KeyCustody`](scp_platform::KeyCustody) backend to sign the
/// broadcast envelope — the custody trait uses RPITIT and cannot cross
/// an actor mailbox. For commit 11 the non-saga variants store only the
/// [`KeyHandle`](scp_platform::KeyHandle); the handler reaches back to
/// the attached [`Supervisor`](crate::context::supervisor::Supervisor)
/// for the custody reference, matching the bridge-level wiring the
/// legacy method uses today.
pub enum BroadcastCommand {
    /// Placeholder — reserved for Phase 2 actor-mailbox wiring of
    /// ADR-049 (post-review-round-1 plan). Used as a no-op
    /// handshake target by mailbox tests so the end-to-end dispatch
    /// pipe is exercised without a real command. Handler replies
    /// [`ContextError::NotImplemented`](scp_protocol::context::ContextError::NotImplemented).
    Placeholder {
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Subscribe a DID to a broadcast context. Mirrors
    /// [`ContextManager::subscribe_broadcast`](crate::context::broadcast_helpers::subscribe_broadcast).
    ///
    /// The validation-context-generic variant on `ContextManager` carries
    /// a `ValidationContext<'_, D, N, R, P, S>` parameter; the actor
    /// command surface passes `None` for that slot to match the default
    /// unvalidated path. Gated contexts with a UCAN still route through
    /// the UCAN token's inline validation.
    SubscribeBroadcast {
        /// Boxed owned payload.
        payload: Box<SubscribeBroadcastPayload>,
        /// Oneshot reply channel. See [`SubscribeBroadcastReply`].
        reply: SubscribeBroadcastReply,
    },

    /// Unsubscribe a DID from a broadcast context. Mirrors
    /// [`ContextManager::unsubscribe_broadcast`](crate::context::broadcast_helpers::unsubscribe_broadcast).
    UnsubscribeBroadcast {
        /// Boxed owned payload.
        payload: Box<UnsubscribeBroadcastPayload>,
        /// Oneshot reply channel. See [`UnsubscribeBroadcastReply`].
        reply: UnsubscribeBroadcastReply,
    },

    /// Publish raw bytes to a broadcast context. Mirrors
    /// [`ContextManager::publish_broadcast`](crate::context::broadcast_helpers::publish_broadcast).
    PublishBroadcast {
        /// Boxed owned payload.
        payload: Box<PublishBroadcastPayload>,
        /// Oneshot reply channel. See [`PublishBroadcastReply`].
        reply: PublishBroadcastReply,
    },

    /// Publish structured [`BroadcastContent`](scp_protocol::context::broadcast_content::BroadcastContent)
    /// to a broadcast context. Mirrors
    /// [`ContextManager::publish_broadcast_content`](crate::context::broadcast_helpers::publish_broadcast_content).
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
    /// [`ContextManager::block_broadcast_subscriber`](crate::context::broadcast_helpers::block_broadcast_subscriber).
    BlockBroadcastSubscriber {
        /// Boxed owned payload.
        payload: Box<BroadcastBlockPayload>,
        /// Oneshot reply channel. See [`BlockBroadcastSubscriberReply`].
        reply: BlockBroadcastSubscriberReply,
    },

    /// Unblock a previously blocked subscriber. Mirrors
    /// [`ContextManager::unblock_broadcast_subscriber`](crate::context::broadcast_helpers::unblock_broadcast_subscriber).
    UnblockBroadcastSubscriber {
        /// Boxed owned payload.
        payload: Box<BroadcastBlockPayload>,
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Evaluate a subscriber's broadcast-key request. Mirrors
    /// [`ContextManager::handle_broadcast_key_request`](crate::context::broadcast_helpers::handle_broadcast_key_request).
    ///
    /// Read-mostly (no per-context mutation) — handler reports
    /// `mutated: false`.
    HandleBroadcastKeyRequest {
        /// Context identifier string.
        context_id: String,
        /// Author DID (locally controlled) whose key is being requested.
        author_did: scp_identity::DID,
        /// Requester DID.
        requester_did: scp_identity::DID,
        /// Oneshot reply channel. See
        /// [`HandleBroadcastKeyRequestReply`].
        reply: HandleBroadcastKeyRequestReply,
    },

    /// Return the subscriber count for a broadcast context. Mirrors
    /// [`ContextManager::broadcast_subscriber_count`](crate::context::broadcast_helpers::broadcast_subscriber_count).
    /// Read-only. `Ok(None)` iff the context is unknown or not broadcast.
    BroadcastSubscriberCount {
        /// Context identifier string.
        context_id: String,
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<Option<usize>, ContextError>>,
    },

    /// Membership predicate — `true` iff `did` is a subscriber. Mirrors
    /// [`ContextManager::is_broadcast_subscriber`](crate::context::broadcast_helpers::is_broadcast_subscriber).
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
    /// [`ContextManager::broadcast_admission`](crate::context::broadcast_helpers::broadcast_admission).
    /// Read-only. `Ok(None)` iff the context is unknown or not broadcast.
    BroadcastAdmission {
        /// Context identifier string.
        context_id: String,
        /// Oneshot reply channel. See [`BroadcastAdmissionReply`].
        reply: BroadcastAdmissionReply,
    },

    /// Saga-initiator path for the broadcast-hosting handshake. Returns
    /// [`ContextError::NotImplemented`] in commit 11 — the handshake
    /// protocol (subscriber-to-host key exchange, host config negotiation,
    /// §5.14.2 step 4 transport) is spec-gapped. See
    /// `.docs/adrs/DEFERRED-commit-11-saga-use-cases.md`.
    InitiateBroadcastHostingHandshake {
        /// Host context ID (32-byte hash).
        host_context_id: [u8; 32],
        /// Broadcast context ID (32-byte hash).
        broadcast_context_id: [u8; 32],
        /// Subscriber DID requesting hosting.
        subscriber_did: scp_identity::DID,
        /// Oneshot reply channel. Carries the saga's durable ID on
        /// success; `ContextError::NotImplemented` during the deferred
        /// window.
        reply:
            oneshot::Sender<Result<crate::context::supervisor::saga_journal::SagaId, ContextError>>,
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
/// `rollback_economy_ticket_inline`)
/// are `pub(super)` helpers invoked by the messaging path. Commit 12
/// rewires the sender-side pipeline to construct economy commands
/// internally rather than calling the helpers directly; commit 10
/// lands only the public surface.
pub enum EconomyCommand {
    /// Placeholder — reserved for Phase 2 actor-mailbox wiring of
    /// ADR-049 (post-review-round-1 plan). Used as a no-op
    /// handshake target by mailbox tests so the end-to-end dispatch
    /// pipe is exercised without a real command. Handler replies
    /// [`ContextError::NotImplemented`](scp_protocol::context::ContextError::NotImplemented).
    Placeholder {
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Verifies a batch of payment receipts against the configured
    /// payment adapter. Mirrors
    /// [`ContextManager::verify_payment_receipts`](crate::context::economy_helpers::verify_payment_receipts).
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
    pub creator_did: scp_identity::DID,
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
    /// Placeholder — reserved for Phase 2 actor-mailbox wiring of
    /// ADR-049 (post-review-round-1 plan). Used as a no-op
    /// handshake target by mailbox tests so the end-to-end dispatch
    /// pipe is exercised without a real command. Handler replies
    /// [`ContextError::NotImplemented`](scp_protocol::context::ContextError::NotImplemented).
    Placeholder {
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Creates a governance-aware checkpoint for a context. Mirrors
    /// [`ContextManager::create_governance_checkpoint`](crate::context::trust_recovery_helpers::create_governance_checkpoint).
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
    /// [`ContextManager::add_checkpoint_cosignature`](crate::context::trust_recovery_helpers::add_checkpoint_cosignature).
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
    /// [`ContextManager::recovery_advance_epoch`](crate::context::trust_recovery_helpers::recovery_advance_epoch).
    RecoveryAdvanceEpoch {
        /// Context identifier string.
        context_id: String,
        /// Oneshot reply channel. Carries the new epoch number.
        reply: oneshot::Sender<Result<u64, ContextError>>,
    },

    /// Sends a recovery notification directly through a named context
    /// (spec §9.12 step 5 — context already known). Mirrors
    /// [`ContextManager::recovery_send_notification`](crate::context::trust_recovery_helpers::recovery_send_notification).
    RecoverySendNotification {
        /// Boxed owned payload (carries the signing key bytes).
        payload: Box<RecoverySendNotificationPayload>,
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Sends a recovery notification to a contact DID by finding a
    /// shared context. Mirrors
    /// [`ContextManager::recovery_notify_contact`](crate::context::trust_recovery_helpers::recovery_notify_contact).
    RecoveryNotifyContact {
        /// Boxed owned payload (carries the signing key bytes).
        payload: Box<RecoveryNotifyContactPayload>,
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },
}

/// See [`ContextCommand::Standing`]. Real variants cover every public
/// method on [`crate::context::standing_helpers`] that is NOT the
/// saga-wired standing-pair-create initiator path. The saga path is
/// spec-gapped — see
/// `.docs/adrs/DEFERRED-commit-11-saga-use-cases.md`.
pub enum StandingCommand {
    /// Placeholder — reserved for Phase 2 actor-mailbox wiring of
    /// ADR-049 (post-review-round-1 plan). Used as a no-op
    /// handshake target by mailbox tests so the end-to-end dispatch
    /// pipe is exercised without a real command. Handler replies
    /// [`ContextError::NotImplemented`](scp_protocol::context::ContextError::NotImplemented).
    Placeholder {
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Get-or-create a standing bilateral context between two identities
    /// (spec §5.12.4 — contact graph). Mirrors
    /// [`ContextManager::standing_context`](crate::context::standing_helpers::standing_context).
    ///
    /// Idempotent at the legacy-method level — a concurrent call
    /// returning `Active` or `Creating` surfaces the same context ID
    /// without error.
    ///
    /// # Saga scope
    ///
    /// The legacy method internally calls
    /// [`ContextManager::create_context`](crate::context::supervisor::Supervisor::create_context).
    /// Commit 11 routes through that legacy path directly — the
    /// standing-pair-create saga FSM (Prepare+Commit 2-phase) is
    /// deferred per
    /// `.docs/adrs/DEFERRED-commit-11-saga-use-cases.md`.
    StandingContext {
        /// Local identity DID.
        local_did: scp_identity::DID,
        /// Remote peer DID.
        peer_did: scp_identity::DID,
        /// Oneshot reply channel. `Ok(String)` carries the
        /// deterministic standing context ID; the legacy method returns
        /// the same ID whether the context already existed or was
        /// freshly created.
        reply: oneshot::Sender<Result<String, ContextError>>,
    },

    /// Returns the number of tracked standing contexts. Mirrors
    /// [`ContextManager::standing_context_count`](crate::context::standing_helpers::standing_context_count).
    /// Read-only.
    StandingContextCount {
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<usize, ContextError>>,
    },

    /// Returns `true` iff a standing context exists for the given peer.
    /// Mirrors
    /// [`ContextManager::has_standing_context`](crate::context::standing_helpers::has_standing_context).
    /// Read-only.
    HasStandingContext {
        /// Candidate peer DID.
        peer_did: scp_identity::DID,
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<bool, ContextError>>,
    },

    /// Registers an existing context as a standing context. Mirrors
    /// [`ContextManager::register_standing_context`](crate::context::standing_helpers::register_standing_context).
    /// Called during SDK init to restore the contact-graph index from a
    /// persisted snapshot.
    RegisterStandingContext {
        /// Peer DID whose context to register.
        peer_did: scp_identity::DID,
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Reconnects transport for every standing context. Mirrors
    /// [`ContextManager::reconnect_all_standing`](crate::context::standing_helpers::reconnect_all_standing).
    /// Returns the number of contexts that were successfully
    /// reconnected.
    ReconnectAllStanding {
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<usize, ContextError>>,
    },

    /// Saga-initiator path for standing-pair creation. Returns
    /// [`ContextError::NotImplemented`] in commit 11 — the 2-phase
    /// Prepare+Commit decomposition is spec-gapped. See
    /// `.docs/adrs/DEFERRED-commit-11-saga-use-cases.md`.
    InitiateStandingPairCreate {
        /// Local identity DID initiating the pair.
        local_did: scp_identity::DID,
        /// Remote peer DID.
        peer_did: scp_identity::DID,
        /// Oneshot reply channel. Carries the saga's durable ID on
        /// success; `ContextError::NotImplemented` during the deferred
        /// window.
        reply:
            oneshot::Sender<Result<crate::context::supervisor::saga_journal::SagaId, ContextError>>,
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
    /// Context params — used to rebuild the ephemeral handle that
    /// the timer task will pass to `run_ttl_expiry_with_retries`.
    pub params: scp_protocol::context::params::ContextParams,
    /// TTL duration. Fires relative to the dispatcher's clock for
    /// `StartTtlTimer`; the replacement duration for
    /// `ResetTtlTimer`.
    pub duration: std::time::Duration,
}

/// See [`ContextCommand::TtlClose`]. Real variants land in commit 9 of
/// the ADR-049 commit ladder (see `handlers/ttl_close.rs`). Variants
/// mirror the legacy
/// [`Supervisor`](crate::context::supervisor::Supervisor) TTL
/// surface one-to-one. The handler shim delegates to the legacy method
/// under the hood.
///
/// **TTL timer specifics (commit 9 scope).** The post-refactor
/// architecture turns the TTL timer into a `select!` arm in
/// [`ContextActor::run`](crate::context::actor::ContextActor). Commit 9
/// keeps the timer spawned from the legacy
/// [`Supervisor`](crate::context::supervisor::Supervisor) internals
/// (`spawn_ttl_timer`); the handler variants here respond to
/// caller-initiated TTL commands (extend, finalize, explicit expiry)
/// synchronously. Full timer-owning actor logic migrates with plan row
/// 11.
pub enum TtlCloseCommand {
    /// Placeholder — reserved for Phase 2 actor-mailbox wiring of
    /// ADR-049 (post-review-round-1 plan). Used by the actor's
    /// `run()` skeleton dispatch as a no-op handshake target so the
    /// mailbox machinery exercises end-to-end without a real
    /// command. Handler replies
    /// [`ContextError::NotImplemented`](scp_protocol::context::ContextError::NotImplemented)
    /// and returns `Outcome::err`.
    Placeholder {
        /// Oneshot reply channel. Handler stub sends
        /// `Err(ContextError::NotImplemented(..))` back.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Fires a single TTL tick on THIS actor: evaluate whether the
    /// context's TTL has elapsed and, if so, run the close pipeline on the
    /// actor-owned state.
    ///
    /// Sent by the per-context TTL timer task (spawned at
    /// `create_context` / `restore_context` time) on each wake. The task
    /// holds no `&Supervisor` and reads no DashMap; it resolves the actor
    /// via [`Supervisor::lookup`](crate::context::supervisor::Supervisor::lookup)
    /// (lock-free registry) and mailboxes this command. A `lookup → None`
    /// (actor gone) replaces the legacy stale-generation gate: the timer
    /// task stops when the context's actor no longer exists.
    ///
    /// Replaces the legacy `spawn_ttl_timer_legacy` task that probed
    /// `contexts_arc.get(ctx).generation` for the stale-gen gate and held
    /// the supervisor's `task_set` (ADR-049 Phase 2A finalization — DashMap
    /// removal). The handler operates on the actor's owned `&mut state`.
    FireTimer {
        /// Oneshot reply channel. `Ok(true)` iff the timer should keep
        /// running (context still open); `Ok(false)` once the close
        /// pipeline has fired so the task can exit.
        reply: oneshot::Sender<Result<bool, ContextError>>,
    },

    /// Spawns (or respawns) the TTL timer for the given context with a
    /// caller-supplied duration. Installed on actor-owned state by
    /// `ttl_close_helpers::spawn_ttl_timer` at `create_context` /
    /// `restore_context` time.
    ///
    /// `Ok(())` once the timer has been successfully installed.
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
        member_did: scp_identity::DID,
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
    /// In commit 9 this is the explicit-expiry entry point; the timer
    /// task spawned by `StartTtlTimer` still runs the automatic path
    /// internally. Commit 11 converges both paths onto the actor's
    /// `select!` arm.
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

/// See [`ContextCommand::Tools`]. Real variants cover every public
/// method on [`crate::context::tools_helpers`] EXCEPT
/// [`ContextManager::invoke_tool_with_economy`](crate::context::supervisor::Supervisor::invoke_tool_with_economy)
/// — that method is the cross-context tool-invocation entry and carries
/// a generic executor closure `F: FnOnce(Value) -> Fut` which cannot
/// cross the actor mailbox. The cross-context saga path is spec-gapped
/// regardless; see
/// `.docs/adrs/DEFERRED-commit-11-saga-use-cases.md`.
///
/// The migrated variants are the hard-rate-limit consume / refund
/// helpers (async + sync + runtime-agnostic) that FFI bridges call from
/// their own tool-dispatch paths. All 6 methods on
/// [`crate::context::tools_helpers`] migrate here because they are the
/// supervisor-observable tool surface.
pub enum ToolsCommand {
    /// Placeholder — reserved for Phase 2 actor-mailbox wiring of
    /// ADR-049 (post-review-round-1 plan). Used as a no-op
    /// handshake target by mailbox tests so the end-to-end dispatch
    /// pipe is exercised without a real command. Handler replies
    /// [`ContextError::NotImplemented`](scp_protocol::context::ContextError::NotImplemented).
    Placeholder {
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Try to consume one hard-rate-limit token for the given
    /// `(context_id, did)` pair (async variant). Mirrors
    /// [`ContextManager::try_consume_hard_rate_limit`](crate::context::tools_helpers::try_consume_hard_rate_limit).
    ///
    /// Reply carries `Ok(true)` iff a token was consumed or the context
    /// is unknown (pass-through contract on unknown contexts — matches
    /// the legacy method).
    TryConsumeHardRateLimit {
        /// Context identifier string.
        context_id: String,
        /// Sender DID.
        did: scp_identity::DID,
        /// Current Unix time in seconds — caller supplies to keep the
        /// handler pure / deterministic.
        now_secs: u64,
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<bool, ContextError>>,
    },

    /// Refund one hard-rate-limit token (async variant). Mirrors
    /// [`ContextManager::refund_hard_rate_limit`](crate::context::tools_helpers::refund_hard_rate_limit).
    /// No-op on unknown context.
    RefundHardRateLimit {
        /// Context identifier string.
        context_id: String,
        /// Sender DID.
        did: scp_identity::DID,
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Phase 1 of the tool economy pipeline — economy reserve on
    /// actor-owned state. Mirrors the first lock phase of the legacy
    /// `invoke_tool_with_economy`: consume the hard rate limit, record
    /// the velocity entry, run the economy pre-check, deduct budget,
    /// authorize the payment escrow. Replies with a `Send`
    /// [`ToolEconomyReservation`](crate::context::tools_helpers::ToolEconomyReservation)
    /// that the supervisor carries across the non-`Send` executor.
    ///
    /// See [`crate::context::tools_helpers::reserve_tool_economy`].
    ReserveToolEconomy {
        /// Context identifier string.
        context_id: String,
        /// Invoker DID.
        invoker_did: scp_identity::DID,
        /// Optional spending UCAN for paid actions (§19.5). Boxed so the
        /// variant payload stays pointer-sized.
        spending_ucan: Option<Box<scp_protocol::crypto::ucan::UcanToken>>,
        /// Current Unix time in seconds — caller supplies to keep the
        /// handler deterministic.
        now_secs: u64,
        /// Oneshot reply channel carrying the Phase-1 reservation.
        reply: oneshot::Sender<
            Result<Box<crate::context::tools_helpers::ToolEconomyReservation>, ContextError>,
        >,
    },

    /// Phase 3 of the tool economy pipeline — settle on actor-owned
    /// state. On executor success runs post-invocation bookkeeping +
    /// consequence enforcement + payment capture; on executor failure
    /// voids the escrow and reverses budget / velocity / rate-limit.
    ///
    /// See [`crate::context::tools_helpers::settle_tool_economy_capture`]
    /// and [`crate::context::tools_helpers::rollback_tool_economy`].
    SettleToolEconomy {
        /// Context identifier string.
        context_id: String,
        /// Invoker DID.
        invoker_did: scp_identity::DID,
        /// Capture-or-rollback request carrying the in-flight ticket.
        /// Boxed so the variant payload stays pointer-sized.
        request: Box<crate::context::tools_helpers::ToolSettleRequest>,
        /// Oneshot reply channel carrying the Phase-3 settle outcome
        /// (consequences + receipt + committed cost).
        reply:
            oneshot::Sender<Result<crate::context::tools_helpers::ToolSettleOutcome, ContextError>>,
    },

    /// Saga-initiator path for cross-context tool invocation. Returns
    /// [`ContextError::NotImplemented`] in commit 11 — the cross-context
    /// invoke transport protocol (caller→target context forwarding,
    /// UCAN proof plumbing, receipt relay) is spec-gapped. See
    /// `.docs/adrs/DEFERRED-commit-11-saga-use-cases.md`.
    InitiateCrossContextToolInvocation {
        /// Calling context ID (32-byte hash).
        caller_context_id: [u8; 32],
        /// Calling DID.
        caller_did: scp_identity::DID,
        /// Target tool registration ID.
        tool_registration_id: String,
        /// Oneshot reply channel. Carries the saga's durable ID on
        /// success; `ContextError::NotImplemented` during the deferred
        /// window.
        reply:
            oneshot::Sender<Result<crate::context::supervisor::saga_journal::SagaId, ContextError>>,
    },
}

/// See [`ContextCommand::Queries`]. Pure-read variants — handlers MUST
/// NOT mutate `PerContextState` or any observable state reachable through
/// the view / deps. Each variant carries a typed oneshot reply channel;
/// the dispatch function sends the reply and returns
/// `Outcome { mutated: false }`.
///
/// Commit 7 lands the real read variants. Commit 12c.7 deletes the
/// transitional `QueryStateView` borrow adapter and routes the
/// `&PerContextState` + shared event-log provider directly into the
/// query handler. Variants that mutate state (even if they live in
/// `manager/queries.rs` today — `drain_events`, access-key management,
/// `compare_remote_checkpoint`, `prove_event_*`, etc.) are NOT migrated
/// here and continue to route through the legacy `ContextManager` until
/// their respective handler commits (8-11).
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
        /// (matches the legacy `ContextManager::member_count` contract).
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
        reply: oneshot::Sender<
            Result<Option<Vec<crate::context::providers::event_log::EventLogEntry>>, ContextError>,
        >,
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
        member_did: scp_identity::DID,
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
        member_did: scp_identity::DID,
        /// Current Unix time (seconds) — caller supplies to keep the
        /// handler pure / deterministic.
        now_secs: u64,
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<u64, ContextError>>,
    },
}

/// See [`ContextCommand::SagaPhase`]. Saga phase routing lands with the
/// saga path in commit 11.
pub enum SagaPhaseMessage {
    /// Placeholder.
    Placeholder {
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

/// Returns the oneshot reply sender for a command, consuming the command.
/// Used by the test-only `send_not_implemented` helper on
/// [`crate::context::actor::ContextActorHandle`] to close out a stub
/// dispatch. Not part of the public API — the field is pattern-matched
/// directly by the handler stubs once they migrate.
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
        let cmd = ContextCommand::Messaging(MessagingCommand::Placeholder { reply: tx });
        assert!(!cmd.is_shutdown());
    }

    #[test]
    fn sub_enum_placeholders_carry_reply_channels() {
        // Compile-time witness: every placeholder variant carries a
        // oneshot reply channel with the expected type.
        let (tx, rx) = oneshot::channel::<Result<(), ContextError>>();
        let _ = ContextCommand::Messaging(MessagingCommand::Placeholder { reply: tx });
        drop(rx);
    }
}
