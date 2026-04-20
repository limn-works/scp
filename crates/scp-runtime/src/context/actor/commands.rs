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

// ---------------------------------------------------------------------------
// Outer enum
// ---------------------------------------------------------------------------

/// Every command the `ContextActor` accepts. Routed by the actor's
/// dispatch loop to the matching handler module.
///
/// Variants correspond one-to-one with handler files under
/// [`crate::context::actor::handlers`]. The dispatch loop in
/// [`crate::context::actor::ContextActor::dispatch`] matches on this enum.
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
/// management messages all stay on the legacy [`ContextManager`] surface
/// until commits 10-11 per the plan row-6 scope.
pub enum MessagingCommand {
    /// Placeholder — retained so out-of-tree callers constructed during
    /// commit 6 still compile. Handler replies `NotImplemented` and
    /// returns `Outcome::err`. Removed in commit 12 when the shim is
    /// deleted.
    Placeholder {
        /// Oneshot reply channel. Handler stub sends
        /// `Err(ContextError::NotImplemented(..))` back.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Encrypts and transmits a message within an active context.
    ///
    /// Mirrors the legacy
    /// [`ContextManager::send_message`](crate::context::manager::ContextManager::send_message)
    /// signature exactly: the handler delegates to that method for
    /// byte-identical envelope construction, inner-signature signing,
    /// sender-key sealing, MLS encryption, and transport fan-out.
    ///
    /// # Owned payload fields
    ///
    /// Every field is owned (`Vec<u8>`, `String`, `DID`,
    /// `ContextParams`) rather than borrowed so the command can cross
    /// the actor mailbox without lifetime juggling. The handler
    /// reconstructs an ephemeral [`ContextHandle`] on the receive side
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
    /// [`ContextManager::deliver_incoming`](crate::context::manager::ContextManager::deliver_incoming)
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

/// Reply-channel type alias for [`LifecycleCommand::ExportContext`]. The
/// reply carries a fully-populated
/// [`ContextExport`](crate::context::export_import::ContextExport) —
/// snapshot, Merkle event log, (currently empty) MLS state, and signed
/// header.
pub type ExportContextReply =
    oneshot::Sender<Result<crate::context::export_import::ContextExport, ContextError>>;

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

/// See [`ContextCommand::Lifecycle`]. Real variants land in commit 9 of
/// the ADR-049 commit ladder (see `handlers/lifecycle.rs`). Variants
/// mirror the legacy
/// [`ContextManager`](crate::context::manager::ContextManager) lifecycle
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
/// [`ContextManager::create_context`](crate::context::manager::ContextManager::create_context)
/// / [`ContextManager::join_context`](crate::context::manager::ContextManager::join_context)
/// directly; saga wiring moves into this enum in commit 11.
pub enum LifecycleCommand {
    /// Placeholder — retained so out-of-tree callers constructed during
    /// commit 6 still compile. Handler replies `NotImplemented` and
    /// returns `Outcome::err`. Removed in commit 12 when the shim is
    /// deleted.
    Placeholder {
        /// Oneshot reply channel. Handler stub sends
        /// `Err(ContextError::NotImplemented(..))` back.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Creates a new MLS-backed (or broadcast-mode) context. Mirrors
    /// [`ContextManager::create_context`](crate::context::manager::ContextManager::create_context).
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
    /// [`ContextManager::join_context`](crate::context::manager::ContextManager::join_context).
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
    /// [`ContextManager::leave_context`](crate::context::manager::ContextManager::leave_context).
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
    /// [`ContextManager::close_context`](crate::context::manager::ContextManager::close_context)
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
    /// Mirrors
    /// [`ContextManager::export_context`](crate::context::manager::ContextManager::export_context).
    ExportContext {
        /// Context identifier string.
        context_id: String,
        /// Exporter DID — signs the export header.
        exporter_did: scp_identity::DID,
        /// Oneshot reply channel. See [`ExportContextReply`].
        reply: ExportContextReply,
    },

    /// Imports a previously exported context. Mirrors
    /// [`ContextManager::import_context`](crate::context::manager::ContextManager::import_context).
    ///
    /// The per-instance authorization-state wipe policy (C3) is enforced
    /// by the legacy method; the command carries the raw export and
    /// expects the handler to pass it through verbatim.
    ImportContext {
        /// Fully-parsed context export — envelope has already been
        /// deserialized by the FFI bridge.
        export: Box<crate::context::export_import::ContextExport>,
        /// Oneshot reply channel. See [`ImportContextReply`].
        reply: ImportContextReply,
    },
}

/// See [`ContextCommand::Governance`]. Real variants arrive in commit 10.
pub enum GovernanceCommand {
    /// Placeholder.
    Placeholder {
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },
}

/// See [`ContextCommand::Broadcast`]. Real variants arrive in commit 11.
pub enum BroadcastCommand {
    /// Placeholder.
    Placeholder {
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },
}

/// See [`ContextCommand::Economy`]. Real variants arrive in commit 10.
pub enum EconomyCommand {
    /// Placeholder.
    Placeholder {
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },
}

/// See [`ContextCommand::TrustRecovery`]. Real variants arrive in commit 10.
pub enum TrustRecoveryCommand {
    /// Placeholder.
    Placeholder {
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },
}

/// See [`ContextCommand::Standing`]. Real variants arrive in commit 11.
pub enum StandingCommand {
    /// Placeholder.
    Placeholder {
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
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
/// [`ContextManager`](crate::context::manager::ContextManager) TTL
/// surface one-to-one. The handler shim delegates to the legacy method
/// under the hood.
///
/// **TTL timer specifics (commit 9 scope).** The post-refactor
/// architecture turns the TTL timer into a `select!` arm in
/// [`ContextActor::run`](crate::context::actor::ContextActor). Commit 9
/// keeps the timer spawned from the legacy
/// [`ContextManager`](crate::context::manager::ContextManager) internals
/// (`spawn_ttl_timer`); the handler variants here respond to
/// caller-initiated TTL commands (extend, finalize, explicit expiry)
/// synchronously. Full timer-owning actor logic migrates with plan row
/// 11.
pub enum TtlCloseCommand {
    /// Placeholder — retained so out-of-tree callers constructed during
    /// commit 6 still compile. Handler replies `NotImplemented` and
    /// returns `Outcome::err`. Removed in commit 12 when the shim is
    /// deleted.
    Placeholder {
        /// Oneshot reply channel. Handler stub sends
        /// `Err(ContextError::NotImplemented(..))` back.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Spawns (or respawns) the TTL timer for the given context with a
    /// caller-supplied duration. Mirrors the legacy
    /// [`ContextManager::spawn_ttl_timer`](crate::context::manager::ContextManager)
    /// call path used at `create_context` / `restore_context` time.
    ///
    /// `Ok(())` once the timer has been successfully installed.
    StartTtlTimer {
        /// Boxed owned payload — see [`TtlTimerPayload`].
        payload: Box<TtlTimerPayload>,
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Proposes a TTL extension on behalf of a specific member. Mirrors
    /// [`ContextManager::propose_ttl_extension`](crate::context::manager::ContextManager::propose_ttl_extension).
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
    /// [`ContextManager::reset_ttl_timer`](crate::context::manager::ContextManager::reset_ttl_timer).
    ResetTtlTimer {
        /// Boxed owned payload — see [`TtlTimerPayload`].
        payload: Box<TtlTimerPayload>,
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },

    /// Executes a caller-initiated TTL expiry. Mirrors
    /// [`ContextManager::handle_ttl_expiry`](crate::context::manager::ContextManager::handle_ttl_expiry).
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
    /// [`ContextManager::finalize_close`](crate::context::manager::ContextManager::finalize_close).
    FinalizeClose {
        /// Boxed owned payload — see [`TtlContextPayload`].
        payload: Box<TtlContextPayload>,
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },
}

/// See [`ContextCommand::Tools`]. Real variants arrive in commit 11.
pub enum ToolsCommand {
    /// Placeholder.
    Placeholder {
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },
}

/// See [`ContextCommand::Queries`]. Pure-read variants — handlers MUST
/// NOT mutate `PerContextState` or any observable state reachable through
/// the view / deps. Each variant carries a typed oneshot reply channel;
/// the dispatch function sends the reply and returns
/// `Outcome { mutated: false }`.
///
/// Commit 7 lands the real read variants that route through the
/// transitional
/// [`QueryStateView`](crate::context::actor::query_state_view::QueryStateView)
/// borrow adapter. Variants that mutate state (even if they live in
/// `manager/queries.rs` today — `drain_events`, access-key management,
/// `compare_remote_checkpoint`, `prove_event_*`, etc.) are NOT migrated
/// here and continue to route through the legacy `ContextManager` until
/// their respective handler commits (8-11).
pub enum QueriesCommand {
    /// Pseudonym routing ID for the local member (§9.10.4).
    /// `Ok(None)` iff no pseudonym is set. Read-only.
    LocalPseudonym {
        /// Context identifier string (matches the legacy API).
        context_id: String,
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<Option<[u8; 32]>, ContextError>>,
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
        reply: oneshot::Sender<Result<Vec<crate::context::manager::PendingCommit>, ContextError>>,
    },
    /// Active commit-fault marker. `Some` iff the context is in
    /// fail-close state (PR #1606 C6).
    CommitFault {
        /// Context identifier string.
        context_id: String,
        /// Oneshot reply channel. `Ok(None)` iff no fault or unknown.
        reply: oneshot::Sender<
            Result<Option<crate::context::manager::CommitFaultMarker>, ContextError>,
        >,
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
/// [`BridgeInstanceCore`](scp_ffi_common::bridge_instance::BridgeInstanceCore)
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
