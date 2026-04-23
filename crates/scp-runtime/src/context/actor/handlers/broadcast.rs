//! Broadcast handlers — see
//! [`BroadcastCommand`](crate::context::actor::commands::BroadcastCommand)
//! and plan §"Broadcast contexts".
//!
//! # Commit 11 scope
//!
//! Migrates the dispatch shape for the non-saga broadcast surface.
//! Underlying byte-identical implementation still lives on
//! [`ContextManager`](crate::context::manager::ContextManager): each
//! handler delegates to
//! [`ContextManager::subscribe_broadcast`](crate::context::manager::ContextManager::subscribe_broadcast),
//! [`ContextManager::unsubscribe_broadcast`](crate::context::manager::ContextManager::unsubscribe_broadcast),
//! [`ContextManager::publish_broadcast`](crate::context::manager::ContextManager::publish_broadcast),
//! [`ContextManager::publish_broadcast_content`](crate::context::manager::ContextManager::publish_broadcast_content),
//! [`ContextManager::block_broadcast_subscriber`](crate::context::manager::ContextManager::block_broadcast_subscriber),
//! [`ContextManager::unblock_broadcast_subscriber`](crate::context::manager::ContextManager::unblock_broadcast_subscriber),
//! [`ContextManager::handle_broadcast_key_request`](crate::context::manager::ContextManager::handle_broadcast_key_request),
//! [`ContextManager::broadcast_subscriber_count`](crate::context::manager::ContextManager::broadcast_subscriber_count),
//! [`ContextManager::is_broadcast_subscriber`](crate::context::manager::ContextManager::is_broadcast_subscriber),
//! or
//! [`ContextManager::broadcast_admission`](crate::context::manager::ContextManager::broadcast_admission).
//! The shim wraps each delegated call in [`tokio::time::timeout`] with
//! a 30s budget per ADR-049 §7.
//!
//! # Publish + key-custody plumbing
//!
//! The publish entry points on `ContextManager` take
//! `custody: &impl KeyCustody`. Because
//! [`KeyCustody`](scp_platform::KeyCustody) uses RPITIT (not
//! `dyn`-safe), the actor mailbox cannot carry a custody reference
//! directly. The shim-dispatch methods
//! [`Supervisor::dispatch_broadcast_command`](crate::context::supervisor::supervisor::Supervisor::dispatch_broadcast_command)
//! accept the custody as a generic parameter and thread it through to
//! [`dispatch_from_shim_with_custody`]; the command variant carries
//! only the `KeyHandle`. For every NON-publish variant the shim routes
//! through the plain [`dispatch_from_shim`] entry point with no custody
//! parameter.
//!
//! # SAGA WIRING DEFERRED — see
//! `.docs/adrs/DEFERRED-commit-11-saga-use-cases.md`.
//!
//! The `InitiateBroadcastHostingHandshake` saga-initiator variant
//! returns [`ContextError::NotImplemented`](scp_protocol::context::ContextError::NotImplemented)
//! because broadcast hosting handshake protocol is spec-gapped — the
//! spec does not yet define the subscriber→host key-exchange frames,
//! host-config negotiation, or §5.14.2 step-4 transport. Until those
//! land, the saga-initiator path returns
//! `ContextError::NotImplemented`.

use std::time::Duration;

use scp_platform::KeyCustody;
use scp_protocol::context::ContextError;
use tokio::sync::oneshot;

use crate::context::actor::commands::{
    BlockBroadcastSubscriberReply, BroadcastAdmissionReply, BroadcastBlockPayload,
    BroadcastCommand, HandleBroadcastKeyRequestReply, PublishBroadcastContentPayload,
    PublishBroadcastPayload, PublishBroadcastReply, SubscribeBroadcastPayload,
    SubscribeBroadcastReply, UnsubscribeBroadcastPayload, UnsubscribeBroadcastReply,
};
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::outcome::Outcome;
use crate::context::supervisor::Supervisor;

/// Per-call transport budget for broadcast handlers.
pub const HANDLER_TIMEOUT: Duration = Duration::from_secs(30);

/// Dispatch a [`BroadcastCommand`] against an attached supervisor +
/// deps bundle.
///
/// Publish variants require a key custody reference which cannot cross
/// the actor mailbox; this entry point rejects them with a typed error
/// directing the caller to the generic
/// [`dispatch_from_shim_with_custody`] path instead.
///
/// # Supervisor receiver (ADR-049 commit 12c.9c)
///
/// Takes `&Supervisor` so the delegated
/// [`broadcast_helpers`](crate::context::broadcast_helpers) free
/// functions can read the lifted provider slots (crypto, transport,
/// event_log, event_tx, clock, local_dids) directly off the supervisor.
/// Each helper derives `&ContextManager` internally for the remaining
/// manager-only surface (`get_context_arc`, `has_persistence`, etc.)
/// via `supervisor.attached_context_manager().expect(...)`.
pub async fn dispatch(
    supervisor: &Supervisor,
    _deps: &ActorDeps,
    cmd: BroadcastCommand,
) -> Outcome<()> {
    Box::pin(dispatch_inner_no_custody(supervisor, cmd)).await
}

/// Shim-callable dispatch for NON-publish broadcast variants. See the
/// publish-specific entry points below.
pub(crate) async fn dispatch_from_shim(
    supervisor: &Supervisor,
    cmd: BroadcastCommand,
) -> Outcome<()> {
    Box::pin(dispatch_inner_no_custody(supervisor, cmd)).await
}

/// Shim-callable dispatch for publish variants that need a key custody
/// reference. The caller (shim) provides its concrete custody type; the
/// handler passes it straight through to the hoisted
/// [`broadcast_helpers::publish_broadcast`](crate::context::broadcast_helpers::publish_broadcast)
/// / [`broadcast_helpers::publish_broadcast_content`](crate::context::broadcast_helpers::publish_broadcast_content)
/// free functions.
pub(crate) async fn dispatch_from_shim_with_custody<C: KeyCustody>(
    supervisor: &Supervisor,
    cmd: BroadcastCommand,
    custody: &C,
) -> Outcome<()> {
    Box::pin(dispatch_inner_with_custody(supervisor, cmd, custody)).await
}

async fn dispatch_inner_no_custody(supervisor: &Supervisor, cmd: BroadcastCommand) -> Outcome<()> {
    match cmd {
        BroadcastCommand::Placeholder { reply } => reply_not_implemented(reply),
        BroadcastCommand::SubscribeBroadcast { payload, reply } => {
            handle_subscribe_broadcast(supervisor, *payload, reply).await
        }
        BroadcastCommand::UnsubscribeBroadcast { payload, reply } => {
            handle_unsubscribe_broadcast(supervisor, *payload, reply).await
        }
        BroadcastCommand::BlockBroadcastSubscriber { payload, reply } => {
            handle_block_broadcast_subscriber(supervisor, *payload, reply).await
        }
        BroadcastCommand::UnblockBroadcastSubscriber { payload, reply } => {
            handle_unblock_broadcast_subscriber(supervisor, *payload, reply).await
        }
        BroadcastCommand::HandleBroadcastKeyRequest {
            context_id,
            author_did,
            requester_did,
            reply,
        } => {
            handle_handle_broadcast_key_request(
                supervisor,
                &context_id,
                &author_did,
                &requester_did,
                reply,
            )
            .await
        }
        BroadcastCommand::BroadcastSubscriberCount { context_id, reply } => {
            handle_broadcast_subscriber_count(supervisor, &context_id, reply).await
        }
        BroadcastCommand::IsBroadcastSubscriber {
            context_id,
            did,
            reply,
        } => handle_is_broadcast_subscriber(supervisor, &context_id, &did, reply).await,
        BroadcastCommand::BroadcastAdmission { context_id, reply } => {
            handle_broadcast_admission(supervisor, &context_id, reply).await
        }
        BroadcastCommand::PublishBroadcast { reply, .. } => {
            // Publish variants require a custody reference that cannot
            // cross the actor mailbox — route through the `_with_custody`
            // shim. This arm catches callers who took the wrong path
            // and surfaces a typed error.
            const MSG: &str = "BroadcastCommand::PublishBroadcast requires a KeyCustody reference; \
                 route through Supervisor::dispatch_broadcast_command_with_custody (generic over custody)";
            let _ = reply.send(Err(ContextError::InvalidState(MSG.to_owned())));
            Outcome::err(ContextError::InvalidState(MSG.to_owned()))
        }
        BroadcastCommand::PublishBroadcastContent { reply, .. } => {
            const MSG: &str = "BroadcastCommand::PublishBroadcastContent requires a KeyCustody reference; \
                 route through Supervisor::dispatch_broadcast_command_with_custody (generic over custody)";
            let _ = reply.send(Err(ContextError::InvalidState(MSG.to_owned())));
            Outcome::err(ContextError::InvalidState(MSG.to_owned()))
        }
        BroadcastCommand::InitiateBroadcastHostingHandshake { reply, .. } => {
            reply_saga_deferred(reply)
        }
    }
}

async fn dispatch_inner_with_custody<C: KeyCustody>(
    supervisor: &Supervisor,
    cmd: BroadcastCommand,
    custody: &C,
) -> Outcome<()> {
    match cmd {
        BroadcastCommand::PublishBroadcast { payload, reply } => {
            handle_publish_broadcast(supervisor, *payload, custody, reply).await
        }
        BroadcastCommand::PublishBroadcastContent { payload, reply } => {
            handle_publish_broadcast_content(supervisor, *payload, custody, reply).await
        }
        // Non-publish variants do not need a custody reference. Fall
        // through to the no-custody dispatch so the custody-generic
        // shim method can carry every variant (not just publish).
        other => dispatch_inner_no_custody(supervisor, other).await,
    }
}

async fn handle_subscribe_broadcast(
    supervisor: &Supervisor,
    p: SubscribeBroadcastPayload,
    reply: SubscribeBroadcastReply,
) -> Outcome<()> {
    let context_id = p.context_id.clone();

    // Pass `None` for the validation-context generic — gated
    // broadcasts still validate inline via the inline UCAN token
    // path. The full validation context is plumbed through the
    // FFI bridges' own UCAN registry and not carried through the
    // mailbox. The no-op turbofish types satisfy the helper's
    // generic bounds; passing `None` for the optional
    // `validation_ctx` argument short-circuits the full pipeline.
    let subscribe_fut = crate::context::broadcast_helpers::subscribe_broadcast::<
        NoopDidResolver,
        NoopNonceTracker,
        NoopRevocationChecker,
        NoopProofResolver,
        std::collections::hash_map::RandomState,
    >(
        supervisor,
        &p.context_id,
        &p.subscriber_did,
        p.ucan.as_ref(),
        p.timestamp,
        None,
    );

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, subscribe_fut).await {
        Ok(Ok(result)) => (Outcome::ok_mutated(()), Ok(result)),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err_mutated(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "subscribe_broadcast exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

async fn handle_unsubscribe_broadcast(
    supervisor: &Supervisor,
    p: UnsubscribeBroadcastPayload,
    reply: UnsubscribeBroadcastReply,
) -> Outcome<()> {
    let context_id = p.context_id.clone();

    let unsub_fut = crate::context::broadcast_helpers::unsubscribe_broadcast(
        supervisor,
        &p.context_id,
        &p.subscriber_did,
        p.rotate_keys,
    );

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, unsub_fut).await {
        Ok(Ok(result)) => (Outcome::ok_mutated(()), Ok(result)),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err_mutated(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "unsubscribe_broadcast exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

async fn handle_publish_broadcast<C: KeyCustody>(
    supervisor: &Supervisor,
    p: PublishBroadcastPayload,
    custody: &C,
    reply: PublishBroadcastReply,
) -> Outcome<()> {
    let context_id = p.context_id.clone();

    let publish_fut = crate::context::broadcast_helpers::publish_broadcast(
        supervisor,
        &p.context_id,
        &p.author_did,
        &p.payload,
        custody,
        &p.signing_key_handle,
    );

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, publish_fut).await {
        Ok(Ok(env)) => (Outcome::ok_mutated(()), Ok(env)),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err_mutated(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "publish_broadcast exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

async fn handle_publish_broadcast_content<C: KeyCustody>(
    supervisor: &Supervisor,
    p: PublishBroadcastContentPayload,
    custody: &C,
    reply: PublishBroadcastReply,
) -> Outcome<()> {
    let context_id = p.context_id.clone();

    let publish_fut = crate::context::broadcast_helpers::publish_broadcast_content(
        supervisor,
        &p.context_id,
        &p.author_did,
        p.content,
        custody,
        &p.signing_key_handle,
    );

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, publish_fut).await {
        Ok(Ok(env)) => (Outcome::ok_mutated(()), Ok(env)),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err_mutated(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "publish_broadcast_content exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

async fn handle_block_broadcast_subscriber(
    supervisor: &Supervisor,
    p: BroadcastBlockPayload,
    reply: BlockBroadcastSubscriberReply,
) -> Outcome<()> {
    let context_id = p.context_id.clone();

    let block_fut = crate::context::broadcast_helpers::block_broadcast_subscriber(
        supervisor,
        &p.context_id,
        &p.author_did,
        &p.subscriber_did,
    );

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, block_fut).await {
        Ok(Ok(result)) => (Outcome::ok_mutated(()), Ok(result)),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err_mutated(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "block_broadcast_subscriber exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

async fn handle_unblock_broadcast_subscriber(
    supervisor: &Supervisor,
    p: BroadcastBlockPayload,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let context_id = p.context_id.clone();

    let unblock_fut = crate::context::broadcast_helpers::unblock_broadcast_subscriber(
        supervisor,
        &p.context_id,
        &p.author_did,
        &p.subscriber_did,
    );

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, unblock_fut).await {
        Ok(Ok(())) => (Outcome::ok_mutated(()), Ok(())),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err_mutated(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "unblock_broadcast_subscriber exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

async fn handle_handle_broadcast_key_request(
    supervisor: &Supervisor,
    context_id: &str,
    author_did: &scp_identity::DID,
    requester_did: &scp_identity::DID,
    reply: HandleBroadcastKeyRequestReply,
) -> Outcome<()> {
    let key_req_fut = crate::context::broadcast_helpers::handle_broadcast_key_request(
        supervisor,
        context_id,
        author_did,
        requester_did,
    );

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, key_req_fut).await {
        Ok(Ok(decision)) => (Outcome::ok(()), Ok(decision)),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "handle_broadcast_key_request exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

async fn handle_broadcast_subscriber_count(
    supervisor: &Supervisor,
    context_id: &str,
    reply: oneshot::Sender<Result<Option<usize>, ContextError>>,
) -> Outcome<()> {
    let count_fut =
        crate::context::broadcast_helpers::broadcast_subscriber_count(supervisor, context_id);

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, count_fut).await {
        Ok(count) => (Outcome::ok(()), Ok(count)),
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "broadcast_subscriber_count exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

async fn handle_is_broadcast_subscriber(
    supervisor: &Supervisor,
    context_id: &str,
    did: &str,
    reply: oneshot::Sender<Result<bool, ContextError>>,
) -> Outcome<()> {
    let is_fut =
        crate::context::broadcast_helpers::is_broadcast_subscriber(supervisor, context_id, did);

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, is_fut).await {
        Ok(is) => (Outcome::ok(()), Ok(is)),
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "is_broadcast_subscriber exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

async fn handle_broadcast_admission(
    supervisor: &Supervisor,
    context_id: &str,
    reply: BroadcastAdmissionReply,
) -> Outcome<()> {
    let admission_fut =
        crate::context::broadcast_helpers::broadcast_admission(supervisor, context_id);

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, admission_fut).await {
        Ok(admission) => (Outcome::ok(()), Ok(admission)),
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "broadcast_admission exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

// ---------------------------------------------------------------------------
// No-op UCAN validation trait impls — satisfy the generic bounds on
// [`ContextManager::subscribe_broadcast`](crate::context::manager::ContextManager::subscribe_broadcast)
// when the caller passes `None` for `validation_ctx`. No method is
// actually invoked; the types exist only as compile-time witnesses so
// the turbofish has something to bind to. Mirrors the
// `NoOpDidResolver` / `NoOpNonceTracker` / ... stubs in the PyO3
// bridge's `context.rs` (public-open broadcast path does not touch
// UCAN validation at all).
// ---------------------------------------------------------------------------

struct NoopDidResolver;
impl scp_protocol::crypto::ucan::validate::DidResolver for NoopDidResolver {
    fn resolve_public_key(
        &self,
        _did: &str,
    ) -> Result<[u8; 32], scp_protocol::crypto::ucan::UcanError> {
        Err(scp_protocol::crypto::ucan::UcanError::MalformedToken(
            "NoopDidResolver (actor broadcast handler) — no resolution available".into(),
        ))
    }
}

struct NoopNonceTracker;
impl scp_protocol::crypto::ucan::validate::NonceTracker for NoopNonceTracker {
    fn check_replay(
        &self,
        _nonce: &str,
        _token_expiry: u64,
    ) -> Result<(), scp_protocol::crypto::ucan::UcanError> {
        Ok(())
    }

    fn record(
        &mut self,
        _nonce: &str,
        _token_expiry: u64,
    ) -> Result<(), scp_protocol::crypto::ucan::UcanError> {
        Ok(())
    }
}

struct NoopRevocationChecker;
impl scp_protocol::crypto::ucan::validate::RevocationChecker for NoopRevocationChecker {
    fn is_revoked(&self, _token_cid: &str) -> bool {
        false
    }
}

struct NoopProofResolver;
impl scp_protocol::crypto::ucan::validate::ProofResolver for NoopProofResolver {
    fn resolve_proof(
        &self,
        _proof_cid: &str,
    ) -> Result<scp_protocol::crypto::ucan::UcanToken, scp_protocol::crypto::ucan::UcanError> {
        Err(scp_protocol::crypto::ucan::UcanError::MalformedToken(
            "NoopProofResolver (actor broadcast handler) — no proof resolution".into(),
        ))
    }
}

/// Produce a best-effort clone-equivalent `ContextError` for the
/// handler's [`Outcome`] sink.
fn outcome_error_sketch(err: &ContextError) -> ContextError {
    match err {
        ContextError::TransportTimeout(msg) => ContextError::TransportTimeout(msg.clone()),
        ContextError::TransportFailed(msg) => ContextError::TransportFailed(msg.clone()),
        ContextError::CryptoFailed(msg) => ContextError::CryptoFailed(msg.clone()),
        ContextError::PermissionDenied(msg) => ContextError::PermissionDenied(msg.clone()),
        ContextError::MemberNotFound(msg) => ContextError::MemberNotFound(msg.clone()),
        ContextError::ContextNotRegistered(msg) => ContextError::ContextNotRegistered(msg.clone()),
        ContextError::ContextNotActive => ContextError::ContextNotActive,
        ContextError::MembershipFailed(msg) => ContextError::MembershipFailed(msg.clone()),
        ContextError::EventLogFailed(msg) => ContextError::EventLogFailed(msg.clone()),
        ContextError::GovernanceFailed(msg) => ContextError::GovernanceFailed(msg.clone()),
        ContextError::InvalidState(msg) => ContextError::InvalidState(msg.clone()),
        ContextError::NotImplemented(msg) => ContextError::NotImplemented(msg.clone()),
        other => ContextError::CryptoFailed(format!("{other}")),
    }
}

fn reply_not_implemented(reply: oneshot::Sender<Result<(), ContextError>>) -> Outcome<()> {
    const MSG: &str = "BroadcastCommand::Placeholder — real variants migrate in commit 11 of \
                       ADR-049; Placeholder retained for commit-6 compile stability and \
                       deleted in commit 12 with the shim";
    let _ = reply.send(Err(ContextError::NotImplemented(MSG.to_owned())));
    Outcome::err(ContextError::NotImplemented(MSG.to_owned()))
}

fn reply_saga_deferred(
    reply: oneshot::Sender<Result<crate::context::supervisor::saga_journal::SagaId, ContextError>>,
) -> Outcome<()> {
    const MSG: &str = "broadcast::initiate_broadcast_hosting_handshake — saga wiring deferred \
                       to commit 11.5 per 5 enumerated spec gaps; see \
                       .docs/adrs/DEFERRED-commit-11-saga-use-cases.md (gap 3: broadcast \
                       hosting handshake protocol)";
    let _ = reply.send(Err(ContextError::NotImplemented(MSG.to_owned())));
    Outcome::err(ContextError::NotImplemented(MSG.to_owned()))
}
