//! Economy handlers — see
//! [`EconomyCommand`](crate::context::actor::commands::EconomyCommand)
//! and spec §19 / plan row 10 of the commit ladder.
//!
//! # Phase 2A.3 — actor-shape dispatch
//!
//! The handler's primary entry point [`dispatch`] takes
//! `(&mut PerContextState, &ActorDeps, EconomyCommand)` and routes to
//! actor-shaped helpers in [`crate::context::economy_helpers`]. The shim
//! entry point was deleted in Phase 2A finalization; the
//! no-mailbox-context fallback now lives on
//! [`Supervisor::dispatch_economy_direct`](crate::context::supervisor::Supervisor::dispatch_economy_direct).

use std::time::Duration;

use scp_protocol::context::ContextError;

use crate::context::actor::class_s::ClassSCell;
use crate::context::actor::commands::EconomyCommand;
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::outcome::Outcome;
use crate::economy::receipt::ReceiptVerificationError;

/// Per-call transport budget for economy handlers. Plan §"Transport
/// timeouts inside actor handlers": 30 seconds.
pub const HANDLER_TIMEOUT: Duration = Duration::from_secs(30);

/// Dispatch an [`EconomyCommand`] against actor-owned state and
/// capability-reduced dependencies.
///
/// The domain is mixed: [`EconomyCommand::VerifyPaymentReceipts`] is
/// read-only (receipt verification flows entirely through the payment
/// adapter on `deps`), while [`EconomyCommand::RevokeSpendingUcan`] mutates
/// the actor's Class-S `revoked_spending_ucan_cids` gate through the cell's
/// fail-closed persist-on-commit combinator (ADR-049 §9). The `&mut cell`
/// referent also keeps the spawned dispatch future `Send`, which a shared
/// `&ClassSCell` would not (`ClassSCell` is not `Sync`).
pub(crate) async fn dispatch(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    cmd: EconomyCommand,
) -> Outcome<()> {
    match cmd {
        EconomyCommand::VerifyPaymentReceipts { receipts, reply } => {
            handle_verify_payment_receipts(deps, *receipts, reply).await
        }
        EconomyCommand::RevokeSpendingUcan {
            context_id,
            revoked_cid,
            scope,
            issuer_did,
            revoker_did,
            reply,
        } => {
            handle_revoke_spending_ucan(
                cell,
                deps,
                context_id,
                revoked_cid,
                scope,
                issuer_did,
                revoker_did,
                reply,
            )
            .await
        }
    }
}

/// Handle [`EconomyCommand::VerifyPaymentReceipts`] — delegates to
/// [`economy_helpers::verify_payment_receipts`](crate::context::economy_helpers::verify_payment_receipts)
/// under a 30s timeout. Read-only — the helper does not read or mutate
/// per-context state; it calls the configured payment adapter's
/// `verify_dyn` method per receipt and collates results.
async fn handle_verify_payment_receipts(
    deps: &ActorDeps,
    receipts: Vec<crate::economy::adapter::PaymentReceipt>,
    reply: crate::context::actor::commands::VerifyPaymentReceiptsReply,
) -> Outcome<()> {
    let verify_fut = crate::context::economy_helpers::verify_payment_receipts(deps, &receipts);

    let results = match tokio::time::timeout(HANDLER_TIMEOUT, verify_fut).await {
        Ok(vec) => vec,
        Err(_elapsed) => {
            // On timeout, synthesize a per-receipt NoVerifierForAdapter
            // error — callers see the same vector shape whether the
            // adapter returned per-receipt errors or the handler timed
            // out. The legacy method returns `Vec<Result<..>>` (always
            // Ok(vec)), so the outer Result here surfaces ONLY the
            // timeout path.
            receipts
                .iter()
                .map(|r| {
                    Err(ReceiptVerificationError::NoVerifierForAdapter {
                        receipt_id: r.receipt_id,
                        adapter_id: r.adapter_id.clone(),
                    })
                })
                .collect()
        }
    };

    let _ = reply.send(results);
    // Verify payment receipts is a pure read — mutated=false.
    Outcome::ok(())
}

/// Handle [`EconomyCommand::RevokeSpendingUcan`] — carry a revoked spending
/// UCAN's revocation CID into the actor's Class-S `revoked_spending_ucan_cids`
/// set (the authoritative paid-action gate consulted by
/// `validate_spending_ucan_signed`), then emit the convergent
/// [`SpendingUcanRevoked`](scp_event_log::EventType::SpendingUcanRevoked) leaf
/// (spec §19.5, §19.6.1).
///
/// # Fail-closed ordering (ADR-049 §9)
///
/// 1. The insertion rides [`ClassSCell::commit_class_s_keep`] — a **fail-closed**
///    persist-on-commit combinator, keep-direction: the CID is written through a
///    [`ClassSMut`](crate::context::actor::class_s::ClassSMut) view (reaching the
///    `pub(in crate::context)` set via `rest_mut`, the documented route for this
///    Class-S field, which lives in `GovernanceState` rather than the
///    `GovernanceClassS` sub-struct) and persisted before the revocation is
///    acknowledged. On persist failure the in-memory revocation is RETAINED
///    (un-revoking would re-open the re-spend window the human closed) and the
///    error is surfaced — the caller never observes a half-durable revocation as
///    success.
/// 2. Only after the gate is durably closed is the `SpendingUcanRevoked` leaf
///    appended. A leaf-append failure is surfaced but does NOT roll the gate
///    back — the safe direction (the gate stays closed; only the audit leaf is
///    missing).
#[allow(clippy::too_many_arguments)]
async fn handle_revoke_spending_ucan(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    context_id: String,
    revoked_cid: String,
    scope: String,
    issuer_did: String,
    revoker_did: String,
    reply: tokio::sync::oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    // Step 0a: reject an empty caller principal explicitly (spec §19.5, invariant
    // 3b). The supervisor-side `debug_assert!(!revoker_did.is_empty())` is stripped
    // in release builds; and an empty `revoker_did` would otherwise spuriously
    // match an empty recorded `creator_did` on the creator-authorization branch
    // below, authorizing an unauthenticated revoke.
    if revoker_did.trim().is_empty() {
        let _ = reply.send(Err(ContextError::PermissionDenied(
            "SCP-ECON-12068: revoker_did must be a non-empty, caller-authenticated principal"
                .to_owned(),
        )));
        return Outcome::ok(());
    }

    // Step 0b: scope-matched authorization (spec §19.5). A context-scoped
    // spending UCAN may be revoked ONLY by its issuer (the self-issuing payer,
    // `iss == aud`) OR by the creator of THIS context — the token's actual scope
    // context, whose authoritative creator DID the actor holds. This closes the
    // hole where any context's creator, by naming their own context on the
    // caller-supplied `ucan_revoke` path, could revoke a token scoped to a
    // DIFFERENT context. The authorization keys off the actor's own creator, not
    // any caller-supplied value.
    // Read the authoritative creator DID through the cell's read-only `Deref`
    // to `PerContextState` (no `&mut` state escape hatch is needed for a read).
    let creator_did = cell.role_state.creator_did.clone();
    // The creator branch requires a NON-empty recorded creator, so an empty
    // `creator_did` can never authorize (invariant 3b).
    let revoker_is_creator =
        !creator_did.trim().is_empty() && revoker_did.as_str() == creator_did.as_str();
    let revoker_is_issuer = revoker_did.as_str() == issuer_did.as_str();
    if !revoker_is_issuer && !revoker_is_creator {
        let _ = reply.send(Err(ContextError::PermissionDenied(format!(
            "SCP-ECON-12067: revoker '{revoker_did}' is neither the spending UCAN's issuer \
             ('{issuer_did}') nor the creator of its scope context ('{creator_did}')"
        ))));
        // Read-only: no state mutated when authorization fails.
        return Outcome::ok(());
    }

    // Step 0c: membership gate (spec §19.5, invariant 3a — defense-in-depth). The
    // revoker must be a CURRENT member of the context; the scope-context creator
    // remains allowed even if not a listed member. This reduces the flood surface
    // for the convergent per-context revoked-CID set to members — it does NOT
    // bound the set (a self-issuing member can still commit many revocations of
    // self-issued, never-granted tokens; the principled bound is the separate
    // observed/granted-tokens mechanism, issue #2072).
    if !revoker_is_creator && !cell.membership.contains(revoker_did.as_str()) {
        let _ = reply.send(Err(ContextError::PermissionDenied(format!(
            "SCP-ECON-12069: revoker '{revoker_did}' is not a current member of context \
             '{context_id}' — context-scoped spending-UCAN revocation is restricted to members"
        ))));
        return Outcome::ok(());
    }

    // Step 1: insert the CID into the Class-S gate, persisted fail-closed.
    let cid_for_leaf = revoked_cid.clone();
    let insert_result = cell
        .commit_class_s_keep(deps, &context_id, |mut view| {
            // `revoked_spending_ucan_cids` is a Class-S field of `GovernanceState`
            // (not the `GovernanceClassS` sub-struct); its documented mutation
            // route is a fail-closed combinator via the whole-state `rest_mut`
            // reach. `insert` is idempotent — a re-revocation is a no-op.
            view.rest_mut()
                .governance
                .revoked_spending_ucan_cids
                .insert(revoked_cid);
            Ok(())
        })
        .await;
    if let Err(e) = insert_result {
        // Keep-direction: the in-memory insertion is retained; surface the
        // persist error so the caller does not treat a non-durable revocation
        // as success.
        let _ = reply.send(Err(e));
        return Outcome::ok_mutated(());
    }

    // Step 2: append the convergent SpendingUcanRevoked leaf (§19.6.1).
    let payload = match scp_event_log::payload::encode_payload(
        &scp_event_log::payload::SpendingUcanRevokedPayload {
            token_cid: cid_for_leaf,
            scope,
        },
    ) {
        Ok(p) => p,
        Err(e) => {
            let _ = reply.send(Err(ContextError::EventLogFailed(e.to_string())));
            return Outcome::ok_mutated(());
        }
    };
    let context_id_bytes = crate::context::state::context_id_to_bytes(&context_id);
    let timestamp_secs = deps.clock.now_secs();
    let append_result = deps
        .event_log
        .append_context_event_with_payload(
            &context_id_bytes,
            scp_event_log::EventType::SpendingUcanRevoked,
            &revoker_did,
            payload,
            timestamp_secs,
        )
        .await;
    let _ = reply.send(append_result);
    Outcome::ok_mutated(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::Arc;

    use scp_did::DID;
    use scp_protocol::context::ContextError;

    use super::handle_revoke_spending_ucan;
    use crate::context::actor::class_s::ClassSCell;
    use crate::context::actor::deps::ActorDeps;
    use crate::context::actor::state::PerContextState;

    const ADMIN: &str = "did:example:revoke-authz-admin";
    const PAYER: &str = "did:dht:z6MkRevokeAuthzPayer";
    const CTX_BYTES: [u8; 32] = [0xC1u8; 32];

    /// Build `ActorDeps` over a working in-memory persistence + Merkle event log
    /// so the fail-closed Class-S commit and the audit-leaf append both succeed on
    /// the authorized paths.
    async fn build_deps() -> ActorDeps {
        use crate::context::providers::InMemoryPersistence;
        use crate::context::supervisor::supervisor::Supervisor;

        let crypto = Arc::new(crate::crypto::mls::provider::MlsCryptoProvider::new(
            ADMIN.to_owned(),
            Arc::new(scp_clock::SystemClock),
        ));
        let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
            Box::new(crate::context::builder::NotConfiguredTransportProvider);
        let event_log: Box<dyn crate::context::builder::ContextEventLogProvider> =
            Box::new(crate::context::providers::MerkleEventLogProvider::new());
        let key_resolver: scp_protocol::context::governance::KeyResolver = Arc::new(|_, _| None);
        let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> =
            Arc::new(
                crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
                    scp_platform::testing::InMemoryStorage::new(),
                )),
            );
        let supervisor = Supervisor::with_providers(
            crypto,
            transport,
            event_log,
            key_resolver,
            Some(Box::new(InMemoryPersistence::new())),
            None,
            None,
            Some(Arc::new(scp_clock::TestClock::new(1_700_000_000))),
            mls_storage,
            None, // revoked_spending_ucan_store
        );
        supervisor
            .build_actor_deps(&DID(ADMIN.to_owned()))
            .await
            .expect("build_actor_deps")
    }

    /// Fresh Active context whose creator is ADMIN. `members` are added to the
    /// membership set (the 3a gate reads `cell.membership`).
    fn seed_cell(members: &[&str]) -> ClassSCell {
        let mut state = PerContextState::new_for_test_encrypted(
            CTX_BYTES,
            1_700_000_000,
            DID(ADMIN.to_owned()),
        );
        state.role_state.creator_did = ADMIN.to_owned();
        for m in members {
            state
                .membership
                .add_member(DID((*m).to_owned()), "member".to_owned(), Vec::new());
        }
        ClassSCell::new(state)
    }

    async fn revoke(
        cell: &mut ClassSCell,
        deps: &ActorDeps,
        issuer_did: &str,
        revoker_did: &str,
    ) -> Result<(), ContextError> {
        let ctx_key = hex::encode(CTX_BYTES);
        let (tx, rx) = tokio::sync::oneshot::channel();
        let _ = handle_revoke_spending_ucan(
            cell,
            deps,
            ctx_key.clone(),
            "revoked-cid".to_owned(),
            format!("scp:spending:{ctx_key}"),
            issuer_did.to_owned(),
            revoker_did.to_owned(),
            tx,
        )
        .await;
        rx.await.expect("handler must send a reply")
    }

    /// Invariant 3b: an empty `revoker_did` is rejected explicitly (a
    /// release-stripped debug_assert cannot be relied on, and an empty revoker
    /// would otherwise match an empty creator).
    #[tokio::test]
    async fn revoke_rejects_empty_revoker_did() {
        let deps = build_deps().await;
        let mut cell = seed_cell(&[PAYER]);
        let result = revoke(&mut cell, &deps, PAYER, "").await;
        assert!(
            matches!(&result, Err(ContextError::PermissionDenied(msg)) if msg.contains("SCP-ECON-12068")),
            "empty revoker_did must be rejected with SCP-ECON-12068, got {result:?}"
        );
        assert!(
            !cell
                .governance
                .revoked_spending_ucan_cids
                .contains("revoked-cid"),
            "a rejected revoke must not insert the CID into the gate"
        );
    }

    /// Invariant 3a: a revoker who is the token's issuer but is NOT a current
    /// member (and not the creator) is rejected — the membership gate reduces the
    /// flood surface to members.
    #[tokio::test]
    async fn revoke_rejects_non_member_issuer() {
        let deps = build_deps().await;
        // PAYER is the issuer but NOT in the membership set.
        let mut cell = seed_cell(&[]);
        let result = revoke(&mut cell, &deps, PAYER, PAYER).await;
        assert!(
            matches!(&result, Err(ContextError::PermissionDenied(msg)) if msg.contains("SCP-ECON-12069")),
            "a non-member issuer must be rejected with SCP-ECON-12069, got {result:?}"
        );
        assert!(
            !cell
                .governance
                .revoked_spending_ucan_cids
                .contains("revoked-cid")
        );
    }

    /// Invariant 3a: a revoker who is BOTH the issuer AND a current member is
    /// authorized — the CID lands in the gate.
    #[tokio::test]
    async fn revoke_allows_member_issuer() {
        let deps = build_deps().await;
        // The authorized path proceeds to append the audit leaf — initialize the
        // context's event log so that Step 2 succeeds.
        deps.event_log.init_event_log(&CTX_BYTES).await.unwrap();
        let mut cell = seed_cell(&[PAYER]);
        revoke(&mut cell, &deps, PAYER, PAYER)
            .await
            .expect("a member issuer must be authorized to revoke");
        assert!(
            cell.governance
                .revoked_spending_ucan_cids
                .contains("revoked-cid"),
            "an authorized revoke must insert the CID into the gate"
        );
    }

    /// The scope-context creator remains allowed even when NOT a listed member
    /// (creator exemption on the 3a gate).
    #[tokio::test]
    async fn revoke_allows_creator_even_when_not_a_member() {
        let deps = build_deps().await;
        deps.event_log.init_event_log(&CTX_BYTES).await.unwrap();
        // ADMIN is the creator but is NOT added to the membership set here.
        let mut cell = seed_cell(&[]);
        revoke(&mut cell, &deps, PAYER, ADMIN)
            .await
            .expect("the scope-context creator must remain allowed even if not a member");
        assert!(
            cell.governance
                .revoked_spending_ucan_cids
                .contains("revoked-cid"),
            "the creator's revoke must insert the CID into the gate"
        );
    }
}
