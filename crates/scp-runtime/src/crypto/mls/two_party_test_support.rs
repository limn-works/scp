//! Shared two-party joined-pair bootstrap for provider-level unit tests.
//!
//! [`stand_up_two_party`] stands up Alice (creator) and Bob (joiner) over the
//! REAL end-to-end join path — Bob reserves a `KeyPackage` from his own
//! `KeyPackageStoreActor`, Alice adds that KP and emits a Welcome, and Bob
//! confirms the join at the PROVIDER level (the real fused `ConfirmConsume` join
//! → the joined `ScpMlsGroup`) and installs it via `install_joined_group`. It
//! deliberately does NOT drive the full [`Supervisor::spawn_actor_from_welcome`]
//! entrypoint, which moves the joiner's crypto ONE-WAY into a spawned actor
//! (ADR-049 PR-7 C2) — this fixture must return providers that still OWN their
//! per-context crypto so consumers can `take_crypto_state` each onto an actor.
//!
//! Alice is a BARE `MlsCryptoProvider` that hand-seals the bundle (no creator
//! `Supervisor` needed); Bob is driven through a real joiner `Supervisor`. After
//! the join, Bob PULLS Alice's sender key via the §9.16.2 request/response
//! protocol (the provider PUSH drain is deleted post-ADR-049 PR-7) so Bob can
//! decrypt Alice's application sends — the exact behaviour the H9
//! receive-ceiling fixtures and the app-data / agent-binding pipeline fixtures
//! depend on.
//!
//! The helper is SYNC (its callers are sync `#[test]` functions) and drives the
//! async join on an internal current-thread runtime. After the join the joiner's
//! MLS group lives in Bob's provider (`install_joined_group`), so each returned
//! `Arc<MlsCryptoProvider>` still owns its per-context crypto material and can be
//! destructively `take_crypto_state`'d onto the actor seam (where the deleted
//! steady-state twins now live) even after the `Supervisor` and runtime drop.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// `spawn_actor_from_welcome` returns a deliberately large state-building future;
// this helper awaits it directly inside `block_on`, so allow the large-future
// lint module-wide rather than box the single call site.
#![allow(clippy::large_futures)]

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use scp_did::DID;
use scp_platform::KeyCustody;
use scp_platform::testing::{InMemoryKeyCustody, InMemoryStorage};
use scp_protocol::context::governance::KeyResolver;
use scp_protocol::context::roles::{Capability, CapabilityCeiling};
use scp_protocol::context::{ContextMode, ContextParams, ScpContextExtension};
use zeroize::Zeroizing;

use super::provider::MlsCryptoProvider;
use super::storage_adapter::{OpenMlsStorageAdapter, SpawnBlockingStorageAdapter};
use crate::context::builder::{
    ContextEventLogProvider, ContextTransportProvider, NotConfiguredTransportProvider,
};
use crate::context::providers::event_log::MerkleEventLogProvider;
use crate::context::supervisor::Supervisor;
use crate::context::supervisor::key_package_actor::KeyPackageCommand;

/// Alice's (creator) fixed bundle-signing key. The bootstrap resolver maps
/// `alice_did` to its verifying key so the joiner can verify the creator-signed
/// invitation bundle.
// `pub` (crate-internal via the `pub(crate)` module ceiling) so the seam-level
// e2e tests can sign Alice's inner application envelope with the SAME key the
// pair resolver maps `alice_did` to.
pub fn alice_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0xA1; 32])
}

/// Bob's (joiner) fixed #active key. Bob's custody imports THIS seed and the
/// resolver maps `bob_did` to its verifying key, so a bundle sealed to the
/// resolved #active opens with the identical private key.
fn bob_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0xB0; 32])
}

/// Resolves `alice_did` / `bob_did` to their fixed verifying keys (all else
/// `None`). The joiner verifies the creator (`alice`) signature; the seal
/// addresses the invitee (`bob`) #active key.
fn pair_resolver(alice_did: &str, bob_did: &str) -> KeyResolver {
    let alice = DID::from(alice_did);
    let bob = DID::from(bob_did);
    let alice_vk = alice_signing_key().verifying_key();
    let bob_vk = bob_signing_key().verifying_key();
    Arc::new(move |did: &DID, _| {
        if did == &alice {
            Some(alice_vk)
        } else if did == &bob {
            Some(bob_vk)
        } else {
            None
        }
    })
}

/// The joiner's legible context parameters (encrypted, single-admin) — the same
/// ceiling the creator commits into the group's `0xFF02` extension and the
/// joiner enforces on install.
fn joiner_params() -> ContextParams {
    ContextParams {
        mode: ContextMode::Encrypted,
        ceiling: vec![
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::RoleAssign,
            Capability::MemberInvite,
            Capability::MemberRemove,
            Capability::GovernancePropose,
            Capability::GovernanceVote,
            Capability::ContextClose,
        ],
        ..ContextParams::default()
    }
}

/// Builds the creator-committed `scp_context_params` (`0xFF02`) extension for a
/// ROOT context from `params`, committing `creator_did` (rule 8) exactly the way
/// the creator write path does — so a matching-`params` join verifies.
fn honest_ext(context_id: &str, creator_did: &str, params: &ContextParams) -> ScpContextExtension {
    ScpContextExtension::for_root(
        context_id.to_owned(),
        DID::from(creator_did),
        params.mode,
        &params.governance,
        params.ceiling_policy,
        &CapabilityCeiling::new(params.ceiling.iter().cloned()),
    )
    .expect("honest context extension serializes")
}

fn fresh_mls_storage() -> Arc<dyn OpenMlsStorageAdapter> {
    Arc::new(SpawnBlockingStorageAdapter::new(Arc::new(
        InMemoryStorage::new(),
    )))
}

/// Builds Bob's real joiner `Supervisor` (real MLS crypto, not-configured
/// transport, in-memory event log + MLS storage, the `pair_resolver`). Returns
/// the supervisor and a clone of Bob's crypto provider.
// `pub` (not `pub(crate)`) inside this `pub(crate)` test-only module: the module
// gate already caps the effective visibility to the crate, and
// `clippy::redundant_pub_crate` (nursery) rejects a redundant `pub(crate)`.
pub fn bob_supervisor(
    bob_did: &str,
    resolver: KeyResolver,
) -> (Arc<Supervisor>, Arc<MlsCryptoProvider>) {
    let crypto = Arc::new(MlsCryptoProvider::new(
        bob_did.to_owned(),
        Arc::new(scp_clock::SystemClock),
    ));
    let transport: Box<dyn ContextTransportProvider> = Box::new(NotConfiguredTransportProvider);
    let event_log: Box<dyn ContextEventLogProvider> = Box::new(MerkleEventLogProvider::new());
    let sup = Supervisor::with_providers(
        Arc::clone(&crypto),
        transport,
        event_log,
        resolver,
        None,
        None,
        None,
        None,
        fresh_mls_storage(),
    );
    (sup, crypto)
}

/// Stands up a two-party joined pair (Alice creator, Bob joiner) over the REAL
/// reserve → creator-add → `ConfirmConsume` → `install_joined_group` path, then
/// has Bob PULL Alice's sender key via the §9.16.2 request/response protocol
/// (Bob's sender-key high-water for Alice becomes epoch 1). Returns
/// `(alice, bob, ctx_bytes)` where both providers still OWN the per-context
/// crypto for the group keyed by `context_id_bytes(ctx_str)`.
///
/// # Panics
///
/// Panics if any step of the join fails — this is a test-only fixture, so a
/// setup failure is a test failure.
// `pub` (not `pub(crate)`) inside this `pub(crate)` test-only module: the module
// gate already caps the effective visibility to the crate, and `clippy::
// redundant_pub_crate` (nursery) rejects a redundant `pub(crate)` under an
// already-crate-scoped module.
pub fn stand_up_two_party(
    ctx_str: &str,
    alice_did: &str,
    bob_did: &str,
) -> (Arc<MlsCryptoProvider>, Arc<MlsCryptoProvider>, [u8; 32]) {
    let ctx_bytes = scp_protocol::context::context_id_bytes(ctx_str);

    tokio::runtime::Builder::new_current_thread() // ci-allow: block-on: test-only two-party fixture drives async MLS provider calls from sync #[test] callers; not a production async bridge
        .enable_all()
        .build()
        .unwrap()
        .block_on(async move {
            let bob = DID::from(bob_did);

            // Bob's joiner supervisor + a clone of his provider (holds the group
            // after the join and after the supervisor is dropped).
            let (bob_sup, bob_crypto) = bob_supervisor(bob_did, pair_resolver(alice_did, bob_did));

            // Publish Bob's OWN provider wrapping keypair BEFORE the KeyPackage
            // store spawns, so the pooled KP's `0xFF01` wrapping-leaf pubkey and
            // the secret `bob_crypto` opens distributed sender keys with stay the
            // SAME keypair across the reserve → spawn-from-Welcome migration
            // (`wrapping_keypair_snapshot`). This makes Alice's sender-key
            // distribution — a real X25519 DH to that wrapping key — decryptable by
            // Bob. The KP also declares `0xFF02` (`scp_context_params`)
            // unconditionally.
            let (bob_wrap_public, bob_wrap_secret) = bob_crypto.wrapping_keypair_snapshot();
            bob_sup
                .set_wrapping_keys(
                    bob.clone(),
                    bob_wrap_public.to_vec(),
                    Zeroizing::new(bob_wrap_secret.to_vec()),
                )
                .await
                .expect("publish bob's wrapping key");
            let (reservation_id, kp_public_bytes) = bob_sup
                .reserve_key_package(bob.clone())
                .await
                .expect("bob reserves a real KeyPackage from his own store");

            // Alice (bare creator provider) creates the honest SCP context group
            // (committing her DID + params into `0xFF02`), mints her sender key,
            // and adds Bob's reserved KP — producing the real Welcome.
            let params = joiner_params();
            let alice_crypto = Arc::new(MlsCryptoProvider::new(
                alice_did.to_owned(),
                Arc::new(scp_clock::SystemClock),
            ));
            alice_crypto
                .create_mls_group_with_context(&ctx_bytes, &honest_ext(ctx_str, alice_did, &params))
                .expect("alice creates the SCP context group (0xFF02)");
            alice_crypto
                .generate_sender_key(&ctx_bytes)
                .expect("alice mints her sender key");
            let add_output = alice_crypto
                .add_member(&ctx_bytes, bob_did, Some(&kp_public_bytes))
                .expect("alice adds bob's reserved key package");

            // Bob's #active custody holds the SAME seed the resolver returns for
            // `bob_did` — used below to sign Bob's §9.16.2 sender-key pull request.
            let bob_custody = InMemoryKeyCustody::new();
            let bob_handle = bob_custody
                .import_ed25519_signing_key(&Zeroizing::new(bob_signing_key().to_bytes()))
                .await
                .expect("import bob's #active seed into custody");

            // Bob confirms the join at the PROVIDER level (the real fused
            // `ConfirmConsume` join → the joined `ScpMlsGroup`) and installs it
            // into his provider via `install_joined_group`, KEEPING the crypto
            // provider-resident. The full `spawn_actor_from_welcome` entrypoint
            // moves the crypto ONE-WAY into a spawned actor (ADR-049 PR-7 C2),
            // which would leave `bob_crypto` empty; this fixture must return
            // providers that still OWN their per-context crypto so consumers'
            // `take_crypto_state` seam can move each into an actor exactly once.
            let bob_deps = bob_sup
                .build_actor_deps(&bob)
                .await
                .expect("build bob's actor deps");
            let joined_group = bob_deps
                .key_package_store
                .send(|reply| KeyPackageCommand::ConfirmConsume {
                    reservation_id,
                    welcome_bytes: add_output.welcome_bytes,
                    reply,
                })
                .await
                .expect("bob confirms the join and receives the joined MLS group");
            bob_crypto
                .install_joined_group(&ctx_bytes, joined_group)
                .expect("install bob's joined group into his provider");

            // Bob mints his own sender key (the install already seeded one; this
            // rotates it to a fresh value, matching the old fixture), then Bob
            // acquires Alice's sender key so he can decrypt her application sends.
            bob_crypto
                .generate_sender_key(&ctx_bytes)
                .expect("bob mints his sender key");

            // Bob PULLS Alice's sender key via the §9.16.2 request/response
            // protocol. Post-ADR-049 PR-7 the provider PUSH `drain_pending_
            // sender_key_messages` twin is DELETED; the pull path uses only the
            // retained receive-side provider methods (`handle_sender_key_request`
            // / `store_member_sender_key` / `set_sender_key_unchecked`) and keeps
            // BOTH parties as providers so the golden `take_into_actor` seam can
            // destructively move each into an actor exactly once.
            let request = crate::crypto::sender_keys::key_protocol::request_sender_key(
                &bob_custody,
                &bob_handle,
                bob_did,
                alice_did,
                0, // bob's initial sender-key epoch (not validated by the responder)
                &scp_clock::SystemClock,
            )
            .await
            .expect("bob builds a signed sender-key request for alice's key");
            let blocked = std::collections::HashSet::new();
            let response_bytes = alice_crypto
                .handle_sender_key_request(
                    &ctx_bytes,
                    &request.request_message,
                    bob_signing_key().verifying_key().as_bytes(),
                    &blocked,
                )
                .expect("alice accepts bob's sender-key request (H1 membership gate)")
                .expect("alice returns a response for a non-blocked member");
            let response: scp_protocol::crypto::sender_keys::SenderKeyResponse =
                rmp_serde::from_slice(&response_bytes).expect("decode alice's SenderKeyResponse");
            let ctx_id_hex = hex::encode(ctx_bytes);
            let alice_key = crate::crypto::sender_keys::key_protocol::open_sender_key_response(
                &bob_custody,
                &request.wrapping_key_handle,
                &ctx_id_hex,
                &response,
            )
            .await
            .expect("bob opens alice's HPKE-sealed sender key");
            // ADR-049 PR-6: store returns the authenticated (key, epoch); install
            // is a separate explicit `set_sender_key_unchecked`.
            let (alice_key, _epoch) = bob_crypto
                .store_member_sender_key(&ctx_bytes, alice_did, alice_key, response.epoch)
                .expect("bob verifies + returns alice's pulled sender key");
            bob_crypto.set_sender_key_unchecked(&ctx_bytes, alice_did, alice_key);

            // Drop the joiner supervisor; the installed group persists in
            // `bob_crypto` (a separate `Arc` clone of the same provider).
            drop(bob_sup);

            (alice_crypto, bob_crypto, ctx_bytes)
        })
}
