//! Shared two-party joined-pair bootstrap for provider-level unit tests.
//!
//! [`stand_up_two_party`] stands up Alice (creator) and Bob (joiner) over the
//! REAL end-to-end join path — Bob reserves a `KeyPackage` from his own
//! `KeyPackageStoreActor`, Alice adds that KP and emits a Welcome, Alice signs
//! and HPKE-seals a §5.12.3 [`InvitationBundle`], and Bob installs the joined
//! group through [`Supervisor::spawn_actor_from_welcome`]. It replaces the
//! legacy TEST-ONLY `MlsCryptoProvider::prepare_key_package_for_join` /
//! `MlsCryptoProvider::join_from_welcome` shortcut the old fixtures used (those
//! provider methods are being retired).
//!
//! Alice is a BARE `MlsCryptoProvider` that hand-seals the bundle (no creator
//! `Supervisor` needed); Bob is driven through a real joiner `Supervisor`. After
//! the join, Alice distributes her sender key to Bob (setting Bob's sender-key
//! high-water for Alice to epoch 1) — the exact behaviour the H9 receive-ceiling
//! fixtures and the app-data / agent-binding pipeline fixtures depend on.
//!
//! The helper is SYNC (its callers are sync `#[test]` functions) and drives the
//! async join on an internal current-thread runtime. After the join the joiner's
//! MLS group lives in Bob's provider (`install_joined_group`), so the returned
//! `Arc<MlsCryptoProvider>` pair `seal`/`open`/`export_crypto_state` even after
//! the `Supervisor` and runtime are dropped.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// `spawn_actor_from_welcome` returns a deliberately large state-building future;
// this helper awaits it directly inside `block_on`, so allow the large-future
// lint module-wide rather than box the single call site.
#![allow(clippy::large_futures)]

use std::sync::Arc;

use ed25519_dalek::{Signer as _, SigningKey};
use scp_did::DID;
use scp_platform::KeyCustody;
use scp_platform::in_memory::InMemoryStorage;
use scp_platform::testing::InMemoryKeyCustody;
use scp_protocol::context::governance::KeyResolver;
use scp_protocol::context::roles::{Capability, CapabilityCeiling};
use scp_protocol::context::{
    ContextMode, ContextParams, InvitationBundle, InvitationKeyMaterial, ScpContextExtension,
};
use scp_protocol::crypto::envelope_seal::{ed25519_pubkey_to_x25519, hpke_seal_invitation};
use zeroize::Zeroizing;

use super::provider::MlsCryptoProvider;
use super::storage_adapter::{OpenMlsStorageAdapter, SpawnBlockingStorageAdapter};
use crate::context::builder::{
    ContextEventLogProvider, ContextTransportProvider, NotConfiguredTransportProvider,
};
use crate::context::invitation_helpers::{SnapshotRuntimeFacts, build_metadata_snapshot};
use crate::context::providers::event_log::MerkleEventLogProvider;
use crate::context::supervisor::Supervisor;
use crate::context::supervisor::WelcomeJoinRequest;
use crate::context::supervisor::key_package_actor::ReservationId;

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

/// A REAL §9.10.4 local pseudonym (a distinctive non-`[0u8; 32]` constant). The
/// spawn-from-Welcome entrypoint rejects `None` for the encrypted join surface.
const PSEUDONYM: [u8; 32] = [0x5a; 32];

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

/// Builds a signed [`InvitationBundle`] (creator = `signer`) carrying `params`,
/// `context_id`, and `welcome_bytes`, with a structural snapshot copied verbatim
/// from `params`. The signature is over the §5.12.3.1 signing hash.
fn signed_bundle(
    signer: &SigningKey,
    creator_did: &DID,
    context_id: &str,
    params: &ContextParams,
    welcome_bytes: Vec<u8>,
) -> InvitationBundle {
    let facts = SnapshotRuntimeFacts {
        member_count: Some(1),
        creator_did: Some(creator_did.clone()),
        ..SnapshotRuntimeFacts::default()
    };
    let mut bundle = InvitationBundle {
        context_id: context_id.to_owned(),
        creator_did: creator_did.clone(),
        relay_urls: vec![],
        welcome_message: welcome_bytes,
        key_material: InvitationKeyMaterial {
            context_metadata_key: [7u8; 32],
            sender_key_seed: None,
        },
        context_params: params.clone(),
        metadata_snapshot: build_metadata_snapshot(params, facts),
        signature: vec![],
    };
    let hash = bundle
        .invitation_bundle_signing_hash()
        .expect("signing hash");
    bundle.signature = signer.sign(&hash).to_bytes().to_vec();
    bundle
}

/// HPKE-seals a validly-signed bundle into a reshaped [`WelcomeJoinRequest`]
/// addressed to `recipient_x25519`, with a real pseudonym.
fn seal_join_request(
    signer: &SigningKey,
    creator_did: &DID,
    context_id: &str,
    params: &ContextParams,
    welcome_bytes: Vec<u8>,
    recipient_x25519: &[u8; 32],
    reservation_id: ReservationId,
) -> WelcomeJoinRequest {
    let bundle = signed_bundle(signer, creator_did, context_id, params, welcome_bytes);
    let wire = bundle.to_wire_bytes().expect("bundle serializes");
    let (ct, enc) = hpke_seal_invitation(&wire, recipient_x25519, context_id, creator_did.as_ref())
        .expect("HPKE seal");
    WelcomeJoinRequest {
        context_id: context_id.to_owned(),
        creator_did: creator_did.clone(),
        sealed_bundle_enc: enc,
        sealed_bundle_ct: ct,
        reservation_id,
        local_pseudonym: Some(PSEUDONYM),
    }
}

/// Parameterized seal for callers that already hold a LIVE creator `Supervisor`
/// (e.g. the agent-binding pipeline fixture, which drives `sup.send_message`).
/// Signs a §5.12.3 [`InvitationBundle`] with `creator_signing_key`, seals it to
/// `recipient_active_verifying_key` (an Ed25519 #active key, mapped to X25519
/// here), and returns the reshaped [`WelcomeJoinRequest`]. The joiner's
/// `Supervisor` must carry a resolver that maps `creator_did` to
/// `creator_signing_key.verifying_key()` so the creator signature verifies.
///
/// # Panics
///
/// Panics if the Ed25519→X25519 mapping, bundle serialization, or HPKE seal
/// fails — this is a test-only helper.
// Gated to `feature = "testing"` to match its sole caller — the
// `#[cfg(feature = "testing")]` agent-binding pipeline fixture. Under a plain
// `cfg(test)` build (the provider-level fixtures) it has no caller, so gating it
// alongside the caller avoids a dead-code warning while keeping the shared
// `stand_up_two_party` path available to both.
#[cfg(feature = "testing")]
#[allow(clippy::too_many_arguments)]
pub fn seal_welcome_for_joiner(
    creator_signing_key: &SigningKey,
    creator_did: &DID,
    context_id: &str,
    params: &ContextParams,
    welcome_bytes: Vec<u8>,
    recipient_active_verifying_key: &[u8; 32],
    reservation_id: ReservationId,
    local_pseudonym: [u8; 32],
) -> WelcomeJoinRequest {
    let recipient_x25519 = ed25519_pubkey_to_x25519(recipient_active_verifying_key)
        .expect("map recipient's #active ed25519 key to x25519");
    let bundle = signed_bundle(
        creator_signing_key,
        creator_did,
        context_id,
        params,
        welcome_bytes,
    );
    let wire = bundle.to_wire_bytes().expect("bundle serializes");
    let (ct, enc) =
        hpke_seal_invitation(&wire, &recipient_x25519, context_id, creator_did.as_ref())
            .expect("HPKE seal");
    WelcomeJoinRequest {
        context_id: context_id.to_owned(),
        creator_did: creator_did.clone(),
        sealed_bundle_enc: enc,
        sealed_bundle_ct: ct,
        reservation_id,
        local_pseudonym: Some(local_pseudonym),
    }
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
/// reserve → creator-add → sign → HPKE-seal → `spawn_actor_from_welcome` path,
/// then distributes Alice's sender key to Bob (Bob's sender-key high-water for
/// Alice becomes epoch 1). Returns `(alice, bob, ctx_bytes)` where both
/// providers `seal`/`open` the group keyed by `context_id_bytes(ctx_str)`.
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
            let alice = DID::from(alice_did);
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
            // `bob_did`, so the bundle sealed to that resolved #active opens.
            let bob_custody = InMemoryKeyCustody::new();
            let bob_handle = bob_custody
                .import_ed25519_signing_key(&Zeroizing::new(bob_signing_key().to_bytes()))
                .await
                .expect("import bob's #active seed into custody");

            // Hand-seal the creator-signed §5.12.3 bundle to Bob's #active and
            // install the joined group into Bob's provider via the real spawn path.
            let bob_recipient =
                ed25519_pubkey_to_x25519(bob_signing_key().verifying_key().as_bytes())
                    .expect("map bob's #active ed25519 key to x25519");
            let req = seal_join_request(
                &alice_signing_key(),
                &alice,
                ctx_str,
                &params,
                add_output.welcome_bytes,
                &bob_recipient,
                reservation_id,
            );
            bob_sup
                .spawn_actor_from_welcome(bob.clone(), &bob_custody, &bob_handle, req)
                .await
                .expect("bob installs the joined group from alice's real invitation");

            // Bob mints his own sender key (the install already seeded one at epoch
            // 1; this rotates it to a fresh value, matching the old fixture), then
            // Alice distributes HER sender key to Bob so Bob's sender-key high-water
            // for Alice becomes epoch 1 (the H9 ceiling anchor) and Bob can decrypt
            // Alice's application sends.
            bob_crypto
                .generate_sender_key(&ctx_bytes)
                .expect("bob mints his sender key");
            alice_crypto
                .distribute_sender_key(&ctx_bytes, bob_did)
                .expect("alice distributes her sender key to bob");
            for (_target, msg) in alice_crypto
                .drain_pending_sender_key_messages(&ctx_bytes)
                .expect("drain alice's pending sender-key messages")
            {
                let (key, _epoch) = bob_crypto
                    .process_incoming_sender_key(&ctx_bytes, alice_did, &msg)
                    .expect("bob processes alice's distributed sender key");
                // ADR-049 PR-6: install the authenticated key (decomposed
                // process_incoming no longer installs).
                bob_crypto.set_sender_key_unchecked(&ctx_bytes, alice_did, key);
            }

            // Drop the joiner supervisor; the installed group persists in
            // `bob_crypto` (a separate `Arc` clone of the same provider).
            drop(bob_sup);

            (alice_crypto, bob_crypto, ctx_bytes)
        })
}
