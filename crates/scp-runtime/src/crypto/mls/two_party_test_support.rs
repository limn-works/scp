//! Shared two-party joined-pair bootstrap for actor-level crypto unit tests.
//!
//! [`stand_up_two_party`] stands up Alice (creator) and Bob (joiner) over the
//! REAL end-to-end join path — Bob reserves a `KeyPackage` from his own
//! `KeyPackageStoreActor`, Alice adds that KP on her OWNED actor state and emits
//! a Welcome, and Bob confirms the join at the PROVIDER level (the real fused
//! `ConfirmConsume` join → the joined `ScpMlsGroup`). It deliberately does NOT
//! drive the full [`Supervisor::spawn_actor_from_welcome`] entrypoint — this
//! fixture births the pair directly onto actor-owned state so consumers receive
//! ready-to-seal [`PerContextState`]s, not providers to move.
//!
//! ADR-049 #2148 (birth-into-actor) slice 2: the pair is born DIRECTLY onto
//! actor-owned [`PerContextState`] via the owned-return MLS constructors
//! ([`MlsCryptoProvider::create_mls_group_with_context_owned`] /
//! [`MlsCryptoProvider::install_joined_group_owned`]) plus the production
//! [`PerContextState::seed_encrypted_crypto_from_owned`] seed primitive — never
//! through a provider-resident insert + `take_crypto_state` round-trip. The
//! returned providers are kept ONLY as the node-resident source of each party's
//! X25519 wrapping keypair (`wrapping_keypair_snapshot`); they never own the
//! per-context crypto.
//!
//! Alice creates the honest SCP context group (`0xFF02`) on her owned state and
//! adds Bob's reserved KP through the actor-native
//! [`PerContextState::add_member`]; Bob is driven through a real joiner
//! `Supervisor`. After the join, Bob PULLS Alice's sender key via the §9.16.2
//! request/response protocol answered through the ACTOR-native
//! [`ContextCryptoState::handle_sender_key_request`] (which emits the wrapped
//! `SenderKeyDistributionMessage::KeyResponse` envelope), so Bob can decrypt
//! Alice's application sends — the exact behaviour the H9 receive-ceiling
//! fixtures and the app-data / agent-binding pipeline fixtures depend on.
//!
//! The helper is SYNC (its callers are sync `#[test]` functions) and drives the
//! async join on an internal current-thread runtime. It returns
//! `(alice_provider, alice_state, bob_provider, bob_state, ctx_bytes)`: each
//! [`PerContextState`] already OWNS its per-context crypto (seeded from the
//! owned constructor), and each `Arc<MlsCryptoProvider>` is retained solely for
//! its node-resident wrapping keypair.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// `spawn_actor_from_welcome` returns a deliberately large state-building future;
// this helper awaits it directly inside `block_on`, so allow the large-future
// lint module-wide rather than box the single call site.
#![allow(clippy::large_futures)]

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use scp_clock::Clock as _;
use scp_did::DID;
use scp_platform::KeyCustody;
use scp_platform::in_memory::InMemoryStorage;
use scp_platform::testing::InMemoryKeyCustody;
use scp_protocol::context::governance::KeyResolver;
use scp_protocol::context::roles::{Capability, CapabilityCeiling};
use scp_protocol::context::{ContextMode, ContextParams, ScpContextExtension};
use scp_protocol::crypto::sender_keys::SenderKeyDistributionMessage;
use zeroize::Zeroizing;

use crate::context::actor::{ContextCryptoState, ContextModeState, PerContextState};

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
// `pub(crate)` (crate-internal — seam-level e2e tests sign Bob's inner envelopes /
// sender-key requests with the SAME key the pair resolver maps `bob_did` to). The
// explicit `pub(crate)` keeps this test helper out of the source-text
// `check-cross-layer` gate with no PR-body exemption; `redundant_pub_crate` is a
// false positive because the enclosing `two_party_test_support` module is already
// `pub(crate)` yet the helper is reached crate-wide.
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn bob_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0xB0; 32])
}

/// Resolves `alice_did` / `bob_did` to their fixed verifying keys (all else
/// `None`). The joiner verifies the creator (`alice`) signature; the seal
/// addresses the invitee (`bob`) #active key. `pub(crate)` (crate-internal) so
/// seam-level e2e tests can hand a real DID→key resolver to a production
/// `ActorDeps` (e.g. to verify a §9.16.2 sender-key request signature). The
/// explicit `pub(crate)` keeps this test helper out of the source-text
/// `check-cross-layer` gate with no PR-body exemption; `redundant_pub_crate` is a
/// false positive (the enclosing module is `pub(crate)`, the helper is reached
/// crate-wide).
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn pair_resolver(alice_did: &str, bob_did: &str) -> KeyResolver {
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

/// Borrows the Encrypted-mode [`ContextCryptoState`] out of an actor
/// [`PerContextState`] (panics on Broadcast) — the seam the actor-native
/// answer half [`ContextCryptoState::handle_sender_key_request`] runs on.
fn encrypted_crypto_mut(state: &mut PerContextState) -> &mut ContextCryptoState {
    match &mut state.mode {
        ContextModeState::Encrypted(crypto) => crypto,
        ContextModeState::Broadcast(_) => panic!("expected encrypted mode"),
    }
}

/// Stands up a two-party joined pair (Alice creator, Bob joiner) over the REAL
/// reserve → creator-add → `ConfirmConsume` join path, born DIRECTLY onto
/// actor-owned [`PerContextState`] via the owned-return constructors + the
/// production `seed_encrypted_crypto_from_owned` primitive, then has Bob PULL
/// Alice's sender key via the §9.16.2 request/response protocol answered through
/// the ACTOR-native [`ContextCryptoState::handle_sender_key_request`] (Bob's
/// installed sender-key for Alice becomes epoch 1). Returns
/// `(alice_provider, alice_state, bob_provider, bob_state, ctx_bytes)` where each
/// [`PerContextState`] OWNS the per-context crypto for the group keyed by
/// `context_id_bytes(ctx_str)` and each provider is retained solely for its
/// node-resident wrapping keypair.
///
/// # Panics
///
/// Panics if any step of the join fails — this is a test-only fixture, so a
/// setup failure is a test failure.
// `pub` (not `pub(crate)`) inside this `pub(crate)` test-only module: the module
// gate already caps the effective visibility to the crate, and `clippy::
// redundant_pub_crate` (nursery) rejects a redundant `pub(crate)` under an
// already-crate-scoped module.
// One cohesive bootstrap flow (reserve → owned-birth alice → actor add_member →
// confirm-join → owned-birth bob → §9.16.2 pull) driven end to end; splitting it
// would obscure the linear join narrative, so allow the length.
#[allow(clippy::too_many_lines)]
pub fn stand_up_two_party(
    ctx_str: &str,
    alice_did: &str,
    bob_did: &str,
) -> (
    Arc<MlsCryptoProvider>,
    PerContextState,
    Arc<MlsCryptoProvider>,
    PerContextState,
    [u8; 32],
) {
    let ctx_bytes = scp_protocol::context::context_id_bytes(ctx_str);

    tokio::runtime::Builder::new_current_thread() // ci-allow: block-on: test-only two-party fixture drives async MLS provider calls from sync #[test] callers; not a production async bridge
        .enable_all()
        .build()
        .unwrap()
        .block_on(async move {
            let clock = scp_clock::SystemClock;
            let bob = DID::from(bob_did);

            // Bob's joiner supervisor + a clone of his provider. The provider is
            // retained ONLY as the node-resident source of Bob's X25519 wrapping
            // keypair (`wrapping_keypair_snapshot`); the joined crypto is born onto
            // Bob's actor state below, never installed into the provider.
            let (bob_sup, bob_crypto) = bob_supervisor(bob_did, pair_resolver(alice_did, bob_did));

            // Publish Bob's OWN provider wrapping keypair BEFORE the KeyPackage
            // store spawns, so the pooled KP's `0xFF01` wrapping-leaf pubkey and
            // the secret `bob_crypto` opens distributed sender keys with stay the
            // SAME keypair across the reserve → join migration
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

            // Alice (bare creator provider) BIRTHS the honest SCP context group
            // (committing her DID + params into `0xFF02`) DIRECTLY onto owned
            // actor state via `create_mls_group_with_context_owned` + the
            // production seed primitive — no provider-resident insert. The owned
            // constructor mints her sender key (epoch 1).
            let params = joiner_params();
            let alice_crypto = Arc::new(MlsCryptoProvider::new(
                alice_did.to_owned(),
                Arc::new(scp_clock::SystemClock),
            ));
            let alice_owned = alice_crypto
                .create_mls_group_with_context_owned(&honest_ext(ctx_str, alice_did, &params))
                .expect("alice births the owned SCP context group (0xFF02)");
            let mut alice_state = PerContextState::new_for_test_encrypted(
                ctx_bytes,
                0,
                DID::from(alice_did.to_owned()),
            );
            alice_state.seed_encrypted_crypto_from_owned(alice_owned);

            // Alice adds Bob's reserved KP through the ACTOR-native `add_member`
            // on her OWNED group — producing the real Welcome and advancing her
            // local tree to include Bob (so the §9.16.2 H1 membership gate below
            // sees Bob as a current member).
            let add_output = alice_state
                .add_member(bob_did, Some(&kp_public_bytes), &clock)
                .expect("alice adds bob's reserved key package on her owned group");

            // Bob's #active custody holds the SAME seed the resolver returns for
            // `bob_did` — used below to sign Bob's §9.16.2 sender-key pull request.
            let bob_custody = InMemoryKeyCustody::new();
            let bob_handle = bob_custody
                .import_ed25519_signing_key(&Zeroizing::new(bob_signing_key().to_bytes()))
                .await
                .expect("import bob's #active seed into custody");

            // Bob confirms the join at the PROVIDER level (the real fused
            // `ConfirmConsume` join → the joined `ScpMlsGroup`), then BIRTHS the
            // joined crypto DIRECTLY onto owned actor state via
            // `install_joined_group_owned` + the production seed primitive — no
            // provider-resident insert, no `take_crypto_state` round-trip. The
            // owned constructor mints Bob's own sender key (epoch 1) locally
            // (§9.16.1 — the Welcome carries no sender key).
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
            let bob_owned = bob_crypto.install_joined_group_owned(joined_group);
            let mut bob_state = PerContextState::new_for_test_encrypted(
                ctx_bytes,
                0,
                DID::from(bob_did.to_owned()),
            );
            bob_state.seed_encrypted_crypto_from_owned(bob_owned);

            // Bob PULLS Alice's sender key via the §9.16.2 request/response
            // protocol, answered through the ACTOR-native
            // `ContextCryptoState::handle_sender_key_request` on Alice's seeded
            // state (H1 membership gate reads Alice's MLS group tree). The answer
            // is the wrapped `SenderKeyDistributionMessage::KeyResponse` envelope
            // (the actor wire shape), which Bob decodes, opens via his ephemeral
            // wrapping key in custody, and installs on his actor state through the
            // actor-native `set_sender_key_unchecked` seam.
            let request = crate::crypto::sender_keys::key_protocol::request_sender_key(
                &bob_custody,
                &bob_handle,
                bob_did,
                alice_did,
                0, // bob's initial sender-key epoch (not validated by the responder)
                &clock,
            )
            .await
            .expect("bob builds a signed sender-key request for alice's key");
            let blocked = std::collections::HashSet::new();
            let response_bytes = encrypted_crypto_mut(&mut alice_state)
                .handle_sender_key_request(
                    &ctx_bytes,
                    alice_did,
                    clock.now_secs(),
                    &request.request_message,
                    bob_signing_key().verifying_key().as_bytes(),
                    &blocked,
                )
                .expect("alice accepts bob's sender-key request (H1 membership gate)")
                .expect("alice returns a response for a non-blocked member");
            // Decode the WRAPPED `SenderKeyDistributionMessage::KeyResponse`
            // envelope the actor answer half emits (`to_bytes`), then extract the
            // inner `SenderKeyResponse` to open via Bob's ephemeral wrapping key.
            let response = match SenderKeyDistributionMessage::from_bytes(&response_bytes)
                .expect("decode alice's SenderKeyDistributionMessage envelope")
            {
                SenderKeyDistributionMessage::KeyResponse(response) => response,
                other => panic!("expected a KeyResponse envelope, got {other:?}"),
            };
            let ctx_id_hex = hex::encode(ctx_bytes);
            let alice_key = crate::crypto::sender_keys::key_protocol::open_sender_key_response(
                &bob_custody,
                &request.wrapping_key_handle,
                &ctx_id_hex,
                &response,
            )
            .await
            .expect("bob opens alice's HPKE-sealed sender key");
            bob_state.set_sender_key_unchecked(alice_did, alice_key);

            // Drop the joiner supervisor; each party's crypto lives on its owned
            // actor state, independent of the supervisor and runtime.
            drop(bob_sup);

            (alice_crypto, alice_state, bob_crypto, bob_state, ctx_bytes)
        })
}
