//! Tests for [`Supervisor::spawn_actor_from_welcome`] (ADR-049 Phase 2J,
//! spawn-from-Welcome; Deferred Work #1).
//!
//! These exercise the REAL end-to-end join path — the joiner reserves a
//! `KeyPackage` from its own `KeyPackageStoreActor`, a creator adds that KP and
//! emits a Welcome, and the joiner spawns a per-context actor from that Welcome
//! through the fused `ConfirmConsume` → `install_joined_group` →
//! persist-before-ack → spawn ladder. The pre-2J gap (a Welcome-joined node
//! could DECRYPT but had no actor-backed send `ContextHandle`, so any send
//! failed closed with "context not found in node's handles") is closed here:
//! after `spawn_actor_from_welcome` the joiner is a registered, send-capable
//! participant (`member_count` returns `Some`, not the unregistered `None`),
//! its installed MLS group processes creator traffic AND encrypts joiner
//! traffic the creator decrypts, and the initial keyed snapshot is persisted
//! fail-closed BEFORE the actor is reachable (a persist failure leaves NO live
//! half-keyed actor — Decision 1/8/9).

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// `spawn_actor_from_welcome` returns a deliberately large state-building future
// (~16 KB — the Welcome-derived `PerContextState`); production callers `Box::pin`
// it at the `SupervisorHandle` seam. These tests await it directly, so allow the
// large-future lint module-wide rather than box every call site.
#![allow(clippy::large_futures)]
// The reshaped join tests are linear integration fixtures (reserve → creator-add →
// sign → HPKE-seal → open → spawn → assert); several run past 100 lines and read
// clearer unsplit than fragmented across per-step helpers, so allow the
// line-count lint module-wide (these are test fixtures, not production handlers).
#![allow(clippy::too_many_lines)]
// The `FailingPersistence` double is stateless; the `RecordingPersistence` double
// (durable first-writer-wins test) backs its in-memory store with a lock-free
// `DashMap`/`DashSet` (matching the `CapturingPersistence` pattern), so it needs
// no `Mutex` and holds no guard across an `.await`.

use std::sync::Arc;

use ed25519_dalek::{Signer as _, SigningKey};
use scp_did::{DID, SigningKeyId};
use scp_platform::testing::{InMemoryKeyCustody, InMemoryStorage};
use scp_platform::{KeyCustody, KeyHandle, KeyType};
use scp_protocol::context::builder::OpenResult;
use scp_protocol::context::governance::KeyResolver;
use scp_protocol::context::roles::{Capability, CapabilityCeiling};
use scp_protocol::context::{
    CeilingPolicy, ContextMode, ContextParams, GovernanceModel, InvitationBundle,
    InvitationKeyMaterial, ScpContextExtension,
};
use scp_protocol::crypto::envelope_seal::{ed25519_pubkey_to_x25519, hpke_seal_invitation};
use zeroize::Zeroizing;

use super::key_package_actor::{KeyPackageCommand, ReservationId};
use super::{InviteMemberOutcome, MessageSigner, Supervisor, WelcomeJoinRequest};
use crate::context::builder::{
    ContextEventLogProvider, ContextTransportProvider, NotConfiguredTransportProvider,
};
use crate::context::invitation_helpers::{SnapshotRuntimeFacts, build_metadata_snapshot};
use crate::context::persistence::ContextPersistence;
use crate::context::providers::event_log::MerkleEventLogProvider;
use crate::context::state::context_id_to_bytes;
use crate::crypto::mls::provider::MlsCryptoProvider;
use crate::crypto::mls::storage_adapter::{OpenMlsStorageAdapter, SpawnBlockingStorageAdapter};

const ALICE_DID: &str = "did:dht:z6MkAliceSpawnFromWelcomeCreator";
const BOB_DID: &str = "did:dht:z6MkBobSpawnFromWelcomeJoiner";
/// Mallory (an in-group member / attacker) used by the BLACK-2J10-001-R
/// creator-substitution regression: she forges an invitation bundle naming
/// herself as `creator_did` and signs it with her OWN key.
const MALLORY_DID: &str = "did:dht:z6MkMalloryCreatorSubstitution";

/// Alice (creator) fixed signing key. `ALICE_DID` resolves to its verifying key
/// via [`pair_resolver`], so a joiner can verify the creator-signed invitation
/// bundle. Unrelated to the MLS group creator identity (which is the `ALICE_DID`
/// string) — this key only produces / is verified against the bundle signature.
fn alice_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0xA1; 32])
}

/// Bob (invitee) fixed signing key. Used by the `invite_member` round-trip
/// (Test M): `BOB_DID` resolves to its verifying key via [`pair_resolver`], and
/// Bob's #active custody imports the SAME seed (see [`bob_imported_custody`]) so
/// the key the creator seals to (resolved from `BOB_DID`) is exactly the key
/// Bob's custody can open with.
fn bob_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0xB0; 32])
}

/// Mallory (attacker) fixed signing key. `MALLORY_DID` resolves to its verifying
/// key via [`trio_resolver`], so a bundle Mallory signs with THIS key and labels
/// `creator_did = MALLORY_DID` passes the bundle signature check — the §5.13.3
/// rule-8 creator binding against the group-committed genesis creator is what
/// rejects it.
fn mallory_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0xEE; 32])
}

/// Resolves `ALICE_DID` / `BOB_DID` to their fixed #active verifying keys (all
/// else `None`). The joiner verifies the creator (`ALICE`) signature; the
/// inviter (`invite_member`) seals to the invitee (`BOB`) #active key. One
/// resolver serves both roles — resolving the extra DID is inert on the joiner
/// path (only `bundle.creator_did` is ever resolved there).
fn pair_resolver() -> KeyResolver {
    let alice = DID::from(ALICE_DID);
    let bob = DID::from(BOB_DID);
    let alice_vk = alice_signing_key().verifying_key();
    let bob_vk = bob_signing_key().verifying_key();
    Arc::new(move |did: &DID, _: SigningKeyId| {
        if did == &alice {
            Some(alice_vk)
        } else if did == &bob {
            Some(bob_vk)
        } else {
            None
        }
    })
}

/// Bob's #active custody with a FRESH random Ed25519 key. Returns
/// `(custody, handle, recipient_x25519)` where `recipient_x25519` is the
/// birational X25519 mapping of the #active public key — the value a creator
/// seals an invitation to. The joiner spawn opens via
/// `custody.ed25519_to_x25519_agree(handle, enc)`, which reconstructs the SAME
/// DH, so a bundle sealed to `recipient_x25519` opens. Resolver identity is
/// irrelevant here (`BOB` is never resolved on the joiner path); only Test M
/// needs a resolver-matching key (see [`bob_imported_custody`]).
async fn bob_active_custody() -> (InMemoryKeyCustody, KeyHandle, [u8; 32]) {
    let custody = InMemoryKeyCustody::new();
    let handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
    let pk = custody.public_key(&handle).await.unwrap();
    let pk_bytes: [u8; 32] = pk.as_bytes().try_into().unwrap();
    let x = ed25519_pubkey_to_x25519(&pk_bytes).unwrap();
    (custody, handle, x)
}

/// Bob's #active custody holding the FIXED [`bob_signing_key`] seed, so
/// `custody.public_key(handle)` equals the verifying key [`pair_resolver`]
/// returns for `BOB_DID`. Test M's `invite_member` seals to that resolved key;
/// Bob must open with the identical private key.
async fn bob_imported_custody() -> (InMemoryKeyCustody, KeyHandle) {
    let custody = InMemoryKeyCustody::new();
    let handle = custody
        .import_ed25519_signing_key(&Zeroizing::new(bob_signing_key().to_bytes()))
        .await
        .unwrap();
    (custody, handle)
}

/// Builds a signed [`InvitationBundle`] (creator = `signer`) carrying `params`,
/// `context_id`, and `welcome_bytes`, with a structural snapshot copied verbatim
/// from `params` (so `verify_structural_consistency` passes). The signature is
/// over the §5.12.3.1 signing hash produced with `signer` — pass the creator key
/// for a valid bundle, or an ATTACKER key to drive a signature-verify rejection.
/// Callers may hand-tamper the returned bundle (e.g. flip a `signature` byte or
/// diverge a `metadata_snapshot.structural` field) before sealing it.
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

/// HPKE-seals a (possibly hand-tampered) `bundle` into a reshaped
/// [`WelcomeJoinRequest`]. `hint_ctx` / `hint_creator` are the HPKE `info`/`aad`
/// binding hints AND the request's untrusted `context_id` / `creator_did`
/// (normally == the bundle's values, so the open succeeds and the downstream
/// signature / binding check is what rejects). `local_pseudonym` is passed
/// through (use `None` to drive the BLACK-2J-04 precheck).
fn seal_bundle(
    bundle: &InvitationBundle,
    recipient_x25519: &[u8; 32],
    hint_ctx: &str,
    hint_creator: &DID,
    reservation_id: ReservationId,
    local_pseudonym: Option<[u8; 32]>,
) -> WelcomeJoinRequest {
    let wire = bundle.to_wire_bytes().expect("bundle serializes");
    let (ct, enc) = hpke_seal_invitation(&wire, recipient_x25519, hint_ctx, hint_creator.as_ref())
        .expect("HPKE seal");
    WelcomeJoinRequest {
        context_id: hint_ctx.to_owned(),
        creator_did: hint_creator.clone(),
        sealed_bundle_enc: enc,
        sealed_bundle_ct: ct,
        reservation_id,
        local_pseudonym,
    }
}

/// The common case: build a validly-signed bundle and seal it into a request
/// with a real pseudonym. `bundle_*` go INTO the signed bundle; `hint_*` are the
/// request's untrusted binding hints (normally == the bundle values). Where a
/// test drives a mismatch, pass the divergent value as `bundle_context_id` /
/// `bundle_params` and keep the hints equal to the bundle so the open succeeds
/// and the downstream §5.13.3 check is what rejects.
#[allow(clippy::too_many_arguments)]
fn seal_join_request(
    signer: &SigningKey,
    bundle_creator_did: &DID,
    bundle_context_id: &str,
    bundle_params: &ContextParams,
    welcome_bytes: Vec<u8>,
    recipient_x25519: &[u8; 32],
    hint_ctx: &str,
    hint_creator: &DID,
    reservation_id: ReservationId,
) -> WelcomeJoinRequest {
    let bundle = signed_bundle(
        signer,
        bundle_creator_did,
        bundle_context_id,
        bundle_params,
        welcome_bytes,
    );
    seal_bundle(
        &bundle,
        recipient_x25519,
        hint_ctx,
        hint_creator,
        reservation_id,
        some_pseudonym(),
    )
}

/// A 64-hex canonical context id (ADR-056 decodes it to its 32-byte digest).
fn ctx_hex(seed: u8) -> String {
    let byte = format!("{seed:02x}");
    byte.repeat(32)
}

/// A REAL §9.10.4 local pseudonym (a distinctive non-`[0u8; 32]` constant). The
/// spawn-from-Welcome entrypoint rejects `None` for the encrypted join surface
/// (BLACK-2J-04), so every valid join fixture must supply one. Returns the
/// `Option` shape the request field / create path take directly.
#[allow(clippy::unnecessary_wraps)]
fn some_pseudonym() -> Option<[u8; 32]> {
    Some([0x5a; 32])
}

/// The joiner's legible context parameters (encrypted, single-admin).
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

/// Bob's X25519 wrapping key material (§9.16.1). A joiner's KeyPackage must
/// declare the `scp_context_params` (`0xFF02`) capability to be added to an SCP
/// context group (OpenMLS `valn0502`); since 9fe3b4c9b the production
/// `generate_key_package` path declares `0xFF02` UNCONDITIONALLY (its capability
/// is decoupled from any wrapping key). Publishing a wrapping key here exercises
/// the wrapping-key-PRESENT leaf path (the `0xFF01` wrapping-key leaf extension)
/// — NOT because `0xFF02` requires it. The bytes are an opaque leaf extension
/// during add/join (no X25519 DH runs on the MLS join path), so a fixed non-zero
/// constant suffices.
const BOB_WRAP: [u8; 32] = [0xB2; 32];

/// Builds the creator-committed `scp_context_params` (`0xFF02`) extension for a
/// ROOT context from `params`, byte-for-byte the way the creator write path
/// (`builder::create_context` → `create_mls_group_with_context`) does — so a
/// group created with this extension and a matching-`params` join verifies, and
/// a divergent join is refused (spec §5.13.3, FFI-02).
fn honest_ext(context_id: &str, params: &ContextParams) -> ScpContextExtension {
    // The honest creator committed into the group's `0xFF02` extension is
    // `ALICE_DID` (rule 8) — the same DID the honest bundle carries as
    // `creator_did`, so the join's creator binding passes.
    ScpContextExtension::for_root(
        context_id.to_owned(),
        DID::from(ALICE_DID),
        params.mode,
        &params.governance,
        params.ceiling_policy,
        &CapabilityCeiling::new(params.ceiling.iter().cloned()),
    )
    .expect("honest context extension serializes")
}

/// Publishes Bob's wrapping key on `sup` so his pooled KeyPackages carry the
/// `0xFF01` wrapping-key leaf extension, exercising the wrapping-key-PRESENT path
/// (see [`BOB_WRAP`]); the `0xFF02` context-params capability is declared
/// unconditionally regardless. Idempotent; must run BEFORE the KeyPackage store
/// is first spawned (i.e. before [`reserve_bob_kp`]).
async fn set_bob_wrapping(sup: &Arc<Supervisor>, bob: &DID) {
    sup.set_wrapping_keys(
        bob.clone(),
        BOB_WRAP.to_vec(),
        Zeroizing::new(BOB_WRAP.to_vec()),
    )
    .await
    .expect("set bob's wrapping key");
}

/// Resolves `ALICE_DID` / `BOB_DID` / `MALLORY_DID` to their fixed #active
/// verifying keys. Used by the creator-substitution regression so the joiner can
/// verify a bundle Mallory signs with her OWN key (labelled `creator_did =
/// MALLORY_DID`) — proving the rejection is the §5.13.3 rule-8 creator binding,
/// not a signature failure.
fn trio_resolver() -> KeyResolver {
    let alice = DID::from(ALICE_DID);
    let bob = DID::from(BOB_DID);
    let mallory = DID::from(MALLORY_DID);
    let alice_vk = alice_signing_key().verifying_key();
    let bob_vk = bob_signing_key().verifying_key();
    let mallory_vk = mallory_signing_key().verifying_key();
    Arc::new(move |did: &DID, _: SigningKeyId| {
        if did == &alice {
            Some(alice_vk)
        } else if did == &bob {
            Some(bob_vk)
        } else if did == &mallory {
            Some(mallory_vk)
        } else {
            None
        }
    })
}

fn fresh_mls_storage() -> Arc<dyn OpenMlsStorageAdapter> {
    Arc::new(SpawnBlockingStorageAdapter::new(Arc::new(
        InMemoryStorage::new(),
    )))
}

/// Builds Bob's real joiner `Supervisor` (real MLS crypto, not-configured
/// transport, in-memory event log + MLS storage). Returns the supervisor and a
/// clone of Bob's crypto provider (so a test can assert on the installed group).
///
/// `persistence` is threaded straight through: pass `None` for the happy path
/// (a `NoopContextPersistence` default that always succeeds) or a failing
/// double for the crash-safety test.
fn bob_supervisor(
    persistence: Option<Box<dyn ContextPersistence>>,
) -> (Arc<Supervisor>, Arc<MlsCryptoProvider>) {
    bob_supervisor_with_resolver(persistence, pair_resolver())
}

/// Builds Bob's joiner `Supervisor` with a caller-supplied [`KeyResolver`] — used
/// by the creator-substitution regression, which needs a resolver that also
/// resolves `MALLORY_DID` (see [`trio_resolver`]).
fn bob_supervisor_with_resolver(
    persistence: Option<Box<dyn ContextPersistence>>,
    resolver: KeyResolver,
) -> (Arc<Supervisor>, Arc<MlsCryptoProvider>) {
    let crypto = Arc::new(MlsCryptoProvider::new(
        BOB_DID.to_owned(),
        std::sync::Arc::new(scp_clock::SystemClock),
    ));
    let transport: Box<dyn ContextTransportProvider> = Box::new(NotConfiguredTransportProvider);
    let event_log: Box<dyn ContextEventLogProvider> = Box::new(MerkleEventLogProvider::new());
    let sup = Supervisor::with_providers(
        Arc::clone(&crypto),
        transport,
        event_log,
        resolver,
        persistence,
        None,
        None,
        None,
        fresh_mls_storage(),
    );
    (sup, crypto)
}

/// Builds Alice's creator `Supervisor` (real MLS crypto under `ALICE_DID`,
/// not-configured transport, in-memory event log + MLS storage, the
/// [`pair_resolver`] that resolves BOTH `ALICE`/`BOB` #active keys). Used by the
/// `invite_member` round-trip (Test M), which resolves the INVITEE (`BOB`)
/// #active to seal to. Returns the supervisor and a clone of Alice's crypto
/// provider (so the test can drive the installed group).
fn alice_supervisor() -> (Arc<Supervisor>, Arc<MlsCryptoProvider>) {
    let crypto = Arc::new(MlsCryptoProvider::new(
        ALICE_DID.to_owned(),
        std::sync::Arc::new(scp_clock::SystemClock),
    ));
    let transport: Box<dyn ContextTransportProvider> = Box::new(NotConfiguredTransportProvider);
    let event_log: Box<dyn ContextEventLogProvider> = Box::new(MerkleEventLogProvider::new());
    let sup = Supervisor::with_providers(
        Arc::clone(&crypto),
        transport,
        event_log,
        pair_resolver(),
        None,
        None,
        None,
        None,
        fresh_mls_storage(),
    );
    (sup, crypto)
}

/// Reserves one `KeyPackage` from Bob's own `KeyPackageStoreActor` and returns the
/// `(reservation_id, public_kp_bytes)` pair. The store's startup replenish fills
/// the pool before any command is served; the extra explicit `Replenish` is a
/// deterministic barrier (not a sleep) proving the pool is non-empty.
async fn reserve_bob_kp(
    sup: &Arc<Supervisor>,
    bob: &DID,
) -> (super::key_package_actor::ReservationId, Vec<u8>) {
    // Publish Bob's wrapping key BEFORE the store spawns so every pooled KP
    // declares `0xFF02` and satisfies `valn0502` when added to an SCP context
    // group (§5.13.3). Harmless for the wrapping-only (non-SCP) group fixtures —
    // a group with no `0xFF02` requirement accepts a `0xFF02`-declaring KP.
    set_bob_wrapping(sup, bob).await;
    let store = sup
        .key_package_store_for(bob)
        .await
        .expect("bob's key-package store spawns");
    store
        .send(|reply| KeyPackageCommand::Replenish { reply })
        .await
        .expect("replenish barrier");
    let pooled = store
        .send(|reply| KeyPackageCommand::ListPooled { reply })
        .await
        .expect("list pooled KPs");
    let (kp_ref, _public) = pooled
        .into_iter()
        .next()
        .expect("the auto-replenished pool holds at least one KP");
    store
        .send(|reply| KeyPackageCommand::Reserve { kp_ref, reply })
        .await
        .expect("reserve a pooled KP for join")
}

/// The joiner-side outcome of the shared bootstrap: everything a test needs to
/// assert on the spawned joiner and drive MLS traffic through its group.
struct Joined {
    sup: Arc<Supervisor>,
    bob_crypto: Arc<MlsCryptoProvider>,
    alice_crypto: Arc<MlsCryptoProvider>,
    ctx_id: String,
    ctx_bytes: [u8; 32],
}

/// Destructively move a provider-resident context onto a throwaway actor
/// [`PerContextState`](crate::context::actor::state::PerContextState) via the
/// retained `take_crypto_state` + the production `seed_encrypted_crypto_from_owned`
/// seed primitive. Post-ADR-049 PR-7 the steady-state crypto twins
/// (`mls_encrypt_management` / `seal` / `open`) live on the actor, so the
/// round-trip tests move each party onto the actor first. One-way: the provider
/// loses the context, so take each party exactly once.
fn take_into_actor(
    crypto: &Arc<MlsCryptoProvider>,
    ctx: &[u8; 32],
) -> crate::context::actor::state::PerContextState {
    let owned = crypto
        .take_crypto_state(ctx)
        .expect("take owned crypto material off the provider");
    let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
        *ctx,
        0,
        DID::from(crypto.local_did().to_owned()),
    );
    state.seed_encrypted_crypto_from_owned(owned);
    state
}

/// Runs the full reserve → creator-add → Welcome → `spawn_actor_from_welcome`
/// ladder, returning the spawn result plus the pieces needed to assert on it.
///
/// The FFI-02 axis is exposed by letting the CREATOR-committed parameters differ
/// from what Bob sends in his `WelcomeJoinRequest`:
///
/// - `committed`: `Some(params)` → Alice creates an **honest SCP context group**
///   whose `scp_context_params` (`0xFF02`) extension binds `params` under the
///   group's `context_id`; `None` → Alice creates a **wrapping-only** group with
///   NO `0xFF02` (a non-SCP group, for the rule-1 test).
/// - `request_params`: the params Bob puts in his request (what
///   `build_welcome_joiner_state` would build authority from). Differ from
///   `committed` to drive a binding mismatch.
/// - `request_ctx_id`: the `context_id` Bob claims (`None` → the group's real
///   `ctx_hex(seed)`). Differ to drive a context_id mismatch.
///
/// `Joined.ctx_id` / `ctx_bytes` are the REQUEST id (the slot Bob tried to
/// install under), so rollback assertions probe the right crypto slot.
async fn run_join_with(
    seed: u8,
    persistence: Option<Box<dyn ContextPersistence>>,
    committed: Option<ContextParams>,
    request_params: ContextParams,
    request_ctx_id: Option<String>,
) -> (
    Result<crate::context::ContextHandle, crate::context::ContextError>,
    Joined,
) {
    let bob = DID::from(BOB_DID);
    let group_ctx_id = ctx_hex(seed);
    let group_ctx_bytes = context_id_to_bytes(&group_ctx_id);

    let (sup, bob_crypto) = bob_supervisor(persistence);

    // Bob reserves a real KP from his own store (private signer-state stays in
    // the actor; only the reservation id + public bytes come back). This also
    // publishes Bob's wrapping key so the KP declares `0xFF02`.
    let (reservation_id, kp_public_bytes) = reserve_bob_kp(&sup, &bob).await;

    // Alice (bare creator provider) creates the group and adds Bob's reserved
    // KP, producing the real Welcome addressed to that KP's init key. When
    // `committed` is `Some`, the group carries the honest `0xFF02` extension;
    // otherwise it is a wrapping-only (non-SCP) group.
    let alice_crypto = Arc::new(MlsCryptoProvider::new(
        ALICE_DID.to_owned(),
        std::sync::Arc::new(scp_clock::SystemClock),
    ));
    match &committed {
        Some(committed_params) => alice_crypto
            .create_mls_group_with_context(
                &group_ctx_bytes,
                &honest_ext(&group_ctx_id, committed_params),
            )
            .expect("alice creates the SCP context group (0xFF02)"),
        None => alice_crypto
            .create_mls_group(&group_ctx_bytes)
            .expect("alice creates a wrapping-only group (no 0xFF02)"),
    }
    let add_output = alice_crypto
        .add_member(&group_ctx_bytes, BOB_DID, Some(&kp_public_bytes))
        .expect("alice adds bob's reserved key package");

    let request_ctx_id = request_ctx_id.unwrap_or_else(|| group_ctx_id.clone());
    let request_ctx_bytes = context_id_to_bytes(&request_ctx_id);

    // Seal the creator-signed §5.12.3 bundle to Bob's #active. The bundle carries
    // the (possibly divergent) `request_params` / `request_ctx_id`; the hints
    // equal them so the open succeeds and the §5.13.3 `0xFF02` cross-check against
    // the committed group is what accepts or rejects.
    let (bob_custody, bob_handle, bob_recipient) = bob_active_custody().await;
    let req = seal_join_request(
        &alice_signing_key(),
        &DID::from(ALICE_DID),
        &request_ctx_id,
        &request_params,
        add_output.welcome_bytes,
        &bob_recipient,
        &request_ctx_id,
        &DID::from(ALICE_DID),
        reservation_id,
    );

    let result = sup
        .spawn_actor_from_welcome(bob, &bob_custody, &bob_handle, req)
        .await;
    (
        result,
        Joined {
            sup,
            bob_crypto,
            alice_crypto,
            ctx_id: request_ctx_id,
            ctx_bytes: request_ctx_bytes,
        },
    )
}

/// The honest happy-path join: Alice commits `joiner_params()` into the group's
/// `0xFF02` extension and Bob requests those SAME params under the group's real
/// id, so the FFI-02 binding check passes and the join proceeds through install
/// → persist → spawn.
async fn join_bob(
    seed: u8,
    persistence: Option<Box<dyn ContextPersistence>>,
) -> (
    Result<crate::context::ContextHandle, crate::context::ContextError>,
    Joined,
) {
    run_join_with(
        seed,
        persistence,
        Some(joiner_params()),
        joiner_params(),
        None,
    )
    .await
}

// ---------------------------------------------------------------------------
// Test A — joiner-spawn happy path (Deferred Work #1 landing signal).
// ---------------------------------------------------------------------------

/// A Welcome-joined node becomes a LIVE, send-capable participant: the spawn
/// registers a context actor whose mailbox serves queries (`member_count`
/// returns `Some`, the exact discriminator against the pre-2J unregistered
/// `None`), the joiner is a `member` and the creator the `admin`, and the joined
/// MLS group is installed in the provider.
///
/// # Event-log wiring (test-quality AC1)
///
/// The joiner's event-log provider is WIRED (the supervisor's shared
/// `MerkleEventLogProvider` is reachable for the spawned context, i.e.
/// `event_log_entries` answers `Ok`, not `Err(NotInitialized)`). The joiner
/// entrypoint appends NO local join event — `MemberJoined` is a creator-side
/// leaf — so the joiner-local log legitimately starts EMPTY and CONVERGES via
/// cross-member event-log leaf replication (the follow-on that Phase 2J
/// unblocks). This test therefore asserts the provider is wired AND that the
/// joiner-local log is absent/empty, not a joiner-local entry that the spec does
/// not have this entrypoint emit.
#[tokio::test]
async fn spawn_from_welcome_yields_a_live_send_capable_actor() {
    let (result, j) = join_bob(0x11, None).await;
    let handle = result.expect("spawn_actor_from_welcome succeeds on a valid Welcome");
    assert_eq!(handle.context_id(), j.ctx_id);

    // The live-actor discriminator: an UNREGISTERED context yields `None`
    // (the pre-2J joiner had no actor at all); a live registered actor answers
    // its membership through the mailbox. This is the working send-handle proof.
    assert_eq!(
        j.sup.member_count(&j.ctx_id).await,
        Some(2),
        "the joiner's actor is registered and serves its mailbox (send handle live)"
    );
    assert!(
        j.sup.lookup(&j.ctx_id).is_some(),
        "a context actor handle is registered for the joiner"
    );

    let members = j.sup.member_dids(&j.ctx_id).await;
    assert!(
        members.contains(&ALICE_DID.to_owned()),
        "the creator is tracked as a member (admin)"
    );
    assert!(
        members.contains(&BOB_DID.to_owned()),
        "the joiner is tracked as a member"
    );

    // The joined MLS group is resident on the joiner's context ACTOR (ADR-049
    // PR-7: the welcome path takes the crypto off the provider and seeds the
    // live actor). `local_mls_epoch` returns `Some(epoch)` for an installed
    // encrypted group and `None` for an absent context, so its `is_some()` is
    // the presence discriminator.
    assert!(
        j.sup.local_mls_epoch(&j.ctx_id).await.is_some(),
        "the joined MLS group is installed on the joiner actor"
    );

    // Event-log provider WIRED (AC1) AND joiner-local log EMPTY: the spawned
    // context resolves against the supervisor's shared event-log provider (an
    // unwired supervisor answers `Err(NotInitialized)`, so `.expect` catches an
    // unwired provider), and the joiner appends NO local join leaf — the log is
    // absent/empty here and converges via cross-member event-log leaf
    // replication. `event_log_entries` returns `None` for an untouched context,
    // so `is_none_or(is_empty)` is the accurate "no local leaf" shape; a
    // regression that starts emitting a spurious local join event fails it.
    assert!(
        j.sup
            .event_log_entries(&j.ctx_bytes)
            .expect("event-log provider is wired")
            .is_none_or(|v| v.is_empty()),
        "joiner emits no local join leaf; the log converges via cross-member \
         event-log leaf replication"
    );
}

// ---------------------------------------------------------------------------
// Test A2 — the joiner seeds its ABSOLUTE MLS epoch from the joined group.
// ---------------------------------------------------------------------------

/// The joiner's `EpochState.mls_epoch` is the REAL absolute epoch of the group
/// it joined — NOT a `0` placeholder. In the fixture the creator builds the
/// group at epoch 0, then adds the joiner via a Commit that advances it to
/// epoch 1; the Welcome is FOR epoch 1, so the joiner must come up at epoch 1.
/// A wrong seed (the old `0`, or any other value) would stamp the wrong epoch
/// into checkpoints (§9.9.3), recovery envelopes, and governance events.
///
/// Non-vacuity: `local_mls_epoch` returns `Some(state.epoch.mls_epoch)`, so the
/// `Some(1)` assertion fails under both the pre-fix `mls_epoch: 0` seed and any
/// mutated constant (`999`) — it pins the read-the-joined-group-epoch behavior.
#[tokio::test]
async fn spawn_from_welcome_seeds_the_real_joined_group_epoch() {
    let (result, j) = join_bob(0x55, None).await;
    result.expect("spawn_actor_from_welcome succeeds");

    assert_eq!(
        j.sup.local_mls_epoch(&j.ctx_id).await,
        Some(1),
        "the joiner comes up at the joined group's real absolute epoch (1), not a \
         0 placeholder"
    );
}

// ---------------------------------------------------------------------------
// Test B — bidirectional MLS round-trip through the entrypoint-installed group.
// ---------------------------------------------------------------------------

/// The entrypoint-installed group is BIDIRECTIONALLY functional: the creator
/// encrypts a management message the joiner decrypts (creator → joiner), and the
/// joiner encrypts a management message the creator decrypts (joiner → creator).
/// The joiner-send direction is the landing signal — pre-2J the joiner had no
/// send handle at all; here its group produces valid ciphertext the creator
/// opens, and its actor is registered (`member_count` is `Some`).
#[tokio::test]
async fn spawn_from_welcome_group_round_trips_both_directions() {
    let (result, j) = join_bob(0x22, None).await;
    result.expect("spawn_actor_from_welcome succeeds");

    let routing_id = scp_protocol::context::context_routing_id(&hex::encode(j.ctx_bytes));

    // Move both parties onto the actor seam (the provider mls_encrypt_management
    // / open twins are deleted post-ADR-049 PR-7). Management traffic is
    // group-keyed (no sender key needed), so both actors round-trip directly.
    let mut alice_actor = take_into_actor(&j.alice_crypto, &j.ctx_bytes);
    let mut bob_actor = take_into_actor(&j.bob_crypto, &j.ctx_bytes);

    // Creator -> joiner: Alice encrypts, Bob's installed group decrypts.
    let from_alice = b"management-payload-from-alice";
    let wrapped_alice = alice_actor
        .mls_encrypt_management(from_alice, &routing_id, 3600)
        .expect("alice encrypts a management message");
    let opened_alice = bob_actor
        .open(&scp_clock::SystemClock, &j.ctx_id, &wrapped_alice)
        .expect("bob opens alice's message");
    assert!(
        matches!(
            &opened_alice,
            OpenResult::Management { payload, .. } if payload.as_slice() == from_alice.as_slice()
        ),
        "joiner decrypts creator traffic through the installed group; \
         expected Management({from_alice:?}), got {opened_alice:?}"
    );

    // Joiner -> creator: Bob encrypts through his installed group, Alice decrypts.
    // Pre-2J this direction was impossible (the joiner had no send-capable group
    // wired into an actor). Both the actor handle AND the group now exist.
    assert_eq!(
        j.sup.member_count(&j.ctx_id).await,
        Some(2),
        "joiner send handle is live"
    );
    let from_bob = b"management-payload-from-bob";
    let wrapped_bob = bob_actor
        .mls_encrypt_management(from_bob, &routing_id, 3600)
        .expect("bob encrypts a management message through the joined group");
    let opened_bob = alice_actor
        .open(&scp_clock::SystemClock, &j.ctx_id, &wrapped_bob)
        .expect("alice opens bob's message");
    assert!(
        matches!(
            &opened_bob,
            OpenResult::Management { payload, .. } if payload.as_slice() == from_bob.as_slice()
        ),
        "creator decrypts joiner traffic — bidirectional round-trip closed; \
         expected Management({from_bob:?}), got {opened_bob:?}"
    );
}

// ---------------------------------------------------------------------------
// Test C — key-injection crash-safety (Decision 1/8/9), non-vacuous.
// ---------------------------------------------------------------------------

/// A failing persistence double: `persist_context` always errors, every other
/// method is a benign success. Models a crash/storage-fault at the fail-closed
/// snapshot write BETWEEN key-injection and durable persist.
struct FailingPersistence;

#[async_trait::async_trait]
impl ContextPersistence for FailingPersistence {
    async fn persist_context(
        &self,
        _context_id: &str,
        _snapshot: &crate::context::state::ContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Err("induced persist failure at the fail-closed snapshot write".into())
    }
    async fn load_context(
        &self,
        _context_id: &str,
    ) -> Result<
        Option<crate::context::state::ContextSnapshot>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        Ok(None)
    }
    async fn delete_context(
        &self,
        _context_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
    async fn list_persisted_contexts(
        &self,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Vec::new())
    }
}

/// When the fail-closed initial-snapshot persist fails, the spawn returns
/// `Err(PersistenceFailed)` and leaves NO live half-keyed actor: the just-
/// installed group is torn back out of the provider and no actor handle is
/// registered. A respawn therefore finds a fully-keyed snapshot OR none — never
/// a half-keyed actor that can decrypt but has no durable key state.
///
/// # Non-vacuity (mutation argument)
///
/// The persist here happens BEFORE the spawn is acked and the group is rolled
/// back on failure. If the entrypoint were mutated to persist best-effort
/// (swallow the error) or to persist AFTER `spawn_actor_with_state`, then on
/// this induced failure the group would REMAIN installed (`with_context` would
/// be `Ok`) and the actor WOULD be registered (`member_count` would be `Some`).
/// Both assertions below would then fail — so the test is non-vacuous with
/// respect to the persist-before-ack + fail-closed-rollback ordering.
#[tokio::test]
async fn persist_failure_leaves_no_half_keyed_actor() {
    let (result, j) = join_bob(0x33, Some(Box::new(FailingPersistence))).await;

    let err = result.expect_err("a fail-closed persist failure rejects the spawn");
    assert!(
        matches!(err, crate::context::ContextError::PersistenceFailed(_)),
        "expected PersistenceFailed, got {err:?}"
    );

    // The installed group was rolled back — no half-keyed crypto is resident.
    // (An absent context exports an EMPTY snapshot; an installed one is
    // non-empty — see the happy-path test.)
    assert!(
        j.sup.local_mls_epoch(&j.ctx_id).await.is_none(),
        "the just-installed group must be torn back out on a persist failure"
    );

    // No live actor is registered — the context is unreachable, not half-keyed.
    assert!(
        j.sup.lookup(&j.ctx_id).is_none(),
        "no actor handle may be registered after a fail-closed rejection"
    );
    assert_eq!(
        j.sup.member_count(&j.ctx_id).await,
        None,
        "an unregistered context answers the unregistered default, not a live count"
    );
}

// ---------------------------------------------------------------------------
// Test D — single-use holds across the entrypoint (two-anchor backstop).
// ---------------------------------------------------------------------------

/// A second spawn reusing the SAME reservation (its `KeyPackage` already durably
/// consumed by the first successful join) is rejected by the reservation-journal
/// anchor — the fused `ConfirmConsume` finds no live reservation and replies a
/// typed error. Single-use is preserved: the first live actor is untouched and a
/// replayed Welcome can NOT stand up a second context.
///
/// The replay targets a DIFFERENT context id from the first join, so the
/// up-front actor-registry precheck (Fix 1a) does NOT short-circuit it — the
/// replay reaches the `ConfirmConsume` reservation-journal anchor, which is the
/// single-use property this test exercises. (The same-id replay is covered by
/// the collision precheck test; here we prove the journal anchor holds even for
/// a fresh context id.)
#[tokio::test]
async fn second_spawn_reusing_a_consumed_reservation_is_rejected() {
    let bob = DID::from(BOB_DID);
    let ctx_id = ctx_hex(0x44);
    let ctx_bytes = context_id_to_bytes(&ctx_id);
    // A distinct id for the replay so it clears the up-front registry precheck
    // and actually hits the reservation-journal anchor.
    let replay_ctx_id = ctx_hex(0x4a);

    let (sup, bob_crypto) = bob_supervisor(None);
    let (reservation_id, kp_public_bytes) = reserve_bob_kp(&sup, &bob).await;

    let alice_crypto = Arc::new(MlsCryptoProvider::new(
        ALICE_DID.to_owned(),
        std::sync::Arc::new(scp_clock::SystemClock),
    ));
    alice_crypto
        .create_mls_group_with_context(&ctx_bytes, &honest_ext(&ctx_id, &joiner_params()))
        .unwrap();
    let add_output = alice_crypto
        .add_member(&ctx_bytes, BOB_DID, Some(&kp_public_bytes))
        .unwrap();
    let welcome = add_output.welcome_bytes;

    // Both spawns present Bob's SAME #active custody (the replay opens an
    // identically-sealed bundle); the single-use anchor tested is the reservation
    // journal, not the opening key.
    let (bob_custody, bob_handle, bob_recipient) = bob_active_custody().await;
    let make_req = |context_id: &str, welcome_bytes: Vec<u8>| {
        seal_join_request(
            &alice_signing_key(),
            &DID::from(ALICE_DID),
            context_id,
            &joiner_params(),
            welcome_bytes,
            &bob_recipient,
            context_id,
            &DID::from(ALICE_DID),
            reservation_id.clone(),
        )
    };

    // First join succeeds and consumes the reservation's single-use KP.
    sup.spawn_actor_from_welcome(
        bob.clone(),
        &bob_custody,
        &bob_handle,
        make_req(&ctx_id, welcome.clone()),
    )
    .await
    .expect("first spawn-from-Welcome succeeds");
    assert_eq!(sup.member_count(&ctx_id).await, Some(2));

    // Second spawn (fresh context id) reusing the SAME (now-consumed) reservation
    // is rejected at the fused ConfirmConsume — the reservation journal no longer
    // holds it.
    let replay = sup
        .spawn_actor_from_welcome(
            bob,
            &bob_custody,
            &bob_handle,
            make_req(&replay_ctx_id, welcome),
        )
        .await
        .expect_err("a consumed reservation must not spawn a second actor");
    assert!(
        matches!(replay, crate::context::ContextError::InvalidState(_)),
        "expected InvalidState for a consumed reservation, got {replay:?}"
    );
    assert!(
        sup.lookup(&replay_ctx_id).is_none(),
        "the replay to a fresh context id must not stand up an actor"
    );

    // The first live actor and its group are untouched by the rejected replay.
    assert_eq!(
        sup.member_count(&ctx_id).await,
        Some(2),
        "the first join's live actor survives the rejected replay"
    );
    assert!(
        sup.local_mls_epoch(&ctx_id).await.is_some(),
        "the first join's installed group is intact"
    );
}

// ---------------------------------------------------------------------------
// Shared setup for the reversible-precheck tests (Fix 1a / Fix 6).
// ---------------------------------------------------------------------------

/// Alice (a bare creator provider) creates an HONEST SCP context group under
/// `context_id` — committing the `joiner_params()` `scp_context_params`
/// (`0xFF02`) extension — and adds Bob's RESERVED public KP, returning
/// `(alice_crypto, welcome_bytes)`. The committed extension binds `context_id`,
/// so a join under a DIFFERENT id (or with divergent params) is refused by the
/// FFI-02 binding check; every caller here joins under the SAME `context_id`.
fn alice_welcome_for(
    context_id: &str,
    kp_public_bytes: &[u8],
) -> (Arc<MlsCryptoProvider>, Vec<u8>) {
    let ctx_bytes = context_id_to_bytes(context_id);
    let alice_crypto = Arc::new(MlsCryptoProvider::new(
        ALICE_DID.to_owned(),
        std::sync::Arc::new(scp_clock::SystemClock),
    ));
    alice_crypto
        .create_mls_group_with_context(&ctx_bytes, &honest_ext(context_id, &joiner_params()))
        .expect("alice creates the SCP context group (0xFF02)");
    let add_output = alice_crypto
        .add_member(&ctx_bytes, BOB_DID, Some(kp_public_bytes))
        .expect("alice adds bob's reserved key package");
    (alice_crypto, add_output.welcome_bytes)
}

// ---------------------------------------------------------------------------
// Test E — a missing local pseudonym is rejected BEFORE the KP consume (Fix 6).
// ---------------------------------------------------------------------------

/// spawn-from-Welcome always stands up an ENCRYPTED context, so a `None`
/// `local_pseudonym` must be rejected (no silent `[0u8; 32]` sentinel — a
/// linkable constant). The reject is a REVERSIBLE precheck: it fires BEFORE the
/// irreversible `ConfirmConsume`, so the single-use `KeyPackage` is NOT burned.
///
/// Non-vacuity: the SAME reservation + Welcome, retried with a REAL pseudonym,
/// then succeeds — proving the rejected attempt neither consumed the KP nor
/// stood up any context.
#[tokio::test]
async fn missing_pseudonym_is_rejected_before_the_kp_consume() {
    let bob = DID::from(BOB_DID);
    let ctx_id = ctx_hex(0x66);
    let ctx_bytes = context_id_to_bytes(&ctx_id);

    let (sup, bob_crypto) = bob_supervisor(None);
    let (reservation_id, kp_public_bytes) = reserve_bob_kp(&sup, &bob).await;
    let (_alice, welcome) = alice_welcome_for(&ctx_id, &kp_public_bytes);

    // A validly-signed bundle (so the open + creator-signature verify PASS and
    // control reaches Precheck B); only the request's `local_pseudonym` varies.
    let (bob_custody, bob_handle, bob_recipient) = bob_active_custody().await;
    let bundle = signed_bundle(
        &alice_signing_key(),
        &DID::from(ALICE_DID),
        &ctx_id,
        &joiner_params(),
        welcome,
    );
    let make_req = |pseudonym: Option<[u8; 32]>| {
        seal_bundle(
            &bundle,
            &bob_recipient,
            &ctx_id,
            &DID::from(ALICE_DID),
            reservation_id.clone(),
            pseudonym,
        )
    };

    // `None` is rejected up front (CreationFailed), no context stands up.
    let err = sup
        .spawn_actor_from_welcome(bob.clone(), &bob_custody, &bob_handle, make_req(None))
        .await
        .expect_err("a None pseudonym must be rejected on the encrypted join surface");
    assert!(
        matches!(err, crate::context::ContextError::CreationFailed(_)),
        "expected CreationFailed for a missing pseudonym, got {err:?}"
    );
    assert!(
        sup.lookup(&ctx_id).is_none(),
        "no actor may be registered after a pseudonym rejection"
    );
    assert!(
        sup.local_mls_epoch(&ctx_id).await.is_none(),
        "no group may be installed after a pseudonym rejection"
    );

    // KP NOT burned: the same reservation + Welcome now succeed WITH a real
    // pseudonym — the reject happened before `ConfirmConsume`.
    sup.spawn_actor_from_welcome(bob, &bob_custody, &bob_handle, make_req(some_pseudonym()))
        .await
        .expect("the retry with a real pseudonym succeeds — the KP was never burned");
    assert_eq!(
        sup.member_count(&ctx_id).await,
        Some(2),
        "the retry stands up the live joiner actor"
    );
}

// ---------------------------------------------------------------------------
// Test F — a colliding context id is rejected UP FRONT, before the KP consume
// (Fix 1a — broadcast split-registry clobber). BLACK-2J-01.
// ---------------------------------------------------------------------------

/// A join whose `context_id` collides with an EXISTING broadcast context is
/// rejected by the up-front actor-registry check, BEFORE the irreversible
/// `ConfirmConsume`. This is the split-registry case the step-2
/// `install_joined_group` Vacant guard alone would MISS: a broadcast context's
/// crypto lives in `broadcast_keys`, so the `contexts` map slot the install
/// guard checks is VACANT — only the registry check catches the collision.
///
/// The test proves all three: (1) the join is rejected (`CreationFailed`), (2) the
/// broadcast context SURVIVES intact (still registered, its snapshot never
/// clobbered), and (3) the single-use `KeyPackage` is NOT burned (a join to a
/// fresh, non-colliding context id reusing the SAME reservation + Welcome then
/// succeeds).
#[tokio::test]
async fn colliding_broadcast_context_id_is_rejected_before_the_kp_consume() {
    let bob = DID::from(BOB_DID);
    let collide_id = ctx_hex(0x77);
    let collide_bytes = context_id_to_bytes(&collide_id);

    let (sup, bob_crypto) = bob_supervisor(None);

    // Publish bob's wrapping key BEFORE `create_context` — which get-or-spawns
    // bob's KeyPackage store via `build_actor_deps` and freezes its
    // wrapping-pubkey deps at spawn time. Without this, the pooled KPs would be
    // wrapping-only (no `0xFF02`) and could not join Alice's SCP context group.
    set_bob_wrapping(&sup, &bob).await;

    // Bob pre-creates a BROADCAST context under `collide_id`: this registers an
    // actor (so `lookup` is `Some`) while the encrypted `contexts` crypto slot
    // stays VACANT (broadcast keys live in `broadcast_keys`).
    let broadcast_params = ContextParams {
        mode: ContextMode::Broadcast,
        // Broadcast contexts only support `MemoryScope::Full`.
        memory_scope: scp_protocol::context::params::MemoryScope::Full,
        ..ContextParams::default()
    };
    sup.create_context(
        collide_id.clone(),
        broadcast_params,
        bob.clone(),
        some_pseudonym(),
    )
    .await
    .expect("bob creates the colliding broadcast context");
    assert!(
        sup.lookup(&collide_id).is_some(),
        "the broadcast context registered an actor"
    );
    assert!(
        sup.local_mls_epoch(&collide_id).await.is_none(),
        "the broadcast context's ENCRYPTED crypto slot is vacant (split registry) \
         — the install Vacant guard alone could not catch this collision"
    );

    // Bob reserves a KP; Alice builds a Welcome addressed to it for `collide_id`.
    let (reservation_id, kp_public_bytes) = reserve_bob_kp(&sup, &bob).await;
    let (_alice, welcome) = alice_welcome_for(&collide_id, &kp_public_bytes);

    // The colliding join is rejected UP FRONT — before the consume. The bundle
    // opens + verifies (valid alice signature) so control reaches Precheck A,
    // which is the live-registry collision guard under test.
    let (bob_custody, bob_handle, bob_recipient) = bob_active_custody().await;
    let colliding_req = seal_join_request(
        &alice_signing_key(),
        &DID::from(ALICE_DID),
        &collide_id,
        &joiner_params(),
        welcome.clone(),
        &bob_recipient,
        &collide_id,
        &DID::from(ALICE_DID),
        reservation_id.clone(),
    );
    let err = sup
        .spawn_actor_from_welcome(bob.clone(), &bob_custody, &bob_handle, colliding_req)
        .await
        .expect_err("a join colliding with a live context id must be rejected");
    assert!(
        matches!(err, crate::context::ContextError::CreationFailed(_)),
        "expected CreationFailed for a colliding context id, got {err:?}"
    );

    // The broadcast context SURVIVES intact — not clobbered.
    assert!(
        sup.lookup(&collide_id).is_some(),
        "the pre-existing broadcast context survives the rejected colliding join"
    );
    assert_eq!(
        sup.local_mls_epoch(&collide_id).await,
        None,
        "the survivor is still the broadcast context (broadcast reports no MLS epoch)"
    );

    // KP NOT burned: the SAME reservation now stands up a join to a FRESH,
    // non-colliding context id — proving the collision reject happened before
    // `ConfirmConsume` (a burned reservation would fail closed at the fused
    // consume, as Test D shows). The Welcome is rebuilt for `fresh_id` (Alice
    // re-adds the same reserved KP to a fresh honest group whose `0xFF02`
    // extension binds `fresh_id`): under FFI-02 the collide-bound Welcome cannot
    // be replayed under a different id — the binding check would refuse it — so
    // the retry uses a correctly-bound Welcome for the id it installs under.
    let fresh_id = ctx_hex(0x78);
    let (_fresh_alice, fresh_welcome) = alice_welcome_for(&fresh_id, &kp_public_bytes);
    let fresh_req = seal_join_request(
        &alice_signing_key(),
        &DID::from(ALICE_DID),
        &fresh_id,
        &joiner_params(),
        fresh_welcome,
        &bob_recipient,
        &fresh_id,
        &DID::from(ALICE_DID),
        reservation_id,
    );
    sup.spawn_actor_from_welcome(bob, &bob_custody, &bob_handle, fresh_req)
        .await
        .expect("the fresh-id retry succeeds — the KP was never burned by the collision");
    assert_eq!(
        sup.member_count(&fresh_id).await,
        Some(2),
        "the fresh-id join stands up a live joiner actor"
    );
}

// ---------------------------------------------------------------------------
// Test G — the entrypoint-level crypto fail-closed predicate (Fix 4).
// ---------------------------------------------------------------------------

/// The spawn-from-Welcome entrypoint gates on
/// [`welcome_snapshot_crypto_is_durable`] AFTER the fail-closed persist: an
/// EMPTY or ERRORED crypto export (which `build_snapshot_for_persist` would turn
/// into a keyless `needs_reconnect` snapshot that persists SUCCESSFULLY) is
/// fatal for a JOINER, which cannot reconnect-derive.
///
/// The concrete `MlsCryptoProvider` always returns a NON-EMPTY export for a
/// just-installed group, so the export-failure branch cannot be induced through
/// the full entrypoint with the real provider (install guarantees a live group).
/// This unit test therefore pins the fail-closed DECISION directly on the pure
/// predicate: an empty blob and an errored export both read as NOT durable
/// (→ the entrypoint rolls back + fails closed), while a populated blob reads as
/// durable (→ the spawn proceeds). Mutating the predicate to a constant `true`
/// (fail-open) fails the first two assertions.
#[test]
fn welcome_snapshot_crypto_durability_predicate_fails_closed_on_empty_or_error() {
    use crate::context::messaging_helpers::welcome_snapshot_crypto_is_durable;

    // A populated crypto blob is durable — the spawn may proceed.
    assert!(
        welcome_snapshot_crypto_is_durable(&Ok(vec![0x01, 0x02, 0x03])),
        "a non-empty crypto export is durable"
    );
    // An EMPTY blob is the keyless-snapshot signal — NOT durable, fail closed.
    assert!(
        !welcome_snapshot_crypto_is_durable(&Ok(Vec::new())),
        "an empty crypto export must fail closed (a joiner cannot reconnect-derive)"
    );
    // An ERRORED export is likewise not durable — fail closed.
    assert!(
        !welcome_snapshot_crypto_is_durable(&Err(crate::context::ContextError::CryptoFailed(
            "induced export failure".to_owned()
        ))),
        "an errored crypto export must fail closed"
    );
}

// ---------------------------------------------------------------------------
// Test H — the crypto-durability fail-closed branch, driven END-TO-END (Item B).
// ---------------------------------------------------------------------------

/// The entrypoint's crypto-durability gate (step 3b) fails the spawn CLOSED when
/// the joined group produces a non-durable crypto export — WITHOUT persisting a
/// keyless snapshot and WITHOUT standing up an actor. The real `MlsCryptoProvider`
/// always exports a non-empty blob for a just-installed group, so this branch is
/// otherwise unreachable through the full entrypoint; a one-shot test seam
/// (`arm_export_failure_once`) forces the NEXT export to fail so the WIRING —
/// predicate on the live export → on non-durable, roll back (destroy) + `Err`,
/// never spawn — is exercised, not just the pure predicate (Test G).
///
/// The seam fires at the step-3b durability read (the first export call, BEFORE
/// the persist), so the rollback path runs with nothing persisted. Post-rollback
/// the seam has cleared and the destroyed group exports empty.
#[tokio::test]
async fn non_durable_crypto_export_fails_closed_without_standing_up_an_actor() {
    let bob = DID::from(BOB_DID);
    let ctx_id = ctx_hex(0x9a);
    let ctx_bytes = context_id_to_bytes(&ctx_id);

    let (sup, bob_crypto) = bob_supervisor(None);
    let (reservation_id, kp_public_bytes) = reserve_bob_kp(&sup, &bob).await;
    let (_alice, welcome) = alice_welcome_for(&ctx_id, &kp_public_bytes);

    // A valid bundle (open + signature + §5.13.3 all pass) so control reaches the
    // step-3b durability check, which is where the armed seam fires.
    let (bob_custody, bob_handle, bob_recipient) = bob_active_custody().await;
    let req = seal_join_request(
        &alice_signing_key(),
        &DID::from(ALICE_DID),
        &ctx_id,
        &joiner_params(),
        welcome,
        &bob_recipient,
        &ctx_id,
        &DID::from(ALICE_DID),
        reservation_id,
    );

    // Arm the one-shot seam: the step-3b durability check reads the live export
    // FIRST, so the seam fires there → the export reads non-durable.
    bob_crypto.arm_export_failure_once();

    let err = sup
        .spawn_actor_from_welcome(bob, &bob_custody, &bob_handle, req)
        .await
        .expect_err("a non-durable crypto export must fail the spawn closed");
    assert!(
        matches!(err, crate::context::ContextError::PersistenceFailed(_)),
        "expected PersistenceFailed for a non-durable export, got {err:?}"
    );

    // Rollback fired: the just-installed group was destroyed. The one-shot seam
    // has cleared, so this export reads normally → empty for the now-absent group.
    assert!(
        sup.local_mls_epoch(&ctx_id).await.is_none(),
        "the installed group must be rolled back on a non-durable export"
    );
    // No actor registered — the keyless joiner never became reachable, and the
    // fail-closed branch ran BEFORE the persist (nothing durable to resurrect).
    assert!(
        sup.lookup(&ctx_id).is_none(),
        "no actor may be registered after a fail-closed non-durable export"
    );
    assert_eq!(
        sup.member_count(&ctx_id).await,
        None,
        "an unregistered context answers the unregistered default, not a live count"
    );
}

// ---------------------------------------------------------------------------
// Test I — durable first-writer-wins (BLACK-2J-06): a persisted-but-UNSPAWNED
// same-id snapshot rejects the join without clobbering it or burning the KP.
// ---------------------------------------------------------------------------

/// A recording persistence double: stores what it persists, returns it on load,
/// and records deletes. `Arc`-shared so a test can seed ONE supervisor's real
/// snapshot and then read it back through a SECOND, independent supervisor that
/// shares the store but has NO live actor for the id — the exact
/// persisted-but-unspawned window Precheck A (`lookup`, live registry only)
/// cannot see and durable Precheck D must catch.
#[derive(Clone, Default)]
struct RecordingPersistence {
    store: Arc<dashmap::DashMap<String, crate::context::state::ContextSnapshot>>,
    deletes: Arc<dashmap::DashSet<String>>,
}

#[async_trait::async_trait]
impl ContextPersistence for RecordingPersistence {
    async fn persist_context(
        &self,
        context_id: &str,
        snapshot: &crate::context::state::ContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.store.insert(context_id.to_owned(), snapshot.clone());
        Ok(())
    }
    async fn load_context(
        &self,
        context_id: &str,
    ) -> Result<
        Option<crate::context::state::ContextSnapshot>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        Ok(self.store.get(context_id).map(|e| e.value().clone()))
    }
    async fn delete_context(
        &self,
        context_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.deletes.insert(context_id.to_owned());
        self.store.remove(context_id);
        Ok(())
    }
    async fn list_persisted_contexts(
        &self,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.store.iter().map(|e| e.key().clone()).collect())
    }
}

/// spawn-from-Welcome is the FIRST join for a NEW context, so an EXISTING durable
/// snapshot for the same id means either a griefing victim or the joiner's own
/// stale/prior context — which must be recovered via restore/reconnect, not
/// re-joined. The join is rejected by the durable first-writer-wins precheck
/// (Precheck D), which — unlike the live-registry Precheck A — sees a
/// persisted-but-unspawned snapshot. The victim snapshot is NOT clobbered or
/// deleted, and because the reject fires BEFORE `ConfirmConsume`, the single-use
/// `KeyPackage` is NOT burned (a retry after the snapshot is cleared succeeds).
#[tokio::test]
async fn durable_snapshot_collision_is_rejected_without_clobbering_or_burning_kp() {
    let bob = DID::from(BOB_DID);
    let ctx_id = ctx_hex(0x99);
    let ctx_bytes = context_id_to_bytes(&ctx_id);

    let rec = RecordingPersistence::default();

    // ONE Bob #active custody opens every bundle here (seed + target reject +
    // target retry); the property under test is durable first-writer-wins, not
    // the opening key, so a single custody sealed-to across supervisors is faithful.
    let (bob_custody, bob_handle, bob_recipient) = bob_active_custody().await;

    // --- Seed: a first supervisor persists a REAL snapshot for `ctx_id` via a
    //     successful join. It shares the recording store; the spawn persists the
    //     joiner's initial Class-S snapshot under `ctx_id`.
    let (seed_sup, _seed_crypto) = bob_supervisor(Some(Box::new(rec.clone())));
    let (seed_res, seed_kp) = reserve_bob_kp(&seed_sup, &bob).await;
    let (_seed_alice, seed_welcome) = alice_welcome_for(&ctx_id, &seed_kp);
    seed_sup
        .spawn_actor_from_welcome(
            bob.clone(),
            &bob_custody,
            &bob_handle,
            seal_join_request(
                &alice_signing_key(),
                &DID::from(ALICE_DID),
                &ctx_id,
                &joiner_params(),
                seed_welcome,
                &bob_recipient,
                &ctx_id,
                &DID::from(ALICE_DID),
                seed_res,
            ),
        )
        .await
        .expect("the seed join persists a real snapshot for ctx_id");
    let seeded = rec
        .store
        .get(&ctx_id)
        .map(|e| e.value().clone())
        .expect("the seed join persisted a snapshot for ctx_id");

    // --- Target: a SECOND, independent supervisor sharing the SAME store. It has
    //     NO live actor for `ctx_id`, so Precheck A `lookup` misses and only the
    //     durable Precheck D can catch the collision.
    let (target_sup, target_crypto) = bob_supervisor(Some(Box::new(rec.clone())));
    assert!(
        target_sup.lookup(&ctx_id).is_none(),
        "the target supervisor has no live actor for the id (only durable state exists)"
    );

    let (reservation_id, kp_public_bytes) = reserve_bob_kp(&target_sup, &bob).await;
    let (_alice, welcome) = alice_welcome_for(&ctx_id, &kp_public_bytes);
    let make_req = |reservation_id: ReservationId, welcome_bytes: Vec<u8>| {
        seal_join_request(
            &alice_signing_key(),
            &DID::from(ALICE_DID),
            &ctx_id,
            &joiner_params(),
            welcome_bytes,
            &bob_recipient,
            &ctx_id,
            &DID::from(ALICE_DID),
            reservation_id,
        )
    };

    let err = target_sup
        .spawn_actor_from_welcome(
            bob.clone(),
            &bob_custody,
            &bob_handle,
            make_req(reservation_id.clone(), welcome.clone()),
        )
        .await
        .expect_err("a durable same-id snapshot must reject the first-join");
    assert!(
        matches!(err, crate::context::ContextError::CreationFailed(_)),
        "expected CreationFailed for a durable-snapshot collision, got {err:?}"
    );

    // The victim snapshot is INTACT — neither clobbered nor deleted.
    assert!(
        !rec.deletes.contains(&ctx_id),
        "the victim durable snapshot must not be deleted by the rejected join"
    );
    let after = rec
        .store
        .get(&ctx_id)
        .map(|e| e.value().clone())
        .expect("the victim snapshot is still present after the reject");
    assert_eq!(
        after.context_id, seeded.context_id,
        "the victim snapshot's identity is unchanged"
    );
    assert_eq!(
        after.state, seeded.state,
        "the victim snapshot's lifecycle state is unchanged (not overwritten)"
    );
    // No actor stood up and no group was installed on the target.
    assert!(
        target_sup.lookup(&ctx_id).is_none(),
        "no actor may be registered after a durable-collision reject"
    );
    assert!(
        target_sup.local_mls_epoch(&ctx_id).await.is_none(),
        "no group may be installed after a durable-collision reject"
    );

    // KP NOT burned: clear the durable snapshot (as a recover/reconnect would)
    // and retry the SAME reservation + Welcome to the SAME id — it now succeeds,
    // proving the durable-collision reject fired BEFORE `ConfirmConsume`.
    rec.store.remove(&ctx_id);
    rec.deletes.clear();
    target_sup
        .spawn_actor_from_welcome(
            bob,
            &bob_custody,
            &bob_handle,
            make_req(reservation_id, welcome),
        )
        .await
        .expect("the retry after clearing the snapshot succeeds — the KP was never burned");
    assert_eq!(
        target_sup.member_count(&ctx_id).await,
        Some(2),
        "the retry stands up the live joiner actor"
    );
}

// ---------------------------------------------------------------------------
// Test J — a locked region that exceeds LIFECYCLE_TIMEOUT fails the join closed,
// rolls back, and RELEASES the global bootstrap lock (BLACK-2J-07 global-lock
// DoS). The step-1 `ConfirmConsume` send blocks on MLS processing of
// attacker-supplied `welcome_bytes` with no reply timeout; the entrypoint's
// `timeout(LIFECYCLE_TIMEOUT, ...)` wrap bounds that unbounded wait so a slow or
// crafted Welcome can no longer pin the single global `bootstrap_spawn_lock` and
// wedge every other bootstrap node-wide.
// ---------------------------------------------------------------------------

/// A join whose locked region (step-1 `ConfirmConsume`) never completes within
/// `LIFECYCLE_TIMEOUT` returns a typed `TransportTimeout`, rolls back (no group
/// installed, no snapshot persisted, no actor registered), and — critically —
/// RELEASES the global `bootstrap_spawn_lock`, so a subsequent bootstrap for a
/// DIFFERENT context id proceeds promptly instead of deadlocking.
///
/// The `ConfirmConsume` wait is bounded ONLY by the entrypoint's
/// `timeout(LIFECYCLE_TIMEOUT, ...)` (the `KeyPackageStoreHandle::send` reply
/// await itself has no timeout), so this is the exact path a slow/crafted
/// Welcome would take. A fake key-package store injected for Bob receives the
/// `ConfirmConsume` and holds its reply channel open while sleeping far past
/// `LIFECYCLE_TIMEOUT`; under `start_paused` the runtime auto-advances virtual
/// time to the earliest timer, so the entrypoint's timeout fires FIRST and the
/// elapse is deterministic and instant (no wall-clock wait).
///
/// Non-vacuity: without the `LIFECYCLE_TIMEOUT` wrap, `spawn_actor_from_welcome`
/// would await the never-answered reply forever while holding
/// `bootstrap_spawn_lock`; the first `.await` would hang (the join never returns)
/// and, even if it did, the follow-up `create_context` would deadlock acquiring
/// the still-held global lock. Both the `TransportTimeout` result and the prompt
/// follow-up create therefore pin the timeout-bound-and-release behavior.
#[tokio::test(start_paused = true)]
async fn slow_confirm_consume_times_out_rolls_back_and_releases_the_lock() {
    use std::time::Duration;

    use super::key_package_actor::KeyPackageStoreHandle;

    let bob = DID::from(BOB_DID);
    let ctx_id = ctx_hex(0xa5);
    let ctx_bytes = context_id_to_bytes(&ctx_id);

    let (sup, bob_crypto) = bob_supervisor(None);

    // Inject a fake key-package store for Bob whose `ConfirmConsume` handler
    // holds the reply channel open and sleeps far past `LIFECYCLE_TIMEOUT`
    // without answering — modelling a slow/crafted Welcome whose MLS processing
    // does not return. `key_package_store_for` returns this pre-inserted handle
    // (get-or-spawn: it never spawns a real actor when one is already present),
    // so `build_actor_deps` threads it into `deps.key_package_store` and step 1
    // sends `ConfirmConsume` here.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<KeyPackageCommand>(8);
    let fake_actor = tokio::spawn(async move {
        while let Some(cmd) = rx.recv().await {
            if let KeyPackageCommand::ConfirmConsume { reply, .. } = cmd {
                // Keep `reply` alive (so the caller's reply await stays pending,
                // not an immediate channel-closed error) but never answer within
                // the join's budget — the entrypoint timeout wins first.
                tokio::time::sleep(Duration::from_hours(1)).await;
                drop(reply);
            }
        }
    });
    sup.key_package_stores
        .insert(bob.clone(), KeyPackageStoreHandle::from_sender(tx));

    // A well-formed request: the fake store ignores `reservation_id` /
    // `welcome_bytes`, so they need not name a real reserved KP. The reversible
    // prechecks (A live-registry miss, B pseudonym, C legible params, D durable
    // first-writer-wins) all PASS, so control reaches the timed region and blocks
    // in the step-1 `ConfirmConsume`.
    // A validly-signed bundle so the open + verify + reversible prechecks (A–D)
    // all PASS and control reaches the timed ConfirmConsume region (the fake store
    // ignores `reservation_id` / `welcome_message`, so both may be junk). No Alice
    // group is needed — §5.13.3 runs only AFTER ConfirmConsume returns, which it
    // never does here.
    let (bob_custody, bob_handle, bob_recipient) = bob_active_custody().await;
    let req = seal_join_request(
        &alice_signing_key(),
        &DID::from(ALICE_DID),
        &ctx_id,
        &joiner_params(),
        vec![0u8; 4],
        &bob_recipient,
        &ctx_id,
        &DID::from(ALICE_DID),
        ReservationId::new_random(),
    );

    let err = sup
        .spawn_actor_from_welcome(bob.clone(), &bob_custody, &bob_handle, req)
        .await
        .expect_err("a ConfirmConsume exceeding LIFECYCLE_TIMEOUT must fail the join closed");
    assert!(
        matches!(err, crate::context::ContextError::TransportTimeout(_)),
        "expected TransportTimeout on the LIFECYCLE_TIMEOUT elapse, got {err:?}"
    );

    // Rollback fired on the elapse: no MLS group is installed and no actor stood
    // up. (The consume never completed, so there was nothing installed yet; the
    // unconditional teardown on `Elapsed` is still safe — the idempotent
    // `destroy_mls_group` / `delete_context` no-op.)
    assert!(
        sup.local_mls_epoch(&ctx_id).await.is_none(),
        "no MLS group may be installed after a timed-out join"
    );
    assert!(
        sup.lookup(&ctx_id).is_none(),
        "no actor may be registered after a timed-out join"
    );
    assert_eq!(
        sup.member_count(&ctx_id).await,
        None,
        "an unregistered context answers the unregistered default, not a live count"
    );

    // CRITICAL — the global `bootstrap_spawn_lock` was RELEASED: a subsequent
    // bootstrap for a DIFFERENT context id completes promptly. If the timed-out
    // join had pinned the lock, this create would deadlock acquiring it.
    // `create_context` builds a fresh group and never sends `ConfirmConsume`, so
    // it does not touch the still-sleeping fake store.
    let other_id = ctx_hex(0xa6);
    sup.create_context(
        other_id.clone(),
        joiner_params(),
        bob.clone(),
        some_pseudonym(),
    )
    .await
    .expect("a later bootstrap for a different id proceeds — the global lock was released");
    assert!(
        sup.lookup(&other_id).is_some(),
        "the follow-up create stood up its own live actor (the global lock was not pinned)"
    );
    assert!(
        sup.member_count(&other_id).await.is_some(),
        "the follow-up context's actor serves its mailbox — the lock is free"
    );

    fake_actor.abort();
}

// ---------------------------------------------------------------------------
// The PUBLIC bare-`DID` `Supervisor` joiner entrypoints (ADR-049 Phase 2J):
// `reserve_key_package` + `spawn_actor_from_welcome` are bridge-initiated
// node-level bootstraps (custody enforced at the FFI bridge layer, the same
// trust model as `create_context`), NOT actor-internal `OwnedIdentityDid`-gated
// methods. These exercise the reserve→spawn round trip and the store-binding
// fail-closed path through those public methods.
// ---------------------------------------------------------------------------

/// The two PUBLIC bare-`DID` `Supervisor` bootstrap entrypoints compose into a
/// working join: `reserve_key_package` reserves one of the joiner's own pooled
/// `KeyPackages`, the creator builds a Welcome addressed to it, and
/// `spawn_actor_from_welcome` fuses that Welcome into a live, send-capable
/// actor. The joiner comes up registered (`member_count` is `Some(2)`, the
/// live-actor discriminator) and the installed group is bidirectionally
/// functional (bob encrypts through it, alice decrypts).
#[tokio::test]
async fn reserve_then_spawn_via_supervisor_yields_a_live_send_capable_actor() {
    let bob = DID::from(BOB_DID);
    let ctx_id = ctx_hex(0xb1);
    let ctx_bytes = context_id_to_bytes(&ctx_id);

    let (sup, bob_crypto) = bob_supervisor(None);

    // Publish bob's wrapping key so his pooled KP declares `0xFF02` (valn0502).
    set_bob_wrapping(&sup, &bob).await;

    // Reserve via the PUBLIC `Supervisor` entrypoint (get-or-spawn bob's store,
    // replenish barrier, list, reserve) — bare DID; in production the FFI bridge
    // enforces that the DID is locally custodied.
    let (reservation_id, kp_public_bytes) = sup
        .reserve_key_package(bob.clone())
        .await
        .expect("reserve_key_package yields a reservation for the identity");

    // Alice (bare creator provider) adds the reserved KP → the real Welcome.
    let (alice_crypto, welcome) = alice_welcome_for(&ctx_id, &kp_public_bytes);

    // Spawn via the PUBLIC `Supervisor` entrypoint — the reservation feeds
    // straight in through the creator-signed, sealed bundle.
    let (bob_custody, bob_handle, bob_recipient) = bob_active_custody().await;
    let joined = sup
        .spawn_actor_from_welcome(
            bob.clone(),
            &bob_custody,
            &bob_handle,
            seal_join_request(
                &alice_signing_key(),
                &DID::from(ALICE_DID),
                &ctx_id,
                &joiner_params(),
                welcome,
                &bob_recipient,
                &ctx_id,
                &DID::from(ALICE_DID),
                reservation_id,
            ),
        )
        .await
        .expect("spawn_actor_from_welcome stands up the joiner actor");
    assert_eq!(joined.context_id(), ctx_id);

    // Live-actor discriminator: `Some(2)` (vs the unregistered `None`).
    assert_eq!(
        sup.member_count(&ctx_id).await,
        Some(2),
        "the reserve->spawn join stands up a registered, send-capable actor"
    );
    assert!(
        sup.lookup(&ctx_id).is_some(),
        "a context actor handle is registered for the joiner"
    );

    // The installed group is real: bob encrypts through it, alice decrypts. Both
    // parties move onto the actor seam (the provider mls_encrypt_management / open
    // twins are deleted post-ADR-049 PR-7); management traffic is group-keyed.
    let routing_id = scp_protocol::context::context_routing_id(&hex::encode(ctx_bytes));
    let mut bob_actor = take_into_actor(&bob_crypto, &ctx_bytes);
    let mut alice_actor = take_into_actor(&alice_crypto, &ctx_bytes);
    let from_bob = b"supervisor-seam-payload-from-bob";
    let wrapped_bob = bob_actor
        .mls_encrypt_management(from_bob, &routing_id, 3600)
        .expect("bob encrypts a management message through the installed group");
    let opened = alice_actor
        .open(&scp_clock::SystemClock, &ctx_id, &wrapped_bob)
        .expect("alice opens bob's message");
    assert!(
        matches!(
            &opened,
            OpenResult::Management { payload, .. } if payload.as_slice() == from_bob.as_slice()
        ),
        "creator decrypts joiner traffic through the installed group; \
         expected Management({from_bob:?}), got {opened:?}"
    );
}

/// The join binds to the identity whose `KeyPackageStoreActor` holds the
/// reservation. A reservation minted for BOB is consumed under CHARLIE — whose
/// OWN (fresh) store never held it — so the fused `ConfirmConsume` fails closed
/// with `InvalidState` and NO actor stands up. Non-vacuity: the SAME
/// reservation + Welcome, retried under BOB, then succeeds — proving Charlie's
/// rejected attempt neither burned the KP nor stood up the context.
#[tokio::test]
async fn spawn_under_a_different_did_is_rejected() {
    let bob = DID::from(BOB_DID);
    let charlie = DID::from("did:dht:z6MkCharlieNotTheJoinerSpawnFromWelcome");
    let ctx_id = ctx_hex(0xb2);

    let (sup, _bob_crypto) = bob_supervisor(None);

    // Publish bob's wrapping key so his pooled KP declares `0xFF02` (valn0502).
    set_bob_wrapping(&sup, &bob).await;

    // Bob reserves under HIS OWN DID; Alice builds the Welcome for that KP.
    let (reservation_id, kp_public_bytes) = sup
        .reserve_key_package(bob.clone())
        .await
        .expect("bob reserves a KP under his own DID");
    let (_alice, welcome) = alice_welcome_for(&ctx_id, &kp_public_bytes);

    // Both spawns open the SAME bundle sealed to Bob's #active custody; the
    // identity binding under test is the reservation's per-identity KeyPackage
    // store (via `owning_did`), independent of the bundle-opening key.
    let (bob_custody, bob_handle, bob_recipient) = bob_active_custody().await;
    let make_req = |reservation_id: ReservationId, welcome_bytes: Vec<u8>| {
        seal_join_request(
            &alice_signing_key(),
            &DID::from(ALICE_DID),
            &ctx_id,
            &joiner_params(),
            welcome_bytes,
            &bob_recipient,
            &ctx_id,
            &DID::from(ALICE_DID),
            reservation_id,
        )
    };

    // Spawn under CHARLIE: `spawn_actor_from_welcome` resolves Charlie's OWN
    // fresh KeyPackage store, which never held bob's reservation, so the fused
    // `ConfirmConsume` finds no live reservation and fails closed.
    let err = sup
        .spawn_actor_from_welcome(
            charlie,
            &bob_custody,
            &bob_handle,
            make_req(reservation_id.clone(), welcome.clone()),
        )
        .await
        .expect_err("a reservation bound to bob must not consume under a different DID");
    assert!(
        matches!(err, crate::context::ContextError::InvalidState(_)),
        "expected InvalidState for an absent (cross-identity) reservation, got {err:?}"
    );
    assert!(
        sup.lookup(&ctx_id).is_none(),
        "no actor may stand up under the wrong identity"
    );

    // Non-vacuity: bob's OWN DID now spawns the joiner with the same reservation
    // + Welcome — Charlie's rejected attempt burned nothing.
    sup.spawn_actor_from_welcome(
        bob,
        &bob_custody,
        &bob_handle,
        make_req(reservation_id, welcome),
    )
    .await
    .expect("bob's own DID spawns the joiner — the reservation stayed bound to him");
    assert_eq!(
        sup.member_count(&ctx_id).await,
        Some(2),
        "bob's join stands up the live joiner actor after the cross-identity reject"
    );
}

// ---------------------------------------------------------------------------
// Test L — FFI-02 context-parameter binding: a join whose caller-supplied
// params/context_id DIVERGE from what the creator cryptographically committed
// into the group's `scp_context_params` (`0xFF02`) extension is REFUSED before
// any crypto is installed, any snapshot persisted, or any actor registered
// (spec §5.13.3). This is the load-bearing forgery guard: a malicious inviter
// cannot present benign params while the real group differs.
// ---------------------------------------------------------------------------

/// Asserts a spawn `result` was refused by the FFI-02 binding check (a
/// `CryptoFailed` whose message names the greppable refusal + the `0xFF02`
/// extension) and that the rejection had NO side effects: no group installed in
/// the provider (empty crypto export for the request slot), no live actor
/// registered, and — via the shared `RecordingPersistence` — no snapshot
/// persisted. Mirrors the 2J rollback-assertion pattern (Test C / H).
async fn assert_binding_refused_no_side_effects(
    result: Result<crate::context::ContextHandle, crate::context::ContextError>,
    j: &Joined,
    rec: &RecordingPersistence,
) {
    let err = result.expect_err("a diverging context-parameter binding must be refused");
    assert!(
        matches!(
            &err,
            crate::context::ContextError::CryptoFailed(msg)
                if msg.contains("spawn-from-Welcome refused") && msg.contains("0xFF02")
        ),
        "expected the FFI-02 binding refusal naming the 0xFF02 extension, got: {err:?}"
    );

    // No crypto installed under the slot Bob tried to install into (an absent
    // context exports an EMPTY blob; an installed one is non-empty).
    assert!(
        j.sup.local_mls_epoch(&j.ctx_id).await.is_none(),
        "no MLS group may be installed after a binding refusal"
    );
    // No actor registered / reachable.
    assert!(
        j.sup.lookup(&j.ctx_id).is_none(),
        "no actor handle may be registered after a binding refusal"
    );
    assert_eq!(
        j.sup.member_count(&j.ctx_id).await,
        None,
        "an unregistered context answers the unregistered default, not a live count"
    );
    // No snapshot persisted — the refusal fires BEFORE the step-4 persist.
    assert!(
        rec.store.is_empty(),
        "no snapshot may be persisted after a binding refusal"
    );
}

/// The caller's `governance` diverges from the creator-committed governance
/// model: `GovernanceHashMismatch` → refused before install.
#[tokio::test]
async fn tamper_governance_mismatch_is_refused_before_install() {
    let rec = RecordingPersistence::default();
    let mut tampered = joiner_params();
    tampered.governance = GovernanceModel::Threshold {
        threshold: 1,
        signers: vec![DID::from("did:dht:z6MkThresholdSignerForTamperTest")],
    };
    let (result, j) = run_join_with(
        0xc1,
        Some(Box::new(rec.clone())),
        Some(joiner_params()),
        tampered,
        None,
    )
    .await;
    assert_binding_refused_no_side_effects(result, &j, &rec).await;
}

/// The caller's capability `ceiling` diverges from the committed one:
/// `CeilingHashMismatch` → refused before install.
#[tokio::test]
async fn tamper_ceiling_mismatch_is_refused_before_install() {
    let rec = RecordingPersistence::default();
    let mut tampered = joiner_params();
    // A strict subset of the committed ceiling — valid entries, different hash.
    tampered.ceiling = vec![Capability::MessagesRead];
    let (result, j) = run_join_with(
        0xc2,
        Some(Box::new(rec.clone())),
        Some(joiner_params()),
        tampered,
        None,
    )
    .await;
    assert_binding_refused_no_side_effects(result, &j, &rec).await;
}

/// The caller's `ceiling_policy` diverges (Immutable committed vs Governed
/// requested): `CeilingPolicyMismatch` → refused before install.
#[tokio::test]
async fn tamper_ceiling_policy_mismatch_is_refused_before_install() {
    let rec = RecordingPersistence::default();
    let mut tampered = joiner_params();
    tampered.ceiling_policy = CeilingPolicy::Governed;
    let (result, j) = run_join_with(
        0xc3,
        Some(Box::new(rec.clone())),
        Some(joiner_params()),
        tampered,
        None,
    )
    .await;
    assert_binding_refused_no_side_effects(result, &j, &rec).await;
}

/// The caller's `mode` diverges (Encrypted committed vs Broadcast requested):
/// `ModeMismatch` → refused before install.
#[tokio::test]
async fn tamper_mode_mismatch_is_refused_before_install() {
    let rec = RecordingPersistence::default();
    let mut tampered = joiner_params();
    tampered.mode = ContextMode::Broadcast;
    let (result, j) = run_join_with(
        0xc4,
        Some(Box::new(rec.clone())),
        Some(joiner_params()),
        tampered,
        None,
    )
    .await;
    assert_binding_refused_no_side_effects(result, &j, &rec).await;
}

/// The caller's `context_id` diverges from the id the group's `0xFF02` extension
/// commits (a Welcome for context A replayed as context B): `ContextIdMismatch`
/// → refused before install. The install slot (the REQUEST id) stays empty.
#[tokio::test]
async fn tamper_context_id_mismatch_is_refused_before_install() {
    let rec = RecordingPersistence::default();
    let (result, j) = run_join_with(
        0xc5,
        Some(Box::new(rec.clone())),
        Some(joiner_params()),
        joiner_params(),
        Some(ctx_hex(0xc6)), // a DIFFERENT id than the group commits (0xc5)
    )
    .await;
    assert_binding_refused_no_side_effects(result, &j, &rec).await;
}

/// FFI-02 rule 1: a Welcome for a WRAPPING-ONLY group (no `0xFF02` extension —
/// not an SCP context) is refused on join, even when the caller's params are
/// otherwise well-formed. No crypto installed, no snapshot persisted, no actor.
#[tokio::test]
async fn join_group_without_scp_context_extension_is_refused() {
    let rec = RecordingPersistence::default();
    let (result, j) = run_join_with(
        0xc7,
        Some(Box::new(rec.clone())),
        None, // wrapping-only group: NO 0xFF02 extension
        joiner_params(),
        None,
    )
    .await;

    let err = result.expect_err("a group with no 0xFF02 extension is not an SCP context");
    assert!(
        matches!(
            &err,
            crate::context::ContextError::CryptoFailed(msg)
                if msg.contains("spawn-from-Welcome refused")
                    && msg.contains("no scp_context_params (0xFF02)")
        ),
        "expected the rule-1 refusal (no 0xFF02 extension), got: {err:?}"
    );
    assert!(
        j.sup.local_mls_epoch(&j.ctx_id).await.is_none(),
        "no MLS group may be installed after a rule-1 refusal"
    );
    assert!(
        j.sup.lookup(&j.ctx_id).is_none(),
        "no actor handle may be registered after a rule-1 refusal"
    );
    assert!(
        rec.store.is_empty(),
        "no snapshot may be persisted after a rule-1 refusal"
    );
}

// ===========================================================================
// SIGNED §5.12.3 INVITATION-BUNDLE CRYPTO ACCEPTANCE (ADR-049 Phase 2J, FFI-02
// Option A). These pin the open → verify → structural → §5.13.3 ladder that
// spawn-from-Welcome runs BEFORE deriving any authority: authority comes ONLY
// from the creator-signed, HPKE-sealed bundle, never from caller-supplied loose
// params (BLACK-2J10-001 admin-hijack). Each rejection has NO side effects and,
// where the reject fires BEFORE the irreversible ConfirmConsume, does NOT burn
// the single-use KeyPackage.
//
// Coverage notes:
//   * "signed params disagree with the committed 0xFF02 group" is covered by the
//     `tamper_*_mismatch_is_refused_before_install` tests above — with the FFI-02
//     reshape those now carry the divergence INSIDE the creator-signed bundle
//     (`bundle.verify` + `verify_structural_consistency` pass; the kept §5.13.3
//     `0xFF02` cross-check against the committed group is what rejects).
//   * "wrong-signer rejected" is covered by
//     `non_creator_signed_bundle_is_rejected_before_kp_consume` below.
// ===========================================================================

/// BLACK-2J10-001 — a bundle signed by a NON-creator key is rejected at the
/// creator-signature verify (step 2), BEFORE the irreversible `ConfirmConsume`.
/// The bundle claims `creator_did = ALICE` and honest params, but is signed by an
/// ATTACKER key; the resolver resolves `ALICE -> alice_vk`, so `bundle.verify`
/// fails closed. The KeyPackage is NOT burned: the SAME reservation + Welcome,
/// retried with a validly creator-signed bundle, then succeeds (a burned KP would
/// fail closed at the fused consume, as Test D shows).
#[tokio::test]
async fn non_creator_signed_bundle_is_rejected_before_kp_consume() {
    let bob = DID::from(BOB_DID);
    let ctx_id = ctx_hex(0xd1);
    let ctx_bytes = context_id_to_bytes(&ctx_id);

    let (sup, bob_crypto) = bob_supervisor(None);
    let (reservation_id, kp_public_bytes) = reserve_bob_kp(&sup, &bob).await;
    let (_alice, welcome) = alice_welcome_for(&ctx_id, &kp_public_bytes);
    let (bob_custody, bob_handle, bob_recipient) = bob_active_custody().await;

    // Signed by an ATTACKER key, NOT alice's — `bundle.verify(alice_vk)` fails.
    let attacker = SigningKey::from_bytes(&[0xEE; 32]);
    let forged = seal_join_request(
        &attacker,
        &DID::from(ALICE_DID),
        &ctx_id,
        &joiner_params(),
        welcome.clone(),
        &bob_recipient,
        &ctx_id,
        &DID::from(ALICE_DID),
        reservation_id.clone(),
    );
    let err = sup
        .spawn_actor_from_welcome(bob.clone(), &bob_custody, &bob_handle, forged)
        .await
        .expect_err("a bundle NOT signed by the creator's #active key must be rejected");
    assert!(
        matches!(
            &err,
            crate::context::ContextError::CryptoFailed(msg) if msg.contains("signature invalid")
        ),
        "expected the creator-signature refusal, got: {err:?}"
    );
    // Reject fired before any state build — nothing installed, no actor.
    assert!(
        sup.local_mls_epoch(&ctx_id).await.is_none(),
        "no group may be installed after a signature refusal"
    );
    assert!(
        sup.lookup(&ctx_id).is_none(),
        "no actor may be registered after a signature refusal"
    );

    // KP NOT burned: the SAME reservation + Welcome, now validly creator-signed,
    // succeeds — proving the signature reject fired BEFORE `ConfirmConsume`.
    let honest = seal_join_request(
        &alice_signing_key(),
        &DID::from(ALICE_DID),
        &ctx_id,
        &joiner_params(),
        welcome,
        &bob_recipient,
        &ctx_id,
        &DID::from(ALICE_DID),
        reservation_id,
    );
    sup.spawn_actor_from_welcome(bob, &bob_custody, &bob_handle, honest)
        .await
        .expect("the retry with a creator-signed bundle succeeds — the KP was never burned");
    assert_eq!(
        sup.member_count(&ctx_id).await,
        Some(2),
        "the valid retry stands up the live joiner actor"
    );
}

/// A tampered HPKE ciphertext fails the AEAD open — the join is refused with
/// `CryptoFailed("... open failed ...")` and no crypto / actor is left resident.
/// The AEAD tag binds `enc || pkRm || info || aad || ct`, so a single flipped
/// ciphertext byte is fatal and indistinguishable from a wrong-key error.
#[tokio::test]
async fn tampered_ciphertext_fails_aead_open() {
    let bob = DID::from(BOB_DID);
    let ctx_id = ctx_hex(0xd2);
    let ctx_bytes = context_id_to_bytes(&ctx_id);

    let (sup, bob_crypto) = bob_supervisor(None);
    let (reservation_id, kp_public_bytes) = reserve_bob_kp(&sup, &bob).await;
    let (_alice, welcome) = alice_welcome_for(&ctx_id, &kp_public_bytes);
    let (bob_custody, bob_handle, bob_recipient) = bob_active_custody().await;

    let mut req = seal_join_request(
        &alice_signing_key(),
        &DID::from(ALICE_DID),
        &ctx_id,
        &joiner_params(),
        welcome,
        &bob_recipient,
        &ctx_id,
        &DID::from(ALICE_DID),
        reservation_id,
    );
    // Flip a ciphertext byte -> the AEAD tag no longer verifies.
    req.sealed_bundle_ct[0] ^= 0xFF;

    let err = sup
        .spawn_actor_from_welcome(bob, &bob_custody, &bob_handle, req)
        .await
        .expect_err("a tampered ciphertext must fail the AEAD open");
    assert!(
        matches!(
            &err,
            crate::context::ContextError::CryptoFailed(msg) if msg.contains("open failed")
        ),
        "expected the AEAD open-failure refusal, got: {err:?}"
    );
    assert!(
        sup.local_mls_epoch(&ctx_id).await.is_none(),
        "no group may be installed after an open failure"
    );
    assert!(
        sup.lookup(&ctx_id).is_none(),
        "no actor may be registered after an open failure"
    );
}

/// A corrupted creator signature (flipped BEFORE sealing, so the AEAD open still
/// succeeds) is rejected at `bundle.verify` — `CryptoFailed("... signature
/// invalid ...")`, no crypto / actor resident.
#[tokio::test]
async fn tampered_bundle_signature_is_rejected() {
    let bob = DID::from(BOB_DID);
    let ctx_id = ctx_hex(0xd3);
    let ctx_bytes = context_id_to_bytes(&ctx_id);

    let (sup, bob_crypto) = bob_supervisor(None);
    let (reservation_id, kp_public_bytes) = reserve_bob_kp(&sup, &bob).await;
    let (_alice, welcome) = alice_welcome_for(&ctx_id, &kp_public_bytes);
    let (bob_custody, bob_handle, bob_recipient) = bob_active_custody().await;

    let mut bundle = signed_bundle(
        &alice_signing_key(),
        &DID::from(ALICE_DID),
        &ctx_id,
        &joiner_params(),
        welcome,
    );
    // Corrupt the signature; the ciphertext stays intact so the open succeeds and
    // the creator-signature verify is what rejects.
    bundle.signature[0] ^= 0xFF;
    let req = seal_bundle(
        &bundle,
        &bob_recipient,
        &ctx_id,
        &DID::from(ALICE_DID),
        reservation_id,
        some_pseudonym(),
    );

    let err = sup
        .spawn_actor_from_welcome(bob, &bob_custody, &bob_handle, req)
        .await
        .expect_err("a corrupted bundle signature must be rejected");
    assert!(
        matches!(
            &err,
            crate::context::ContextError::CryptoFailed(msg) if msg.contains("signature invalid")
        ),
        "expected the creator-signature refusal, got: {err:?}"
    );
    assert!(
        sup.local_mls_epoch(&ctx_id).await.is_none(),
        "no group may be installed after a signature refusal"
    );
    assert!(
        sup.lookup(&ctx_id).is_none(),
        "no actor may be registered after a signature refusal"
    );
}

/// A bundle whose `metadata_snapshot.structural.governance` diverges from the
/// signed `context_params.governance` is a signed self-contradiction — rejected
/// by `verify_structural_consistency` (spec §5.12.3.1 step 2) with
/// `CryptoFailed("... metadata inconsistent ...")`, no crypto / actor resident.
/// The bundle is otherwise validly creator-signed, so this pins the structural
/// check specifically (not the signature).
#[tokio::test]
async fn structurally_inconsistent_bundle_is_rejected() {
    let bob = DID::from(BOB_DID);
    let ctx_id = ctx_hex(0xd4);
    let ctx_bytes = context_id_to_bytes(&ctx_id);

    let (sup, bob_crypto) = bob_supervisor(None);
    let (reservation_id, kp_public_bytes) = reserve_bob_kp(&sup, &bob).await;
    let (_alice, welcome) = alice_welcome_for(&ctx_id, &kp_public_bytes);
    let (bob_custody, bob_handle, bob_recipient) = bob_active_custody().await;

    // Hand-build a bundle whose structural governance diverges from the params
    // governance (bypassing `build_metadata_snapshot`, which copies structural
    // verbatim), then sign it VALIDLY.
    let params = joiner_params();
    let facts = SnapshotRuntimeFacts {
        member_count: Some(1),
        creator_did: Some(DID::from(ALICE_DID)),
        ..SnapshotRuntimeFacts::default()
    };
    let mut snapshot = build_metadata_snapshot(&params, facts);
    snapshot.structural.governance = GovernanceModel::Threshold {
        threshold: 1,
        signers: vec![DID::from("did:dht:z6MkStructuralInconsistencySigner")],
    };
    let mut bundle = InvitationBundle {
        context_id: ctx_id.clone(),
        creator_did: DID::from(ALICE_DID),
        relay_urls: vec![],
        welcome_message: welcome,
        key_material: InvitationKeyMaterial {
            context_metadata_key: [7u8; 32],
            sender_key_seed: None,
        },
        context_params: params,
        metadata_snapshot: snapshot,
        signature: vec![],
    };
    let hash = bundle
        .invitation_bundle_signing_hash()
        .expect("signing hash");
    bundle.signature = alice_signing_key().sign(&hash).to_bytes().to_vec();
    let req = seal_bundle(
        &bundle,
        &bob_recipient,
        &ctx_id,
        &DID::from(ALICE_DID),
        reservation_id,
        some_pseudonym(),
    );

    let err = sup
        .spawn_actor_from_welcome(bob, &bob_custody, &bob_handle, req)
        .await
        .expect_err("a structurally inconsistent bundle must be rejected");
    assert!(
        matches!(
            &err,
            crate::context::ContextError::CryptoFailed(msg) if msg.contains("metadata inconsistent")
        ),
        "expected the structural-consistency refusal, got: {err:?}"
    );
    assert!(
        sup.local_mls_epoch(&ctx_id).await.is_none(),
        "no group may be installed after a structural refusal"
    );
    assert!(
        sup.lookup(&ctx_id).is_none(),
        "no actor may be registered after a structural refusal"
    );
}

// ---------------------------------------------------------------------------
// Test M — the flagship end-to-end round trip: `Supervisor::invite_member`
// (creator side) → `spawn_actor_from_welcome` (joiner side). A real MLS
// add-member + a creator-signed, HPKE-sealed §5.12.3 bundle stands the invitee
// up as a live, bidirectionally-functional member.
// ---------------------------------------------------------------------------

/// Alice creates an encrypted context, `invite_member` produces the signed,
/// sealed invitation for Bob's reserved KeyPackage, and Bob's
/// `spawn_actor_from_welcome` opens it (split custody), verifies the creator
/// signature, and stands up a live actor whose installed group round-trips MLS
/// traffic in BOTH directions. Bob's #active custody holds the SAME key
/// `pair_resolver` returns for `BOB_DID`, so the invitation (sealed to that
/// resolved #active) opens.
#[tokio::test]
async fn invite_member_round_trip_stands_up_a_bidirectional_joiner() {
    let ctx_id = ctx_hex(0xd5);
    let ctx_bytes = context_id_to_bytes(&ctx_id);
    let alice = DID::from(ALICE_DID);
    let bob = DID::from(BOB_DID);

    // (a) Alice creates the encrypted context.
    let (alice_sup, alice_crypto) = alice_supervisor();
    alice_sup
        .create_context(
            ctx_id.clone(),
            joiner_params(),
            alice.clone(),
            some_pseudonym(),
        )
        .await
        .expect("alice creates the encrypted context");

    // (b) Bob reserves a KeyPackage from HIS OWN supervisor + store (declares
    //     0xFF02 via `reserve_bob_kp`'s wrapping-key publish).
    let (bob_sup, bob_crypto) = bob_supervisor(None);
    let (reservation_id, kp_public_bytes) = reserve_bob_kp(&bob_sup, &bob).await;

    // (c) Alice invites Bob: the add is routed through the context actor's
    //     governance gate (SingleAdmin → auto-executes the real in-actor MLS
    //     add), then the returned Welcome is signed + sealed into a §5.12.3
    //     bundle with alice's #active key.
    let outcome = alice_sup
        .invite_member(
            ctx_id.clone(),
            alice.clone(),
            bob.clone(),
            kp_public_bytes,
            vec![],
            &alice_signing_key(),
        )
        .await
        .expect("alice seals an invitation for bob");
    // SingleAdmin creator invite must SEAL (governed contexts return `Err`, not a
    // deferral). The `Sealed` bundle is the SAME `SealedInvitation` wire type the
    // joiner consumes below — directly usable as the join input with no re-boxing
    // (the runtime `WelcomeJoinRequest` reads its `enc`/`ciphertext` straight off
    // the bundle). `enc` is validated to be exactly 32 bytes at the seal.
    let InviteMemberOutcome::Sealed { bundle, .. } = outcome;
    let enc =
        <[u8; 32]>::try_from(bundle.enc.as_slice()).expect("sealed bundle enc is exactly 32 bytes");
    let ciphertext = bundle.ciphertext;

    // (c') The creator's OWN role_state now reflects Bob (the split-brain the
    //      old off-mailbox add left behind is closed: the add ran in-actor).
    assert_eq!(
        alice_sup.member_count(&ctx_id).await,
        Some(2),
        "the in-actor governance add updates the CREATOR's membership/role_state"
    );

    // (d) Bob joins. His #active custody holds the fixed BOB seed = the key
    //     `pair_resolver` returns for BOB, which is what `invite_member` sealed to.
    let (bob_custody, bob_handle) = bob_imported_custody().await;
    let req = WelcomeJoinRequest {
        context_id: ctx_id.clone(),
        creator_did: alice.clone(),
        sealed_bundle_enc: enc,
        sealed_bundle_ct: ciphertext,
        reservation_id,
        local_pseudonym: some_pseudonym(),
    };
    let handle = bob_sup
        .spawn_actor_from_welcome(bob.clone(), &bob_custody, &bob_handle, req)
        .await
        .expect("bob joins from alice's real invitation");
    assert_eq!(handle.context_id(), ctx_id);

    // (e) Bob is a live, registered member and his joined group is installed.
    assert_eq!(
        bob_sup.member_count(&ctx_id).await,
        Some(2),
        "the invited joiner stands up a live, send-capable actor"
    );
    assert!(
        bob_sup.local_mls_epoch(&ctx_id).await.is_some(),
        "bob's joined MLS group is installed"
    );

    // Bidirectional MLS traffic through the invitation-installed group. Both
    // parties move onto the actor seam (the provider mls_encrypt_management / open
    // twins are deleted post-ADR-049 PR-7); management traffic is group-keyed.
    let routing_id = scp_protocol::context::context_routing_id(&hex::encode(ctx_bytes));
    let mut alice_actor = take_into_actor(&alice_crypto, &ctx_bytes);
    let mut bob_actor = take_into_actor(&bob_crypto, &ctx_bytes);
    let from_alice = b"invite-member-round-trip-from-alice";
    let wrapped_alice = alice_actor
        .mls_encrypt_management(from_alice, &routing_id, 3600)
        .expect("alice encrypts a management message");
    let opened_alice = bob_actor
        .open(&scp_clock::SystemClock, &ctx_id, &wrapped_alice)
        .expect("bob opens alice's message");
    assert!(
        matches!(
            &opened_alice,
            OpenResult::Management { payload, .. } if payload.as_slice() == from_alice.as_slice()
        ),
        "bob decrypts alice's traffic through the invitation-installed group; got {opened_alice:?}"
    );

    let from_bob = b"invite-member-round-trip-from-bob";
    let wrapped_bob = bob_actor
        .mls_encrypt_management(from_bob, &routing_id, 3600)
        .expect("bob encrypts a management message");
    let opened_bob = alice_actor
        .open(&scp_clock::SystemClock, &ctx_id, &wrapped_bob)
        .expect("alice opens bob's message");
    assert!(
        matches!(
            &opened_bob,
            OpenResult::Management { payload, .. } if payload.as_slice() == from_bob.as_slice()
        ),
        "alice decrypts bob's traffic — bidirectional round-trip closed; got {opened_bob:?}"
    );
}

// ---------------------------------------------------------------------------
// Test M2 — root fix: the governance AddMember broadcasts its epoch Commit.
// ---------------------------------------------------------------------------

/// A transport that watches for a non-empty `send_message` to ONE expected
/// routing id and flips an atomic flag when it sees one. Used to prove the
/// add-member Commit was broadcast to existing members. `send_message`
/// succeeds (so the Commit is delivered, not enqueued for retry); all other
/// operations are inert. An [`AtomicBool`](std::sync::atomic::AtomicBool)
/// avoids a `Mutex` on the sync transport hot path.
struct BroadcastWatchTransport {
    /// The routing id whose broadcast proves the fix (`context_routing_id`).
    expected_routing: [u8; 32],
    /// Set to `true` when a non-empty `send_message` to `expected_routing` is
    /// observed.
    saw_broadcast: Arc<std::sync::atomic::AtomicBool>,
}

#[async_trait::async_trait]
impl ContextTransportProvider for BroadcastWatchTransport {
    fn is_connected(&self) -> bool {
        true
    }

    async fn publish_context(
        &self,
        _context_id: &[u8; 32],
        _params: &ContextParams,
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        Ok(())
    }

    async fn delete_published(
        &self,
        _context_id: &[u8; 32],
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        Ok(())
    }

    async fn send_message(
        &self,
        context_id: &[u8; 32],
        encrypted_payload: &[u8],
    ) -> Result<(), crate::context::ContextError> {
        if *context_id == self.expected_routing && !encrypted_payload.is_empty() {
            self.saw_broadcast
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        Ok(())
    }
}

/// Builds Alice's creator supervisor wired to a caller-supplied transport (so a
/// test can observe the outbound Commit broadcast). Mirrors [`alice_supervisor`]
/// otherwise.
fn alice_supervisor_with_transport(
    transport: Box<dyn ContextTransportProvider>,
) -> (Arc<Supervisor>, Arc<MlsCryptoProvider>) {
    let crypto = Arc::new(MlsCryptoProvider::new(
        ALICE_DID.to_owned(),
        std::sync::Arc::new(scp_clock::SystemClock),
    ));
    let event_log: Box<dyn ContextEventLogProvider> = Box::new(MerkleEventLogProvider::new());
    let sup = Supervisor::with_providers(
        Arc::clone(&crypto),
        transport,
        event_log,
        pair_resolver(),
        None,
        None,
        None,
        None,
        fresh_mls_storage(),
    );
    (sup, crypto)
}

/// Proves the ROOT fix: `execute_add_member` now broadcasts the epoch-advancing
/// MLS Commit to the existing members (parity with remove/reset). Before the
/// fix the add's Commit was only buffered into the broadcast-suppressed
/// `WelcomeGenerated` event and NEVER hit the transport — so an add into a
/// multi-member context silently desynced every existing member. Here the
/// invite routes `AddMember` through the actor; the recording transport must
/// capture a `send_message` to the context routing id carrying the Commit.
#[tokio::test]
async fn invite_member_broadcasts_the_add_commit_to_existing_members() {
    let ctx_id = ctx_hex(0xd6);
    let alice = DID::from(ALICE_DID);
    let bob = DID::from(BOB_DID);

    let want_routing = scp_protocol::context::context_routing_id(&ctx_id);
    let saw_broadcast = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let transport = BroadcastWatchTransport {
        expected_routing: want_routing,
        saw_broadcast: Arc::clone(&saw_broadcast),
    };
    let (alice_sup, _alice_crypto) = alice_supervisor_with_transport(Box::new(transport));
    alice_sup
        .create_context(
            ctx_id.clone(),
            joiner_params(),
            alice.clone(),
            some_pseudonym(),
        )
        .await
        .expect("alice creates the encrypted context");

    let (bob_sup, _bob_crypto) = bob_supervisor(None);
    let (_reservation_id, kp_public_bytes) = reserve_bob_kp(&bob_sup, &bob).await;

    let outcome = alice_sup
        .invite_member(
            ctx_id.clone(),
            alice.clone(),
            bob.clone(),
            kp_public_bytes,
            vec![],
            &alice_signing_key(),
        )
        .await
        .expect("alice invites bob");
    assert!(
        matches!(outcome, InviteMemberOutcome::Sealed { .. }),
        "SingleAdmin invite seals a bundle"
    );

    // The add's Commit must have been broadcast to the context routing id.
    assert!(
        saw_broadcast.load(std::sync::atomic::Ordering::SeqCst),
        "the in-actor governance add must broadcast its epoch Commit to existing \
         members (a non-empty send_message to the context routing id)"
    );
}

// ---------------------------------------------------------------------------
// Test M3 — auth by construction: a voting context refuses the invite.
// ---------------------------------------------------------------------------

/// A voting governance model (`Threshold`) does NOT authorize a unilateral
/// invite. `invite_member` refuses BEFORE proposing — it does NOT create a
/// dead-on-arrival pending proposal — and returns
/// `Err(ContextError::InvalidState)` because governed-context invitations are
/// not yet implemented, adding NO member (no sealed bundle, no MLS add, no
/// proposal). This is the structural auth gate: an honest error, not a
/// phantom-success outcome that drops the invite while claiming a deferral.
#[tokio::test]
async fn invite_member_into_voting_context_is_rejected() {
    let ctx_id = ctx_hex(0xd7);
    let alice = DID::from(ALICE_DID);
    let bob = DID::from(BOB_DID);

    let voting_params = ContextParams {
        governance: GovernanceModel::Threshold {
            threshold: 2,
            signers: vec![alice.clone(), bob.clone()],
        },
        ..joiner_params()
    };

    let (alice_sup, _alice_crypto) = alice_supervisor();
    alice_sup
        .create_context(
            ctx_id.clone(),
            voting_params,
            alice.clone(),
            some_pseudonym(),
        )
        .await
        .expect("alice creates the voting context");

    let (bob_sup, _bob_crypto) = bob_supervisor(None);
    let (_reservation_id, kp_public_bytes) = reserve_bob_kp(&bob_sup, &bob).await;

    let err = alice_sup
        .invite_member(
            ctx_id.clone(),
            alice.clone(),
            bob.clone(),
            kp_public_bytes,
            vec![],
            &alice_signing_key(),
        )
        .await
        .expect_err("a voting context refuses a unilateral invite with an error");

    // The refusal is an honest `InvalidState` error — no phantom-success
    // outcome, no proposal, no member.
    assert!(
        matches!(err, crate::context::ContextError::InvalidState(_)),
        "a unilateral invite into a voting context is refused with InvalidState; got {err:?}"
    );
    // No member was added — the add did not run.
    assert_eq!(
        alice_sup.member_count(&ctx_id).await,
        Some(1),
        "the refused invite adds NO member to the voting context"
    );
    // And NO proposal was created: the SingleAdmin-only gate returns before any
    // governance proposal is submitted, so the context has zero pending
    // proposals.
    assert!(
        alice_sup
            .list_proposals(&ctx_id)
            .await
            .expect("listing proposals succeeds")
            .is_empty(),
        "the refused invite creates NO governance proposal"
    );
}

// ---------------------------------------------------------------------------
// Test M4 — auth by construction: a non-admin caller cannot invite.
// ---------------------------------------------------------------------------

/// A non-admin caller inviting into a `SingleAdmin` context is rejected by the
/// governance gate (`propose_governance_action_checked` verifies the proposer's
/// `governance:propose` capability, and `SingleAdminEngine::propose` rejects any
/// non-admin proposer). `invite_member` returns `Err` and adds NO member —
/// authorization is a property of the governance gate, not an ad-hoc check.
#[tokio::test]
async fn invite_member_by_non_admin_is_rejected() {
    let ctx_id = ctx_hex(0xd8);
    let alice = DID::from(ALICE_DID);
    let bob = DID::from(BOB_DID);

    // Alice creates the SingleAdmin context (she is the admin).
    let (alice_sup, _alice_crypto) = alice_supervisor();
    alice_sup
        .create_context(
            ctx_id.clone(),
            joiner_params(),
            alice.clone(),
            some_pseudonym(),
        )
        .await
        .expect("alice creates the encrypted SingleAdmin context");

    // Bob (NOT the admin, not even a member) reserves a KeyPackage and attempts
    // to invite himself using HIS OWN signing key as the proposer.
    let (bob_sup, _bob_crypto) = bob_supervisor(None);
    let (_reservation_id, kp_public_bytes) = reserve_bob_kp(&bob_sup, &bob).await;

    let result = alice_sup
        .invite_member(
            ctx_id.clone(),
            bob.clone(),
            bob.clone(),
            kp_public_bytes,
            vec![],
            &bob_signing_key(),
        )
        .await;

    assert!(
        result.is_err(),
        "a non-admin caller must not be able to invite into a SingleAdmin context; got {result:?}"
    );
    // No member was added — the governance gate rejected before the add ran.
    assert_eq!(
        alice_sup.member_count(&ctx_id).await,
        Some(1),
        "a rejected non-admin invite adds NO member"
    );
}

// ---------------------------------------------------------------------------
// Test M5 — no zombie member on a post-add sealing/delivery failure (FIX 4).
// ---------------------------------------------------------------------------

/// A transport that BROADCASTS successfully (so the add's epoch Commit is
/// delivered and the add itself succeeds) but whose invitation delivery
/// (`send_to_routing_id`) returns a FATAL (non-`TransportFailed`) error. This
/// drives the post-add failure path: the invitee is really added, but the sealed
/// Welcome can never be delivered.
struct FatalDeliveryTransport;

#[async_trait::async_trait]
impl ContextTransportProvider for FatalDeliveryTransport {
    fn is_connected(&self) -> bool {
        true
    }

    async fn publish_context(
        &self,
        _context_id: &[u8; 32],
        _params: &ContextParams,
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        Ok(())
    }

    async fn delete_published(
        &self,
        _context_id: &[u8; 32],
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        Ok(())
    }

    // Commit broadcast succeeds (so both the add and the compensating remove
    // deliver their epoch Commits without enqueuing).
    async fn send_message(
        &self,
        _context_id: &[u8; 32],
        _encrypted_payload: &[u8],
    ) -> Result<(), crate::context::ContextError> {
        Ok(())
    }

    // Invitation delivery fails FATALLY (not `TransportFailed`), so the invitee
    // gets nothing — this is the case that must trigger the compensating remove.
    async fn send_to_routing_id(
        &self,
        _routing_id: &[u8; 32],
        _payload: &[u8],
        _ttl: u32,
    ) -> Result<(), crate::context::ContextError> {
        Err(crate::context::ContextError::CryptoFailed(
            "fatal invitation delivery failure (test)".to_owned(),
        ))
    }
}

/// Proves FIX 4: after the governance add commits (real MLS add + role_state +
/// broadcast Commit), a FATAL failure in the invitation sealing/delivery path
/// must NOT leave a zombie member behind. `invite_member` dispatches a
/// compensating `RemoveMember` through the same actor governance gate (which
/// broadcasts its own Commit) and surfaces the original error, so the group is
/// restored to its pre-invite membership.
#[tokio::test]
async fn invite_member_rolls_back_the_add_on_delivery_failure() {
    let ctx_id = ctx_hex(0xd9);
    let alice = DID::from(ALICE_DID);
    let bob = DID::from(BOB_DID);

    let (alice_sup, _alice_crypto) =
        alice_supervisor_with_transport(Box::new(FatalDeliveryTransport));
    alice_sup
        .create_context(
            ctx_id.clone(),
            joiner_params(),
            alice.clone(),
            some_pseudonym(),
        )
        .await
        .expect("alice creates the encrypted context");

    let (bob_sup, _bob_crypto) = bob_supervisor(None);
    let (_reservation_id, kp_public_bytes) = reserve_bob_kp(&bob_sup, &bob).await;

    let result = alice_sup
        .invite_member(
            ctx_id.clone(),
            alice.clone(),
            bob.clone(),
            kp_public_bytes,
            vec![],
            &alice_signing_key(),
        )
        .await;

    // The fatal delivery error is surfaced to the caller.
    assert!(
        result.is_err(),
        "a fatal post-add delivery failure surfaces as an error; got {result:?}"
    );
    // And the added member was rolled back — no zombie. The compensating remove
    // ran through the actor governance gate, so the creator's membership is back
    // to just alice.
    assert_eq!(
        alice_sup.member_count(&ctx_id).await,
        Some(1),
        "the compensating remove rolls back the added member — no zombie member remains"
    );
}

// ---------------------------------------------------------------------------
// Test N — BLACK-2J10-001-R creator-substitution regression (§5.13.3 rule 8).
// ---------------------------------------------------------------------------

/// An honest SingleAdmin context commits `creator_did = Alice` into its `0xFF02`
/// group-context extension. Mallory (an in-group member) forges an invitation
/// bundle that names HERSELF as `creator_did`, signs it with her OWN key (which
/// the resolver resolves, so the bundle signature verifies), and carries Alice's
/// REAL params — so every bundle check passes. The join is nonetheless REJECTED
/// by the §5.13.3 rule-8 creator binding (`bundle.creator_did` != the committed
/// genesis creator), BEFORE any `SingleAdminEngine(Mallory)` is built or any
/// crypto is installed.
///
/// Without the creator binding this attack succeeds: `GovernanceModel::SingleAdmin`
/// is a DID-less unit variant, so `governance_policy_hash` is a CONSTANT that
/// matches regardless of who the admin is — no other §5.13.3 rule catches the
/// substitution, and `build_welcome_joiner_state` would install Mallory as the
/// context admin.
#[tokio::test]
async fn spawn_from_welcome_rejects_creator_substitution_before_admin_install() {
    let bob = DID::from(BOB_DID);
    let ctx_id = ctx_hex(0x9e);
    let ctx_bytes = context_id_to_bytes(&ctx_id);
    // Default governance is SingleAdmin (a DID-less unit variant) — the vulnerable
    // case whose `governance_policy_hash` commits no identity.
    let params = joiner_params();
    assert!(
        matches!(params.governance, GovernanceModel::SingleAdmin),
        "the regression targets the DID-less SingleAdmin governance model"
    );

    // Bob's joiner supervisor with a resolver that also resolves Mallory, so her
    // self-signed bundle passes the signature check and the rule-8 binding is the
    // sole reason for rejection.
    let (sup, bob_crypto) = bob_supervisor_with_resolver(None, trio_resolver());
    let (reservation_id, kp_public_bytes) = reserve_bob_kp(&sup, &bob).await;

    // Alice creates the honest SCP group (its `0xFF02` extension commits
    // creator = Alice via `honest_ext`) and adds Bob's reserved KP, producing the
    // real Welcome. The committed extension rides through the add Commit unchanged
    // as part of the group's cryptographic identity, so it still binds creator =
    // Alice regardless of who issued the add.
    let alice_crypto = Arc::new(MlsCryptoProvider::new(
        ALICE_DID.to_owned(),
        std::sync::Arc::new(scp_clock::SystemClock),
    ));
    alice_crypto
        .create_mls_group_with_context(&ctx_bytes, &honest_ext(&ctx_id, &params))
        .expect("alice creates the honest SCP context group committing creator=Alice");
    let add_output = alice_crypto
        .add_member(&ctx_bytes, BOB_DID, Some(&kp_public_bytes))
        .expect("alice adds bob's reserved key package");

    // Mallory's forged bundle: creator_did = Mallory, signed with Mallory's key,
    // params = Alice's REAL params. Hints == Mallory so the HPKE open succeeds and
    // the §5.13.3 rule-8 binding is what rejects (not the open or the signature).
    let mallory = DID::from(MALLORY_DID);
    let (bob_custody, bob_handle, bob_recipient) = bob_active_custody().await;
    let bundle = signed_bundle(
        &mallory_signing_key(),
        &mallory,
        &ctx_id,
        &params,
        add_output.welcome_bytes,
    );
    let req = seal_bundle(
        &bundle,
        &bob_recipient,
        &ctx_id,
        &mallory,
        reservation_id,
        some_pseudonym(),
    );

    let err = sup
        .spawn_actor_from_welcome(bob, &bob_custody, &bob_handle, req)
        .await
        .expect_err("a creator-substituted bundle must be rejected");

    // The rejection is the §5.13.3 rule-8 creator-DID binding (surfaced as a
    // CryptoFailed carrying the `0xFF02` binding-mismatch reason).
    assert!(
        matches!(err, crate::context::ContextError::CryptoFailed(_)),
        "expected CryptoFailed for the creator-binding rejection, got {err:?}"
    );
    let msg = format!("{err}");
    assert!(
        msg.contains("creator DID mismatch") && msg.contains("0xFF02"),
        "expected a §5.13.3 rule-8 creator-binding rejection naming 0xFF02, got: {msg}"
    );

    // No `SingleAdminEngine(Mallory)`: the binding check fires BEFORE
    // `install_joined_group` and `build_welcome_joiner_state` (which builds the
    // governance engine from `creator_did`), so NO context actor is registered
    // and Bob's crypto provider has NO installed group for this id.
    assert!(
        sup.lookup(&ctx_id).is_none(),
        "no context actor may be registered for a creator-substituted join — \
         build_welcome_joiner_state (and SingleAdminEngine::new) never ran"
    );
    assert_eq!(
        sup.member_count(&ctx_id).await,
        None,
        "an unregistered context yields None member_count — no admin was installed"
    );
    assert!(
        sup.local_mls_epoch(&ctx_id).await.is_none(),
        "no MLS group may be installed after a creator-binding rejection"
    );
}

// ---------------------------------------------------------------------------
// FIX 1 (BLACK-2JF-01) — `discard_joined_context` is a COMPLETE teardown.
// ---------------------------------------------------------------------------

/// The FFI compensating path (a post-irreversible-commit join step failing —
/// e.g. a concurrent close/leave removed the bridge state before the
/// authenticated ceiling could be synced) must FULLY reverse what
/// `spawn_actor_from_welcome` materialized, not merely drop the in-memory actor
/// handle. `discard_joined_context` removes the actor AND destroys the resident
/// MLS crypto group AND deletes the durable Class-S snapshot the join persisted,
/// mirroring the entrypoint's OWN post-consume rollback arms. A bare
/// `despawn_actor` would leave the crypto group + snapshot behind, so on restart
/// the "torn-down" context would RESURRECT (FFI/runtime divergence) and the
/// residual snapshot would block a fresh re-join via the durable
/// first-writer-wins precheck (Precheck D).
///
/// This drives a REAL happy-path join (installs a group, registers an actor,
/// persists a snapshot into the shared recording store), asserts all three
/// pieces of state exist, then calls `discard_joined_context` and asserts each
/// is fully reversed: no actor handle remains, the crypto group is destroyed,
/// and no durable snapshot remains — so a subsequent restore (which reads
/// `load_context`) finds NOTHING to resurrect.
#[tokio::test]
async fn discard_joined_context_fully_reverses_a_welcome_join() {
    let rec = RecordingPersistence::default();
    let (result, j) = join_bob(0x6d, Some(Box::new(rec.clone()))).await;
    result.expect("the happy-path join succeeds");

    // --- Pre-teardown: all three pieces of join state are present. ---
    assert!(
        j.sup.lookup(&j.ctx_id).is_some(),
        "a live context actor is registered for the joiner"
    );
    assert!(
        j.sup.local_mls_epoch(&j.ctx_id).await.is_some(),
        "the joined MLS group is resident in the crypto provider"
    );
    assert!(
        rec.load_context(&j.ctx_id)
            .await
            .expect("load never errors")
            .is_some(),
        "the join persisted an initial Class-S snapshot"
    );

    // Populate the supervisor-owned Class-M floor registry with a real
    // per-sender registry floor for this ctx (as the mirror-forward would on
    // live traffic) so the teardown has non-empty state to prune (ADR-049
    // PR-4). `max_advance = u64::MAX` keeps the single +1 advance well within
    // the overshoot ceiling without importing the const.
    j.sup
        .check_and_advance_sender_epoch(&j.ctx_bytes, BOB_DID, 1, u64::MAX)
        .expect("first sender-epoch advance is accepted");
    assert!(
        j.sup.floors.contains_key(&j.ctx_bytes),
        "a registry floor entry exists for the joined context before teardown"
    );

    // --- COMPLETE teardown (the FFI compensating path). ---
    let removed = j.sup.discard_joined_context(&j.ctx_id).await;
    assert!(
        removed,
        "discard_joined_context reports it removed the live actor handle"
    );

    // 1. Actor handle gone — no orphaned live actor lingers.
    assert!(
        j.sup.lookup(&j.ctx_id).is_none(),
        "the actor handle is removed"
    );
    assert_eq!(
        j.sup.member_count(&j.ctx_id).await,
        None,
        "an unregistered context yields None member_count (the mailbox is gone)"
    );

    // 2. Crypto group destroyed — a bare `despawn_actor` would leave it
    //    resident (`local_mls_epoch` answers `None` once the actor's MLS group
    //    is gone / the actor is despawned).
    assert!(
        j.sup.local_mls_epoch(&j.ctx_id).await.is_none(),
        "the resident MLS group is destroyed"
    );

    // 3. Durable snapshot deleted → a restore finds NOTHING to resurrect and
    //    Precheck D no longer blocks a fresh re-join. The delete was actually
    //    issued to the backend (recorded), and a subsequent load is empty.
    assert!(
        rec.load_context(&j.ctx_id)
            .await
            .expect("load never errors")
            .is_none(),
        "no durable snapshot remains — a restore cannot resurrect the context"
    );
    assert!(
        rec.deletes.contains(&j.ctx_id),
        "the snapshot delete was issued to the persistence backend"
    );

    // 4. Supervisor-owned Class-M floor registry entry pruned (ADR-049 PR-4) —
    //    mirrors the provider's per-context floor-map prune inside
    //    `destroy_mls_group`. Without this the authoritative registry would leak a
    //    `ContextFloors` entry (and its per-sender maps) for every torn-down
    //    context. Safe on permanent teardown: a re-created deterministic id is a
    //    NEW MLS group with fresh keys, so the discarded floors are moot.
    assert!(
        !j.sup.floors.contains_key(&j.ctx_bytes),
        "the registry floor entry is pruned on permanent teardown — no leak"
    );
}

// ---------------------------------------------------------------------------
// Test N — §9(b) runtime pin: the joiner is `Active` AND send-capable through
// its actor command path (not merely crypto-capable).
// ---------------------------------------------------------------------------

/// A transport that accepts every `send_message` (returns `Ok`, so the send
/// pipeline completes rather than fail-closed on the `NotConfigured` default)
/// and counts the non-empty application ciphertexts it observes. An
/// [`AtomicUsize`](std::sync::atomic::AtomicUsize) keeps the sync transport hot
/// path lock-free.
struct AcceptingSendTransport {
    /// Incremented for each non-empty `send_message` payload observed.
    sends: Arc<std::sync::atomic::AtomicUsize>,
}

#[async_trait::async_trait]
impl ContextTransportProvider for AcceptingSendTransport {
    fn is_connected(&self) -> bool {
        true
    }

    async fn publish_context(
        &self,
        _context_id: &[u8; 32],
        _params: &ContextParams,
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        Ok(())
    }

    async fn delete_published(
        &self,
        _context_id: &[u8; 32],
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        Ok(())
    }

    async fn send_message(
        &self,
        _context_id: &[u8; 32],
        encrypted_payload: &[u8],
    ) -> Result<(), crate::context::ContextError> {
        if !encrypted_payload.is_empty() {
            self.sends.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        Ok(())
    }
}

/// Builds Bob's real joiner `Supervisor` wired to a caller-supplied transport so
/// a test can drive a REAL application send through the spawned joiner's actor
/// and observe it succeed (the [`bob_supervisor`] default is
/// `NotConfiguredTransportProvider`, whose `send_message` fails closed).
/// Mirrors [`bob_supervisor`] otherwise.
fn bob_supervisor_with_transport(transport: Box<dyn ContextTransportProvider>) -> Arc<Supervisor> {
    let crypto = Arc::new(MlsCryptoProvider::new(
        BOB_DID.to_owned(),
        std::sync::Arc::new(scp_clock::SystemClock),
    ));
    let event_log: Box<dyn ContextEventLogProvider> = Box::new(MerkleEventLogProvider::new());
    Supervisor::with_providers(
        crypto,
        transport,
        event_log,
        pair_resolver(),
        None,
        None,
        None,
        None,
        fresh_mls_storage(),
    )
}

/// §9(b) RUNTIME pin: the Welcome-joiner that `spawn_actor_from_welcome` stands
/// up is `Active` and SEND-CAPABLE through its actor command path — not merely
/// crypto-capable.
///
/// The existing round-trip tests
/// ([`spawn_from_welcome_group_round_trips_both_directions`],
/// [`invite_member_round_trip_stands_up_a_bidirectional_joiner`]) drive
/// `mls_encrypt_management` DIRECTLY on the crypto provider, which BYPASSES the
/// lifecycle send-gate: an application send routed through
/// `Supervisor::send_message` (→ `MessagingCommand::SendMessage` →
/// `state::require_active` in `messaging.rs`) is the ONLY path that exercises
/// it. Step 3a of `spawn_actor_from_welcome` transitions the joiner's handle to
/// `Active`; without it the handle is stuck in `Creating` and every
/// `Active`-gated operation fails closed with `ContextError::ContextNotActive`.
///
/// This test therefore FAILS if step 3a is reverted — the direct pin sees
/// `Creating` instead of `Active`, and the behavioral pin's send returns
/// `Err(ContextNotActive)` instead of `Ok`.
#[tokio::test]
async fn spawn_from_welcome_joiner_is_active_and_send_capable() {
    let seed = 0x2f;
    let bob = DID::from(BOB_DID);
    let alice = DID::from(ALICE_DID);
    let group_ctx_id = ctx_hex(seed);
    let group_ctx_bytes = context_id_to_bytes(&group_ctx_id);

    // Bob's joiner supervisor wired to a WORKING (accepting) transport so a real
    // send returns `Ok` rather than the `NotConfigured` fail-closed default.
    let sends = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let sup = bob_supervisor_with_transport(Box::new(AcceptingSendTransport {
        sends: Arc::clone(&sends),
    }));

    // Bob reserves a real KP from his own store (§9.16.1 wrapping key published
    // so the KP declares `0xFF02`).
    let (reservation_id, kp_public_bytes) = reserve_bob_kp(&sup, &bob).await;

    // Alice (bare creator provider) creates the honest SCP context group and
    // adds Bob's reserved KP, producing the real Welcome addressed to that KP.
    let alice_crypto = Arc::new(MlsCryptoProvider::new(
        ALICE_DID.to_owned(),
        std::sync::Arc::new(scp_clock::SystemClock),
    ));
    alice_crypto
        .create_mls_group_with_context(
            &group_ctx_bytes,
            &honest_ext(&group_ctx_id, &joiner_params()),
        )
        .expect("alice creates the SCP context group (0xFF02)");
    let add_output = alice_crypto
        .add_member(&group_ctx_bytes, BOB_DID, Some(&kp_public_bytes))
        .expect("alice adds bob's reserved key package");

    // Seal the creator-signed §5.12.3 bundle to Bob's #active and spawn.
    let (bob_custody, bob_handle, bob_recipient) = bob_active_custody().await;
    let req = seal_join_request(
        &alice_signing_key(),
        &alice,
        &group_ctx_id,
        &joiner_params(),
        add_output.welcome_bytes,
        &bob_recipient,
        &group_ctx_id,
        &alice,
        reservation_id,
    );
    let handle = sup
        .spawn_actor_from_welcome(bob.clone(), &bob_custody, &bob_handle, req)
        .await
        .expect("spawn_actor_from_welcome succeeds on a valid Welcome");

    // (a) DIRECT PIN — the joiner's lifecycle handle is `Active` post-spawn
    //     (sync getter after item-2's ArcSwap conversion). FAILS with `Creating`
    //     if step 3a is reverted.
    assert_eq!(
        handle.state(),
        scp_protocol::context::ContextState::Active,
        "spawn_actor_from_welcome must leave the joiner handle Active (§9(b))"
    );

    // (b) BEHAVIORAL PIN — a real application send routed through the joiner's
    //     actor command path passes `require_active`. Seed Alice's per-member
    //     pseudonym so the 2-member fan-out (§9.10.4) has a recipient routing id.
    sup.seed_peer_pseudonym(&group_ctx_id, alice.clone(), [0x42; 32])
        .await
        .expect("seed alice's per-member pseudonym");

    let result = sup
        .send_message(
            &handle,
            &bob,
            b"joiner send after welcome (\xc2\xa79b)",
            MessageSigner::Active(&bob_signing_key()),
            None,
            None,
        )
        .await;
    assert!(
        result.is_ok(),
        "the joiner's actor must accept an application send (require_active \
         passes); a reverted step-3a activation yields Err(ContextNotActive). \
         Got: {result:?}"
    );

    // The send actually reached the wire (a non-empty application ciphertext was
    // broadcast to Alice's pseudonym), so the `Ok` is a real send, not a no-op.
    assert!(
        sends.load(std::sync::atomic::Ordering::SeqCst) >= 1,
        "the accepted send must have produced at least one application ciphertext"
    );
}

// ---------------------------------------------------------------------------
// Test §9(b)-app — a real B→A APPLICATION-DATA round-trip (coverage gap pin).
// ---------------------------------------------------------------------------

/// §9(b) APPLICATION-path pin: a Welcome-joiner (Bob) seals a real application
/// message and the creator (Alice) opens it.
///
/// # Why this test exists (the coverage gap that shipped a bug green)
///
/// The existing bidirectional round-trip tests
/// ([`spawn_from_welcome_group_round_trips_both_directions`],
/// [`invite_member_round_trip_stands_up_a_bidirectional_joiner`]) drive
/// [`MlsCryptoProvider::mls_encrypt_management`] / [`MlsCryptoProvider::open`],
/// which travels the MANAGEMENT path: MLS-encrypt only, decoded as
/// [`OpenResult::Management`]. That path NEVER touches the per-sender key layer.
/// Application messages ride an extra AEAD layer keyed by the sender's sender
/// key (distributed out-of-band via HPKE), decoded as [`OpenResult::Application`].
///
/// Because no test exercised the B→A *application* direction, a real defect
/// shipped green: a Welcome-joiner was RECEIVE-ONLY. The joiner cannot proactively
/// PUSH its sender key to incumbents (a push seals to each incumbent's STABLE
/// `0xFF01` wrapping key, which openmls 0.8.1 does not expose from a joined group,
/// ADR-057), so incumbents must PULL it (§9.16.2). But the pull answer,
/// [`MlsCryptoProvider::handle_sender_key_request`], gated membership on the
/// `member_wrapping_keys` cache — which is EMPTY for a joiner — and so rejected
/// every incumbent's request as "from a non-member". The fix reads membership from
/// the joiner's MLS group tree instead (§9.16.6 Mitigation 1). This test drives the
/// real PULL round trip end-to-end and then the FULL application pipeline: `seal`
/// (sender-key AEAD → MLS application encrypt → outer envelope) on Bob and `open`
/// (MLS decrypt → sender-key AEAD decrypt → deserialize) on Alice.
///
/// # Non-vacuity
///
/// The round trip fails CLOSED — not silently — if the fix is reverted:
/// - If `handle_sender_key_request` is reverted to the `member_wrapping_keys`
///   gate, Bob returns `Err("sender key request from non-member")` and the
///   `expect` on Bob's response panics — Alice never obtains Bob's key.
/// - Even past that, if Alice's opened key is wrong or unstored, `open` returns
///   `Err(CryptoFailed("sender key lookup failed"))` at step 2 of the Application
///   arm, or the recovered plaintext mismatches.
/// - If Bob's joined group is at the wrong epoch relative to Alice, the MLS
///   decrypt at step 1 fails before the sender-key layer is even reached.
///
/// A passing management-path round-trip does NOT imply a passing application-path
/// round-trip — that gap is exactly what this test pins.
#[tokio::test]
async fn spawn_from_welcome_application_data_round_trips_joiner_to_creator() {
    // Bob joins Alice's real SCP context group via the Welcome path.
    let (result, j) = join_bob(0x40, None).await;
    result.expect("spawn_actor_from_welcome succeeds");

    // Alice (the incumbent) PULLS Bob's sender key via the §9.16.2 request/
    // response protocol — the spec's canonical new-member mechanism, and the only
    // one openmls 0.8.1 supports for a joiner (a joiner cannot push; ADR-057).
    // Alice issues a signed `SenderKeyRequest` carrying a FRESH EPHEMERAL wrapping
    // key; Bob answers via `handle_sender_key_request`; Alice opens the response
    // with her ephemeral secret and stores Bob's key. Application messages ride
    // the sender-key layer, so without this Alice cannot decrypt Bob's traffic.
    //
    // NON-VACUITY ANCHOR: `handle_sender_key_request` is exactly where the H1
    // membership gate lives. Bob's `member_wrapping_keys` is empty (a joiner never
    // caches incumbents' stable keys), so if the gate is reverted to the cache
    // check Bob returns `Err("sender key request from non-member")` and the first
    // `expect` below panics — this test cannot pass on the old, buggy gate.
    let alice_signing = alice_signing_key();
    let custody = InMemoryKeyCustody::new();
    // Alice's #active signing key, for the request signature. The EPHEMERAL
    // wrapping keypair is generated INSIDE `request_sender_key` (custody-held),
    // and its handle comes back as `request.wrapping_key_handle`.
    let alice_signing_handle = custody.import_ed25519_key(&alice_signing.to_bytes()).await;
    let request = crate::crypto::sender_keys::key_protocol::request_sender_key(
        &custody,
        &alice_signing_handle,
        ALICE_DID,
        BOB_DID,
        1, // joiner's initial sender-key epoch (not validated by the responder)
        &scp_clock::SystemClock,
    )
    .await
    .expect("alice builds a signed sender-key request for bob's key");

    let blocked = std::collections::HashSet::new();
    let response_bytes = j
        .bob_crypto
        .handle_sender_key_request(
            &j.ctx_bytes,
            &request.request_message,
            alice_signing.verifying_key().as_bytes(),
            &blocked,
        )
        .expect(
            "bob ACCEPTS alice's sender-key request — the H1 gate reads bob's MLS group \
             membership, not his empty member_wrapping_keys cache (§9.16.6 Mitigation 1)",
        )
        .expect("bob returns a response for a non-blocked member");

    let response: scp_protocol::crypto::sender_keys::SenderKeyResponse =
        rmp_serde::from_slice(&response_bytes).expect("decode bob's SenderKeyResponse");
    assert_eq!(
        response.sender_did, BOB_DID,
        "the response carries bob's sender key"
    );
    let ctx_id_hex = hex::encode(j.ctx_bytes);
    let bob_key = crate::crypto::sender_keys::key_protocol::open_sender_key_response(
        &custody,
        &request.wrapping_key_handle,
        &ctx_id_hex,
        &response,
    )
    .await
    .expect("alice opens bob's HPKE-sealed sender key with her ephemeral secret");
    // ADR-049 PR-6: store returns the authenticated (key, epoch); install is a
    // separate explicit set_sender_key_unchecked (mirrors production seam 2).
    let (bob_key, _epoch) = j
        .alice_crypto
        .store_member_sender_key(&j.ctx_bytes, BOB_DID, bob_key, response.epoch)
        .expect("alice verifies + returns bob's pulled sender key");
    j.alice_crypto
        .set_sender_key_unchecked(&j.ctx_bytes, BOB_DID, bob_key);

    // Bob seals a REAL application message through the full send pipeline.
    let payload = b"application-data-from-the-welcome-joiner-\xc2\xa79b";
    let params = crate::envelope::inner::InnerEnvelopeParams {
        version: scp_protocol::envelope::SCP_PROTOCOL_VERSION,
        context_id: &j.ctx_id,
        sender_did: BOB_DID,
        epoch: 0,
        generation: 0,
        sequence: 0,
        timestamp: 1_700_000_000,
        message_type: crate::envelope::inner::MessageType::Content,
        payload,
        provenance: None,
        signing_key_id: SigningKeyId::Active,
    };
    let inner =
        crate::envelope::inner::sign::create_inner_envelope_raw(&params, &bob_signing_key())
            .expect("bob builds a signed application inner envelope");
    let routing_id = scp_protocol::context::context_routing_id(&j.ctx_id);
    // Bob seals through his actor; Alice opens through hers (the provider seal /
    // open twins are deleted post-ADR-049 PR-7). Alice's actor is taken AFTER the
    // sender-key install above, so it carries Bob's pulled sender key.
    let mut bob_actor = take_into_actor(&j.bob_crypto, &j.ctx_bytes);
    let mut alice_actor = take_into_actor(&j.alice_crypto, &j.ctx_bytes);
    let sealed = bob_actor
        .seal(BOB_DID, &inner, &routing_id, 3600)
        .expect("bob seals the application message through the joined group");

    // Alice opens Bob's APPLICATION ciphertext — the direction + layer no
    // management-path test reaches. Fails closed on an epoch mismatch (MLS
    // decrypt) or a missing sender key (sender-key lookup).
    let opened = alice_actor
        .open(&scp_clock::SystemClock, &j.ctx_id, &sealed)
        .expect("alice opens bob's application ciphertext (B→A application round-trip)");
    // ADR-049 §10 bans the panic family across the whole `context/` tree; the
    // panic-ban scanner reads this `#[cfg(test)]`-gated file standalone (the gate
    // sits on the parent `mod` in supervisor/mod.rs), so a bare `panic!` here is
    // flagged. Assert the variant instead — a test assertion the gate accepts —
    // then destructure the now-proven `Application` payload.
    assert!(
        matches!(opened, OpenResult::Application(_)),
        "expected OpenResult::Application from a sealed app message, got {opened:?}",
    );
    let OpenResult::Application(env) = opened else {
        // Unreachable: the assertion above already failed the test otherwise.
        return;
    };
    let env = *env;
    assert_eq!(
        env.sender_did, BOB_DID,
        "the opened application message is attributed to the joiner (bob)"
    );
    let recovered = scp_protocol::envelope::padding::strip_padding(&env.inner.payload)
        .expect("strip bucket padding from the opened application payload");
    assert_eq!(
        recovered.as_slice(),
        payload.as_slice(),
        "alice recovers bob's exact application plaintext — B→A application round-trip closed"
    );
}
