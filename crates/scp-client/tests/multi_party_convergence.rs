//! Multi-party event-log convergence over the single-threaded SCP participant
//! driver (ADR-057 Slice 2).
//!
//! SCP contexts are inherently multi-party. This test exercises the property a
//! 2-party test cannot: when an EXISTING member processes an MLS Commit that
//! ADDS a new member, that existing member must append the identical convergent
//! `MemberJoined` leaf the committer appended and the new joiner replayed — so
//! all three members' event-log Merkle roots and membership sets converge.
//!
//! It proves two things the 2-party test left unproven:
//!
//! 1. **Existing-member add-Commit convergence** — Alice creates, adds Bob,
//!    then adds Carol. Bob (an existing member, not the committer, not the
//!    joiner) processes Alice's add-Carol Commit and converges his event-log
//!    root + membership to Alice's and Carol's. This is the regression test for
//!    the multi-party divergence bug: pre-fix, Bob's Control arm dropped the
//!    add and his log/membership permanently diverged.
//!
//! 2. **Convergence rides on the authenticated timestamp, not local clocks** — a
//!    reciprocal Bob → Alice send, where Bob stamps his OWN (deliberately
//!    different) clock onto a `MessageSent` leaf and binds that value into the
//!    ciphertext's authenticated MLS AAD, and Alice/Carol converge to Bob's leaf
//!    via the timestamp recovered from the verified frame (ADR-057).
//!    Because the three members' clocks all differ, this can only converge if the
//!    convergent timestamp is carried authenticated with each message.

// Integration tests assert on happy-path results; `expect`/`panic!` make the
// failure messages legible. The workspace denies these in production code.
#![allow(clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use scp_client::{ClientError, ContextStatus, LocalSigner, MemoryStorage, ScpClient, Storage};
use scp_clock::{Clock, SystemClock, TestClock};
use scp_protocol::context::membership::ContextEvent;

const CTX: &str = "ctx-adr057-slice2-multi-party";
const ALICE_DID: &str = "did:key:z6MkAliceMultiPartyFixtureKeyAAAAAAAAAAAAAA";
const BOB_DID: &str = "did:key:z6MkBobMultiPartyFixtureKeyBBBBBBBBBBBBBBBB";
const CAROL_DID: &str = "did:key:z6MkCarolMultiPartyFixtureKeyCCCCCCCCCCCCCC";

// Distinct per-member clock offsets applied to a shared real-time base. Kept
// small (seconds) so every minted KeyPackage `Lifetime` stays valid against
// openmls's un-injectable internal (real) clock, while remaining pairwise
// distinct — the convergence property depends only on the clocks *differing*,
// not on their magnitude (ADR-057 §Prereq-1 test-clock realism). Seeding from
// `SystemClock.now_secs()` (instead of a fixed past epoch) keeps the minted
// KeyPackages inside openmls's acceptance window at test time.
const ALICE_OFFSET: u64 = 0;
const BOB_OFFSET: u64 = 100;
const CAROL_OFFSET: u64 = 200;

/// Builds a fresh client for `did` over a fixed-time clock.
fn client_for(did: &str, now_secs: u64) -> ScpClient {
    let signer = Arc::new(LocalSigner::active(did));
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let clock: Arc<dyn Clock> = Arc::new(TestClock::new(now_secs));
    // A fresh store restores nothing, so construction cannot fail here.
    ScpClient::new(signer, storage, clock).expect("construct fresh client")
}

/// Hands every pair of clients the other's sender key, out-of-band (the MISSING
/// SEAM the crate root documents — there is no in-tab distribution path yet).
fn exchange_sender_keys(clients: &mut [(&str, &mut ScpClient)]) {
    let keys: Vec<(String, [u8; 32])> = clients
        .iter()
        .map(|(did, c)| {
            (
                (*did).to_owned(),
                c.local_sender_key_bytes(CTX).expect("local sender key"),
            )
        })
        .collect();
    for (did, client) in clients.iter_mut() {
        for (peer_did, key) in &keys {
            if peer_did != did {
                client
                    .install_sender_key(CTX, peer_did, *key)
                    .expect("install peer sender key");
            }
        }
    }
}

#[test]
fn three_party_add_commit_converges_across_all_members() {
    // Three deliberately different local clocks: convergence must NOT depend on
    // them agreeing — only on the convergent timestamp transported with each
    // commit/message.
    let base = SystemClock.now_secs();
    let mut alice = client_for(ALICE_DID, base + ALICE_OFFSET);
    let mut bob = client_for(BOB_DID, base + BOB_OFFSET);
    let mut carol = client_for(CAROL_DID, base + CAROL_OFFSET);

    // --- Alice creates the context. ---
    alice.create_context(CTX).expect("Alice creates");

    // --- Alice adds Bob. Bob joins via the Welcome + replay. ---
    let bob_kp = bob
        .generate_key_package_for_join(CTX)
        .expect("Bob key package");
    let add_bob = alice.add_member(CTX, &bob_kp).expect("Alice adds Bob");
    bob.join_context_encrypted(CTX, &add_bob.welcome, &add_bob.event_log, &add_bob.members)
        .expect("Bob joins");

    assert_eq!(
        bob.event_log_root(CTX),
        alice.event_log_root(CTX),
        "after the first add, Bob converges to Alice"
    );

    // --- Alice adds Carol. This is the multi-party case: Alice's add-Carol
    // Commit must be processed by the EXISTING member Bob, who has to append the
    // identical MemberJoined(Carol) leaf — not silently drop it. ---
    let carol_kp = carol
        .generate_key_package_for_join(CTX)
        .expect("Carol key package");
    let add_carol = alice.add_member(CTX, &carol_kp).expect("Alice adds Carol");

    // Carol joins from the Welcome, replaying Alice's full log (which now
    // includes both MemberJoined leaves).
    carol
        .join_context_encrypted(
            CTX,
            &add_carol.welcome,
            &add_carol.event_log,
            &add_carol.members,
        )
        .expect("Carol joins");

    // Bob (existing member) processes Alice's add-Carol Commit. The convergent
    // committer timestamp is bound into the Commit's authenticated AAD (ADR-057
    //), so Bob recovers it from the verified frame — no separate value is
    // transported. `receive_message` returns `false` (no application payload),
    // but its side effect — appending the convergent MemberJoined leaf and
    // recording Carol — is what makes Bob converge. Pre-fix, this arm dropped the
    // add: Bob stayed at 2 leaves with Carol missing and his root diverged from
    // Alice's and Carol's.
    let was_application = bob
        .receive_message(CTX, &add_carol.commit)
        .expect("Bob processes the add-Carol commit");
    assert!(
        !was_application,
        "an add-Commit carries no application payload"
    );

    // === All three members converge: identical leaf count, identical leaf
    // hashes, identical Merkle root, identical membership set. ===
    assert_eq!(
        alice.event_log_leaf_count(CTX),
        Some(3),
        "Alice: ContextCreated + MemberJoined(Bob) + MemberJoined(Carol)"
    );
    assert_eq!(
        bob.event_log_leaf_count(CTX),
        Some(3),
        "Bob converged to 3 leaves after processing the add-Carol commit"
    );
    assert_eq!(
        carol.event_log_leaf_count(CTX),
        Some(3),
        "Carol replayed all 3 leaves"
    );

    let alice_root = alice.event_log_root(CTX).expect("alice root");
    let bob_root = bob.event_log_root(CTX).expect("bob root");
    let carol_root = carol.event_log_root(CTX).expect("carol root");
    assert_eq!(alice_root, bob_root, "Alice and Bob roots converge");
    assert_eq!(alice_root, carol_root, "Alice and Carol roots converge");

    let alice_leaves = alice.event_log_leaf_hashes(CTX).expect("alice leaves");
    let bob_leaves = bob.event_log_leaf_hashes(CTX).expect("bob leaves");
    let carol_leaves = carol.event_log_leaf_hashes(CTX).expect("carol leaves");
    assert_eq!(
        alice_leaves, bob_leaves,
        "every leaf hash is byte-identical between Alice and Bob"
    );
    assert_eq!(
        alice_leaves, carol_leaves,
        "every leaf hash is byte-identical between Alice and Carol"
    );

    // Membership sets converge (order-insensitive).
    let mut alice_members = alice.member_dids(CTX).expect("alice members");
    let mut bob_members = bob.member_dids(CTX).expect("bob members");
    let mut carol_members = carol.member_dids(CTX).expect("carol members");
    alice_members.sort();
    bob_members.sort();
    carol_members.sort();
    let expected = {
        let mut v = vec![
            ALICE_DID.to_owned(),
            BOB_DID.to_owned(),
            CAROL_DID.to_owned(),
        ];
        v.sort();
        v
    };
    assert_eq!(alice_members, expected, "Alice sees all three members");
    assert_eq!(
        bob_members, expected,
        "Bob's membership converged to all three"
    );
    assert_eq!(carol_members, expected, "Carol sees all three members");
}

#[test]
fn reciprocal_send_converges_via_transported_timestamp() {
    // Distinct clocks across all three members.
    let base = SystemClock.now_secs();
    let mut alice = client_for(ALICE_DID, base + ALICE_OFFSET);
    let mut bob = client_for(BOB_DID, base + BOB_OFFSET);
    let mut carol = client_for(CAROL_DID, base + CAROL_OFFSET);

    alice.create_context(CTX).expect("Alice creates");

    let bob_kp = bob
        .generate_key_package_for_join(CTX)
        .expect("Bob key package");
    let add_bob = alice.add_member(CTX, &bob_kp).expect("Alice adds Bob");
    bob.join_context_encrypted(CTX, &add_bob.welcome, &add_bob.event_log, &add_bob.members)
        .expect("Bob joins");

    let carol_kp = carol
        .generate_key_package_for_join(CTX)
        .expect("Carol key package");
    let add_carol = alice.add_member(CTX, &carol_kp).expect("Alice adds Carol");
    carol
        .join_context_encrypted(
            CTX,
            &add_carol.welcome,
            &add_carol.event_log,
            &add_carol.members,
        )
        .expect("Carol joins");
    bob.receive_message(CTX, &add_carol.commit)
        .expect("Bob processes the add-Carol commit");

    // All three converge before any application message.
    assert_eq!(alice.event_log_root(CTX), bob.event_log_root(CTX));
    assert_eq!(alice.event_log_root(CTX), carol.event_log_root(CTX));

    // Out-of-band sender-key exchange among all three.
    exchange_sender_keys(&mut [
        (ALICE_DID, &mut alice),
        (BOB_DID, &mut bob),
        (CAROL_DID, &mut carol),
    ]);

    // --- Reciprocal send: BOB sends. Bob stamps the leaf with HIS OWN clock
    // reading (base + BOB_OFFSET), distinct from Alice's and Carol's, and binds
    // that same value into the ciphertext's authenticated AAD (ADR-057). ---
    let plaintext = b"hello from Bob, stamped with Bob's clock";
    let bob_ciphertext = bob.send_message(CTX, plaintext).expect("Bob sends");

    // Alice and Carol receive Bob's message and stamp the SAME authenticated
    // timestamp (recovered from the verified AAD) onto their MessageSent leaf —
    // NOT their own clocks, and NOT a separately-transported value. That the
    // stamped value is Bob's clock reading (base + BOB_OFFSET), not Alice's or
    // Carol's, is proven below by the leaf/root convergence across three
    // deliberately-distinct clocks.
    assert!(
        alice
            .receive_message(CTX, &bob_ciphertext)
            .expect("Alice receives Bob's message"),
        "an application message"
    );
    assert!(
        carol
            .receive_message(CTX, &bob_ciphertext)
            .expect("Carol receives Bob's message"),
        "an application message"
    );

    // The MessageSent leaf converges across all three despite three different
    // local clocks — proving convergence rides on the transported timestamp.
    let alice_root = alice.event_log_root(CTX).expect("alice root");
    let bob_root = bob.event_log_root(CTX).expect("bob root");
    let carol_root = carol.event_log_root(CTX).expect("carol root");
    assert_eq!(
        alice_root, bob_root,
        "Alice converged to Bob's leaf via the transported timestamp, not her clock"
    );
    assert_eq!(
        alice_root, carol_root,
        "Carol converged to Bob's leaf via the transported timestamp, not her clock"
    );
    assert_eq!(
        alice.event_log_leaf_count(CTX),
        Some(4),
        "created + joined(Bob) + joined(Carol) + sent(Bob)"
    );

    // Alice and Carol each drained Bob's plaintext.
    let alice_events = alice.drain_events(CTX).expect("alice drains");
    assert_eq!(alice_events.len(), 1);
    match &alice_events[0] {
        ContextEvent::MessageReceived {
            sender_did,
            payload,
        } => {
            assert_eq!(sender_did.0, BOB_DID, "sender is Bob");
            assert_eq!(payload.as_slice(), plaintext);
        }
        other => panic!("expected MessageReceived, got {other:?}"),
    }
}

#[test]
#[allow(clippy::too_many_lines)] // one end-to-end raw-group remove scenario, read top-to-bottom
fn remove_commit_is_rejected_fail_closed_without_skew() {
    // The regression test for Fix 1: a Remove-bearing Commit must be rejected by
    // `receive_message` AND must leave the receiver's MLS group + SCP membership +
    // event log mutually consistent (pre-remove). `scp-mls` now inspects the
    // staged commit's Remove proposals and drops the StagedCommit WITHOUT merging,
    // so the MLS epoch never half-advances while the SCP membership/log stay put.
    //
    // ADR-057 Slice 2 deliberately gives the participant `ScpClient` NO remove op
    // (there is no convergent removal-leaf transport yet). To manufacture the very
    // Remove-bearing Commit the driver must reject, this test drives ALICE as a
    // raw `scp-mls` group (a dev-dependency) — exactly the wire bytes a hostile or
    // out-of-scope committer could put on the wire — while BOB is a real
    // `ScpClient` whose `receive_message` is the unit under test.
    use openmls::prelude::{BasicCredential, KeyPackageIn};
    use scp_did::SigningKeyId;
    use scp_mls::group::{
        add_member, add_member_with_convergent_timestamp, create_group, generate_key_package,
        remove_member,
    };
    use scp_mls::{ScpCredential, SignatureKeyPair};
    use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};

    // The raw Alice group and Bob's client share a real-time base so every
    // KeyPackage `Lifetime` stays valid against openmls's internal (real) clock
    // and the hardened SCP checks (ADR-057 §Prereq-1). The raw group uses
    // `SystemClock` directly; Bob's client uses a TestClock at the same base.
    let base = SystemClock.now_secs();
    let alice_cred = ScpCredential::new(ALICE_DID.to_owned(), None, SigningKeyId::Active)
        .expect("alice credential");
    let mut alice_group = create_group(&alice_cred, &SystemClock).expect("Alice's raw MLS group");

    let mut bob = client_for(BOB_DID, base + BOB_OFFSET);

    // Bob's ScpClient mints its join KeyPackage (private half retained inside the
    // client). Alice (raw group) adds Bob from that KeyPackage and Bob joins via
    // the resulting Welcome, starting from an empty replay log.
    let bob_kp_bytes = bob
        .generate_key_package_for_join(CTX)
        .expect("Bob key package");
    let bob_kp_in = KeyPackageIn::tls_deserialize(&mut &*bob_kp_bytes).expect("bob kp deserialize");
    let add_bob = add_member(&mut alice_group, bob_kp_in, &SystemClock).expect("Alice adds Bob");
    let bob_welcome = add_bob
        .welcome
        .tls_serialize_detached()
        .expect("welcome bytes");
    bob.join_context_encrypted(CTX, &bob_welcome, &[], &[ALICE_DID.to_owned()])
        .expect("Bob joins Alice's raw group");

    // Alice (raw group) adds Carol — a raw `scp-mls` member that exists only so
    // Alice has someone to remove. Bob applies the add-Carol Commit through his
    // ScpClient so Bob and Alice share the post-add epoch and Bob records Carol.
    let carol_cred = ScpCredential::new(CAROL_DID.to_owned(), None, SigningKeyId::Active)
        .expect("carol credential");
    let (carol_bundle, _carol_signer, _carol_provider): (_, SignatureKeyPair, _) =
        generate_key_package(&carol_cred, &SystemClock).expect("carol key package");
    let carol_kp_in = KeyPackageIn::tls_deserialize(
        &mut &*carol_bundle
            .key_package()
            .tls_serialize_detached()
            .expect("carol kp bytes"),
    )
    .expect("carol kp deserialize");
    // The add path converges + appends a MemberJoined leaf on Bob, so the raw
    // Commit must carry a convergent-timestamp AAD (ADR-057) plausible
    // against Bob's clock (`base`, well inside his window); Bob recovers it from
    // the verified AAD.
    let add_carol =
        add_member_with_convergent_timestamp(&mut alice_group, carol_kp_in, &SystemClock, base)
            .expect("Alice adds Carol");
    let add_carol_commit = add_carol
        .commit
        .tls_serialize_detached()
        .expect("add-carol commit bytes");
    bob.receive_message(CTX, &add_carol_commit)
        .expect("Bob processes the add-Carol commit");

    // Snapshot Bob's pre-remove state: MLS epoch, SCP membership, log leaf count,
    // and Merkle root. After the rejected remove these must ALL be unchanged.
    let bob_epoch_before = bob.mls_epoch(CTX).expect("bob epoch");
    let bob_leaf_count_before = bob.event_log_leaf_count(CTX);
    let bob_root_before = bob.event_log_root(CTX);
    let mut bob_members_before = bob.member_dids(CTX).expect("bob members");
    bob_members_before.sort();
    assert!(
        bob_members_before.contains(&CAROL_DID.to_owned()),
        "pre-remove: Carol is in Bob's membership set"
    );

    // Alice (raw group) builds a Commit removing Carol by her leaf index.
    let carol_leaf = alice_group
        .members()
        .expect("alice members")
        .into_iter()
        .find(|m| {
            BasicCredential::try_from(m.credential.clone())
                .ok()
                .and_then(|basic| ScpCredential::from_bytes(basic.identity()).ok())
                .is_some_and(|cred| cred.did == CAROL_DID)
        })
        .map(|m| m.index)
        .expect("Carol's leaf index");
    let remove_carol = remove_member(&mut alice_group, carol_leaf).expect("Alice removes Carol");
    let remove_carol_commit = remove_carol
        .commit
        .tls_serialize_detached()
        .expect("remove-carol commit bytes");

    // Bob receives the remove Commit. `scp-mls` decides the Remove-refusal BEFORE
    // the AAD check, so the raw (AAD-less) remove Commit is still rejected as
    // UnsupportedMembershipChange — never as a missing timestamp.
    let result = bob.receive_message(CTX, &remove_carol_commit);

    // (1) FAIL-LOUD: the driver surfaces UnsupportedMembershipChange naming Carol.
    match result {
        Err(ClientError::UnsupportedMembershipChange(msg)) => {
            assert!(
                msg.contains(CAROL_DID),
                "the error must name the removed member, got: {msg}"
            );
        }
        other => panic!("expected UnsupportedMembershipChange, got {other:?}"),
    }

    // (2) NO SKEW: Bob's MLS group did NOT half-advance — the Remove-bearing
    // Commit was dropped BEFORE `merge_staged_commit`, so the MLS epoch is
    // exactly what it was before. This is the crux of Fix 1: pre-fix the group
    // merged (epoch advanced, Carol evicted from the tree) and only then errored,
    // leaving MLS ahead of the SCP layer.
    assert_eq!(
        bob.mls_epoch(CTX).expect("bob epoch after"),
        bob_epoch_before,
        "a rejected remove must NOT advance Bob's MLS epoch (no half-merge)"
    );

    // (3) NO SKEW: Bob's SCP membership set is unchanged (Carol still listed —
    // the driver did not evict her, since it never applied the Commit).
    let mut bob_members_after = bob.member_dids(CTX).expect("bob members after");
    bob_members_after.sort();
    assert_eq!(
        bob_members_after, bob_members_before,
        "a rejected remove must NOT mutate Bob's SCP membership set"
    );

    // (4) NO SKEW: Bob's event log is unchanged (same leaf count, same root) —
    // no membership leaf was appended or dropped.
    assert_eq!(
        bob.event_log_leaf_count(CTX),
        bob_leaf_count_before,
        "a rejected remove must NOT change Bob's event-log leaf count"
    );
    assert_eq!(
        bob.event_log_root(CTX),
        bob_root_before,
        "a rejected remove must NOT change Bob's event-log Merkle root"
    );

    // The four no-skew assertions above prove the crux of Fix 1: MLS state and
    // SCP state are LEFT MUTUALLY CONSISTENT (both pre-remove), because the
    // Remove-bearing Commit was dropped before `merge_staged_commit` rather than
    // merged-then-errored. (That the group also stays *encryptable* on its
    // unchanged epoch after a rejected remove is proven at the MLS layer by the
    // `scp-mls` unit test `decrypt_with_membership_changes_rejects_remove_without_merging`.)
}

/// Builds a client for `did` over a retained, mutable `TestClock` so a test can
/// move the clock after construction (to simulate a mis-clocked / lying sender
/// whose stamped timestamp lands outside a receiver's window).
fn client_with_clock(did: &str, clock: Arc<TestClock>) -> ScpClient {
    let signer = Arc::new(LocalSigner::active(did));
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    ScpClient::new(signer, storage, clock as Arc<dyn Clock>).expect("construct fresh client")
}

#[test]
fn application_committer_lie_beyond_window_rejected_then_honest_resend_succeeds() {
    // ADR-057 at the DRIVER: a sender whose clock is 10 minutes AHEAD of
    // the receiver's binds a committer timestamp beyond the receiver's 300s
    // future-skew window into the authenticated AAD. The receiver's driver
    // REJECTS the message (scp-mls window-validates the authenticated value and
    // refuses — never clamps), so NO `MessageSent` leaf is stamped, the context
    // stays Live + usable, and an honest in-window re-send (after the clocks
    // re-converge) still decrypts.
    let base = SystemClock.now_secs();
    // Retain Alice's clock so we can move it later; start 10 minutes ahead of Bob.
    let alice_clock = Arc::new(TestClock::new(base + 600));
    let mut alice = client_with_clock(ALICE_DID, Arc::clone(&alice_clock));
    let mut bob = client_for(BOB_DID, base);

    alice.create_context(CTX).expect("alice creates");
    let bob_kp = bob
        .generate_key_package_for_join(CTX)
        .expect("bob key package");
    let add = alice.add_member(CTX, &bob_kp).expect("alice adds bob");
    bob.join_context_encrypted(CTX, &add.welcome, &add.event_log, &add.members)
        .expect("bob joins");
    exchange_sender_keys(&mut [(ALICE_DID, &mut alice), (BOB_DID, &mut bob)]);

    let bob_leaf_before = bob.event_log_leaf_count(CTX);
    let bob_root_before = bob.event_log_root(CTX);

    // Alice (600s ahead) sends: the AAD carries base+600, beyond Bob's window.
    let lie_ct = alice
        .send_message(CTX, b"stamped 10 minutes in the future")
        .expect("alice sends");
    let result = bob.receive_message(CTX, &lie_ct);
    assert!(
        matches!(result, Err(ClientError::Mls(_))),
        "an implausible committer timestamp must be rejected at the driver, got {result:?}"
    );

    // FAIL-CLOSED, NO SKEW: no leaf was stamped and the log root is unchanged; the
    // rejection happens BEFORE any leaf append or persist. The context is Live.
    assert_eq!(
        bob.event_log_leaf_count(CTX),
        bob_leaf_before,
        "a rejected message stamps NO leaf"
    );
    assert_eq!(
        bob.event_log_root(CTX),
        bob_root_before,
        "a rejected message leaves the event-log root unchanged"
    );
    assert_eq!(
        bob.context_status(CTX),
        ContextStatus::Live,
        "the context stays Live and usable after a rejected message"
    );

    // Honest re-send: move Alice's clock back in sync with Bob and re-send. The
    // new message's authenticated AAD is now inside Bob's window, so it decrypts.
    alice_clock.set(base);
    let honest_ct = alice
        .send_message(CTX, b"now in sync")
        .expect("alice re-sends honestly");
    assert!(
        bob.receive_message(CTX, &honest_ct)
            .expect("bob receives the honest re-send"),
        "an honest in-window re-send after a rejection still decrypts"
    );
    let events = bob.drain_events(CTX).expect("bob drains");
    assert_eq!(events.len(), 1, "only the honest message is delivered");
    match &events[0] {
        ContextEvent::MessageReceived { payload, .. } => {
            assert_eq!(payload.as_slice(), b"now in sync");
        }
        other => panic!("expected MessageReceived, got {other:?}"),
    }
}

#[test]
fn add_commit_committer_lie_beyond_window_rejected_without_epoch_or_membership_skew() {
    // ADR-057 for the ADD path at the driver: an existing member rejects an
    // add-Commit whose authenticated timestamp is beyond its window, and the
    // reject is fail-closed — scp-mls drops the staged commit BEFORE merging, so
    // the receiver's MLS epoch, SCP membership set, and event log are all
    // unchanged.
    let base = SystemClock.now_secs();
    // Alice (adder/committer) is 10 minutes ahead of Bob (existing member).
    let alice_clock = Arc::new(TestClock::new(base + 600));
    let mut alice = client_with_clock(ALICE_DID, Arc::clone(&alice_clock));
    let mut bob = client_for(BOB_DID, base);
    let mut carol = client_for(CAROL_DID, base + CAROL_OFFSET);

    alice.create_context(CTX).expect("alice creates");
    // First add (Bob): Bob JOINS via Welcome + replay — no AAD window check on the
    // join path — so Bob adopts Alice's base+600 MemberJoined leaf and converges.
    let bob_kp = bob
        .generate_key_package_for_join(CTX)
        .expect("bob key package");
    let add_bob = alice.add_member(CTX, &bob_kp).expect("alice adds bob");
    bob.join_context_encrypted(CTX, &add_bob.welcome, &add_bob.event_log, &add_bob.members)
        .expect("bob joins");
    assert_eq!(
        bob.event_log_root(CTX),
        alice.event_log_root(CTX),
        "Bob converges to Alice after joining"
    );

    // Snapshot Bob's pre-add-Carol state.
    let bob_epoch_before = bob.mls_epoch(CTX).expect("bob epoch");
    let bob_leaf_before = bob.event_log_leaf_count(CTX);
    let bob_root_before = bob.event_log_root(CTX);
    let mut bob_members_before = bob.member_dids(CTX).expect("bob members");
    bob_members_before.sort();

    // Alice adds Carol; the add-Carol Commit's AAD carries Alice's base+600 —
    // beyond Bob's window. Bob, an EXISTING member, processes it and must reject.
    let carol_kp = carol
        .generate_key_package_for_join(CTX)
        .expect("carol key package");
    let add_carol = alice.add_member(CTX, &carol_kp).expect("alice adds carol");
    let result = bob.receive_message(CTX, &add_carol.commit);
    assert!(
        matches!(result, Err(ClientError::Mls(_))),
        "an implausible add-Commit timestamp must be rejected at the driver, got {result:?}"
    );

    // FAIL-CLOSED, NO SKEW: the staged commit was dropped before merge, so Bob's
    // MLS epoch, membership set, and event log are ALL unchanged.
    assert_eq!(
        bob.mls_epoch(CTX).expect("bob epoch after"),
        bob_epoch_before,
        "a rejected add-Commit must NOT advance Bob's MLS epoch"
    );
    let mut bob_members_after = bob.member_dids(CTX).expect("bob members after");
    bob_members_after.sort();
    assert_eq!(
        bob_members_after, bob_members_before,
        "a rejected add-Commit must NOT add the member to Bob's SCP membership set"
    );
    assert_eq!(
        bob.event_log_leaf_count(CTX),
        bob_leaf_before,
        "a rejected add-Commit must NOT append a MemberJoined leaf"
    );
    assert_eq!(
        bob.event_log_root(CTX),
        bob_root_before,
        "a rejected add-Commit must NOT change Bob's event-log root"
    );
    assert_eq!(
        bob.context_status(CTX),
        ContextStatus::Live,
        "the context stays Live and usable after a rejected add-Commit"
    );
}

#[test]
fn tampered_ciphertext_produces_no_leaf() {
    // A hostile relay flips a byte of a valid ciphertext. The AEAD tag (which also
    // covers the convergent-timestamp AAD) fails, so the receiver's decrypt errors
    // and NO leaf is stamped — the context is untouched and stays usable.
    let base = SystemClock.now_secs();
    let mut alice = client_for(ALICE_DID, base);
    let mut bob = client_for(BOB_DID, base + BOB_OFFSET);

    alice.create_context(CTX).expect("alice creates");
    let bob_kp = bob
        .generate_key_package_for_join(CTX)
        .expect("bob key package");
    let add = alice.add_member(CTX, &bob_kp).expect("alice adds bob");
    bob.join_context_encrypted(CTX, &add.welcome, &add.event_log, &add.members)
        .expect("bob joins");
    exchange_sender_keys(&mut [(ALICE_DID, &mut alice), (BOB_DID, &mut bob)]);

    let bob_leaf_before = bob.event_log_leaf_count(CTX);
    let bob_root_before = bob.event_log_root(CTX);

    let mut ciphertext = alice
        .send_message(CTX, b"tamper target")
        .expect("alice sends");
    // Flip the last byte (corrupts the AEAD tag covering the AAD + payload).
    if let Some(byte) = ciphertext.last_mut() {
        *byte ^= 0xFF;
    }
    assert!(
        bob.receive_message(CTX, &ciphertext).is_err(),
        "a tampered ciphertext must be rejected, not silently accepted"
    );
    assert_eq!(
        bob.event_log_leaf_count(CTX),
        bob_leaf_before,
        "a tampered ciphertext stamps NO leaf"
    );
    assert_eq!(
        bob.event_log_root(CTX),
        bob_root_before,
        "a tampered ciphertext leaves the event-log root unchanged"
    );
    assert_eq!(
        bob.context_status(CTX),
        ContextStatus::Live,
        "the context stays Live after a tampered-ciphertext rejection"
    );
}
