//! Two-party end-to-end exchange driven THROUGH the `#[wasm_bindgen]` surface
//! (ADR-057 Slice 3, MVP proof).
//!
//! This is the Slice-3 milestone: it proves the *exposed* browser surface and
//! its dependency-injection wiring work end-to-end, not just the underlying
//! Slice-2 driver (which `scp-client`'s own `two_party_exchange.rs` already
//! covers). It drives two [`WasmScpClient`]s — Alice (creator) and Bob (joiner)
//! — through create / generate-key-package / add-member / join / send / receive
//! / drain / close, touching ONLY the `#[wasm_bindgen]`-exported methods and the
//! JS-friendly wrapper types (`WasmAddMemberOutput`, `WasmSendOutput`,
//! `WasmReceivedEvent`) exactly as JavaScript would.
//!
//! # Why a native host test, not `wasm-bindgen-test`
//!
//! This environment has the `wasm32-unknown-unknown` target and `wasm-pack`,
//! but **no `wasm-bindgen-test-runner`** (no headless browser/node test
//! harness wired). Per ADR-057 Slice 3's stated fallback, the strongest proof
//! available here is a native host test that exercises the wasm-bindgen-exposed
//! API surface with mock-JS-shaped injected adapters:
//! - [`scp_client::LocalSigner`] stands in for the `JsKeyCustody`-derived signer
//!   (same `scp_client::Signer` contract the `JsSigner` satisfies under wasm32);
//! - [`scp_client::MemoryStorage`] stands in for the `JsStorage`-backed adapter
//!   (same `scp_client::Storage` contract);
//! - [`scp_primitives::TestClock`] stands in for the hardened `WasmClock` (same
//!   `scp_primitives::Clock` contract).
//!
//! The `#[wasm_bindgen]` attribute is inert on native, so `WasmScpClient` and
//! its wrapper types compile and run here as plain Rust — the host test drives
//! the identical method bodies and dependency construction
//! (`WasmScpClient::from_parts`) the browser `from_js` constructor produces. The
//! JS-extern adapters themselves (captured `Date.now`, `JsStorage`,
//! `JsKeyCustody`) are wasm32-only and are covered by the build gate
//! (`cargo build --target wasm32-unknown-unknown`), not this test.
//!
//! When a wasm test runner is wired into CI, a `#[wasm_bindgen_test]` driving
//! the same flow from real JS would be the strongest proof; the build pipeline
//! gap is reported in the slice write-up.

// Integration tests assert on happy-path results; `expect`/`panic!` make the
// failure messages legible. The workspace denies these in production code.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::Arc;

use scp_client::{LocalSigner, MemoryStorage, Signer, Storage};
use scp_client_wasm::WasmScpClient;
use scp_primitives::{Clock, TestClock};

const CTX: &str = "ctx-adr057-slice3-wasm-surface";
const ALICE_DID: &str = "did:key:z6MkAlice3SurfaceExchangeFixtureKeyAAAAAAA";
const BOB_DID: &str = "did:key:z6MkBob3SurfaceExchangeFixtureKeyBBBBBBBBBB";

/// Builds a `WasmScpClient` over mock-JS-shaped in-memory adapters, through the
/// same `from_parts` seam the wasm32 `from_js` constructor uses.
fn client_for(did: &str, now_secs: u64) -> WasmScpClient {
    let signer: Arc<dyn Signer> = Arc::new(LocalSigner::active(did));
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let clock: Arc<dyn Clock> = Arc::new(TestClock::new(now_secs));
    WasmScpClient::from_parts(signer, storage, clock)
}

/// Performs the out-of-band §9.16 sender-key handoff through the exposed
/// `localSenderKeyBytes` / `installSenderKey` methods. The driver has no in-tab
/// distribution path (ADR-057 MISSING SEAM), so each side hands the other its
/// sender key directly.
fn exchange_sender_keys(alice: &mut WasmScpClient, bob: &mut WasmScpClient) {
    let alice_sk = alice
        .local_sender_key_bytes(CTX.to_owned())
        .expect("alice sender key");
    let bob_sk = bob
        .local_sender_key_bytes(CTX.to_owned())
        .expect("bob sender key");
    assert_eq!(
        alice_sk.len(),
        32,
        "sender key is 32 bytes over the surface"
    );
    bob.install_sender_key(CTX.to_owned(), ALICE_DID.to_owned(), alice_sk)
        .expect("Bob installs Alice's sender key");
    alice
        .install_sender_key(CTX.to_owned(), BOB_DID.to_owned(), bob_sk)
        .expect("Alice installs Bob's sender key");
}

/// Asserts the §9.9.3 convergence property through the surface: both members'
/// event logs hold byte-identical leaf hashes and an equal Merkle root. The
/// leaf-hashes query returns the flat 32-bytes-per-leaf concatenation.
fn assert_convergence(alice: &WasmScpClient, bob: &WasmScpClient) {
    let alice_leaves = alice
        .event_log_leaf_hashes(CTX.to_owned())
        .expect("alice leaves");
    let bob_leaves = bob
        .event_log_leaf_hashes(CTX.to_owned())
        .expect("bob leaves");
    assert_eq!(alice_leaves.len(), 3 * 32, "3 leaves × 32 bytes");
    assert_eq!(
        alice_leaves, bob_leaves,
        "every leaf hash is byte-identical across both members (convergence)"
    );
    assert_eq!(
        alice.event_log_root(CTX.to_owned()),
        bob.event_log_root(CTX.to_owned()),
        "the Merkle roots converge byte-for-byte (§9.9.3)"
    );
}

#[test]
fn two_party_exchange_through_wasm_surface() {
    // Deliberately different local clocks: convergence must depend only on the
    // convergent timestamp that travels with each message, not on the members'
    // clocks agreeing (ADR-057 §9.9.3).
    let mut alice = client_for(ALICE_DID, 1_700_000_000);
    let mut bob = client_for(BOB_DID, 1_650_000_000);

    assert_eq!(alice.did(), ALICE_DID, "the surface reports Alice's DID");

    // --- Alice creates the context through the exposed surface. ---
    alice
        .create_context(CTX.to_owned())
        .expect("Alice creates the context");
    assert_eq!(
        alice.member_dids(CTX.to_owned()).as_deref(),
        Some(&[ALICE_DID.to_owned()][..])
    );
    assert_eq!(
        alice.event_log_leaf_count(CTX.to_owned()),
        Some(1),
        "creation appends exactly the ContextCreated leaf"
    );

    // --- Bob generates a KeyPackage; the public bytes go to Alice. ---
    let bob_key_package = bob
        .generate_key_package_for_join(CTX.to_owned())
        .expect("Bob generates a key package");
    assert!(
        !bob_key_package.is_empty(),
        "the surface returns serialized key-package bytes"
    );

    // --- Alice adds Bob → WasmAddMemberOutput (commit/welcome/timestamp/log). ---
    let add = alice
        .add_member(CTX.to_owned(), bob_key_package)
        .expect("Alice adds Bob");
    assert!(!add.commit().is_empty(), "commit bytes present");
    assert!(!add.welcome().is_empty(), "welcome bytes present");
    assert!(
        !add.event_log().is_empty(),
        "serialized event-log stream present for the joiner to replay"
    );

    let mut alice_members = alice.member_dids(CTX.to_owned()).expect("alice members");
    alice_members.sort();
    assert_eq!(
        alice_members,
        vec![ALICE_DID.to_owned(), BOB_DID.to_owned()]
    );
    assert_eq!(alice.event_log_leaf_count(CTX.to_owned()), Some(2));

    // --- Bob joins from the Welcome + replays Alice's serialized log. ---
    bob.join_context_encrypted(
        CTX.to_owned(),
        add.welcome(),
        add.event_log(),
        add.members(),
    )
    .expect("Bob joins from the Welcome");

    assert_eq!(
        bob.event_log_leaf_count(CTX.to_owned()),
        Some(2),
        "Bob replayed Alice's log: ContextCreated + MemberJoined"
    );
    assert_eq!(
        bob.event_log_root(CTX.to_owned()),
        alice.event_log_root(CTX.to_owned()),
        "after replay, Bob's root equals Alice's (full-log convergence)"
    );

    // --- Out-of-band sender-key exchange (ADR-057 MISSING SEAM). ---
    exchange_sender_keys(&mut alice, &mut bob);

    // --- Alice sends an application message → WasmSendOutput. ---
    let plaintext = b"hello from Alice through the wasm-bindgen surface".to_vec();
    let send = alice
        .send_message(CTX.to_owned(), plaintext.clone())
        .expect("Alice sends");
    assert!(!send.ciphertext().is_empty(), "ciphertext present");
    assert_eq!(
        alice.event_log_leaf_count(CTX.to_owned()),
        Some(3),
        "Alice's log is now created + joined + sent"
    );

    // --- Bob receives + decrypts using the convergent timestamp, then drains. ---
    let was_application = bob
        .receive_message(
            CTX.to_owned(),
            send.ciphertext(),
            send.committer_timestamp_secs(),
        )
        .expect("Bob receives the message");
    assert!(was_application, "Alice's send is an application message");

    let events = bob.drain_events(CTX.to_owned()).expect("Bob drains events");
    assert_eq!(events.len(), 1, "exactly one received event is buffered");
    assert_eq!(events[0].kind(), "MessageReceived");
    assert_eq!(events[0].sender_did(), ALICE_DID, "the sender DID is Alice");
    assert_eq!(
        events[0].payload(),
        plaintext,
        "Bob recovered Alice's exact plaintext through the surface"
    );

    // Draining again yields nothing (pull-based, FIFO, consumed).
    assert!(
        bob.drain_events(CTX.to_owned())
            .expect("re-drain ok")
            .is_empty()
    );

    // --- Convergence (§9.9.3): identical leaf hashes AND equal Merkle roots,
    // despite differing local clocks. ---
    assert_convergence(&alice, &bob);

    // --- MLS epoch is observable through the surface and advanced past 0. ---
    assert!(
        alice.mls_epoch(CTX.to_owned()).expect("alice epoch") >= 1,
        "the add Commit advanced Alice's MLS epoch"
    );

    // --- Close tears down crypto state on both sides through the surface. ---
    alice.close_context(CTX.to_owned()).expect("Alice closes");
    bob.close_context(CTX.to_owned()).expect("Bob closes");
    assert_eq!(
        alice.member_dids(CTX.to_owned()),
        None,
        "context is gone after close"
    );
}

// NOTE on error-path coverage: a `#[wasm_bindgen]` method that returns
// `Err(JsValue)` cannot be exercised on the native host — constructing the
// `JsValue` aborts (wasm-bindgen imported calls cannot run off-wasm), before any
// `Result` is returned. So the surface's error mapping is NOT asserted in this
// native happy-path test. It is covered instead by:
//   * the pure `error::error_code` mapping (native unit tests in `error.rs`),
//     which proves duplicate-context → `SCP-CTX-2002`, unknown-context →
//     `SCP-CTX-2001`, etc.; and
//   * `error::wasm_tests` (`#[wasm_bindgen_test]`), which proves the wrapped
//     `JsValue` carries that prefix and the message.
// This native-host limitation is a real property of testing a wasm-bindgen
// surface off-target, reported in the slice write-up.
