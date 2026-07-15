//! Two-party end-to-end exchange driven THROUGH the `#[wasm_bindgen]` surface
//! (ADR-057 Slice 3, MVP proof).
//!
//! This is the Slice-3 milestone: it proves the *exposed* browser surface and
//! its dependency-injection wiring work end-to-end, not just the underlying
//! Slice-2 driver (which `scp-client`'s own `two_party_exchange.rs` already
//! covers). It drives two [`WasmScpClient`]s — Alice (creator) and Bob (joiner)
//! — through create / generate-key-package / add-member / join / send / receive
//! / drain / close, touching ONLY the `#[wasm_bindgen]`-exported methods and the
//! JS-friendly wrapper types (`WasmAddMemberOutput`, `WasmReceivedEvent`)
//! exactly as JavaScript would. `sendMessage` returns the ciphertext bytes
//! directly: an application message is plain-encrypted and is not a convergent
//! event-log leaf (ADR-011), so there is no `WasmSendOutput` wrapper and no
//! transported timestamp — `receiveMessage` takes only the ciphertext. The
//! convergent committer timestamp survives only on the add-Commit path, bound
//! into that Commit's authenticated AAD (ADR-057 T3).
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
//! - [`scp_clock::TestClock`] stands in for the hardened `WasmClock` (same
//!   `scp_clock::Clock` contract).
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
use scp_client_wasm::{WasmScpClient, WasmSenderKeyDistribution};
use scp_clock::{Clock, SystemClock, TestClock};

const CTX: &str = "ctx-adr057-slice3-wasm-surface";
const ALICE_DID: &str = "did:key:z6MkAlice3SurfaceExchangeFixtureKeyAAAAAAA";
const BOB_DID: &str = "did:key:z6MkBob3SurfaceExchangeFixtureKeyBBBBBBBBBB";

/// A real-time clock seed with a small distinct offset (seconds).
///
/// These surface tests run on the native host (`#[test]`), where both
/// `scp_clock::SystemClock` and openmls's un-injectable internal
/// `Lifetime::is_valid` read `std::time::SystemTime`. Seeding the stand-in
/// `TestClock` from the real clock (instead of a fixed past epoch) keeps every
/// minted `KeyPackage` `Lifetime` valid against openmls's internal check while
/// remaining pairwise distinct (ADR-057 §Prereq-1 test-clock realism);
/// convergence rides on transported timestamps, not clock magnitude.
fn seed(offset: u64) -> u64 {
    SystemClock.now_secs() + offset
}

/// Builds a `WasmScpClient` over mock-JS-shaped in-memory adapters, through the
/// same `from_parts` seam the wasm32 `from_js` constructor uses.
fn client_for(did: &str, now_secs: u64) -> WasmScpClient {
    let signer: Arc<dyn Signer> = Arc::new(LocalSigner::active(did));
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let clock: Arc<dyn Clock> = Arc::new(TestClock::new(now_secs));
    // A fresh store restores nothing, so construction cannot fail here.
    WasmScpClient::from_parts(signer, storage, clock).expect("construct fresh surface client")
}

/// Routes each in-tab §9.16 sender-key distribution to its target client through
/// the exposed `receiveMessage` surface (§9.16.1/§9.16.2). There is no out-of-band
/// hand-off — `localSenderKeyBytes` / `installSenderKey` no longer exist on the
/// surface. Asserts each install is a no-op receive (not an application message).
fn deliver(
    dists: Vec<WasmSenderKeyDistribution>,
    alice: &mut WasmScpClient,
    bob: &mut WasmScpClient,
) {
    for d in dists {
        let target = d.target_did();
        let out = if target == ALICE_DID {
            alice.receive_message(CTX.to_owned(), d.ciphertext())
        } else if target == BOB_DID {
            bob.receive_message(CTX.to_owned(), d.ciphertext())
        } else {
            panic!("unexpected distribution target {target}");
        }
        .expect("install distribution through the surface");
        assert!(
            !out.application(),
            "a sender-key distribution is not an application message"
        );
        assert!(
            out.sender_key_distributions().is_empty(),
            "installing a distribution triggers no further distribution"
        );
    }
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
    assert_eq!(alice_leaves.len(), 2 * 32, "2 membership leaves × 32 bytes");
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
#[allow(clippy::too_many_lines)] // one end-to-end two-party surface scenario, read top-to-bottom
fn two_party_exchange_through_wasm_surface() {
    // Deliberately different local clocks: convergence must depend only on the
    // convergent timestamp that travels with each message, not on the members'
    // clocks agreeing (ADR-057 §9.9.3).
    let mut alice = client_for(ALICE_DID, seed(0));
    let mut bob = client_for(BOB_DID, seed(100));

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

    // --- Bob joins from the Welcome + replays Alice's serialized log. The join
    // returns Bob's sender-key distributions (Bob → each existing member). ---
    let bob_join_dists = bob
        .join_context_encrypted(
            CTX.to_owned(),
            add.welcome(),
            add.event_log(),
            add.wrapping_keys(),
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

    // --- In-tab §9.16 distribution through the surface: route Alice's add-seal
    // (Alice → Bob) and Bob's join-seals (Bob → Alice). NO out-of-band exchange. ---
    deliver(add.sender_key_distributions(), &mut alice, &mut bob);
    deliver(bob_join_dists, &mut alice, &mut bob);

    // --- Alice sends an application message → ciphertext bytes (Uint8Array). ---
    let plaintext = b"hello from Alice through the wasm-bindgen surface".to_vec();
    let ciphertext = alice
        .send_message(CTX.to_owned(), plaintext.clone())
        .expect("Alice sends");
    assert!(!ciphertext.is_empty(), "ciphertext present");
    assert_eq!(
        alice.event_log_leaf_count(CTX.to_owned()),
        Some(2),
        "a send stamps NO convergent leaf (ADR-011): Alice's log stays created + joined"
    );

    // --- Bob receives + decrypts a plain application message (no AAD), then
    // drains. ---
    let received = bob
        .receive_message(CTX.to_owned(), ciphertext)
        .expect("Bob receives the message");
    assert!(
        received.application(),
        "Alice's send is an application message"
    );

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

/// Builds a `WasmScpClient` over a caller-supplied (shared) storage handle. When
/// the storage already holds this identity's snapshots, the CONSTRUCTOR restores
/// them (ADR-057 T2) — a reopened tab resumes with no explicit "load" call.
fn client_over(did: &str, storage: Arc<dyn Storage>, now_secs: u64) -> WasmScpClient {
    let signer: Arc<dyn Signer> = Arc::new(LocalSigner::active(did));
    let clock: Arc<dyn Clock> = Arc::new(TestClock::new(now_secs));
    WasmScpClient::from_parts(signer, storage, clock).expect("construct/restore surface client")
}

#[test]
fn restore_through_wasm_surface() {
    // Alice creates + adds Bob; Bob joins — all through the exposed surface.
    // Bob's storage is shared so a reopened-tab client can restore from it.
    let alice_storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let bob_storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());

    let mut alice = client_over(ALICE_DID, alice_storage, seed(0));
    let mut bob = client_over(BOB_DID, Arc::clone(&bob_storage), seed(100));

    alice.create_context(CTX.to_owned()).expect("alice creates");
    let bob_kp = bob
        .generate_key_package_for_join(CTX.to_owned())
        .expect("bob key package");
    let add = alice
        .add_member(CTX.to_owned(), bob_kp)
        .expect("alice adds bob");
    let bob_join_dists = bob
        .join_context_encrypted(
            CTX.to_owned(),
            add.welcome(),
            add.event_log(),
            add.wrapping_keys(),
        )
        .expect("bob joins");
    deliver(add.sender_key_distributions(), &mut alice, &mut bob);
    deliver(bob_join_dists, &mut alice, &mut bob);

    let expected_root = bob.event_log_root(CTX.to_owned());
    drop(bob); // The tab closes.

    // The reopened tab: a fresh surface client over Bob's identity + storage. The
    // constructor restores the converged context from the shared store.
    let mut bob2 = client_over(BOB_DID, Arc::clone(&bob_storage), seed(150));
    assert_eq!(
        bob2.member_dids(CTX.to_owned()).map(|mut m| {
            m.sort();
            m
        }),
        Some(vec![ALICE_DID.to_owned(), BOB_DID.to_owned()]),
        "the converged context was restored on construction"
    );
    assert_eq!(
        bob2.event_log_root(CTX.to_owned()),
        expected_root,
        "restored root matches through the surface"
    );

    // The restored surface client decrypts a message Alice sends post-restore.
    let ciphertext = alice
        .send_message(CTX.to_owned(), b"after restore".to_vec())
        .expect("alice sends");
    let received = bob2
        .receive_message(CTX.to_owned(), ciphertext)
        .expect("bob2 receives");
    assert!(received.application());
    let events = bob2.drain_events(CTX.to_owned()).expect("bob2 drains");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].payload(), b"after restore");
}

#[test]
fn context_ids_lists_contexts_through_the_surface() {
    // The surface exposes `contextIds` so a reopened tab can enumerate the
    // conversations the constructor restored. Here we assert it over live contexts
    // created through the surface (sorted).
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    {
        let mut c = client_over(ALICE_DID, Arc::clone(&storage), seed(0));
        c.create_context("ctx-surface-b".to_owned())
            .expect("create b");
        c.create_context("ctx-surface-a".to_owned())
            .expect("create a");
        assert_eq!(
            c.context_ids(),
            vec!["ctx-surface-a".to_owned(), "ctx-surface-b".to_owned()],
            "the surface lists contexts sorted"
        );
    }
    // A reopened surface client over the same storage restores + lists both.
    let c2 = client_over(ALICE_DID, Arc::clone(&storage), seed(50));
    assert_eq!(
        c2.context_ids(),
        vec!["ctx-surface-a".to_owned(), "ctx-surface-b".to_owned()],
        "the reopened surface client lists both restored contexts"
    );
}

#[test]
fn context_status_reports_live_and_absent_through_the_surface() {
    // The surface exposes `contextStatus` as a lowercase string ("live"/"poisoned"
    // /"absent") so a caller can distinguish a held context from an absent one
    // without the `Option` observers' poisoned/absent ambiguity.
    let mut c = client_for(ALICE_DID, seed(0));

    // Absent before creation.
    assert_eq!(c.context_status("ctx-never-existed".to_owned()), "absent");

    // Live after creation.
    c.create_context(CTX.to_owned()).expect("create");
    assert_eq!(c.context_status(CTX.to_owned()), "live");

    // Absent again after close.
    c.close_context(CTX.to_owned()).expect("close");
    assert_eq!(c.context_status(CTX.to_owned()), "absent");

    // The "poisoned" status is unreachable through the wasm surface on the native
    // host: poisoning requires a mutating op whose persist fails, and that op
    // returns `Err(JsValue)`, which aborts off-wasm before returning (the same
    // native-host limitation documented for error-path coverage below). The full
    // three-state mapping is asserted directly against the driver in `scp-client`'s
    // `context_status_reports_live_poisoned_and_absent`.
}

/// ADR-057 at the surface: the convergent-timestamp forgery seam is gone
/// **by construction**. `sendMessage` returns the raw ciphertext bytes (no
/// `WasmSendOutput` wrapper carrying a loose `committerTimestampSecs`), and
/// `receiveMessage` takes ONLY `(context_id, ciphertext)` — there is no third
/// `u64` timestamp parameter a caller or relay could set to a forged value. This
/// is a compile-time proof: binding each method to its exact function type only
/// type-checks if the signature matches, so a re-introduction of a transported
/// timestamp parameter (or a send-output wrapper) fails the build.
#[test]
#[allow(clippy::type_complexity)] // the explicit fn-pointer type IS the assertion
fn convergent_timestamp_forgery_seam_is_gone_by_construction() {
    use scp_client_wasm::WasmReceiveOutput;
    use wasm_bindgen::JsValue;

    // `receiveMessage` accepts only the ciphertext — no timestamp to forge.
    let _: fn(&mut WasmScpClient, String, Vec<u8>) -> Result<WasmReceiveOutput, JsValue> =
        WasmScpClient::receive_message;
    // `sendMessage` returns the ciphertext bytes directly — the convergent
    // timestamp rides inside the authenticated AAD, not a separate return value.
    let _: fn(&mut WasmScpClient, String, Vec<u8>) -> Result<Vec<u8>, JsValue> =
        WasmScpClient::send_message;
}

// NOTE on error-path coverage: a `#[wasm_bindgen]` method that returns
// `Err(JsValue)` cannot be exercised on the native host — constructing the
// `JsValue` aborts (wasm-bindgen imported calls cannot run off-wasm), before any
// `Result` is returned. So the surface's error mapping — including the
// tampered-ciphertext rejection through `receiveMessage` — is NOT asserted in
// this native happy-path test. It is covered instead by:
//   * the driver-level tamper test `tampered_ciphertext_produces_no_leaf`
//     (`scp-client`), which proves a flipped ciphertext byte is rejected and
//     stamps no leaf — `receiveMessage` is a thin forwarder to that exact path;
//   * the pure `error::error_code` mapping (native unit tests in `error.rs`),
//     which proves duplicate-context → `SCP-CTX-2002`, unknown-context →
//     `SCP-CTX-2001`, and the convergent-timestamp family → `SCP-CRYPTO-4040`;
//     and
//   * `error::wasm_tests` (`#[wasm_bindgen_test]`), which proves the wrapped
//     `JsValue` carries that prefix and the message.
// This native-host limitation is a real property of testing a wasm-bindgen
// surface off-target, reported in the slice write-up.

// wasm-target tests: exercises the real `JsStorage` extern against a JS
// `Map`-backed store — the synchronous-facade shape a browser SDK injects
// (ADR-057 T2, `storage.rs` module docs). Runs only under a wasm test runner (no
// `wasm-bindgen-test-runner` is wired here — see the module header — so these are
// compiled by the `wasm32` build gate and run when a runner is present).
#[cfg(all(test, target_arch = "wasm32"))]
mod wasm_tests {
    use scp_client::Storage;
    use scp_client_wasm::storage::{JsStorage, JsStorageAdapter};
    use wasm_bindgen::prelude::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    // A synchronous, in-memory `Map`-backed store implementing the `JsStorage`
    // contract (`get`/`set`/`delete`/`listKeys`) — the shape the TypeScript SDK's
    // IndexedDB mirror satisfies.
    #[wasm_bindgen(inline_js = "export function makeMapStore() { \
        const m = new Map(); \
        return { \
            get(k) { return m.has(k) ? m.get(k) : undefined; }, \
            set(k, v) { m.set(k, v); }, \
            delete(k) { m.delete(k); }, \
            listKeys(prefix) { const out = []; for (const k of m.keys()) { if (k.startsWith(prefix)) out.push(k); } return out; } \
        }; \
    }")]
    extern "C" {
        #[wasm_bindgen(js_name = "makeMapStore")]
        fn make_map_store() -> JsStorage;
    }

    #[wasm_bindgen_test]
    fn map_backed_js_store_round_trips_through_the_adapter() {
        let store = JsStorageAdapter::new(make_map_store());

        // Absent key → Ok(None), not an error.
        assert_eq!(store.get("scp-client/ctx/a").unwrap(), None);

        store.put("scp-client/ctx/a", vec![1, 2, 3]).unwrap();
        store.put("scp-client/ctx/b", vec![4]).unwrap();
        store.put("scp-client/pending/a", vec![9]).unwrap();

        // Values round-trip byte-for-byte.
        assert_eq!(store.get("scp-client/ctx/a").unwrap(), Some(vec![1, 2, 3]));

        // Prefix enumeration returns exactly the matching keys (the restore path).
        let mut ctx_keys = store.list_keys("scp-client/ctx/").unwrap();
        ctx_keys.sort();
        assert_eq!(
            ctx_keys,
            vec!["scp-client/ctx/a".to_owned(), "scp-client/ctx/b".to_owned()]
        );
        assert_eq!(
            store.list_keys("scp-client/pending/").unwrap(),
            vec!["scp-client/pending/a".to_owned()]
        );

        // Delete removes exactly one key.
        store.delete("scp-client/ctx/a").unwrap();
        assert_eq!(store.get("scp-client/ctx/a").unwrap(), None);
        assert_eq!(store.list_keys("scp-client/ctx/").unwrap().len(), 1);
    }
}
