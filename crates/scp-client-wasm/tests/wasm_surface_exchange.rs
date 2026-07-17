//! Two-party end-to-end exchange driven THROUGH the `#[wasm_bindgen]` surface
//! (ADR-057 Slice 3, transport slice — MVP proof).
//!
//! This is the Slice-3 milestone: it proves the *exposed* browser surface and its
//! dependency-injection wiring work end-to-end over the injected relay `Socket`,
//! not just the underlying driver. It drives two [`WasmScpClient`]s — Alice
//! (creator) and Bob (joiner) — through create / generate-key-package / add-member
//! / join / send / **relay-route** / receive / drain / close, touching ONLY the
//! `#[wasm_bindgen]`-exported methods (`sendMessage`, `handleRelayFrame`, …) and
//! the JS-friendly wrapper types exactly as JavaScript would.
//!
//! `sendMessage` no longer returns ciphertext: it fans the message out over the
//! injected socket as relay `PUBLISH` frames (§9.10.4 per-pseudonym fan-out). A
//! test loopback captures those frames and routes them into the peer's
//! `handleRelayFrame` as relay `BLOB`s — the "dumb pipe" a real relay is. Sender
//! keys and pseudonym announcements bootstrap the pair before app data can flow.
//!
//! # Why a native host test, not `wasm-bindgen-test`
//!
//! This environment has the `wasm32-unknown-unknown` target and `wasm-pack`, but
//! **no `wasm-bindgen-test-runner`**. Per ADR-057 Slice 3's stated fallback, the
//! strongest proof available here is a native host test that exercises the
//! wasm-bindgen-exposed surface with mock-JS-shaped injected adapters
//! ([`LocalSigner`]/[`MemoryStorage`]/[`TestClock`] and a native loopback
//! [`Socket`](scp_client::Socket) standing in for `JsSigner`/`JsStorage`/
//! `WasmClock`/`JsSocket`). The `#[wasm_bindgen]` attribute is inert on native, so
//! the host test drives the identical method bodies the browser `from_js`
//! constructor produces; the JS-extern adapters are wasm32-only and covered by the
//! build gate (`cargo build --target wasm32-unknown-unknown`).

// Integration tests assert on happy-path results; `expect`/`panic!` make the
// failure messages legible. The workspace denies these in production code.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::{Arc, Mutex};

use scp_client::{LocalSigner, MemoryStorage, Signer, Socket, Storage};
use scp_client_wasm::{WasmScpClient, WasmSenderKeyDistribution};
use scp_clock::{Clock, SystemClock, TestClock};
use scp_relay_client::{ClientMessage, RelayMessage};

const CTX: &str = "ctx-adr057-slice3-wasm-surface";
const ALICE_DID: &str = "did:key:z6MkAlice3SurfaceExchangeFixtureKeyAAAAAAA";
const BOB_DID: &str = "did:key:z6MkBob3SurfaceExchangeFixtureKeyBBBBBBBBBB";

/// A native loopback [`Socket`] capturing every relay frame the surface publishes.
#[derive(Clone, Default)]
struct LoopbackSocket {
    frames: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl LoopbackSocket {
    fn new() -> Self {
        Self::default()
    }
    fn take_frames(&self) -> Vec<Vec<u8>> {
        std::mem::take(&mut *self.frames.lock().expect("loopback lock"))
    }
}

impl Socket for LoopbackSocket {
    fn send(&self, frame: Vec<u8>) -> Result<(), String> {
        self.frames.lock().expect("loopback lock").push(frame);
        Ok(())
    }
}

/// Converts a captured `PUBLISH` frame into the relay `BLOB` frame `handleRelayFrame`
/// consumes; `None` for a `SUBSCRIBE` frame.
fn publish_to_blob(publish_frame: &[u8]) -> Option<Vec<u8>> {
    match ClientMessage::from_bytes(publish_frame).ok()? {
        ClientMessage::Publish {
            routing_id,
            recipient_hint,
            blob_ttl,
            blob,
            ..
        } => RelayMessage::Blob {
            routing_id,
            blob_id: [0u8; 32],
            recipient_hint,
            blob_ttl,
            stored_at: 0,
            blob,
        }
        .to_bytes()
        .ok(),
        _ => None,
    }
}

/// Routes every `PUBLISH` `from` captured into `to`'s `handleRelayFrame`.
fn route_publishes(from: &LoopbackSocket, to: &mut WasmScpClient) {
    for frame in from.take_frames() {
        if let Some(blob) = publish_to_blob(&frame) {
            to.handle_relay_frame(blob).expect("route relay blob");
        }
    }
}

fn seed(offset: u64) -> u64 {
    SystemClock.now_secs() + offset
}

/// Builds a `WasmScpClient` over mock-JS-shaped in-memory adapters + a native
/// loopback socket, through the same `from_parts` seam the wasm32 `from_js`
/// constructor uses. Returns the client and a handle to its socket.
fn client_for(did: &str, now_secs: u64) -> (WasmScpClient, LoopbackSocket) {
    let socket = LoopbackSocket::new();
    let signer: Arc<dyn Signer> = Arc::new(LocalSigner::active(did));
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let clock: Arc<dyn Clock> = Arc::new(TestClock::new(now_secs));
    let socket_dyn: Arc<dyn Socket> = Arc::new(socket.clone());
    let client = WasmScpClient::from_parts(signer, storage, clock, socket_dyn)
        .expect("construct fresh surface client");
    (client, socket)
}

/// Builds a `WasmScpClient` over a caller-supplied (shared) storage handle + a
/// fresh loopback socket. When the storage already holds this identity's
/// snapshots, the CONSTRUCTOR restores them (ADR-057 T2).
fn client_over(
    did: &str,
    storage: Arc<dyn Storage>,
    now_secs: u64,
) -> (WasmScpClient, LoopbackSocket) {
    let socket = LoopbackSocket::new();
    let signer: Arc<dyn Signer> = Arc::new(LocalSigner::active(did));
    let clock: Arc<dyn Clock> = Arc::new(TestClock::new(now_secs));
    let socket_dyn: Arc<dyn Socket> = Arc::new(socket.clone());
    let client = WasmScpClient::from_parts(signer, storage, clock, socket_dyn)
        .expect("construct/restore surface client");
    (client, socket)
}

/// Routes each in-tab §9.16 sender-key distribution to its target client through
/// the exposed `receiveMessage` surface. Sender-key distributions are delivered
/// DIRECTLY (out-of-band), not over the socket.
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

/// Asserts the §9.9.3 convergence property through the surface.
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

/// Wires Alice (creator) + Bob (joiner) into a fully-connected pair through the
/// surface: MLS shared, §9.16 sender keys exchanged both ways, both pseudonym
/// registries populated. Drains bootstrap events + socket frames before return.
fn connect(
    alice: &mut WasmScpClient,
    alice_sock: &LoopbackSocket,
    bob: &mut WasmScpClient,
    bob_sock: &LoopbackSocket,
) {
    alice.create_context(CTX.to_owned()).expect("Alice creates");
    let bob_kp = bob
        .generate_key_package_for_join(CTX.to_owned())
        .expect("Bob key package");
    let add = alice
        .add_member(CTX.to_owned(), bob_kp)
        .expect("Alice adds Bob");
    let bob_dists = bob
        .join_context_encrypted(
            CTX.to_owned(),
            add.welcome(),
            add.event_log(),
            add.wrapping_keys(),
        )
        .expect("Bob joins");

    deliver(add.sender_key_distributions(), alice, bob);
    deliver(bob_dists, alice, bob);

    // Pump each side's pseudonym announcement to the other.
    route_publishes(alice_sock, bob);
    route_publishes(bob_sock, alice);

    let _ = alice.drain_events(CTX.to_owned());
    let _ = bob.drain_events(CTX.to_owned());
    let _ = alice_sock.take_frames();
    let _ = bob_sock.take_frames();
}

#[test]
#[allow(clippy::too_many_lines)] // one end-to-end two-party surface scenario, read top-to-bottom
fn two_party_exchange_through_wasm_surface() {
    let (mut alice, alice_sock) = client_for(ALICE_DID, seed(0));
    let (mut bob, bob_sock) = client_for(BOB_DID, seed(100));

    assert_eq!(alice.did(), ALICE_DID, "the surface reports Alice's DID");

    // Wire the pair (create/add/join, sender-key + pseudonym bootstrap).
    connect(&mut alice, &alice_sock, &mut bob, &bob_sock);

    let mut alice_members = alice.member_dids(CTX.to_owned()).expect("alice members");
    alice_members.sort();
    assert_eq!(
        alice_members,
        vec![ALICE_DID.to_owned(), BOB_DID.to_owned()]
    );
    assert_eq!(alice.event_log_leaf_count(CTX.to_owned()), Some(2));
    assert_eq!(
        bob.event_log_root(CTX.to_owned()),
        alice.event_log_root(CTX.to_owned()),
        "after replay, Bob's root equals Alice's (full-log convergence)"
    );

    // --- Alice sends an application message: it fans out over the socket; there is
    // NO return value. Route it into Bob's handleRelayFrame. ---
    let plaintext = b"hello from Alice through the wasm-bindgen surface".to_vec();
    alice
        .send_message(CTX.to_owned(), plaintext.clone())
        .expect("Alice sends");
    assert_eq!(
        alice.event_log_leaf_count(CTX.to_owned()),
        Some(2),
        "a send stamps NO convergent leaf (ADR-011): Alice's log stays created + joined"
    );
    route_publishes(&alice_sock, &mut bob);

    // --- Bob drains the decrypted application message. ---
    let events = bob.drain_events(CTX.to_owned()).expect("Bob drains events");
    let received: Vec<_> = events
        .iter()
        .filter(|e| e.kind() == "MessageReceived")
        .collect();
    assert_eq!(
        received.len(),
        1,
        "exactly one received message is buffered"
    );
    assert_eq!(
        received[0].sender_did(),
        ALICE_DID,
        "the sender DID is Alice"
    );
    assert_eq!(
        received[0].payload(),
        plaintext,
        "Bob recovered Alice's exact plaintext through the surface"
    );

    // Draining again yields nothing (pull-based, FIFO, consumed).
    assert!(
        bob.drain_events(CTX.to_owned())
            .expect("re-drain ok")
            .is_empty()
    );

    // --- Reverse direction: Bob → Alice through the surface. ---
    bob.send_message(CTX.to_owned(), b"hi Alice".to_vec())
        .expect("Bob sends");
    route_publishes(&bob_sock, &mut alice);
    let alice_events = alice.drain_events(CTX.to_owned()).expect("Alice drains");
    let alice_received: Vec<_> = alice_events
        .iter()
        .filter(|e| e.kind() == "MessageReceived")
        .collect();
    assert_eq!(alice_received.len(), 1, "Alice receives Bob's message");
    assert_eq!(alice_received[0].payload(), b"hi Alice");

    // --- Convergence (§9.9.3): identical leaf hashes AND equal Merkle roots. ---
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

#[test]
fn restore_through_wasm_surface() {
    // Alice creates + adds Bob; Bob joins — all through the exposed surface, over a
    // shared storage so a reopened-tab client can restore from it.
    let alice_storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let bob_storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());

    let (mut alice, alice_sock) = client_over(ALICE_DID, alice_storage, seed(0));
    let (mut bob, bob_sock) = client_over(BOB_DID, Arc::clone(&bob_storage), seed(100));

    connect(&mut alice, &alice_sock, &mut bob, &bob_sock);

    let expected_root = bob.event_log_root(CTX.to_owned());
    drop(bob); // The tab closes.

    // The reopened tab: a fresh surface client over Bob's identity + storage. The
    // constructor restores the converged context (incl. the persisted peer-pseudonym
    // registry) and re-derives + re-subscribes the local pseudonym.
    let (mut bob2, _bob2_sock) = client_over(BOB_DID, Arc::clone(&bob_storage), seed(150));
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

    // The restored surface client decrypts a message Alice sends post-restore
    // (Alice still holds Bob's pseudonym; Bob2 re-derived the same local pseudonym).
    alice
        .send_message(CTX.to_owned(), b"after restore".to_vec())
        .expect("alice sends");
    route_publishes(&alice_sock, &mut bob2);
    let events = bob2.drain_events(CTX.to_owned()).expect("bob2 drains");
    let received: Vec<_> = events
        .iter()
        .filter(|e| e.kind() == "MessageReceived")
        .collect();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].payload(), b"after restore");
}

#[test]
fn context_ids_lists_contexts_through_the_surface() {
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    {
        let (mut c, _sock) = client_over(ALICE_DID, Arc::clone(&storage), seed(0));
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
    let (c2, _sock) = client_over(ALICE_DID, Arc::clone(&storage), seed(50));
    assert_eq!(
        c2.context_ids(),
        vec!["ctx-surface-a".to_owned(), "ctx-surface-b".to_owned()],
        "the reopened surface client lists both restored contexts"
    );
}

#[test]
fn context_status_reports_live_and_absent_through_the_surface() {
    let (mut c, _sock) = client_for(ALICE_DID, seed(0));

    assert_eq!(c.context_status("ctx-never-existed".to_owned()), "absent");
    c.create_context(CTX.to_owned()).expect("create");
    assert_eq!(c.context_status(CTX.to_owned()), "live");
    c.close_context(CTX.to_owned()).expect("close");
    assert_eq!(c.context_status(CTX.to_owned()), "absent");
}

/// ADR-057 at the surface: the convergent-timestamp forgery seam is gone **by
/// construction**. `receiveMessage` takes ONLY `(context_id, ciphertext)` — no
/// third `u64` timestamp a caller/relay could forge — and `sendMessage` returns
/// `()` (the ciphertext leaves via the socket, not the caller), with the inbound
/// path being `handleRelayFrame(frame)`. Binding each method to its exact function
/// type only type-checks if the signature matches, so re-introducing a transported
/// timestamp parameter or a bare-bytes return fails the build.
#[test]
#[allow(clippy::type_complexity)] // the explicit fn-pointer type IS the assertion
fn convergent_timestamp_forgery_seam_is_gone_by_construction() {
    use scp_client_wasm::WasmReceiveOutput;
    use wasm_bindgen::JsValue;

    let _: fn(&mut WasmScpClient, String, Vec<u8>) -> Result<WasmReceiveOutput, JsValue> =
        WasmScpClient::receive_message;
    // `sendMessage` returns unit — no bare ciphertext, no timestamp.
    let _: fn(&mut WasmScpClient, String, Vec<u8>) -> Result<(), JsValue> =
        WasmScpClient::send_message;
    // The inbound path is the relay-frame pump.
    let _: fn(&mut WasmScpClient, Vec<u8>) -> Result<(), JsValue> =
        WasmScpClient::handle_relay_frame;
}

// NOTE on error-path coverage: a `#[wasm_bindgen]` method that returns
// `Err(JsValue)` cannot be exercised on the native host — constructing the
// `JsValue` aborts (wasm-bindgen imported calls cannot run off-wasm). So the
// surface's error mapping is NOT asserted here; it is covered by the driver-level
// adversarial tests (`scp-client`), the pure `error::error_code` mapping (native
// unit tests in `error.rs`), and `error::wasm_tests` (`#[wasm_bindgen_test]`).

// wasm-target tests: exercises the real `JsStorage` extern against a JS
// `Map`-backed store — the synchronous-facade shape a browser SDK injects
// (ADR-057 T2, `storage.rs` module docs). Runs only under a wasm test runner.
#[cfg(all(test, target_arch = "wasm32"))]
mod wasm_tests {
    use scp_client::Storage;
    use scp_client_wasm::storage::{JsStorage, JsStorageAdapter};
    use wasm_bindgen::prelude::*;
    use wasm_bindgen_test::wasm_bindgen_test;

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

        assert_eq!(store.get("scp-client/ctx/a").unwrap(), None);

        store.put("scp-client/ctx/a", vec![1, 2, 3]).unwrap();
        store.put("scp-client/ctx/b", vec![4]).unwrap();
        store.put("scp-client/pending/a", vec![9]).unwrap();

        assert_eq!(store.get("scp-client/ctx/a").unwrap(), Some(vec![1, 2, 3]));

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

        store.delete("scp-client/ctx/a").unwrap();
        assert_eq!(store.get("scp-client/ctx/a").unwrap(), None);
        assert_eq!(store.list_keys("scp-client/ctx/").unwrap().len(), 1);
    }

    #[wasm_bindgen_test]
    fn retaining_js_store_survives_wasm_memory_reuse() {
        // Regression pin for the `set(value: Vec<u8>)` owned-copy fix (1af0deb72).
        let store = JsStorageAdapter::new(make_map_store());

        let blob_a = vec![0xA1u8; 96];
        let blob_b = vec![0xB2u8; 512];
        let blob_c: Vec<u8> = (0..256u32).map(|i| (i % 251) as u8).collect();
        store.put("scp-client/blob/a", blob_a.clone()).unwrap();
        store.put("scp-client/blob/b", blob_b.clone()).unwrap();
        store.put("scp-client/blob/c", blob_c.clone()).unwrap();

        for i in 0..64u32 {
            let filler = vec![(i & 0xff) as u8; 4096];
            store.put(&format!("scp-client/churn/{i}"), filler).unwrap();
        }
        store
            .put("scp-client/churn/grow", vec![0xD4u8; 32 * 1024 * 1024])
            .unwrap();

        assert_eq!(
            store.get("scp-client/blob/a").unwrap(),
            Some(blob_a),
            "blob A intact after wasm memory churn (owned copy, not a view)"
        );
        assert_eq!(
            store.get("scp-client/blob/b").unwrap(),
            Some(blob_b),
            "blob B intact after wasm memory churn"
        );
        assert_eq!(
            store.get("scp-client/blob/c").unwrap(),
            Some(blob_c),
            "blob C intact after wasm memory churn"
        );
    }
}
