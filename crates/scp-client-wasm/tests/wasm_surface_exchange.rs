//! Two-party end-to-end exchange driven THROUGH the `#[wasm_bindgen]` surface
//! (ADR-057 Slice 3, transport slice — MVP proof).
//!
//! This is the Slice-3 milestone: it proves the *exposed* browser surface and its
//! dependency-injection wiring work end-to-end over the injected relay `RelaySink`,
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
//! [`RelaySink`](scp_client::RelaySink) standing in for `JsSigner`/`JsStorage`/
//! `WasmClock`/`JsSocket`). The `#[wasm_bindgen]` attribute is inert on native, so
//! the host test drives the identical method bodies the browser `from_js`
//! constructor produces; the JS-extern adapters are wasm32-only and covered by the
//! build gate (`cargo build --target wasm32-unknown-unknown`).

// Integration tests assert on happy-path results; `expect`/`panic!` make the
// failure messages legible. The workspace denies these in production code.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
// Test-harness noise: a couple of similar local names (`bob`/`bob2`). The relay
// mock (and its `Mutex`) now lives in the single-sourced `scp-relay-mock` crate.
#![allow(clippy::similar_names)]

// The surface exchange + convergence tests are NATIVE-HOST tests (they drive
// `from_parts` with in-memory adapters and run off-target — no wasm test runner is
// wired here; see the module header). `from_parts` is gated off wasm32, so this
// whole native-host block is native-only. The `wasm_tests` module below is the
// wasm32-target portion.
#[cfg(not(target_arch = "wasm32"))]
mod native_host {
    use std::sync::Arc;

    use scp_client::{LocalSigner, MemoryStorage, Signer, Storage};
    use scp_client_wasm::{WasmScpClient, WasmSenderKeyDistribution};
    use scp_clock::{Clock, SystemClock, TestClock};
    // The faithful in-memory relay model is single-sourced in the dev-only
    // `scp-relay-mock` crate (shared with the `scp-client` suite); this module
    // adapts the surface's `(client, conn)` convention to its `RelayParty` pump.
    use scp_relay_mock::{ConnId, Relay, RelayParty};

    const CTX: &str = "ctx-adr057-slice3-wasm-surface";
    const ALICE_DID: &str = "did:key:z6MkAlice3SurfaceExchangeFixtureKeyAAAAAAA";
    const BOB_DID: &str = "did:key:z6MkBob3SurfaceExchangeFixtureKeyBBBBBBBBBB";

    /// Drives a [`WasmScpClient`] as a [`RelayParty`] so the single-sourced
    /// [`Relay::pump`] can pump the surface. The surface's `handle_relay_frame`
    /// takes owned bytes and returns `Result<(), JsValue>`; on the native host the
    /// happy path returns `Ok` without constructing a `JsValue` (which would abort
    /// off-wasm), so the error arm is unreachable here and mapped to a fixed string.
    struct WasmParty<'a> {
        client: &'a mut WasmScpClient,
        conn: ConnId,
    }

    impl RelayParty for WasmParty<'_> {
        fn conn_id(&self) -> ConnId {
            self.conn
        }

        fn deliver(&mut self, frame: Vec<u8>) -> Result<(), String> {
            self.client
                .handle_relay_frame(frame)
                .map_err(|_| "wasm handle_relay_frame error".to_owned())
        }
    }

    /// Delivers queued `BLOB`s into each party's `handleRelayFrame`, iteratively
    /// until quiescent (running the §9.10.4 reciprocal-announce cascade), through the
    /// single-sourced [`Relay::pump`]. Adapts the `(client, conn)` convention the
    /// surface tests use to the shared [`RelayParty`]-driven pump.
    fn pump(relay: &Relay, parties: &mut [(&mut WasmScpClient, ConnId)]) {
        let mut wrapped: Vec<WasmParty> = parties
            .iter_mut()
            .map(|(client, conn)| WasmParty {
                client,
                conn: *conn,
            })
            .collect();
        let mut refs: Vec<&mut WasmParty> = wrapped.iter_mut().collect();
        relay.pump(&mut refs);
    }

    /// Builds a surface client over mock-JS-shaped in-memory adapters + a relay
    /// connection, through the same `from_parts` seam the wasm32 `from_js`
    /// constructor uses. Returns the client and its connection id.
    fn new_party(relay: &Relay, did: &str, now_secs: u64) -> (WasmScpClient, ConnId) {
        let (conn, sink) = relay.connect();
        let signer: Arc<dyn Signer> = Arc::new(LocalSigner::active_for_testing(did));
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let clock: Arc<dyn Clock> = Arc::new(TestClock::new(now_secs));
        let client = WasmScpClient::from_parts(signer, storage, clock, sink)
            .expect("construct fresh surface client");
        (client, conn)
    }

    /// Builds a surface client over a caller-supplied (shared) storage handle. When
    /// the storage already holds this identity's snapshots, the CONSTRUCTOR restores
    /// them (ADR-057 T2).
    fn party_over(
        relay: &Relay,
        did: &str,
        storage: Arc<dyn Storage>,
        now_secs: u64,
    ) -> (WasmScpClient, ConnId) {
        let (conn, sink) = relay.connect();
        let signer: Arc<dyn Signer> = Arc::new(LocalSigner::active_for_testing(did));
        let clock: Arc<dyn Clock> = Arc::new(TestClock::new(now_secs));
        let client = WasmScpClient::from_parts(signer, storage, clock, sink)
            .expect("construct/restore surface client");
        (client, conn)
    }

    fn seed(offset: u64) -> u64 {
        SystemClock.now_secs() + offset
    }

    /// Routes each in-tab §9.16 sender-key distribution to its target client through
    /// the exposed `receiveMessage` surface. Delivered DIRECTLY (out-of-band), not over
    /// the relay.
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
    /// registries populated (via the pumped reciprocal cascade). Drains bootstrap
    /// events before return.
    fn connect(
        relay: &Relay,
        alice: &mut WasmScpClient,
        alice_conn: ConnId,
        bob: &mut WasmScpClient,
        bob_conn: ConnId,
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
        pump(relay, &mut [(alice, alice_conn), (bob, bob_conn)]);

        let _ = alice.drain_events(CTX.to_owned());
        let _ = bob.drain_events(CTX.to_owned());
    }

    #[test]
    #[allow(clippy::too_many_lines)] // one end-to-end two-party surface scenario, read top-to-bottom
    fn two_party_exchange_through_wasm_surface() {
        let relay = Relay::new();
        let (mut alice, alice_conn) = new_party(&relay, ALICE_DID, seed(0));
        let (mut bob, bob_conn) = new_party(&relay, BOB_DID, seed(100));

        assert_eq!(alice.did(), ALICE_DID, "the surface reports Alice's DID");

        connect(&relay, &mut alice, alice_conn, &mut bob, bob_conn);

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

        // --- Alice sends an application message: it fans out over the relay; there is
        // NO return value. Pump it into Bob's handleRelayFrame. ---
        let plaintext = b"hello from Alice through the wasm-bindgen surface".to_vec();
        alice
            .send_message(CTX.to_owned(), plaintext.clone())
            .expect("Alice sends");
        assert_eq!(
            alice.event_log_leaf_count(CTX.to_owned()),
            Some(2),
            "a send stamps NO convergent leaf (ADR-011): Alice's log stays created + joined"
        );
        pump(
            &relay,
            &mut [(&mut alice, alice_conn), (&mut bob, bob_conn)],
        );

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

        assert!(
            bob.drain_events(CTX.to_owned())
                .expect("re-drain ok")
                .is_empty()
        );

        // --- Reverse direction: Bob → Alice through the surface. ---
        bob.send_message(CTX.to_owned(), b"hi Alice".to_vec())
            .expect("Bob sends");
        pump(
            &relay,
            &mut [(&mut alice, alice_conn), (&mut bob, bob_conn)],
        );
        let alice_events = alice.drain_events(CTX.to_owned()).expect("Alice drains");
        let alice_received: Vec<_> = alice_events
            .iter()
            .filter(|e| e.kind() == "MessageReceived")
            .collect();
        assert_eq!(alice_received.len(), 1, "Alice receives Bob's message");
        assert_eq!(alice_received[0].payload(), b"hi Alice");

        assert_convergence(&alice, &bob);

        assert!(
            alice.mls_epoch(CTX.to_owned()).expect("alice epoch") >= 1,
            "the add Commit advanced Alice's MLS epoch"
        );

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
        let relay = Relay::new();
        let alice_storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let bob_storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());

        let (mut alice, alice_conn) = party_over(&relay, ALICE_DID, alice_storage, seed(0));
        let (mut bob, bob_conn) = party_over(&relay, BOB_DID, Arc::clone(&bob_storage), seed(100));

        connect(&relay, &mut alice, alice_conn, &mut bob, bob_conn);

        let expected_root = bob.event_log_root(CTX.to_owned());
        drop(bob); // The tab closes.

        // The reopened tab restores the converged context (incl. the persisted
        // peer-pseudonym registry) and re-derives + re-subscribes the local pseudonym.
        let (mut bob2, bob2_conn) =
            party_over(&relay, BOB_DID, Arc::clone(&bob_storage), seed(150));
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

        // The restored client decrypts a message Alice sends post-restore (Alice still
        // holds Bob's pseudonym; Bob2 re-derived the same local pseudonym).
        alice
            .send_message(CTX.to_owned(), b"after restore".to_vec())
            .expect("alice sends");
        pump(
            &relay,
            &mut [(&mut alice, alice_conn), (&mut bob2, bob2_conn)],
        );
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
        let relay = Relay::new();
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        {
            let (mut c, _conn) = party_over(&relay, ALICE_DID, Arc::clone(&storage), seed(0));
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
        let (c2, _conn) = party_over(&relay, ALICE_DID, Arc::clone(&storage), seed(50));
        assert_eq!(
            c2.context_ids(),
            vec!["ctx-surface-a".to_owned(), "ctx-surface-b".to_owned()],
            "the reopened surface client lists both restored contexts"
        );
    }

    #[test]
    fn context_status_reports_live_and_absent_through_the_surface() {
        let relay = Relay::new();
        let (mut c, _conn) = new_party(&relay, ALICE_DID, seed(0));
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
}

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
