// wasm-bindgen requires owned `String` / `Vec<u8>` parameters on exported
// methods (not `&str` / `&[u8]`), so `needless_pass_by_value` is a false
// positive on the bridge surface. wasm-bindgen also cannot mark exported
// methods `const`.
#![allow(clippy::needless_pass_by_value, clippy::missing_const_for_fn)]

//! `wasm-bindgen` browser surface for the SCP participant driver (ADR-057
//! Slice 3, MVP).
//!
//! This crate is the in-tab participant's JS entry point: a thin
//! `#[wasm_bindgen]` translation layer over [`scp_client::ScpClient`], the
//! single-threaded driver Slice 2 built over the shared `scp-mls` /
//! `scp-protocol` / `scp-event-log` machine. It exposes the participant
//! operations to JavaScript, with bytes crossing as `Uint8Array`/`Vec<u8>` and
//! errors as thrown JS exceptions carrying stable `[SCP-…]` code prefixes.
//!
//! # Thin by construction
//!
//! Every method body forwards to `scp_client::ScpClient`; this crate re-derives
//! **no** protocol logic. That is the whole point of ADR-057: one MLS state
//! machine compiled to two targets, not a wasm re-implementation kept
//! byte-identical to native (the parity tax ADR-055 removed). The deleted WASM
//! bridge (`crates/scp-ffi/wasm/`, pinned at `1a3b41a5e^`) is the restoration
//! source for the browser *infra* shape — the hardened clock, the JS-injected
//! storage/custody externs, the error-code mapping, the panic hook — **not**
//! for its protocol bodies.
//!
//! # Injected platform dependencies (keys on-device)
//!
//! The browser constructor `WasmScpClient::from_js` takes three JS-injected
//! objects: a `WebCrypto`-backed key-custody object (its bound DID becomes this
//! participant's identity; see [`custody`] for the ADR-057 friction note on
//! where the MLS signing key currently lives), an `IndexedDB`/OPFS-backed storage
//! object, and a [`socket::JsSocket`] wrapping the tab's relay WebSocket (the
//! outbound relay port; inbound frames are pushed back in via
//! [`WasmScpClient::handle_relay_frame`]). The clock is **not** injected: it is
//! the hardened captured-`Date.now` source ([`time::WasmClock`]) built inside wasm
//! at construction, closing the override surface an injected JS clock would
//! reintroduce. The native host-test seam [`WasmScpClient::from_parts`] takes the
//! four built driver dependencies (signer, storage, clock, socket) directly.
//!
//! # Scope fence (ADR-057, mechanically enforced)
//!
//! Participant message path ONLY. The fence is enforced by the dependency
//! graph: this crate depends only on the wasm-safe shared crates plus the
//! wasm-bindgen stack, and MUST NOT depend on `scp-runtime`, `scp-identity`, or
//! `tokio`. Economy, governance, broadcast hosting, saga coordination, and
//! presence are node-side by construction.

pub mod custody;
pub mod error;
pub mod socket;
pub mod storage;
pub mod time;

use std::sync::Arc;

use scp_client::{ContextStatus, RelaySink, ScpClient, Signer, Storage};
use scp_clock::Clock;
use wasm_bindgen::prelude::*;

use crate::error::map_err;

/// Initializes the browser surface.
///
/// Installs a panic hook that routes Rust panics to the browser console as a
/// **payload-free, redacted** message plus the static source `file:line`. The
/// driver runs the §9.16 crypto path, so a panic there could otherwise
/// interpolate key material or plaintext into its message; this hook never reads
/// the panic payload (mirroring the native supervisor watchdog redaction,
/// ADR-049 §10). Idempotent — `set_hook` replaces any prior hook.
///
/// Call once after the WASM module loads, before any other entry point.
#[wasm_bindgen]
#[cfg(target_arch = "wasm32")]
pub fn scp_init() {
    std::panic::set_hook(Box::new(|info| {
        let location = info.location().map_or_else(
            || "unknown".to_owned(),
            |l| format!("{}:{}", l.file(), l.line()),
        );
        let redacted =
            format!("scp panic at {location}; payload withheld (may contain key material)");
        web_sys::console::error_1(&JsValue::from_str(&redacted));
    }));
}

/// Returns the crate version string.
#[must_use]
#[wasm_bindgen]
pub fn scp_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

/// The wire output of [`WasmScpClient::add_member`]: the bytes the caller must
/// distribute, plus the join-replay material the new member needs.
///
/// Mirrors [`scp_client::AddMemberOutput`] across the JS boundary. The
/// convergent committer timestamp is **not** a field: it is bound into the
/// `commit`'s authenticated MLS AAD (ADR-057), so existing members recover
/// it from the verified frame in [`WasmScpClient::receive_message`] rather than
/// being handed a forgeable loose value. The `event_log` is exposed as its
/// TLS/MessagePack-serialized form so it can ride the wire to the joiner; the
/// joiner feeds it back via [`WasmScpClient::join_context_encrypted`].
#[wasm_bindgen]
pub struct WasmAddMemberOutput {
    commit: Vec<u8>,
    welcome: Vec<u8>,
    event_log: Vec<u8>,
    wrapping_keys: Vec<u8>,
    sender_key_distributions: Vec<WasmSenderKeyDistribution>,
}

#[wasm_bindgen]
impl WasmAddMemberOutput {
    /// The TLS-serialized MLS Commit for existing members.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn commit(&self) -> Vec<u8> {
        self.commit.clone()
    }

    /// The TLS-serialized MLS Welcome for the new member.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn welcome(&self) -> Vec<u8> {
        self.welcome.clone()
    }

    /// The adder's serialized event-log stream after the add. The joiner
    /// replays it (via [`WasmScpClient::join_context_encrypted`]) to converge.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "eventLog")]
    pub fn event_log(&self) -> Vec<u8> {
        self.event_log.clone()
    }

    /// The adder's serialized member-wrapping-key directory after the add — the
    /// authoritative member set as `(did, wrapping_key)` pairs (ADR-057 sender-key
    /// distribution). The joiner feeds it back via
    /// [`WasmScpClient::join_context_encrypted`] so it can seal its sender key to
    /// every existing member.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "wrappingKeys")]
    pub fn wrapping_keys(&self) -> Vec<u8> {
        self.wrapping_keys.clone()
    }

    /// The adder's own §9.16 sender key, HPKE-sealed to the new joiner (delivered
    /// to `target_did` via [`WasmScpClient::receive_message`]).
    #[must_use]
    #[wasm_bindgen(getter, js_name = "senderKeyDistributions")]
    pub fn sender_key_distributions(&self) -> Vec<WasmSenderKeyDistribution> {
        self.sender_key_distributions.clone()
    }
}

/// A single HPKE-sealed sender-key distribution to deliver (§9.16.1/§9.16.2).
///
/// `ciphertext` is an MLS-encrypted management frame; the caller routes it to
/// `targetDid`'s [`WasmScpClient::receive_message`], which installs the key.
#[wasm_bindgen]
#[derive(Clone)]
pub struct WasmSenderKeyDistribution {
    target_did: String,
    ciphertext: Vec<u8>,
}

#[wasm_bindgen]
impl WasmSenderKeyDistribution {
    /// The DID this distribution is sealed for (the in-tab delivery hint).
    #[must_use]
    #[wasm_bindgen(getter, js_name = "targetDid")]
    pub fn target_did(&self) -> String {
        self.target_did.clone()
    }

    /// The MLS-encrypted management frame carrying the HPKE-sealed sender key.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }
}

impl From<scp_client::SenderKeyDistribution> for WasmSenderKeyDistribution {
    fn from(d: scp_client::SenderKeyDistribution) -> Self {
        Self {
            target_did: d.target_did,
            ciphertext: d.ciphertext,
        }
    }
}

/// The outcome of [`WasmScpClient::receive_message`].
///
/// Reports whether an application message was produced, plus any sender-key
/// distributions the receive triggered (the bystander re-distribution trigger —
/// ADR-057 INVARIANT 2).
#[wasm_bindgen]
pub struct WasmReceiveOutput {
    application: bool,
    sender_key_distributions: Vec<WasmSenderKeyDistribution>,
}

#[wasm_bindgen]
impl WasmReceiveOutput {
    /// `true` if an application message was decrypted (a `MessageReceived` event
    /// is buffered for [`WasmScpClient::drain_events`]); `false` for a Commit, a
    /// sender-key install, or a bare proposal.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn application(&self) -> bool {
        self.application
    }

    /// Sender-key distributions this receive triggered (empty except when
    /// processing an add-Commit as an existing member — INVARIANT 2).
    #[must_use]
    #[wasm_bindgen(getter, js_name = "senderKeyDistributions")]
    pub fn sender_key_distributions(&self) -> Vec<WasmSenderKeyDistribution> {
        self.sender_key_distributions.clone()
    }
}

/// A drained context event, in JS-friendly form.
///
/// The participant driver buffers local message history — a sender's own
/// `MessageSent` and a receiver's `MessageReceived` — and this carries the
/// (decrypted) message across the boundary. `kind` is the event variant name
/// (`"MessageSent"` / `"MessageReceived"`) so the caller can discriminate, and
/// the surface stays forward-safe if the driver buffers more variants later.
#[wasm_bindgen]
pub struct WasmReceivedEvent {
    kind: String,
    sender_did: String,
    payload: Vec<u8>,
}

#[wasm_bindgen]
impl WasmReceivedEvent {
    /// The event variant name (e.g. `"MessageReceived"`).
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn kind(&self) -> String {
        self.kind.clone()
    }

    /// The sender's DID.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "senderDid")]
    pub fn sender_did(&self) -> String {
        self.sender_did.clone()
    }

    /// The decrypted plaintext payload.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn payload(&self) -> Vec<u8> {
        self.payload.clone()
    }
}

/// The browser participant client: a `#[wasm_bindgen]` facade over
/// [`scp_client::ScpClient`].
#[wasm_bindgen]
pub struct WasmScpClient {
    inner: ScpClient,
}

impl WasmScpClient {
    /// Constructs the facade from already-built driver dependencies, **restoring**
    /// any persisted contexts and pending joins from `storage` (ADR-057 T2).
    ///
    /// This is the native-host test seam: the host test builds in-memory adapters
    /// (including a soft [`TestClock`](scp_clock::TestClock)) and calls this
    /// directly, exercising the same driver construction the browser path uses.
    ///
    /// **Gated off the `wasm32` target** (`#[cfg(not(target_arch = "wasm32"))]`):
    /// on a browser build the ONLY constructor is [`WasmScpClient::from_js`], which
    /// builds the hardened captured-`Date.now` [`WasmClock`](crate::time::WasmClock)
    /// internally. Exposing `from_parts` (which accepts an INJECTED clock) on the
    /// wasm surface would let a caller substitute a soft/attacker-controllable clock
    /// and bypass the `WasmClock` hardening (ADR-057 §Prereq-1, api-design minor).
    /// `from_js` therefore constructs the driver inline rather than through this
    /// seam. Available on native for the host tests (which run off-target — see
    /// `wasm_surface_exchange`, itself native-only).
    ///
    /// # Errors
    ///
    /// Returns the mapped `[SCP-STORAGE-…]` / `[SCP-CRYPTO-…]` error if restore
    /// fails closed (corrupt/foreign/unreadable snapshot).
    #[cfg(not(target_arch = "wasm32"))]
    pub fn from_parts(
        signer: Arc<dyn Signer>,
        storage: Arc<dyn Storage>,
        clock: Arc<dyn Clock>,
        relay_sink: Arc<dyn RelaySink>,
    ) -> Result<Self, JsValue> {
        Ok(Self {
            inner: map_err(ScpClient::new(signer, storage, clock, relay_sink))?,
        })
    }
}

#[wasm_bindgen]
impl WasmScpClient {
    /// Constructs a browser participant client from JS-injected dependencies.
    ///
    /// `custody` is a `WebCrypto`-backed key custody object (its bound DID
    /// becomes this participant's identity); `storage` is an
    /// `IndexedDB`/OPFS-backed key/value object. The clock is the hardened
    /// captured-`Date.now` source — not injected, because hardening it requires
    /// capturing the reference *inside* wasm at init (an injected JS clock would
    /// reintroduce the override surface the capture defends against).
    ///
    /// On construction the client **restores** any contexts and pending joins the
    /// injected storage holds for this identity (ADR-057 T2) — a reopened tab
    /// resumes its live state here, with no separate "load" call.
    ///
    /// # Errors
    ///
    /// Throws if the custody object has no bound DID identity, or a
    /// `[SCP-STORAGE-…]` / `[SCP-CRYPTO-…]` error if a persisted snapshot fails
    /// its restore (corrupt, foreign-owned, or unreadable) — restore fails closed.
    #[wasm_bindgen(constructor)]
    #[cfg(target_arch = "wasm32")]
    pub fn from_js(
        custody: crate::custody::JsKeyCustody,
        storage: crate::storage::JsStorage,
        socket: crate::socket::JsSocket,
    ) -> Result<Self, JsValue> {
        let signer: Arc<dyn Signer> = Arc::new(crate::custody::JsSigner::from_custody(custody)?);
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::JsStorageAdapter::new(storage));
        // The clock is built HERE, hardened, and never injected — see `from_parts`
        // (which is gated off the shipped wasm target so no soft clock can be
        // substituted). Construct the driver inline rather than through `from_parts`.
        let clock: Arc<dyn Clock> = Arc::new(crate::time::WasmClock::new());
        let relay_sink: Arc<dyn RelaySink> = Arc::new(crate::socket::JsSocketAdapter::new(socket));
        Ok(Self {
            inner: map_err(ScpClient::new(signer, storage, clock, relay_sink))?,
        })
    }

    /// This participant's DID.
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn did(&self) -> String {
        self.inner.did().to_owned()
    }

    /// Creates a new encrypted context with this participant as sole member.
    ///
    /// # Errors
    ///
    /// Throws `[SCP-CTX-2002]` if the context id is already held, or a
    /// `[SCP-CRYPTO-…]` error on group-creation / leaf failure. A
    /// `[SCP-STORAGE-8010]` on the post-create snapshot write **poisons** the
    /// freshly-created context (its in-memory state exists but was never durably
    /// recorded); discard this client and reconstruct it via the [`WasmScpClient`] constructor for your target.
    /// The poisoned context then surfaces `[SCP-STORAGE-8013]` on any later op —
    /// see [`ContextStatus`](scp_client::ContextStatus).
    #[wasm_bindgen(js_name = "createContext")]
    pub fn create_context(&mut self, context_id: String) -> Result<(), JsValue> {
        map_err(self.inner.create_context(&context_id))
    }

    /// Generates a single-use `KeyPackage` so this participant can be added to
    /// `context_id` by an existing member. Returns the public key-package bytes
    /// to hand to the adder; the private join material is retained internally.
    ///
    /// # Errors
    ///
    /// Throws a `[SCP-CRYPTO-…]` / `[SCP-VALID-…]` error on generation or
    /// serialization failure.
    #[wasm_bindgen(js_name = "generateKeyPackageForJoin")]
    pub fn generate_key_package_for_join(
        &mut self,
        context_id: String,
    ) -> Result<Vec<u8>, JsValue> {
        map_err(self.inner.generate_key_package_for_join(&context_id))
    }

    /// Adds a member to `context_id` from their serialized `KeyPackage`.
    ///
    /// # Errors
    ///
    /// Throws `[SCP-CTX-2001]` if the context is not held, `[SCP-VALID-7010]`
    /// if the key package cannot be deserialized, or a `[SCP-CRYPTO-…]` error on
    /// MLS / leaf failure. A `[SCP-STORAGE-8010]` on the post-add snapshot write
    /// **poisons** the context (its state advanced in memory but was not durably
    /// recorded), and `[SCP-STORAGE-8013]` is thrown if the context is already
    /// poisoned — either way, discard this client and reconstruct it via the [`WasmScpClient`]
    /// constructor for your target (see [`ContextStatus`](scp_client::ContextStatus)).
    #[wasm_bindgen(js_name = "addMember")]
    pub fn add_member(
        &mut self,
        context_id: String,
        key_package_bytes: Vec<u8>,
    ) -> Result<WasmAddMemberOutput, JsValue> {
        let out = map_err(self.inner.add_member(&context_id, &key_package_bytes))?;
        let event_log = serialize_event_log(&out.event_log)?;
        let wrapping_keys = serialize_wrapping_keys(&out.wrapping_keys)?;
        Ok(WasmAddMemberOutput {
            commit: out.commit,
            welcome: out.welcome,
            event_log,
            wrapping_keys,
            sender_key_distributions: out
                .sender_key_distributions
                .into_iter()
                .map(WasmSenderKeyDistribution::from)
                .collect(),
        })
    }

    /// Joins `context_id` from a Welcome, replaying the adder's serialized
    /// event-log stream (from [`WasmAddMemberOutput::event_log`]) and adopting
    /// its membership snapshot so the joiner converges to the adder's root.
    ///
    /// # Errors
    ///
    /// Throws `[SCP-CTX-2005]` if there is no pending join material (route this
    /// case to the reconstruct-from-durable retry path), `[SCP-CTX-2004]` on a
    /// generic driver-invariant violation (bad argument),
    /// `[SCP-CTX-2002]` if already joined, `[SCP-VALID-7010]` if the event-log
    /// stream cannot be deserialized, or a `[SCP-CRYPTO-…]` error on Welcome /
    /// replay failure. A `[SCP-STORAGE-8010]` on the post-join snapshot write
    /// **poisons** the freshly-joined context (its state advanced in memory but was
    /// not durably recorded); discard this client and reconstruct it via the [`WasmScpClient`]
    /// constructor for your target, which restores the still-present pending material and
    /// lets the join be retried. The poisoned context then surfaces
    /// `[SCP-STORAGE-8013]` on any later op — see
    /// [`ContextStatus`](scp_client::ContextStatus).
    #[wasm_bindgen(js_name = "joinContextEncrypted")]
    pub fn join_context_encrypted(
        &mut self,
        context_id: String,
        welcome_bytes: Vec<u8>,
        event_log_bytes: Vec<u8>,
        wrapping_keys_bytes: Vec<u8>,
    ) -> Result<Vec<WasmSenderKeyDistribution>, JsValue> {
        let prior_event_log = deserialize_event_log(&event_log_bytes)?;
        let wrapping_keys = deserialize_wrapping_keys(&wrapping_keys_bytes)?;
        let distributions = map_err(self.inner.join_context_encrypted(
            &context_id,
            &welcome_bytes,
            &prior_event_log,
            &wrapping_keys,
        ))?;
        Ok(distributions
            .into_iter()
            .map(WasmSenderKeyDistribution::from)
            .collect())
    }

    /// Encrypts an application message in `context_id` and **fans it out** over
    /// the injected socket to every announced peer pseudonym (§9.10.4, ADR-057
    /// transport slice).
    ///
    /// There is no return value: the ciphertext leaves via the injected `JsSocket`
    /// as one relay `PUBLISH` per peer, not back to the caller. Inbound delivery is
    /// the reverse — the embedder pumps relay `BLOB` frames into
    /// [`WasmScpClient::handle_relay_frame`]. The convergent committer timestamp is
    /// bound into the ciphertext's authenticated MLS AAD (ADR-057), recovered by
    /// the recipient from the verified frame.
    ///
    /// # Errors
    ///
    /// Throws `[SCP-CTX-2001]` if the context is not held, `[SCP-CTX-2040]` if no
    /// peer has announced a pseudonym yet (retryable — pump peers' announcements in
    /// first), a `[SCP-CRYPTO-…]` error on a crypto / leaf failure, or
    /// `[SCP-TRANS-5010]` if the socket rejects a frame. A `[SCP-STORAGE-8010]`
    /// on the pre-publish snapshot write **poisons** the context, and
    /// `[SCP-STORAGE-8013]` is thrown if the context is already poisoned — either
    /// way, discard this client and reconstruct it via the [`WasmScpClient`]
    /// constructor for your target (see [`ContextStatus`](scp_client::ContextStatus)).
    #[wasm_bindgen(js_name = "sendMessage")]
    pub fn send_message(&mut self, context_id: String, plaintext: Vec<u8>) -> Result<(), JsValue> {
        map_err(self.inner.send_message(&context_id, &plaintext))
    }

    /// Feeds one inbound relay frame (the binary payload of a relay WebSocket
    /// `onmessage`) into the driver (ADR-057 transport slice).
    ///
    /// A relay `BLOB` is resolved to its owning context, unwrapped, and decrypted —
    /// recording a peer's pseudonym announcement, buffering an application message
    /// for [`WasmScpClient::drain_events`], or applying a membership Commit. A frame
    /// for a routing id this client does not track is dropped (not an error).
    ///
    /// # Errors
    ///
    /// Throws `[SCP-VALID-7010]` if the frame or its wrapped envelope cannot be
    /// deserialized, `[SCP-TRANS-5010]` if the relay reported an error, or a
    /// `[SCP-CRYPTO-…]` / `[SCP-CTX-…]` / `[SCP-STORAGE-…]` error if decrypting or
    /// applying a resolved blob fails (the same failures
    /// [`WasmScpClient::receive_message`] raises).
    #[wasm_bindgen(js_name = "handleRelayFrame")]
    pub fn handle_relay_frame(&mut self, frame: Vec<u8>) -> Result<(), JsValue> {
        map_err(self.inner.handle_relay_frame(&frame))
    }

    /// Re-drives a `SUBSCRIBE` for every routing id this client tracks (its local
    /// pseudonym and each held context's shared announcement channel).
    ///
    /// The embedder MUST call this from the relay WebSocket's `onopen` on EVERY
    /// (re)connect. Entry-time subscription is best-effort and never fails context
    /// entry (ADR-057 F-API1/R1), so any `SUBSCRIBE` enqueued while the socket was
    /// closed — including every subscription for a tab restored from storage before
    /// the socket first opened — was silently dropped. Without this call the client
    /// is durably present but receives nothing (goes deaf). Idempotent and
    /// best-effort: safe to call any time the socket is (re)opened; it never throws
    /// (a failed re-subscribe is retried on the next `onopen`).
    #[wasm_bindgen(js_name = "resubscribeAll")]
    pub fn resubscribe_all(&self) {
        self.inner.resubscribe_all();
    }

    /// Receives an inbound MLS message in `context_id`. Returns a
    /// [`WasmReceiveOutput`]: `application` is `true` if it was an application
    /// message (a `MessageReceived` event is buffered for
    /// [`WasmScpClient::drain_events`]), `false` for a membership Commit, a
    /// sender-key install, or a bare proposal; `senderKeyDistributions` carries the
    /// bystander re-distributions an add-Commit triggers (ADR-057 INVARIANT 2), to
    /// deliver to their targets.
    ///
    /// Takes only the ciphertext: the convergent committer timestamp each mirrored
    /// leaf is stamped with is recovered from the message's own **authenticated**
    /// MLS AAD (ADR-057), not passed in — so there is no forgery seam where
    /// a caller (or relay) could supply a mismatched timestamp.
    ///
    /// # Errors
    ///
    /// Throws `[SCP-CTX-2001]` if the context is not held, `[SCP-CTX-2003]` if
    /// the Commit removes a member (out of Slice 2 scope; rejected pre-merge so
    /// the context stays consistent), or a `[SCP-CRYPTO-…]` error on failure
    /// (including a missing or malformed convergent-timestamp AAD —
    /// `[SCP-CRYPTO-4040]`). A `[SCP-STORAGE-8010]` on the post-receive snapshot
    /// write **poisons** the context (the decrypt advanced the ratchet but the new
    /// state was not durably recorded), and `[SCP-STORAGE-8013]` is thrown if the
    /// context is already poisoned — either way, discard this client and
    /// reconstruct it via the [`WasmScpClient`] constructor for your target (see
    /// [`ContextStatus`](scp_client::ContextStatus)).
    #[wasm_bindgen(js_name = "receiveMessage")]
    pub fn receive_message(
        &mut self,
        context_id: String,
        ciphertext: Vec<u8>,
    ) -> Result<WasmReceiveOutput, JsValue> {
        let out = map_err(self.inner.receive_message(&context_id, &ciphertext))?;
        Ok(WasmReceiveOutput {
            application: out.application,
            sender_key_distributions: out
                .sender_key_distributions
                .into_iter()
                .map(WasmSenderKeyDistribution::from)
                .collect(),
        })
    }

    /// Drains all buffered receive events for `context_id` in FIFO order.
    ///
    /// # Errors
    ///
    /// Throws `[SCP-CTX-2001]` if the context is not held. A `[SCP-STORAGE-8010]`
    /// on the snapshot write that records the emptied buffer **poisons** the
    /// context (the buffer was drained in memory but the emptied state was not
    /// durably recorded), and `[SCP-STORAGE-8013]` is thrown if the context is
    /// already poisoned — either way, discard this client and reconstruct it via the [`WasmScpClient`]
    /// constructor for your target (see [`ContextStatus`](scp_client::ContextStatus)).
    #[wasm_bindgen(js_name = "drainEvents")]
    pub fn drain_events(&mut self, context_id: String) -> Result<Vec<WasmReceivedEvent>, JsValue> {
        use scp_protocol::context::membership::ContextEvent;
        let events = map_err(self.inner.drain_events(&context_id))?;
        Ok(events
            .into_iter()
            .map(|event| match event {
                ContextEvent::MessageReceived {
                    sender_did,
                    payload,
                } => WasmReceivedEvent {
                    kind: "MessageReceived".to_owned(),
                    sender_did: sender_did.0,
                    payload,
                },
                // A sender's own local `MessageSent` history (ADR-011 / ADR-057
                // T3): the driver buffers it on send, so the surface returns it
                // with its sender DID + payload, discriminated by `kind`.
                ContextEvent::MessageSent {
                    sender_did,
                    payload,
                    ..
                } => WasmReceivedEvent {
                    kind: "MessageSent".to_owned(),
                    sender_did: sender_did.0,
                    payload,
                },
                // A peer's pseudonym announcement (§9.10.4 — parity with the native
                // event stream): surfaced with the announcer's DID as `senderDid`
                // and the 32-byte routing id as `payload`, so a JS caller can act on
                // "peer X is now reachable at routing id Y" (api-design F-API2).
                ContextEvent::PseudonymAnnounced {
                    member_did,
                    pseudonym,
                } => WasmReceivedEvent {
                    kind: "PseudonymAnnounced".to_owned(),
                    sender_did: member_did.0,
                    payload: pseudonym.to_vec(),
                },
                // Any other variant is surfaced with its name and an empty payload
                // rather than dropped, so the surface is forward-safe.
                other => WasmReceivedEvent {
                    kind: event_kind(&other).to_owned(),
                    sender_did: String::new(),
                    payload: Vec::new(),
                },
            })
            .collect())
    }

    /// Closes and removes `context_id`, destroying its crypto state (forward
    /// secrecy — ADR-057 lose-device-lose-history).
    ///
    /// # Errors
    ///
    /// Throws `[SCP-CTX-2001]` if the context is not held, or `[SCP-STORAGE-8010]`
    /// if a durable delete (the pending-join blob or the snapshot) fails. Close is
    /// retryable: on such a failure the in-memory context is left intact and the
    /// recoverable snapshot is preserved (the delete order deletes the snapshot
    /// last), so the caller can retry.
    #[wasm_bindgen(js_name = "closeContext")]
    pub fn close_context(&mut self, context_id: String) -> Result<(), JsValue> {
        map_err(self.inner.close_context(&context_id))
    }

    // ----------------------------------------------------------------------
    // Sender-key rotation (§9.16.5)
    // ----------------------------------------------------------------------

    /// Rotates this participant's §9.16 sender key and re-distributes it to every
    /// member (§9.16.5), returning the distributions to deliver via
    /// [`WasmScpClient::receive_message`].
    ///
    /// # Errors
    ///
    /// Throws `[SCP-CTX-2001]` if the context is not held, `[SCP-STORAGE-8013]` if
    /// it is poisoned, or a `[SCP-CRYPTO-…]` error on epoch overflow or a
    /// seal/frame failure. A `[SCP-STORAGE-8010]` on the post-rotation snapshot
    /// write **poisons** the context.
    #[wasm_bindgen(js_name = "rotateSenderKey")]
    pub fn rotate_sender_key(
        &mut self,
        context_id: String,
    ) -> Result<Vec<WasmSenderKeyDistribution>, JsValue> {
        let distributions = map_err(self.inner.rotate_sender_key(&context_id))?;
        Ok(distributions
            .into_iter()
            .map(WasmSenderKeyDistribution::from)
            .collect())
    }

    // ----------------------------------------------------------------------
    // Queries
    // ----------------------------------------------------------------------

    /// Returns the ids of every context this client holds (live and poisoned
    /// alike), sorted.
    ///
    /// A reopened tab uses this to list the conversations the constructor restored
    /// from storage — without it there would be no way to enumerate the restored
    /// contexts.
    #[must_use]
    #[wasm_bindgen(getter, js_name = "contextIds")]
    pub fn context_ids(&self) -> Vec<String> {
        self.inner.context_ids()
    }

    /// Reports whether `context_id` is `"live"`, `"poisoned"`, or `"absent"` — the
    /// non-throwing predicate form of the poison guard.
    ///
    /// The `Option` observers ([`memberDids`](WasmScpClient::member_dids) et al.)
    /// collapse "poisoned" into `undefined`, indistinguishable from "absent"; this
    /// distinguishes all three so a caller can decide between RECOVER (reconstruct it
    /// via the [`WasmScpClient`] constructor for your target) and ABANDON ([`closeContext`](WasmScpClient::close_context))
    /// for a poisoned context without provoking `[SCP-STORAGE-8013]`. The status is
    /// a lowercase string (the surface's enum idiom, matching
    /// [`WasmReceivedEvent::kind`]).
    #[must_use]
    #[wasm_bindgen(js_name = "contextStatus")]
    pub fn context_status(&self, context_id: String) -> String {
        match self.inner.context_status(&context_id) {
            ContextStatus::Live => "live",
            ContextStatus::Poisoned => "poisoned",
            ContextStatus::Absent => "absent",
        }
        .to_owned()
    }

    /// Returns the member DIDs of `context_id`, or `undefined` if not held (or
    /// poisoned — see `[SCP-STORAGE-8013]`; poisoned contexts still appear in
    /// [`contextIds`](WasmScpClient::context_ids)).
    #[must_use]
    #[wasm_bindgen(js_name = "memberDids")]
    pub fn member_dids(&self, context_id: String) -> Option<Vec<String>> {
        self.inner.member_dids(&context_id)
    }

    /// Returns the event-log Merkle root (32 bytes) for `context_id`, or
    /// `undefined` if not held (or poisoned — see `[SCP-STORAGE-8013]`; poisoned
    /// contexts still appear in [`contextIds`](WasmScpClient::context_ids)).
    #[must_use]
    #[wasm_bindgen(js_name = "eventLogRoot")]
    pub fn event_log_root(&self, context_id: String) -> Option<Vec<u8>> {
        self.inner
            .event_log_root(&context_id)
            .map(|root| root.to_vec())
    }

    /// Returns the event-log leaf count for `context_id`, or `undefined` if not
    /// held (or poisoned — see `[SCP-STORAGE-8013]`; poisoned contexts still appear
    /// in [`contextIds`](WasmScpClient::context_ids)).
    #[must_use]
    #[wasm_bindgen(js_name = "eventLogLeafCount")]
    pub fn event_log_leaf_count(&self, context_id: String) -> Option<u64> {
        self.inner.event_log_leaf_count(&context_id)
    }

    /// Returns the concatenated event-log leaf hashes (32 bytes each, sequence
    /// order) for `context_id`, or `undefined` if not held (or poisoned — see
    /// `[SCP-STORAGE-8013]`; poisoned contexts still appear in
    /// [`contextIds`](WasmScpClient::context_ids)). Used to assert the §9.9.3
    /// per-leaf convergence property across members.
    #[must_use]
    #[wasm_bindgen(js_name = "eventLogLeafHashes")]
    pub fn event_log_leaf_hashes(&self, context_id: String) -> Option<Vec<u8>> {
        self.inner.event_log_leaf_hashes(&context_id).map(|hashes| {
            let mut flat = Vec::with_capacity(hashes.len() * 32);
            for hash in hashes {
                flat.extend_from_slice(&hash);
            }
            flat
        })
    }

    /// Returns the MLS group epoch for `context_id`.
    ///
    /// # Errors
    ///
    /// Throws `[SCP-CTX-2001]` if the context is not held, `[SCP-CRYPTO-…]`
    /// if the MLS group has been destroyed, or `[SCP-STORAGE-8013]` if the context
    /// is poisoned (discard this client and reconstruct it via the [`WasmScpClient`] constructor for your target
    /// — see [`ContextStatus`](scp_client::ContextStatus)). This read-only observer
    /// never writes, so it cannot raise `[SCP-STORAGE-8010]`.
    #[wasm_bindgen(js_name = "mlsEpoch")]
    pub fn mls_epoch(&self, context_id: String) -> Result<u64, JsValue> {
        map_err(self.inner.mls_epoch(&context_id))
    }

    // Persistence (ADR-057 T2): there is no explicit save/restore surface. The
    // driver writes a snapshot to the injected storage after every state-mutating
    // op automatically, and RESTORES all persisted contexts + pending joins in the
    // constructor ([`WasmScpClient::from_js`]) — a reopened tab reconstructs its
    // live state simply by being built over the same storage.
}

// ---------------------------------------------------------------------------
// §5.4.5 outlet-streaming pure wrappers (browser invoker "signs/verifies its
// own steps" — ADR-057 scope fence)
// ---------------------------------------------------------------------------
//
// These are the ONLY outlet-streaming operations the browser can host. They are
// stateless `scp-protocol` predicates — no client state, no `scp-runtime`, no
// stream pump — so they live here as free `#[wasm_bindgen]` functions (like
// [`scp_version`]). There is NO native FFI counterpart to the signing/preimage
// predicates: on the native (PyO3/UniFFI/NAPI) bridges, credit signing is
// runtime-internal (the runtime signs under the registry-held invoker key via
// KeyCustody, gated by the §5.4.5 FFI caller-auth). These wasm predicates are the
// browser-invoker's ON-DEVICE equivalent (there is no always-on runtime in a
// tab), producing the SAME §5.4.5 `scp-protocol` wire the node's saga validates.
// The browser INVOKER predicate set is:
//
// - [`outlet_stream_compute_caveats_binding`] — the 32-byte `caveats_binding`
//   the invoker commits into its open-request UCAN.
// - [`outlet_stream_verify_chunk_signature`] — verify each operator-signed chunk
//   the invoker receives.
// - [`outlet_stream_sign_credit`] — the invoker SIGNS its own credit-grant step
//   (§5.4.5). A credit grant is an *invoker-authored* message, so signing it is
//   exactly the "participant signs its own steps" the ADR-057 fence permits — it
//   is not coordination.
// - [`outlet_stream_compute_credit_preimage`] — the 32-byte SHA-256 preimage the
//   credit signature covers, exposed as a pure seam so a future WebCrypto/off-wasm
//   signer (the browser custody-signing slice — see the seed-custody note below)
//   can sign the preimage without the private key ever entering wasm.
//
// Browser-initiated streaming CANCEL is deliberately NOT part of this surface:
// §5.4.5 (Cancel signature) binds a cancel's `next_seq` to the runtime's live
// emission cursor ("never a value supplied by the caller"), which a remote
// browser invoker cannot read — so cancel stays node-delegated (ADR-057;
// outlet.json CRITICAL #3), deferred to a future cross-context-cancel slice. A
// browser drain that detects a §5.4.5 sequence gap surfaces `StreamGap` and
// node-side credit-stall / timeout reclaims the stream.
//
// # Signing decision — the caller-supplied seed momentarily lives in wasm memory
//
// [`outlet_stream_sign_credit`] reconstructs an `ed25519_dalek::SigningKey` from
// a caller-supplied 32-byte seed to produce the §5.4.5 signature. This
// momentarily holds a private-key seed in wasm linear memory — the SAME as-built
// posture ADR-057 already documents and sanctions for the MLS signing key in
// Slice 3 (§Consequences "As-built caveat (Slice 3)": the ed25519
// `SignatureKeyPair` "is generated and held inside `scp-mls` in wasm linear
// memory … Until then it is defense-in-depth that is *not yet realized*, not a
// property confidentiality currently rests on (in the tab threat model an
// attacker able to read wasm memory can already read plaintext + group secrets
// regardless)"). Routing signing off-wasm through WebCrypto (so the key never
// enters wasm) is the browser custody-signing slice; the preimage predicate above
// is the forward seam for it. The transient seed copies are best-effort zeroized
// here as hygiene (not load-bearing — see the ADR threat model above).
//
// # Why NOT the pump / open / poll / seal / capture / escrow / receipt
//
// The runtime-backed control plane (`Supervisor::open_outlet_stream`, the
// `StreamSessionHandle` pump, escrow/capture, credit accounting, and executor
// receipt-signing) is `scp-runtime` machinery — tokio-multi-thread, and NOT
// wasm-hostable (ADR-034). The ADR-057 scope fence (§"Scope fence (mandatory)")
// puts economy/saga COORDINATION node-side by construction and enforces it
// MECHANICALLY: `scp-client` / this crate must not depend on `scp-runtime`, so
// the pump/seal/escrow/receipt path is unreachable here by the dependency graph,
// not by prose. The browser is a *participant* that "signs its own steps" (the
// invoker's caveats-binding and credit) but does not *coordinate*, host escrow,
// or sign executor receipts. It also does NOT mint UCANs in wasm — it computes
// the `caveats_binding` bound into a caller/node-supplied UCAN. The transport
// that carries the open-request to the hosting node and the operator's chunks
// back is out of this crate's scope today (it is the remote-invoker /
// cross-context transport slice; `scp-client` has no outlet invocation surface
// yet), the same out-of-band-seam shape the sender-key hand-off above uses.
//
// # BigInt marshalling (note for the TS-wasm session, SCP-OUT-048 unit B)
//
// `monotonic_seq` and `stream_epoch` are `u64` and therefore marshal across the
// wasm-bindgen boundary as JS `BigInt`, not `number`. The TS-wasm wrapper must
// pass `BigInt` values for these parameters.

/// Computes the §5.4.5 `caveats_binding` (pure; mirrors
/// `outlet_stream_compute_caveats_binding`). Returns the 32-byte binding as a
/// `Uint8Array`.
///
/// A browser invoker binds this value into its outlet-stream open request so the
/// hosting node can pin the exact UCAN caveats the stream was authorized under.
/// It is a deterministic SHA-256 over `(ucan_cid, request_id, invoker_did,
/// estimated_chunk_count, effective_caveats_jcs)` — see
/// [`scp_protocol::context::outlets::stream::compute_caveats_binding`].
///
/// `effectiveCaveatsJcs` MUST be the RFC 8785 JCS canonical encoding of the
/// post-narrowing `InvocationCaveats` (§7.3.8), with `None` fields OMITTED (not
/// serialized as `null`) per the §5.4.5 JCS Option rule. This function consumes
/// those bytes as produced; it does not canonicalize.
///
/// # Errors
///
/// Throws `[SCP-VALID-7010]` if `requestId` is not exactly 16 bytes.
#[wasm_bindgen(js_name = "outletStreamComputeCaveatsBinding")]
pub fn outlet_stream_compute_caveats_binding(
    ucan_cid: Vec<u8>,
    request_id: Vec<u8>,
    invoker_did: String,
    estimated_chunk_count: u32,
    effective_caveats_jcs: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    use scp_protocol::context::outlets::stream::compute_caveats_binding;
    let request_id = <[u8; 16]>::try_from(request_id.as_slice())
        .map_err(|_| JsValue::from_str("[SCP-VALID-7010] request_id must be 16 bytes"))?;
    let binding = compute_caveats_binding(
        &ucan_cid,
        &request_id,
        &invoker_did,
        estimated_chunk_count,
        &effective_caveats_jcs,
    );
    Ok(binding.to_vec())
}

/// Verifies an outlet-stream chunk's operator signature (pure; mirrors
/// `outlet_stream_verify_chunk_signature`).
///
/// This is a browser invoker's chunk-acceptance step: a remote invoker that
/// receives §5.4.5 stream chunks over transport verifies each was signed by the
/// outlet OPERATOR for this stream before acting on it. Delegates to
/// [`scp_protocol::context::outlets::stream::verify_chunk_signature`], whose
/// preimage binds `(context_id, outlet_id, chunk.request_id, chunk.sequence,
/// caveats_binding, chunk.payload)`.
///
/// `chunk` is the JSON-serialized [`OutletStreamChunk`] (the same wire encoding
/// the NAPI bridge accepts, so the TS SDK produces/consumes ONE chunk form
/// across bindings). `operatorPk` and `caveatsBinding` are 32-byte values.
///
/// Returns `true` iff the signature is valid; a valid chunk that fails
/// verification (wrong key, tampered payload) returns `false` — that is a
/// verification RESULT, not an error.
///
/// # Errors
///
/// Throws `[SCP-VALID-7010]` on malformed INPUT — a chunk that will not
/// deserialize, an `operatorPk` that is not 32 bytes or not a valid Ed25519
/// point, or a `caveatsBinding` that is not 32 bytes. These are distinct from a
/// `false` return so a caller can tell "I was handed garbage" from "this chunk
/// is not from the operator".
#[wasm_bindgen(js_name = "outletStreamVerifyChunkSignature")]
pub fn outlet_stream_verify_chunk_signature(
    chunk: Vec<u8>,
    operator_pk: Vec<u8>,
    context_id: String,
    outlet_id: String,
    caveats_binding: Vec<u8>,
) -> Result<bool, JsValue> {
    use scp_protocol::context::outlets::stream::{OutletStreamChunk, verify_chunk_signature};
    let chunk: OutletStreamChunk = serde_json::from_slice(&chunk).map_err(|e| {
        JsValue::from_str(&format!(
            "[SCP-VALID-7010] invalid OutletStreamChunk bytes: {e}"
        ))
    })?;
    let pk_bytes = <[u8; 32]>::try_from(operator_pk.as_slice())
        .map_err(|_| JsValue::from_str("[SCP-VALID-7010] operator_pk must be 32 bytes"))?;
    let operator_verifying_key =
        ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes).map_err(|e| {
            JsValue::from_str(&format!(
                "[SCP-VALID-7010] operator_pk is not a valid key: {e}"
            ))
        })?;
    let binding = <[u8; 32]>::try_from(caveats_binding.as_slice())
        .map_err(|_| JsValue::from_str("[SCP-VALID-7010] caveats_binding must be 32 bytes"))?;
    Ok(verify_chunk_signature(
        &chunk,
        &operator_verifying_key,
        &context_id,
        &outlet_id,
        &binding,
    ))
}

/// Signs an outlet-stream credit grant with the invoker's Ed25519 signing key
/// (pure).
///
/// This is the browser-invoker's ON-DEVICE credit-signing equivalent — there is
/// no native sign-credit FFI to mirror (on the native bridges credit signing is
/// runtime-internal via `KeyCustody`); this predicate produces the same §5.4.5
/// `scp-protocol` wire the node's saga validates.
///
/// A browser invoker authors credit grants for a node-hosted stream: each grant
/// authorizes the executor to emit `grant` additional billable chunks. This
/// reconstructs the invoker's `SigningKey` from `signingKeySeed`, signs the
/// §5.4.5 credit-grant preimage via
/// [`scp_protocol::context::outlets::stream::sign_credit_grant`], assembles the
/// [`OutletStreamCredit`] (`request_id` ‖ `grant` ‖ `monotonic_seq` ‖ `sig`),
/// and returns its JSON encoding.
///
/// `monotonicSeq` and `streamEpoch` are `u64` → JS `BigInt`.
///
/// # Security
///
/// `signingKeySeed` is a 32-byte private-key seed held momentarily in wasm
/// memory (ADR-057 §Consequences "As-built caveat (Slice 3)"); see the section
/// module doc. The transient seed copies are zeroized best-effort.
///
/// # Errors
///
/// Throws `[SCP-VALID-7010]` if `signingKeySeed` is not exactly 32 bytes,
/// `requestId` is not 16 bytes, or `caveatsBinding` is not 32 bytes.
#[wasm_bindgen(js_name = "outletStreamSignCredit")]
// Flat §5.4.5 credit envelope — agent-first named params over the wasm-bindgen
// boundary (no borrowed structs across the JS seam). `Vec<u8>` is marshalled by
// value by wasm-bindgen.
#[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]
pub fn outlet_stream_sign_credit(
    signing_key_seed: Vec<u8>,
    context_id: String,
    outlet_id: String,
    request_id: Vec<u8>,
    grant: u32,
    monotonic_seq: u64,
    stream_epoch: u64,
    caveats_binding: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    use scp_protocol::context::outlets::stream::{
        CreditGrantSigningInputs, OutletStreamCredit, sign_credit_grant,
    };
    let signing_key = signing_key_from_seed(signing_key_seed)?;
    let request_id = request_id_16(&request_id)?;
    let binding = caveats_binding_32(&caveats_binding)?;
    let sig = sign_credit_grant(
        &signing_key,
        &CreditGrantSigningInputs {
            context_id: &context_id,
            outlet_id: &outlet_id,
            request_id: &request_id,
            grant,
            monotonic_seq,
            stream_epoch,
            caveats_binding: &binding,
        },
    );
    let credit = OutletStreamCredit {
        request_id,
        grant,
        monotonic_seq,
        sig,
    };
    serde_json::to_vec(&credit)
        .map_err(|e| JsValue::from_str(&format!("[SCP-VALID-7010] serializing credit: {e}")))
}

/// Computes the §5.4.5 credit-grant signature preimage (pure; mirrors
/// [`scp_protocol::context::outlets::stream::compute_credit_sig_preimage`]).
///
/// This is the #1980-forward `WebCrypto` seam: it returns the 32-byte SHA-256
/// hash the invoker's signature covers, WITHOUT touching any private key, so an
/// off-wasm signer (`WebCrypto`, hardware custody) can sign the preimage and the
/// caller assembles the [`OutletStreamCredit`] itself. `outletStreamSignCredit`
/// is the in-wasm counterpart for the current seed-in-wasm posture.
///
/// `monotonicSeq` and `streamEpoch` are `u64` → JS `BigInt`.
///
/// # Errors
///
/// Throws `[SCP-VALID-7010]` if `requestId` is not 16 bytes or `caveatsBinding`
/// is not 32 bytes.
#[wasm_bindgen(js_name = "outletStreamComputeCreditPreimage")]
#[allow(clippy::needless_pass_by_value)] // wasm-bindgen marshals `Vec<u8>` by value
pub fn outlet_stream_compute_credit_preimage(
    context_id: String,
    outlet_id: String,
    request_id: Vec<u8>,
    grant: u32,
    monotonic_seq: u64,
    stream_epoch: u64,
    caveats_binding: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    use scp_protocol::context::outlets::stream::compute_credit_sig_preimage;
    let request_id = request_id_16(&request_id)?;
    let binding = caveats_binding_32(&caveats_binding)?;
    let preimage = compute_credit_sig_preimage(
        &context_id,
        &outlet_id,
        &request_id,
        grant,
        monotonic_seq,
        stream_epoch,
        &binding,
    );
    Ok(preimage.to_vec())
}

/// Reconstructs an `ed25519_dalek::SigningKey` from a caller-supplied 32-byte
/// seed, failing closed `[SCP-VALID-7010]` on any other length. The transient
/// seed byte copies (the caller's `Vec` and the fixed array) are zeroized
/// best-effort after the key is built — hygiene, not a load-bearing guarantee
/// (see the section module doc's seed-custody note + ADR-057 Slice-3 caveat).
fn signing_key_from_seed(
    mut signing_key_seed: Vec<u8>,
) -> Result<ed25519_dalek::SigningKey, JsValue> {
    use zeroize::Zeroize;
    let mut seed = <[u8; 32]>::try_from(signing_key_seed.as_slice()).map_err(|_| {
        signing_key_seed.zeroize();
        JsValue::from_str("[SCP-VALID-7010] signing_key_seed must be 32 bytes")
    })?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    seed.zeroize();
    signing_key_seed.zeroize();
    Ok(signing_key)
}

/// Parses a 16-byte `request_id`, failing closed `[SCP-VALID-7010]` otherwise.
fn request_id_16(request_id: &[u8]) -> Result<[u8; 16], JsValue> {
    <[u8; 16]>::try_from(request_id)
        .map_err(|_| JsValue::from_str("[SCP-VALID-7010] request_id must be 16 bytes"))
}

/// Parses a 32-byte `caveats_binding`, failing closed `[SCP-VALID-7010]`
/// otherwise.
fn caveats_binding_32(caveats_binding: &[u8]) -> Result<[u8; 32], JsValue> {
    <[u8; 32]>::try_from(caveats_binding)
        .map_err(|_| JsValue::from_str("[SCP-VALID-7010] caveats_binding must be 32 bytes"))
}

/// Serializes the adder's event-log stream for transport to the joiner.
///
/// `scp_event_log::Event` is `serde`; the joiner deserializes the identical
/// sequence via [`deserialize_event_log`]. This is `MessagePack` (`rmp_serde`)
/// in its compact positional (array) encoding — a self-consistent
/// serialize/deserialize pair used only as ephemeral join-replay transport
/// across the JS boundary. It is width-/endianness-independent (ADR-057). It is
/// NOT the convergent artifact: the §9.9.3 Merkle root is computed over the
/// `Event` field values by `append_unsigned_event` on replay, independent of
/// this transport encoding.
fn serialize_event_log(events: &[scp_event_log::Event]) -> Result<Vec<u8>, JsValue> {
    rmp_serde::to_vec(events)
        .map_err(|e| JsValue::from_str(&format!("[SCP-VALID-7010] serializing event log: {e}")))
}

/// Deserializes the adder's event-log stream the joiner replays.
fn deserialize_event_log(bytes: &[u8]) -> Result<Vec<scp_event_log::Event>, JsValue> {
    rmp_serde::from_slice(bytes)
        .map_err(|e| JsValue::from_str(&format!("[SCP-VALID-7010] deserializing event log: {e}")))
}

/// Serializes the adder's member-wrapping-key directory for transport to the
/// joiner (`MessagePack`, width-/endianness-independent — same transport idiom as
/// the event-log stream).
fn serialize_wrapping_keys(wrapping_keys: &[(String, [u8; 32])]) -> Result<Vec<u8>, JsValue> {
    rmp_serde::to_vec(wrapping_keys)
        .map_err(|e| JsValue::from_str(&format!("[SCP-VALID-7010] serializing wrapping keys: {e}")))
}

/// Deserializes the member-wrapping-key directory the joiner adopts.
fn deserialize_wrapping_keys(bytes: &[u8]) -> Result<Vec<(String, [u8; 32])>, JsValue> {
    rmp_serde::from_slice(bytes).map_err(|e| {
        JsValue::from_str(&format!(
            "[SCP-VALID-7010] deserializing wrapping keys: {e}"
        ))
    })
}

/// The variant name of a non-`MessageReceived` context event (forward-safety
/// for [`WasmScpClient::drain_events`]).
fn event_kind(event: &scp_protocol::context::membership::ContextEvent) -> &'static str {
    use scp_protocol::context::membership::ContextEvent;
    match event {
        ContextEvent::MessageReceived { .. } => "MessageReceived",
        ContextEvent::MessageSent { .. } => "MessageSent",
        ContextEvent::PseudonymAnnounced { .. } => "PseudonymAnnounced",
        ContextEvent::MemberJoined { .. } => "MemberJoined",
        ContextEvent::MemberLeft { .. } => "MemberLeft",
        _ => "Other",
    }
}

// Native-host tests: the HAPPY path of the two §5.4.5 pure wrappers. These
// exercise only the `Ok(...)` arms, which never construct a `JsValue` — so they
// run on the native host, where wasm-bindgen imported calls (`JsValue::from_str`)
// abort. The `Err(JsValue)` (bad-input) arms cannot run natively and are covered
// by the wasm-target tests below. This mirrors the split in `crate::error`.
#[cfg(test)]
mod pure_wrapper_tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::format_collect
    )]

    use scp_protocol::context::outlets::stream::{
        ChunkPayload, OutletStreamChunk, compute_caveats_binding, sign_chunk,
    };
    use scp_protocol::trust::caveats::InvocationCaveats;

    use super::*;

    /// `outletStreamComputeCaveatsBinding` produces the 32-byte binding that the
    /// core `compute_caveats_binding` helper produces for the same inputs — the
    /// wasm wrapper adds nothing but the byte translation.
    #[test]
    fn compute_caveats_binding_matches_core_helper() {
        let caveats_jcs = InvocationCaveats::empty()
            .to_canonical_json_bytes()
            .unwrap();
        let request_id = [7u8; 16];

        let got = outlet_stream_compute_caveats_binding(
            b"cid-abc".to_vec(),
            request_id.to_vec(),
            "did:dht:zInvoker".to_owned(),
            3,
            caveats_jcs.clone(),
        )
        .expect("valid inputs produce a binding");
        assert_eq!(got.len(), 32, "caveats binding is 32 bytes");

        let expected =
            compute_caveats_binding(b"cid-abc", &request_id, "did:dht:zInvoker", 3, &caveats_jcs);
        assert_eq!(
            got.as_slice(),
            expected.as_slice(),
            "the wrapper matches the core helper byte-for-byte"
        );
    }

    /// `outletStreamVerifyChunkSignature` accepts a chunk signed under the
    /// matching operator key (`true`) and rejects one checked against a different
    /// key (`false`) — fail-closed. Both are `Ok(...)` results (no `JsValue`), so
    /// this runs natively.
    #[test]
    fn verify_chunk_signature_accepts_matching_key_rejects_other() {
        let caveats_jcs = InvocationCaveats::empty()
            .to_canonical_json_bytes()
            .unwrap();
        let request_id = [7u8; 16];
        let binding =
            compute_caveats_binding(b"cid-abc", &request_id, "did:dht:zInvoker", 3, &caveats_jcs);

        let operator = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let payload = ChunkPayload::Data {
            value: serde_json::json!({ "sum": 3 }),
        };
        let sig = sign_chunk(
            &operator,
            "ctx-1",
            "outlet-1",
            &request_id,
            0,
            &binding,
            &payload,
        )
        .unwrap();
        let chunk = OutletStreamChunk {
            request_id,
            sequence: 0,
            payload,
            sig,
        };
        let chunk_bytes = serde_json::to_vec(&chunk).unwrap();

        assert!(
            outlet_stream_verify_chunk_signature(
                chunk_bytes.clone(),
                operator.verifying_key().as_bytes().to_vec(),
                "ctx-1".to_owned(),
                "outlet-1".to_owned(),
                binding.to_vec(),
            )
            .expect("well-formed inputs verify without error"),
            "accepts a chunk signed under the matching operator key"
        );

        let other = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        assert!(
            !outlet_stream_verify_chunk_signature(
                chunk_bytes,
                other.verifying_key().as_bytes().to_vec(),
                "ctx-1".to_owned(),
                "outlet-1".to_owned(),
                binding.to_vec(),
            )
            .expect("a wrong-key check is a `false` RESULT, not an error"),
            "rejects a chunk checked against a different operator key"
        );
    }

    /// `outletStreamSignCredit` produces an [`OutletStreamCredit`] whose `sig`
    /// verifies under the invoker's public key + matching epoch/binding, and
    /// fails closed under a wrong PK or a wrong `stream_epoch` (the epoch is bound
    /// into the §5.4.5 preimage). Signed under the §25.2 RFC-8032 reference seed
    /// so the wire bytes align with the other tiers' KATs.
    #[test]
    fn sign_credit_roundtrips_and_binds_epoch() {
        use scp_protocol::context::outlets::stream::{OutletStreamCredit, verify_credit_signature};

        let seed = REFERENCE_OPERATOR_SEED;
        let invoker_pk = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
        assert_eq!(
            invoker_pk.as_bytes(),
            &EXPECTED_OPERATOR_PK,
            "the §25.2 reference seed must derive the §25.2 public key"
        );
        let request_id = [7u8; 16];
        let binding = [3u8; 32];
        let (ctx, outlet, grant, monotonic_seq, stream_epoch) =
            ("ctx-1", "outlet-1", 5u32, 2u64, 9u64);

        let bytes = outlet_stream_sign_credit(
            seed.to_vec(),
            ctx.to_owned(),
            outlet.to_owned(),
            request_id.to_vec(),
            grant,
            monotonic_seq,
            stream_epoch,
            binding.to_vec(),
        )
        .expect("valid inputs sign a credit");

        let credit: OutletStreamCredit =
            serde_json::from_slice(&bytes).expect("credit JSON round-trips");
        assert_eq!(credit.request_id, request_id);
        assert_eq!(credit.grant, grant);
        assert_eq!(credit.monotonic_seq, monotonic_seq);

        assert!(
            verify_credit_signature(&credit, &invoker_pk, ctx, outlet, stream_epoch, &binding),
            "accepts under the correct invoker PK + matching epoch/binding"
        );

        let wrong_pk = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]).verifying_key();
        assert!(
            !verify_credit_signature(&credit, &wrong_pk, ctx, outlet, stream_epoch, &binding),
            "rejects under a wrong invoker PK"
        );

        assert!(
            !verify_credit_signature(
                &credit,
                &invoker_pk,
                ctx,
                outlet,
                stream_epoch + 1,
                &binding
            ),
            "rejects under a wrong stream_epoch (epoch is bound into the preimage)"
        );
    }

    /// The credit preimage predicate reproduces the core helper byte-for-byte,
    /// and the sign predicate signs exactly that preimage (verified by
    /// reconstructing the signature from the preimage under the §25.2 reference
    /// seed). Cancel is node-delegated (ADR-057; §5.4.5 runtime-derived
    /// `next_seq`), so there is no browser cancel predicate to pin here.
    #[test]
    fn credit_preimage_matches_core_helper() {
        use ed25519_dalek::Signer;
        use scp_protocol::context::outlets::stream::{
            OutletStreamCredit, compute_credit_sig_preimage,
        };

        let request_id = [7u8; 16];
        let binding = [3u8; 32];
        let (ctx, outlet) = ("ctx-1", "outlet-1");

        let credit_pre = outlet_stream_compute_credit_preimage(
            ctx.to_owned(),
            outlet.to_owned(),
            request_id.to_vec(),
            5,
            2,
            9,
            binding.to_vec(),
        )
        .expect("credit preimage");
        assert_eq!(credit_pre.len(), 32, "credit preimage is 32 bytes");
        let expected_credit =
            compute_credit_sig_preimage(ctx, outlet, &request_id, 5, 2, 9, &binding);
        assert_eq!(
            credit_pre.as_slice(),
            expected_credit.as_slice(),
            "credit preimage matches the core helper byte-for-byte"
        );

        // The sign predicate signs exactly the preimage: reconstruct the
        // signature from the preimage under the reference seed and compare.
        let key = ed25519_dalek::SigningKey::from_bytes(&REFERENCE_OPERATOR_SEED);
        let credit_bytes = outlet_stream_sign_credit(
            REFERENCE_OPERATOR_SEED.to_vec(),
            ctx.to_owned(),
            outlet.to_owned(),
            request_id.to_vec(),
            5,
            2,
            9,
            binding.to_vec(),
        )
        .expect("sign credit");
        let credit: OutletStreamCredit = serde_json::from_slice(&credit_bytes).unwrap();
        assert_eq!(
            credit.sig,
            key.sign(&expected_credit).to_bytes(),
            "signed credit sig == Ed25519(seed, credit_preimage)"
        );
    }

    // -----------------------------------------------------------------------
    // SCP-OUT-039 (§5.4.5) — outlet streaming conformance vectors, WASM tier.
    //
    // WASM has NO tokio runtime (ADR-034 / ADR-057): it cannot open a stream,
    // drive the credit control plane, or observe a `StreamTerminalStatus`.
    // Its conformance role is therefore WIRE INTEGRITY, not terminal status: for
    // EVERY chunk of EVERY vector it (a) recomputes the §5.4.5 `caveats_binding`
    // through the pure wrapper and asserts it equals the core helper byte-for-byte,
    // and (b) signs the chunk under the §25.2 REFERENCE OPERATOR KEY (RFC 8032
    // §7.1 Test Vector 1) and asserts `outletStreamVerifyChunkSignature` returns
    // `true` under the operator key and `false` under a wrong key. The runtime
    // terminal-status behaviour of these same 7 vectors is covered at the runtime
    // and bridge tiers (see .docs/specs/25-test-vectors.md §25.21).
    // -----------------------------------------------------------------------

    /// The §25.2 reference operator Ed25519 seed (RFC 8032 §7.1 Test Vector 1).
    /// Every vector chunk is signed under this key so the WASM tier reproduces
    /// the exact operator-signature wire bytes the other tiers replay.
    const REFERENCE_OPERATOR_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    /// The Ed25519 PUBLIC key that [`REFERENCE_OPERATOR_SEED`] (the §25.2 seed,
    /// RFC 8032 §7.1 Test 1 secret) actually derives — verified independently by
    /// `ed25519_dalek`, OpenSSL, and a standalone RFC-8032 implementation. Pinned
    /// so a corrupted seed byte fails loudly instead of self-consistently.
    ///
    /// Matches the public key stated in spec §25.2 (`…daa62325af021a68f707511a`,
    /// the RFC 8032 §7.1 Test Vector 1 public key) and the repo KAT
    /// `crates/scp-runtime/tests/test_vectors.rs` `REF_PUBKEY`.
    const EXPECTED_OPERATOR_PK: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];

    /// A fixed context id used to build the §5.4.5 chunk-signature preimage for
    /// the WASM vectors. The vectors carry payload descriptors, not literal
    /// context ids (§25.21), so the harness pins one; it is bound identically
    /// into the sign and verify calls. (The opening-UCAN CID is the vector's
    /// declared `open.ucan_cid`, so the `caveats_binding` is a cross-SDK KAT.)
    const VECTOR_CONTEXT_ID: &str = "scp-out-039-ctx";

    /// Builds a sample [`DataProvenance`] for `End` chunks (the vector JSON omits
    /// the provenance record; it is synthesized here so a real `ChunkPayload::End`
    /// can be signed and verified).
    fn sample_provenance() -> scp_protocol::provenance::DataProvenance {
        use scp_protocol::context::params::MemoryScope;
        use scp_protocol::provenance::{DataProvenance, DiscoveryMethod, SourceType};
        DataProvenance {
            source_context: "scp-out-039-source".to_owned(),
            source_type: SourceType::Persistent,
            counterparties: Vec::new(),
            purpose: None,
            discovery_method: DiscoveryMethod::OutOfBand,
            age: std::time::Duration::from_secs(0),
            memory_scope: MemoryScope::Full,
            chain_depth: 0,
            chain_path: None,
            payment_amount: None,
            payment_adapter: None,
            payment_receipt_id: None,
        }
    }

    /// Converts one vector payload descriptor (a `serde_json::Value` with the
    /// §5.4.5 `@type` discriminator) into a real [`ChunkPayload`]. `End` injects
    /// [`sample_provenance`] because the vector JSON omits the provenance record.
    fn payload_from_vector(payload: &serde_json::Value) -> ChunkPayload {
        match payload["@type"]
            .as_str()
            .expect("payload @type is a string")
        {
            "data" => ChunkPayload::Data {
                value: payload["value"].clone(),
            },
            "progress" => ChunkPayload::Progress {
                pct: u16::try_from(payload["pct"].as_u64().expect("pct is u64"))
                    .expect("pct fits u16"),
                note: payload["note"].as_str().map(str::to_owned),
            },
            "end" => ChunkPayload::End {
                aggregate: payload["aggregate"].clone(),
                provenance: sample_provenance(),
                execution_time_ms: payload["execution_time_ms"]
                    .as_u64()
                    .expect("execution_time_ms is u64"),
            },
            "error" => ChunkPayload::Error {
                code: payload["code"].as_str().expect("error code").to_owned(),
                message: payload["message"]
                    .as_str()
                    .expect("error message")
                    .to_owned(),
                terminal: payload["terminal"].as_bool().expect("error terminal flag"),
            },
            other => panic!("unknown payload @type: {other}"),
        }
    }

    /// Reads the 16-byte `request_id` array out of a vector's `open` object.
    fn request_id_from_open(open: &serde_json::Value) -> [u8; 16] {
        let arr = open["request_id"]
            .as_array()
            .expect("request_id is an array");
        assert_eq!(arr.len(), 16, "request_id must be 16 bytes");
        let mut id = [0u8; 16];
        for (i, byte) in arr.iter().enumerate() {
            id[i] = u8::try_from(byte.as_u64().expect("request_id byte is u64"))
                .expect("request_id byte fits u8");
        }
        id
    }

    /// For every chunk of every vector, the WASM pure wrappers reproduce the
    /// §5.4.5 wire integrity: the `caveats_binding` matches the core helper and
    /// the operator signature verifies `true` under the §25.2 key and `false`
    /// under a wrong key.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn outlet_stream_vectors_wire_integrity_across_all_seven() {
        let raw = include_str!("../../../tests/conformance/vectors/outlet_stream_vectors.json");
        let doc: serde_json::Value = serde_json::from_str(raw).expect("vectors JSON parses");
        let vectors = doc["vectors"].as_array().expect("vectors is an array");
        assert_eq!(vectors.len(), 7, "exactly 7 streaming conformance vectors");

        let operator = ed25519_dalek::SigningKey::from_bytes(&REFERENCE_OPERATOR_SEED);
        // Pin the §25.2 public key: a corrupted seed byte fails loudly here rather
        // than producing a self-consistent (but wrong-key) sign/verify roundtrip.
        assert_eq!(
            operator.verifying_key().as_bytes(),
            &EXPECTED_OPERATOR_PK,
            "the §25.2 reference seed must derive the §25.2 public key"
        );
        let operator_pk = operator.verifying_key().as_bytes().to_vec();
        let wrong_pk = ed25519_dalek::SigningKey::from_bytes(&[0x11u8; 32])
            .verifying_key()
            .as_bytes()
            .to_vec();

        let caveats_jcs = InvocationCaveats::empty()
            .to_canonical_json_bytes()
            .expect("empty caveats JCS");

        let mut total_chunks = 0usize;
        for vector in vectors {
            let open = &vector["open"];
            let outlet_id = open["outlet_id"].as_str().expect("outlet_id").to_owned();
            let invoker_did = open["invoker_did"]
                .as_str()
                .expect("invoker_did")
                .to_owned();
            let estimated_chunk_count = u32::try_from(
                open["estimated_chunk_count"]
                    .as_u64()
                    .expect("estimated_chunk_count is u64"),
            )
            .expect("estimated_chunk_count fits u32");
            let request_id = request_id_from_open(open);
            let ucan_cid = open["ucan_cid"].as_str().expect("ucan_cid").to_owned();
            let expected_binding_hex = open["expected_caveats_binding"]
                .as_str()
                .expect("expected_caveats_binding")
                .to_owned();

            // (a) caveats_binding: the pure wrapper == the core helper, byte-for-byte,
            // AND both equal the vector's pinned canonical binding (a cross-SDK KAT
            // over the vector's declared ucan_cid — §25.21).
            let binding_wrapper = outlet_stream_compute_caveats_binding(
                ucan_cid.clone().into_bytes(),
                request_id.to_vec(),
                invoker_did.clone(),
                estimated_chunk_count,
                caveats_jcs.clone(),
            )
            .expect("caveats binding computes");
            let binding_core = compute_caveats_binding(
                ucan_cid.as_bytes(),
                &request_id,
                &invoker_did,
                estimated_chunk_count,
                &caveats_jcs,
            );
            assert_eq!(
                binding_wrapper.as_slice(),
                binding_core.as_slice(),
                "vector {}: wasm caveats-binding wrapper must match the core helper",
                vector["name"]
            );
            let binding =
                <[u8; 32]>::try_from(binding_wrapper.as_slice()).expect("binding is 32 bytes");
            let binding_hex = {
                use std::fmt::Write as _;
                let mut h = String::with_capacity(64);
                for b in binding {
                    let _ = write!(h, "{b:02x}");
                }
                h
            };
            assert_eq!(
                binding_hex, expected_binding_hex,
                "vector {}: computed caveats_binding must equal the vector's pinned KAT",
                vector["name"]
            );

            // (b) per-chunk operator signature: true under the §25.2 key, false
            // under a wrong key.
            for chunk_desc in vector["chunks"].as_array().expect("chunks is an array") {
                let sequence = chunk_desc["sequence"].as_u64().expect("sequence is u64");
                let payload = payload_from_vector(&chunk_desc["payload"]);
                let sig = sign_chunk(
                    &operator,
                    VECTOR_CONTEXT_ID,
                    &outlet_id,
                    &request_id,
                    sequence,
                    &binding,
                    &payload,
                )
                .expect("chunk signs under the reference operator key");
                let chunk = OutletStreamChunk {
                    request_id,
                    sequence,
                    payload,
                    sig,
                };
                let chunk_bytes = serde_json::to_vec(&chunk).expect("chunk serializes");

                assert!(
                    outlet_stream_verify_chunk_signature(
                        chunk_bytes.clone(),
                        operator_pk.clone(),
                        VECTOR_CONTEXT_ID.to_owned(),
                        outlet_id.clone(),
                        binding.to_vec(),
                    )
                    .expect("well-formed verify is an Ok result"),
                    "vector {} seq {sequence}: chunk verifies under the §25.2 operator key",
                    vector["name"]
                );
                assert!(
                    !outlet_stream_verify_chunk_signature(
                        chunk_bytes,
                        wrong_pk.clone(),
                        VECTOR_CONTEXT_ID.to_owned(),
                        outlet_id.clone(),
                        binding.to_vec(),
                    )
                    .expect("wrong-key verify is a `false` result, not an error"),
                    "vector {} seq {sequence}: chunk must NOT verify under a wrong key",
                    vector["name"]
                );
                total_chunks += 1;
            }
        }
        // 2 + 12 + 4 + 2 + 5 + 3 + 2 == 30 chunk descriptors across the 7 vectors
        // (multi_chunk carries an interleaved Progress chunk — §5.4.5).
        assert_eq!(total_chunks, 30, "every chunk descriptor exercised");
    }
}

// wasm-target tests: the `Err(JsValue)` (malformed-input) arms of the two pure
// wrappers, which construct a `JsValue` and so cannot run on the native host.
#[cfg(all(test, target_arch = "wasm32"))]
mod pure_wrapper_wasm_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use wasm_bindgen::JsValue;
    use wasm_bindgen_test::wasm_bindgen_test;

    use super::*;

    fn err_message(err: JsValue) -> String {
        err.as_string().unwrap_or_default()
    }

    /// A `request_id` that is not 16 bytes fails closed as `[SCP-VALID-7010]`.
    #[wasm_bindgen_test]
    fn compute_caveats_binding_rejects_wrong_request_id_len() {
        let err = outlet_stream_compute_caveats_binding(
            b"cid".to_vec(),
            vec![0u8; 8],
            "did:dht:zX".to_owned(),
            1,
            b"{}".to_vec(),
        )
        .expect_err("an 8-byte request_id must be rejected");
        let msg = err_message(err);
        assert!(
            msg.contains("[SCP-VALID-7010]") && msg.contains("request_id must be 16 bytes"),
            "wrong-length request_id fails closed: {msg}"
        );
    }

    /// Malformed chunk bytes, a wrong-length operator key, and a wrong-length
    /// caveats binding each fail closed as `[SCP-VALID-7010]` — distinct from the
    /// `false` a well-formed-but-unauthentic chunk returns.
    #[wasm_bindgen_test]
    fn verify_chunk_signature_rejects_malformed_inputs() {
        use scp_protocol::context::outlets::stream::{
            ChunkPayload, OutletStreamChunk, compute_caveats_binding, sign_chunk,
        };
        use scp_protocol::trust::caveats::InvocationCaveats;

        // Unparseable chunk JSON.
        let err = outlet_stream_verify_chunk_signature(
            b"not json".to_vec(),
            vec![0u8; 32],
            "ctx-1".to_owned(),
            "outlet-1".to_owned(),
            vec![0u8; 32],
        )
        .expect_err("garbage chunk bytes are rejected");
        assert!(
            err_message(err).contains("[SCP-VALID-7010]"),
            "unparseable chunk fails closed"
        );

        // A REAL, round-trippable chunk (built via `sign_chunk`, not hand-authored
        // JSON) so parsing succeeds and the code reaches the key/binding length
        // guards under test.
        let caveats_jcs = InvocationCaveats::empty()
            .to_canonical_json_bytes()
            .unwrap_or_default();
        let request_id = [7u8; 16];
        let binding = compute_caveats_binding(b"cid", &request_id, "did:dht:zX", 1, &caveats_jcs);
        let operator = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let payload = ChunkPayload::Data {
            value: serde_json::json!({ "sum": 3 }),
        };
        let sig = sign_chunk(
            &operator,
            "ctx-1",
            "outlet-1",
            &request_id,
            0,
            &binding,
            &payload,
        )
        .expect("sign a well-formed chunk");
        let chunk_bytes = serde_json::to_vec(&OutletStreamChunk {
            request_id,
            sequence: 0,
            payload,
            sig,
        })
        .expect("serialize the chunk");

        // Wrong-length operator key.
        let err = outlet_stream_verify_chunk_signature(
            chunk_bytes.clone(),
            vec![0u8; 31],
            "ctx-1".to_owned(),
            "outlet-1".to_owned(),
            binding.to_vec(),
        )
        .expect_err("a 31-byte operator key is rejected");
        assert!(
            err_message(err).contains("operator_pk must be 32 bytes"),
            "wrong-length operator key fails closed"
        );

        // Wrong-length caveats binding.
        let err = outlet_stream_verify_chunk_signature(
            chunk_bytes,
            operator.verifying_key().as_bytes().to_vec(),
            "ctx-1".to_owned(),
            "outlet-1".to_owned(),
            vec![0u8; 31],
        )
        .expect_err("a 31-byte caveats binding is rejected");
        assert!(
            err_message(err).contains("caveats_binding must be 32 bytes"),
            "wrong-length caveats binding fails closed"
        );
    }

    /// `outletStreamSignCredit` fails closed `[SCP-VALID-7010]` on a wrong-length
    /// seed, request_id, or caveats binding — checked in that order.
    #[wasm_bindgen_test]
    fn sign_credit_rejects_malformed_inputs() {
        let err = outlet_stream_sign_credit(
            vec![0u8; 31],
            "ctx".to_owned(),
            "o".to_owned(),
            vec![0u8; 16],
            1,
            0,
            0,
            vec![0u8; 32],
        )
        .expect_err("a 31-byte seed is rejected");
        let msg = err_message(err);
        assert!(
            msg.contains("[SCP-VALID-7010]") && msg.contains("signing_key_seed must be 32 bytes"),
            "wrong-length seed fails closed: {msg}"
        );

        let err = outlet_stream_sign_credit(
            vec![0u8; 32],
            "ctx".to_owned(),
            "o".to_owned(),
            vec![0u8; 8],
            1,
            0,
            0,
            vec![0u8; 32],
        )
        .expect_err("an 8-byte request_id is rejected");
        assert!(
            err_message(err).contains("request_id must be 16 bytes"),
            "wrong-length request_id fails closed"
        );

        let err = outlet_stream_sign_credit(
            vec![0u8; 32],
            "ctx".to_owned(),
            "o".to_owned(),
            vec![0u8; 16],
            1,
            0,
            0,
            vec![0u8; 31],
        )
        .expect_err("a 31-byte caveats binding is rejected");
        assert!(
            err_message(err).contains("caveats_binding must be 32 bytes"),
            "wrong-length caveats binding fails closed"
        );
    }

    /// The credit preimage predicate fails closed `[SCP-VALID-7010]` on a
    /// wrong-length request_id or caveats binding (it takes no seed).
    #[wasm_bindgen_test]
    fn compute_preimages_reject_malformed_inputs() {
        let err = outlet_stream_compute_credit_preimage(
            "ctx".to_owned(),
            "o".to_owned(),
            vec![0u8; 8],
            1,
            0,
            0,
            vec![0u8; 32],
        )
        .expect_err("an 8-byte request_id is rejected");
        assert!(
            err_message(err).contains("request_id must be 16 bytes"),
            "credit preimage: wrong-length request_id fails closed"
        );

        let err = outlet_stream_compute_credit_preimage(
            "ctx".to_owned(),
            "o".to_owned(),
            vec![0u8; 16],
            1,
            0,
            0,
            vec![0u8; 31],
        )
        .expect_err("a 31-byte caveats binding is rejected");
        assert!(
            err_message(err).contains("caveats_binding must be 32 bytes"),
            "credit preimage: wrong-length caveats binding fails closed"
        );
    }
}
