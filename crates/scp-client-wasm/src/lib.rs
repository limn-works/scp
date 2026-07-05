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
//! The browser constructor `WasmScpClient::from_js` takes two JS-injected
//! objects: a `WebCrypto`-backed key-custody object (its bound DID becomes this
//! participant's identity; see [`custody`] for the ADR-057 friction note on
//! where the MLS signing key currently lives) and an `IndexedDB`/OPFS-backed
//! storage object. The clock is **not** injected: it is the hardened
//! captured-`Date.now` source ([`time::WasmClock`]) built inside wasm at
//! construction, closing the override surface an injected JS clock would
//! reintroduce. The native host-test seam [`WasmScpClient::from_parts`] takes
//! the three built driver dependencies (signer, storage, clock) directly.
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
pub mod storage;
pub mod time;

use std::sync::Arc;

use scp_client::{ContextStatus, ScpClient, Signer, Storage};
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
    members: Vec<String>,
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

    /// The adder's membership set after the add (member DIDs).
    #[must_use]
    #[wasm_bindgen(getter)]
    pub fn members(&self) -> Vec<String> {
        self.members.clone()
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
    /// This is the cross-target seam: the `wasm32` constructor
    /// ([`WasmScpClient::from_js`]) builds the JS-injected adapters and calls
    /// this; the native host test builds in-memory adapters and calls this
    /// directly. Keeping the dependency wiring here (not duplicated per target)
    /// means the host test exercises the exact same driver construction the
    /// browser path uses.
    ///
    /// # Errors
    ///
    /// Returns the mapped `[SCP-STORAGE-…]` / `[SCP-CRYPTO-…]` error if restore
    /// fails closed (corrupt/foreign/unreadable snapshot).
    pub fn from_parts(
        signer: Arc<dyn Signer>,
        storage: Arc<dyn Storage>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, JsValue> {
        Ok(Self {
            inner: map_err(ScpClient::new(signer, storage, clock))?,
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
    ) -> Result<Self, JsValue> {
        let signer: Arc<dyn Signer> = Arc::new(crate::custody::JsSigner::from_custody(custody)?);
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::JsStorageAdapter::new(storage));
        let clock: Arc<dyn Clock> = Arc::new(crate::time::WasmClock::new());
        Self::from_parts(signer, storage, clock)
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
        Ok(WasmAddMemberOutput {
            commit: out.commit,
            welcome: out.welcome,
            event_log,
            members: out.members,
        })
    }

    /// Joins `context_id` from a Welcome, replaying the adder's serialized
    /// event-log stream (from [`WasmAddMemberOutput::event_log`]) and adopting
    /// its membership snapshot so the joiner converges to the adder's root.
    ///
    /// # Errors
    ///
    /// Throws `[SCP-CTX-2004]` if there is no pending join material,
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
        members: Vec<String>,
    ) -> Result<(), JsValue> {
        let prior_event_log = deserialize_event_log(&event_log_bytes)?;
        map_err(self.inner.join_context_encrypted(
            &context_id,
            &welcome_bytes,
            &prior_event_log,
            &members,
        ))
    }

    /// Encrypts and "sends" an application message in `context_id`, returning
    /// the wire ciphertext (`Uint8Array`).
    ///
    /// The convergent committer timestamp is bound into the ciphertext's
    /// authenticated MLS AAD (ADR-057) rather than returned separately, so
    /// the recipient recovers it from the verified frame in
    /// [`WasmScpClient::receive_message`] — there is no forgeable loose value for
    /// the caller to relay.
    ///
    /// # Errors
    ///
    /// Throws `[SCP-CTX-2001]` if the context is not held, or a `[SCP-CRYPTO-…]`
    /// error on a crypto / leaf failure. A `[SCP-STORAGE-8010]` on the post-send
    /// snapshot write **poisons** the context (the message's state advanced in
    /// memory but was not durably recorded, so no ciphertext is returned), and
    /// `[SCP-STORAGE-8013]` is thrown if the context is already poisoned — either
    /// way, discard this client and reconstruct it via the [`WasmScpClient`] constructor for your target (see
    /// [`ContextStatus`](scp_client::ContextStatus)).
    #[wasm_bindgen(js_name = "sendMessage")]
    pub fn send_message(
        &mut self,
        context_id: String,
        plaintext: Vec<u8>,
    ) -> Result<Vec<u8>, JsValue> {
        map_err(self.inner.send_message(&context_id, &plaintext))
    }

    /// Receives an inbound MLS message in `context_id`. Returns `true` if it was
    /// an application message (a `MessageReceived` event is buffered for
    /// [`WasmScpClient::drain_events`]), `false` for a membership Commit or
    /// bare proposal.
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
    ) -> Result<bool, JsValue> {
        map_err(self.inner.receive_message(&context_id, &ciphertext))
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
    // Sender-key hand-off (out-of-band — ADR-057 MISSING SEAM)
    // ----------------------------------------------------------------------

    /// Returns this participant's local §9.16 sender-key bytes for `context_id`.
    ///
    /// The driver has no in-tab cross-member sender-key distribution path (a
    /// gap ADR-057 defers to a later HPKE-over-`scp_wrapping_key` slice); the
    /// caller hands these to peers out-of-band, who install them via
    /// [`WasmScpClient::install_sender_key`].
    ///
    /// # Errors
    ///
    /// Throws `[SCP-CTX-2001]` if the context is not held, or `[SCP-STORAGE-8013]`
    /// if the context is poisoned (discard this client and reconstruct it via the [`WasmScpClient`]
    /// constructor for your target — see [`ContextStatus`](scp_client::ContextStatus)).
    /// This read-only observer never writes, so it cannot raise
    /// `[SCP-STORAGE-8010]`.
    #[wasm_bindgen(js_name = "localSenderKeyBytes")]
    pub fn local_sender_key_bytes(&self, context_id: String) -> Result<Vec<u8>, JsValue> {
        let key = map_err(self.inner.local_sender_key_bytes(&context_id))?;
        Ok(key.to_vec())
    }

    /// Installs a peer's §9.16 sender key for `context_id` (received
    /// out-of-band). `key_bytes` MUST be exactly 32 bytes.
    ///
    /// # Errors
    ///
    /// Throws `[SCP-VALID-7010]` if `key_bytes` is not 32 bytes, or
    /// `[SCP-CTX-2001]` if the context is not held. A `[SCP-STORAGE-8010]` on the
    /// snapshot write that persists the updated sender-key store **poisons** the
    /// context, and `[SCP-STORAGE-8013]` is thrown if the context is already
    /// poisoned — either way, discard this client and reconstruct it via the [`WasmScpClient`]
    /// constructor for your target (see [`ContextStatus`](scp_client::ContextStatus)).
    #[wasm_bindgen(js_name = "installSenderKey")]
    pub fn install_sender_key(
        &mut self,
        context_id: String,
        sender_did: String,
        key_bytes: Vec<u8>,
    ) -> Result<(), JsValue> {
        let key: [u8; 32] = key_bytes.try_into().map_err(|v: Vec<u8>| {
            JsValue::from_str(&format!(
                "[SCP-VALID-7010] sender key must be 32 bytes, got {}",
                v.len()
            ))
        })?;
        map_err(self.inner.install_sender_key(&context_id, &sender_did, key))
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

/// The variant name of a non-`MessageReceived` context event (forward-safety
/// for [`WasmScpClient::drain_events`]).
fn event_kind(event: &scp_protocol::context::membership::ContextEvent) -> &'static str {
    use scp_protocol::context::membership::ContextEvent;
    match event {
        ContextEvent::MessageReceived { .. } => "MessageReceived",
        ContextEvent::MessageSent { .. } => "MessageSent",
        ContextEvent::MemberJoined { .. } => "MemberJoined",
        ContextEvent::MemberLeft { .. } => "MemberLeft",
        _ => "Other",
    }
}
