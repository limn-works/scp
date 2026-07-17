//! Single-threaded SCP participant driver (ADR-057 Slice 2).
//!
//! `scp-client` is the in-tab participant: a synchronous driver over the shared
//! [`scp_mls`] MLS state machine, the shared [`scp_protocol`] sender-key layer,
//! and the canonical [`scp_event_log`] Merkle log. It proves that the SCP
//! participant path — create / join / add-member / send / receive-decrypt /
//! process-commit / close, with the §9.16 double-encryption pipeline and the
//! event-log leaves — runs **single-threaded** and **compiles to wasm32**,
//! with no `scp-runtime` actor/tokio orchestration.
//!
//! # Relationship to the deleted WASM bridge
//!
//! This crate restores the *shape* of the WASM bridge removed by ADR-055
//! (pinned at `1a3b41a5e^`): a per-context state map accessed synchronously,
//! op methods of the same names, and a pull-based `drain_events` model. It does
//! **not** restore the bridge's protocol *bodies* — those were a wasm-local
//! re-implementation that had to stay byte-identical to native (the parity tax
//! ADR-055 killed). Every body here calls shared [`scp_mls`] / [`scp_protocol`]
//! / [`scp_event_log`] logic, so there is one implementation compiled to two
//! targets, not two implementations to keep in lock-step.
//!
//! # Scope fence (ADR-057, mechanically enforced)
//!
//! The driver covers the **participant message path only**. Economy, governance
//! voting, broadcast hosting, cross-context saga coordination, outlets,
//! discovery, and UCAN minting are node-side and out of scope — they require
//! always-on hosts and would regrow the driver toward the deleted 15.5K-line
//! manager. The fence is enforced **by the dependency graph**, not prose: this
//! crate depends only on the wasm-safe shared crates plus the `openmls` stack
//! and MUST NOT depend on `scp-runtime`, `scp-identity`, or `tokio`. Anything
//! that needs those is, by construction, node-side.
//!
//! # Injected dependencies (keys on-device, storage abstracted)
//!
//! [`ScpClient`] is constructed with three injected dependencies:
//! - a [`Signer`] — the on-device DID identity (a [`LocalSigner`] for the MVP;
//!   a WebCrypto-callback custody backend in a later slice — the key never
//!   enters wasm memory),
//! - a [`Storage`] — per-context snapshot store the driver writes after every
//!   mutating op and restores from (by key-prefix enumeration) in
//!   [`ScpClient::new`] when a tab reopens (ADR-057 T2). [`MemoryStorage`] is a
//!   valid production backend for an ephemeral (no-persistence) client and the
//!   convenient one in tests; an `IndexedDB`/OPFS backend backs a durable browser
//!   client,
//! - a [`scp_clock::Clock`] — the hardened time source for
//!   committer-assigned event-log leaf timestamps (ADR-057 Prerequisite 1),
//! - a [`RelaySink`] — the injected **outbound** relay port. The driver hands it
//!   serialized relay `ClientMessage` frames (a `SUBSCRIBE` on context entry, a
//!   `PUBLISH` per §9.10.4 fan-out address on send/announce); inbound relay
//!   frames flow the other way, pushed by the embedder into
//!   [`ScpClient::handle_relay_frame`]. In a browser this is a `wasm-bindgen`
//!   `JsSocket` over the tab's WebSocket ([`MemoryStorage`] has no transport
//!   analogue — a no-persistence client still needs a real socket to reach peers).
//!
//! # In-tab sender-key distribution (§9.16.1/§9.16.2, ADR-057)
//!
//! Members share their §9.16 sender keys **in-tab**, over the MLS
//! `scp_wrapping_key` leaf extension — there is no out-of-band hand-off. Each
//! member publishes a stable X25519 **wrapping key** in its `KeyPackage` / creator
//! leaf; peers HPKE-seal their per-member sender keys to it and deliver the
//! sealed key as an MLS-authenticated **management message** (SCPM-tagged,
//! §9.16.1) over the same wire path as an application message. The wrapping-key
//! **directory** (`did → wrapping_key`) IS the authoritative member set, so a
//! member is never recorded without the key a peer needs to seal to it.
//!
//! Distribution fires on three events (a topologically complete push mesh):
//! 1. the **adder** seals its key to the joiner
//!    ([`AddMemberOutput::sender_key_distributions`]);
//! 2. the **joiner** seals its key to every existing member
//!    ([`ScpClient::join_context_encrypted`] return);
//! 3. every **bystander** processing the add-Commit seals its key to the new
//!    member ([`ReceiveOutput::sender_key_distributions`] — the make-or-break
//!    third trigger; without it members silently cannot decrypt each other).
//!
//! A member installs an incoming distribution by HPKE-opening it with its
//! wrapping secret in [`ScpClient::receive_message`]; only the sealed-to member
//! can open it. [`ScpClient::rotate_sender_key`] re-distributes a fresh key
//! (§9.16.5). Residuals (out of scope, pending the pull path): a signed
//! `SenderKeyEpochAdvance`, block-triggered auto-rotation, and re-driving a push
//! to a member that was offline during it.

mod client;
mod context;
mod crypto_state;
mod error;
mod relay_sink;
mod signer;
mod snapshot;
mod storage;

pub use client::{AddMemberOutput, ContextStatus, ReceiveOutput, ScpClient};
pub use context::{EVENT_BUFFER_CAP, PerContextState};
pub use crypto_state::{
    ContextCryptoState, INITIAL_SENDER_KEY_EPOCH, Inbound, RecvChannel, SenderKeyDistribution,
};
pub use error::ClientError;
pub use relay_sink::RelaySink;
pub use signer::{LocalSigner, Signer};
// `ContextSnapshot` / `SNAPSHOT_FORMAT_VERSION` are intentionally NOT re-exported:
// the snapshot blob format is a crate-internal persistence detail (captured/
// restored only inside this driver), so it stays `crate`-visible in the private
// `snapshot` module rather than surfacing on the public API.
pub use storage::{MemoryStorage, Storage};
