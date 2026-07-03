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
//! voting, broadcast hosting, cross-context saga coordination, tools,
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
//! - a [`Storage`] — out-of-band snapshot store ([`MemoryStorage`] for the MVP;
//!   `IndexedDB` in a later slice),
//! - a [`scp_clock::Clock`] — the hardened time source for
//!   committer-assigned event-log leaf timestamps (ADR-057 Prerequisite 1).
//!
//! # MISSING SEAM (cross-member sender-key distribution)
//!
//! The driver has **no in-tab path to distribute a member's §9.16 sender key to
//! its peers**. This is a pre-existing gap inherited from the deleted bridge:
//! `send_message` emits only the double-ciphertext, never the sender key.
//! ADR-057 defers HPKE-sealed distribution over the MLS `scp_wrapping_key`
//! leaf-node extension (already published by
//! [`scp_mls::generate_key_package_with_wrapping_key`]) to a later slice. For
//! the MVP, [`ScpClient::local_sender_key_bytes`] /
//! [`ScpClient::install_sender_key`] expose the hand-off so a test harness — or
//! a later distribution layer — can wire it; the integration test performs the
//! exchange out-of-band over its "dumb pipe". This is a distribution gap, not a
//! missing `scp-mls` MLS-op seam.

mod client;
mod context;
mod crypto_state;
mod error;
mod signer;
mod storage;

pub use client::{AddMemberOutput, ScpClient, SendOutput};
pub use context::PerContextState;
pub use crypto_state::{ContextCryptoState, INITIAL_SENDER_KEY_EPOCH, Inbound};
pub use error::ClientError;
pub use signer::{LocalSigner, Signer};
pub use storage::{MemoryStorage, Storage};
