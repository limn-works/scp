//! WASM-local MLS encryption and sender key layer.
//!
//! This module ports the cryptographic operations from `scp-core`'s
//! `crypto::mls` and `crypto::sender_keys` modules into a WASM-compatible
//! form. All operations are synchronous (no tokio, no async).
//!
//! # Architecture
//!
//! - `credential` — `WasmScpCredential` (MessagePack-serialized identity payload).
//! - `error` — `WasmCryptoError` error type.
//! - `group` — `WasmMlsGroup` wrapping `OpenMLS` `MlsGroup`.
//! - `encrypt` — Higher-level MLS encrypt/decrypt with TLS serialization.
//! - `sender_key` — AES-256-GCM sender-side key layer.
//! - `state` — `WasmCryptoState` orchestrating both layers.
//!
//! See ADR-001 for the MLS wrapper design and ADR-007 for the sender key layer.

pub mod credential;
pub mod encrypt;
pub mod error;
pub mod group;
pub mod sender_key;
pub mod state;

pub use credential::{WasmScpCredential, WasmSigningKeyId};
pub use encrypt::{mls_decrypt, mls_encrypt};
pub use error::WasmCryptoError;
pub use group::WasmMlsGroup;
pub use sender_key::{SenderKey, decrypt_sender_layer, encrypt_sender_layer, generate_sender_key};
pub use state::{INITIAL_SENDER_KEY_EPOCH, WasmCryptoState, WasmReplayStateSnapshot};
