//! Per-sender AES-256 symmetric key layer for SCP — pure protocol types.
//!
//! SenderKey, SenderKeyStore, SenderKeyError, generate_sender_key.
//! The `key_protocol` module (async key exchange) stays in scp-runtime.

pub mod broadcast;
pub mod encrypt;
pub mod key_protocol_verify;
