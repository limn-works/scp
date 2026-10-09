//! SCP envelope wire format — async runtime.
//!
//! Pure types are in `scp-protocol::envelope`. This module retains the
//! async `pseudonym` module and the inner stub that declares the async `sign`
//! submodule. Sealing and opening run only in the context actor
//! (`ContextCryptoState::seal` and `ContextCryptoState::open`).

pub mod inner;
pub mod pseudonym;
