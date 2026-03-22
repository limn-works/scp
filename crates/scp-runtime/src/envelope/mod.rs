//! SCP envelope wire format — async runtime.
//!
//! Pure types are in scp-protocol::envelope. This module retains the
//! async `pseudonym` module and the inner/outer stubs that declare async
//! submodules (sign, ops).

pub mod inner;
pub mod outer;
pub mod pseudonym;
