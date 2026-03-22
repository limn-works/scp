//! UCAN token types and capability enforcement for SCP — pure protocol types.
//!
//! UcanError, UcanToken, UcanHeader, UcanPayload, Attenuation types.
//! The `mint` module (async UCAN minting) stays in scp-runtime.

pub mod capability;
pub mod nonce;
pub mod revoke;
pub mod spending;
pub mod validate;
