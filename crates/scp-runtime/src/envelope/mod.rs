//! SCP envelope wire format — async runtime.
//!
//! Pure types are in scp-protocol::envelope. This module retains the
//! async `pseudonym` module and the inner/outer stubs that declare async
//! submodules (sign, ops).

pub mod inner;
pub mod outer;
pub mod pseudonym;

// Re-export pure types from scp-protocol::envelope.
// Note: inner/outer are local modules (they have async submodules),
// so we only re-export non-conflicting modules and types.
pub use scp_protocol::envelope::chunk;
pub use scp_protocol::envelope::padding;
pub use scp_protocol::envelope::validation;
pub use scp_protocol::envelope::{
    EnvelopeError, SCP_PROTOCOL_VERSION, VersionCompatibility, check_version_compatibility,
    version_major, version_minor,
};
