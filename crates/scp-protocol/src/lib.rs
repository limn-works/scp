#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! Pure sync protocol types and logic for SCP.
//! No tokio, no async, no `OpenMLS`, no scp-platform.

pub mod bridge;
pub mod context;
pub mod crypto;
pub mod discovery;
pub mod economy;
pub mod envelope;
pub mod identity;
pub mod jcs;
pub mod provenance;
pub mod serde_util;
pub mod sync;
pub mod time;
pub mod trust;
pub mod uri;
