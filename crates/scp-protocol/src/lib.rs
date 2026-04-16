#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! Protocol types and logic for SCP.
//! Provider traits use `#[async_trait]` for dyn-compatibility (no runtime
//! dependency — the macro desugars to `Pin<Box<dyn Future>>`).
//! No tokio, no `OpenMLS`, no scp-platform.

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
