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

// Outlet surface re-exports (SCP-OUT-002, AC-5). `OutletId` is exported from
// [`context::roles`]; the remaining types come from [`context::outlets`] and
// its submodules. See §5.4.1 and ADR-049.
//
// Coverage notes:
// - `OutletLifecycleEvent`, `OutletIntegrityStatus`, and `OutletSummary` are
//   umbrella names in the story. The current implementation factors lifecycle
//   into `OutletInvokedEvent` / `OutletRequest` / `OutletResponse` /
//   `OutletStatus` / `OutletErrorCode` / `OutletExecutionError` / `OutletCancel`;
//   integrity into `OutletVerificationResult` / `OutletVerificationSchedule`;
//   and summary into `ContextSummary` (shared with other context facets).
//   All the concrete types are re-exported below so every story-named facade
//   is reachable from the crate root.
pub use context::outlets::integrity::OutletVerificationSchedule;
pub use context::outlets::interface::OutletInterface;
pub use context::outlets::registry::{
    OutletCost, OutletRegistration, OutletRegistry, OutletSchema, OutletTestVector,
    OutletVerificationResult,
};
pub use context::outlets::{
    OutletCancel, OutletError, OutletErrorCode, OutletExecutionError, OutletInvokedEvent,
    OutletKind, OutletRegisteredEvent, OutletRequest, OutletResponse, OutletStatus,
    OutletUpdatedEvent, OutletVerifiedEvent, OutletVerifiedReason,
};
pub use context::roles::OutletId;
