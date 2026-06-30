//! Canonical `SagaError` decomposition shared by all FFI bridges.
//!
//! The §6.2.4 cross-context tool-invocation saga reaches one of three typed
//! terminals on failure (`Aborted` / `NeedsRepair` / `Busy`). Every bridge
//! (`PyO3`, napi-rs, `UniFFI`) must turn that terminal into its OWN typed
//! error variant, reading every structured datum STRUCTURALLY off the
//! variant — never by re-parsing a message string. Before this module each
//! bridge inlined an identical decomposition: the same
//! `SagaAbortReason::RateLimited → Option<u64>` read, the same
//! `None`-never-coerced-to-`0` rule, the same `SCP-SAGA-{code}` numeric
//! formatting, the same fixed terminal codes. Three copies of one
//! classification let the bridges silently drift (mirroring the `UcanError`
//! drift that motivated [`crate::ucan_errors`]).
//!
//! This module exposes one function — [`decompose_saga_error`] — that every
//! bridge routes through. It returns a neutral [`SagaErrorParts`] carrying the
//! already-formatted `SCP-SAGA-…` code, the message, and a [`SagaErrorKind`]
//! holding only the per-terminal structured payload. Each bridge's
//! `map_saga_error` becomes a thin 3-arm match from [`SagaErrorParts`] onto
//! its own enum, carrying only the per-bridge field-label difference
//! (`message:` vs `msg:`) and the napi-rs message-suffix encoding. Any change
//! to the saga-error classification (the `RateLimited → Option`,
//! `None`-never-`0`, or `SCP-SAGA-{code}` rules) happens here exactly once and
//! propagates to every bridge.
//!
//! `SagaError` lives in `scp-core` (re-exported from `scp-runtime`), so this
//! module is behind the `resolvers` feature — the same gate as the other
//! scp-core-dependent shared adapters. Only bridges that build against scp-core
//! (and therefore drive the `Supervisor`) compile this module.
//!
//! Provenance: §6.2.4 (cross-context tool-invocation saga) + ADR-049 §3a
//! (atomic cross-context invocation, `RateLimited { retry_after_ms }` /
//! `Rejected` abort reasons, `NeedsRepair` operator-repair handle).

use crate::error_codes as codes;
use scp_core::context::supervisor::{SagaAbortReason, SagaError};

/// The per-terminal structured payload of a decomposed [`SagaError`], with the
/// `SCP-SAGA-{code}` formatting and the `RateLimited → Option<u64>` /
/// `None`-never-`0` classification already applied.
///
/// Holds ONLY the datum that differs per terminal; the shared `code` and
/// `message` live on [`SagaErrorParts`]. Each bridge matches this kind onto its
/// own error enum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SagaErrorKind {
    /// A Prepare-phase abort (spec §6.2.4) — neither side committed.
    ///
    /// `retry_after_ms` is read off the back-off-carrying
    /// `SagaAbortReason::RateLimited` (an `Option<u64>`); the unit
    /// `SagaAbortReason::MailboxSaturated` (no precise drain instant) and a plain
    /// `Rejected` both carry `None`. `None` is propagated, NEVER coerced to
    /// `Some(0)` — a `0` would read as "retry immediately" and re-trip the same
    /// hard limit / re-saturate the same mailbox.
    Aborted {
        /// Rate-limit back-off hint in milliseconds, or `None` (never `0`).
        retry_after_ms: Option<u64>,
    },
    /// Commit-retry exhausted — the saga diverged and requires operator repair
    /// (ADR-049 §3a). Carries the durable saga identifier (the repair handle).
    NeedsRepair {
        /// The durable saga identifier — the operator-repair handle.
        saga_id: String,
    },
    /// The participant context set overlapped an in-flight saga's set
    /// (spec §5.15.4). Carries the contended context id.
    Busy {
        /// The shared context id that forced serialization.
        contended_context: String,
    },
}

/// The neutral, bridge-agnostic decomposition of a [`SagaError`] terminal.
///
/// Carries the canonical `SCP-SAGA-…` `code` (already formatted — for
/// `Aborted` it is `SCP-SAGA-{numeric}`, for `NeedsRepair`/`Busy` it is the
/// fixed terminal code), the human-readable `message`, and the per-terminal
/// structured payload in `kind`. Each bridge's thin `map_saga_error` maps this
/// onto its own typed error enum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SagaErrorParts {
    /// The per-terminal structured payload (`retry_after_ms` / `saga_id` /
    /// `contended_context`).
    pub kind: SagaErrorKind,
    /// The canonical `SCP-SAGA-…` code string (already formatted).
    pub code: String,
    /// Human-readable detail (the underlying terminal's message).
    pub message: String,
}

/// Decomposes a [`SagaError`] terminal into the neutral [`SagaErrorParts`]
/// every FFI bridge maps onto its own typed error enum.
///
/// This is the SINGLE home of the saga-error classification:
///
/// - `Aborted { reason, code, message }` → `kind = Aborted { retry_after_ms }`
///   where `retry_after_ms` is read off the back-off-carrying
///   `SagaAbortReason::RateLimited` (an `Option<u64>`); the unit
///   `SagaAbortReason::MailboxSaturated` and a plain `Rejected` both carry
///   `None`. `None` is propagated, NEVER coerced to `Some(0)`. `code` is
///   formatted as the canonical `SCP-SAGA-{code}` string from the numeric
///   discriminant.
/// - `NeedsRepair { saga_id, message }` → `kind = NeedsRepair { saga_id }`,
///   `code = SCP-SAGA-13065` (the durable operator-repair terminal).
/// - `Busy { contended_context, message }` → `kind = Busy { contended_context }`,
///   `code = SCP-SAGA-13066`.
#[must_use]
pub fn decompose_saga_error(err: SagaError) -> SagaErrorParts {
    match err {
        SagaError::Aborted {
            reason,
            code,
            message,
        } => {
            let retry_after_ms = match reason {
                SagaAbortReason::RateLimited { retry_after_ms } => retry_after_ms,
                // The unit `MailboxSaturated` (no precise drain instant) and a
                // plain `Rejected` both carry no back-off hint.
                SagaAbortReason::MailboxSaturated | SagaAbortReason::Rejected => None,
            };
            SagaErrorParts {
                kind: SagaErrorKind::Aborted { retry_after_ms },
                code: format!("SCP-SAGA-{code}"),
                message,
            }
        }
        SagaError::NeedsRepair { saga_id, message } => SagaErrorParts {
            kind: SagaErrorKind::NeedsRepair { saga_id: saga_id.0 },
            code: codes::SAGA_13065.to_owned(),
            message,
        },
        SagaError::Busy {
            contended_context,
            message,
        } => SagaErrorParts {
            kind: SagaErrorKind::Busy { contended_context },
            code: codes::SAGA_13066.to_owned(),
            message,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scp_core::context::supervisor::SagaId;

    /// A rate-limited abort preserves `retry_after_ms = Some(ms)` STRUCTURALLY
    /// and formats the producer's numeric `code` as the canonical
    /// `SCP-SAGA-{code}` string.
    #[test]
    fn rate_limited_preserves_retry_after_ms_and_formats_code() {
        let parts = decompose_saga_error(SagaError::Aborted {
            reason: SagaAbortReason::RateLimited {
                retry_after_ms: Some(2500),
            },
            code: 13026,
            message: "inbound rate limit exceeded".to_owned(),
        });
        assert_eq!(parts.code, "SCP-SAGA-13026");
        assert_eq!(parts.message, "inbound rate limit exceeded");
        assert_eq!(
            parts.kind,
            SagaErrorKind::Aborted {
                retry_after_ms: Some(2500),
            }
        );
    }

    /// A rate-limited abort with NO precise back-off instant preserves
    /// `retry_after_ms = None` — NEVER coerced to `Some(0)` (a `0` would read
    /// as "retry immediately" and re-trip the same hard limit). This is the
    /// load-bearing classification rule, now tested ONCE here for all bridges.
    #[test]
    fn rate_limited_none_is_never_coerced_to_zero() {
        let parts = decompose_saga_error(SagaError::Aborted {
            reason: SagaAbortReason::RateLimited {
                retry_after_ms: None,
            },
            code: 13026,
            message: "hard limit, no precise back-off".to_owned(),
        });
        assert_eq!(
            parts.kind,
            SagaErrorKind::Aborted {
                retry_after_ms: None,
            },
            "None must NOT be coerced to Some(0)"
        );
    }

    /// The transient unit `MailboxSaturated` abort decomposes to the retryable
    /// `Aborted` kind carrying `retry_after_ms = None` (the variant has no
    /// precise drain instant to surface, so it carries no hint) and formats the
    /// dedicated `SCP-SAGA-13068` code from the numeric discriminant.
    #[test]
    fn mailbox_saturated_decomposes_to_retryable_aborted_kind_and_formats_code() {
        let parts = decompose_saga_error(SagaError::Aborted {
            reason: SagaAbortReason::MailboxSaturated,
            code: 13068,
            message: "participant actor inbox closed during Prepare".to_owned(),
        });
        assert_eq!(parts.code, "SCP-SAGA-13068");
        assert_eq!(
            parts.kind,
            SagaErrorKind::Aborted {
                retry_after_ms: None,
            },
            "the unit MailboxSaturated must decompose to the retryable Aborted kind with no back-off hint"
        );
    }

    /// A plain (non-rate-limit) `Rejected` abort carries `retry_after_ms = None`
    /// and still formats the numeric `code`.
    #[test]
    fn rejected_has_no_retry_hint() {
        let parts = decompose_saga_error(SagaError::Aborted {
            reason: SagaAbortReason::Rejected,
            code: 13050,
            message: "caller not a member".to_owned(),
        });
        assert_eq!(parts.code, "SCP-SAGA-13050");
        assert_eq!(
            parts.kind,
            SagaErrorKind::Aborted {
                retry_after_ms: None,
            }
        );
    }

    /// `NeedsRepair` preserves the durable `saga_id` operator-repair handle and
    /// the fixed terminal code `SCP-SAGA-13065`.
    #[test]
    fn needs_repair_preserves_saga_id_and_fixed_code() {
        let parts = decompose_saga_error(SagaError::NeedsRepair {
            saga_id: SagaId("saga-abc-123".to_owned()),
            message: "commit retries exhausted".to_owned(),
        });
        assert_eq!(parts.code, codes::SAGA_13065);
        assert_eq!(
            parts.kind,
            SagaErrorKind::NeedsRepair {
                saga_id: "saga-abc-123".to_owned(),
            }
        );
    }

    /// `Busy` preserves the contended context id and the fixed terminal code
    /// `SCP-SAGA-13066`.
    #[test]
    fn busy_preserves_contended_context_and_fixed_code() {
        let parts = decompose_saga_error(SagaError::Busy {
            contended_context: "ctx-shared-99".to_owned(),
            message: "participant set overlaps an in-flight saga".to_owned(),
        });
        assert_eq!(parts.code, codes::SAGA_13066);
        assert_eq!(
            parts.kind,
            SagaErrorKind::Busy {
                contended_context: "ctx-shared-99".to_owned(),
            }
        );
    }
}
