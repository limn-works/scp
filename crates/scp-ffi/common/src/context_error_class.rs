//! The one classification of [`ContextError`] every bridge maps from.
//!
//! [`classify_context_error`] names, for each `ContextError` variant, the
//! error class and the code from [`crate::error_codes`] the variant carries in
//! every binding. Its match is exhaustive with no wildcard arm, so a new
//! variant does not compile until it is given a class and a code here, and the
//! `PyO3`, napi and `UniFFI` mappers cannot drift apart on it. Each bridge
//! turns a class into its own error type; only the routing of a
//! [`ContextErrorClass::PermissionDenied`] message by its embedded code prefix
//! is bridge-specific, because the bridges' exception hierarchies differ.

use scp_crypto::CustodyFailure;
use scp_protocol::context::{CeilingDeclaration, ContextError};

use crate::error_codes as codes;

/// The error class and code of one [`ContextError`] value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextErrorClass<'a> {
    /// A key custody failure; the bridge's `custody_failure` constructor picks
    /// its code ([`codes::custody_failure_code`]).
    Custody(&'a CustodyFailure),
    /// A context error with a dedicated code.
    Context(&'static str),
    /// A context error with no dedicated code: `SCP-CTX-2001`, which a bridge
    /// reports with a hint to check context state, membership and permissions.
    Generic,
    /// A rejected input value.
    Validation(&'static str),
    /// A cryptographic or key-custody precondition that failed.
    Crypto(&'static str),
    /// `ContextError::PermissionDenied`, whose message may embed an
    /// `SCP-PERM-`, `SCP-OUTLET-`, `SCP-ECON-` or `SCP-STORAGE-` code the
    /// bridge recovers and routes.
    PermissionDenied(&'a str),
    /// An outlet invocation error carrying its §5.4.4 code.
    Outlet(&'a str),
}

/// Classifies `e` (module doc).
#[must_use]
pub fn classify_context_error(e: &ContextError) -> ContextErrorClass<'_> {
    use ContextErrorClass as K;
    match e {
        ContextError::Custody(failure) => K::Custody(failure),
        ContextError::RateLimited { .. } => K::Context(codes::ECON_12090),
        ContextError::SnapshotFloorRegression { .. } => K::Context(codes::CTX_2091),
        ContextError::ImportRejected { .. } => K::Context(codes::CTX_2092),
        ContextError::SnapshotSignatureInvalid { .. } => K::Context(codes::CTX_2093),
        ContextError::ExportVersionUnsupported { .. } => K::Context(codes::CTX_2094),
        ContextError::PseudonymRegistryEmpty { .. } => K::Context(codes::CTX_2095),
        ContextError::NotPseudonymousContext { .. } => K::Context(codes::CTX_2096),
        // construction.md M2: no ceiling, or a null one, omits a required
        // field; an empty one is an invalid field value.
        ContextError::CeilingRequired(CeilingDeclaration::Absent | CeilingDeclaration::Null) => {
            K::Validation(codes::VALID_7004)
        }
        ContextError::CeilingRequired(CeilingDeclaration::Empty) => {
            K::Validation(codes::VALID_7005)
        }
        // §9.16.2 Open step 1: an invitation `enc` that is not a 65-byte
        // uncompressed P-256 point is an invalid field value.
        ContextError::InvitationEncMalformed(_) => K::Validation(codes::VALID_7005),
        ContextError::WrappingKeyCustodyUnavailable => K::Crypto(codes::CRYPTO_4063),
        ContextError::WrappingKeyHandleInvalid => K::Crypto(codes::CRYPTO_4064),
        ContextError::AttestationSignerActiveKeyUnresolved => K::Crypto(codes::CRYPTO_4065),
        ContextError::AttestationSignerNotActiveKey => K::Crypto(codes::CRYPTO_4066),
        // §9.7.1: a KeyPackage that fails validation or attestation, whatever
        // the reason, is one code in every binding.
        ContextError::InvalidKeyPackage(_) => K::Crypto(codes::CRYPTO_4067),
        ContextError::ActorBusy(_) => K::Context(codes::CTX_2130),
        ContextError::ContextPoisoned(_) => K::Context(codes::CTX_2134),
        ContextError::ActorCrashed(_) => K::Context(codes::CTX_2135),
        ContextError::KeyPackageReplay(_) => K::Context(codes::CTX_2136),
        ContextError::NothingToRestore(_) => K::Context(codes::CTX_2137),
        ContextError::SupervisorShutDown(_) => K::Context(codes::CTX_2138),
        ContextError::PermissionDenied(msg) => K::PermissionDenied(msg),
        ContextError::Outlet(surface) => K::Outlet(&surface.code),
        // The reserve-gate carrier renders no lifecycle state (it runs before
        // authorization), so it carries only the session code.
        ContextError::OutletContextNotActive { .. } => {
            K::Outlet(scp_protocol::context::outlets::error_codes::CODE_PROTOCOL_SESSION)
        }
        ContextError::InvalidTransition { .. }
        | ContextError::CeilingImmutable
        | ContextError::ContextNotActive
        | ContextError::ContextClosed
        | ContextError::ContextExpired
        | ContextError::TemplateMismatch(_)
        | ContextError::MembershipFailed(_)
        | ContextError::CryptoFailed(_)
        | ContextError::SenderMismatch { .. }
        | ContextError::TransportFailed(_)
        | ContextError::EventLogFailed(_)
        | ContextError::MemberNotFound(_)
        | ContextError::InvalidState(_)
        | ContextError::LimitExceeded(_)
        | ContextError::InvalidMemoryScopeForBroadcast
        | ContextError::IntegrationFailed(_)
        | ContextError::PersistenceFailed(_)
        | ContextError::GovernanceFailed(_)
        | ContextError::CreationFailed(_)
        | ContextError::ContextNotRegistered(_)
        | ContextError::VersionIncompatible { .. }
        | ContextError::CommitBroadcastFault { .. }
        | ContextError::NotImplemented(_)
        | ContextError::NotInitialized(_)
        | ContextError::NoParticipationFacts { .. }
        | ContextError::TransportTimeout(_) => K::Generic,
    }
}

#[cfg(test)]
mod tests {
    use super::{ContextErrorClass, classify_context_error};
    use crate::error_codes as codes;
    use scp_protocol::context::ContextError;

    #[test]
    fn the_wrapping_key_and_attestation_signer_failures_carry_their_own_crypto_codes() {
        let cases = [
            (
                ContextError::WrappingKeyCustodyUnavailable,
                codes::CRYPTO_4063,
            ),
            (ContextError::WrappingKeyHandleInvalid, codes::CRYPTO_4064),
            (
                ContextError::AttestationSignerActiveKeyUnresolved,
                codes::CRYPTO_4065,
            ),
            (
                ContextError::AttestationSignerNotActiveKey,
                codes::CRYPTO_4066,
            ),
        ];
        for (e, code) in &cases {
            assert_eq!(
                classify_context_error(e),
                ContextErrorClass::Crypto(code),
                "{e}"
            );
        }
    }

    #[test]
    fn a_malformed_invitation_enc_is_an_invalid_field_value() {
        assert_eq!(
            classify_context_error(&ContextError::InvitationEncMalformed("33 bytes".into())),
            ContextErrorClass::Validation(codes::VALID_7005)
        );
    }

    #[test]
    fn a_rejected_key_package_carries_its_own_crypto_code() {
        assert_eq!(
            classify_context_error(&ContextError::InvalidKeyPackage("x".into())),
            ContextErrorClass::Crypto(codes::CRYPTO_4067)
        );
    }

    #[test]
    fn a_variant_without_a_dedicated_code_is_generic() {
        assert_eq!(
            classify_context_error(&ContextError::MemberNotFound("x".into())),
            ContextErrorClass::Generic
        );
    }
}
