//! Reading a device attestation (`09-security-model.md` §9.3.1).
//!
//! This module holds the reader's public outcome types; in [`digest`], the
//! four digests §9.3.1 defines: the binding digest `D`, the tag `T`, the
//! assertion digest `A` and the policy digest `P`; the App Attest checks, the
//! Play Integrity checks and the `PlayIntegrityVerifier` entry parser, which
//! only the full reader calls, with a `D` it computed itself; and the owner's
//! re-encoding of an attestation object, [`canonicalize_app_attest_object`];
//! and the owner's pure producer half: the Play Integrity verdict request and
//! response, the assembled verdict, the owner's check before it publishes, the
//! two entries' `serviceEndpoint` strings and the renewal deadline.

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the SCP-316 reader (keri/p6-reader-scp-316) is the first caller outside the tests"
    )
)]
mod app_attest;
mod cbor;
pub mod digest;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the SCP-316 reader (keri/p6-reader-scp-316) is the first caller outside the tests"
    )
)]
mod play_integrity;
mod produce;
#[cfg(test)]
mod test_ca;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the SCP-316 reader (keri/p6-reader-scp-316) is the first caller outside the tests"
    )
)]
mod x509;

pub use cbor::{APP_ATTEST_FMT, AppAttestObjectError, canonicalize_app_attest_object};
pub use digest::{BindingDigest, device_attestation_binding_digest};
pub use play_integrity::VERDICT_LEN;
pub use produce::{
    AppAttestEntryError, AppAttestEntryInput, CheckedVerdict, MAX_VERDICT_REQUEST_LEN,
    MAX_VERDICT_RESPONSE_LEN, MAX_VERDICT_TOKEN_LEN, VERDICT_REFUSED_BODY, VerdictCheck,
    VerdictCheckInput, VerdictRequest, VerdictRequestError, VerdictRequestInput, VerdictResponse,
    VerdictResponseError, app_attest_entry_endpoint, assemble_verdict,
    check_play_integrity_verdict, play_integrity_entry_endpoint, renewal_deadline,
};

/// The most `ScpDeviceAttestation` entries one record may carry for one
/// context's tag (§9.18.17). A reader that finds more returns
/// `Rejected{TooManyEntries}`.
pub const MAX_DEVICE_ATTESTATIONS_PER_CHALLENGE: usize = 1;

/// The platform that minted a verified device attestation (§9.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeviceAttestationPlatform {
    /// Apple App Attest.
    AppAttest,
    /// Google Play Integrity, through a verifier the context names.
    PlayIntegrity,
}

/// A device attestation that passed every §9.3.1 check.
///
/// Only the reader builds one, so holding it means the checks ran. Its fields
/// are private, and the accessors read them.
///
/// ```compile_fail,E0451
/// # use scp_protocol::trust::device_attestation::{
/// #     DeviceAttestationPlatform, VerifiedDeviceAttestation,
/// # };
/// let forged = VerifiedDeviceAttestation {
///     platform: DeviceAttestationPlatform::AppAttest,
///     entry_id: String::new(),
///     credential: [0; 32],
///     minted_at: 0,
/// };
/// ```
///
/// The positive control: the type and its accessors are public, so the
/// struct literal above fails on field privacy alone.
///
/// ```
/// # use scp_protocol::trust::device_attestation::{
/// #     DeviceAttestationPlatform, VerifiedDeviceAttestation,
/// # };
/// fn read(v: &VerifiedDeviceAttestation) -> (DeviceAttestationPlatform, &str, [u8; 32], u64) {
///     (v.platform(), v.entry_id(), *v.credential(), v.minted_at())
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDeviceAttestation {
    platform: DeviceAttestationPlatform,
    entry_id: String,
    credential: [u8; 32],
    minted_at: u64,
}

impl VerifiedDeviceAttestation {
    /// Builds the outcome of a read whose every check passed. Only the
    /// platform readers in this module call it.
    const fn new(
        platform: DeviceAttestationPlatform,
        entry_id: String,
        credential: [u8; 32],
        minted_at: u64,
    ) -> Self {
        Self {
            platform,
            entry_id,
            credential,
            minted_at,
        }
    }

    /// The platform that minted the attestation.
    #[must_use]
    pub const fn platform(&self) -> DeviceAttestationPlatform {
        self.platform
    }

    /// The service-record entry's `id`.
    #[must_use]
    pub fn entry_id(&self) -> &str {
        &self.entry_id
    }

    /// For App Attest, the key ID: the SHA-256 of the attested credential
    /// public key. For Play Integrity, `SHA-256(token)`.
    #[must_use]
    pub const fn credential(&self) -> &[u8; 32] {
        &self.credential
    }

    /// For App Attest, the credential certificate's `notBefore`; for Play
    /// Integrity, the verdict's `token_issued_at`. Unix seconds.
    #[must_use]
    pub const fn minted_at(&self) -> u64 {
        self.minted_at
    }
}

/// Defines a §9.3.1 verdict-cause enum, its `ALL` list and its `as_str`
/// from one variant list, so no variant can exist outside `ALL` and every
/// `as_str` value is the variant's own name.
macro_rules! verdict_cause_enum {
    (
        $(#[$enum_meta:meta])*
        $name:ident {
            $( $(#[$variant_meta:meta])* $variant:ident, )+
        }
    ) => {
        $(#[$enum_meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name {
            $( $(#[$variant_meta])* $variant, )+
        }

        impl $name {
            /// Every value, in §9.3.1's order.
            pub const ALL: [Self; [$(stringify!($variant)),+].len()] = [$(Self::$variant),+];

            /// The value's §9.3.1 name.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => stringify!($variant),)+
                }
            }
        }
    };
}

verdict_cause_enum! {
    /// Why the context's entry failed a check the reader ran to completion
    /// (§9.3.1). Twenty-one values.
    DeviceAttestationRejection {
        /// The policy's challenge is 32 bytes of `0x00`.
        ContextChallengeUnset,
        /// The entry's `serviceEndpoint` is not the platform's field layout.
        MalformedEntry,
        /// The platform token does not decode.
        MalformedToken,
        /// App Attest `authData` is shorter than its fields require.
        AuthDataTruncated,
        /// App Attest `authData` names a credential ID that is not 32 bytes.
        CredentialIdLengthInvalid,
        /// The certificate chain does not verify to the pinned root.
        CertificateChainInvalid,
        /// The reader's time is past `minted_at` plus the policy's maximum age.
        Expired,
        /// The attestation's start time is later than the skew allows.
        NotYetValid,
        /// The App Attest nonce does not cover the binding digest.
        NonceMismatch,
        /// The credential ID differs from the credential key's digest.
        KeyIdMismatch,
        /// The App ID is not in the policy's accepted list.
        AppIdNotAccepted,
        /// The App Attest sign counter is not zero.
        CounterNotZero,
        /// The attestation comes from Apple's development environment.
        DevelopmentEnvironment,
        /// The credential certificate fits neither the iOS nor the macOS path.
        PlatformUnreported,
        /// An accepted App ID matches, but no matching element names the
        /// platform path the credential certificate took.
        PlatformMismatch,
        /// On the macOS path, the `aclBlob` extension is not the value §9.3.1
        /// fixes.
        AclBlobMismatch,
        /// The launch validation category is not accepted.
        ValidationCategoryNotAccepted,
        /// The bundle version is not accepted.
        BundleVersionNotAccepted,
        /// The Android package or its signing certificate is not accepted.
        PackageNotAccepted,
        /// The Play Integrity verdict's signature does not verify.
        VerdictSignatureInvalid,
        /// More than [`MAX_DEVICE_ATTESTATIONS_PER_CHALLENGE`] entries carry the
        /// context's tag.
        TooManyEntries,
    }
}

verdict_cause_enum! {
    /// Why the reader could not run a check to completion (§9.3.1). Five values.
    ///
    /// A reader never caches one of these outcomes, because each depends on a
    /// record or key state that can become reachable on a later read.
    DeviceAttestationUnverifiable {
        /// The service record read was `Rejected`, `Inconclusive`, or named
        /// another identifier.
        ServiceRecordUnavailable,
        /// The policy names no verifier for the entry's Android package.
        NoVerifierNamed,
        /// The Play Integrity entry carries no verdict.
        VerdictAbsent,
        /// The verdict names a verifier other than the one the policy names.
        VerdictFromUnnamedVerifier,
        /// The verifier's key state is unresolved or older than the freshness
        /// bound allows.
        VerifierKeyStateUnresolved,
    }
}

/// What a reader returns for one identifier and one context (§9.3.1).
/// `Verified` is the only outcome that yields a trust signal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceAttestationVerdict {
    /// The context's one entry passed every check.
    Verified {
        /// The checked attestation.
        attestation: VerifiedDeviceAttestation,
    },
    /// The service record was `Absent`, or it holds no entry whose tag equals
    /// the tag the reader computed.
    Absent,
    /// The context's entry failed a check the reader ran to completion.
    Rejected {
        /// The check that failed.
        cause: DeviceAttestationRejection,
    },
    /// The reader could not run a check to completion.
    Unverifiable {
        /// What the reader could not reach.
        cause: DeviceAttestationUnverifiable,
    },
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{
        DeviceAttestationRejection, DeviceAttestationUnverifiable,
        MAX_DEVICE_ATTESTATIONS_PER_CHALLENGE,
    };

    /// The §9.3.1 lists, in its order.
    const SPEC_REJECTIONS: [&str; 21] = [
        "ContextChallengeUnset",
        "MalformedEntry",
        "MalformedToken",
        "AuthDataTruncated",
        "CredentialIdLengthInvalid",
        "CertificateChainInvalid",
        "Expired",
        "NotYetValid",
        "NonceMismatch",
        "KeyIdMismatch",
        "AppIdNotAccepted",
        "CounterNotZero",
        "DevelopmentEnvironment",
        "PlatformUnreported",
        "PlatformMismatch",
        "AclBlobMismatch",
        "ValidationCategoryNotAccepted",
        "BundleVersionNotAccepted",
        "PackageNotAccepted",
        "VerdictSignatureInvalid",
        "TooManyEntries",
    ];
    const SPEC_UNVERIFIABLE: [&str; 5] = [
        "ServiceRecordUnavailable",
        "NoVerifierNamed",
        "VerdictAbsent",
        "VerdictFromUnnamedVerifier",
        "VerifierKeyStateUnresolved",
    ];

    /// Each enum holds exactly the §9.3.1 values: `ALL` lists each value once,
    /// in order, under its spec name and its `Debug` name.
    #[test]
    fn verdict_causes_match_spec_lists() {
        let rejections: Vec<&str> = DeviceAttestationRejection::ALL
            .iter()
            .map(|cause| cause.as_str())
            .collect();
        assert_eq!(rejections, SPEC_REJECTIONS);
        assert_eq!(
            DeviceAttestationRejection::ALL
                .iter()
                .collect::<HashSet<_>>()
                .len(),
            21
        );
        for cause in DeviceAttestationRejection::ALL {
            assert_eq!(format!("{cause:?}"), cause.as_str());
        }
        let unverifiable: Vec<&str> = DeviceAttestationUnverifiable::ALL
            .iter()
            .map(|cause| cause.as_str())
            .collect();
        assert_eq!(unverifiable, SPEC_UNVERIFIABLE);
        assert_eq!(
            DeviceAttestationUnverifiable::ALL
                .iter()
                .collect::<HashSet<_>>()
                .len(),
            5
        );
        for cause in DeviceAttestationUnverifiable::ALL {
            assert_eq!(format!("{cause:?}"), cause.as_str());
        }
    }

    /// §9.18.17 registers one entry per challenge.
    #[test]
    fn one_entry_per_challenge() {
        assert_eq!(MAX_DEVICE_ATTESTATIONS_PER_CHALLENGE, 1);
    }
}
