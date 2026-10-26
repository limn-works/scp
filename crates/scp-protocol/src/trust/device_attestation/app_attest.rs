//! The App Attest checks (`09-security-model.md` §9.3.1, "App Attest
//! checks" 1 through 12).
//!
//! [`read_app_attest`] runs every check on one attestation object against the
//! pinned Apple App Attestation Root CA and returns the verified attestation
//! or the first failing check's rejection. Procedure steps 1 through 5 (the
//! challenge, the service record, the tag and the entry fields) belong to the
//! full reader, which computes the binding digest `D` and calls this function.
//!
//! The checks run in [`APP_ATTEST_CHECKS`] order, one function per check, and
//! check 7's `aclBlob` comparison is its own entry so the record of checks
//! that ran shows whether it ran. Each check reads the decoded parts it needs
//! through a [`State`] accessor. When the check that produces a part is
//! missing from the array, the accessor decodes the part leniently instead,
//! and when even that fails it stops the run with [`Stop::Prerequisite`].
//! Production always runs the whole array, where each accessor's input has
//! already passed the strict check before it, so `Prerequisite` cannot occur
//! there; [`read_with_root`] still maps it to `MalformedToken`, failing
//! closed. Only the test harness runs a shortened array.

use scp_crypto::p256::P256PublicKey;
use scp_crypto::p384::P384PublicKey;
use sha2::{Digest, Sha256};

use super::cbor::{self, Value};
use super::x509::{self, SubjectKey, Tbs};
use super::{DeviceAttestationPlatform, DeviceAttestationRejection, VerifiedDeviceAttestation};
use crate::trust::sybil::{ApplePlatform, ValidatedSybilPolicy};

/// The clock skew §9.3.1 allows when it compares a platform time with the
/// reader's current time.
const CLOCK_SKEW_SECS: u64 = 300;

/// The DER bytes of Apple's App Attestation Root CA certificate, from
/// `scripts/apple-app-attestation-root-ca.pem`. Its SHA-256 is §25.35
/// Vector 88 of `25-test-vectors.md`.
const APPLE_ROOT_DER: [u8; 549] = [
    0x30, 0x82, 0x02, 0x21, 0x30, 0x82, 0x01, 0xa7, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10, 0x0b,
    0xf3, 0xbe, 0x0e, 0xf1, 0xcd, 0xd2, 0xe0, 0xfb, 0x8c, 0x6e, 0x72, 0x1f, 0x62, 0x17, 0x98, 0x30,
    0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03, 0x30, 0x52, 0x31, 0x26, 0x30,
    0x24, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x1d, 0x41, 0x70, 0x70, 0x6c, 0x65, 0x20, 0x41, 0x70,
    0x70, 0x20, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x52, 0x6f,
    0x6f, 0x74, 0x20, 0x43, 0x41, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0a,
    0x41, 0x70, 0x70, 0x6c, 0x65, 0x20, 0x49, 0x6e, 0x63, 0x2e, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03,
    0x55, 0x04, 0x08, 0x0c, 0x0a, 0x43, 0x61, 0x6c, 0x69, 0x66, 0x6f, 0x72, 0x6e, 0x69, 0x61, 0x30,
    0x1e, 0x17, 0x0d, 0x32, 0x30, 0x30, 0x33, 0x31, 0x38, 0x31, 0x38, 0x33, 0x32, 0x35, 0x33, 0x5a,
    0x17, 0x0d, 0x34, 0x35, 0x30, 0x33, 0x31, 0x35, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30,
    0x52, 0x31, 0x26, 0x30, 0x24, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x1d, 0x41, 0x70, 0x70, 0x6c,
    0x65, 0x20, 0x41, 0x70, 0x70, 0x20, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f,
    0x6e, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55,
    0x04, 0x0a, 0x0c, 0x0a, 0x41, 0x70, 0x70, 0x6c, 0x65, 0x20, 0x49, 0x6e, 0x63, 0x2e, 0x31, 0x13,
    0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a, 0x43, 0x61, 0x6c, 0x69, 0x66, 0x6f, 0x72,
    0x6e, 0x69, 0x61, 0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
    0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04, 0x45, 0x31, 0xe1, 0x98, 0xb5,
    0xb4, 0xec, 0x04, 0xda, 0x15, 0x02, 0x04, 0x57, 0x04, 0xed, 0x4f, 0x87, 0x72, 0x72, 0xd7, 0x61,
    0x35, 0xb2, 0x61, 0x16, 0xcf, 0xc8, 0x8b, 0x61, 0x5d, 0x0a, 0x00, 0x07, 0x19, 0xba, 0x69, 0x85,
    0x8d, 0xfe, 0x77, 0xca, 0xa3, 0xb8, 0x39, 0xe0, 0x20, 0xdd, 0xd6, 0x56, 0x14, 0x14, 0x04, 0x70,
    0x28, 0x31, 0xe4, 0x3f, 0x70, 0xb8, 0x8f, 0xd6, 0xc3, 0x94, 0xb6, 0x08, 0xea, 0x2b, 0xd6, 0xae,
    0x61, 0xe9, 0xf5, 0x98, 0xc1, 0x2f, 0x46, 0xaf, 0x52, 0x93, 0x72, 0x66, 0xe5, 0x7f, 0x14, 0xeb,
    0x61, 0xfe, 0xc5, 0x30, 0xf7, 0x14, 0x4f, 0x53, 0x81, 0x2e, 0x35, 0xa3, 0x42, 0x30, 0x40, 0x30,
    0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff,
    0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xac, 0x91, 0x10, 0x53, 0x33,
    0xbd, 0xbe, 0x68, 0x41, 0xff, 0xa7, 0x0c, 0xa9, 0xe5, 0xfa, 0xea, 0xe5, 0xe5, 0x8a, 0xa1, 0x30,
    0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x01, 0x06, 0x30,
    0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03, 0x03, 0x68, 0x00, 0x30, 0x65,
    0x02, 0x30, 0x42, 0x01, 0x46, 0x9c, 0x1c, 0xaf, 0xb2, 0x25, 0x5b, 0xa5, 0x32, 0xb0, 0x4a, 0x06,
    0xb4, 0x90, 0xfd, 0x1e, 0xf0, 0x47, 0x83, 0x4b, 0x8f, 0xac, 0x42, 0x64, 0xef, 0x6f, 0xbb, 0xe7,
    0xe7, 0x73, 0xb9, 0xf8, 0x54, 0x57, 0x81, 0xe2, 0xe1, 0xa4, 0x9d, 0x3a, 0xca, 0xc0, 0xb9, 0x3e,
    0xb3, 0xb2, 0x02, 0x31, 0x00, 0xa7, 0x95, 0x38, 0xc4, 0x38, 0x04, 0x82, 0x59, 0x45, 0xec, 0x49,
    0xf7, 0x55, 0xc1, 0x37, 0x89, 0xec, 0x59, 0x66, 0xd2, 0x9e, 0x62, 0x7a, 0x6a, 0xb6, 0x28, 0xd5,
    0xa3, 0x21, 0x6b, 0x69, 0x65, 0x48, 0xc9, 0xdf, 0xdd, 0x81, 0xa9, 0xe6, 0xad, 0xdb, 0x82, 0xd5,
    0xb9, 0x93, 0x04, 0x6c, 0x03,
];

/// The `aclBlob` §9.3.1 check 7 requires on the macOS path: the 66 bytes
/// whose base64 is
/// `MEAMAjExMDowCQwCb2uhAwEB/zAJDAJvYaEDAQH/MAsMBG9kZWyhAwEB/zAVDARvc2duoAYMBHJzZWMwBaYDAgEB`.
pub(super) const MACOS_ACL_BLOB: [u8; 66] = [
    0x30, 0x40, 0x0c, 0x02, 0x31, 0x31, 0x30, 0x3a, 0x30, 0x09, 0x0c, 0x02, 0x6f, 0x6b, 0xa1, 0x03,
    0x01, 0x01, 0xff, 0x30, 0x09, 0x0c, 0x02, 0x6f, 0x61, 0xa1, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0b,
    0x0c, 0x04, 0x6f, 0x64, 0x65, 0x6c, 0xa1, 0x03, 0x01, 0x01, 0xff, 0x30, 0x15, 0x0c, 0x04, 0x6f,
    0x73, 0x67, 0x6e, 0xa0, 0x06, 0x0c, 0x04, 0x72, 0x73, 0x65, 0x63, 0x30, 0x05, 0xa6, 0x03, 0x02,
    0x01, 0x01,
];

/// The AAGUID of Apple's production environment: `"appattest"` and seven
/// `0x00` bytes.
const AAGUID_PRODUCTION: [u8; 16] = *b"appattest\0\0\0\0\0\0\0";
/// The AAGUID of Apple's development environment.
const AAGUID_DEVELOPMENT: [u8; 16] = *b"appattestdevelop";

/// The `authData` extensions key check 11 reads.
const VALIDATION_CATEGORY_KEY: &str = "apple_validation_category_01";
/// The `authData` extensions key check 12 reads.
const BUNDLE_VERSION_KEY: &str = "apple_bundle_version_01";
/// Launch validation categories a reader rejects whatever the policy says:
/// Apple's table calls 0 invalid and 7, 8 and 9 inappropriate.
const ALWAYS_REJECTED_CATEGORIES: [u32; 4] = [0, 7, 8, 9];
/// The category an empty `accepted_validation_categories` accepts, which
/// Apple's table names the App Store.
const DEFAULT_ACCEPTED_CATEGORY: u32 = 4;

/// The `authData` offsets of check 2.
const RP_ID_HASH_END: usize = 32;
const COUNTER_START: usize = 33;
const AAGUID_START: usize = 37;
const CREDENTIAL_ID_LENGTH_START: usize = 53;
const CREDENTIAL_ID_START: usize = 55;
/// The only credential ID length check 2 accepts.
const CREDENTIAL_ID_LEN: usize = 32;

/// The trust anchor a chain must verify to. Production reads only
/// [`APPLE_APP_ATTESTATION_ROOT`]; the field is private, so no other module
/// builds one outside test code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct AppAttestRoot<'a> {
    der: &'a [u8],
}

impl<'a> AppAttestRoot<'a> {
    /// The root certificate's DER bytes.
    pub(super) const fn der(&self) -> &'a [u8] {
        self.der
    }

    /// A root built from a test certificate authority's DER.
    #[cfg(test)]
    pub(super) const fn from_test_der(der: &'a [u8]) -> Self {
        Self { der }
    }
}

/// Apple's App Attestation Root CA, the one anchor production chains verify
/// to.
pub(super) const APPLE_APP_ATTESTATION_ROOT: AppAttestRoot<'static> = AppAttestRoot {
    der: &APPLE_ROOT_DER,
};

/// The inputs of one App Attest read.
#[derive(Debug, Clone, Copy)]
pub struct AppAttestRead<'a> {
    /// The attestation object, decoded from the entry's base64url field.
    pub attestation_object: &'a [u8],
    /// The binding digest `D` the full reader computed for the identifier,
    /// the context id and the context's challenge.
    pub binding_digest: [u8; 32],
    /// The context's validated Sybil policy.
    pub policy: ValidatedSybilPolicy<'a>,
    /// The reader's current time, Unix seconds.
    pub now_secs: u64,
    /// The service-record entry's `id`, which a `Verified` outcome carries.
    pub entry_id: &'a str,
}

/// Runs App Attest checks 1 through 12 against the pinned Apple root.
///
/// # Errors
///
/// The first failing check's [`DeviceAttestationRejection`].
pub fn read_app_attest(
    read: &AppAttestRead<'_>,
) -> Result<VerifiedDeviceAttestation, DeviceAttestationRejection> {
    read_with_root(&APPLE_APP_ATTESTATION_ROOT, read)
}

/// Runs every check against `root`. Production reaches this only through
/// [`read_app_attest`], with the pinned root.
pub(super) fn read_with_root(
    root: &AppAttestRoot<'_>,
    read: &AppAttestRead<'_>,
) -> Result<VerifiedDeviceAttestation, DeviceAttestationRejection> {
    run(root, read, &APP_ATTEST_CHECKS)
        .result
        .map_err(|stop| match stop {
            Stop::Reject(cause) => cause,
            // Unreachable with the full array (see the module documentation);
            // an input the checks could not take apart is malformed.
            Stop::Prerequisite(_) => DeviceAttestationRejection::MalformedToken,
        })
}

/// One App Attest check, in §9.3.1 order. Check 7 is two entries: the path
/// choice and, on the macOS path only, the `aclBlob` comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum AppAttestCheck {
    /// Check 1: the object's keys, types and canonical encoding.
    ObjectEncoding,
    /// Check 2: the `authData` layout, COSE key and extensions.
    AuthData,
    /// Check 3: the certificate chain.
    CertificateChain,
    /// Check 4: the maximum age.
    MaxAge,
    /// Check 5: the nonce.
    Nonce,
    /// Check 6: the key ID.
    KeyId,
    /// Check 7: the platform path.
    PlatformPath,
    /// Check 7, macOS path: the `aclBlob`.
    AclBlob,
    /// Check 8: the App ID and its platform.
    AppId,
    /// Check 9: the counter.
    Counter,
    /// Check 10: the AAGUID.
    Aaguid,
    /// Check 11: the launch validation category.
    ValidationCategory,
    /// Check 12: the bundle version.
    BundleVersion,
}

impl AppAttestCheck {
    /// Every check, in run order.
    #[cfg(test)]
    pub(super) const ALL: [Self; 13] = [
        Self::ObjectEncoding,
        Self::AuthData,
        Self::CertificateChain,
        Self::MaxAge,
        Self::Nonce,
        Self::KeyId,
        Self::PlatformPath,
        Self::AclBlob,
        Self::AppId,
        Self::Counter,
        Self::Aaguid,
        Self::ValidationCategory,
        Self::BundleVersion,
    ];
}

/// Whether a check applied to the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Ran {
    /// The check ran and passed.
    Yes,
    /// The check does not apply to this input (the `aclBlob` comparison on
    /// the iOS path).
    NotApplicable,
}

/// Why a run stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Stop {
    /// A check failed with this rejection.
    Reject(DeviceAttestationRejection),
    /// A check needed a part that the named check produces, that check was
    /// not in the array, and the part could not be decoded leniently.
    Prerequisite(AppAttestCheck),
}

/// The signature of one check.
pub(super) type CheckFn = fn(&mut State<'_>) -> Result<Ran, Stop>;

/// Every App Attest check, in §9.3.1 order.
pub(super) const APP_ATTEST_CHECKS: [(AppAttestCheck, CheckFn); 13] = [
    (AppAttestCheck::ObjectEncoding, check_object_encoding),
    (AppAttestCheck::AuthData, check_auth_data),
    (AppAttestCheck::CertificateChain, check_certificate_chain),
    (AppAttestCheck::MaxAge, check_max_age),
    (AppAttestCheck::Nonce, check_nonce),
    (AppAttestCheck::KeyId, check_key_id),
    (AppAttestCheck::PlatformPath, check_platform_path),
    (AppAttestCheck::AclBlob, check_acl_blob),
    (AppAttestCheck::AppId, check_app_id),
    (AppAttestCheck::Counter, check_counter),
    (AppAttestCheck::Aaguid, check_aaguid),
    (
        AppAttestCheck::ValidationCategory,
        check_validation_category,
    ),
    (AppAttestCheck::BundleVersion, check_bundle_version),
];

/// The outcome of a run and the checks that ran, in order. A check that
/// stopped the run is recorded; a check that did not apply is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Run {
    /// The verified attestation, or why the run stopped.
    pub(super) result: Result<VerifiedDeviceAttestation, Stop>,
    /// The checks that ran.
    pub(super) ran: Vec<AppAttestCheck>,
}

/// Runs `checks` in order on one read.
pub(super) fn run(
    root: &AppAttestRoot<'_>,
    read: &AppAttestRead<'_>,
    checks: &[(AppAttestCheck, CheckFn)],
) -> Run {
    let mut state = State {
        root_der: root.der(),
        read: *read,
        object: None,
        auth_data: None,
        chain: None,
        path: Path::Unread,
    };
    let mut ran = Vec::with_capacity(checks.len());
    for (id, check) in checks {
        match check(&mut state) {
            Ok(Ran::Yes) => ran.push(*id),
            Ok(Ran::NotApplicable) => {}
            Err(stop) => {
                ran.push(*id);
                return Run {
                    result: Err(stop),
                    ran,
                };
            }
        }
    }
    Run {
        result: state.verified(),
        ran,
    }
}

/// The attestation object's parts check 1 admits.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Object {
    auth_data: Vec<u8>,
    leaf: Vec<u8>,
    intermediate: Vec<u8>,
}

/// The `authData` fields check 2 defines.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthData {
    rp_id_hash: [u8; 32],
    counter: u32,
    aaguid: [u8; 16],
    credential_id: Vec<u8>,
    /// The extensions map's pairs, `None` when `authData` carries none.
    extensions: Option<Vec<(Value, Value)>>,
}

/// The three parsed `tbsCertificate`s.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Chain {
    root: Tbs,
    intermediate: Tbs,
    leaf: Tbs,
}

/// The parts of one read the checks decode, each decoded once.
pub(super) struct State<'a> {
    root_der: &'a [u8],
    read: AppAttestRead<'a>,
    object: Option<Object>,
    auth_data: Option<AuthData>,
    chain: Option<Chain>,
    path: Path,
}

/// Check 7's path, once chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Path {
    Unread,
    Fits(ApplePlatform),
    FitsNeither,
}

impl State<'_> {
    const fn policy(&self) -> &crate::trust::sybil::ContextSybilPolicy {
        self.read.policy.policy()
    }

    fn object(&mut self) -> Result<&Object, Stop> {
        if self.object.is_none() {
            self.object = Some(
                lenient_object(self.read.attestation_object)
                    .ok_or(Stop::Prerequisite(AppAttestCheck::ObjectEncoding))?,
            );
        }
        self.object
            .as_ref()
            .ok_or(Stop::Prerequisite(AppAttestCheck::ObjectEncoding))
    }

    fn auth_data(&mut self) -> Result<&AuthData, Stop> {
        if self.auth_data.is_none() {
            let raw = self.object()?.auth_data.clone();
            self.auth_data =
                Some(lenient_auth_data(&raw).ok_or(Stop::Prerequisite(AppAttestCheck::AuthData))?);
        }
        self.auth_data
            .as_ref()
            .ok_or(Stop::Prerequisite(AppAttestCheck::AuthData))
    }

    fn chain(&mut self) -> Result<&Chain, Stop> {
        if self.chain.is_none() {
            let root_der = self.root_der;
            let object = self.object()?;
            let parse = |der: &[u8]| {
                x509::split_certificate(der).and_then(|parts| x509::parse_tbs(parts.tbs))
            };
            let chain = parse(root_der).and_then(|root| {
                Ok(Chain {
                    root,
                    intermediate: parse(&object.intermediate)?,
                    leaf: parse(&object.leaf)?,
                })
            });
            self.chain =
                Some(chain.map_err(|_| Stop::Prerequisite(AppAttestCheck::CertificateChain))?);
        }
        self.chain
            .as_ref()
            .ok_or(Stop::Prerequisite(AppAttestCheck::CertificateChain))
    }

    /// The leaf's 65-byte P-256 point.
    fn leaf_point(&mut self) -> Result<[u8; 65], Stop> {
        match &self.chain()?.leaf.key {
            SubjectKey::P256(point) => Ok(*point),
            SubjectKey::P384(_) | SubjectKey::Other => {
                Err(Stop::Prerequisite(AppAttestCheck::CertificateChain))
            }
        }
    }

    fn path(&mut self) -> Result<Option<ApplePlatform>, Stop> {
        match self.path {
            Path::Fits(platform) => return Ok(Some(platform)),
            Path::FitsNeither => return Ok(None),
            Path::Unread => {}
        }
        let path = choose_platform_path(&self.chain()?.leaf);
        self.path = path.map_or(Path::FitsNeither, Path::Fits);
        Ok(path)
    }

    /// The path, for a check after check 7.
    fn chosen_path(&mut self) -> Result<ApplePlatform, Stop> {
        self.path()?
            .ok_or(Stop::Prerequisite(AppAttestCheck::PlatformPath))
    }

    /// Check 8's selection: the index of the `AcceptedAppId` whose `app_id`
    /// hashes to the `rpIdHash` and whose platform is the path.
    fn select_app_id(&mut self) -> Result<Result<usize, DeviceAttestationRejection>, Stop> {
        let rp_id_hash = self.auth_data()?.rp_id_hash;
        let path = self.chosen_path()?;
        let mut hash_matched = false;
        for (index, accepted) in self.policy().accepted_app_ids.iter().enumerate() {
            if Sha256::digest(accepted.app_id.as_bytes()).as_slice() == rp_id_hash {
                hash_matched = true;
                if accepted.platform == path {
                    return Ok(Ok(index));
                }
            }
        }
        Ok(Err(if hash_matched {
            DeviceAttestationRejection::PlatformMismatch
        } else {
            DeviceAttestationRejection::AppIdNotAccepted
        }))
    }

    /// The value one `authData` extensions key maps to.
    fn extension(&mut self, key: &str) -> Result<Option<Value>, Stop> {
        let Some(pairs) = &self.auth_data()?.extensions else {
            return Ok(None);
        };
        cbor::lookup(pairs, key)
            .map(Option::<&Value>::cloned)
            .map_err(|_| reject(DeviceAttestationRejection::MalformedToken))
    }

    fn verified(&mut self) -> Result<VerifiedDeviceAttestation, Stop> {
        let point = self.leaf_point()?;
        let minted_at = self.chain()?.leaf.not_before;
        Ok(VerifiedDeviceAttestation::new(
            DeviceAttestationPlatform::AppAttest,
            self.read.entry_id.to_owned(),
            Sha256::digest(point).into(),
            minted_at,
        ))
    }
}

const fn reject(cause: DeviceAttestationRejection) -> Stop {
    Stop::Reject(cause)
}

/// Takes the parts apart without the check 1 rules: the first `authData`,
/// the first `attStmt` and its first `x5c`, with tags removed, and the first
/// two `x5c` elements. Only a run without check 1 relies on this.
fn lenient_object(input: &[u8]) -> Option<Object> {
    fn untag(value: &Value) -> &Value {
        match value {
            Value::Tag(_, inner) => untag(inner),
            other => other,
        }
    }
    fn first<'v>(pairs: &'v [(Value, Value)], key: &str) -> Option<&'v Value> {
        pairs
            .iter()
            .find(|(candidate, _)| matches!(untag(candidate), Value::Text(text) if text == key))
            .map(|(_, value)| untag(value))
    }
    let (value, _) = cbor::decode_prefix(input).ok()?;
    let Value::Map(pairs) = untag(&value) else {
        return None;
    };
    let Value::Bytes(auth_data) = first(pairs, "authData")? else {
        return None;
    };
    let Value::Map(statement) = first(pairs, "attStmt")? else {
        return None;
    };
    let Value::Array(x5c) = first(statement, "x5c")? else {
        return None;
    };
    let (Some(Value::Bytes(leaf)), Some(Value::Bytes(intermediate))) =
        (x5c.first().map(untag), x5c.get(1).map(untag))
    else {
        return None;
    };
    Some(Object {
        auth_data: auth_data.clone(),
        leaf: leaf.clone(),
        intermediate: intermediate.clone(),
    })
}

/// The fixed `authData` fields, and the credential ID of the stated length.
/// `None` when `authData` is too short for them.
fn auth_data_fields(raw: &[u8]) -> Option<(AuthData, usize)> {
    let rp_id_hash: [u8; 32] = raw.get(..RP_ID_HASH_END)?.try_into().ok()?;
    let counter: [u8; 4] = raw.get(COUNTER_START..AAGUID_START)?.try_into().ok()?;
    let aaguid: [u8; 16] = raw
        .get(AAGUID_START..CREDENTIAL_ID_LENGTH_START)?
        .try_into()
        .ok()?;
    let length: [u8; 2] = raw
        .get(CREDENTIAL_ID_LENGTH_START..CREDENTIAL_ID_START)?
        .try_into()
        .ok()?;
    let length = usize::from(u16::from_be_bytes(length));
    let credential_end = CREDENTIAL_ID_START.checked_add(length)?;
    let credential_id = raw.get(CREDENTIAL_ID_START..credential_end)?.to_vec();
    Some((
        AuthData {
            rp_id_hash,
            counter: u32::from_be_bytes(counter),
            aaguid,
            credential_id,
            extensions: None,
        },
        credential_end,
    ))
}

/// `authData` read without the check 2 rules: any credential ID length, and
/// extensions taken only when they decode. Only a run without check 2 relies
/// on this.
fn lenient_auth_data(raw: &[u8]) -> Option<AuthData> {
    let (mut fields, credential_end) = auth_data_fields(raw)?;
    let after_credential = raw.get(credential_end..)?;
    if let Ok((_, cose_len)) = cbor::decode_prefix(after_credential)
        && let Some(Ok(Value::Map(pairs))) = after_credential
            .get(cose_len..)
            .filter(|rest| !rest.is_empty())
            .map(cbor::decode_exact)
    {
        fields.extensions = Some(pairs);
    }
    Some(fields)
}

/// Check 2 on `authData`.
fn parse_auth_data(raw: &[u8]) -> Result<AuthData, DeviceAttestationRejection> {
    if raw.len() < CREDENTIAL_ID_START {
        return Err(DeviceAttestationRejection::AuthDataTruncated);
    }
    let length = raw
        .get(CREDENTIAL_ID_LENGTH_START..CREDENTIAL_ID_START)
        .map(|bytes| {
            bytes
                .iter()
                .fold(0usize, |acc, b| (acc << 8) | usize::from(*b))
        });
    if length != Some(CREDENTIAL_ID_LEN) {
        return Err(DeviceAttestationRejection::CredentialIdLengthInvalid);
    }
    let (mut fields, credential_end) =
        auth_data_fields(raw).ok_or(DeviceAttestationRejection::AuthDataTruncated)?;
    let after_credential = raw
        .get(credential_end..)
        .ok_or(DeviceAttestationRejection::AuthDataTruncated)?;
    let (cose_key, cose_len) = cbor::decode_prefix(after_credential)
        .map_err(|_| DeviceAttestationRejection::MalformedToken)?;
    if !matches!(cose_key, Value::Map(_)) {
        return Err(DeviceAttestationRejection::MalformedToken);
    }
    let extensions = after_credential
        .get(cose_len..)
        .ok_or(DeviceAttestationRejection::MalformedToken)?;
    if !extensions.is_empty() {
        // RFC 8949 §5.6: a map with a repeated key is not valid, so the
        // extensions must decode to a map whose keys all differ. Its encoding
        // need not be canonical ("Canonical encodings" exempts it).
        let Ok(Value::Map(pairs)) = cbor::decode_exact(extensions) else {
            return Err(DeviceAttestationRejection::MalformedToken);
        };
        let mut keys = Vec::with_capacity(pairs.len());
        for (key, _) in &pairs {
            let mut encoded = Vec::new();
            cbor::encode_canonical(key, &mut encoded)
                .map_err(|_| DeviceAttestationRejection::MalformedToken)?;
            if keys.contains(&encoded) {
                return Err(DeviceAttestationRejection::MalformedToken);
            }
            keys.push(encoded);
        }
        fields.extensions = Some(pairs);
    }
    Ok(fields)
}

/// Check 3 on the three certificates: each equals its rebuild, the root and
/// the intermediate hold P-384 keys and the leaf a P-256 key, each signature
/// uses an accepted algorithm and verifies, each certificate is valid at the
/// leaf's `notBefore`, and that `notBefore` is no later than `now_secs` plus
/// the skew.
pub(super) fn verify_chain(
    root_der: &[u8],
    intermediate_der: &[u8],
    leaf_der: &[u8],
    now_secs: u64,
) -> Result<(), x509::CertificateMalformed> {
    use x509::CertificateMalformed as Bad;

    let root = x509::parse_tbs(x509::split_certificate(root_der)?.tbs)?;
    let intermediate_parts = x509::split_certificate(intermediate_der)?;
    let intermediate = x509::parse_tbs(intermediate_parts.tbs)?;
    let leaf_parts = x509::split_certificate(leaf_der)?;
    let leaf = x509::parse_tbs(leaf_parts.tbs)?;

    if !x509::rebuild_matches(
        intermediate_der,
        &intermediate_parts,
        &intermediate.signature_algorithm_tlv,
    ) {
        return Err(Bad("intermediate differs from its rebuild"));
    }
    if !x509::rebuild_matches(leaf_der, &leaf_parts, &leaf.signature_algorithm_tlv) {
        return Err(Bad("leaf differs from its rebuild"));
    }

    let p384 = |key: &SubjectKey| match key {
        SubjectKey::P384(point) => {
            P384PublicKey::from_sec1(point).map_err(|_| Bad("P-384 point invalid"))
        }
        SubjectKey::P256(_) | SubjectKey::Other => Err(Bad("issuer key is not P-384")),
    };
    let root_key = p384(&root.key)?;
    let intermediate_key = p384(&intermediate.key)?;
    match &leaf.key {
        SubjectKey::P256(point) => {
            P256PublicKey::from_uncompressed(point).map_err(|_| Bad("P-256 point invalid"))?;
        }
        SubjectKey::P384(_) | SubjectKey::Other => return Err(Bad("leaf key is not P-256")),
    }

    if !x509::verify_signature(
        &root_key,
        intermediate.signature_algorithm,
        &intermediate_parts,
    ) {
        return Err(Bad("intermediate signature does not verify"));
    }
    if !x509::verify_signature(&intermediate_key, leaf.signature_algorithm, &leaf_parts) {
        return Err(Bad("leaf signature does not verify"));
    }

    let minted_at = leaf.not_before;
    for certificate in [&root, &intermediate, &leaf] {
        if minted_at < certificate.not_before || minted_at > certificate.not_after {
            return Err(Bad("certificate not valid at the leaf's notBefore"));
        }
    }
    if minted_at > now_secs.saturating_add(CLOCK_SKEW_SECS) {
        return Err(Bad("leaf notBefore is later than the skew allows"));
    }
    Ok(())
}

/// Check 7's path choice on the credential certificate. `None` when the
/// certificate fits neither path: extension 8.7's `[1026]` element names a
/// system other than `macosx` or `iphoneos`, or extension 8.7 is not a
/// `SEQUENCE` of context-tagged elements, and extension 8.6 is absent.
pub(super) fn choose_platform_path(leaf: &Tbs) -> Option<ApplePlatform> {
    if leaf.extension(x509::OID_APPLE_ACL_BLOB).is_some() {
        return Some(ApplePlatform::MacOs);
    }
    let system = match leaf.extension(x509::OID_APPLE_PLATFORM) {
        None => None,
        Some(value) => x509::platform_system_name(value).ok()?,
    };
    match system.as_deref() {
        Some(b"macosx") => Some(ApplePlatform::MacOs),
        None | Some(b"iphoneos") => Some(ApplePlatform::Ios),
        Some(_) => None,
    }
}

fn check_object_encoding(state: &mut State<'_>) -> Result<Ran, Stop> {
    let input = state.read.attestation_object;
    let canonical = cbor::decode_exact(input)
        .ok()
        .filter(cbor::is_app_attest_object_shape)
        .and_then(|value| {
            let mut out = Vec::with_capacity(input.len());
            cbor::encode_canonical(&value, &mut out).ok().map(|()| out)
        });
    if canonical.as_deref() != Some(input) {
        return Err(reject(DeviceAttestationRejection::MalformedToken));
    }
    state.object()?;
    Ok(Ran::Yes)
}

fn check_auth_data(state: &mut State<'_>) -> Result<Ran, Stop> {
    let parsed = parse_auth_data(&state.object()?.auth_data).map_err(reject)?;
    state.auth_data = Some(parsed);
    Ok(Ran::Yes)
}

fn check_certificate_chain(state: &mut State<'_>) -> Result<Ran, Stop> {
    let now_secs = state.read.now_secs;
    let root_der = state.root_der;
    let object = state.object()?;
    verify_chain(root_der, &object.intermediate, &object.leaf, now_secs)
        .map_err(|_| reject(DeviceAttestationRejection::CertificateChainInvalid))?;
    state.chain()?;
    Ok(Ran::Yes)
}

fn check_max_age(state: &mut State<'_>) -> Result<Ran, Stop> {
    let not_before = state.chain()?.leaf.not_before;
    if state.read.now_secs > state.read.policy.device_attestation_expiry(not_before) {
        return Err(reject(DeviceAttestationRejection::Expired));
    }
    Ok(Ran::Yes)
}

fn check_nonce(state: &mut State<'_>) -> Result<Ran, Stop> {
    let binding_digest = state.read.binding_digest;
    let mut hasher = Sha256::new();
    hasher.update(&state.object()?.auth_data);
    hasher.update(binding_digest);
    let nonce = hasher.finalize();
    let extension = state
        .chain()?
        .leaf
        .extension(x509::OID_APPLE_NONCE)
        .ok_or(reject(DeviceAttestationRejection::MalformedToken))?;
    let carried = x509::explicit_octet_string_in_sequence(extension, 1)
        .ok()
        .filter(|octets| octets.len() == 32)
        .ok_or(reject(DeviceAttestationRejection::MalformedToken))?;
    if carried.as_slice() != nonce.as_slice() {
        return Err(reject(DeviceAttestationRejection::NonceMismatch));
    }
    Ok(Ran::Yes)
}

fn check_key_id(state: &mut State<'_>) -> Result<Ran, Stop> {
    let key_id = Sha256::digest(state.leaf_point()?);
    if state.auth_data()?.credential_id.as_slice() != key_id.as_slice() {
        return Err(reject(DeviceAttestationRejection::KeyIdMismatch));
    }
    Ok(Ran::Yes)
}

fn check_platform_path(state: &mut State<'_>) -> Result<Ran, Stop> {
    state
        .path()?
        .ok_or(reject(DeviceAttestationRejection::PlatformUnreported))?;
    Ok(Ran::Yes)
}

fn check_acl_blob(state: &mut State<'_>) -> Result<Ran, Stop> {
    if state.chosen_path()? == ApplePlatform::Ios {
        return Ok(Ran::NotApplicable);
    }
    let matches = state
        .chain()?
        .leaf
        .extension(x509::OID_APPLE_ACL_BLOB)
        .and_then(|value| x509::explicit_octet_string_in_sequence(value, 3).ok())
        .is_some_and(|blob| blob == MACOS_ACL_BLOB);
    if !matches {
        return Err(reject(DeviceAttestationRejection::AclBlobMismatch));
    }
    Ok(Ran::Yes)
}

fn check_app_id(state: &mut State<'_>) -> Result<Ran, Stop> {
    state.select_app_id()?.map_err(reject)?;
    Ok(Ran::Yes)
}

fn check_counter(state: &mut State<'_>) -> Result<Ran, Stop> {
    if state.auth_data()?.counter != 0 {
        return Err(reject(DeviceAttestationRejection::CounterNotZero));
    }
    Ok(Ran::Yes)
}

fn check_aaguid(state: &mut State<'_>) -> Result<Ran, Stop> {
    match state.auth_data()?.aaguid {
        AAGUID_PRODUCTION => Ok(Ran::Yes),
        AAGUID_DEVELOPMENT => Err(reject(DeviceAttestationRejection::DevelopmentEnvironment)),
        _ => Err(reject(DeviceAttestationRejection::MalformedToken)),
    }
}

fn check_validation_category(state: &mut State<'_>) -> Result<Ran, Stop> {
    let not_accepted = reject(DeviceAttestationRejection::ValidationCategoryNotAccepted);
    let category = match state.extension(VALIDATION_CATEGORY_KEY)? {
        Some(Value::Bytes(bytes)) => {
            let bytes: [u8; 4] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| reject(DeviceAttestationRejection::MalformedToken))?;
            u32::from_le_bytes(bytes)
        }
        Some(_) => return Err(reject(DeviceAttestationRejection::MalformedToken)),
        None => {
            let path = state.chosen_path()?;
            if path == ApplePlatform::MacOs || state.policy().require_validation_category {
                return Err(not_accepted);
            }
            return Ok(Ran::Yes);
        }
    };
    let accepted = &state.policy().accepted_validation_categories;
    let allowed = if accepted.is_empty() {
        category == DEFAULT_ACCEPTED_CATEGORY
    } else {
        accepted.contains(&category)
    };
    if ALWAYS_REJECTED_CATEGORIES.contains(&category) || !allowed {
        return Err(not_accepted);
    }
    Ok(Ran::Yes)
}

fn check_bundle_version(state: &mut State<'_>) -> Result<Ran, Stop> {
    let version = match state.extension(BUNDLE_VERSION_KEY)? {
        Some(Value::Text(text)) => Some(text),
        Some(_) => return Err(reject(DeviceAttestationRejection::MalformedToken)),
        None => None,
    };
    let index = state
        .select_app_id()?
        .map_err(|_| Stop::Prerequisite(AppAttestCheck::AppId))?;
    let accepted = state
        .policy()
        .accepted_app_ids
        .get(index)
        .map(|app| app.accepted_bundle_versions.as_slice())
        .ok_or(Stop::Prerequisite(AppAttestCheck::AppId))?;
    if accepted.is_empty() {
        return Ok(Ran::Yes);
    }
    match version {
        Some(version) if accepted.contains(&version) => Ok(Ran::Yes),
        _ => Err(reject(DeviceAttestationRejection::BundleVersionNotAccepted)),
    }
}

#[cfg(test)]
mod tests;
