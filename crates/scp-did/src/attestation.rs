//! Key custody attestation for DID document service entries (ADR-039 Layer 4).
//!
//! At identity creation, the DID document includes a service entry declaring
//! the key custody model for each verification method. This provides a
//! verifiable signal about how signing keys are stored and protected.
//!
//! Absence of attestation is a valid state — it is itself a signal ("I cannot
//! prove my keys are isolated"). The attestation is signed by `#0` (Identity
//! Key) as part of the DID document publication.
//!
//! # Service Entry Format
//!
//! The attestation is published as a DID document service with:
//! - `type`: `"ScpKeyCustodyAttestation"`
//! - `serviceEndpoint`: JSON-encoded attestation data
//!
//! # Platform Attestation
//!
//! Optional platform-specific proof bytes (Apple App Attest / Android Key
//! Attestation) can accompany the custody model declaration. These proofs are
//! opaque to the protocol — verification is platform-specific.
//!
//! See ADR-039 §Enforcement Stack Layer 4 in `.docs/adrs/phase-1.md`.

use std::fmt;
use std::str::FromStr;

use crate::document::{DidError, Service};
use serde::{Deserialize, Serialize};

/// The service type string for custody attestation entries.
const CUSTODY_ATTESTATION_SERVICE_TYPE: &str = "ScpKeyCustodyAttestation";

/// Key custody model attestation published in DID document service entries.
///
/// Declares how signing keys are stored and protected. Published as a service
/// entry in the DID document, signed by `#0` as part of document publication.
///
/// See ADR-039 acceptance criterion 16.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScpKeyCustodyAttestation {
    /// Custody model for the `#active` key.
    pub active_key_custody: KeyCustodyModel,

    /// Custody model for the `#agent` key. `None` if no agent key exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_key_custody: Option<KeyCustodyModel>,

    /// The platform where this identity was created.
    pub platform: Platform,

    /// Optional platform attestation proof (Apple App Attest / Android Key
    /// Attestation). Opaque to the protocol — verification is platform-specific.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform_attestation: Option<PlatformAttestation>,

    /// Unix timestamp (seconds) when this attestation was created.
    pub created_at: u64,
}

/// The platform where this identity was created.
///
/// Used in custody attestation to indicate the runtime environment, which
/// affects what key custody models are available (e.g., hardware-biometric
/// requires iOS or Android).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Platform {
    /// Apple iOS (Secure Enclave available).
    Ios,
    /// Android (Android Keystore available).
    Android,
    /// Desktop (macOS, Windows, Linux).
    Desktop,
    /// Web browser (`WebCrypto`).
    Browser,
}

/// How a signing key is stored and protected.
///
/// Ordered from strongest to weakest custody guarantee. The custody model
/// affects trust evaluation (§7.1) — hardware-biometric provides the strongest
/// key isolation signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyCustodyModel {
    /// Secure Enclave / Android Keystore with biometric unlock.
    /// Strongest custody: key material never leaves hardware, access requires
    /// biometric authentication.
    HardwareBiometric,

    /// Hardware-backed key storage with PIN unlock.
    /// Key material in hardware but unlock uses knowledge factor (PIN/password)
    /// rather than biometric.
    HardwarePin,

    /// Software keychain storage.
    /// Key material in software — no hardware isolation. Typical for agent keys
    /// and software-only platforms.
    Software,
}

/// Platform-specific attestation proof.
///
/// Contains opaque proof bytes from a platform attestation service. The proof
/// format and verification procedure are platform-specific and outside the
/// scope of the SCP protocol itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformAttestation {
    /// The platform that produced this attestation.
    pub platform: AttestationPlatform,

    /// Opaque platform-specific proof bytes.
    ///
    /// For Apple App Attest: the attestation object from
    /// `DCAppAttestService.attestKey`.
    /// For Android Key Attestation: the certificate chain from
    /// `KeyStore.getCertificateChain`.
    #[serde(with = "serde_proof_bytes")]
    pub proof: Vec<u8>,
}

/// Platform that produced an attestation proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttestationPlatform {
    /// Apple App Attest (iOS 14+, macOS 14+).
    AppleAppAttest,

    /// Android Key Attestation (Android 8+).
    AndroidKeyAttestation,
}

/// Custom serde module for proof bytes.
///
/// Serializes `Vec<u8>` as base64 in human-readable formats (JSON) and as raw
/// bytes in binary formats. This keeps the DID document service endpoint
/// JSON-safe without requiring consumers to handle raw byte arrays in JSON.
mod serde_proof_bytes {
    use serde::{self, Deserialize, Deserializer, Serializer};

    use base64::Engine;

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
            serializer.serialize_str(&b64)
        } else {
            serde_bytes::serialize(bytes, serializer)
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            base64::engine::general_purpose::STANDARD
                .decode(&s)
                .map_err(serde::de::Error::custom)
        } else {
            serde_bytes::deserialize(deserializer)
        }
    }
}

impl ScpKeyCustodyAttestation {
    /// Create a new custody attestation.
    #[must_use]
    pub const fn new(
        active_key_custody: KeyCustodyModel,
        agent_key_custody: Option<KeyCustodyModel>,
        platform: Platform,
        platform_attestation: Option<PlatformAttestation>,
        created_at: u64,
    ) -> Self {
        Self {
            active_key_custody,
            agent_key_custody,
            platform,
            platform_attestation,
            created_at,
        }
    }

    /// Creates a DID document service entry for this custody attestation.
    ///
    /// The attestation data is JSON-encoded in the `serviceEndpoint` field.
    /// The service `id` uses the DID string with a `#custody-attestation`
    /// fragment.
    ///
    /// # Arguments
    ///
    /// * `did` - The DID string that owns this attestation (used for service ID).
    ///
    /// # Errors
    ///
    /// Returns [`DidError::DocumentSerializationError`] if the attestation
    /// data cannot be serialized to JSON (should not happen for well-formed data).
    pub fn to_service_entry(&self, did: &str) -> Result<Service, DidError> {
        let endpoint = serde_json::to_string(self).map_err(|e| {
            DidError::DocumentSerializationError(format!(
                "failed to serialize custody attestation: {e}"
            ))
        })?;

        Ok(Service {
            id: format!("{did}#custody-attestation"),
            service_type: CUSTODY_ATTESTATION_SERVICE_TYPE.to_owned(),
            service_endpoint: endpoint,
        })
    }

    /// Parses a custody attestation from a DID document service entry.
    ///
    /// # Arguments
    ///
    /// * `entry` - A service entry with `type: "ScpKeyCustodyAttestation"`.
    ///
    /// # Errors
    ///
    /// Returns [`DidError::DocumentDeserializationError`] if the service
    /// type does not match or the endpoint cannot be parsed.
    pub fn from_service_entry(entry: &Service) -> Result<Self, DidError> {
        if entry.service_type != CUSTODY_ATTESTATION_SERVICE_TYPE {
            return Err(DidError::DocumentDeserializationError(format!(
                "expected service type '{}', got '{}'",
                CUSTODY_ATTESTATION_SERVICE_TYPE, entry.service_type
            )));
        }

        serde_json::from_str(&entry.service_endpoint).map_err(|e| {
            DidError::DocumentDeserializationError(format!(
                "failed to parse custody attestation from service endpoint: {e}"
            ))
        })
    }
}

// ---------------------------------------------------------------------------
// Identity Link Platform Registry (spec §3.5.1)
// ---------------------------------------------------------------------------

/// Platform identifier for identity link attestations (spec §3.5.1).
///
/// Each variant corresponds to an entry in the closed provider registry.
/// New providers are added by spec amendment only.
///
/// NOTE: The spec currently lists 7 platforms. This enum includes 16 as
/// agreed in the attestation design discussion. A spec amendment adding
/// the remaining 9 (linkedin.com, discord.com, reddit.com, bluesky.com,
/// telegram.com, npm, pypi, steam, well-known) is pending.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IdentityLinkPlatform {
    /// GitHub (`github.com`). Class 2. Verification: `SignedPost` (profile bio).
    #[serde(rename = "github.com")]
    Github,
    /// X / Twitter (`x.com`). Class 2. Verification: `SignedPost` (profile description).
    #[serde(rename = "x.com")]
    X,
    /// Google (`google.com`). Class 1. Verification: `Oauth` (OIDC).
    #[serde(rename = "google.com")]
    Google,
    /// Apple (`apple.com`). Class 1. Verification: `Oauth` (OIDC).
    #[serde(rename = "apple.com")]
    Apple,
    /// Microsoft (`microsoft.com`). Class 1. Verification: `Oauth` (OIDC).
    #[serde(rename = "microsoft.com")]
    Microsoft,
    /// Mastodon (`mastodon`). Class 2. Verification: `SignedPost` (profile bio).
    ///
    /// Mastodon is a federated platform with many instances. The spec says the
    /// platform value should be `mastodon:<instance>` (e.g., `mastodon:mastodon.social`).
    /// However, the enum variant serializes to just `"mastodon"` because enum
    /// variants cannot carry instance-specific data.
    ///
    /// **Convention:** The `platform_handle` field should include the full Mastodon
    /// address with instance (e.g., `@user@mastodon.social`). Verifiers should
    /// extract the instance from the handle when needed. For attestations that
    /// need instance-specific platform values, use the raw string `"mastodon:<instance>"`
    /// directly instead of this enum variant.
    #[serde(rename = "mastodon")]
    Mastodon,
    /// DNS (`dns`). Class 2. Verification: `DnsRecord` (`_scp-verify.<domain>`).
    #[serde(rename = "dns")]
    Dns,
    /// `LinkedIn` (`linkedin.com`). Class 2. Verification: `SignedPost`.
    #[serde(rename = "linkedin.com")]
    Linkedin,
    /// Discord (`discord.com`). Class 1. Verification: `Oauth`.
    #[serde(rename = "discord.com")]
    Discord,
    /// Reddit (`reddit.com`). Class 2. Verification: `SignedPost`.
    #[serde(rename = "reddit.com")]
    Reddit,
    /// Bluesky (`bluesky.com`). Class 2. Verification: `SignedPost`.
    #[serde(rename = "bluesky.com")]
    Bluesky,
    /// Telegram (`telegram.com`). Class 2. Verification: `ChallengeResponse`.
    #[serde(rename = "telegram.com")]
    Telegram,
    /// npm (`npm`). Class 2. Verification: `SignedPost` (package metadata).
    #[serde(rename = "npm")]
    Npm,
    /// `PyPI` (`pypi`). Class 2. Verification: `SignedPost` (package metadata).
    #[serde(rename = "pypi")]
    Pypi,
    /// Steam (`steam`). Class 2. Verification: `SignedPost` (profile).
    #[serde(rename = "steam")]
    Steam,
    /// Well-known (`well-known`). Class 2. Verification: `DnsRecord`
    /// (`/.well-known/scp-verify`).
    #[serde(rename = "well-known")]
    WellKnown,
}

/// All platform variants in registry order, for iteration.
const ALL_PLATFORMS: [IdentityLinkPlatform; 16] = [
    IdentityLinkPlatform::Github,
    IdentityLinkPlatform::X,
    IdentityLinkPlatform::Google,
    IdentityLinkPlatform::Apple,
    IdentityLinkPlatform::Microsoft,
    IdentityLinkPlatform::Mastodon,
    IdentityLinkPlatform::Dns,
    IdentityLinkPlatform::Linkedin,
    IdentityLinkPlatform::Discord,
    IdentityLinkPlatform::Reddit,
    IdentityLinkPlatform::Bluesky,
    IdentityLinkPlatform::Telegram,
    IdentityLinkPlatform::Npm,
    IdentityLinkPlatform::Pypi,
    IdentityLinkPlatform::Steam,
    IdentityLinkPlatform::WellKnown,
];

impl IdentityLinkPlatform {
    /// Returns the canonical wire-format string for this platform.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Github => "github.com",
            Self::X => "x.com",
            Self::Google => "google.com",
            Self::Apple => "apple.com",
            Self::Microsoft => "microsoft.com",
            Self::Mastodon => "mastodon",
            Self::Dns => "dns",
            Self::Linkedin => "linkedin.com",
            Self::Discord => "discord.com",
            Self::Reddit => "reddit.com",
            Self::Bluesky => "bluesky.com",
            Self::Telegram => "telegram.com",
            Self::Npm => "npm",
            Self::Pypi => "pypi",
            Self::Steam => "steam",
            Self::WellKnown => "well-known",
        }
    }

    /// Returns all platform variants in registry order.
    #[must_use]
    pub const fn all() -> &'static [Self; 16] {
        &ALL_PLATFORMS
    }
}

impl fmt::Display for IdentityLinkPlatform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error returned when a string does not match any known platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownPlatformError(pub String);

impl fmt::Display for UnknownPlatformError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown identity link platform: '{}'", self.0)
    }
}

impl std::error::Error for UnknownPlatformError {}

impl FromStr for IdentityLinkPlatform {
    type Err = UnknownPlatformError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "github.com" => Ok(Self::Github),
            "x.com" => Ok(Self::X),
            "google.com" => Ok(Self::Google),
            "apple.com" => Ok(Self::Apple),
            "microsoft.com" => Ok(Self::Microsoft),
            "mastodon" => Ok(Self::Mastodon),
            "dns" => Ok(Self::Dns),
            "linkedin.com" => Ok(Self::Linkedin),
            "discord.com" => Ok(Self::Discord),
            "reddit.com" => Ok(Self::Reddit),
            "bluesky.com" => Ok(Self::Bluesky),
            "telegram.com" => Ok(Self::Telegram),
            "npm" => Ok(Self::Npm),
            "pypi" => Ok(Self::Pypi),
            "steam" => Ok(Self::Steam),
            "well-known" => Ok(Self::WellKnown),
            other => Err(UnknownPlatformError(other.to_owned())),
        }
    }
}

// ---------------------------------------------------------------------------
// Identity Link Attestation Service Entry (§3.5.3)
// ---------------------------------------------------------------------------

/// The service type string for identity link attestation entries.
const IDENTITY_LINK_ATTESTATION_SERVICE_TYPE: &str = "ScpIdentityLinkAttestation";

/// An identity link attestation service entry in a DID document (§3.5.3).
///
/// This is the minimal service entry format — the full `IdentityLinkAttestation`
/// is stored separately (in the identity's attestation store via relay or DHT).
/// The service entry only records the platform, index, and attestation ID for
/// discovery purposes.
///
/// Fragment format: `attestation-<platform>--<index>` (e.g.,
/// `attestation-github.com--0`). The double-dash separates the platform from
/// the zero-based index to disambiguate multiple attestations for the same
/// platform (e.g., multiple Mastodon instances).
///
/// The `serviceEndpoint` contains only the hex-encoded attestation ID (§3.5.2).
impl IdentityLinkServiceEntry {
    /// Creates a DID document service entry for an identity link attestation.
    ///
    /// # Arguments
    ///
    /// * `did` - The DID string that owns this attestation (used for service ID).
    /// * `platform` - Platform identifier from the provider registry (§3.5.1).
    /// * `attestation_id` - Hex-encoded deterministic attestation ID (§3.5.2).
    /// * `index` - Zero-based index among attestation entries for this platform.
    #[must_use]
    pub fn to_service_entry(
        did: &str,
        platform: &str,
        attestation_id: &str,
        index: usize,
    ) -> Service {
        Service {
            id: format!("{did}#attestation-{platform}--{index}"),
            service_type: IDENTITY_LINK_ATTESTATION_SERVICE_TYPE.to_owned(),
            service_endpoint: attestation_id.to_owned(),
        }
    }

    /// Parses an identity link attestation service entry from a DID document
    /// service entry.
    ///
    /// Extracts the attestation ID from the `serviceEndpoint` and the platform
    /// and index from the fragment.
    ///
    /// # Errors
    ///
    /// Returns [`DidError::DocumentDeserializationError`] if the service
    /// type does not match or the fragment cannot be parsed.
    pub fn from_service_entry(entry: &Service) -> Result<Self, DidError> {
        if entry.service_type != IDENTITY_LINK_ATTESTATION_SERVICE_TYPE {
            return Err(DidError::DocumentDeserializationError(format!(
                "expected service type '{}', got '{}'",
                IDENTITY_LINK_ATTESTATION_SERVICE_TYPE, entry.service_type
            )));
        }

        // Parse fragment: "...#attestation-<platform>--<index>"
        let fragment = entry
            .id
            .rsplit_once('#')
            .map(|(_, frag)| frag)
            .ok_or_else(|| {
                DidError::DocumentDeserializationError("service id has no fragment".to_owned())
            })?;

        let rest = fragment.strip_prefix("attestation-").ok_or_else(|| {
            DidError::DocumentDeserializationError(format!(
                "fragment does not start with 'attestation-': {fragment}"
            ))
        })?;

        // Split on the double-dash separator (last occurrence to handle platforms
        // that contain dashes, though current platform values don't).
        let (platform, index_str) = rest.rsplit_once("--").ok_or_else(|| {
            DidError::DocumentDeserializationError(format!(
                "fragment missing '--' separator: {fragment}"
            ))
        })?;

        let index = index_str.parse::<usize>().map_err(|e| {
            DidError::DocumentDeserializationError(format!(
                "invalid index in fragment '{fragment}': {e}"
            ))
        })?;

        Ok(Self {
            platform: platform.to_owned(),
            attestation_id: entry.service_endpoint.clone(),
            index,
        })
    }
}

/// Parsed identity link attestation service entry data.
///
/// Contains the platform, attestation ID, and index extracted from a DID
/// document service entry. This is the minimal information needed for
/// discovery — the full attestation must be fetched separately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityLinkServiceEntry {
    /// Platform identifier from the provider registry (§3.5.1).
    pub platform: String,

    /// Hex-encoded deterministic attestation ID (§3.5.2).
    pub attestation_id: String,

    /// Zero-based index among attestation entries for this platform.
    pub index: usize,
}

/// Revocation status for identity link service entries.
///
/// A typed enum replacing the raw `String` field. Serializes to
/// lowercase `"active"` / `"revoked"` for wire compatibility with
/// existing DID document service entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceRevocationStatus {
    /// The attestation is active (not revoked).
    Active,
    /// The attestation has been revoked.
    Revoked,
}

impl ServiceRevocationStatus {
    /// Returns the wire-format string for this status.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }
}

impl std::fmt::Display for ServiceRevocationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;

    fn test_did() -> &'static str {
        "did:dht:zTestCustody"
    }

    // --- Construction tests ---

    #[test]
    fn attestation_with_hardware_biometric_model() {
        let attestation = ScpKeyCustodyAttestation {
            active_key_custody: KeyCustodyModel::HardwareBiometric,
            agent_key_custody: Some(KeyCustodyModel::Software),
            platform: Platform::Ios,
            platform_attestation: None,
            created_at: 1_700_000_000,
        };

        assert_eq!(
            attestation.active_key_custody,
            KeyCustodyModel::HardwareBiometric
        );
        assert_eq!(
            attestation.agent_key_custody,
            Some(KeyCustodyModel::Software)
        );
        assert!(attestation.platform_attestation.is_none());
    }

    #[test]
    fn attestation_with_software_model() {
        let attestation = ScpKeyCustodyAttestation {
            active_key_custody: KeyCustodyModel::Software,
            agent_key_custody: None,
            platform: Platform::Desktop,
            platform_attestation: None,
            created_at: 1_700_000_000,
        };

        assert_eq!(attestation.active_key_custody, KeyCustodyModel::Software);
        assert!(attestation.agent_key_custody.is_none());
        assert!(attestation.platform_attestation.is_none());
    }

    #[test]
    fn attestation_with_hardware_pin_model() {
        let attestation = ScpKeyCustodyAttestation {
            active_key_custody: KeyCustodyModel::HardwarePin,
            agent_key_custody: Some(KeyCustodyModel::HardwarePin),
            platform: Platform::Android,
            platform_attestation: None,
            created_at: 1_700_000_000,
        };

        assert_eq!(attestation.active_key_custody, KeyCustodyModel::HardwarePin);
        assert_eq!(
            attestation.agent_key_custody,
            Some(KeyCustodyModel::HardwarePin)
        );
    }

    // --- Service entry round-trip tests ---

    #[test]
    fn roundtrip_through_service_entry_without_platform_attestation() {
        let original = ScpKeyCustodyAttestation {
            active_key_custody: KeyCustodyModel::HardwareBiometric,
            agent_key_custody: Some(KeyCustodyModel::Software),
            platform: Platform::Ios,
            platform_attestation: None,
            created_at: 1_700_000_000,
        };

        let service = original.to_service_entry(test_did()).unwrap();
        assert_eq!(service.service_type, "ScpKeyCustodyAttestation");
        assert_eq!(service.id, format!("{}#custody-attestation", test_did()));

        let parsed = ScpKeyCustodyAttestation::from_service_entry(&service).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn roundtrip_through_service_entry_with_platform_attestation() {
        let proof_bytes = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];
        let original = ScpKeyCustodyAttestation {
            active_key_custody: KeyCustodyModel::HardwareBiometric,
            agent_key_custody: Some(KeyCustodyModel::Software),
            platform: Platform::Ios,
            platform_attestation: Some(PlatformAttestation {
                platform: AttestationPlatform::AppleAppAttest,
                proof: proof_bytes,
            }),
            created_at: 1_700_000_000,
        };

        let service = original.to_service_entry(test_did()).unwrap();
        let parsed = ScpKeyCustodyAttestation::from_service_entry(&service).unwrap();
        assert_eq!(original, parsed);
        assert_eq!(
            parsed.platform_attestation.as_ref().unwrap().proof,
            [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04]
        );
        assert_eq!(
            parsed.platform_attestation.as_ref().unwrap().platform,
            AttestationPlatform::AppleAppAttest
        );
    }

    #[test]
    fn roundtrip_with_android_key_attestation() {
        let proof_bytes = vec![0x01; 128]; // Simulated certificate chain
        let original = ScpKeyCustodyAttestation {
            active_key_custody: KeyCustodyModel::HardwarePin,
            agent_key_custody: None,
            platform: Platform::Android,
            platform_attestation: Some(PlatformAttestation {
                platform: AttestationPlatform::AndroidKeyAttestation,
                proof: proof_bytes,
            }),
            created_at: 1_700_000_000,
        };

        let service = original.to_service_entry(test_did()).unwrap();
        let parsed = ScpKeyCustodyAttestation::from_service_entry(&service).unwrap();
        assert_eq!(original, parsed);
        assert_eq!(
            parsed.platform_attestation.as_ref().unwrap().platform,
            AttestationPlatform::AndroidKeyAttestation
        );
    }

    #[test]
    fn roundtrip_software_only_no_agent_key() {
        let original = ScpKeyCustodyAttestation {
            active_key_custody: KeyCustodyModel::Software,
            agent_key_custody: None,
            platform: Platform::Browser,
            platform_attestation: None,
            created_at: 1_700_000_000,
        };

        let service = original.to_service_entry(test_did()).unwrap();
        let parsed = ScpKeyCustodyAttestation::from_service_entry(&service).unwrap();
        assert_eq!(original, parsed);

        // Verify the JSON endpoint does not contain agent_key_custody or
        // platform_attestation fields when they are None.
        assert!(!service.service_endpoint.contains("agent_key_custody"));
        assert!(!service.service_endpoint.contains("platform_attestation"));
    }

    // --- Error cases ---

    #[test]
    fn from_service_entry_rejects_wrong_service_type() {
        let service = Service {
            id: format!("{}#pre-rotation", test_did()),
            service_type: "PreRotationCommitment".to_owned(),
            service_endpoint: "sha256:abc123".to_owned(),
        };

        let result = ScpKeyCustodyAttestation::from_service_entry(&service);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("expected service type"),
            "error should mention expected type, got: {err}"
        );
    }

    #[test]
    fn from_service_entry_rejects_invalid_json() {
        let service = Service {
            id: format!("{}#custody-attestation", test_did()),
            service_type: CUSTODY_ATTESTATION_SERVICE_TYPE.to_owned(),
            service_endpoint: "not valid json".to_owned(),
        };

        let result = ScpKeyCustodyAttestation::from_service_entry(&service);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("failed to parse"),
            "error should mention parse failure, got: {err}"
        );
    }

    // --- Serde direct tests ---

    #[test]
    fn serde_json_roundtrip() {
        let attestation = ScpKeyCustodyAttestation {
            active_key_custody: KeyCustodyModel::HardwareBiometric,
            agent_key_custody: Some(KeyCustodyModel::Software),
            platform: Platform::Ios,
            platform_attestation: Some(PlatformAttestation {
                platform: AttestationPlatform::AppleAppAttest,
                proof: vec![1, 2, 3, 4, 5],
            }),
            created_at: 1_700_000_000,
        };

        let json = serde_json::to_string(&attestation).unwrap();
        let parsed: ScpKeyCustodyAttestation = serde_json::from_str(&json).unwrap();
        assert_eq!(attestation, parsed);
    }

    #[test]
    fn serde_key_custody_model_kebab_case() {
        // Verify enum variants serialize as kebab-case strings.
        let hw_bio = serde_json::to_string(&KeyCustodyModel::HardwareBiometric).unwrap();
        assert_eq!(hw_bio, "\"hardware-biometric\"");

        let hw_pin = serde_json::to_string(&KeyCustodyModel::HardwarePin).unwrap();
        assert_eq!(hw_pin, "\"hardware-pin\"");

        let sw = serde_json::to_string(&KeyCustodyModel::Software).unwrap();
        assert_eq!(sw, "\"software\"");

        // Verify round-trip from strings.
        let parsed: KeyCustodyModel = serde_json::from_str("\"hardware-biometric\"").unwrap();
        assert_eq!(parsed, KeyCustodyModel::HardwareBiometric);

        let parsed: KeyCustodyModel = serde_json::from_str("\"hardware-pin\"").unwrap();
        assert_eq!(parsed, KeyCustodyModel::HardwarePin);

        let parsed: KeyCustodyModel = serde_json::from_str("\"software\"").unwrap();
        assert_eq!(parsed, KeyCustodyModel::Software);
    }

    #[test]
    fn serde_attestation_platform_variants() {
        let apple = serde_json::to_string(&AttestationPlatform::AppleAppAttest).unwrap();
        assert_eq!(apple, "\"AppleAppAttest\"");

        let android = serde_json::to_string(&AttestationPlatform::AndroidKeyAttestation).unwrap();
        assert_eq!(android, "\"AndroidKeyAttestation\"");
    }

    #[test]
    fn serde_proof_bytes_base64_in_json() {
        use base64::Engine;

        let attestation = PlatformAttestation {
            platform: AttestationPlatform::AppleAppAttest,
            proof: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };

        let json = serde_json::to_string(&attestation).unwrap();
        // Proof should be base64-encoded in JSON, not a byte array.
        assert!(
            !json.contains("[222,"),
            "proof should be base64 in JSON, not a byte array: {json}"
        );

        // Verify it's valid base64.
        let expected_b64 =
            base64::engine::general_purpose::STANDARD.encode([0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(
            json.contains(&expected_b64),
            "expected base64 '{expected_b64}' in JSON: {json}"
        );

        // Round-trip.
        let parsed: PlatformAttestation = serde_json::from_str(&json).unwrap();
        assert_eq!(attestation, parsed);
    }

    #[test]
    fn empty_proof_bytes_roundtrip() {
        let attestation = PlatformAttestation {
            platform: AttestationPlatform::AndroidKeyAttestation,
            proof: vec![],
        };

        let json = serde_json::to_string(&attestation).unwrap();
        let parsed: PlatformAttestation = serde_json::from_str(&json).unwrap();
        assert_eq!(attestation, parsed);
        assert!(parsed.proof.is_empty());
    }

    // --- Platform enum tests ---

    #[test]
    fn serde_platform_enum_kebab_case() {
        let ios = serde_json::to_string(&Platform::Ios).unwrap();
        assert_eq!(ios, "\"ios\"");

        let android = serde_json::to_string(&Platform::Android).unwrap();
        assert_eq!(android, "\"android\"");

        let desktop = serde_json::to_string(&Platform::Desktop).unwrap();
        assert_eq!(desktop, "\"desktop\"");

        let browser = serde_json::to_string(&Platform::Browser).unwrap();
        assert_eq!(browser, "\"browser\"");

        // Round-trip from strings.
        let parsed: Platform = serde_json::from_str("\"ios\"").unwrap();
        assert_eq!(parsed, Platform::Ios);

        let parsed: Platform = serde_json::from_str("\"android\"").unwrap();
        assert_eq!(parsed, Platform::Android);

        let parsed: Platform = serde_json::from_str("\"desktop\"").unwrap();
        assert_eq!(parsed, Platform::Desktop);

        let parsed: Platform = serde_json::from_str("\"browser\"").unwrap();
        assert_eq!(parsed, Platform::Browser);
    }

    #[test]
    fn attestation_with_each_platform_variant() {
        for platform in [
            Platform::Ios,
            Platform::Android,
            Platform::Desktop,
            Platform::Browser,
        ] {
            let attestation = ScpKeyCustodyAttestation {
                active_key_custody: KeyCustodyModel::Software,
                agent_key_custody: None,
                platform,
                platform_attestation: None,
                created_at: 1_700_000_000,
            };

            let service = attestation.to_service_entry(test_did()).unwrap();
            let parsed = ScpKeyCustodyAttestation::from_service_entry(&service).unwrap();
            assert_eq!(attestation, parsed);
            assert_eq!(parsed.platform, platform);
        }
    }

    #[test]
    fn new_constructor() {
        let attestation = ScpKeyCustodyAttestation::new(
            KeyCustodyModel::HardwareBiometric,
            Some(KeyCustodyModel::Software),
            Platform::Ios,
            None,
            1_700_000_000,
        );

        assert_eq!(
            attestation.active_key_custody,
            KeyCustodyModel::HardwareBiometric
        );
        assert_eq!(
            attestation.agent_key_custody,
            Some(KeyCustodyModel::Software)
        );
        assert_eq!(attestation.platform, Platform::Ios);
        assert!(attestation.platform_attestation.is_none());
        assert_eq!(attestation.created_at, 1_700_000_000);
    }

    // ===================================================================
    // IdentityLinkPlatform tests
    // ===================================================================

    #[test]
    fn identity_link_platform_as_str_roundtrip_all() {
        let expected: &[(&str, IdentityLinkPlatform)] = &[
            ("github.com", IdentityLinkPlatform::Github),
            ("x.com", IdentityLinkPlatform::X),
            ("google.com", IdentityLinkPlatform::Google),
            ("apple.com", IdentityLinkPlatform::Apple),
            ("microsoft.com", IdentityLinkPlatform::Microsoft),
            ("mastodon", IdentityLinkPlatform::Mastodon),
            ("dns", IdentityLinkPlatform::Dns),
            ("linkedin.com", IdentityLinkPlatform::Linkedin),
            ("discord.com", IdentityLinkPlatform::Discord),
            ("reddit.com", IdentityLinkPlatform::Reddit),
            ("bluesky.com", IdentityLinkPlatform::Bluesky),
            ("telegram.com", IdentityLinkPlatform::Telegram),
            ("npm", IdentityLinkPlatform::Npm),
            ("pypi", IdentityLinkPlatform::Pypi),
            ("steam", IdentityLinkPlatform::Steam),
            ("well-known", IdentityLinkPlatform::WellKnown),
        ];

        assert_eq!(
            expected.len(),
            16,
            "must test all 16 platforms in the provider registry"
        );

        for &(s, variant) in expected {
            assert_eq!(variant.as_str(), s, "as_str mismatch for {variant:?}");
            let parsed: IdentityLinkPlatform = s.parse().unwrap();
            assert_eq!(parsed, variant, "from_str mismatch for '{s}'");
        }
    }

    #[test]
    fn identity_link_platform_from_str_unknown() {
        let err = "unknown-platform"
            .parse::<IdentityLinkPlatform>()
            .unwrap_err();
        assert!(
            err.to_string().contains("unknown identity link platform"),
            "error should mention unknown platform, got: {err}"
        );
    }

    #[test]
    fn identity_link_platform_display() {
        assert_eq!(format!("{}", IdentityLinkPlatform::Github), "github.com");
        assert_eq!(format!("{}", IdentityLinkPlatform::WellKnown), "well-known");
    }

    #[test]
    fn identity_link_platform_serde_roundtrip_all() {
        for &platform in IdentityLinkPlatform::all() {
            let json = serde_json::to_string(&platform).unwrap();
            let parsed: IdentityLinkPlatform = serde_json::from_str(&json).unwrap();
            assert_eq!(platform, parsed, "serde roundtrip failed for {platform:?}");
            // Verify the JSON value matches as_str.
            assert_eq!(json, format!("\"{}\"", platform.as_str()));
        }
    }

    #[test]
    fn identity_link_platform_all_returns_16() {
        assert_eq!(IdentityLinkPlatform::all().len(), 16);
    }

    // --- Identity link attestation service entry tests (§3.5.3) ---

    #[test]
    fn identity_link_to_service_entry_format() {
        let entry =
            IdentityLinkServiceEntry::to_service_entry(test_did(), "github.com", "abc123def456", 0);

        assert_eq!(
            entry.id,
            format!("{}#attestation-github.com--0", test_did())
        );
        assert_eq!(entry.service_type, "ScpIdentityLinkAttestation");
        assert_eq!(entry.service_endpoint, "abc123def456");
    }

    #[test]
    fn identity_link_to_service_entry_with_nonzero_index() {
        let entry = IdentityLinkServiceEntry::to_service_entry(
            test_did(),
            "mastodon:mastodon.social",
            "deadbeef",
            3,
        );

        assert_eq!(
            entry.id,
            format!("{}#attestation-mastodon:mastodon.social--3", test_did())
        );
        assert_eq!(entry.service_endpoint, "deadbeef");
    }

    #[test]
    fn identity_link_roundtrip_through_service_entry() {
        let entry =
            IdentityLinkServiceEntry::to_service_entry(test_did(), "github.com", "abc123", 0);

        let parsed = IdentityLinkServiceEntry::from_service_entry(&entry).unwrap();
        assert_eq!(parsed.platform, "github.com");
        assert_eq!(parsed.attestation_id, "abc123");
        assert_eq!(parsed.index, 0);
    }

    #[test]
    fn identity_link_roundtrip_multiple_indices() {
        for idx in 0..5 {
            let entry = IdentityLinkServiceEntry::to_service_entry(
                test_did(),
                "x.com",
                &format!("attest-{idx}"),
                idx,
            );

            let parsed = IdentityLinkServiceEntry::from_service_entry(&entry).unwrap();
            assert_eq!(parsed.platform, "x.com");
            assert_eq!(parsed.attestation_id, format!("attest-{idx}"));
            assert_eq!(parsed.index, idx);
        }
    }

    #[test]
    fn identity_link_from_service_entry_rejects_wrong_type() {
        let service = Service {
            id: format!("{}#attestation-github.com--0", test_did()),
            service_type: "WrongType".to_owned(),
            service_endpoint: "abc123".to_owned(),
        };

        let result = IdentityLinkServiceEntry::from_service_entry(&service);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("expected service type")
        );
    }

    #[test]
    fn identity_link_from_service_entry_rejects_missing_fragment() {
        let service = Service {
            id: "no-fragment-here".to_owned(),
            service_type: "ScpIdentityLinkAttestation".to_owned(),
            service_endpoint: "abc123".to_owned(),
        };

        let result = IdentityLinkServiceEntry::from_service_entry(&service);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no fragment"));
    }

    #[test]
    fn identity_link_from_service_entry_rejects_missing_double_dash() {
        let service = Service {
            id: format!("{}#attestation-github.com-0", test_did()),
            service_type: "ScpIdentityLinkAttestation".to_owned(),
            service_endpoint: "abc123".to_owned(),
        };

        let result = IdentityLinkServiceEntry::from_service_entry(&service);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("--"));
    }

    #[test]
    fn identity_link_from_service_entry_rejects_invalid_index() {
        let service = Service {
            id: format!("{}#attestation-github.com--notanumber", test_did()),
            service_type: "ScpIdentityLinkAttestation".to_owned(),
            service_endpoint: "abc123".to_owned(),
        };

        let result = IdentityLinkServiceEntry::from_service_entry(&service);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid index"));
    }

    #[test]
    fn identity_link_service_endpoint_is_just_attestation_id() {
        // Verify that the endpoint is the bare attestation ID, not a JSON blob.
        let entry = IdentityLinkServiceEntry::to_service_entry(
            test_did(),
            "github.com",
            "deadbeefcafe0123",
            0,
        );

        assert_eq!(entry.service_endpoint, "deadbeefcafe0123");
        // Should NOT start with '{' (not JSON).
        assert!(
            !entry.service_endpoint.starts_with('{'),
            "endpoint should be bare attestation ID, not JSON"
        );
    }
}
