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

use super::IdentityError;
use super::document::Service;
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
    /// Returns [`IdentityError::DocumentSerializationError`] if the attestation
    /// data cannot be serialized to JSON (should not happen for well-formed data).
    pub fn to_service_entry(&self, did: &str) -> Result<Service, IdentityError> {
        let endpoint = serde_json::to_string(self).map_err(|e| {
            IdentityError::DocumentSerializationError(format!(
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
    /// Returns [`IdentityError::DocumentDeserializationError`] if the service
    /// type does not match or the endpoint cannot be parsed.
    pub fn from_service_entry(entry: &Service) -> Result<Self, IdentityError> {
        if entry.service_type != CUSTODY_ATTESTATION_SERVICE_TYPE {
            return Err(IdentityError::DocumentDeserializationError(format!(
                "expected service type '{}', got '{}'",
                CUSTODY_ATTESTATION_SERVICE_TYPE, entry.service_type
            )));
        }

        serde_json::from_str(&entry.service_endpoint).map_err(|e| {
            IdentityError::DocumentDeserializationError(format!(
                "failed to parse custody attestation from service endpoint: {e}"
            ))
        })
    }
}

// ---------------------------------------------------------------------------
// Identity Link Attestation Service Entry (spec §3.5.3)
// ---------------------------------------------------------------------------

/// The service type string for identity link attestation entries.
const IDENTITY_LINK_SERVICE_TYPE: &str = "ScpIdentityLinkAttestation";

/// Platform identifier for identity link attestations (spec §3.5.1).
///
/// Each variant corresponds to an entry in the closed provider registry.
/// New providers are added by spec amendment only.
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
    /// Instance is specified in the platform handle (e.g., `@user@mastodon.social`).
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

/// Identity link attestation published as a DID document service entry (spec §3.5.3).
///
/// Represents a self-signed claim that the DID owner controls a specific
/// external platform identity. Published as a service entry in the DID
/// document for discovery — any party resolving the document can enumerate
/// the owner's identity links.
///
/// Follows the same pattern as [`ScpKeyCustodyAttestation`]: the struct is
/// serialized as JSON in the `serviceEndpoint` field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScpIdentityLinkService {
    /// Deterministic attestation ID (hex-encoded SHA-256, per §3.5.2).
    pub attestation_id: String,

    /// Platform identifier from the provider registry (§3.5.1).
    pub platform: IdentityLinkPlatform,

    /// Handle on the platform (e.g., `"@alice"`, `"alice123"`).
    pub platform_handle: String,

    /// Platform-specific immutable user ID (e.g., Twitter user ID, OIDC sub).
    /// `None` when the platform does not provide a stable ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform_id: Option<String>,

    /// The DID verification method fragment that signed the attestation
    /// (e.g., `"#active"` or `"#agent"`).
    pub verification_method: String,

    /// Unix timestamp (seconds) when the attestation was last verified.
    pub verified_at: u64,

    /// Revocation status: `"active"` or `"revoked"`.
    pub revocation_status: String,
}

impl ScpIdentityLinkService {
    /// Revocation status value for an active attestation.
    pub const STATUS_ACTIVE: &'static str = "active";

    /// Revocation status value for a revoked attestation.
    pub const STATUS_REVOKED: &'static str = "revoked";

    /// Creates a DID document service entry for this identity link attestation.
    ///
    /// The attestation data is JSON-encoded in the `serviceEndpoint` field.
    /// The service `id` uses the fragment format
    /// `attestation-<platform>-<attestation_id_prefix>` where the prefix is the
    /// first 8 characters of `attestation_id` for disambiguation.
    ///
    /// # Arguments
    ///
    /// * `did` - The DID string that owns this attestation (used for service ID).
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::DocumentSerializationError`] if the attestation
    /// data cannot be serialized to JSON.
    pub fn to_service_entry(&self, did: &str) -> Result<Service, IdentityError> {
        let endpoint = serde_json::to_string(self).map_err(|e| {
            IdentityError::DocumentSerializationError(format!(
                "failed to serialize identity link attestation: {e}"
            ))
        })?;

        let id_prefix = if self.attestation_id.len() >= 8 {
            &self.attestation_id[..8]
        } else {
            &self.attestation_id
        };

        Ok(Service {
            id: format!("{did}#attestation-{}-{id_prefix}", self.platform.as_str()),
            service_type: IDENTITY_LINK_SERVICE_TYPE.to_owned(),
            service_endpoint: endpoint,
        })
    }

    /// Parses an identity link attestation from a DID document service entry.
    ///
    /// # Arguments
    ///
    /// * `entry` - A service entry with `type: "ScpIdentityLinkAttestation"`.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::DocumentDeserializationError`] if the service
    /// type does not match or the endpoint cannot be parsed.
    pub fn from_service_entry(entry: &Service) -> Result<Self, IdentityError> {
        if entry.service_type != IDENTITY_LINK_SERVICE_TYPE {
            return Err(IdentityError::DocumentDeserializationError(format!(
                "expected service type '{}', got '{}'",
                IDENTITY_LINK_SERVICE_TYPE, entry.service_type
            )));
        }

        serde_json::from_str(&entry.service_endpoint).map_err(|e| {
            IdentityError::DocumentDeserializationError(format!(
                "failed to parse identity link attestation from service endpoint: {e}"
            ))
        })
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

    // ===================================================================
    // ScpIdentityLinkService tests
    // ===================================================================

    fn test_link_service() -> ScpIdentityLinkService {
        ScpIdentityLinkService {
            attestation_id: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
                .to_owned(),
            platform: IdentityLinkPlatform::Github,
            platform_handle: "@alice".to_owned(),
            platform_id: Some("12345678".to_owned()),
            verification_method: "#active".to_owned(),
            verified_at: 1_700_000_000,
            revocation_status: ScpIdentityLinkService::STATUS_ACTIVE.to_owned(),
        }
    }

    #[test]
    fn identity_link_service_roundtrip() {
        let original = test_link_service();
        let service = original.to_service_entry(test_did()).unwrap();

        assert_eq!(service.service_type, "ScpIdentityLinkAttestation");
        assert_eq!(
            service.id,
            format!("{}#attestation-github.com-abcdef01", test_did())
        );

        let parsed = ScpIdentityLinkService::from_service_entry(&service).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn identity_link_service_without_platform_id() {
        let original = ScpIdentityLinkService {
            attestation_id: "deadbeef01234567".to_owned(),
            platform: IdentityLinkPlatform::Dns,
            platform_handle: "example.com".to_owned(),
            platform_id: None,
            verification_method: "#active".to_owned(),
            verified_at: 1_700_000_000,
            revocation_status: ScpIdentityLinkService::STATUS_ACTIVE.to_owned(),
        };

        let service = original.to_service_entry(test_did()).unwrap();
        // Verify the JSON endpoint does not contain platform_id when None.
        assert!(
            !service.service_endpoint.contains("platform_id"),
            "service endpoint should not contain platform_id when None"
        );

        let parsed = ScpIdentityLinkService::from_service_entry(&service).unwrap();
        assert_eq!(original, parsed);
        assert!(parsed.platform_id.is_none());
    }

    #[test]
    fn identity_link_service_short_attestation_id() {
        let original = ScpIdentityLinkService {
            attestation_id: "abc".to_owned(),
            platform: IdentityLinkPlatform::X,
            platform_handle: "@bob".to_owned(),
            platform_id: None,
            verification_method: "#agent".to_owned(),
            verified_at: 1_700_000_000,
            revocation_status: ScpIdentityLinkService::STATUS_ACTIVE.to_owned(),
        };

        let service = original.to_service_entry(test_did()).unwrap();
        // Short ID should use the full string as prefix.
        assert_eq!(service.id, format!("{}#attestation-x.com-abc", test_did()));

        let parsed = ScpIdentityLinkService::from_service_entry(&service).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn identity_link_service_each_platform() {
        for &platform in IdentityLinkPlatform::all() {
            let service_entry = ScpIdentityLinkService {
                attestation_id: "abcdef0123456789".to_owned(),
                platform,
                platform_handle: "testuser".to_owned(),
                platform_id: None,
                verification_method: "#active".to_owned(),
                verified_at: 1_700_000_000,
                revocation_status: ScpIdentityLinkService::STATUS_ACTIVE.to_owned(),
            };

            let service = service_entry.to_service_entry(test_did()).unwrap();
            assert!(
                service
                    .id
                    .contains(&format!("attestation-{}", platform.as_str())),
                "service ID should contain platform: {platform:?}"
            );

            let parsed = ScpIdentityLinkService::from_service_entry(&service).unwrap();
            assert_eq!(service_entry, parsed);
        }
    }

    #[test]
    fn identity_link_service_rejects_wrong_type() {
        let service = Service {
            id: format!("{}#custody-attestation", test_did()),
            service_type: "ScpKeyCustodyAttestation".to_owned(),
            service_endpoint: "{}".to_owned(),
        };

        let result = ScpIdentityLinkService::from_service_entry(&service);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("expected service type"),
            "error should mention expected type, got: {err}"
        );
    }

    #[test]
    fn identity_link_service_rejects_invalid_json() {
        let service = Service {
            id: format!("{}#attestation-github.com-abcdef01", test_did()),
            service_type: IDENTITY_LINK_SERVICE_TYPE.to_owned(),
            service_endpoint: "not valid json".to_owned(),
        };

        let result = ScpIdentityLinkService::from_service_entry(&service);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("failed to parse"),
            "error should mention parse failure, got: {err}"
        );
    }

    #[test]
    fn identity_link_service_serde_json_roundtrip() {
        let original = test_link_service();
        let json = serde_json::to_string(&original).unwrap();
        let parsed: ScpIdentityLinkService = serde_json::from_str(&json).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn identity_link_service_revoked_status() {
        let original = ScpIdentityLinkService {
            attestation_id: "revoked_id_0123456789".to_owned(),
            platform: IdentityLinkPlatform::Apple,
            platform_handle: "alice@icloud.com".to_owned(),
            platform_id: Some("oidc-sub-12345".to_owned()),
            verification_method: "#active".to_owned(),
            verified_at: 1_700_000_000,
            revocation_status: ScpIdentityLinkService::STATUS_REVOKED.to_owned(),
        };

        let service = original.to_service_entry(test_did()).unwrap();
        let parsed = ScpIdentityLinkService::from_service_entry(&service).unwrap();
        assert_eq!(parsed.revocation_status, "revoked");
    }

    #[test]
    fn identity_link_service_status_constants() {
        assert_eq!(ScpIdentityLinkService::STATUS_ACTIVE, "active");
        assert_eq!(ScpIdentityLinkService::STATUS_REVOKED, "revoked");
    }
}
