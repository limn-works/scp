//! Capability definition records (spec 07 §7.3.4.6).
//!
//! Every challengeable capability URI has one definition: the minimum case
//! count, the pass threshold, the retry ceiling and the cooldown floor. A
//! protocol URI's definition is computed from its §7.3.4.3 row; an
//! identifier-scoped URI's is signed by its definer and fetched. Until the
//! fetch path ships, [`ProtocolOnlyDefinitions`] is the only source, and it
//! refuses every identifier-scoped URI with [`DefinitionError::Unavailable`].

use sha2::{Digest, Sha256};

use scp_event_log::Ed25519Signature;

use super::TrustError;
use super::capability_registry::{Grading, MinCases, lookup_protocol_capability};
use super::capability_uri::CapabilityUri;
use super::challenge::{MAX_CAPABILITY_DESCRIPTION_BYTES, TOTAL_WEIGHT_BPS};
use crate::crypto::canonical::{CanonicalField, canonical_hash_bytes};

/// Domain separator of the definition preimage `Def` (`09-security-model.md`
/// §9.18.2).
const DOMAIN_CAPABILITY_DEFINITION_V1: &[u8] = b"SCP-CAPABILITY-DEFINITION-V1:";

/// The standard one capability URI defines (spec 07 §7.3.4.6).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CapabilityDefinition {
    /// The URI the definition governs, in canonical form.
    pub capability_uri: String,
    /// The minimum number of test cases.
    pub min_cases: MinCases,
    /// The pass threshold in basis points, `1..=10000`. A request and a
    /// record carry exactly this value.
    pub pass_threshold_bps: u32,
    /// The retry ceiling. Any `u32`: the protocol sets no ceiling.
    pub max_retries: u32,
    /// The cooldown floor in seconds. Any `u32`: the protocol sets no
    /// ceiling.
    pub cooldown_secs: u32,
    /// UTF-8, at most `MAX_CAPABILITY_DESCRIPTION_BYTES`.
    pub description: String,
}

/// A definition its definer signed (identifier-scoped URIs only).
///
/// Spec 07 types the signature `P256Signature`; the code signs Ed25519 until
/// the P-256 move, as every other challenge signature does.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SignedCapabilityDefinition {
    /// The signed definition.
    pub definition: CapabilityDefinition,
    /// The definer's `#active` signature over [`CapabilityDefinition::digest`].
    pub definer_signature: Ed25519Signature,
}

impl CapabilityDefinition {
    /// The protocol row's definition for `uri` (§7.3.4.3), with the row's
    /// registry description; `None` when `uri` names no protocol row.
    #[must_use]
    pub fn protocol_row(uri: &str) -> Option<(Self, Grading)> {
        let entry = lookup_protocol_capability(uri)?;
        let standard = entry.challenge?;
        Some((
            Self {
                capability_uri: uri.to_owned(),
                min_cases: standard.min_cases,
                pass_threshold_bps: standard.pass_threshold_bps,
                max_retries: standard.max_retries,
                cooldown_secs: standard.cooldown_secs,
                description: entry.description.clone(),
            },
            standard.grading,
        ))
    }

    /// The preimage `Def` of §7.3.4.6.
    ///
    /// # Errors
    ///
    /// [`TrustError::CanonicalizationFailed`] if a field exceeds `u32::MAX`
    /// bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, TrustError> {
        let (tag, min) = match self.min_cases {
            MinCases::Total(n) => (0u8, n),
            MinCases::PerCategory(n) => (1u8, n),
        };
        canonical_hash_bytes(
            DOMAIN_CAPABILITY_DEFINITION_V1,
            &[
                CanonicalField::VarBytes(self.capability_uri.as_bytes()),
                CanonicalField::U8(tag),
                CanonicalField::U32(min),
                CanonicalField::U32(self.pass_threshold_bps),
                CanonicalField::U32(self.max_retries),
                CanonicalField::U32(self.cooldown_secs),
                CanonicalField::VarBytes(self.description.as_bytes()),
            ],
        )
        .map_err(|e| TrustError::CanonicalizationFailed {
            reason: format!("capability definition preimage failed: {e}"),
        })
    }

    /// `definition_digest = SHA-256(Def)`.
    ///
    /// # Errors
    ///
    /// As [`canonical_bytes`](Self::canonical_bytes).
    pub fn digest(&self) -> Result<[u8; 32], TrustError> {
        Ok(Sha256::digest(self.canonical_bytes()?).into())
    }

    /// Checks the §7.3.4.6 validity rules.
    ///
    /// # Errors
    ///
    /// [`DefinitionError::Unavailable`] naming the broken rule: a party
    /// treats an invalid definition as one it cannot obtain.
    pub fn validate(&self) -> Result<(), DefinitionError> {
        let invalid = |reason: String| {
            Err(DefinitionError::Unavailable {
                uri: self.capability_uri.clone(),
                reason,
            })
        };
        let min = match self.min_cases {
            MinCases::Total(n) | MinCases::PerCategory(n) => n,
        };
        if min == 0 {
            return invalid("min_cases is 0".to_owned());
        }
        if self.pass_threshold_bps == 0 || self.pass_threshold_bps > TOTAL_WEIGHT_BPS {
            return invalid(format!(
                "pass_threshold_bps {} is outside 1..={TOTAL_WEIGHT_BPS}",
                self.pass_threshold_bps
            ));
        }
        if self.description.len() > MAX_CAPABILITY_DESCRIPTION_BYTES {
            return invalid(format!(
                "description of {} bytes exceeds {MAX_CAPABILITY_DESCRIPTION_BYTES}",
                self.description.len()
            ));
        }
        Ok(())
    }
}

/// Why no usable definition was obtained.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DefinitionError {
    /// No valid definition can be obtained: an outage, not a judgment on a
    /// subject.
    #[error("capability definition unavailable for {uri}: {reason}")]
    Unavailable {
        /// The capability URI.
        uri: String,
        /// Why none was obtained.
        reason: String,
    },
    /// The URI names a standard that outputs cannot grade (§7.3.4.7) or a
    /// system capability.
    #[error("capability {uri} is not gradable from outputs")]
    NotGradable {
        /// The capability URI.
        uri: String,
    },
    /// Two validly signed definitions for the URI differ.
    #[error("capability definition equivocation for {uri}")]
    Equivocation {
        /// The capability URI.
        uri: String,
    },
}

impl From<DefinitionError> for TrustError {
    fn from(error: DefinitionError) -> Self {
        match error {
            DefinitionError::Unavailable { uri, .. } => {
                Self::CapabilityDefinitionUnavailable { uri }
            }
            DefinitionError::NotGradable { uri } => Self::StandardNotGradable { uri },
            DefinitionError::Equivocation { uri } => Self::DefinitionEquivocation { uri },
        }
    }
}

/// Where a party obtains capability definitions (spec 07 §7.3.4.6).
///
/// Synchronous and object-safe, so a check that holds `&dyn
/// CapabilityDefinitionSource` runs inside an actor turn.
pub trait CapabilityDefinitionSource: Send + Sync {
    /// The valid, gradable definition for `uri`.
    ///
    /// # Errors
    ///
    /// [`DefinitionError`]; an implementation never substitutes a default.
    fn definition(&self, uri: &CapabilityUri) -> Result<CapabilityDefinition, DefinitionError>;
}

/// The protocol rows of §7.3.4.3, and nothing else.
///
/// Identifier-scoped URIs get [`DefinitionError::Unavailable`] until the
/// definer fetch path ships; system URIs and the five §7.3.4.7 rows get
/// [`DefinitionError::NotGradable`].
#[derive(Debug, Clone, Copy, Default)]
pub struct ProtocolOnlyDefinitions;

impl CapabilityDefinitionSource for ProtocolOnlyDefinitions {
    fn definition(&self, uri: &CapabilityUri) -> Result<CapabilityDefinition, DefinitionError> {
        let text = uri.to_string();
        match uri {
            CapabilityUri::System { .. } => Err(DefinitionError::NotGradable { uri: text }),
            CapabilityUri::IdentifierScoped { .. } => Err(DefinitionError::Unavailable {
                uri: text,
                reason: "no definer fetch path: only protocol rows are available".to_owned(),
            }),
            CapabilityUri::Protocol { .. } => {
                let Some((definition, grading)) = CapabilityDefinition::protocol_row(&text) else {
                    return Err(DefinitionError::Unavailable {
                        uri: text,
                        reason: "not a protocol row".to_owned(),
                    });
                };
                if grading == Grading::Refused {
                    return Err(DefinitionError::NotGradable { uri: text });
                }
                definition.validate()?;
                Ok(definition)
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn parse(uri: &str) -> CapabilityUri {
        uri.parse().unwrap()
    }

    /// Spec 25 Vector 65: the fixture definition's `Def` and digest.
    #[test]
    fn vector_65_capability_definition() {
        let definition = CapabilityDefinition {
            capability_uri: "scp:tfgiiao36zlseo2tzfoi32knfx6topped3qloxcsube5gdvfrqgq:capability:schema-validation/v1".to_owned(),
            min_cases: MinCases::Total(1),
            pass_threshold_bps: 8000,
            max_retries: 2,
            cooldown_secs: 3600,
            description: "Fixture definition for spec 25 vectors 59-62.".to_owned(),
        };
        let bytes = definition.canonical_bytes().unwrap();
        assert_eq!(bytes.len(), 187);
        assert_eq!(
            hex::encode(definition.digest().unwrap()),
            "1947de3173cb08e14fa71bd41bb256274ba2b62e0d0d9e73b83af1a971ee8f67"
        );
    }

    /// Protocol rows: the digests the spec 07 table commits to.
    #[test]
    fn protocol_row_definition_digest_kat() {
        for (uri, len, digest) in [
            (
                "scp:capability:schema-validation/v1",
                163,
                "c8cf8deed8911cd50cf388477442e52e9b7541509e9eeb010bf2c70341603002",
            ),
            (
                "scp:capability:content-safety/v1",
                150,
                "6448edfbdc8ac611321441a564dd0951a00e4c102e01f6b34f1ad3e791100de8",
            ),
        ] {
            let definition = ProtocolOnlyDefinitions.definition(&parse(uri)).unwrap();
            assert_eq!(definition.canonical_bytes().unwrap().len(), len, "{uri}");
            assert_eq!(hex::encode(definition.digest().unwrap()), digest, "{uri}");
        }
    }

    #[test]
    fn identifier_scoped_uri_fails_closed() {
        let uri = parse(
            "scp:tfgiiao36zlseo2tzfoi32knfx6topped3qloxcsube5gdvfrqgq:capability:schema-validation/v1",
        );
        let err = ProtocolOnlyDefinitions.definition(&uri).unwrap_err();
        assert!(
            matches!(err, DefinitionError::Unavailable { .. }),
            "{err:?}"
        );
        assert!(matches!(
            TrustError::from(err),
            TrustError::CapabilityDefinitionUnavailable { .. }
        ));
    }

    #[test]
    fn refused_rows_and_system_uris_are_not_gradable() {
        for uri in [
            "scp:capability:latency-compliance/v1",
            "scp:capability:rate-limit-compliance/v1",
            "scp:capability:cost-awareness/v1",
            "scp:capability:code-generation/v1",
            "scp:capability:code-review/v1",
            "scp:system:key-rotation",
        ] {
            let err = ProtocolOnlyDefinitions.definition(&parse(uri)).unwrap_err();
            assert!(matches!(err, DefinitionError::NotGradable { .. }), "{uri}");
        }
    }

    /// A named edit of one definition field.
    type Mutation = (&'static str, fn(&mut CapabilityDefinition));

    #[test]
    fn definition_validation_refuses_out_of_bound_limits() {
        let (good, _) =
            CapabilityDefinition::protocol_row("scp:capability:schema-validation/v1").unwrap();
        good.validate().unwrap();
        let mutations: [Mutation; 5] = [
            ("min 0", |d| d.min_cases = MinCases::Total(0)),
            ("per-category min 0", |d| {
                d.min_cases = MinCases::PerCategory(0);
            }),
            ("threshold 0", |d| d.pass_threshold_bps = 0),
            ("threshold above 10000", |d| d.pass_threshold_bps = 10_001),
            ("description too long", |d| {
                d.description = "x".repeat(MAX_CAPABILITY_DESCRIPTION_BYTES + 1);
            }),
        ];
        for (name, mutate) in mutations {
            let mut d = good.clone();
            mutate(&mut d);
            assert!(
                matches!(d.validate(), Err(DefinitionError::Unavailable { .. })),
                "{name}"
            );
        }
        let mut edge = good;
        edge.max_retries = u32::MAX;
        edge.cooldown_secs = u32::MAX;
        edge.pass_threshold_bps = TOTAL_WEIGHT_BPS;
        edge.description = "x".repeat(MAX_CAPABILITY_DESCRIPTION_BYTES);
        edge.validate().unwrap();
    }
}
