//! Push notification registration types for SCP.
//!
//! `22-human-readable-addressing.md` §22.11.4 defines the `PushRegistration`
//! and `PushDeregistration` wire tables, and the two push tables of
//! `09-security-model.md` §9.5.2 define their signature preimages.
//! `10-infrastructure-and-self-hosting.md` §10.7.1 states how a relay verifies
//! and stores them.
//!
//! This module owns the only code that builds a push preimage:
//! [`push_registration_signing_bytes`] and
//! [`push_deregistration_signing_bytes`]. The signer and the relay's
//! verifier both call them, and each takes the relay URL whose §9.18.2
//! canonical form ends the preimage, so a signature binds to one relay.
//!
//! Push payloads are fully opaque: the relay sends each platform the wake
//! signal that the wake-signal table of spec §10.7.1 step 5 gives, and no
//! context ID, sender, `registrant` (the identity that signed the
//! registration) or message preview. Apple/Google learn only that
//! the device received a notification at a specific time.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use scp_did::{DID, RelayEndpoint, RelayUrlError, canonical_relay_url};

use crate::crypto::canonical::{CanonicalError, CanonicalField, canonical_hash_bytes};
use crate::serde_util::{serde_bounded_bytes, serde_signature_64};

// ---------------------------------------------------------------------------
// Domain separators (§9.18.2)
// ---------------------------------------------------------------------------

/// Signature-preimage separator of `PushRegistration` (§9.5.2).
pub const PUSH_REGISTER_DOMAIN: &str = "SCP-PUSH-REGISTER-V1:";

/// Signature-preimage separator of `PushDeregistration` (§9.5.2).
pub const PUSH_DEREGISTER_DOMAIN: &str = "SCP-PUSH-DEREGISTER-V1:";

/// Routing-derivation prefix of a relay's reserved push routing ID (§9.18.2).
///
/// A routing-derivation prefix, not a §9.5.1 signature-preimage separator:
/// the derivation is `SHA-256(prefix || canonical relay_url)` with no length
/// prefix and no separator byte.
pub const PUSH_ROUTING_PREFIX: &str = "scp-push-registration";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A push message that cannot be decoded, encoded, or signed.
///
/// A relay that offers push answers every variant that a received message
/// causes with `4060` `PUSH_REGISTRATION_REJECTED` (ADR-004: "the message does
/// not decode, or a registration's `routing_ids` list is empty").
/// [`PushMessageError::InvalidRelayUrl`] names a relay URL the caller
/// supplied, never a field of the message.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PushMessageError {
    /// The bytes are not a `MessagePack` encoding of the message.
    #[error("push message does not decode: {0}")]
    Decode(String),
    /// The message decoded but bytes followed it.
    #[error("push message is followed by {count} trailing bytes")]
    TrailingBytes {
        /// Number of bytes after the encoded message.
        count: usize,
    },
    /// The message could not be `MessagePack`-encoded.
    #[error("push message does not encode: {0}")]
    Encode(String),
    /// A `PushRegistration` lists no routing ID (§22.11.4: an empty list is
    /// invalid).
    #[error("push registration lists no routing ID")]
    EmptyRoutingIds,
    /// A `PushRegistration` lists more routing IDs than a 4-byte element count
    /// encodes.
    #[error("push registration lists {count} routing IDs, more than a BE32 count encodes")]
    TooManyRoutingIds {
        /// Number of routing IDs listed.
        count: usize,
    },
    /// The `registrant` field is empty.
    #[error("push message registrant is empty")]
    EmptyRegistrant,
    /// The `token` field is empty, so the message names no device.
    #[error("push message token is empty")]
    EmptyToken,
    /// The relay URL has no §9.18.2 canonical form.
    #[error("invalid relay URL: {0}")]
    InvalidRelayUrl(#[from] RelayUrlError),
    /// A length-prefixed field exceeded the 4-byte length prefix (§9.5.1).
    #[error("push preimage field too large: {0}")]
    FieldTooLarge(#[from] CanonicalError),
}

// ---------------------------------------------------------------------------
// PushPlatform
// ---------------------------------------------------------------------------

/// Push notification service platform.
///
/// Maps to the `platform` field of both push messages (§22.11.4). The 1-byte
/// tag values are used in the §9.5.2 signature preimages:
/// `0x01` = APNS, `0x02` = FCM, `0x03` = `WebPush`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PushPlatform {
    /// Apple Push Notification service (iOS, macOS).
    Apns,
    /// Firebase Cloud Messaging (Android).
    Fcm,
    /// Web Push API (browsers).
    WebPush,
}

impl PushPlatform {
    /// Returns the 1-byte tag used in the canonical signed structure.
    #[must_use]
    pub const fn tag_byte(self) -> u8 {
        match self {
            Self::Apns => 0x01,
            Self::Fcm => 0x02,
            Self::WebPush => 0x03,
        }
    }
}

impl std::fmt::Display for PushPlatform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Apns => write!(f, "APNS"),
            Self::Fcm => write!(f, "FCM"),
            Self::WebPush => write!(f, "WebPush"),
        }
    }
}

// ---------------------------------------------------------------------------
// PushRegistration (§22.11.4)
// ---------------------------------------------------------------------------

/// Push notification registration message (§22.11.4).
///
/// A client publishes it to a relay's reserved push routing ID
/// ([`push_registration_routing_id`]). The relay stores it under the
/// registration key (`registrant`, `platform`, `token`) and wakes `token`
/// when a blob arrives at any listed routing ID (§10.7.1).
///
/// The signature covers [`push_registration_signing_bytes`], which reads every
/// field except `signature`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushRegistration {
    /// The registering identity's identifier, the only identity field.
    ///
    /// §22.11.4 types this field as the `Identifier` SCP-308 defines, and
    /// §9.5.2 encodes it as the 56-byte `scp:` text form. Until SCP-315, the
    /// slice S12 cut-over of every identity path to the key-event log,
    /// retypes it, the field holds today's `did:dht` string, so the code lags
    /// the spec here. The retype changes the bytes inside the field's 4-byte
    /// length prefix and leaves the `SCP-PUSH-REGISTER-V1:` separator unchanged.
    pub registrant: DID,
    /// Push service platform (APNS, FCM, or `WebPush`).
    pub platform: PushPlatform,
    /// Platform-specific device token.
    #[serde(with = "serde_bounded_bytes")]
    pub token: Vec<u8>,
    /// The relay routing IDs to wake this device for: each context's
    /// `context_routing_id` and the device's own `pseudonym_routing_id`
    /// (§9.10.4). Never empty.
    #[serde(with = "serde_routing_ids")]
    pub routing_ids: Vec<[u8; 32]>,
    /// Registration timestamp (Unix seconds).
    pub timestamp: u64,
    /// P-256 signature by the registrant's `Current` `#active` key over the
    /// SHA-256 of [`push_registration_signing_bytes`].
    #[serde(with = "serde_signature_64")]
    pub signature: [u8; 64],
}

impl PushRegistration {
    /// Checks the §22.11.4 field rules a decoded or outgoing registration
    /// must meet. It does not check the signature.
    ///
    /// # Errors
    ///
    /// Returns [`PushMessageError::EmptyRegistrant`],
    /// [`PushMessageError::EmptyToken`], [`PushMessageError::EmptyRoutingIds`]
    /// or [`PushMessageError::TooManyRoutingIds`].
    pub fn validate(&self) -> Result<(), PushMessageError> {
        validate_common(&self.registrant, &self.token)?;
        routing_id_count(&self.routing_ids).map(|_| ())
    }

    /// Decodes a registration from its `MessagePack` wire bytes and validates it.
    ///
    /// # Errors
    ///
    /// Returns [`PushMessageError::Decode`] or
    /// [`PushMessageError::TrailingBytes`] for bytes that are not exactly one
    /// encoded registration, and any error of [`Self::validate`].
    pub fn from_msgpack(bytes: &[u8]) -> Result<Self, PushMessageError> {
        let msg: Self = decode_exact(bytes)?;
        msg.validate()?;
        Ok(msg)
    }

    /// Validates the registration and encodes it as `MessagePack` with named
    /// fields.
    ///
    /// # Errors
    ///
    /// Returns any error of [`Self::validate`], or
    /// [`PushMessageError::Encode`].
    pub fn to_msgpack(&self) -> Result<Vec<u8>, PushMessageError> {
        self.validate()?;
        rmp_serde::to_vec_named(self).map_err(|e| PushMessageError::Encode(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// PushDeregistration (§22.11.4)
// ---------------------------------------------------------------------------

/// Push notification deregistration message (§22.11.4).
///
/// Removes the one registration whose key is (`registrant`, `platform`,
/// `token`), so deregistering one device leaves the identity's other devices
/// registered (§10.7.1).
///
/// The signature covers [`push_deregistration_signing_bytes`], which reads
/// every field except `signature`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushDeregistration {
    /// The deregistering identity's identifier, the only identity field.
    ///
    /// §22.11.4 types this field as the `Identifier` SCP-308 defines, and
    /// §9.5.2 encodes it as the 56-byte `scp:` text form. Until SCP-315, the
    /// slice S12 cut-over of every identity path to the key-event log,
    /// retypes it, the field holds today's `did:dht` string, so the code lags
    /// the spec here. The retype changes the bytes inside the field's 4-byte
    /// length prefix and leaves the `SCP-PUSH-DEREGISTER-V1:` separator unchanged.
    pub registrant: DID,
    /// Push service platform to deregister from.
    pub platform: PushPlatform,
    /// The device token whose registration is removed.
    #[serde(with = "serde_bounded_bytes")]
    pub token: Vec<u8>,
    /// Deregistration timestamp (Unix seconds).
    pub timestamp: u64,
    /// P-256 signature by the registrant's `Current` `#active` key over the
    /// SHA-256 of [`push_deregistration_signing_bytes`].
    #[serde(with = "serde_signature_64")]
    pub signature: [u8; 64],
}

impl PushDeregistration {
    /// Checks the §22.11.4 field rules a decoded or outgoing deregistration
    /// must meet. It does not check the signature.
    ///
    /// # Errors
    ///
    /// Returns [`PushMessageError::EmptyRegistrant`] or
    /// [`PushMessageError::EmptyToken`].
    pub fn validate(&self) -> Result<(), PushMessageError> {
        validate_common(&self.registrant, &self.token)
    }

    /// Decodes a deregistration from its `MessagePack` wire bytes and validates
    /// it.
    ///
    /// # Errors
    ///
    /// Returns [`PushMessageError::Decode`] or
    /// [`PushMessageError::TrailingBytes`] for bytes that are not exactly one
    /// encoded deregistration, and any error of [`Self::validate`].
    pub fn from_msgpack(bytes: &[u8]) -> Result<Self, PushMessageError> {
        let msg: Self = decode_exact(bytes)?;
        msg.validate()?;
        Ok(msg)
    }

    /// Validates the deregistration and encodes it as `MessagePack` with named
    /// fields.
    ///
    /// # Errors
    ///
    /// Returns any error of [`Self::validate`], or
    /// [`PushMessageError::Encode`].
    pub fn to_msgpack(&self) -> Result<Vec<u8>, PushMessageError> {
        self.validate()?;
        rmp_serde::to_vec_named(self).map_err(|e| PushMessageError::Encode(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Canonical signing bytes (§9.5.2)
// ---------------------------------------------------------------------------

/// Builds the §9.5.2 `PushRegistration` signature preimage for the relay at
/// `relay_url`.
///
/// The bytes are `"SCP-PUSH-REGISTER-V1:" || BE32(len) || registrant ||
/// platform_tag || BE32(len) || token || BE32(count) || routing_ids ||
/// BE64(timestamp) || BE32(len) || canonical relay_url`. `signature` is not
/// read. The signer signs, and the verifier checks, the SHA-256 of these
/// bytes. `relay_url` is canonicalized with [`canonical_relay_url`] first, so
/// every spelling of one relay URL yields one preimage.
///
/// This function and [`push_deregistration_signing_bytes`] are the only code
/// that builds a push preimage.
///
/// # Errors
///
/// Returns any error of [`PushRegistration::validate`],
/// [`PushMessageError::InvalidRelayUrl`], or
/// [`PushMessageError::FieldTooLarge`].
pub fn push_registration_signing_bytes(
    registration: &PushRegistration,
    relay_url: &str,
) -> Result<Vec<u8>, PushMessageError> {
    validate_common(&registration.registrant, &registration.token)?;
    let count = routing_id_count(&registration.routing_ids)?;
    let url = canonical_relay_url(relay_url)?;

    let mut fields = Vec::with_capacity(6 + registration.routing_ids.len());
    fields.push(CanonicalField::VarBytes(registration.registrant.as_bytes()));
    fields.push(CanonicalField::U8(registration.platform.tag_byte()));
    fields.push(CanonicalField::VarBytes(&registration.token));
    fields.push(CanonicalField::U32(count));
    fields.extend(registration.routing_ids.iter().map(CanonicalField::Fixed32));
    fields.push(CanonicalField::U64(registration.timestamp));
    fields.push(CanonicalField::VarBytes(url.as_bytes()));

    Ok(canonical_hash_bytes(
        PUSH_REGISTER_DOMAIN.as_bytes(),
        &fields,
    )?)
}

/// Builds the §9.5.2 `PushDeregistration` signature preimage for the relay at
/// `relay_url`.
///
/// The bytes are `"SCP-PUSH-DEREGISTER-V1:" || BE32(len) || registrant ||
/// platform_tag || BE32(len) || token || BE64(timestamp) || BE32(len) ||
/// canonical relay_url`. `signature` is not read. `relay_url` is canonicalized
/// with [`canonical_relay_url`] first.
///
/// # Errors
///
/// Returns any error of [`PushDeregistration::validate`],
/// [`PushMessageError::InvalidRelayUrl`], or
/// [`PushMessageError::FieldTooLarge`].
pub fn push_deregistration_signing_bytes(
    deregistration: &PushDeregistration,
    relay_url: &str,
) -> Result<Vec<u8>, PushMessageError> {
    deregistration.validate()?;
    let url = canonical_relay_url(relay_url)?;

    Ok(canonical_hash_bytes(
        PUSH_DEREGISTER_DOMAIN.as_bytes(),
        &[
            CanonicalField::VarBytes(deregistration.registrant.as_bytes()),
            CanonicalField::U8(deregistration.platform.tag_byte()),
            CanonicalField::VarBytes(&deregistration.token),
            CanonicalField::U64(deregistration.timestamp),
            CanonicalField::VarBytes(url.as_bytes()),
        ],
    )?)
}

// ---------------------------------------------------------------------------
// Reserved routing ID and canonical relay URL (§9.18.2)
// ---------------------------------------------------------------------------

/// Derives the relay's reserved push routing ID,
/// `SHA-256("scp-push-registration" || canonical relay_url)` (§9.18.2).
///
/// # Errors
///
/// Returns [`PushMessageError::InvalidRelayUrl`] when `relay_url` has no
/// canonical form.
pub fn push_registration_routing_id(relay_url: &str) -> Result<[u8; 32], PushMessageError> {
    Ok(routing_id_of_canonical(&canonical_relay_url(relay_url)?))
}

/// [`push_registration_routing_id`] for a [`RelayEndpoint`], which already
/// holds the §9.18.2 canonical form, so the derivation cannot fail.
#[must_use]
pub fn relay_endpoint_push_routing_id(endpoint: &RelayEndpoint) -> [u8; 32] {
    routing_id_of_canonical(endpoint.as_str())
}

/// `SHA-256("scp-push-registration" || canonical)` over a URL already in its
/// §9.18.2 canonical form.
fn routing_id_of_canonical(canonical: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PUSH_ROUTING_PREFIX.as_bytes());
    hasher.update(canonical.as_bytes());
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn validate_common(registrant: &DID, token: &[u8]) -> Result<(), PushMessageError> {
    if registrant.is_empty() {
        return Err(PushMessageError::EmptyRegistrant);
    }
    if token.is_empty() {
        return Err(PushMessageError::EmptyToken);
    }
    Ok(())
}

/// Returns the §9.5.1 element count of a non-empty routing-ID list.
fn routing_id_count(routing_ids: &[[u8; 32]]) -> Result<u32, PushMessageError> {
    if routing_ids.is_empty() {
        return Err(PushMessageError::EmptyRoutingIds);
    }
    u32::try_from(routing_ids.len()).map_err(|_| PushMessageError::TooManyRoutingIds {
        count: routing_ids.len(),
    })
}

/// Decodes exactly one `MessagePack` value of type `T`, rejecting trailing bytes
/// so that unsigned bytes never ride along with a signed message.
fn decode_exact<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, PushMessageError> {
    let mut reader = bytes;
    let mut de = rmp_serde::Deserializer::new(&mut reader);
    let msg = T::deserialize(&mut de).map_err(|e| PushMessageError::Decode(e.to_string()))?;
    if !reader.is_empty() {
        return Err(PushMessageError::TrailingBytes {
            count: reader.len(),
        });
    }
    Ok(msg)
}

/// Serde for `Vec<[u8; 32]>`: a sequence of 32-byte `MessagePack` `bin`
/// values, each length-checked on decode.
mod serde_routing_ids {
    use serde::de::{SeqAccess, Visitor};
    use serde::ser::SerializeSeq;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use crate::serde_util::{BOUNDED_BYTES_MAX, serde_hash_32};

    /// Most routing IDs a decoder accepts: one 32-byte ID per byte the
    /// bounded-bytes cap admits, so the list never outgrows a relay blob.
    const MAX_ROUTING_IDS: usize = BOUNDED_BYTES_MAX / 32;

    struct Ref<'a>(&'a [u8; 32]);

    impl Serialize for Ref<'_> {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            serde_hash_32::serialize(self.0, s)
        }
    }

    #[derive(Deserialize)]
    struct Owned(#[serde(with = "serde_hash_32")] [u8; 32]);

    pub fn serialize<S: Serializer>(ids: &[[u8; 32]], s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(ids.len()))?;
        for id in ids {
            seq.serialize_element(&Ref(id))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<[u8; 32]>, D::Error> {
        struct IdsVisitor;

        impl<'de> Visitor<'de> for IdsVisitor {
            type Value = Vec<[u8; 32]>;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "a list of at most {MAX_ROUTING_IDS} 32-byte routing IDs")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let hint = seq.size_hint().unwrap_or(0);
                if hint > MAX_ROUTING_IDS {
                    return Err(serde::de::Error::custom(format!(
                        "routing ID list declares {hint} entries, limit is {MAX_ROUTING_IDS}"
                    )));
                }
                let mut out = Vec::with_capacity(hint);
                while let Some(Owned(id)) = seq.next_element()? {
                    if out.len() >= MAX_ROUTING_IDS {
                        return Err(serde::de::Error::custom(format!(
                            "routing ID list exceeds {MAX_ROUTING_IDS} entries"
                        )));
                    }
                    out.push(id);
                }
                Ok(out)
            }
        }

        d.deserialize_seq(IdsVisitor)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    const REGISTRANT: &str = "did:dht:z6Mkp5HpCyHSafDFTtqRzbKWJsxVLaGz1sQojsLVQfHQ9u8m";

    fn registration(routing_ids: Vec<[u8; 32]>) -> PushRegistration {
        PushRegistration {
            registrant: DID::from(REGISTRANT),
            platform: PushPlatform::Apns,
            token: vec![0xA1, 0xB2, 0xC3],
            routing_ids,
            timestamp: 1_700_000_000,
            signature: [0x55; 64],
        }
    }

    fn deregistration() -> PushDeregistration {
        PushDeregistration {
            registrant: DID::from(REGISTRANT),
            platform: PushPlatform::Fcm,
            token: vec![0xD4, 0xE5],
            timestamp: 1_700_000_100,
            signature: [0x66; 64],
        }
    }

    #[test]
    fn push_platform_tag_bytes() {
        assert_eq!(PushPlatform::Apns.tag_byte(), 0x01);
        assert_eq!(PushPlatform::Fcm.tag_byte(), 0x02);
        assert_eq!(PushPlatform::WebPush.tag_byte(), 0x03);
    }

    #[test]
    fn push_platform_display() {
        assert_eq!(PushPlatform::Apns.to_string(), "APNS");
        assert_eq!(PushPlatform::Fcm.to_string(), "FCM");
        assert_eq!(PushPlatform::WebPush.to_string(), "WebPush");
    }

    #[test]
    fn registration_msgpack_roundtrip_preserves_every_field() {
        let reg = registration(vec![[1; 32], [2; 32]]);
        let decoded = PushRegistration::from_msgpack(&reg.to_msgpack().unwrap()).unwrap();
        assert_eq!(decoded, reg);
    }

    #[test]
    fn deregistration_msgpack_roundtrip_preserves_every_field() {
        let dereg = deregistration();
        let decoded = PushDeregistration::from_msgpack(&dereg.to_msgpack().unwrap()).unwrap();
        assert_eq!(decoded, dereg);
    }

    #[test]
    fn decode_registration_with_zero_routing_ids_returns_typed_error() {
        // Encode around `to_msgpack`, which refuses an empty list itself.
        let bytes = rmp_serde::to_vec_named(&registration(Vec::new())).unwrap();
        assert_eq!(
            PushRegistration::from_msgpack(&bytes),
            Err(PushMessageError::EmptyRoutingIds)
        );
    }

    #[test]
    fn encode_registration_with_zero_routing_ids_is_refused() {
        assert_eq!(
            registration(Vec::new()).to_msgpack(),
            Err(PushMessageError::EmptyRoutingIds)
        );
    }

    #[test]
    fn decode_rejects_empty_token_and_empty_registrant() {
        let mut reg = registration(vec![[1; 32]]);
        reg.token.clear();
        let bytes = rmp_serde::to_vec_named(&reg).unwrap();
        assert_eq!(
            PushRegistration::from_msgpack(&bytes),
            Err(PushMessageError::EmptyToken)
        );

        let mut dereg = deregistration();
        dereg.registrant = DID::from("");
        let bytes = rmp_serde::to_vec_named(&dereg).unwrap();
        assert_eq!(
            PushDeregistration::from_msgpack(&bytes),
            Err(PushMessageError::EmptyRegistrant)
        );
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let mut bytes = registration(vec![[1; 32]]).to_msgpack().unwrap();
        bytes.push(0xC0);
        assert_eq!(
            PushRegistration::from_msgpack(&bytes),
            Err(PushMessageError::TrailingBytes { count: 1 })
        );
    }

    #[test]
    fn decode_rejects_garbage_and_wrong_length_fields() {
        // A field-by-field registration whose byte fields take any length.
        #[derive(Serialize)]
        struct Raw<'a> {
            registrant: &'a str,
            platform: PushPlatform,
            #[serde(with = "serde_bytes")]
            token: &'a [u8],
            routing_ids: Vec<serde_bytes::ByteBuf>,
            timestamp: u64,
            #[serde(with = "serde_bytes")]
            signature: &'a [u8],
        }

        assert!(matches!(
            PushRegistration::from_msgpack(&[0xFF, 0x00]),
            Err(PushMessageError::Decode(_))
        ));
        assert!(matches!(
            PushDeregistration::from_msgpack(&[]),
            Err(PushMessageError::Decode(_))
        ));

        // A 31-byte routing ID and a 63-byte signature both fail to decode.
        let short_id = Raw {
            registrant: REGISTRANT,
            platform: PushPlatform::Apns,
            token: &[1],
            routing_ids: vec![serde_bytes::ByteBuf::from(vec![0u8; 31])],
            timestamp: 1,
            signature: &[0u8; 64],
        };
        let bytes = rmp_serde::to_vec_named(&short_id).unwrap();
        assert!(matches!(
            PushRegistration::from_msgpack(&bytes),
            Err(PushMessageError::Decode(_))
        ));
        let short_sig = Raw {
            routing_ids: vec![serde_bytes::ByteBuf::from(vec![0u8; 32])],
            signature: &[0u8; 63],
            ..short_id
        };
        let bytes = rmp_serde::to_vec_named(&short_sig).unwrap();
        assert!(matches!(
            PushRegistration::from_msgpack(&bytes),
            Err(PushMessageError::Decode(_))
        ));
        // Control: the same encoding with correct lengths decodes.
        let correct = Raw {
            signature: &[0u8; 64],
            ..short_sig
        };
        let bytes = rmp_serde::to_vec_named(&correct).unwrap();
        assert!(PushRegistration::from_msgpack(&bytes).is_ok());
    }

    #[test]
    fn signing_bytes_refuse_invalid_messages() {
        assert_eq!(
            push_registration_signing_bytes(&registration(Vec::new()), "wss://r.example"),
            Err(PushMessageError::EmptyRoutingIds)
        );
        let mut dereg = deregistration();
        dereg.token.clear();
        assert_eq!(
            push_deregistration_signing_bytes(&dereg, "wss://r.example"),
            Err(PushMessageError::EmptyToken)
        );
        assert_eq!(
            push_registration_signing_bytes(&registration(vec![[1; 32]]), "https://r.example"),
            Err(PushMessageError::InvalidRelayUrl(
                RelayUrlError::UnsupportedScheme
            ))
        );
    }

    #[test]
    fn signing_bytes_ignore_the_signature_field() {
        let a = registration(vec![[1; 32]]);
        let mut b = a.clone();
        b.signature = [0; 64];
        assert_eq!(
            push_registration_signing_bytes(&a, "wss://r.example").unwrap(),
            push_registration_signing_bytes(&b, "wss://r.example").unwrap()
        );
    }

    /// Two registrations hold the same routing-ID bytes, split as two
    /// elements in one and as one element in the other, with the second
    /// element's leading bytes moved into the following timestamp. The
    /// §9.5.1 element count keeps their preimages apart.
    #[test]
    fn routing_id_lists_that_split_differently_produce_different_preimages() {
        let r1 = [0x11; 32];
        let mut r2 = [0x22; 32];
        r2[..8].copy_from_slice(&1_700_000_000u64.to_be_bytes());
        let two = registration(vec![r1, r2]);
        let mut one = registration(vec![r1]);
        one.timestamp = u64::from_be_bytes(r2[..8].try_into().unwrap());

        let a = push_registration_signing_bytes(&two, "wss://r.example").unwrap();
        let b = push_registration_signing_bytes(&one, "wss://r.example").unwrap();
        assert_ne!(a, b);

        // The list starts after the separator, the registrant, the platform
        // tag and the token, and opens with its BE32 element count.
        let at = PUSH_REGISTER_DOMAIN.len() + 4 + REGISTRANT.len() + 1 + 4 + 3;
        assert_eq!(a[at..at + 4], 2u32.to_be_bytes());
        assert_eq!(b[at..at + 4], 1u32.to_be_bytes());
        // Without the count both would continue with the same 40 bytes.
        assert_eq!(a[at + 4..at + 44], b[at + 4..at + 44]);
    }

    #[test]
    fn registration_and_deregistration_preimages_never_coincide() {
        let reg = registration(vec![[1; 32]]);
        let dereg = PushDeregistration {
            registrant: reg.registrant.clone(),
            platform: reg.platform,
            token: reg.token.clone(),
            timestamp: reg.timestamp,
            signature: reg.signature,
        };
        assert_ne!(
            push_registration_signing_bytes(&reg, "wss://r.example").unwrap(),
            push_deregistration_signing_bytes(&dereg, "wss://r.example").unwrap()
        );
    }

    #[test]
    fn routing_id_is_equal_across_spellings_and_distinct_across_relays() {
        let a = push_registration_routing_id("WSS://Relay.Example:443/").unwrap();
        let b = push_registration_routing_id("wss://relay.example").unwrap();
        let c = push_registration_routing_id("wss://relay.example/scp/v1").unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
        let want: [u8; 32] = Sha256::digest(b"scp-push-registrationwss://relay.example").into();
        assert_eq!(a, want);
        assert_eq!(
            push_registration_routing_id("ftp://relay.example"),
            Err(PushMessageError::InvalidRelayUrl(
                RelayUrlError::UnsupportedScheme
            ))
        );
    }

    #[test]
    fn relay_endpoint_push_routing_id_matches_the_string_derivation() {
        let endpoint = RelayEndpoint::new("WSS://Relay.Example:443/scp/v1/").unwrap();
        assert_eq!(
            relay_endpoint_push_routing_id(&endpoint),
            push_registration_routing_id("wss://relay.example/scp/v1").unwrap()
        );
    }

    proptest! {
        #[test]
        fn registration_roundtrips_through_msgpack(
            token in proptest::collection::vec(any::<u8>(), 1..64),
            ids in proptest::collection::vec(any::<[u8; 32]>(), 1..8),
            timestamp in any::<u64>(),
            platform in prop_oneof![
                Just(PushPlatform::Apns),
                Just(PushPlatform::Fcm),
                Just(PushPlatform::WebPush)
            ],
        ) {
            let reg = PushRegistration {
                registrant: DID::from(REGISTRANT),
                platform,
                token,
                routing_ids: ids,
                timestamp,
                signature: [7; 64],
            };
            let bytes = reg.to_msgpack().unwrap();
            prop_assert_eq!(PushRegistration::from_msgpack(&bytes).unwrap(), reg);
        }

        #[test]
        fn decoding_arbitrary_bytes_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
            let _ = PushRegistration::from_msgpack(&bytes);
            let _ = PushDeregistration::from_msgpack(&bytes);
        }
    }
}
