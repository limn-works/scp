//! Indexed signatures and their verification (`09-security-model.md`
//! §9.7.4.2, "A root signature is an indexed signature group" and
//! "Signature form").
//!
//! An indexed signature is one entry of a key event's signature field: the
//! signature one named index contributes, in the form field 7 declares for
//! it. [`IndexedSignature::read`] reads one entry off the front of a
//! signature field and [`IndexedSignature::to_bytes`] writes it back, so the
//! event decoder walks the field one entry at a time (§9.10.12).
//! [`verify_indexed`] checks one entry against the key at its index and the
//! event's preimage digest `D`.

use scp_crypto::p256::{P256Error, P256PublicKey, verify_prehash_strict};
use sha2::{Digest, Sha256};

use crate::client_data::{ClientDataError, parse};
use crate::constants::{
    KEY_EVENT_CHALLENGE_SEPARATOR, MAX_AUTHENTICATOR_DATA_BYTES, MAX_CLIENT_DATA_JSON_BYTES,
    MIN_AUTHENTICATOR_DATA_BYTES, RAW_SIGNATURE_BYTES,
};
use crate::event::SignatureForm;

/// [`RAW_SIGNATURE_BYTES`] as an array length; 64 fits every `usize`.
const RAW_LEN: usize = RAW_SIGNATURE_BYTES as usize;
/// The length of `"SCP-KEY-EVENT-V1:" ‖ D`: the separator and the 32-byte
/// digest. Derived from the separator, so both copies in
/// [`key_event_challenge`] always fit.
const KEY_EVENT_CHALLENGE_LEN: usize = KEY_EVENT_CHALLENGE_SEPARATOR.len() + 32;

/// The `authenticatorData` byte that carries the flags (Web Authentication
/// Level 2 §6.1), which `MIN_AUTHENTICATOR_DATA_BYTES` guarantees exists.
const FLAGS_BYTE: usize = 32;
/// The user-presence flag, bit 0 of the flags byte.
const FLAG_USER_PRESENT: u8 = 0x01;
/// The user-verification flag, bit 2 of the flags byte.
const FLAG_USER_VERIFIED: u8 = 0x04;
/// The only `clientDataJSON` `type` a key-event assertion carries.
const ASSERTION_TYPE: &str = "webauthn.get";
/// A `BE32` length prefix.
const LENGTH_PREFIX_BYTES: usize = 4;

/// One indexed signature: the signature a named index contributes to its
/// group, in the form the preimage declares for that index (§9.7.4.2
/// field 7).
///
/// The index itself is not part of the value: field 6 of the signed
/// preimage names it, and the signature field carries the entries in that
/// order with no index of its own.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IndexedSignature {
    /// `SignatureForm::Raw`: a 64-byte low-`s` ECDSA P-256 signature over
    /// the event's preimage digest `D`.
    Raw {
        /// The raw `r ‖ s` bytes.
        signature: [u8; RAW_LEN],
    },
    /// `SignatureForm::WebAuthnAssertion`: a `WebAuthn` assertion whose
    /// challenge is `"SCP-KEY-EVENT-V1:" ‖ D`.
    WebAuthnAssertion(AssertionSignature),
}

/// The three parts of an assertion-form indexed signature.
///
/// Each part is within the bound §9.18.17 registers for it, which
/// [`AssertionSignature::new`] enforces. Its wire form is
/// `BE32(len(authenticatorData)) ‖ authenticatorData ‖
/// BE32(len(clientDataJSON)) ‖ clientDataJSON ‖ signature`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AssertionSignature {
    authenticator_data: Vec<u8>,
    client_data_json: Vec<u8>,
    signature: [u8; RAW_LEN],
}

/// The part of an indexed signature a field ran out inside.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IndexedSignaturePart {
    /// A raw-form signature's 64 bytes.
    RawSignature,
    /// The assertion's `authenticatorData` length prefix.
    AuthenticatorDataLength,
    /// The assertion's `authenticatorData`.
    AuthenticatorData,
    /// The assertion's `clientDataJSON` length prefix.
    ClientDataJsonLength,
    /// The assertion's `clientDataJSON`.
    ClientDataJson,
    /// The assertion's 64-byte signature.
    AssertionSignature,
}

/// Why an indexed signature cannot be read off a signature field or built
/// from its parts (§9.7.4.2; §9.18.17). Each variant names one check.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IndexedSignatureReadError {
    /// The field ends inside an indexed signature: a declared length, or a
    /// fixed-width part, runs past it.
    #[error("the signature field ends inside the {part:?}, with {remaining} bytes left")]
    Truncated {
        /// The part being read.
        part: IndexedSignaturePart,
        /// The bytes left when it was read.
        remaining: usize,
    },
    /// `authenticatorData` is shorter than `MIN_AUTHENTICATOR_DATA_BYTES` or
    /// longer than `MAX_AUTHENTICATOR_DATA_BYTES` (§9.18.17).
    #[error("authenticatorData is {len} bytes, outside 37..=256")]
    AuthenticatorDataLength {
        /// The declared or carried length.
        len: usize,
    },
    /// `clientDataJSON` is empty or longer than `MAX_CLIENT_DATA_JSON_BYTES`
    /// (§9.18.17).
    ///
    /// This is the one check of the 512-byte bound: the acceptance-set
    /// validator runs only over an [`AssertionSignature`]'s bytes, which
    /// have passed it.
    #[error("clientDataJSON is {len} bytes, outside 1..=512")]
    ClientDataJsonLength {
        /// The declared or carried length.
        len: usize,
    },
}

/// Why an indexed signature does not verify (§9.7.4.2, "Signature form").
/// Each variant names one check.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IndexedSignatureError {
    /// The signature carries a form other than the one field 7 declares for
    /// its index.
    #[error("field 7 declares the {declared:?} form, and the signature carries {carried:?}")]
    FormMismatch {
        /// The form field 7 declares.
        declared: SignatureForm,
        /// The form the signature carries.
        carried: SignatureForm,
    },
    /// The key at the signature's index is not a valid P-256 point.
    #[error("the key at the signature's index is not a valid P-256 point: {0}")]
    InvalidKey(P256Error),
    /// The user-presence flag, bit 0 of `authenticatorData` byte 32, is
    /// clear.
    #[error("the assertion's user-presence flag is clear")]
    UserPresenceNotSet,
    /// The user-verification flag, bit 2 of `authenticatorData` byte 32, is
    /// clear.
    #[error("the assertion's user-verification flag is clear")]
    UserVerificationNotSet,
    /// `clientDataJSON` is outside the acceptance set.
    #[error("clientDataJSON is not acceptable: {0}")]
    ClientData(#[from] ClientDataError),
    /// The decoded `type` member is not `"webauthn.get"`.
    #[error("the clientDataJSON type is not webauthn.get")]
    ClientDataTypeMismatch,
    /// The decoded `challenge` member is not the unpadded base64url
    /// encoding of `"SCP-KEY-EVENT-V1:" ‖ D`.
    #[error("the clientDataJSON challenge is not the event's challenge")]
    ChallengeMismatch,
    /// The 64-byte signature fails §9.5's checks: a scalar out of range,
    /// a high `s`, or an equation that does not hold.
    #[error("the signature does not verify: {0}")]
    Signature(P256Error),
}

impl AssertionSignature {
    /// An assertion-form indexed signature from its three parts.
    ///
    /// # Errors
    ///
    /// [`IndexedSignatureReadError::AuthenticatorDataLength`] or
    /// [`IndexedSignatureReadError::ClientDataJsonLength`] when a part is
    /// outside its §9.18.17 bound.
    pub fn new(
        authenticator_data: Vec<u8>,
        client_data_json: Vec<u8>,
        signature: [u8; RAW_LEN],
    ) -> Result<Self, IndexedSignatureReadError> {
        check_authenticator_data_length(authenticator_data.len())?;
        check_client_data_json_length(client_data_json.len())?;
        Ok(Self {
            authenticator_data,
            client_data_json,
            signature,
        })
    }

    /// The authenticator's `authenticatorData`.
    #[must_use]
    pub fn authenticator_data(&self) -> &[u8] {
        &self.authenticator_data
    }

    /// The client's `clientDataJSON` bytes, exactly as signed.
    #[must_use]
    pub fn client_data_json(&self) -> &[u8] {
        &self.client_data_json
    }

    /// The 64-byte low-`s` `r ‖ s` signature.
    #[must_use]
    pub const fn signature(&self) -> &[u8; RAW_LEN] {
        &self.signature
    }
}

impl IndexedSignature {
    /// The form this signature takes.
    #[must_use]
    pub const fn form(&self) -> SignatureForm {
        match self {
            Self::Raw { .. } => SignatureForm::Raw,
            Self::WebAuthnAssertion(_) => SignatureForm::WebAuthnAssertion,
        }
    }

    /// Reads one indexed signature of `form` off the front of `field` and
    /// returns it with the bytes it took (§9.10.12, the signature-field
    /// walk). Every length is checked against its bound before the bytes it
    /// declares are read, and no allocation is sized from a length that has
    /// not passed that check.
    ///
    /// # Errors
    ///
    /// [`IndexedSignatureReadError::Truncated`] when a part runs past
    /// `field`; [`IndexedSignatureReadError::AuthenticatorDataLength`] or
    /// [`IndexedSignatureReadError::ClientDataJsonLength`] when a declared
    /// length is outside its bound.
    pub fn read(
        form: SignatureForm,
        field: &[u8],
    ) -> Result<(Self, usize), IndexedSignatureReadError> {
        let mut reader = FieldReader { field, pos: 0 };
        let signature = match form {
            SignatureForm::Raw => Self::Raw {
                signature: reader.signature(IndexedSignaturePart::RawSignature)?,
            },
            SignatureForm::WebAuthnAssertion => {
                let authenticator_len =
                    reader.length(IndexedSignaturePart::AuthenticatorDataLength)?;
                check_authenticator_data_length(authenticator_len)?;
                let authenticator_data =
                    reader.bytes(authenticator_len, IndexedSignaturePart::AuthenticatorData)?;
                let client_data_len = reader.length(IndexedSignaturePart::ClientDataJsonLength)?;
                check_client_data_json_length(client_data_len)?;
                let client_data_json =
                    reader.bytes(client_data_len, IndexedSignaturePart::ClientDataJson)?;
                let signature = reader.signature(IndexedSignaturePart::AssertionSignature)?;
                Self::WebAuthnAssertion(AssertionSignature {
                    authenticator_data: authenticator_data.to_vec(),
                    client_data_json: client_data_json.to_vec(),
                    signature,
                })
            }
        };
        Ok((signature, reader.pos))
    }

    /// The signature-field bytes of this indexed signature, which
    /// [`read`](Self::read) of its form reads back whole.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Raw { signature } => signature.to_vec(),
            Self::WebAuthnAssertion(assertion) => {
                let mut out = Vec::with_capacity(
                    2 * LENGTH_PREFIX_BYTES
                        + assertion.authenticator_data.len()
                        + assertion.client_data_json.len()
                        + RAW_LEN,
                );
                // Both lengths are at most 512 (`AssertionSignature::new`
                // and `read` enforce the bounds), so each fits a `u32`.
                for part in [&assertion.authenticator_data, &assertion.client_data_json] {
                    let len = u32::try_from(part.len()).unwrap_or(u32::MAX);
                    out.extend_from_slice(&len.to_be_bytes());
                    out.extend_from_slice(part);
                }
                out.extend_from_slice(&assertion.signature);
                out
            }
        }
    }
}

/// Verifies one indexed signature of the form field 7 declares (§9.7.4.2,
/// "Signature form").
///
/// `key` is the 33-byte SEC1 point at the signature's index, `event_digest`
/// is the event's preimage digest `D`, and `declared` is the form field 7
/// declares for the index. A signature whose form is not `declared` is rejected first, so a value
/// built by hand cannot verify under a form the event does not declare. A
/// raw-form signature is checked with §9.5's strict verifier over `D`. An
/// assertion-form signature is accepted only when both the user-presence
/// and the user-verification flag of `authenticatorData` byte 32 are set,
/// `clientDataJSON` is in the acceptance set, its decoded `type` is
/// `"webauthn.get"`, its decoded `challenge` equals the unpadded base64url
/// encoding of [`key_event_challenge`] as a string, and the 64-byte
/// signature passes §9.5's strict verifier over
/// `SHA-256(authenticatorData ‖ SHA-256(clientDataJSON))`, which is the
/// message `WebAuthn` defines and not `D`.
///
/// # Errors
///
/// The [`IndexedSignatureError`] naming the first check that fails.
pub fn verify_indexed(
    key: &[u8; 33],
    event_digest: &[u8; 32],
    declared: SignatureForm,
    signature: &IndexedSignature,
) -> Result<(), IndexedSignatureError> {
    let carried = signature.form();
    if carried != declared {
        return Err(IndexedSignatureError::FormMismatch { declared, carried });
    }
    let key = P256PublicKey::from_sec1(key).map_err(IndexedSignatureError::InvalidKey)?;
    match signature {
        IndexedSignature::Raw { signature } => verify_prehash_strict(&key, event_digest, signature)
            .map_err(IndexedSignatureError::Signature),
        IndexedSignature::WebAuthnAssertion(assertion) => {
            verify_assertion(&key, event_digest, assertion)
        }
    }
}

/// The assertion-form checks of [`verify_indexed`], in order.
fn verify_assertion(
    key: &P256PublicKey,
    event_digest: &[u8; 32],
    assertion: &AssertionSignature,
) -> Result<(), IndexedSignatureError> {
    // `AssertionSignature` holds at least MIN_AUTHENTICATOR_DATA_BYTES, so
    // the flags byte exists; a missing byte reads as both flags clear.
    let flags = assertion
        .authenticator_data
        .get(FLAGS_BYTE)
        .copied()
        .unwrap_or(0);
    if flags & FLAG_USER_PRESENT == 0 {
        return Err(IndexedSignatureError::UserPresenceNotSet);
    }
    if flags & FLAG_USER_VERIFIED == 0 {
        return Err(IndexedSignatureError::UserVerificationNotSet);
    }
    let members = parse(&assertion.client_data_json)?;
    if members.client_data_type != ASSERTION_TYPE {
        return Err(IndexedSignatureError::ClientDataTypeMismatch);
    }
    if members.challenge != base64url_unpadded(&key_event_challenge(event_digest)) {
        return Err(IndexedSignatureError::ChallengeMismatch);
    }
    let client_data_hash = Sha256::digest(&assertion.client_data_json);
    let message_digest: [u8; 32] = Sha256::new()
        .chain_update(&assertion.authenticator_data)
        .chain_update(client_data_hash)
        .finalize()
        .into();
    verify_prehash_strict(key, &message_digest, &assertion.signature)
        .map_err(IndexedSignatureError::Signature)
}

/// The `WebAuthn` challenge bytes for the event whose preimage digest is
/// `event_digest`: `"SCP-KEY-EVENT-V1:" ‖ D` (§9.7.4.2 definitions;
/// §9.18.2).
///
/// A signer passes these 49 bytes as the assertion request's challenge, and
/// the client base64url-encodes them into `clientDataJSON` itself. The
/// verifier compares the decoded `challenge` member, as a string, against
/// the canonical unpadded base64url encoding of these bytes and never
/// decodes the member, so a non-canonical encoding of the same bytes is
/// rejected.
#[must_use]
pub const fn key_event_challenge(event_digest: &[u8; 32]) -> [u8; KEY_EVENT_CHALLENGE_LEN] {
    let mut challenge = [0u8; KEY_EVENT_CHALLENGE_LEN];
    let (separator, digest) = challenge.split_at_mut(KEY_EVENT_CHALLENGE_SEPARATOR.len());
    separator.copy_from_slice(KEY_EVENT_CHALLENGE_SEPARATOR);
    digest.copy_from_slice(event_digest);
    challenge
}

/// RFC 4648 §5 base64url, without padding.
fn base64url_unpadded(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk.first().copied().unwrap_or(0);
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let group = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        // A chunk of n bytes carries n + 1 sextets.
        for sextet in 0..=chunk.len() {
            let shift = 18 - 6 * sextet;
            let index = usize::try_from((group >> shift) & 0x3F).unwrap_or(0);
            out.push(char::from(ALPHABET.get(index).copied().unwrap_or(b'A')));
        }
    }
    out
}

/// Rejects an `authenticatorData` length outside §9.18.17's bounds.
fn check_authenticator_data_length(len: usize) -> Result<(), IndexedSignatureReadError> {
    let in_bounds = u32::try_from(len).is_ok_and(|len| {
        (MIN_AUTHENTICATOR_DATA_BYTES..=MAX_AUTHENTICATOR_DATA_BYTES).contains(&len)
    });
    if in_bounds {
        Ok(())
    } else {
        Err(IndexedSignatureReadError::AuthenticatorDataLength { len })
    }
}

/// Rejects a `clientDataJSON` length outside §9.18.17's bounds.
fn check_client_data_json_length(len: usize) -> Result<(), IndexedSignatureReadError> {
    let in_bounds =
        u32::try_from(len).is_ok_and(|len| (1..=MAX_CLIENT_DATA_JSON_BYTES).contains(&len));
    if in_bounds {
        Ok(())
    } else {
        Err(IndexedSignatureReadError::ClientDataJsonLength { len })
    }
}

/// A cursor over a signature field.
struct FieldReader<'a> {
    field: &'a [u8],
    pos: usize,
}

impl<'a> FieldReader<'a> {
    /// The next `len` bytes, or `Truncated` naming `part`.
    fn bytes(
        &mut self,
        len: usize,
        part: IndexedSignaturePart,
    ) -> Result<&'a [u8], IndexedSignatureReadError> {
        let remaining = self.field.len().saturating_sub(self.pos);
        let end = self
            .pos
            .checked_add(len)
            .ok_or(IndexedSignatureReadError::Truncated { part, remaining })?;
        let out = self
            .field
            .get(self.pos..end)
            .ok_or(IndexedSignatureReadError::Truncated { part, remaining })?;
        self.pos = end;
        Ok(out)
    }

    /// A `BE32` length prefix.
    fn length(&mut self, part: IndexedSignaturePart) -> Result<usize, IndexedSignatureReadError> {
        let mut prefix = [0u8; LENGTH_PREFIX_BYTES];
        prefix.copy_from_slice(self.bytes(LENGTH_PREFIX_BYTES, part)?);
        // A value past `usize` on a 16-bit target is out of every bound.
        Ok(usize::try_from(u32::from_be_bytes(prefix)).unwrap_or(usize::MAX))
    }

    /// A 64-byte raw signature.
    fn signature(
        &mut self,
        part: IndexedSignaturePart,
    ) -> Result<[u8; RAW_LEN], IndexedSignatureReadError> {
        let mut signature = [0u8; RAW_LEN];
        signature.copy_from_slice(self.bytes(RAW_LEN, part)?);
        Ok(signature)
    }
}
