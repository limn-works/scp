//! The service record and the `ServiceRecordFrameV5` frame it travels in at
//! `scp:svc:` (`03-identity.md` §3.10.13, `09-security-model.md` §9.10.12).
//!
//! ```text
//! frame     := 0x05 ‖ identifier (32) ‖ value
//! value     := identifier (32) ‖ BE64(sequence) ‖ entries ‖ signature (64)
//! entries   := BE32(count) ‖ entry*
//! entry     := str(id) ‖ str(type) ‖ str(serviceEndpoint) [‖ derivation_id (32)]
//! str       := BE32(len) ‖ bytes
//! signature := ECDSA-P256 over SHA-256("SCP-SERVICE-RECORD-V1:" ‖ value[..len − 64])
//! ```
//!
//! An `IdentityPrivateState` entry carries its 32-byte derivation id after
//! the endpoint string, and every other type carries nothing more
//! (§3.10.13). The entry count is at most `MAX_SERVICE_RECORD_ENTRIES`, and
//! every count and length is bounded by the bytes that remain before any
//! allocation (§9.10.12). A decoder rejects a `value` that does not end
//! exactly where the signature ends, a record whose signed identifier is not
//! the frame's, and a record at sequence `u64::MAX` (§3.10.13: "A reader
//! rejects a record at the maximum representable value").

use scp_crypto::p256::{P256Error, P256PublicKey, SIGNATURE_LEN, verify_prehash_strict};
use scp_did::Identifier;
use scp_kel::constants::MAX_SERVICE_RECORD_ENTRIES;
use sha2::{Digest, Sha256};

use super::frame::{FramePrefixError, MAX_RECORD_FRAME_VALUE_LEN, join_frame, split_frame};

/// The frame's version byte (§9.10.12).
pub const SERVICE_RECORD_FRAME_VERSION: u8 = 5;

/// `"SCP-SERVICE-RECORD-V1:"`, §9.18.2's separator for the record.
pub const SERVICE_RECORD_SEPARATOR: &str = "SCP-SERVICE-RECORD-V1:";

/// The entry type that carries a trailing 32-byte derivation id (§3.7).
pub const IDENTITY_PRIVATE_STATE_TYPE: &str = "IdentityPrivateState";

/// `identifier` (32), `sequence` (8) and the entry count (4).
const RECORD_HEADER_LEN: usize = 44;

/// The fewest bytes one entry occupies: three empty strings.
const MIN_ENTRY_LEN: usize = 12;

/// One entry of a service record (§3.10.13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceEntry {
    /// The entry's `id`.
    pub id: String,
    /// The entry's `type`, which decides whether a derivation id follows.
    pub entry_type: String,
    /// The entry's `serviceEndpoint`.
    pub service_endpoint: String,
    /// The derivation id an `IdentityPrivateState` entry carries; `None` on
    /// every other type.
    pub derivation_id: Option<[u8; 32]>,
}

/// A service record frame that passed every decoder rule. Its signature is
/// unverified: the designated key is read from a chain this crate does not
/// hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceRecordFrame {
    identifier: Identifier,
    sequence: u64,
    entries: Vec<ServiceEntry>,
    signing_digest: [u8; 32],
    signature: [u8; SIGNATURE_LEN],
}

/// Why bytes are not a service record frame, or the record's signature does
/// not verify.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ServiceRecordFrameError {
    /// A prefix rule.
    #[error(transparent)]
    Prefix(#[from] FramePrefixError),
    /// `value` ends before the record header or the signature.
    #[error("service record value ends before its fields and signature")]
    Truncated,
    /// The signed identifier is not the frame's identifier field.
    #[error("service record names an identifier other than the frame's")]
    IdentifierMismatch,
    /// The record's sequence is `u64::MAX`.
    #[error("service record sequence is the maximum value")]
    SequenceExhausted,
    /// The entry count exceeds `MAX_SERVICE_RECORD_ENTRIES`, or the entries
    /// it declares cannot fit the bytes that remain.
    #[error("service record declares {0} entries")]
    TooManyEntries(u32),
    /// An entry's bytes do not parse: a length past the bytes that remain, a
    /// string that is not UTF-8, or a derivation id cut short.
    #[error("service record entry {0} does not parse")]
    EntryMalformed(u32),
    /// Bytes remain between the last entry and the signature.
    #[error("service record value does not end where its signature ends")]
    TrailingBytes,
    /// The signature does not verify under the key handed in.
    #[error("service record signature: {0}")]
    Signature(P256Error),
}

struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.bytes.split_at_checked(len)?;
        self.bytes = rest;
        Some(head)
    }

    fn be32(&mut self) -> Option<u32> {
        self.take(4)
            .and_then(|b| <[u8; 4]>::try_from(b).ok())
            .map(u32::from_be_bytes)
    }

    fn string(&mut self) -> Option<String> {
        let len = usize::try_from(self.be32()?).ok()?;
        let bytes = self.take(len)?;
        String::from_utf8(bytes.to_vec()).ok()
    }
}

fn read_entry(reader: &mut Reader<'_>) -> Option<ServiceEntry> {
    let id = reader.string()?;
    let entry_type = reader.string()?;
    let service_endpoint = reader.string()?;
    let derivation_id = if entry_type == IDENTITY_PRIVATE_STATE_TYPE {
        Some(<[u8; 32]>::try_from(reader.take(32)?).ok()?)
    } else {
        None
    };
    Some(ServiceEntry {
        id,
        entry_type,
        service_endpoint,
        derivation_id,
    })
}

/// The record's field bytes after the separator: `identifier ‖
/// BE64(sequence) ‖ entries`.
///
/// # Errors
///
/// [`ServiceRecordFrameError::TooManyEntries`] past the cap, or
/// [`ServiceRecordFrameError::EntryMalformed`] for a string longer than
/// `u32::MAX` bytes.
pub fn service_record_fields(
    identifier: &Identifier,
    sequence: u64,
    entries: &[ServiceEntry],
) -> Result<Vec<u8>, ServiceRecordFrameError> {
    let count = u32::try_from(entries.len())
        .ok()
        .filter(|count| *count <= MAX_SERVICE_RECORD_ENTRIES)
        .ok_or(ServiceRecordFrameError::TooManyEntries(u32::MAX))?;
    let mut out = Vec::new();
    out.extend_from_slice(identifier.as_bytes());
    out.extend_from_slice(&sequence.to_be_bytes());
    out.extend_from_slice(&count.to_be_bytes());
    for (index, entry) in (0u32..).zip(entries) {
        for text in [&entry.id, &entry.entry_type, &entry.service_endpoint] {
            let len = u32::try_from(text.len())
                .map_err(|_| ServiceRecordFrameError::EntryMalformed(index))?;
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(text.as_bytes());
        }
        match (
            entry.entry_type == IDENTITY_PRIVATE_STATE_TYPE,
            entry.derivation_id,
        ) {
            (true, Some(derivation_id)) => out.extend_from_slice(&derivation_id),
            (false, None) => {}
            _ => return Err(ServiceRecordFrameError::EntryMalformed(index)),
        }
    }
    Ok(out)
}

/// `SHA-256("SCP-SERVICE-RECORD-V1:" ‖ fields)`.
#[must_use]
pub fn service_record_signing_digest(fields: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(SERVICE_RECORD_SEPARATOR.as_bytes())
        .chain_update(fields)
        .finalize()
        .into()
}

impl ServiceRecordFrame {
    /// The identifier the record names, equal to the frame's field.
    #[must_use]
    pub const fn identifier(&self) -> Identifier {
        self.identifier
    }

    /// The record's own sequence, unrelated to the log's.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// The entries, in record order.
    #[must_use]
    pub fn entries(&self) -> &[ServiceEntry] {
        &self.entries
    }

    /// The digest the designated key signed.
    #[must_use]
    pub const fn signing_digest(&self) -> [u8; 32] {
        self.signing_digest
    }

    /// Verifies the signature strictly under `designated`, the 33-byte key
    /// a retained chain designates for the service-record role.
    ///
    /// # Errors
    ///
    /// [`ServiceRecordFrameError::Signature`] for a key that does not parse
    /// or a signature that does not verify.
    pub fn verify(&self, designated: &[u8; 33]) -> Result<(), ServiceRecordFrameError> {
        let key =
            P256PublicKey::from_sec1(designated).map_err(ServiceRecordFrameError::Signature)?;
        verify_prehash_strict(&key, &self.signing_digest, &self.signature)
            .map_err(ServiceRecordFrameError::Signature)
    }
}

/// Decodes a service record frame under every decoder rule. The signature is
/// not checked.
///
/// # Errors
///
/// [`ServiceRecordFrameError`] names the first rule the bytes break.
pub fn decode_service_record_frame(
    bytes: &[u8],
) -> Result<ServiceRecordFrame, ServiceRecordFrameError> {
    let (identifier, value) = split_frame(bytes, SERVICE_RECORD_FRAME_VERSION)?;
    let Some((fields, signature)) = value
        .len()
        .checked_sub(SIGNATURE_LEN)
        .filter(|at| *at >= RECORD_HEADER_LEN)
        .map(|at| value.split_at(at))
    else {
        return Err(ServiceRecordFrameError::Truncated);
    };
    let mut reader = Reader { bytes: fields };
    let signed_identifier = reader
        .take(32)
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or(ServiceRecordFrameError::Truncated)?;
    if signed_identifier != *identifier.as_bytes() {
        return Err(ServiceRecordFrameError::IdentifierMismatch);
    }
    let sequence = reader
        .take(8)
        .and_then(|b| <[u8; 8]>::try_from(b).ok())
        .map(u64::from_be_bytes)
        .ok_or(ServiceRecordFrameError::Truncated)?;
    if sequence == u64::MAX {
        return Err(ServiceRecordFrameError::SequenceExhausted);
    }
    let count = reader.be32().ok_or(ServiceRecordFrameError::Truncated)?;
    let fits = usize::try_from(count)
        .ok()
        .and_then(|count| count.checked_mul(MIN_ENTRY_LEN))
        .is_some_and(|min| min <= reader.bytes.len());
    if count > MAX_SERVICE_RECORD_ENTRIES || !fits {
        return Err(ServiceRecordFrameError::TooManyEntries(count));
    }
    let mut entries = Vec::new();
    for index in 0..count {
        entries
            .push(read_entry(&mut reader).ok_or(ServiceRecordFrameError::EntryMalformed(index))?);
    }
    if !reader.bytes.is_empty() {
        return Err(ServiceRecordFrameError::TrailingBytes);
    }
    let mut sig = [0u8; SIGNATURE_LEN];
    sig.copy_from_slice(signature);
    Ok(ServiceRecordFrame {
        identifier,
        sequence,
        entries,
        signing_digest: service_record_signing_digest(fields),
        signature: sig,
    })
}

/// Encodes a frame from the record's field bytes and the designated key's
/// signature over them.
///
/// # Errors
///
/// [`FramePrefixError::ValueTooLarge`] past the `value` bound.
pub fn encode_service_record_frame(
    identifier: &Identifier,
    fields: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<Vec<u8>, ServiceRecordFrameError> {
    let mut value = Vec::with_capacity(fields.len() + SIGNATURE_LEN);
    value.extend_from_slice(fields);
    value.extend_from_slice(signature);
    if value.len() > MAX_RECORD_FRAME_VALUE_LEN {
        return Err(FramePrefixError::ValueTooLarge(value.len()).into());
    }
    Ok(join_frame(SERVICE_RECORD_FRAME_VERSION, identifier, &value))
}

#[cfg(test)]
mod tests {
    use scp_crypto::p256::{P256SecretKey, SeedLabel, sign_prehash_rfc6979};

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn entries() -> Vec<ServiceEntry> {
        vec![
            ServiceEntry {
                id: "#node-1".into(),
                entry_type: "SCPNode".into(),
                service_endpoint: "wss://node.example/scp/v1".into(),
                derivation_id: None,
            },
            ServiceEntry {
                id: "#private-state-1".into(),
                entry_type: IDENTITY_PRIVATE_STATE_TYPE.into(),
                service_endpoint: "wss://node.example/scp/v1".into(),
                derivation_id: Some([3; 32]),
            },
        ]
    }

    fn frame(
        key: &P256SecretKey,
        identifier: &Identifier,
        sequence: u64,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let fields = service_record_fields(identifier, sequence, &entries())?;
        let signature = sign_prehash_rfc6979(key, &service_record_signing_digest(&fields))?;
        Ok(encode_service_record_frame(
            identifier, &fields, &signature,
        )?)
    }

    #[test]
    fn a_record_round_trips_and_verifies_only_under_its_key() -> TestResult {
        let key = P256SecretKey::from_seed(SeedLabel::TestVectorKey, &[1; 32]);
        let other = P256SecretKey::from_seed(SeedLabel::TestVectorKey, &[2; 32]);
        let identifier = Identifier::from_bytes([9; 32]);
        let decoded = decode_service_record_frame(&frame(&key, &identifier, 4)?)?;
        assert_eq!(decoded.identifier(), identifier);
        assert_eq!(decoded.sequence(), 4);
        assert_eq!(decoded.entries(), entries().as_slice());
        decoded.verify(&key.public_key().to_compressed())?;
        assert!(decoded.verify(&other.public_key().to_compressed()).is_err());
        Ok(())
    }

    #[test]
    fn a_record_naming_another_identifier_is_refused() -> TestResult {
        let key = P256SecretKey::from_seed(SeedLabel::TestVectorKey, &[1; 32]);
        let mut bytes = frame(&key, &Identifier::from_bytes([9; 32]), 4)?;
        bytes[1] ^= 1;
        assert_eq!(
            decode_service_record_frame(&bytes),
            Err(ServiceRecordFrameError::IdentifierMismatch)
        );
        Ok(())
    }

    #[test]
    fn the_maximum_sequence_is_refused() -> TestResult {
        let key = P256SecretKey::from_seed(SeedLabel::TestVectorKey, &[1; 32]);
        let bytes = frame(&key, &Identifier::from_bytes([9; 32]), u64::MAX)?;
        assert_eq!(
            decode_service_record_frame(&bytes),
            Err(ServiceRecordFrameError::SequenceExhausted)
        );
        Ok(())
    }

    #[test]
    fn a_value_with_bytes_before_the_signature_is_refused() -> TestResult {
        let identifier = Identifier::from_bytes([9; 32]);
        let mut fields = service_record_fields(&identifier, 1, &entries())?;
        fields.push(0);
        let bytes = encode_service_record_frame(&identifier, &fields, &[0; SIGNATURE_LEN])?;
        assert_eq!(
            decode_service_record_frame(&bytes),
            Err(ServiceRecordFrameError::TrailingBytes)
        );
        Ok(())
    }

    #[test]
    fn a_count_past_the_cap_or_the_bytes_is_refused_before_allocation() -> TestResult {
        let identifier = Identifier::from_bytes([9; 32]);
        let mut fields = identifier.as_bytes().to_vec();
        fields.extend_from_slice(&1u64.to_be_bytes());
        fields.extend_from_slice(&65u32.to_be_bytes());
        let bytes = encode_service_record_frame(&identifier, &fields, &[0; SIGNATURE_LEN])?;
        assert_eq!(
            decode_service_record_frame(&bytes),
            Err(ServiceRecordFrameError::TooManyEntries(65))
        );
        fields.truncate(40);
        fields.extend_from_slice(&2u32.to_be_bytes());
        let bytes = encode_service_record_frame(&identifier, &fields, &[0; SIGNATURE_LEN])?;
        assert_eq!(
            decode_service_record_frame(&bytes),
            Err(ServiceRecordFrameError::TooManyEntries(2))
        );
        Ok(())
    }

    #[test]
    fn a_string_length_past_the_bytes_is_refused() -> TestResult {
        let identifier = Identifier::from_bytes([9; 32]);
        let mut fields = identifier.as_bytes().to_vec();
        fields.extend_from_slice(&1u64.to_be_bytes());
        fields.extend_from_slice(&1u32.to_be_bytes());
        fields.extend_from_slice(&u32::MAX.to_be_bytes());
        fields.extend_from_slice(&[0; 8]);
        let bytes = encode_service_record_frame(&identifier, &fields, &[0; SIGNATURE_LEN])?;
        assert_eq!(
            decode_service_record_frame(&bytes),
            Err(ServiceRecordFrameError::EntryMalformed(0))
        );
        Ok(())
    }

    #[test]
    fn a_private_state_entry_without_its_derivation_id_is_refused() -> TestResult {
        let identifier = Identifier::from_bytes([9; 32]);
        let mut entry = entries().remove(1);
        entry.derivation_id = None;
        assert_eq!(
            service_record_fields(&identifier, 1, &[entry]),
            Err(ServiceRecordFrameError::EntryMalformed(0))
        );
        let fields = service_record_fields(&identifier, 1, &entries())?;
        let cut = &fields[..fields.len() - 1];
        let bytes = encode_service_record_frame(&identifier, cut, &[0; SIGNATURE_LEN])?;
        assert_eq!(
            decode_service_record_frame(&bytes),
            Err(ServiceRecordFrameError::EntryMalformed(1))
        );
        Ok(())
    }

    #[test]
    fn a_value_shorter_than_header_and_signature_is_refused() {
        let bytes = join_frame(SERVICE_RECORD_FRAME_VERSION, &Identifier::ZERO, &[0; 107]);
        assert_eq!(
            decode_service_record_frame(&bytes),
            Err(ServiceRecordFrameError::Truncated)
        );
    }
}
