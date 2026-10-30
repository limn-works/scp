//! The device record `identity/{identifier}/device_state`
//! (`17-persistence-and-storage.md` §17.3): the handles of the keys this
//! device holds for one identity, and the `KeptComposition` and
//! `PendingSignatureRecord` entries `09-security-model.md` §9.7.4.2 R10
//! requires the device to persist.

use scp_did::Identifier;
use scp_kel::constants::{
    KEPT_COMPOSITION_BYTES, MAX_NEXT_SET_SIZE, MAX_ROOT_SET_SIZE, PENDING_SIGNATURE_RECORD_BYTES,
};
use scp_platform::{EncryptedStorage, KeyHandle, NextSetKeyHandle, sanitize_key_component};

use super::IdentityError;

/// The record's format version (§17.3).
const FORMAT_VERSION: u8 = 0x01;

/// The prefix every device record's key carries (§17.3).
pub(super) const DEVICE_RECORD_PREFIX: &str = "identity/";

/// The suffix every device record's key carries (§17.3).
pub(super) const DEVICE_RECORD_SUFFIX: &str = "/device_state";

/// The width of one root entry: a BE16 root index and a BE64 handle.
const ROOT_ENTRY_BYTES: usize = 2 + 8;

/// The width of one `#active` or next-set handle.
const HANDLE_BYTES: usize = 8;

/// The width of one `KeptComposition` or `PendingSignatureRecord`.
const ENTRY_BYTES: usize = 72;

// §9.18.17 registers both widths, and the encoder writes this one width.
const _: () = assert!(
    KEPT_COMPOSITION_BYTES as usize == ENTRY_BYTES
        && PENDING_SIGNATURE_RECORD_BYTES as usize == ENTRY_BYTES
);

/// The most `#active` handles a record holds (§17.3, `n_active` 0..=1).
const MAX_ACTIVE: usize = 1;

/// One event a device composed and returned as awaiting signatures, or one
/// event it signed and has not adopted: the identifier, the sequence and the
/// event digest (`09-security-model.md` §9.7.4.2 R10). `KeptComposition` and
/// `PendingSignatureRecord` share this layout (§9.18.17).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct EventRef {
    /// The identity the event extends or creates.
    pub(super) identifier: Identifier,
    /// The event's sequence.
    pub(super) sequence: u64,
    /// SHA-256 of the event's signed preimage.
    pub(super) event_digest: [u8; 32],
}

/// One device's state for one key-event-log identity (§17.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DeviceRecord {
    /// The root members this device holds, by root index.
    pub(super) root: Vec<(u16, KeyHandle)>,
    /// The `#active` key this device holds, if any.
    pub(super) active: Option<KeyHandle>,
    /// The next-set members this device holds.
    pub(super) next: Vec<NextSetKeyHandle>,
    /// The `KeptComposition` list.
    pub(super) kept: Vec<EventRef>,
    /// The `PendingSignatureRecord` list, which `cosign` writes.
    pub(super) pending: Vec<EventRef>,
}

/// Why a stored value is not a device record (§17.3's decoder refusals).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(super) enum RecordDefect {
    /// The version byte is not 1.
    #[error("unknown device-record version 0x{0:02x}")]
    UnknownVersion(u8),
    /// The value ends inside a field.
    #[error("the device record is truncated")]
    Truncated,
    /// Bytes follow the last list.
    #[error("the device record carries trailing bytes")]
    TrailingBytes,
    /// A count lies outside its range.
    #[error("a device-record count lies outside its range")]
    CountOutOfRange,
    /// A root index is at or above `MAX_ROOT_SET_SIZE`.
    #[error("a root index lies at or above the root-set bound")]
    RootIndexOutOfRange,
    /// A root index appears twice.
    #[error("a root index repeats")]
    RepeatedRootIndex,
    /// An entry names an identifier other than the key's.
    #[error("an entry names another identifier")]
    IdentifierMismatch,
    /// Two entries of one list carry one digest.
    #[error("two entries of one list carry the same digest")]
    DuplicateDigest,
}

/// The storage key of `identifier`'s device record (§17.3).
///
/// # Errors
///
/// [`IdentityError::PersistFailed`] where the text form fails
/// `sanitize_key_component`, which the canonical form never does.
pub(super) fn device_record_key(identifier: &Identifier) -> Result<String, IdentityError> {
    let text = identifier.to_string();
    let component = sanitize_key_component(&text).map_err(|error| {
        tracing::error!(%error, "an identifier's text form failed key sanitization");
        IdentityError::PersistFailed
    })?;
    Ok(format!(
        "{DEVICE_RECORD_PREFIX}{component}{DEVICE_RECORD_SUFFIX}"
    ))
}

impl DeviceRecord {
    /// Encodes the record in format version 1 (§17.3).
    ///
    /// # Errors
    ///
    /// [`RecordDefect::CountOutOfRange`] where a list exceeds its bound, and
    /// the root-index and digest defects the decoder would refuse, so a
    /// written record always decodes.
    pub(super) fn encode(&self, identifier: &Identifier) -> Result<Vec<u8>, RecordDefect> {
        self.check(identifier)?;
        let n_root = u8::try_from(self.root.len()).map_err(|_| RecordDefect::CountOutOfRange)?;
        let n_next = u8::try_from(self.next.len()).map_err(|_| RecordDefect::CountOutOfRange)?;
        let n_kept = u16::try_from(self.kept.len()).map_err(|_| RecordDefect::CountOutOfRange)?;
        let n_pending =
            u16::try_from(self.pending.len()).map_err(|_| RecordDefect::CountOutOfRange)?;
        let mut out = Vec::with_capacity(
            1 + 1
                + self.root.len() * ROOT_ENTRY_BYTES
                + 1
                + HANDLE_BYTES
                + 1
                + self.next.len() * HANDLE_BYTES
                + 2
                + self.kept.len() * ENTRY_BYTES
                + 2
                + self.pending.len() * ENTRY_BYTES,
        );
        out.push(FORMAT_VERSION);
        out.push(n_root);
        for (index, handle) in &self.root {
            out.extend_from_slice(&index.to_be_bytes());
            out.extend_from_slice(&handle.id().to_be_bytes());
        }
        match self.active {
            Some(handle) => {
                out.push(1);
                out.extend_from_slice(&handle.id().to_be_bytes());
            }
            None => out.push(0),
        }
        out.push(n_next);
        for handle in &self.next {
            out.extend_from_slice(&handle.id().to_be_bytes());
        }
        for (count, list) in [(n_kept, &self.kept), (n_pending, &self.pending)] {
            out.extend_from_slice(&count.to_be_bytes());
            for entry in list {
                out.extend_from_slice(entry.identifier.as_bytes());
                out.extend_from_slice(&entry.sequence.to_be_bytes());
                out.extend_from_slice(&entry.event_digest);
            }
        }
        Ok(out)
    }

    /// Decodes a format-version-1 record stored under `identifier`'s key
    /// (§17.3).
    ///
    /// # Errors
    ///
    /// Every [`RecordDefect`]: the decoder substitutes no default.
    pub(super) fn decode(identifier: &Identifier, bytes: &[u8]) -> Result<Self, RecordDefect> {
        let mut reader = Reader { bytes };
        let version = reader.u8()?;
        if version != FORMAT_VERSION {
            return Err(RecordDefect::UnknownVersion(version));
        }
        let n_root = usize::from(reader.u8()?);
        if n_root == 0 || n_root > MAX_ROOT_SET_SIZE as usize {
            return Err(RecordDefect::CountOutOfRange);
        }
        let mut root = Vec::with_capacity(n_root);
        for _ in 0..n_root {
            let index = u16::from_be_bytes(reader.array()?);
            root.push((index, KeyHandle::new(u64::from_be_bytes(reader.array()?))));
        }
        let n_active = usize::from(reader.u8()?);
        if n_active > MAX_ACTIVE {
            return Err(RecordDefect::CountOutOfRange);
        }
        let active = if n_active == 1 {
            Some(KeyHandle::new(u64::from_be_bytes(reader.array()?)))
        } else {
            None
        };
        let n_next = usize::from(reader.u8()?);
        if n_next > MAX_NEXT_SET_SIZE as usize {
            return Err(RecordDefect::CountOutOfRange);
        }
        let mut next = Vec::with_capacity(n_next);
        for _ in 0..n_next {
            next.push(NextSetKeyHandle::new(u64::from_be_bytes(reader.array()?)));
        }
        let kept = reader.entries()?;
        let pending = reader.entries()?;
        if !reader.bytes.is_empty() {
            return Err(RecordDefect::TrailingBytes);
        }
        let record = Self {
            root,
            active,
            next,
            kept,
            pending,
        };
        record.check(identifier)?;
        Ok(record)
    }

    /// The structural rules both directions enforce: the list bounds, the
    /// root indices, the identifier binding and digest uniqueness (§17.3).
    fn check(&self, identifier: &Identifier) -> Result<(), RecordDefect> {
        if self.root.is_empty()
            || self.root.len() > MAX_ROOT_SET_SIZE as usize
            || self.next.len() > MAX_NEXT_SET_SIZE as usize
        {
            return Err(RecordDefect::CountOutOfRange);
        }
        let mut seen = [false; MAX_ROOT_SET_SIZE as usize];
        for (index, _) in &self.root {
            let slot = seen
                .get_mut(usize::from(*index))
                .ok_or(RecordDefect::RootIndexOutOfRange)?;
            if *slot {
                return Err(RecordDefect::RepeatedRootIndex);
            }
            *slot = true;
        }
        for list in [&self.kept, &self.pending] {
            for (position, entry) in list.iter().enumerate() {
                if entry.identifier != *identifier {
                    return Err(RecordDefect::IdentifierMismatch);
                }
                if list
                    .iter()
                    .skip(position + 1)
                    .any(|other| other.event_digest == entry.event_digest)
                {
                    return Err(RecordDefect::DuplicateDigest);
                }
            }
        }
        Ok(())
    }
}

/// A cursor that refuses to read past the value's end.
pub(super) struct Reader<'a> {
    pub(super) bytes: &'a [u8],
}

impl Reader<'_> {
    pub(super) fn array<const N: usize>(&mut self) -> Result<[u8; N], RecordDefect> {
        let (head, rest) = self
            .bytes
            .split_first_chunk::<N>()
            .ok_or(RecordDefect::Truncated)?;
        self.bytes = rest;
        Ok(*head)
    }

    pub(super) fn u8(&mut self) -> Result<u8, RecordDefect> {
        let [byte] = self.array::<1>()?;
        Ok(byte)
    }

    fn entries(&mut self) -> Result<Vec<EventRef>, RecordDefect> {
        let count = usize::from(u16::from_be_bytes(self.array()?));
        // Refuse a count the remaining bytes cannot hold before allocating
        // for it.
        if count.saturating_mul(ENTRY_BYTES) > self.bytes.len() {
            return Err(RecordDefect::Truncated);
        }
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            entries.push(EventRef {
                identifier: Identifier::from_bytes(self.array()?),
                sequence: u64::from_be_bytes(self.array()?),
                event_digest: self.array()?,
            });
        }
        Ok(entries)
    }
}

/// Reads `identifier`'s device record from `store`, `None` where the key
/// holds nothing.
///
/// # Errors
///
/// [`IdentityError::PersistFailed`] where the read fails or the value is not
/// a record (§17.3).
pub(super) async fn read_device_record<S: EncryptedStorage>(
    store: &S,
    identifier: &Identifier,
) -> Result<Option<DeviceRecord>, IdentityError> {
    let key = device_record_key(identifier)?;
    let Some(bytes) = store.retrieve(&key).await.map_err(|error| {
        tracing::error!(%error, "reading a device record failed");
        IdentityError::PersistFailed
    })?
    else {
        return Ok(None);
    };
    DeviceRecord::decode(identifier, &bytes)
        .map(Some)
        .map_err(|defect| {
            tracing::error!(%defect, "a stored device record failed to decode");
            IdentityError::PersistFailed
        })
}

/// Writes `record` as `identifier`'s device record, in one put (§17.3).
///
/// # Errors
///
/// [`IdentityError::PersistFailed`] where the record breaks a §17.3 rule or
/// the write fails.
pub(super) async fn write_device_record<S: EncryptedStorage>(
    store: &S,
    identifier: &Identifier,
    record: &DeviceRecord,
) -> Result<(), IdentityError> {
    let key = device_record_key(identifier)?;
    let bytes = record.encode(identifier).map_err(|defect| {
        tracing::error!(%defect, "a device record failed to encode");
        IdentityError::PersistFailed
    })?;
    store.store(&key, &bytes).await.map_err(|error| {
        tracing::error!(%error, "writing a device record failed");
        IdentityError::PersistFailed
    })
}

/// Deletes `identifier`'s device record.
///
/// # Errors
///
/// [`IdentityError::PersistFailed`] where the delete fails.
pub(super) async fn delete_device_record<S: EncryptedStorage>(
    store: &S,
    identifier: &Identifier,
) -> Result<(), IdentityError> {
    let key = device_record_key(identifier)?;
    store.delete(&key).await.map_err(|error| {
        tracing::error!(%error, "deleting a device record failed");
        IdentityError::PersistFailed
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const ID: Identifier = Identifier::from_bytes([0x11; 32]);

    fn inception_record() -> DeviceRecord {
        DeviceRecord {
            root: vec![(0, KeyHandle::new(7))],
            active: Some(KeyHandle::new(8)),
            next: vec![NextSetKeyHandle::new(9)],
            kept: vec![EventRef {
                identifier: ID,
                sequence: 0,
                event_digest: [0x22; 32],
            }],
            pending: vec![],
        }
    }

    /// The golden bytes of a fresh inception's record: a little-endian
    /// sequence, a 4-byte handle, or an entry other than 72 bytes changes
    /// them.
    fn golden() -> Vec<u8> {
        let mut bytes = vec![0x01, 0x01, 0x00, 0x00];
        bytes.extend_from_slice(&7u64.to_be_bytes());
        bytes.push(0x01);
        bytes.extend_from_slice(&8u64.to_be_bytes());
        bytes.push(0x01);
        bytes.extend_from_slice(&9u64.to_be_bytes());
        bytes.extend_from_slice(&[0x00, 0x01]);
        bytes.extend_from_slice(&[0x11; 32]);
        bytes.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
        bytes.extend_from_slice(&[0x22; 32]);
        bytes.extend_from_slice(&[0x00, 0x00]);
        bytes
    }

    #[test]
    fn inception_record_encodes_to_the_golden_bytes() -> TestResult {
        let bytes = inception_record().encode(&ID)?;
        assert_eq!(bytes, golden());
        assert_eq!(bytes.len(), 1 + 1 + 10 + 1 + 8 + 1 + 8 + 2 + 72 + 2);
        assert_eq!(DeviceRecord::decode(&ID, &bytes)?, inception_record());
        Ok(())
    }

    #[test]
    fn a_cosign_only_record_round_trips() -> TestResult {
        let record = DeviceRecord {
            root: vec![(3, KeyHandle::new(1)), (0, KeyHandle::new(2))],
            active: None,
            next: vec![],
            kept: vec![],
            pending: vec![EventRef {
                identifier: ID,
                sequence: u64::MAX,
                event_digest: [0x33; 32],
            }],
        };
        let bytes = record.encode(&ID)?;
        assert_eq!(DeviceRecord::decode(&ID, &bytes)?, record);
        Ok(())
    }

    fn refusal(bytes: &[u8]) -> Option<RecordDefect> {
        DeviceRecord::decode(&ID, bytes).err()
    }

    #[test]
    fn decoder_refuses_an_unknown_version() {
        let mut bytes = golden();
        bytes[0] = 0x02;
        assert_eq!(refusal(&bytes), Some(RecordDefect::UnknownVersion(2)));
    }

    #[test]
    fn decoder_refuses_every_truncation() {
        let bytes = golden();
        for len in 0..bytes.len() {
            assert_eq!(
                refusal(&bytes[..len]),
                Some(RecordDefect::Truncated),
                "a {len}-byte prefix"
            );
        }
    }

    #[test]
    fn decoder_refuses_trailing_bytes() {
        let mut bytes = golden();
        bytes.push(0);
        assert_eq!(refusal(&bytes), Some(RecordDefect::TrailingBytes));
    }

    #[test]
    fn decoder_refuses_counts_out_of_range() {
        let mut no_root = golden();
        no_root[1] = 0;
        assert_eq!(refusal(&no_root), Some(RecordDefect::CountOutOfRange));
        let mut many_root = golden();
        many_root[1] = 17;
        assert_eq!(refusal(&many_root), Some(RecordDefect::CountOutOfRange));
        let mut two_active = golden();
        two_active[12] = 2;
        assert_eq!(refusal(&two_active), Some(RecordDefect::CountOutOfRange));
        let mut many_next = golden();
        many_next[21] = 17;
        assert_eq!(refusal(&many_next), Some(RecordDefect::CountOutOfRange));
    }

    #[test]
    fn decoder_refuses_root_index_defects() {
        let mut high = golden();
        high[2..4].copy_from_slice(&16u16.to_be_bytes());
        assert_eq!(refusal(&high), Some(RecordDefect::RootIndexOutOfRange));
        let record = DeviceRecord {
            root: vec![(2, KeyHandle::new(1)), (2, KeyHandle::new(2))],
            ..inception_record()
        };
        assert_eq!(record.encode(&ID), Err(RecordDefect::RepeatedRootIndex));
        let mut repeated = vec![0x01, 0x02];
        for handle in [1u64, 2] {
            repeated.extend_from_slice(&2u16.to_be_bytes());
            repeated.extend_from_slice(&handle.to_be_bytes());
        }
        repeated.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        assert_eq!(refusal(&repeated), Some(RecordDefect::RepeatedRootIndex));
    }

    #[test]
    fn decoder_refuses_an_entry_for_another_identifier() {
        let mut bytes = golden();
        bytes[32] ^= 0x01;
        assert_eq!(refusal(&bytes), Some(RecordDefect::IdentifierMismatch));
    }

    #[test]
    fn decoder_refuses_a_duplicate_digest_within_a_list() {
        let mut bytes = golden();
        bytes.truncate(bytes.len() - 2);
        bytes[30..32].copy_from_slice(&2u16.to_be_bytes());
        let entry = bytes[32..104].to_vec();
        bytes.extend_from_slice(&entry);
        bytes.extend_from_slice(&[0x00, 0x00]);
        assert_eq!(refusal(&bytes), Some(RecordDefect::DuplicateDigest));
    }

    #[test]
    fn device_record_key_uses_the_canonical_text_form() -> TestResult {
        let key = device_record_key(&ID)?;
        assert_eq!(key, format!("identity/{ID}/device_state"));
        assert!(key.starts_with("identity/scp:"));
        assert_eq!(key.len(), "identity/".len() + 56 + "/device_state".len());
        Ok(())
    }
}
