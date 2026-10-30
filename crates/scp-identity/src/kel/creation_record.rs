//! The creation record `identity/creation/{creation_id}`
//! (`17-persistence-and-storage.md` §17.3): the keys one `Identity::create`
//! call has minted and not yet handed to a device record, so no failure,
//! panic or crash leaves a minted key that no call can find.

use std::fmt;

use rand::RngCore;
use scp_platform::{EncryptedStorage, KeyHandle, NextSetKeyHandle, PlatformError};

use super::IdentityError;
use super::device_record::{Reader, RecordDefect};

/// The record's format version (§17.3).
const FORMAT_VERSION: u8 = 0x01;

/// The prefix every creation record's key carries (§17.3).
pub(super) const CREATION_PREFIX: &str = "identity/creation/";

/// The most next-set handles a creation record holds (`n_next` 0..=1).
const MAX_NEXT: usize = 1;

/// The most root and `#active` handles a creation record holds
/// (`n_keys` 0..=2).
const MAX_KEYS: usize = 2;

/// The 16 random bytes naming one creation record (§17.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CreationId(pub [u8; 16]);

impl CreationId {
    /// Draws 16 bytes from the operating system's random source.
    ///
    /// # Errors
    ///
    /// [`IdentityError::PersistFailed`] where the source fails, since no
    /// record can then be named.
    pub(super) fn fresh() -> Result<Self, IdentityError> {
        let mut bytes = [0u8; 16];
        rand::rngs::OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|error| {
                tracing::error!(%error, "drawing a creation id failed");
                IdentityError::PersistFailed
            })?;
        Ok(Self(bytes))
    }

    /// Parses the 32 lowercase hexadecimal characters of a record key's last
    /// component, refusing any other text.
    fn parse(text: &str) -> Option<Self> {
        if text.len() != 32 || !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return None;
        }
        let mut bytes = [0u8; 16];
        hex::decode_to_slice(text, &mut bytes).ok()?;
        Some(Self(bytes))
    }

    /// The storage key of this creation's record.
    fn key(self) -> String {
        format!("{CREATION_PREFIX}{self}")
    }
}

impl fmt::Display for CreationId {
    /// The 32 lowercase hexadecimal characters the record key carries.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

/// The handles one creation has minted (§17.3).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct CreationRecord {
    /// The next-set member, once generated.
    pub(super) next: Option<NextSetKeyHandle>,
    /// `#0`, then `#active`, each once generated.
    pub(super) keys: Vec<KeyHandle>,
}

impl CreationRecord {
    /// Encodes the record in format version 1.
    ///
    /// # Errors
    ///
    /// [`RecordDefect::CountOutOfRange`] where `keys` holds more than two
    /// handles, so a written record always decodes.
    fn encode(&self) -> Result<Vec<u8>, RecordDefect> {
        let n_keys = u8::try_from(self.keys.len())
            .ok()
            .filter(|n| usize::from(*n) <= MAX_KEYS)
            .ok_or(RecordDefect::CountOutOfRange)?;
        let mut out = Vec::with_capacity(1 + 1 + 8 + 1 + MAX_KEYS * 8);
        out.push(FORMAT_VERSION);
        match self.next {
            Some(handle) => {
                out.push(1);
                out.extend_from_slice(&handle.id().to_be_bytes());
            }
            None => out.push(0),
        }
        out.push(n_keys);
        for key in &self.keys {
            out.extend_from_slice(&key.id().to_be_bytes());
        }
        Ok(out)
    }

    /// Decodes a format-version-1 record.
    ///
    /// # Errors
    ///
    /// Every [`RecordDefect`] §17.3 names: the decoder substitutes no
    /// default.
    fn decode(bytes: &[u8]) -> Result<Self, RecordDefect> {
        let mut reader = Reader { bytes };
        let version = reader.u8()?;
        if version != FORMAT_VERSION {
            return Err(RecordDefect::UnknownVersion(version));
        }
        let n_next = usize::from(reader.u8()?);
        if n_next > MAX_NEXT {
            return Err(RecordDefect::CountOutOfRange);
        }
        let next = if n_next == 1 {
            Some(NextSetKeyHandle::new(u64::from_be_bytes(reader.array()?)))
        } else {
            None
        };
        let n_keys = usize::from(reader.u8()?);
        if n_keys > MAX_KEYS {
            return Err(RecordDefect::CountOutOfRange);
        }
        let mut keys = Vec::with_capacity(n_keys);
        for _ in 0..n_keys {
            keys.push(KeyHandle::new(u64::from_be_bytes(reader.array()?)));
        }
        if !reader.bytes.is_empty() {
            return Err(RecordDefect::TrailingBytes);
        }
        Ok(Self { next, keys })
    }
}

/// Logs a store failure and returns SCP-IDENT-1104.
fn persist_failed(what: &str, error: &dyn fmt::Display) -> IdentityError {
    tracing::error!(what, %error, "a creation-record operation failed");
    IdentityError::PersistFailed
}

/// Reads `creation`'s record, `None` where the key holds nothing.
///
/// # Errors
///
/// [`IdentityError::PersistFailed`] where the read fails or the value is not
/// a record.
pub(super) async fn read_creation_record<S: EncryptedStorage>(
    store: &S,
    creation: CreationId,
) -> Result<Option<CreationRecord>, IdentityError> {
    let Some(bytes) = store
        .retrieve(&creation.key())
        .await
        .map_err(|error| persist_failed("read", &error))?
    else {
        return Ok(None);
    };
    CreationRecord::decode(&bytes)
        .map(Some)
        .map_err(|defect| persist_failed("decode", &defect))
}

/// Writes `record` as `creation`'s record, in one put.
///
/// # Errors
///
/// [`IdentityError::PersistFailed`] where the record breaks a bound or the
/// write fails.
pub(super) async fn write_creation_record<S: EncryptedStorage>(
    store: &S,
    creation: CreationId,
    record: &CreationRecord,
) -> Result<(), IdentityError> {
    let bytes = record
        .encode()
        .map_err(|defect| persist_failed("encode", &defect))?;
    store
        .store(&creation.key(), &bytes)
        .await
        .map_err(|error| persist_failed("write", &error))
}

/// Deletes `creation`'s record.
///
/// # Errors
///
/// [`IdentityError::PersistFailed`] where the delete fails.
pub(super) async fn delete_creation_record<S: EncryptedStorage>(
    store: &S,
    creation: CreationId,
) -> Result<(), IdentityError> {
    store
        .delete(&creation.key())
        .await
        .map_err(|error: PlatformError| persist_failed("delete", &error))
}

/// Every creation whose record `store` holds, in key order.
///
/// # Errors
///
/// [`IdentityError::PersistFailed`] where the listing fails or a key under
/// the prefix does not end in a creation id, which only a foreign writer
/// produces.
pub(super) async fn list_creations<S: EncryptedStorage>(
    store: &S,
) -> Result<Vec<CreationId>, IdentityError> {
    let keys = store
        .list_keys(CREATION_PREFIX)
        .await
        .map_err(|error| persist_failed("list", &error))?;
    keys.iter()
        .map(|key| {
            key.strip_prefix(CREATION_PREFIX)
                .and_then(CreationId::parse)
                .ok_or_else(|| persist_failed("parse a creation key", key))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn full() -> CreationRecord {
        CreationRecord {
            next: Some(NextSetKeyHandle::new(5)),
            keys: vec![KeyHandle::new(7), KeyHandle::new(8)],
        }
    }

    #[test]
    fn a_full_record_encodes_to_the_golden_bytes() -> TestResult {
        let mut golden = vec![0x01, 1];
        golden.extend_from_slice(&5u64.to_be_bytes());
        golden.push(2);
        golden.extend_from_slice(&7u64.to_be_bytes());
        golden.extend_from_slice(&8u64.to_be_bytes());
        assert_eq!(full().encode()?, golden);
        assert_eq!(CreationRecord::decode(&golden)?, full());
        Ok(())
    }

    #[test]
    fn every_prefix_of_the_creation_round_trips() -> TestResult {
        for record in [
            CreationRecord::default(),
            CreationRecord {
                next: Some(NextSetKeyHandle::new(1)),
                keys: vec![],
            },
            CreationRecord {
                next: Some(NextSetKeyHandle::new(1)),
                keys: vec![KeyHandle::new(2)],
            },
            full(),
        ] {
            assert_eq!(CreationRecord::decode(&record.encode()?)?, record);
        }
        assert_eq!(CreationRecord::default().encode()?, [0x01, 0, 0]);
        Ok(())
    }

    #[test]
    fn the_decoder_refuses_every_malformed_value() -> TestResult {
        let good = full().encode()?;
        assert_eq!(
            CreationRecord::decode(&[0x02, 0, 0]),
            Err(RecordDefect::UnknownVersion(2))
        );
        assert_eq!(
            CreationRecord::decode(&[0x01, 2, 0]),
            Err(RecordDefect::CountOutOfRange)
        );
        assert_eq!(
            CreationRecord::decode(&[0x01, 0, 3]),
            Err(RecordDefect::CountOutOfRange)
        );
        for len in 0..good.len() {
            assert_eq!(
                CreationRecord::decode(good.get(..len).ok_or("prefix")?),
                Err(RecordDefect::Truncated),
                "a {len}-byte prefix"
            );
        }
        let mut long = good;
        long.push(0);
        assert_eq!(
            CreationRecord::decode(&long),
            Err(RecordDefect::TrailingBytes)
        );
        let three = CreationRecord {
            next: None,
            keys: vec![KeyHandle::new(1), KeyHandle::new(2), KeyHandle::new(3)],
        };
        assert_eq!(three.encode(), Err(RecordDefect::CountOutOfRange));
        Ok(())
    }

    #[test]
    fn an_id_prints_and_parses_as_32_lowercase_hex() {
        let id = CreationId([0xab; 16]);
        assert_eq!(id.to_string(), "ab".repeat(16));
        assert_eq!(id.key(), format!("identity/creation/{}", "ab".repeat(16)));
        assert_eq!(CreationId::parse(&"ab".repeat(16)), Some(id));
        assert_eq!(CreationId::parse(&"AB".repeat(16)), None, "uppercase");
        assert_eq!(CreationId::parse(&"ab".repeat(15)), None, "short");
        assert_eq!(CreationId::parse(&"zz".repeat(16)), None, "not hex");
        assert!(scp_platform::sanitize_key_component(&id.to_string()).is_ok());
    }

    #[test]
    fn fresh_ids_differ() -> TestResult {
        assert_ne!(CreationId::fresh()?, CreationId::fresh()?);
        Ok(())
    }
}
