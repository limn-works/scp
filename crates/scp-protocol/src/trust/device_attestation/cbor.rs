//! The CBOR decoder and core deterministic encoder that App Attest checks 1
//! and 2 use (`09-security-model.md` §9.3.1, RFC 8949).
//!
//! The decoder accepts every well-formed RFC 8949 item: definite and
//! indefinite lengths, length headers longer than necessary, tags, repeated
//! map keys (kept as separate pairs), and every major-type-7 value. It decides
//! well-formedness only. Check 1 decides canonical form the way §9.3.1
//! "Canonical encodings" states it: it re-encodes the decoded value with
//! [`encode_canonical`] and compares the bytes with its input.
//!
//! The decoder is bounded by its input. It nests at most [`MAX_DEPTH`] levels,
//! never reserves memory from a declared count or length, and every item it
//! reads consumes at least one input byte, so a hostile header costs at most
//! the bytes that follow it.

/// The deepest nesting of arrays, maps and tags the decoder accepts. An App
/// Attest object nests three levels (map, `attStmt` map, `x5c` array); the
/// extensions map inside `authData` nests two.
pub(super) const MAX_DEPTH: usize = 16;

/// One decoded CBOR data item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Value {
    /// Major type 0.
    Unsigned(u64),
    /// Major type 1: the value `-1 - n` for the stored `n`.
    Negative(u64),
    /// Major type 2, with indefinite-length chunks joined.
    Bytes(Vec<u8>),
    /// Major type 3, with indefinite-length chunks joined.
    Text(String),
    /// Major type 4.
    Array(Vec<Self>),
    /// Major type 5, in input order, repeated keys kept.
    Map(Vec<(Self, Self)>),
    /// Major type 6: the tag number and the tagged item.
    Tag(u64, Box<Self>),
    /// Major type 7 simple value (`false`, `true`, `null`, `undefined` and
    /// the unassigned values).
    Simple(u8),
    /// Major type 7 floating-point value: its width in bytes (2, 4 or 8) and
    /// its bits. The encoder refuses it, because no position check 1 admits
    /// holds a float.
    Float(u8, u64),
}

/// The input is not one well-formed RFC 8949 item, or it nests deeper than
/// [`MAX_DEPTH`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct NotWellFormed;

/// The value has no core deterministic encoding this encoder writes: it holds
/// a float, or a map with two keys whose encodings are equal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct NotCanonical;

/// Decodes the one item at the start of `input` and returns it with the
/// number of bytes it took.
pub(super) fn decode_prefix(input: &[u8]) -> Result<(Value, usize), NotWellFormed> {
    let mut decoder = Decoder { input, pos: 0 };
    let value = decoder.item(0)?.ok_or(NotWellFormed)?;
    Ok((value, decoder.pos))
}

/// Decodes `input` as exactly one item, with no bytes after it.
pub(super) fn decode_exact(input: &[u8]) -> Result<Value, NotWellFormed> {
    let (value, used) = decode_prefix(input)?;
    if used == input.len() {
        Ok(value)
    } else {
        Err(NotWellFormed)
    }
}

struct Decoder<'a> {
    input: &'a [u8],
    pos: usize,
}

/// The `0xff` break byte that ends an indefinite-length item.
const BREAK: u8 = 0xff;

impl<'a> Decoder<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], NotWellFormed> {
        let end = self.pos.checked_add(len).ok_or(NotWellFormed)?;
        let bytes = self.input.get(self.pos..end).ok_or(NotWellFormed)?;
        self.pos = end;
        Ok(bytes)
    }

    fn byte(&mut self) -> Result<u8, NotWellFormed> {
        let [byte] = self.take(1)? else {
            return Err(NotWellFormed);
        };
        Ok(*byte)
    }

    fn peek(&self) -> Result<u8, NotWellFormed> {
        self.input.get(self.pos).copied().ok_or(NotWellFormed)
    }

    /// Reads the argument that additional information `info` announces.
    /// `None` is the indefinite-length marker (31).
    fn argument(&mut self, info: u8) -> Result<Option<u64>, NotWellFormed> {
        let width = match info {
            0..=23 => return Ok(Some(u64::from(info))),
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            31 => return Ok(None),
            _ => return Err(NotWellFormed),
        };
        let bytes = self.take(width)?;
        Ok(Some(
            bytes
                .iter()
                .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte)),
        ))
    }

    fn length(value: u64) -> Result<usize, NotWellFormed> {
        usize::try_from(value).map_err(|_| NotWellFormed)
    }

    /// Reads one item. `Ok(None)` is a break byte, which only an
    /// indefinite-length array or map may hold.
    fn item(&mut self, depth: usize) -> Result<Option<Value>, NotWellFormed> {
        let initial = self.byte()?;
        let major = initial >> 5;
        let info = initial & 0x1f;
        match major {
            0 => Ok(Some(Value::Unsigned(self.definite(info)?))),
            1 => Ok(Some(Value::Negative(self.definite(info)?))),
            2 => self
                .string(major, info)
                .map(|bytes| Some(Value::Bytes(bytes))),
            3 => {
                let bytes = self.string(major, info)?;
                String::from_utf8(bytes)
                    .map(|text| Some(Value::Text(text)))
                    .map_err(|_| NotWellFormed)
            }
            4 => {
                let depth = Self::deeper(depth)?;
                let mut items = Vec::new();
                match self.argument(info)? {
                    Some(count) => {
                        for _ in 0..count {
                            items.push(self.item(depth)?.ok_or(NotWellFormed)?);
                        }
                    }
                    None => {
                        while let Some(item) = self.item(depth)? {
                            items.push(item);
                        }
                    }
                }
                Ok(Some(Value::Array(items)))
            }
            5 => {
                let depth = Self::deeper(depth)?;
                let mut pairs = Vec::new();
                match self.argument(info)? {
                    Some(count) => {
                        for _ in 0..count {
                            let key = self.item(depth)?.ok_or(NotWellFormed)?;
                            let value = self.item(depth)?.ok_or(NotWellFormed)?;
                            pairs.push((key, value));
                        }
                    }
                    None => {
                        while let Some(key) = self.item(depth)? {
                            let value = self.item(depth)?.ok_or(NotWellFormed)?;
                            pairs.push((key, value));
                        }
                    }
                }
                Ok(Some(Value::Map(pairs)))
            }
            6 => {
                let number = self.definite(info)?;
                let depth = Self::deeper(depth)?;
                let tagged = self.item(depth)?.ok_or(NotWellFormed)?;
                Ok(Some(Value::Tag(number, Box::new(tagged))))
            }
            _ => self.simple_or_float(info),
        }
    }

    const fn deeper(depth: usize) -> Result<usize, NotWellFormed> {
        let next = depth + 1;
        if next > MAX_DEPTH {
            Err(NotWellFormed)
        } else {
            Ok(next)
        }
    }

    /// An argument that may not be indefinite (major types 0, 1 and 6).
    fn definite(&mut self, info: u8) -> Result<u64, NotWellFormed> {
        self.argument(info)?.ok_or(NotWellFormed)
    }

    /// A byte or text string's bytes. An indefinite-length string is a run of
    /// definite-length chunks of the same major type, ended by a break; each
    /// text chunk must itself be valid UTF-8 (RFC 8949 §3.2.3).
    fn string(&mut self, major: u8, info: u8) -> Result<Vec<u8>, NotWellFormed> {
        if let Some(len) = self.argument(info)? {
            return Ok(self.take(Self::length(len)?)?.to_vec());
        }
        let mut joined = Vec::new();
        loop {
            if self.peek()? == BREAK {
                self.pos += 1;
                return Ok(joined);
            }
            let chunk_initial = self.byte()?;
            if chunk_initial >> 5 != major {
                return Err(NotWellFormed);
            }
            let len = self.definite(chunk_initial & 0x1f)?;
            let chunk = self.take(Self::length(len)?)?;
            if major == 3 && core::str::from_utf8(chunk).is_err() {
                return Err(NotWellFormed);
            }
            joined.extend_from_slice(chunk);
        }
    }

    fn simple_or_float(&mut self, info: u8) -> Result<Option<Value>, NotWellFormed> {
        match info {
            0..=23 => Ok(Some(Value::Simple(info))),
            24 => {
                let simple = self.byte()?;
                // RFC 8949 §3.3: a one-byte simple value below 32 is not
                // well-formed.
                if simple < 32 {
                    Err(NotWellFormed)
                } else {
                    Ok(Some(Value::Simple(simple)))
                }
            }
            25..=27 => {
                let width: u8 = match info {
                    25 => 2,
                    26 => 4,
                    _ => 8,
                };
                let bits = self.argument(info)?.ok_or(NotWellFormed)?;
                Ok(Some(Value::Float(width, bits)))
            }
            31 => Ok(None),
            _ => Err(NotWellFormed),
        }
    }
}

/// Writes `value` in the core deterministic encoding of RFC 8949 §4.2.1:
/// shortest argument form, definite lengths, and each map's keys sorted by
/// the bytewise order of their encodings.
pub(super) fn encode_canonical(value: &Value, out: &mut Vec<u8>) -> Result<(), NotCanonical> {
    match value {
        Value::Unsigned(n) => head(0, *n, out),
        Value::Negative(n) => head(1, *n, out),
        Value::Bytes(bytes) => {
            head(2, len_u64(bytes.len()), out);
            out.extend_from_slice(bytes);
        }
        Value::Text(text) => {
            head(3, len_u64(text.len()), out);
            out.extend_from_slice(text.as_bytes());
        }
        Value::Array(items) => {
            head(4, len_u64(items.len()), out);
            for item in items {
                encode_canonical(item, out)?;
            }
        }
        Value::Map(pairs) => {
            let mut encoded = Vec::with_capacity(pairs.len());
            for (key, item) in pairs {
                let mut key_bytes = Vec::new();
                encode_canonical(key, &mut key_bytes)?;
                encoded.push((key_bytes, item));
            }
            encoded.sort_by(|left, right| left.0.cmp(&right.0));
            if encoded.windows(2).any(|pair| match pair {
                [left, right] => left.0 == right.0,
                _ => false,
            }) {
                return Err(NotCanonical);
            }
            head(5, len_u64(encoded.len()), out);
            for (key_bytes, item) in encoded {
                out.extend_from_slice(&key_bytes);
                encode_canonical(item, out)?;
            }
        }
        Value::Tag(number, tagged) => {
            head(6, *number, out);
            encode_canonical(tagged, out)?;
        }
        Value::Simple(simple) => {
            if *simple < 24 {
                out.push(0xe0 | simple);
            } else {
                out.extend_from_slice(&[0xf8, *simple]);
            }
        }
        Value::Float(..) => return Err(NotCanonical),
    }
    Ok(())
}

/// The shortest head for `major` and argument `n` (RFC 8949 §4.2.1, first
/// rule).
fn head(major: u8, n: u64, out: &mut Vec<u8>) {
    let major = major << 5;
    if let Ok(small) = u8::try_from(n) {
        if small < 24 {
            out.push(major | small);
        } else {
            out.extend_from_slice(&[major | 0x18, small]);
        }
    } else if let Ok(two) = u16::try_from(n) {
        out.push(major | 0x19);
        out.extend_from_slice(&two.to_be_bytes());
    } else if let Ok(four) = u32::try_from(n) {
        out.push(major | 0x1a);
        out.extend_from_slice(&four.to_be_bytes());
    } else {
        out.push(major | 0x1b);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

/// A length as a CBOR argument. `usize` is at most 64 bits on every target
/// SCP builds for, so the conversion saturates only in theory.
fn len_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

/// The value a text key maps to in `pairs`, when exactly one pair has that
/// key. `Err` when two pairs have it.
pub(super) fn lookup<'v>(
    pairs: &'v [(Value, Value)],
    key: &str,
) -> Result<Option<&'v Value>, NotCanonical> {
    let mut found = None;
    for (candidate, value) in pairs {
        if matches!(candidate, Value::Text(text) if text == key) {
            if found.is_some() {
                return Err(NotCanonical);
            }
            found = Some(value);
        }
    }
    Ok(found)
}

/// The `fmt` value of an App Attest attestation object.
pub const APP_ATTEST_FMT: &str = "apple-appattest";

/// Whether a decoded value has the shape App Attest check 1 requires: a map
/// holding exactly `fmt` (the text [`APP_ATTEST_FMT`]), `attStmt` and
/// `authData` (a byte string); `attStmt` a map holding exactly `x5c`, or
/// exactly `x5c` and a byte-string `receipt`; `x5c` an array of exactly two
/// byte strings. A tag on any of these values fails, because a tagged item is
/// a [`Value::Tag`], not the type the position requires.
pub(super) fn is_app_attest_object_shape(value: &Value) -> bool {
    let Value::Map(pairs) = value else {
        return false;
    };
    let (Ok(Some(Value::Text(fmt))), Ok(Some(Value::Map(statement))), Ok(Some(Value::Bytes(_)))) = (
        lookup(pairs, "fmt"),
        lookup(pairs, "attStmt"),
        lookup(pairs, "authData"),
    ) else {
        return false;
    };
    // Three pairs, each of the three keys found exactly once: no other key.
    pairs.len() == 3 && fmt == APP_ATTEST_FMT && is_statement_shape(statement)
}

fn is_x5c_shape(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Array(items))
        if items.len() == 2 && items.iter().all(|item| matches!(item, Value::Bytes(_))))
}

fn is_statement_shape(pairs: &[(Value, Value)]) -> bool {
    let Ok(x5c) = lookup(pairs, "x5c") else {
        return false;
    };
    match pairs.len() {
        1 => is_x5c_shape(x5c),
        2 => is_x5c_shape(x5c) && matches!(lookup(pairs, "receipt"), Ok(Some(Value::Bytes(_)))),
        _ => false,
    }
}

/// Why [`canonicalize_app_attest_object`] refused an attestation object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AppAttestObjectError {
    /// The input is not exactly one well-formed CBOR item.
    #[error("attestation object is not one well-formed CBOR item")]
    NotWellFormed,
    /// The item lacks a key App Attest check 1 requires, repeats one, or holds
    /// a value of another type or a tagged value there.
    #[error(
        "attestation object does not hold the fmt, attStmt.x5c and authData App Attest check 1 requires"
    )]
    UnexpectedShape,
}

/// The owner's re-encoding of an attestation object before it publishes it
/// (`09-security-model.md` §9.3.1, "Canonical encodings").
///
/// Keeps only `fmt`, `attStmt` with its `x5c`, and `authData`, drops
/// `receipt` and every other key Apple adds, and writes the result in the core deterministic encoding
/// of RFC 8949 §4.2.1. `authData` and each certificate are copied byte for
/// byte. The output passes App Attest check 1, and canonicalizing it again
/// returns it unchanged.
///
/// # Errors
///
/// [`AppAttestObjectError::NotWellFormed`] or
/// [`AppAttestObjectError::UnexpectedShape`].
pub fn canonicalize_app_attest_object(object: &[u8]) -> Result<Vec<u8>, AppAttestObjectError> {
    let value = decode_exact(object).map_err(|_| AppAttestObjectError::NotWellFormed)?;
    let Value::Map(pairs) = &value else {
        return Err(AppAttestObjectError::UnexpectedShape);
    };
    let (
        Ok(Some(Value::Text(fmt))),
        Ok(Some(Value::Map(statement))),
        Ok(Some(Value::Bytes(auth_data))),
    ) = (
        lookup(pairs, "fmt"),
        lookup(pairs, "attStmt"),
        lookup(pairs, "authData"),
    )
    else {
        return Err(AppAttestObjectError::UnexpectedShape);
    };
    let Ok(x5c @ Some(Value::Array(certificates))) = lookup(statement, "x5c") else {
        return Err(AppAttestObjectError::UnexpectedShape);
    };
    if fmt != APP_ATTEST_FMT || !is_x5c_shape(x5c) {
        return Err(AppAttestObjectError::UnexpectedShape);
    }
    let kept = Value::Map(vec![
        (Value::Text("fmt".to_owned()), Value::Text(fmt.clone())),
        (
            Value::Text("attStmt".to_owned()),
            Value::Map(vec![(
                Value::Text("x5c".to_owned()),
                Value::Array(certificates.clone()),
            )]),
        ),
        (
            Value::Text("authData".to_owned()),
            Value::Bytes(auth_data.clone()),
        ),
    ]);
    let mut out = Vec::with_capacity(object.len());
    // The kept value holds only text, byte strings, one array and maps with
    // distinct keys, so the encoder cannot refuse it.
    encode_canonical(&kept, &mut out).map_err(|_| AppAttestObjectError::UnexpectedShape)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical(value: &Value) -> Vec<u8> {
        let mut out = Vec::new();
        assert_eq!(encode_canonical(value, &mut out), Ok(()));
        out
    }

    #[test]
    fn decodes_definite_and_indefinite_forms() {
        // [_ h'01', h'0203'] as an indefinite byte string: 0x5f 41 01 42 02 03 ff
        assert_eq!(
            decode_exact(&[0x5f, 0x41, 0x01, 0x42, 0x02, 0x03, 0xff]),
            Ok(Value::Bytes(vec![1, 2, 3]))
        );
        // A non-minimal head still decodes: 0x18 0x05 is 5.
        assert_eq!(decode_exact(&[0x18, 0x05]), Ok(Value::Unsigned(5)));
        // An indefinite map {"a": 1}.
        assert_eq!(
            decode_exact(&[0xbf, 0x61, b'a', 0x01, 0xff]),
            Ok(Value::Map(vec![(
                Value::Text("a".into()),
                Value::Unsigned(1)
            )]))
        );
        // A tag survives decoding.
        assert_eq!(
            decode_exact(&[0xc2, 0x41, 0x07]),
            Ok(Value::Tag(2, Box::new(Value::Bytes(vec![7]))))
        );
    }

    #[test]
    fn rejects_malformed_input() {
        for input in [
            &[][..],
            &[0x1c][..],                   // reserved additional information
            &[0x42, 0x01][..],             // truncated byte string
            &[0x5f, 0x61, 0x61, 0xff][..], // text chunk inside a byte string
            &[0xf8, 0x10][..],             // one-byte simple value below 32
            &[0xff][..],                   // a break with nothing open
            &[0x81][..],                   // array missing its element
            &[0x62, 0xff, 0xfe][..],       // invalid UTF-8 text
            &[0x01, 0x02][..],             // trailing bytes
        ] {
            assert_eq!(decode_exact(input), Err(NotWellFormed), "{input:02x?}");
        }
    }

    #[test]
    fn depth_is_bounded() {
        let mut nested = vec![0x81; MAX_DEPTH];
        nested.push(0x00);
        assert!(decode_exact(&nested).is_ok());
        let mut deeper = vec![0x81; MAX_DEPTH + 1];
        deeper.push(0x00);
        assert_eq!(decode_exact(&deeper), Err(NotWellFormed));
    }

    #[test]
    fn huge_declared_count_fails_without_allocating() {
        // An array that declares 2^64 - 1 elements and holds none.
        let input = [0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(decode_exact(&input), Err(NotWellFormed));
        let bytes = [0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(decode_exact(&bytes), Err(NotWellFormed));
    }

    #[test]
    fn canonical_encoding_sorts_keys_and_shortens_heads() {
        let value = Value::Map(vec![
            (Value::Text("authData".into()), Value::Bytes(vec![0; 24])),
            (Value::Text("fmt".into()), Value::Text("x".into())),
        ]);
        let bytes = canonical(&value);
        assert_eq!(&bytes[..5], &[0xa2, 0x63, b'f', b'm', b't']);
        // 24 bytes need the one-byte argument form.
        assert_eq!(
            &bytes[7..18],
            &[
                0x68, b'a', b'u', b't', b'h', b'D', b'a', b't', b'a', 0x58, 24
            ]
        );
        assert_eq!(decode_exact(&bytes).map(|v| canonical(&v)), Ok(bytes));
    }

    #[test]
    fn canonical_encoding_refuses_repeated_keys_and_floats() {
        let repeated = Value::Map(vec![
            (Value::Text("a".into()), Value::Unsigned(1)),
            (Value::Text("a".into()), Value::Unsigned(2)),
        ]);
        assert_eq!(
            encode_canonical(&repeated, &mut Vec::new()),
            Err(NotCanonical)
        );
        assert_eq!(
            encode_canonical(&Value::Float(2, 0), &mut Vec::new()),
            Err(NotCanonical)
        );
    }

    #[test]
    fn lookup_refuses_repeated_key() {
        let pairs = vec![
            (Value::Text("a".into()), Value::Unsigned(1)),
            (Value::Text("b".into()), Value::Unsigned(2)),
        ];
        assert_eq!(lookup(&pairs, "b"), Ok(Some(&Value::Unsigned(2))));
        assert_eq!(lookup(&pairs, "c"), Ok(None));
        let repeated = vec![
            (Value::Text("a".into()), Value::Unsigned(1)),
            (Value::Text("a".into()), Value::Unsigned(2)),
        ];
        assert_eq!(lookup(&repeated, "a"), Err(NotCanonical));
    }
}
