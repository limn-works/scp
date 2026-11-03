//! The key-event record frame, `KeyEventRecordV2`, that carries one segment
//! of an identity's key-event log at `scp:did:` (`09-security-model.md`
//! §9.10.12, **Frame layout** and **`value` layout**).
//!
//! ```text
//! frame := 0x02 ‖ identifier (32) ‖ value
//! value := BE64(first_sequence) ‖ BE64(last_sequence) ‖ BE32(event_count) ‖ events
//! event := BE32(len) ‖ signed preimage ‖ signature field
//! ```
//!
//! [`decode_key_event_frame`] runs every decoder rule §9.10.12 states: the
//! three prefix rules, a non-empty `value`, `event_count` in
//! `1..=MAX_EVENTS_PER_FRAME`, a declared range equal to the sequences the
//! events carry, each event's length prefix within `value`, each signature
//! field walked to its end, and the events ending exactly at `value`'s end.
//! It verifies no signature: R3's check order is
//! [`scp_kel::validate_entry`]'s, which the caller runs over the units this
//! decoder returns.

use scp_did::Identifier;
use scp_kel::constants::MAX_EVENTS_PER_FRAME;
use scp_kel::{EventKind, EventUnit, decode_event};

use super::frame::{FramePrefixError, MAX_RECORD_FRAME_VALUE_LEN, join_frame, split_frame};

/// The key-event record frame's version byte (§9.10.12).
pub const KEY_EVENT_FRAME_VERSION: u8 = 2;

/// `first_sequence` (8), `last_sequence` (8) and `event_count` (4).
const VALUE_HEADER_LEN: usize = 20;

/// One event the frame carries, as read: its unit bytes and the header
/// fields frame admission reads (§9.7.4.2 R10, *Frame admission*).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameEvent<'a> {
    unit: &'a [u8],
    digest: [u8; 32],
    sequence: u64,
    kind: EventKind,
    predecessor: [u8; 32],
    recomputed: Identifier,
}

impl<'a> FrameEvent<'a> {
    /// The event unit, `BE32(len) ‖ signed preimage ‖ signature field`, the
    /// shape [`scp_kel::validate_entry`] reads.
    #[must_use]
    pub const fn unit(&self) -> &'a [u8] {
        self.unit
    }

    /// The event's preimage digest (§9.7.4.2 R9: an event is identified by
    /// its preimage digest).
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// The sequence field 3 carries.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// The kind field 1 carries.
    #[must_use]
    pub const fn kind(&self) -> EventKind {
        self.kind
    }

    /// The predecessor digest field 4 carries; zero on an inception.
    #[must_use]
    pub const fn predecessor(&self) -> &[u8; 32] {
        &self.predecessor
    }

    /// The identifier the signed preimage recomputes to (§9.7.4.2 R2).
    #[must_use]
    pub const fn recomputed_identifier(&self) -> Identifier {
        self.recomputed
    }
}

/// A key-event record frame that passed every §9.10.12 decoder rule. Its
/// events are unverified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyEventFrame<'a> {
    identifier: Identifier,
    events: Vec<FrameEvent<'a>>,
}

impl<'a> KeyEventFrame<'a> {
    /// The unsigned `identifier` field, which binds the frame to its routing
    /// id and nothing else (§9.10.12).
    #[must_use]
    pub const fn identifier(&self) -> Identifier {
        self.identifier
    }

    /// The events, in ascending sequence order; never empty.
    #[must_use]
    pub fn events(&self) -> &[FrameEvent<'a>] {
        &self.events
    }

    /// The first event; a decoded frame carries at least one.
    #[must_use]
    pub fn first(&self) -> Option<&FrameEvent<'a>> {
        self.events.first()
    }
}

/// Why bytes are not a key-event record frame (§9.10.12). A node answers
/// every variant with ADR-004's `4040`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyEventFrameError {
    /// A prefix rule.
    #[error(transparent)]
    Prefix(#[from] FramePrefixError),
    /// `value` is empty.
    #[error("key-event frame value is empty")]
    EmptyValue,
    /// `value` is shorter than its 20-byte header.
    #[error("key-event frame value is {0} bytes, shorter than its 20-byte header")]
    ValueHeaderTruncated(usize),
    /// `event_count` is zero.
    #[error("key-event frame carries no event")]
    NoEvents,
    /// `event_count` exceeds `MAX_EVENTS_PER_FRAME`, refused before any
    /// signature is checked so the publisher re-segments.
    #[error("key-event frame declares {0} events, more than MAX_EVENTS_PER_FRAME")]
    TooManyEvents(u32),
    /// `last_sequence` is below `first_sequence`.
    #[error("key-event frame range ends at {last} before it starts at {first}")]
    RangeInverted {
        /// `first_sequence`.
        first: u64,
        /// `last_sequence`.
        last: u64,
    },
    /// `last_sequence − first_sequence + 1` differs from `event_count`.
    #[error("key-event frame range {first}..={last} does not hold {count} events")]
    RangeMismatch {
        /// `first_sequence`.
        first: u64,
        /// `last_sequence`.
        last: u64,
        /// `event_count`.
        count: u32,
    },
    /// An event's length prefix, or the bytes it covers, run past `value`.
    #[error("key-event frame event {0} runs past the frame's value")]
    EventUnframed(u32),
    /// An event's signed preimage does not begin with the event separator.
    #[error("key-event frame event {0} lacks the SCP-KEL-EVENT-V1: separator")]
    EventNoSeparator(u32),
    /// An event's header does not decode, so its signature field's length
    /// is unknown.
    #[error("key-event frame event {0} has a header that does not decode")]
    EventHeader(u32),
    /// An event's signature field does not walk.
    #[error("key-event frame event {0} has a signature field that does not walk")]
    EventSignatureField(u32),
    /// An event's sequence is not the one the declared range puts there.
    #[error("key-event frame event {index} carries sequence {found}, expected {expected}")]
    SequenceMismatch {
        /// The event's position in the frame.
        index: u32,
        /// The sequence the range puts there.
        expected: u64,
        /// The sequence field 3 carries.
        found: u64,
    },
    /// Bytes follow the last event.
    #[error("key-event frame carries {0} bytes after its last event")]
    TrailingBytes(usize),
}

const fn be_u64(bytes: &[u8]) -> u64 {
    let mut out = [0u8; 8];
    out.copy_from_slice(bytes);
    u64::from_be_bytes(out)
}

const fn be_u32(bytes: &[u8]) -> u32 {
    let mut out = [0u8; 4];
    out.copy_from_slice(bytes);
    u32::from_be_bytes(out)
}

/// Decodes a key-event record frame under every §9.10.12 decoder rule, in
/// the order the section states them.
///
/// No allocation is sized from `event_count`: the events vector grows one
/// read event at a time, and the count is checked against
/// `MAX_EVENTS_PER_FRAME` first.
///
/// # Errors
///
/// [`KeyEventFrameError`] names the first rule the bytes break.
pub fn decode_key_event_frame(bytes: &[u8]) -> Result<KeyEventFrame<'_>, KeyEventFrameError> {
    let (identifier, value) = split_frame(bytes, KEY_EVENT_FRAME_VERSION)?;
    if value.is_empty() {
        return Err(KeyEventFrameError::EmptyValue);
    }
    let Some((header, events)) = value.split_at_checked(VALUE_HEADER_LEN) else {
        return Err(KeyEventFrameError::ValueHeaderTruncated(value.len()));
    };
    let first = be_u64(&header[..8]);
    let last = be_u64(&header[8..16]);
    let count = be_u32(&header[16..]);
    if count == 0 {
        return Err(KeyEventFrameError::NoEvents);
    }
    if count > MAX_EVENTS_PER_FRAME {
        return Err(KeyEventFrameError::TooManyEvents(count));
    }
    if last < first {
        return Err(KeyEventFrameError::RangeInverted { first, last });
    }
    if last - first != u64::from(count) - 1 {
        return Err(KeyEventFrameError::RangeMismatch { first, last, count });
    }
    let mut read = Vec::new();
    let mut offset = 0usize;
    for index in 0..count {
        let unit = match decode_event(events, offset) {
            EventUnit::Unframed => return Err(KeyEventFrameError::EventUnframed(index)),
            EventUnit::NoSeparator => return Err(KeyEventFrameError::EventNoSeparator(index)),
            EventUnit::HeaderFailed(_) => return Err(KeyEventFrameError::EventHeader(index)),
            EventUnit::Read(unit) => unit,
        };
        let consumed = unit
            .signature_field()
            .map_err(|_| KeyEventFrameError::EventSignatureField(index))?
            .consumed();
        // `first + index` cannot overflow: `last − first + 1 == count` and
        // `index < count`, so it is at most `last`.
        let expected = first + u64::from(index);
        let header = unit.header();
        if header.sequence() != expected {
            return Err(KeyEventFrameError::SequenceMismatch {
                index,
                expected,
                found: header.sequence(),
            });
        }
        let end = offset
            .checked_add(consumed)
            .filter(|end| *end <= events.len())
            .ok_or(KeyEventFrameError::EventUnframed(index))?;
        read.push(FrameEvent {
            unit: &events[offset..end],
            digest: unit.raw().event_digest(),
            sequence: expected,
            kind: header.kind(),
            predecessor: *header.predecessor_digest(),
            recomputed: unit.raw().identifier(),
        });
        offset = end;
    }
    if offset != events.len() {
        return Err(KeyEventFrameError::TrailingBytes(events.len() - offset));
    }
    Ok(KeyEventFrame {
        identifier,
        events: read,
    })
}

/// Encodes a frame carrying `units`, each `BE32(len) ‖ signed preimage ‖
/// signature field`, at ascending sequences from `first_sequence`.
///
/// It checks the count and the `value` bound; it reads no unit, so a frame
/// it builds from malformed units fails [`decode_key_event_frame`].
///
/// # Errors
///
/// [`KeyEventFrameError::NoEvents`], [`KeyEventFrameError::TooManyEvents`],
/// or [`FramePrefixError::ValueTooLarge`] inside
/// [`KeyEventFrameError::Prefix`]; [`KeyEventFrameError::RangeInverted`]
/// where the last sequence overflows `u64`.
pub fn encode_key_event_frame(
    identifier: &Identifier,
    first_sequence: u64,
    units: &[&[u8]],
) -> Result<Vec<u8>, KeyEventFrameError> {
    let count =
        u32::try_from(units.len()).map_err(|_| KeyEventFrameError::TooManyEvents(u32::MAX))?;
    if count == 0 {
        return Err(KeyEventFrameError::NoEvents);
    }
    if count > MAX_EVENTS_PER_FRAME {
        return Err(KeyEventFrameError::TooManyEvents(count));
    }
    let last = first_sequence.checked_add(u64::from(count) - 1).ok_or(
        KeyEventFrameError::RangeInverted {
            first: first_sequence,
            last: u64::MAX,
        },
    )?;
    let mut value =
        Vec::with_capacity(VALUE_HEADER_LEN + units.iter().map(|u| u.len()).sum::<usize>());
    value.extend_from_slice(&first_sequence.to_be_bytes());
    value.extend_from_slice(&last.to_be_bytes());
    value.extend_from_slice(&count.to_be_bytes());
    for unit in units {
        value.extend_from_slice(unit);
    }
    if value.len() > MAX_RECORD_FRAME_VALUE_LEN {
        return Err(FramePrefixError::ValueTooLarge(value.len()).into());
    }
    Ok(join_frame(KEY_EVENT_FRAME_VERSION, identifier, &value))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(first: u64, last: u64, count: u32, events: &[u8]) -> Vec<u8> {
        let mut value = first.to_be_bytes().to_vec();
        value.extend_from_slice(&last.to_be_bytes());
        value.extend_from_slice(&count.to_be_bytes());
        value.extend_from_slice(events);
        join_frame(KEY_EVENT_FRAME_VERSION, &Identifier::ZERO, &value)
    }

    #[test]
    fn an_empty_value_is_refused() {
        let frame = join_frame(KEY_EVENT_FRAME_VERSION, &Identifier::ZERO, &[]);
        assert_eq!(
            decode_key_event_frame(&frame),
            Err(KeyEventFrameError::EmptyValue)
        );
    }

    #[test]
    fn a_value_shorter_than_its_header_is_refused() {
        let frame = join_frame(KEY_EVENT_FRAME_VERSION, &Identifier::ZERO, &[0; 19]);
        assert_eq!(
            decode_key_event_frame(&frame),
            Err(KeyEventFrameError::ValueHeaderTruncated(19))
        );
    }

    #[test]
    fn a_zero_count_is_refused() {
        assert_eq!(
            decode_key_event_frame(&value(0, 0, 0, &[])),
            Err(KeyEventFrameError::NoEvents)
        );
    }

    #[test]
    fn a_count_past_the_cap_is_refused_before_any_event_is_read() {
        assert_eq!(
            decode_key_event_frame(&value(0, 16, 17, &[])),
            Err(KeyEventFrameError::TooManyEvents(17))
        );
    }

    #[test]
    fn an_inverted_range_is_refused() {
        assert_eq!(
            decode_key_event_frame(&value(5, 4, 1, &[])),
            Err(KeyEventFrameError::RangeInverted { first: 5, last: 4 })
        );
    }

    #[test]
    fn a_range_that_does_not_hold_the_count_is_refused() {
        assert_eq!(
            decode_key_event_frame(&value(0, 3, 2, &[])),
            Err(KeyEventFrameError::RangeMismatch {
                first: 0,
                last: 3,
                count: 2
            })
        );
    }

    #[test]
    fn an_event_whose_prefix_runs_past_value_is_refused() {
        assert_eq!(
            decode_key_event_frame(&value(0, 0, 1, &[0, 0, 1, 0])),
            Err(KeyEventFrameError::EventUnframed(0))
        );
    }

    #[test]
    fn an_event_without_the_separator_is_refused() {
        let mut unit = 3u32.to_be_bytes().to_vec();
        unit.extend_from_slice(b"abc");
        assert_eq!(
            decode_key_event_frame(&value(0, 0, 1, &unit)),
            Err(KeyEventFrameError::EventNoSeparator(0))
        );
    }

    #[test]
    fn an_event_whose_header_does_not_decode_is_refused() {
        let signed = b"SCP-KEL-EVENT-V1:\x09";
        let mut unit = u32::try_from(signed.len())
            .unwrap_or(0)
            .to_be_bytes()
            .to_vec();
        unit.extend_from_slice(signed);
        assert_eq!(
            decode_key_event_frame(&value(0, 0, 1, &unit)),
            Err(KeyEventFrameError::EventHeader(0))
        );
    }

    #[test]
    fn the_encoder_refuses_an_empty_and_an_oversized_frame() {
        assert_eq!(
            encode_key_event_frame(&Identifier::ZERO, 0, &[]),
            Err(KeyEventFrameError::NoEvents)
        );
        let units: Vec<&[u8]> = vec![b"x"; 17];
        assert_eq!(
            encode_key_event_frame(&Identifier::ZERO, 0, &units),
            Err(KeyEventFrameError::TooManyEvents(17))
        );
        let big = vec![0u8; MAX_RECORD_FRAME_VALUE_LEN];
        assert!(matches!(
            encode_key_event_frame(&Identifier::ZERO, 0, &[&big]),
            Err(KeyEventFrameError::Prefix(FramePrefixError::ValueTooLarge(
                _
            )))
        ));
    }
}
