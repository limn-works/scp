//! The registered constants and domain separators the key-event codec reads.
//!
//! The bounds are `09-security-model.md` §9.18.17's registered values; the
//! separators are §9.7.4.2's and §9.18.2's; the staleness bound is §9.18.7's.
//! Each is a `u32`, a `u64` count of seconds, or a byte string, never a
//! `usize`, so no value here depends on the target's pointer width.
//!
//! Every separator is crate-private: each construction has one public
//! function that applies its separator (ADR-063, implementation
//! constraints), so no caller assembles a separated hash by hand.

/// The most members a root set may carry (§9.18.17).
pub const MAX_ROOT_SET_SIZE: u32 = 16;

/// The most members a next set or commitment list may carry (§9.18.17).
pub const MAX_NEXT_SET_SIZE: u32 = 16;

/// The ceiling on one key event's encoded length in bytes (§9.18.17).
pub const MAX_EVENT_BYTES: u32 = 65_536;

/// The most divergent suffixes a party retains per identifier, beside the
/// accepted chain (§9.18.17; §9.7.4.2 R9's count bound).
pub const MAX_RETAINED_SUFFIXES: u32 = 8;

/// The events-per-suffix factor of [`MAX_RETAINED_BYTES`]'s derivation
/// (§9.18.17). R9 compares a suffix's event count against nothing, so no
/// check reads it but that derivation.
pub const MAX_EVENTS_PER_SUFFIX_RETAINED: u32 = 1_024;

/// The byte bound and the fetch bound of §9.7.4.2 R9 (§9.18.17).
///
/// It caps the divergent-suffix bytes a party retains per identifier and
/// the bytes a verifier downloads for one identifier from one source in one
/// resolution: [`MAX_RETAINED_SUFFIXES`] × [`MAX_EVENTS_PER_SUFFIX_RETAINED`]
/// × [`MAX_EVENT_BYTES`] = 536,870,912.
pub const MAX_RETAINED_BYTES: u32 = 536_870_912;

// §9.18.17 derives the byte bound as the product of three registered
// constants; the value cannot drift from them.
const _: () = assert!(
    MAX_RETAINED_BYTES == MAX_RETAINED_SUFFIXES * MAX_EVENTS_PER_SUFFIX_RETAINED * MAX_EVENT_BYTES
);

/// The most seconds a resolved key state stays fresh (§9.18.7).
///
/// It is the maximum age of the key-event log a party relies on for a key
/// position (§9.7.1 check 2). `ResolvedState::is_fresh` reads it, and scp-mls re-exports it.
pub const MAX_ATTESTATION_KEY_RESOLUTION_STALENESS: u64 = 300;

/// The most witnesses a key-state snapshot may name (§9.18.17).
pub const MAX_WITNESS_SET_SIZE: u32 = 32;

/// The fewest bytes an assertion's `authenticatorData` may carry: the
/// 32-byte `rpIdHash`, the flags byte at byte 32, and the 4-byte counter
/// (§9.18.17; Web Authentication Level 2 §6.1).
pub const MIN_AUTHENTICATOR_DATA_BYTES: u32 = 37;

/// The most bytes an assertion's `authenticatorData` may carry (§9.18.17).
pub const MAX_AUTHENTICATOR_DATA_BYTES: u32 = 256;

/// The most bytes an assertion's `clientDataJSON` may carry (§9.18.17). The
/// fewest is one (§9.7.4.2, the assertion form's layout).
pub const MAX_CLIENT_DATA_JSON_BYTES: u32 = 512;

/// The bytes of the raw `r ‖ s` ECDSA P-256 signature both indexed-signature
/// forms carry (§9.5; §9.7.4.2, "Signature form").
pub const RAW_SIGNATURE_BYTES: u32 = 64;

/// The shortest witnessing interval a key-state snapshot may carry, in
/// seconds (§9.18.17).
pub const MIN_WITNESSING_INTERVAL: u32 = 300;

/// The longest witnessing interval a key-state snapshot may carry, in
/// seconds (§9.18.17).
pub const MAX_WITNESSING_INTERVAL: u32 = 604_800;

/// The encoded width of a `HeldHeadMarker` (§9.18.17).
///
/// The 32-byte identifier, the 8-byte big-endian sequence, the 32-byte preimage digest of the head a
/// device holding a key-event member last adopted, and the 1-byte mode,
/// `0x00` for `Any` and `0x01` for `RevealOnly` (§9.18.17; §9.7.4.2 R10).
pub const HELD_HEAD_MARKER_BYTES: u32 = 73;

/// The witnessing interval, in seconds, the SDK writes into a new identity's
/// first key-state snapshot (§9.18.17; §9.7.4.3, the SDK's default witness
/// set).
pub const DEFAULT_WITNESSING_INTERVAL: u32 = 3_600;

/// The encoded width of a `KeptComposition` (§9.18.17).
///
/// It holds the 32-byte identifier, the 8-byte big-endian sequence, and the
/// 32-byte preimage digest of an event the composing device returned as
/// awaiting signatures (§9.7.4.2 R10's abandonment rule).
pub const KEPT_COMPOSITION_BYTES: u32 = 72;

/// The encoded width of a `PendingSignatureRecord` (§9.18.17).
///
/// It holds the 32-byte identifier, the 8-byte big-endian sequence, and the
/// 32-byte preimage digest of an event a device signed and has not adopted
/// (§9.7.4.2 R10's signing rule).
pub const PENDING_SIGNATURE_RECORD_BYTES: u32 = 72;

// §9.18.17 bounds the default interval by the registered range.
const _: () = assert!(
    DEFAULT_WITNESSING_INTERVAL >= MIN_WITNESSING_INTERVAL
        && DEFAULT_WITNESSING_INTERVAL <= MAX_WITNESSING_INTERVAL
);

/// Prefixes an event's preimage digest in the `WebAuthn` challenge of an
/// assertion-form indexed signature (§9.7.4.2 definitions; §9.18.2). It is
/// distinct from [`KEL_EVENT_SEPARATOR`], so no key-event preimage is a
/// `WebAuthn` challenge. Its one public path is `key_event_challenge`.
pub(crate) const KEY_EVENT_CHALLENGE_SEPARATOR: &[u8] = b"SCP-KEY-EVENT-V1:";

/// Prefixes the nonce in a custody-reachability probe (§9.7.4.1 item 5,
/// step d; §9.18.2). It is distinct from [`KEL_EVENT_SEPARATOR`] and from
/// [`KEY_EVENT_CHALLENGE_SEPARATOR`], so no probe value equals an event
/// digest or a key-event challenge. Its one public path is `CustodyProbe`.
pub(crate) const CUSTODY_PROBE_SEPARATOR: &[u8] = b"SCP-CUSTODY-PROBE-V1:";

/// Prefixes the twelve field bytes in the signed preimage every event
/// digest, signature and identifier derivation reads (§9.7.4.2, R13).
/// Crate-private: `EncodedPreimage` and `RawSignedPreimage` are the public
/// paths to these bytes. Each holds the field bytes and implies the
/// separator; `preimage::field_bytes` is the one place that strips it.
pub(crate) const KEL_EVENT_SEPARATOR: &[u8] = b"SCP-KEL-EVENT-V1:";

/// Prefixes the inception event's signed preimage in the identifier
/// derivation (§9.7.4.2 R13; `03-identity.md` §3.1). Crate-private:
/// `preimage::identifier_of` is the one computation, reached through
/// `EncodedPreimage::inception_identifier`, `derive_identifier` and
/// `RawSignedPreimage::identifier`.
pub(crate) const KEL_ID_SEPARATOR: &[u8] = b"SCP-KEL-ID-V1:";

/// Prefixes a sealed event digest in a key-event seal (§9.7.4.2, field 11).
/// Its one public path is `key_event_seal`.
pub(crate) const KEL_SEAL_SEPARATOR: &[u8] = b"SCP-KEL-SEAL-V1:";

/// Prefixes a pre-rotation public key in its commitment (§9.7.4.2
/// definitions). Its one public path is `prerotation_commitment`.
pub(crate) const PREROTATION_SEPARATOR: &[u8] = b"SCP-PREROTATION-COMMITMENT-V1:";

/// Prefixes an identifier in the routing identifier its key events are
/// stored under (§9.7.4.2 R13). Its one public path is `routing_id`.
pub(crate) const KEY_EVENTS_ROUTING_SEPARATOR: &[u8] = b"scp:did:";

/// Prefixes an identifier in the routing identifier its cosigned heads are
/// stored under (§9.7.4.2 R13; §9.18.2). Its one public path is `routing_id`.
pub(crate) const COSIGNED_HEADS_ROUTING_SEPARATOR: &[u8] = b"scp:wit:";

/// Prefixes an identifier in the routing identifier its witnesses' conflict
/// statements are stored under (§9.7.4.2 R13; §9.18.2). Its one public path
/// is `routing_id`.
pub(crate) const CONFLICT_STATEMENTS_ROUTING_SEPARATOR: &[u8] = b"scp:wcf:";

/// Prefixes an identifier in the routing identifier its service record is
/// stored under (§9.7.4.2 R13; §9.18.2; `03-identity.md` §3.10.13). Its one
/// public path is `routing_id`.
pub(crate) const SERVICE_RECORD_ROUTING_SEPARATOR: &[u8] = b"scp:svc:";
