//! The registered constants and domain separators the key-event codec reads.
//!
//! The bounds are `09-security-model.md` §9.18.17's registered values; the
//! separators are §9.7.4.2's and §9.18.2's. Each is a `u32` or a byte string,
//! never a `usize`, so no value here depends on the target's pointer width.
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

/// The most witnesses a key-state snapshot may name (§9.18.17).
pub const MAX_WITNESS_SET_SIZE: u32 = 32;

/// Prefixes the twelve field bytes in the signed preimage every event
/// digest, signature and identifier derivation reads (§9.7.4.2, R13).
/// Crate-private: `EncodedPreimage` is the one public path to these bytes.
pub(crate) const KEL_EVENT_SEPARATOR: &[u8] = b"SCP-KEL-EVENT-V1:";

/// Prefixes the inception event's signed preimage in the identifier
/// derivation (§9.7.4.2 R13; `03-identity.md` §3.1). Crate-private:
/// `EncodedPreimage::identifier` is the one public path to the derivation.
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
