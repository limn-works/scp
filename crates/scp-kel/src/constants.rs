//! The registered constants and domain separators the key-event codec reads.
//!
//! The bounds are `09-security-model.md` §9.18.17's registered values; the
//! separators are §9.7.4.2's and §9.18.2's. Each is a `u32` or a byte string,
//! never a `usize`, so no value here depends on the target's pointer width.

/// The most members a root set may carry (§9.18.17).
pub const MAX_ROOT_SET_SIZE: u32 = 16;

/// The most members a next set or commitment list may carry (§9.18.17).
pub const MAX_NEXT_SET_SIZE: u32 = 16;

/// The ceiling on one key event's encoded length in bytes (§9.18.17).
pub const MAX_EVENT_BYTES: u32 = 65_536;

/// The most witnesses a key-state snapshot may name (§9.18.17).
pub const MAX_WITNESS_SET_SIZE: u32 = 32;

/// The shortest witnessing interval in seconds (§9.18.17).
pub const MIN_WITNESSING_INTERVAL: u32 = 300;

/// The longest witnessing interval in seconds (§9.18.17).
pub const MAX_WITNESSING_INTERVAL: u32 = 604_800;

/// Prefixes the twelve field bytes in the signed preimage every event
/// digest, signature and identifier derivation reads (§9.7.4.2, R13).
pub const KEL_EVENT_SEPARATOR: &[u8] = b"SCP-KEL-EVENT-V1:";

/// Prefixes the inception event's signed preimage in the identifier
/// derivation (§9.7.4.2 R13; `03-identity.md` §3.1).
pub const KEL_ID_SEPARATOR: &[u8] = b"SCP-KEL-ID-V1:";

/// Prefixes a sealed event digest in a key-event seal (§9.7.4.2, field 11).
pub const KEL_SEAL_SEPARATOR: &[u8] = b"SCP-KEL-SEAL-V1:";

/// Prefixes a pre-rotation public key in its commitment (§9.7.4.2
/// definitions).
pub const PREROTATION_SEPARATOR: &[u8] = b"SCP-PREROTATION-COMMITMENT-V1:";

/// Prefixes an identifier in the routing identifier its key events are
/// stored under (§9.7.4.2 R13).
pub const KEY_EVENTS_ROUTING_SEPARATOR: &[u8] = b"scp:did:";

/// Prefixes an identifier in the routing identifier its cosigned heads are
/// stored under (§9.7.4.2 R13; §9.18.2).
pub const COSIGNED_HEADS_ROUTING_SEPARATOR: &[u8] = b"scp:wit:";

/// Prefixes an identifier in the routing identifier its witnesses' conflict
/// statements are stored under (§9.7.4.2 R13; §9.18.2).
pub const CONFLICT_STATEMENTS_ROUTING_SEPARATOR: &[u8] = b"scp:wcf:";

/// Prefixes an identifier in the routing identifier its service record is
/// stored under (§9.7.4.2 R13; §9.18.2; `03-identity.md` §3.10.13).
pub const SERVICE_RECORD_ROUTING_SEPARATOR: &[u8] = b"scp:svc:";
