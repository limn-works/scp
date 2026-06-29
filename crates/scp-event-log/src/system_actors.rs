//! Convergence-critical system `actor_did` sentinels.
//!
//! Some Merkle event-log leaves are minted by the protocol machinery itself
//! rather than by a member — e.g. a TTL timer firing, a cooperative close
//! finalizing, a cross-context divergence marker, or a governance-consequence
//! enforcement. These leaves carry a fixed *system* sentinel in the
//! [`Event::actor_did`](crate::Event::actor_did) field instead of a real DID.
//!
//! # Byte-parity convergence contract (§9.9.3)
//!
//! The leaf hash is `SHA-256(0x00 ‖ rmp_serde(Event))`, and `actor_did` is part
//! of the serialized [`Event`](crate::Event). For all honest members to mint
//! **byte-identical** leaves for the same logical system event — the
//! precondition for §9.9.3 equivocation detection — every member MUST stamp the
//! **exact same sentinel string** for the same event class.
//!
//! These constants are the single source of truth for those sentinels.
//! Referencing them from the native runtime (`scp-runtime`, which depends on
//! `scp-event-log`) makes convergence true *by construction* rather than by
//! convention (a bare duplicated string literal is one typo away from a silent
//! equivocation false-positive). Production sites and the parity KATs reference
//! these consts.

/// `actor_did` sentinel for a TTL-timer-driven `ContextExpired` leaf.
///
/// Stamped by the timer-fire path when a context's TTL elapses. Must be
/// byte-identical across all honest members (§9.9.3).
pub const SYSTEM_TIMER_ACTOR: &str = "system:timer";

/// `actor_did` sentinel for a cooperative-close `ContextClosed` leaf.
///
/// Stamped by the close-finalization path. Must be byte-identical across
/// all honest members (§9.9.3).
pub const SYSTEM_CLOSE_ACTOR: &str = "system:close";

/// `actor_did` sentinel for a saga `CrossContextDivergenceMarker` leaf.
///
/// Stamped by the cross-context saga machinery. Native-only leaf today, but
/// hoisted here for a single source of truth and forward cross-bridge parity.
pub const SYSTEM_SAGA_ACTOR: &str = "system:saga";

/// `actor_did` sentinel for governance-consequence enforcement leaves.
///
/// Stamped when an automated governance consequence (rate-limit, freeze, etc.)
/// is enforced on a subject. Must be byte-identical across all honest members
/// (§9.9.3).
pub const SYSTEM_CONSEQUENCE_ACTOR: &str = "system";
