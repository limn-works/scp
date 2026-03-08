//! Nostr transport adapter for SCP (NIP-01 relay protocol).
//!
//! This module implements the Nostr-based transport per spec section 10.5.2.
//! Nostr (NIP-01) provides a simple relay protocol over WebSocket, enabling
//! SCP to leverage existing Nostr relay infrastructure without modifications.
//!
//! # Operation Mapping (section 10.5.2)
//!
//! | SCP operation | Nostr primitive | Details |
//! |---------------|-----------------|---------|
//! | `send` | Event publish | Custom kind 9078, `routing_id` in `r` tag |
//! | `subscribe` | `REQ` filter | Filter on kind + `r` tag, stream of `EVENT`s |
//! | `unsubscribe` | `CLOSE` | Close subscription by ID |
//! | `query` | `REQ` + `EOSE` | One-shot query with `since` filter |
//! | `delete` | NIP-09 deletion | Kind 5 event referencing blob event ID |
//!
//! # Wire Format
//!
//! Nostr events are JSON. SCP outer envelopes (`MessagePack`) are base64-encoded
//! in the event `.content` field, adding ~33% overhead. This is inherent to
//! Nostr's JSON-only event format.
//!
//! # Connection Model
//!
//! WebSocket to a Nostr relay. Existing Nostr infrastructure is reusable as-is
//! -- no code changes to Nostr relays are required.
//!
//! # Constraints
//!
//! - Max event size varies by relay (typically 64KB-1MB).
//! - No server-side TTL enforcement (relay purging is operator policy).
//! - Avoid parameterized-replaceable kinds (30000-39999) -- these store only
//!   the latest event per `d`-tag, silently discarding prior messages.
//!
//! See ADR-005 in `.docs/adrs/phase-1.md` for the transport abstraction design.

pub mod adapter;
pub mod protocol;

pub use adapter::NostrAdapter;
