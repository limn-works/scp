//! Two-layer envelope format with bucket padding. See ADR-002.
//!
//! The envelope has two layers:
//! - **Outer envelope** ([`OuterEnvelope`]): visible to relays and the network.
//!   Contains only routing information (`routing_id`, `recipient_hint`, `blob_ttl`)
//!   and an opaque encrypted blob.
//! - **Inner envelope** ([`InnerEnvelope`]): visible only to MLS group members
//!   after decryption. Contains sender identity, sequence metadata, payload,
//!   provenance, and an Ed25519 signature.
//!
//! Payloads are padded to fixed bucket sizes ([`padding::BUCKETS`]) before
//! encryption to prevent traffic analysis by ciphertext length.

pub mod inner;
pub mod outer;
pub mod padding;

pub use inner::{InnerEnvelope, Provenance};
pub use outer::{OuterEnvelope, create_outer_envelope};
pub use padding::{BUCKETS, EnvelopeError, MAX_PAYLOAD_SIZE, pad_to_bucket, strip_padding};
