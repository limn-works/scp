//! The key-event-log identity model (`03-identity.md` §3.10.10,
//! `09-security-model.md` §9.7.4.2).
//!
//! An identity's first key event is its inception, and its identifier is the
//! SHA-256 of the inception's signed preimage. This module replaces the
//! superseded `did:dht` model in [`crate::dht`], whose types stay until that
//! model leaves the tree.

pub mod error;

pub use error::IdentityError;
