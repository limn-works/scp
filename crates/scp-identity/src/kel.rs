//! The key-event-log identity model (`03-identity.md` §3.10.10,
//! `09-security-model.md` §9.7.4.2).
//!
//! An identity's first key event is its inception, and its identifier is the
//! SHA-256 of the inception's signed preimage. This module replaces the
//! superseded `did:dht` model in [`crate::dht`], whose types stay until that
//! model leaves the tree.

mod abandon;
pub mod config;
mod create;
mod device_record;
pub mod error;
mod handle;
pub mod slot;
mod verify;

pub use config::IdentityConfig;
pub use create::{EventOutcome, GroupSigners, PendingEvent, SignerPlan};
pub use error::IdentityError;
pub use handle::{Identity, ScpIdentity};
pub use slot::{ErasedKeyCustody, ErasedNextSetCustody, KeyCustodySlot, NextSetCustodySlot};
pub use verify::{parse_identifier, verify_did};
