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
mod creation_record;
mod device_record;
pub mod error;
mod handle;
pub mod slot;
mod unfinished;
mod verify;
mod witness;

pub use config::{IdentityConfig, RecordLock};
pub use create::{Created, EventOutcome, GroupSigners, PendingEvent, SignerPlan};
pub use creation_record::CreationId;
pub use error::{CleanupFailure, CreateError, IdentityError, UndestroyedKey};
pub use handle::{Identity, ScpIdentity};
pub use slot::{ErasedKeyCustody, ErasedNextSetCustody, KeyCustodySlot, NextSetCustodySlot};
pub use unfinished::{KeptComposition, Unfinished};
pub use verify::{parse_identifier, verify_did};
pub use witness::{
    ListedOperator, WitnessChoice, WitnessDesignation, WitnessWarning, default_witness_set,
};
