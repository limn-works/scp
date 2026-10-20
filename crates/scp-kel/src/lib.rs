#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![doc = include_str!("../README.md")]

pub mod constants;
mod error;
mod event;
mod preimage;
mod routing;

pub use error::{
    DecodeError, DeriveIdentifierError, DiscriminatorField, EncodeError, EventDiscriminatorField,
    ListField, PreimageField,
};
pub use event::{
    CommitmentRolloverFields, Continuation, EventKind, EventPreimage, InceptionFields,
    InstalledRootSet, KeyStateFields, KeyStateSnapshot, RootRecoveryFields, RootRecoveryStanding,
    SignatureForm, SignerGroup, StandingRootDeclaration,
};
pub use preimage::{
    decode_preimage, derive_identifier, encode_preimage, event_digest, key_event_seal,
    prerotation_commitment, signed_preimage,
};
pub use routing::{RoutingKind, routing_id};
