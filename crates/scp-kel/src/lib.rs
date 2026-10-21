#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![doc = include_str!("../README.md")]

pub mod constants;
mod error;
mod event;
mod preimage;
mod routing;

pub use error::{
    DecodeError, DeriveIdentifierError, DidDiscriminatorField, EncodeError, KelDiscriminatorField,
    ListField, PreimageField,
};
pub use event::{
    CommitmentRolloverFields, Continuation, EventKind, EventPreimage, InceptionFields,
    InstalledRootSet, KeyStateFields, KeyStateSnapshot, RootRecoveryFields, SignatureForm,
    SignerGroup, SignerGroupRole, StandingRootDeclaration, StandingRootSigning, signer_group_roles,
};
pub use preimage::{
    EncodedPreimage, decode_preimage, derive_identifier, encode_preimage, key_event_seal,
    prerotation_commitment,
};
pub use routing::{RoutingKind, routing_id};
