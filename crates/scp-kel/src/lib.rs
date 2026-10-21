#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![doc = include_str!("../README.md")]

mod client_data;
pub mod constants;
mod error;
mod event;
mod event_codec;
mod preimage;
mod routing;
mod signature;

pub use client_data::ClientDataError;
#[doc(hidden)]
pub use client_data::{ClientDataMembers, parse_client_data_json};
pub use error::{
    DecodeError, DeriveIdentifierError, DidDiscriminatorField, EncodeError, HeaderError,
    InceptionHeaderDefect, KelDiscriminatorField, ListField, PreimageField, SignatureFieldError,
};
pub use event::{
    CommitmentRolloverFields, Continuation, EventKind, EventPreimage, InceptionFields,
    InstalledRootSet, KeyStateFields, KeyStateSnapshot, RootRecoveryFields, SignatureForm,
    SignerGroup, SignerGroupRole, StandingRootDeclaration, StandingRootSigning, signer_group_roles,
};
pub use event_codec::{
    EventHeader, EventUnit, SignerGroupSignatures, decode_event, inception_header_zero_checks,
    raw_identifier,
};
pub use preimage::{
    EncodedPreimage, decode_preimage, derive_identifier, encode_preimage, key_event_seal,
    prerotation_commitment,
};
pub use routing::{RoutingKind, routing_id};
pub use signature::{
    AssertionSignature, IndexedSignature, IndexedSignatureError, IndexedSignaturePart,
    IndexedSignatureReadError, key_event_challenge, verify_indexed,
};
