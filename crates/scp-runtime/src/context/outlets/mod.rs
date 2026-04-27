//! Outlet registration, invocation, and session management — async runtime.
//!
//! Pure types are in `scp-protocol::context::outlets`. This module retains
//! the async modules: invoke, session, plus the §5.4.4 round-5 per-outlet
//! HMAC key derivation (`message_key`) and acceptance pin helper
//! (`registration`), and the §5.4.4 round-6 receiver-side `OutletError`
//! verification path (`errors`).
//!
//! # Streaming entry point (SCP-OUT-033)
//!
//! The §5.4.5 streaming entry point is
//! [`invoke::invoke_outlet`], which returns
//! `Result<tokio::sync::mpsc::Receiver<OutletStreamChunk>, InvocationError>`.
//! Legacy callers that prefer the value-and-event tuple use
//! [`invoke::invoke_outlet_aggregating`] instead.
//! [`invoke::one_shot_to_stream`] is the adapter that turns a
//! single executor-returned `Value` into the §5.4.5 two-chunk
//! `Data + End` degenerate stream.

pub mod errors;
pub mod invoke;
pub mod message_key;
pub mod registration;
pub mod session;
pub mod stream;

// SCP-OUT-033 — re-export the streaming entry points so consumers can
// `use scp_runtime::context::outlets::{invoke_outlet, OutletStreamChunk}`.
pub use invoke::{
    invoke_outlet, invoke_outlet_aggregating, invoke_outlet_with_cancellation_aggregating,
    one_shot_to_stream,
};
