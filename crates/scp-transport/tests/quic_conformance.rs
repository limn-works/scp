//! QUIC transport adapter conformance.
//!
//! Runs the shared [`transport_conformance!`](scp_testing::transport_conformance)
//! suite (6 cases, spec §16.12.1 / ADR-005) against a real in-process `quinn`
//! QUIC listener + matching [`QuicAdapter`](scp_transport::quic::QuicAdapter)
//! client. This is the Tier-1 conformance gate for the QUIC adapter
//! (spec §10.5.1: "Must pass `transport_conformance!()`").
//!
//! The adapter factory is the synchronous
//! [`conformance_quic_adapter`](scp_transport::quic::test_support::conformance_quic_adapter)
//! helper: the macro evaluates its factory expression synchronously (once per
//! generated `#[tokio::test]`), but QUIC setup is inherently async, so the
//! helper drives listener+client bring-up on a dedicated background runtime and
//! hands back a connected adapter. See `test_support` for the full rationale.

#![cfg(feature = "quic")]

use scp_transport::quic::test_support::conformance_quic_adapter;

scp_testing::transport_conformance!(conformance_quic_adapter());
