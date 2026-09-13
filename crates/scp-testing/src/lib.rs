//! Testing crate for SCP (Shared Context Protocol).
//!
//! Provides simulation harness, conformance macros, assertion primitives, and
//! integration test suites for the full SCP protocol stack.
//!
//! # Simulation harness (spec section 16)
//!
//! - [`clock`] — `Clock` trait + [`SimulatedClock`](clock::SimulatedClock) for
//!   deterministic time control with timer callbacks.
//! - [`relay`] — [`InMemoryRelay`](relay::InMemoryRelay) with fault injection
//!   via [`BehaviorMode`](relay::BehaviorMode) (suppression, equivocation,
//!   replay, delay, deletion non-compliance).
//! - [`transport`] — [`InMemoryTransport`](transport::InMemoryTransport)
//!   implementing `TransportAdapter` backed by `InMemoryRelay`.
//! - [`simulator`] — [`NetworkSimulator`](simulator::NetworkSimulator) with
//!   configurable topology, multiple relays, and simulated identities.
//! - [`builder`] — Fluent [`ScenarioBuilder`](builder::ScenarioBuilder) for
//!   constructing test scenarios.
//! - [`assertions`] — Protocol-level assertion primitives (delivery, ordering,
//!   suppression detection, pseudonym unlinkability, blocking, epoch consistency).
//! - [`presets`] — 8 pre-configured scenarios for common test patterns.
//! - [`helpers`] — Test doubles for `ApplicationNode` (TLS providers, NAT
//!   strategies, DID methods).
//!
//! # Conformance macros
//!
//! - [`storage_conformance!`] — 13 tests for [`Storage`](scp_platform::Storage)
//!   (ADR-006, spec section 16.12.2).
//! - [`blob_store_conformance!`] — 11 tests for
//!   [`BlobStorage`](scp_transport::native::storage::BlobStorage)
//!   (spec sections 17.11, 17.13).
//! - [`payment_adapter_conformance!`] — 8 tests for `PaymentAdapter`
//!   (spec section 19.2.6).
//! - [`transport_conformance!`] — 6 tests for `TransportAdapter` (ADR-005).
//! - [`key_custody_conformance!`] — 4 tests for `KeyCustody` (ADR-006).
//! - [`attestation_conformance!`] — 2 tests for `DeviceAttestation` (ADR-006).
//! - [`push_conformance!`] — 2 tests for `Push` (ADR-006).
//!
//! # Integration tests
//!
//! Run via `cargo test -p scp-testing`. Suites cover identity, agent binding,
//! context lifecycle, broadcast, governance, capabilities, encryption,
//! transport, node, economics, trust, discovery, content access, compromise
//! recovery, bridge cooperative, and attack scenarios.
//!
//! # Running tests
//!
//! ```bash
//! # All scp-testing tests (lib + integration)
//! DYLD_LIBRARY_PATH=$(python3.12 -c "import sysconfig; print(sysconfig.get_config_var('LIBDIR'))") \
//!   cargo test -p scp-testing
//!
//! # A specific integration test suite
//! cargo test --test identity
//! cargo test --test governance
//! cargo test --test attacks
//! ```

#![forbid(unsafe_code)]

pub mod assertions;
mod blob_store_tests;
pub mod builder;
pub mod clock;
pub mod conformance;
pub mod fullstack;
pub mod helpers;
pub mod presets;
pub mod relay;
pub mod simulator;
pub mod test_adapter;
pub mod transport;

pub use test_adapter::TestAdapter;
