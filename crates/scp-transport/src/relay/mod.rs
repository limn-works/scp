//! Relay economic configuration, `.well-known/scp` parsing, STUN service,
//! bridge relay support, and connection URL validation.
//!
//! This module provides types and utilities for relay awareness in the
//! transport layer:
//!
//! - [`config`] -- relay economic config types and helpers for cost
//!   comparison and relay classification.
//! - [`connection`] -- relay URL validation with provenance-based
//!   transport security. Enforces `ws://` vs `wss://` rules per
//!   §10.12.6.
//! - [`wellknown`] -- `.well-known/scp` parsing with economic field
//!   support, bootstrap validation, and relay entry types.
//! - [`stun_service`] -- optional, stateless STUN server for NAT
//!   traversal (spec section 10.12.3). Any SCP relay MAY serve as
//!   a STUN endpoint.
//! - [`bridge`] -- BRIDGE relay operation for symmetric NAT fallback
//!   (spec section 10.12.4). Transparent proxy for self-hosted relays
//!   behind symmetric NAT.
//! - [`did_record_validation`] -- pure, cheapest-first validation of a
//!   `DidRecordV1` frame against its DID-domain `routing_id` (decode →
//!   `DID→routing_id` binding → BEP44 signature). The OPTIONAL validating
//!   SCP-native-relay path (§3.10.2). Stateful single-slot / slot-exclusivity
//!   bookkeeping lives in `native::did_slot`.
//! - [`push`] -- the relay push sender seam ([`push::PushSender`],
//!   [`push::PushSendOutcome`]) that sends the §10.7.1 step 5 wake signal,
//!   with the APNs sender in [`push_apns`] (PUSH-010) and the FCM HTTP v1
//!   sender in [`push_fcm`] (PUSH-011).
//! - `push_store` -- the relay's push registration store (spec section
//!   10.7.1 step 4), indexed by registration key, by routing ID and by
//!   token. Behind the `push-store` feature.
//! - [`push_dispatch`] -- the relay's push queue and drain task (spec
//!   section 10.7.1 step 5 and `PushDeregistration`, PUSH-008): one job per
//!   registered token after each stored blob, and removal after three
//!   consecutive invalid-token responses.
//! - [`push_gate`] -- the relay's interception of every PUBLISH to its
//!   reserved push routing ID (spec section 10.7.1, PUSH-007): the
//!   [`push_gate::PushRole`] selection and the verify-then-store gate.
//!
//! See spec section 19.8 (relay monetization), section 18.3.3 (relay
//! operator configuration), section 10.12.3 (STUN service on relays),
//! section 10.12.4 (bridge relay), section 10.12.6 (transport security),
//! and ADR-033 acceptance criteria 12, 14.

pub mod bridge;
pub mod config;
pub mod connection;
pub mod did_record_validation;
#[cfg(test)]
pub(crate) mod log_capture;
pub mod push;
pub mod push_apns;
pub mod push_dispatch;
pub mod push_fcm;
pub mod push_gate;
#[cfg(feature = "push-store")]
pub mod push_store;
#[cfg(test)]
pub(crate) mod push_test_server;
pub mod rate_limit;
pub mod stun_service;
pub mod subscription;
pub mod wellknown;
