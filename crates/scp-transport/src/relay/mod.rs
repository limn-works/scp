//! Relay economic configuration and `.well-known/scp` parsing.
//!
//! This module provides types and utilities for relay economic awareness
//! in the transport layer:
//!
//! - [`config`] -- relay economic config types and helpers for cost
//!   comparison and relay classification.
//! - [`wellknown`] -- `.well-known/scp` parsing with economic field
//!   support, bootstrap validation, and relay entry types.
//!
//! See spec section 19.8 (relay monetization), section 18.3.3 (relay
//! operator configuration), and ADR-033 acceptance criteria 12, 14.

pub mod config;
pub mod wellknown;
