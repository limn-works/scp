#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
//! Real-time media transport types for SCP (Shared Context Protocol).
//!
//! `scp-media` implements the delegated media model defined in ADR-024.
//! SCP governs identity, trust, governance, and MLS-derived key material.
//! Actual media flows over WebRTC/DTLS-SRTP. Signaling (SDP offers/answers,
//! ICE candidates) goes through SCP as standard encrypted governed messages.
//! No media data touches SCP relays.
//!
//! # Modules
//!
//! - [`keys`] -- DTLS-SRTP key material derived from MLS group state.
//! - [`session`] -- Media session lifecycle types and capability mapping.
//! - [`signaling`] -- WebRTC signaling messages transported over SCP.
//!
//! # Architecture
//!
//! ```text
//! SCP Context (identity + trust + governance + MLS keys)
//!        |
//!        +-- signaling messages (SDP, ICE) --> encrypted SCP messages
//!        |
//!        +-- MLS key export --> DTLS-SRTP key material
//!        |
//!        +-- media frames --> WebRTC peer-to-peer (never through relays)
//! ```
//!
//! See ADR-024 in `.docs/adrs/phase-5.md`.

#![forbid(unsafe_code)]

pub mod keys;
pub mod session;
pub mod signaling;
