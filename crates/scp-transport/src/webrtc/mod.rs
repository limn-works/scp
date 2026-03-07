//! WebRTC transport adapter for SCP (data channels).
//!
//! This module implements the WebRTC-based transport per spec section 10.5.2.
//! WebRTC data channels provide peer-to-peer transport with NAT traversal
//! via ICE (STUN/TURN), enabling direct communication between SCP participants.
//!
//! # Architecture
//!
//! The adapter uses an injected [`DataChannelProvider`] trait for the actual
//! data channel transport. Platform code implements the provider with the
//! platform-specific WebRTC stack:
//!
//! - **Native**: `webrtc-rs` crate wrapping `RTCDataChannel`
//! - **WASM**: `web_sys::RtcDataChannel`
//! - **Testing**: in-memory mock provider
//!
//! The adapter orchestrates SCP message framing (MessagePack serialization)
//! over whatever data channel implementation the provider gives.
//!
//! # Operation Mapping (section 10.5.2)
//!
//! | SCP operation | WebRTC primitive | Details |
//! |---------------|------------------|---------|
//! | `send` | `DataChannel` send | Binary message on channel labeled `hex(routing_id)` |
//! | `subscribe` | `DataChannel` open | Open/accept channel with label `hex(routing_id)` |
//! | `unsubscribe` | `DataChannel` close | Close the data channel |
//! | `query` | Request/response | Application-level over `DataChannel` |
//! | `delete` | Not applicable | P2P, no central store |
//!
//! # Connection Model
//!
//! Peer-to-peer via ICE (STUN/TURN). Signaling uses SCP relay (bootstrap:
//! exchange SDP offers via native relay). DTLS encryption for `DataChannels`
//! (DTLS over SCTP). One `PeerConnection` per peer, multiple `DataChannels`
//! per connection.
//!
//! # Constraints
//!
//! - Requires signaling channel (SCP relay or out-of-band)
//! - P2P only -- no durable storage, no backfill
//! - NAT traversal via ICE
//! - Battery-intensive on mobile (frequent STUN keepalives)
//! - Best for real-time P2P between online peers
//!
//! See ADR-005 in `.docs/adrs/phase-1.md` for the transport abstraction design.

pub mod adapter;
pub mod signaling;

pub use adapter::WebRtcAdapter;
pub use signaling::DataChannelProvider;
