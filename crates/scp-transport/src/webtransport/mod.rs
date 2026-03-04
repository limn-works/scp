//! WebTransport adapter module for SCP transport.
//!
//! Provides WebTransport-based transport for browser clients per spec section
//! 10.15 (HTTP/3 and WebTransport) and ADR-037 (Alternative Transport Bindings).
//!
//! # Architecture
//!
//! WebTransport is the browser-facing equivalent of the QUIC transport binding
//! (section 10.14). The WASM binding uses the browser's `WebTransport` API over
//! HTTP/3. Non-browser clients use QUIC directly.
//!
//! The module provides:
//!
//! - [`WebTransportAdapter`] -- client-side transport adapter for WASM targets.
//!   Implements [`TransportAdapter`] using the browser's `WebTransport` API with
//!   automatic fallback to WebSocket when WebTransport is unavailable.
//!
//! - [`FallbackState`] -- tracks the current transport state (WebTransport or
//!   WebSocket fallback) and handles transparent switching.
//!
//! # Fallback chain (section 10.15.3)
//!
//! Browser clients follow this transport selection order:
//!
//! 1. **WebTransport** -- attempt `new WebTransport(url)`. If the `WebTransport`
//!    API is unavailable (Safari, older browsers) or the connection fails (relay
//!    doesn't support HTTP/3), fall through.
//! 2. **WebSocket** -- fall back to `new WebSocket("wss://<host>/scp/v1")`. This
//!    is the mandatory baseline that all relays support.
//! 3. **Error** -- if WebSocket also fails, report connection failure.
//!
//! The fallback is transparent to `TransportAdapter` callers. The adapter wraps
//! both transports behind the same interface.
//!
//! # Conditional compilation
//!
//! The client-side adapter is only available on `wasm32` targets:
//!
//! ```rust,ignore
//! #[cfg(target_arch = "wasm32")]
//! pub use client::WebTransportAdapter;
//! ```
//!
//! The fallback types ([`FallbackState`], [`TransportKind`]) and URL conversion
//! utilities are available on all targets for testing and shared logic.
//!
//! Server-side WebTransport session handling (section 10.15.2) is in the
//! `session` submodule (SCP-259), not gated behind `wasm32`.
//!
//! [`TransportAdapter`]: crate::TransportAdapter

// Fallback types and URL utilities are platform-independent.
pub mod fallback;

// Server-side WebTransport session handling (section 10.15.2).
// Available on all targets (runs on the relay, not in browser).
pub mod session;

// Server-side WebTransport listener (section 10.15.2, SCP-259).
// Creates and manages sessions for incoming QUIC/HTTP/3 connections.
pub mod server;

// The client adapter requires browser APIs (web-sys, wasm-bindgen) and is
// only compiled for wasm32 targets.
#[cfg(target_arch = "wasm32")]
pub mod client;

#[cfg(target_arch = "wasm32")]
pub use client::WebTransportAdapter;

pub use fallback::{FallbackState, TransportKind};
