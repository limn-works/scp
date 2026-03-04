//! HTTP/3 relay support for SCP transport layer.
//!
//! This module implements relay-side HTTP/3 support per spec section 10.15.1
//! and ADR-037. HTTP/3 serves as the relay's HTTP upgrade path for all HTTP
//! endpoints (`.well-known/scp`, dev API, broadcast projection) and as the
//! foundation for WebTransport (section 10.15.2).
//!
//! # Deployment model
//!
//! 1. The relay serves HTTP/1.1 + HTTP/2 on TCP:443 (via ALPN) and HTTP/3 on
//!    UDP:443 (via QUIC ALPN `h3`).
//! 2. HTTP/3 is advertised via `Alt-Svc` header on HTTP/1.1 and HTTP/2
//!    responses.
//! 3. Clients that support HTTP/3 upgrade transparently -- no application-level
//!    protocol change.
//!
//! # Feature flag
//!
//! This module is conditionally compiled behind the `http3` feature flag.
//! Enable it with `--features http3` in your cargo command.
//!
//! See ADR-037 in `.docs/adrs/phase-2.md` for the full design rationale.

pub mod adapter;
pub mod config;

pub use adapter::Http3Server;
pub use config::{AlpnProtocol, AltSvcHeader, Http3Config};
