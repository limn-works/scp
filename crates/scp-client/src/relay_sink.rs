//! The injected **outbound** relay port for the participant driver (ADR-057
//! transport slice).
//!
//! [`RelaySink`] is the driver's ONLY outbound seam to the network: a
//! **write-only** sink the driver hands fully-serialized relay
//! [`ClientMessage`](scp_relay_client::ClientMessage) frames to (a `SUBSCRIBE`, a
//! `PUBLISH`). The driver never reads from it — inbound frames arrive by the
//! embedder *pushing* them into
//! [`ScpClient::handle_relay_frame`](crate::ScpClient::handle_relay_frame), the
//! sync inbound pump. This directional split keeps the driver single-threaded and
//! free of any async transport: a browser owns the WebSocket, forwards outbound
//! frames from `send`, and pumps inbound frames into the driver on the same task.
//!
//! # Why a directional name (not `Socket`)
//!
//! The port exposes ONLY `send`; there is no `recv`, and inbound delivery is a
//! method on a *different* object (`ScpClient::handle_relay_frame`). Naming it
//! `Socket` misleads an implementor into wiring their WebSocket `onmessage` back
//! into it and expecting bidirectionality. `RelaySink` names exactly what it is —
//! the outbound half — so the two directions are not confused (the JS object it
//! wraps IS a real socket, hence `JsSocket` on the wasm side; the Rust *port* it
//! is adapted to is a sink).
//!
//! # Why write-only
//!
//! Making the port write-only (rather than a full request/response transport) is
//! what lets the driver stay a synchronous `&mut self` state machine with no
//! internal concurrency, no polling, and no runtime — exactly the ADR-057 wasm
//! fence. The relay is a dumb store-and-forward pipe (SCP protocol tenet: "relays
//! are untrusted dumb pipes"); the driver decides *what* to publish and *where to
//! subscribe*, and the embedder decides *when* to deliver what arrives.
//!
//! The trait is deliberately tiny — one method taking an owned `Vec<u8>` frame —
//! so a `wasm-bindgen` `JsSocket` extern maps onto it directly (bytes cross the
//! boundary by value), with no lifetime or borrowing to project across FFI.

/// The injected **outbound** relay port (write-only).
///
/// `send` takes a fully-serialized relay `ClientMessage` frame (produced by the
/// driver via [`ClientMessage::to_bytes`](scp_relay_client::ClientMessage::to_bytes))
/// and hands it to the network. The driver never reads a response through this
/// trait; inbound relay frames are delivered by the embedder calling
/// [`ScpClient::handle_relay_frame`](crate::ScpClient::handle_relay_frame).
///
/// # Errors
///
/// `send` returns `Err(String)` if the embedder could not enqueue the frame (the
/// WebSocket is closed, a JS exception was thrown, etc.). The message is a
/// human-readable diagnostic; the driver surfaces it as
/// [`ClientError::Transport`](crate::ClientError::Transport). A send failure is
/// **best-effort transport loss**, NOT a state-corrupting error: by the time a
/// frame is published the driver's crypto/log state has already advanced and been
/// persisted, and entry-time (`SUBSCRIBE`/announce) sends are re-driven on the
/// embedder's reconnect via
/// [`ScpClient::resubscribe_all`](crate::ScpClient::resubscribe_all). An
/// implementation MAY buffer sends issued before the underlying socket is open.
pub trait RelaySink: Send + Sync {
    /// Hands one serialized relay frame to the network.
    ///
    /// # Errors
    ///
    /// Returns a human-readable diagnostic string if the frame could not be
    /// enqueued for transmission.
    fn send(&self, frame: Vec<u8>) -> Result<(), String>;
}
