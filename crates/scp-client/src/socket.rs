//! The injected outbound relay port for the participant driver (ADR-057
//! transport slice).
//!
//! [`Socket`] is the driver's ONLY outbound seam to the network: an
//! **outbound-only** sink the driver hands fully-serialized relay
//! [`ClientMessage`](scp_relay_client::ClientMessage) frames to (a `SUBSCRIBE`,
//! a `PUBLISH`). The driver never reads from it — inbound frames arrive by the
//! embedder *pushing* them into
//! [`ScpClient::handle_relay_frame`](crate::ScpClient::handle_relay_frame), the
//! sync inbound pump. This split keeps the driver single-threaded and free of any
//! async transport: a browser owns the WebSocket, forwards outbound frames from
//! `send`, and pumps inbound frames into the driver on the same task.
//!
//! # Why outbound-only
//!
//! Making the port outbound-only (rather than a full request/response transport)
//! is what lets the driver stay a synchronous `&mut self` state machine with no
//! internal concurrency, no polling, and no runtime — exactly the ADR-057 wasm
//! fence. The relay is a dumb store-and-forward pipe (SCP protocol tenet:
//! "relays are untrusted dumb pipes"); the driver decides *what* to publish and
//! *where to subscribe*, and the embedder decides *when* to deliver what arrives.
//!
//! The trait is deliberately tiny — one method taking an owned `Vec<u8>` frame —
//! so a `wasm-bindgen` `JsSocket` extern maps onto it directly (bytes cross the
//! boundary by value), with no lifetime or borrowing to project across FFI.

/// The injected outbound relay port.
///
/// `send` takes a fully-serialized relay `ClientMessage` frame (produced by the
/// driver via [`ClientMessage::to_bytes`](scp_relay_client::ClientMessage::to_bytes))
/// and hands it to the network. It is **outbound-only**: the driver never reads a
/// response through this trait; inbound relay frames are delivered by the
/// embedder calling [`ScpClient::handle_relay_frame`](crate::ScpClient::handle_relay_frame).
///
/// # Errors
///
/// `send` returns `Err(String)` if the embedder could not enqueue the frame (the
/// WebSocket is closed, a JS exception was thrown, etc.). The message is a
/// human-readable diagnostic; the driver surfaces it as
/// [`ClientError::Transport`](crate::ClientError::Transport). Callers treat a
/// send failure as best-effort transport loss (the relay is untrusted and a
/// message may be re-driven), NOT as a state-corrupting error — the driver's
/// crypto/log state has already advanced and been persisted by the time `send`
/// is called.
pub trait Socket: Send + Sync {
    /// Hands one serialized relay frame to the network.
    ///
    /// # Errors
    ///
    /// Returns a human-readable diagnostic string if the frame could not be
    /// enqueued for transmission.
    fn send(&self, frame: Vec<u8>) -> Result<(), String>;
}

#[cfg(test)]
pub mod loopback {
    //! An in-memory loopback [`Socket`] for the crate's own unit tests.
    //!
    //! `#[cfg(test)]` — NEVER exported and never reachable in a shipped build. It
    //! captures every frame the driver publishes so a unit test can assert on the
    //! exact relay `ClientMessage`s the fan-out produced (routing IDs, `blob_ttl`,
    //! the decoded `OuterEnvelope`), and can route captured frames back into a
    //! peer's [`ScpClient::handle_relay_frame`](crate::ScpClient::handle_relay_frame)
    //! to drive an in-process two-party exchange with no real relay.
    //!
    //! Integration tests (`tests/`) and the `scp-client-wasm` host round-trip test
    //! define their OWN loopback over the public [`Socket`] trait — this one is
    //! for `src/` unit tests, which also need to reach driver internals.

    use std::sync::{Arc, Mutex};

    use super::Socket;

    /// A loopback socket that records every published frame in insertion order.
    ///
    /// Cheap to clone (an `Arc` handle over the shared buffer), so a test can hold
    /// one handle to inspect/drain frames while the driver holds another as its
    /// injected `Arc<dyn Socket>`.
    #[derive(Clone, Default)]
    pub struct LoopbackSocket {
        frames: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl LoopbackSocket {
        /// A fresh loopback with an empty frame buffer.
        pub fn new() -> Self {
            Self::default()
        }

        /// Drains and returns every captured frame in insertion order, leaving the
        /// buffer empty.
        #[allow(clippy::expect_used)]
        pub fn take_frames(&self) -> Vec<Vec<u8>> {
            std::mem::take(&mut *self.frames.lock().expect("loopback frame lock"))
        }
    }

    impl Socket for LoopbackSocket {
        fn send(&self, frame: Vec<u8>) -> Result<(), String> {
            #[allow(clippy::expect_used)]
            self.frames.lock().expect("loopback frame lock").push(frame);
            Ok(())
        }
    }
}
