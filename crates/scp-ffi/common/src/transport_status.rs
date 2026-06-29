//! Canonical handleless transport-status triple shared across all FFI bridges.
//!
//! Every FFI bridge (`PyO3`, napi-rs, `UniFFI`) exposes a
//! no-handle-supplied `transport_status()` probe whose contract, per
//! ADR-048 §7a, is `(has_transport(), None, None)`. The `relay_url` and
//! `latency_ms` fields live on the `TransportManager` handle, not on the
//! bridge instance — they are only observable when a handle is passed to
//! the *per-handle* variant of the call.
//!
//! The triple was previously constructed inline in each bridge. A
//! hand-rolled `(connected, None, None)` on one bridge and
//! `(connected, relay_url_hint, None)` on another would diverge silently;
//! the cross-bridge parity harness (ADR-046) catches the drift, but only
//! after both bridges ship. Centralising the shape here turns the
//! regression into a compile-level invariant: every bridge calls the
//! same helper, so the disconnected triple stays byte-identical across
//! `PyO3`, napi-rs, and `UniFFI` without further
//! enforcement.
//!
//! # Why `Option<f64>` for `latency_ms`
//!
//! All per-bridge `TransportStatus`-equivalent structs store
//! `latency_ms` as `Option<f64>` so the language SDKs expose a nullable
//! floating-point millisecond value (Swift `Double?`, Kotlin `Double?`,
//! Python `float | None`, TypeScript `number | null`). The shared helper
//! matches that type so callers do not need a cast at the call site.

/// Returns the canonical handleless transport-status triple.
///
/// Every bridge's handleless `transport_status()` probe lowers to this
/// helper so the disconnected shape remains byte-identical across
/// `PyO3`, napi-rs, and `UniFFI`:
///
/// - `connected = has_transport` (the only bit of state the bridge has
///   when no handle is supplied)
/// - `relay_url = None` (lives on the `TransportManager` handle)
/// - `latency_ms = None` (lives on the `TransportManager` handle)
///
/// # Arguments
///
/// * `has_transport` — whether a `TransportManager` is currently
///   installed on the bridge instance.
#[inline]
#[must_use]
pub const fn handleless_transport_status(
    has_transport: bool,
) -> (bool, Option<String>, Option<f64>) {
    (has_transport, None, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disconnected_shape_is_false_none_none() {
        let (connected, relay_url, latency_ms) = handleless_transport_status(false);
        assert!(!connected);
        assert!(relay_url.is_none());
        assert!(latency_ms.is_none());
    }

    #[test]
    fn connected_bit_is_propagated_but_fields_stay_none() {
        // The per-handle variant of each bridge's `transport_status` is
        // the only path that can populate `relay_url`/`latency_ms`. The
        // handleless probe propagates ONLY `has_transport` — the other
        // fields stay `None` even when a transport is installed, because
        // the handleless caller has no `TransportManager` to read them
        // from.
        let (connected, relay_url, latency_ms) = handleless_transport_status(true);
        assert!(connected);
        assert!(relay_url.is_none());
        assert!(latency_ms.is_none());
    }
}
