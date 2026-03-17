# Finding 019: TransportType enum missing Nostr and WebRtc variants

## Severity: minor

## Summary

The `TransportType` enum in `crates/scp-transport/src/pool.rs` has 5 variants (NativeWebSocket, Quic, WebTransport, UdpDtls, CoAP) but the crate ships 7 fully implemented `TransportAdapter` implementations. `NostrAdapter` and `WebRtcAdapter` have no corresponding `TransportType` variant.

## Evidence

**File:** `crates/scp-transport/src/pool.rs:58-69`

```rust
pub enum TransportType {
    NativeWebSocket,
    Quic,
    WebTransport,
    UdpDtls,
    CoAP,
    // Missing: Nostr, WebRtc
}
```

Both adapters are fully implemented:
- `NostrAdapter` in `crates/scp-transport/src/nostr/adapter.rs` (feature `nostr`)
- `WebRtcAdapter` in `crates/scp-transport/src/webrtc/adapter.rs` (feature `webrtc`)

## Impact

- Neither adapter can be stored in or retrieved from the `ConnectionPool`
- `TransportManager` cannot track or deduplicate connections for these adapters
- The pool's per-relay deduplication guarantee (spec §10.13.2 item 1) does not apply to Nostr or WebRTC connections

## Suggested Fix

Add `Nostr` and `WebRtc` variants to the `TransportType` enum.
