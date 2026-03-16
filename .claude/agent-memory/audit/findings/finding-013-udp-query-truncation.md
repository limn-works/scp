# Finding 013: UDP/DTLS adapter query() reads only one datagram, truncating multi-blob results

## Severity: moderate

## Summary

`UdpDtlsAdapter::query()` reads a single DTLS datagram response via a one-shot `send_request()` call. If the relay sends multiple BLOB results before `query_complete`, subsequent responses are silently dropped.

## Evidence

**File:** `crates/scp-transport/src/udp/adapter.rs`, lines 305-358

Other adapters (QUIC, Native WebSocket, CoAP) correctly loop until receiving a `query_complete` marker.

## Impact

Multi-blob query results (e.g., listing context messages) are truncated to the first response. Single-blob queries work correctly.

## Suggested Fix

Add a read loop in `UdpDtlsAdapter::query()` matching the pattern used by other adapters: loop until `query_complete` is received or a timeout expires.
