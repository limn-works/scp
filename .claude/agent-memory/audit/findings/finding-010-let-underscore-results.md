# Finding 010: Silent Result discarding in server/transport code

## Severity: minor

## Summary

Multiple `let _ = tx.send(...)` patterns in the transport server code silently discard send failures. While many are in fire-and-forget contexts (WebSocket forwarding, error responses), some could mask connection issues.

## Evidence

**File:** `crates/scp-transport/src/native/server.rs`
- Line 776: `let _ = tx.send(err_msg).await;`
- Line 809: `let _ = tx.send(err_msg).await;`
- Line 829: `let _ = forward_handle.await;`
- Line 977: `let _ = tx.send(pong).await;`
- Line 1046: `let _ = tx.send(err).await;`
- Line 1061: `let _ = tx.send(err).await;`
- Line 1075: `let _ = tx.send(err).await;`
- Line 1094: `let _ = tx.send(err).await;`
- Line 1111: `let _ = tx.send(ok).await;`
- Line 1144: `let _ = tx.send(err).await;`

**File:** `crates/scp-transport/src/quic/adapter.rs`
- Line 381: `let _ = send.finish();`
- Line 416: `let _ = tx.send(...).await;`

**File:** `crates/scp-mcp/src/sse.rs`
- Line 234: `let _ = self.tx.send((id, data));`

## Assessment

Most of these are in server-side message dispatch paths where the receiver has disconnected and there's nothing meaningful to do. The `let _ = forward_handle.await` (line 829) discards a JoinHandle error which could mask panics.

## Suggested Fix

Low priority. Consider:
1. Adding `tracing::debug!` for discarded send results in development builds
2. Handling the `forward_handle` result to detect panics in the forwarding task
