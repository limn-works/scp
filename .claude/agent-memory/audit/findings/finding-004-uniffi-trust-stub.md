# Finding 004: UniFFI bridge trust event counts return hardcoded (0, 0)

## Severity: moderate

## Summary

The UniFFI bridge's `query_trust_event_counts` function returns `(0, 0)` for all inputs. Trust scoring on mobile platforms (Swift/Kotlin) will always compute with zero participation data, producing inaccurate trust evaluations.

## Evidence

**File:** `crates/scp-ffi/uniffi/src/runtime.rs`, lines 596-601

```rust
pub const fn query_trust_event_counts(_context_id: &str, _did: &str) -> (u64, u64) {
    // UniFFI bridge: ContextManager owns context state but does not expose
    // per-context event log leaf counts directly. Return (0, 0) as a stub.
    // Full trust scoring requires ContextManager event log integration.
    (0, 0)
}
```

Parameters are prefixed with `_` (unused). The function is `const fn` — it cannot access any runtime state.

## Expected Behavior

Should query the ContextManager's event log for the given context and DID, returning actual message and governance event counts. The PyO3 bridge's equivalent reads from `FfiBridgeState.event_log` via `runtime::with_context()`.

## Root Cause

The UniFFI ContextManager does not expose per-context event log leaf counts. The bridge lacks the query path from event log to trust aggregation.

## Suggested Fix

1. Add `event_log_counts(context_id, did)` method to ContextManager or expose the event log per context
2. Wire `query_trust_event_counts` to read from the ContextManager's event log provider
3. Remove `const fn` annotation so the function can access runtime state
