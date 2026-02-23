# Transport Resilience via Decorator Pattern

Network resilience (retry logic, exponential backoff) should be implemented as a transport wrapper using the decorator pattern, rather than modifying existing transport implementations or adding retry logic to individual callers.

## The Pattern

```
Caller (Service)              — doesn't know about retries
    ↓
ResilientTransport            — wraps any transport, adds retry + backoff
    ↓
URLSessionTransport           — actual HTTP execution, single responsibility
```

## Why Decorator

| Alternative | Rejection reason |
|---|---|
| Modify transport directly | Couples retry to specific transport; mocks/test doubles need separate retry |
| Retry at caller site | Cross-cutting concern; duplicated in every caller |
| Retry in protocol extension | Can't add stored properties for retry state |

## Key Design Points

**Retry policies as presets**:
- `default` — 3 attempts, 500ms initial delay, retries on timeout/connection lost/503
- `none` — pass-through, no retries
- `aggressive` — 5 attempts, 250ms initial delay, adds 429 rate limiting

**Streaming behavior**: Retry only applies to **initial connection failure**. Once data starts flowing, failures propagate immediately. This prevents duplicate data, unbounded retries on flaky connections, and user confusion.

```swift
for try await data in stream {
    hasReceivedData = true  // After first chunk, no more retries
    continuation.yield(data)
}
```

**Error classification**: Only specific transient errors trigger retries (timeout, connection lost, 503). Client errors (4xx) and non-network errors are never retried.
