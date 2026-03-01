# Clock Error Message Sanitization

## Problem

Clock-related error types (e.g., `ClockError` in time validation, TTL enforcement, nonce freshness checks) may include raw system clock values, timestamps, or drift amounts in their error messages. If these messages propagate to external parties (error responses, logs visible to other participants, relay error codes), they leak information about the local system's clock state that could be used for timing attacks or fingerprinting.

## Why It Matters

- SCP's metadata privacy protections (spec section 9.10) aim to minimize information leakage to relays and other participants.
- A clock error message like "system clock is 47 seconds behind server" reveals the exact clock drift, enabling an observer to correlate the client across sessions or contexts.
- Nonce freshness errors that include "expected timestamp > 1709312400, got 1709312353" reveal the client's local time with second precision.
- Cover traffic timing (spec section 9.10.6) relies on the attacker not knowing the client's precise clock state.

## Correct Approach

Clock error types should use generic, non-informative error messages in their `Display` / `Error` implementations:

- Use: `"clock validation failed"`, `"timestamp out of acceptable range"`, `"nonce expired"`
- Avoid: `"clock drift: -47s"`, `"timestamp 1709312353 is before minimum 1709312400"`, `"system time unavailable: SystemTimeError(47.123s)"`

Detailed clock diagnostics (exact drift, raw timestamps, system error details) should be logged at `debug` or `trace` level only, never included in error types that cross trust boundaries. The `Debug` impl may include detailed information for local debugging, but `Display` (which feeds into error messages sent over the wire) must remain opaque.

## Rule

**All error types that include clock or timestamp information must sanitize their `Display` output.** Internal `Debug` output may include diagnostics. This applies to any error type in `scp-core` or `scp-platform` that references system time, clock drift, TTL expiry, or timestamp comparison.
