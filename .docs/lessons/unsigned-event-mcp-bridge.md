# Unsigned Events in MCP Bridge (PR #192 Follow-up)

## Problem

`FfiBridgeProvider::invoke_tool` in `crates/scp-ffi/src/mcp.rs` emits `ToolInvokedEvent` entries per ADR-010 criterion 3. These events are appended to the Merkle event log via `append_unsigned_event` — a variant that skips Ed25519 signature verification — because the signing key material is not accessible in the sync execution context.

The root cause is a runtime constraint: `ContextProvider::invoke_tool` is called synchronously from within the tokio runtime. The `KeyCustody` signing trait is async. Calling `tokio::runtime::Runtime::block_on()` from inside a tokio worker thread panics with "Cannot block the current thread from within a runtime." There is no safe way to bridge from sync to async in this context without a dedicated signing thread or channel.

## What Still Works

Unsigned events still receive full chain validation:

- **Sequence ordering** — the event's `sequence` must match the expected next index.
- **Hash chain integrity** — `prev_hash` must match the last leaf hash (or genesis sentinel).
- **Merkle commitment** — the event is serialized and hashed with the RFC 6962 `0x00` leaf domain prefix, producing the same leaf hash as a signed event with identical content.

The event is durably committed to the append-only Merkle tree.

## Security Limitation

The `signature` field on these events is `Vec::new()` (empty). This means:

- A compromised in-process attacker with write access to the `EventLog` could inject fabricated events (e.g., fake `ToolInvokedEvent` entries) that pass sequence and hash-chain validation but carry no cryptographic proof of origin.
- External verifiers cannot distinguish between legitimate unsigned events and injected ones.
- The threat surface is limited to in-process attackers because the `EventLog` is not network-accessible.

## Current Mitigation

- Only trusted in-process callers use `append_unsigned_event` (the MCP bridge and test code).
- The call site in `mcp.rs` carries a `SECURITY: unsigned event` comment explaining the limitation.
- The function's doc comment in `tree.rs` documents the threat model and migration plan.

## Migration Plan (via SCP-214)

When async FFI signing lands:

1. Make `ContextProvider::invoke_tool` async, or introduce a signing channel/thread that can bridge sync-to-async without `block_on`.
2. Obtain the actor's `KeyCustody` handle in the FFI bridge context.
3. Sign the event via `KeyCustody::sign()` before appending.
4. Replace `append_unsigned_event` call sites with `append` (the signed variant).
5. Remove `append_unsigned_event` and its tests.

## Files

- `crates/scp-core/src/event_log/tree.rs` — `append_unsigned_event` function and doc comment
- `crates/scp-ffi/src/mcp.rs` — `FfiBridgeProvider::invoke_tool`, Phase 3 (call site)

## Lesson

When an async signing interface meets a sync FFI boundary inside a tokio runtime, you cannot use `block_on` to bridge the gap. The options are: (a) make the FFI entry point async, (b) use a dedicated signing thread with a channel, or (c) skip signing with documented security trade-offs. Option (c) is acceptable as a temporary measure only when the threat model is limited to in-process attackers, the limitation is prominently documented, and a concrete migration path exists.
