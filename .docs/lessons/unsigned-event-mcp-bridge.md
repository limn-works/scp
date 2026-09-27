# Event-Log Entries Appended Without a Signature

`append_unsigned_event` (`crates/scp-event-log/src/tree.rs`) appends an event with an empty
`signature`. Two production paths use it: `FfiBridgeProvider` in `crates/scp-ffi/src/mcp.rs`
records `OutletInvokedEvent` entries (ADR-010 criterion 3) that way, and the runtime event-log
provider (`crates/scp-runtime/src/context/providers/event_log.rs`) appends every event that
way because it holds no per-event signing key.

**Why the MCP path is unsigned**: `KeyCustody::sign` is async, the call site is synchronous
code already running on the tokio runtime, and `block_on` there panics (see
`.docs/lessons/tokio-mutex-blocking-lock-in-runtime.md`). The ways out are an async entry
point, a dedicated signing thread reached through a channel, or skipping the signature.

**What still holds**: each unsigned event is chain-validated (its `sequence` must be the next
index and its `prev_hash` must match the previous leaf) and Merkle-committed with the RFC 6962
`0x00` leaf prefix, so the log remains tamper-evident after the append.

**What does not**: nothing proves who produced the event. An attacker with in-process write
access to the `EventLog` can append fabricated events that pass sequence and hash-chain
validation, and an external verifier cannot tell them from legitimate ones. The exposure is
limited to in-process attackers because the `EventLog` is not network-reachable.

Replacing these call sites with the signed `append` requires the actor's `KeyCustody` at the
append site and an async path to call it; the doc comment on `append_unsigned_event` lists
the steps.
