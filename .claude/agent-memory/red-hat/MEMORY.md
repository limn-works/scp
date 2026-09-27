# Red Hat Agent Memory

Attack shapes that produced real findings in this codebase. Check each against a new change.

## Trust boundaries
- Network-facing: `ClientMessage`, `RelayMessage`, `OuterEnvelope`, STUN, `.well-known/scp`, BEP44 records.
- Post-MLS (the most dangerous, because the sender is an authenticated but possibly hostile member): `InnerEnvelope`, `SenderKeyDistributionMessage`, `ChunkEnvelope`, `BroadcastEnvelope`, governance proposals, UCAN tokens. Check for a size bound before deserialization and for an allocation sized by an untrusted count (`ChunkEnvelope` reassembly sized a vector from a `u32` `total_chunks`).
- FFI: every `validate_*` function, UCAN and `CapabilityUri` parsing, DID parsing.

## Recurring exploitable shapes
- **Prefix match without a delimiter.** `starts_with("scp:ctx:a")` also matches `scp:ctx:abc`, which grants cross-context access. Require the trailing `/`.
- **Timestamp-only replay protection.** A signed frame accepted inside a freshness window with no nonce and no connection binding can be replayed within that window.
- **Unbounded event-driven loops.** A loop that any channel sender can trigger, with no debounce (a network-change detector driving STUN probes and DID publishes), is an amplification primitive.
- **Catch-all output arms.** When each bridge formats events and escapes output in a catch-all match arm, a new event variant falls through whichever bridge's arm does not escape.
- **Input validation removed "because output is escaped."** The removal is a regression; test both sides.
- **Post-shutdown zombie state.** An accessor that recreates an entry with `entry().or_default()` after shutdown, or a registration path with no `is_shutdown()` check, revives state that shutdown was meant to clear.
- **A coverage gate proves a symbol exists, not that it is reachable.** An alias entry pointing a matrix cell at a dead stub passed `scripts/check-sdk-coverage.py` with zero errors; reachability needs a `pipeline_wiring.rs` assertion or a per-operation test.
- **Error-code fingerprinting.** A bridge-unique error code tells the caller which SDK family it is talking to, and distinct errors for "wrong passphrase" versus "file missing" form an oracle for identity-file state.
