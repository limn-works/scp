# Before persisting protocol state, read the spec's key schema — the record may already exist

## What happened

A branch made the FFI bridges' per-context UCAN revocation list and nonce
tracker durable, because a token revoked before a process restart validated
again after the restart. The branch invented two storage keys for that:
`context/{ctx}/ucan/revocation_list` held a serialized `RevocationList`, and
`context/{ctx}/ucan/nonce_tracker` held the tracker's whole entry set.

§17.3 of the persistence spec already defines both records, one entry per key:
`context/{ctx}/ucan_revocation/{token_id}` and
`context/{ctx}/nonce/{SHA256(nonce)}`. §17.4 already names the repository
methods that write them — `store_revocation`, `is_revoked`,
`check_and_record_nonce`, `prune_expired_nonces` — and
`crates/scp-runtime/src/store/ucan.rs` and `store/nonce.rs` already implement
all four, with tests. No production caller reached any of them.

## Two defects, not one

**The duplicate implementation.** Two key schemas for one protocol record put
the same state in two places, and only one of them is the one
`ProtocolRepository::delete_context` and the operator runbooks know about.

**The collection-per-key shape.** Serializing a whole collection under one key
forces every writer to read the collection, clone it, drop its lock, and write
it back. Two writers then race, and the write that lands second — carrying the
older snapshot — drops the other writer's entry. For a revocation list that
reinstates, as a race, the exact restart bypass the durable record existed to
close. The spec's one-key-per-entry shape has no read-modify-write to lose: two
revocations of two different tokens address two different keys.

The same shape also decides what an unauthenticated caller can cost the process.
The single-blob nonce record was re-encoded and re-written after every run of
the validation pipeline, including every rejected run, so a caller holding no
credential drove a full re-encode of a map capped at 100 000 entries. Writing
the one nonce the pipeline consumed, and writing nothing when it consumed none,
removes that.

## What to do

Before you add a storage key for protocol state, read §17.3 of
`.docs/specs/17-persistence-and-storage.md` — the key schema block lists every
key the protocol defines — and grep `crates/scp-runtime/src/store/` for a
repository method that already writes it. A specced record with no production
caller is an unwired capability to wire, not a gap to fill with a second record.

When you do define a new record, give each entry its own key. Reach for a
collection under one key only when the collection is written by exactly one
writer and read as a unit, and say in the doc comment which writer that is.
