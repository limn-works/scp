# ADR-056 Canonical Context Identity (PR-A rev7, HEAD 7ce298ab2) -- 2026-06-29 -- ZERO FINDINGS

Security tag. Branch chore/...prA-rev7. Diff origin/main...HEAD = 21 files.

## What it does
ADR-056: a context's canonical identity IS its 32-byte digest; id STRING = hex(digest).
Bug #1924: runtime resolved id->keying-bytes by HASHING (SHA-256(hex(digest)) = DOUBLE HASH).
Crypto layer (MLS group / sender keys / event log) keys off the digest; §6.2.4 saga puts the raw
digest on the wire as target_context_id -> never matched state.context_id (the double-hash). Coincided
only in non-hex test fixtures; §6.2.4 saga UNCOMMITTABLE in production with real generate_context_id ids.

## The chokepoint (state.rs:2052, now `pub` not pub(crate))
`context_id_to_bytes(&str)->[u8;32]`: if len==64 && all lowercase-hex -> hex::decode to digest;
else fall through to raw `scp_protocol::context::context_id_bytes` (SHA-256). Total (no panic/unwrap,
clippy-denied). Strict lowercase guard keeps uppercase 64-char test labels on the hash fallback.
The ONLY production raw-primitive site post-change = this resolver's own fallback (state.rs:2088).
Routing (`context_routing_id`) stays on its own domain-separated derivation (NOT keying).

## Recovery fail-open (the rev7 fix, supervisor.rs)
recovery_send_notification_direct is reached for ANY unregistered context (ADR-049 lazy-spawn), NOT
just synthetic identity-private-state: revoke_ucans (seq1) + rotate_key_packages (seq2) dispatch REAL
64-hex member ids with no registration gate. An earlier PR-A commit had flipped this site to the raw
primitive -> double-hashed real ids -> compromise-recovery revocation/rotation notifications sealed to
a slot no member listens on -> SILENTLY UNDELIVERED. rev7 reroutes through context_id_to_bytes; matches
registered-actor handler recovery_send_notification (trust_recovery_helpers.rs:322). seal() keys ONLY
off resolved digest + routing_id; epoch=0 lives in signed plaintext `inner`, NOT a separate AAD arg, so
epoch 0 doesn't affect openability -- symmetric with registered handler default. RecoveryAdvanceEpoch
on unregistered ctx returns ContextNotRegistered (fails clean, no wrong-slot keying).

## All keying sites rerouted to context_id_to_bytes (verified by tree-wide grep)
runtime: builder.rs:766 (local shadow delegates), messaging_helpers, lifecycle_helpers,
governance_logic, key_destruction, ttl, class_s, handlers/governance, mls/provider open-guards,
supervisor reconnect-publish (9078). FFI: 4 event-log + 6 test-harness sites (scp-ffi/src, napi, uniffi)
now scp_core::context::state::context_id_to_bytes. scp-core re-exports state at lib.rs:91 (pre-existing).

## Gate removal posture = ACCEPTABLE
The removed grep keying-gate was NET-NEW WITHIN PR-A (added 5d07963e9, removed da017d9f0) -> no
enforcement regression vs origin/main merge base. Regex pseudo-lexer can't soundly scope #[cfg(test)]
(lifetimes vs char-literals, block comments, multi-line strings) -> perpetual fail-open class. Replaced
by chokepoint + mutation-resistant tests + forthcoming ContextDigest newtype #1931 (compile-error on
raw-primitive keying). Consistent w/ OwnedIdentityDid/ADR-2E precedent (#1826). #1933 verify-sync gap
out of scope, not worsened.

## Tests are genuinely mutation-resistant (not string-search theater)
recovery_direct_keys_real_context_via_chokepoint_not_raw_primitive (supervisor) +
create_context_keys_crypto_under_decoded_digest_not_sha256 (builder): seed crypto under digest, assert
op FINDS it (TransportFailed / non-empty export) while raw-primitive path would MISS (CryptoFailed /
empty export). canonical_context_id_tests (state.rs) pin decode/hash branching.

## LESSON: double-hash trap class
Whenever an id STRING is already hex(digest), re-hashing it to derive keying bytes silently diverges
from every component that addresses the group by the raw digest (MLS/sender-keys/event-log/wire saga).
Recovery/lazy-spawn "direct" paths that bypass the per-context actor are the high-risk sites -- they
re-derive keying bytes locally and a "only the synthetic pseudo-context reaches here" comment was the
false premise that masked the real-context fail-open.
