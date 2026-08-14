# ADR-056 PR-A canonical-context-id = digest (#1924) — ea592648f — ZERO SECURITY FINDINGS / SOUND

Reviewed 2026-06-28 (worktree /tmp/scp-prA-review, base 598a56c37).

## What it does
`state::context_id_to_bytes(id)` = single chokepoint: if id is exactly 64 chars all-lowercase-hex → `hex::decode` to the [u8;32] digest; else → raw `SHA-256(id)` primitive (`scp_protocol::context::context_id_bytes`). Real `generate_context_id` ids (32 OS-CSPRNG bytes, lowercase 64-hex, scp-ffi/common/src/context_id.rs) DECODE to their digest; synthetic labels (`identity-private-state`, `standing-<hex>`, `ctx-…`) keep byte-identical SHA-256 behavior. Fixes the #1924 double-hash: state.context_id was SHA-256(hex(digest)), diverging from the §6.2.4 wire digest / MLS group / sender keys / event log all keyed by the raw digest.

## Security-critical fix CONFIRMED (key_destruction.rs:~91)
Pre-fix: destruction keyed under `context_id_bytes(id)` = SHA-256(id) while live keys under digest → Ephemeral close `destroy_mls_group`/`destroy_sender_key` silently no-op, reported KeysDestroyed while real group SURVIVES (confidentiality fail-OPEN). Fix routes through `context_id_to_bytes` → destruction now targets the live digest-keyed group. CLOSED.

## No sibling divergence
Audited ALL `scp_protocol::context::context_id_bytes` refs in scp-runtime. Production non-test calls = exactly 2, both correct:
- state.rs:2079 — the resolver's OWN fallback (by construction).
- supervisor.rs:3547 — synthetic `identity-private-state` PSK-rotation path (§9.12); never 64-hex, deliberately hashed, byte-identical, self-documented.
All real-context keying sites (builder creation, messaging send/recv/snapshot, lifecycle export/import/restore, governance event-log, ttl close/expire, MLS seal/open AAD guards) now route through `context_id_to_bytes`.

## §9.16.1 AAD preserved
MLS provider seal/open defense-in-depth guards switched from `context_id_bytes` to `context_id_to_bytes` for the digest-consistency check; the AAD itself still binds the RAW context_id STRING (the §9.16.1 contract from prior commit 598a56c37). The negative test for hex(ctx_id) now rejects one layer deeper (AEAD AAD mismatch) instead of the fast-path guard, because hex(digest) IS the canonical id — correct and documented.

## Model security-neutral (CONFIRMED)
Caller-influenced digest is moot: digest = OS-CSPRNG output, decoded not chosen. Import-alias with a chosen id grants nothing without MLS group keys (encryption-as-access-control). Registry first-writer-wins by STRING key (value-agnostic, needs no ADR-056 change).

## Gate check-context-id-keying.sh = SOUND
Closed positive allowlist (2 named production sites + anchor-substring pin). Test scope exempt (`*_tests.rs` or at/after first `#[cfg(test)]`). Bare-call detection gated on file importing the raw symbol; local `fn context_id_bytes` wrappers (builder/ttl) delegate to chokepoint and don't import raw → not flagged. Self-test alive (plants forbidden+allow+test, asserts verdicts), wired into ci.yml BEFORE real check. Ran both: PASS, exit 0. Not gameable in the common copy-the-primitive failure mode. Not a denylist-chasing-spellings antipattern.

## OBSERVATION (latent, non-blocking, NOT a security issue)
Test helpers messaging_helpers.rs:3784/4214, governance.rs (handlers) tests, class_s tests compute `ctx_bytes` from a real 64-hex `ctx_hex(byte)` id via the RAW primitive, then pass it into run_buffered_post_delivery. Harmless TODAY: that param only feeds the DORMANT `event_name=Some` append branch (all callers pass None); the consequence READ re-derives the key from the STRING via the resolver. If a future test exercises the Some-append branch with a 64-hex id, the append (SHA-256) and read (decoded digest) would target different keys. Pre-existing test-helper shape, production-safe, gate-exempt by design.
