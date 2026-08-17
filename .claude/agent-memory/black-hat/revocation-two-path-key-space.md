---
name: revocation-two-path-key-space
description: Attack surfaces in the issuer-scoped attestation revocation list shared by the ingest writer and the bridge reader (commits c946f77cb5 / b6151a9541 / 29d9eacc97 on top of origin/main)
metadata:
  type: project
---

# Revocation list — writer and reader across one persisted map

Reviewed 2026-08-17 at `29d9eacc97` ("attestation verification reads a context
revocation list on every bridge").

## What holds

- `revocation_list_key(issuer, id) = format!("{}:{issuer}:{id}", issuer.len())`
  (`crates/scp-protocol/src/trust/aggregate.rs:192`) IS injective. The first
  colon terminates the decimal length run, which fixes the issuer boundary; no
  character a caller embeds in either field moves it.
- `sanitize_key_component` rejects, never rewrites, so `revocation_entry_key`
  merges no distinct keys.
- SQLite `list_keys` / `delete_prefix` use a `>= prefix AND < successor` range
  scan, not `LIKE`, so an underscore in a context id is not a wildcard.
- Every non-test `AttestationRevocationChecker` implementation is issuer-scoped.

## What does not

**R1 (HIGH) — the attestation CACHE is keyed on a bare id, so the issuer-scoped
revocation list guards a slot two issuers share.**
`crates/scp-runtime/src/store/trust.rs:35-44` builds
`trust/{ctx}/attestation/{subject}/{attestation_id}`; the FFI in-memory store
dedupes on `e.attestation.id == entry.attestation.id`
(`crates/scp-ffi/common/src/trust_store.rs:80-87`). Both drop the issuer. An
attacker mints a free DID, signs `(issuer=A, subject=S, id=X)`, gets it
ingested, and overwrites the honest issuer's cached entry. Then he revokes his
own copy, and `revocation_list_key(A, X)` drops the slot that used to hold
`(H, X)`. The test store that guards issuer scoping,
`ScopingTestStore` (`crates/scp-testing/tests/integration/trust.rs:1336-1351`),
keys on `(ctx, subject, ISSUER, id)` — strictly finer than every production
store — so the guard cannot observe the collision.

**R2 (HIGH) — `trust_verify_attestation` reads the list and never writes it.**
`verify_attestation_in_context`
(`crates/scp-ffi/common/src/trust_store.rs:607-617`) is read-only. Only
`verify_and_cache_attestations` writes, and only `trust_aggregate` /
`participation_record` reach it. An app whose verification entry point is
`trust_verify_attestation` never records a revocation it just saw.

**R3 (MED-HIGH) — `get_revocation_state` loads the whole list per verification.**
`load_trust_revocation_state` (`crates/scp-runtime/src/store/trust.rs:253-266`)
lists and decrypts every entry. The storage key is
`sha256(revocation_list_key)`, so a point lookup is already available and unused.
Unbounded attacker-driven growth degrades every later verification.

**R4 (MED) — `store_trust_revocation_state` deletes the prefix first**
(`crates/scp-runtime/src/store/trust.rs:190-206`). A mid-loop failure leaves the
list truncated and every previously-revoked cached attestation counts again.

**R5 (MED) — twin checkers.** `RevocationMapChecker`
(`crates/scp-protocol/src/trust/aggregate.rs:210-233`) and
`RevocationStateChecker` (`crates/scp-ffi/common/src/trust_store.rs:166-190`)
are the same body in two crates, both private, nothing tying them.

**R6 (MED) — batch abort discards discovered revocations.** Pass 1 of
`verify_and_cache_attestations` returns on an infra error at
`crates/scp-ffi/common/src/trust_store.rs:388`, before the
`add_revocations` write at `:395-400`. Today every `verify_attestation` error is
in `is_verification_rejection`, so caller data cannot trigger it; adding one
variant makes caller data a suppression primitive.

**R7 (LOW) — no subject binding on ingest.** `verify_and_cache_attestations`
caches under `ca.attestation.subject`, which no argument constrains, so one
aggregate call writes cache slots for any subject in the context.

**R8 (LOW) — stale doc.** `crates/scp-ffi/src/trust.rs:674-675` still says
aggregation "falls back to an ephemeral in-memory store"; the body fails closed.

**R9 (LOW) — `renew_attestation`** (`crates/scp-protocol/src/trust/renewal.rs:105`)
gained a `revocation_checker` parameter and has zero production callers.

See [[pr2366-attestation-fail-closed]] for the surfaces this branch built on.
