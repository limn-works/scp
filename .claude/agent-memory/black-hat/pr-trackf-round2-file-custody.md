---
name: pr-trackf-round2-file-custody
description: Round-two adversarial review of branch fix/trackf-remaining-fail-opens — FileKeyCustody v2 HMAC is construction-only and every write path re-seals unverified disk bytes; plus five smaller fail-opens.
metadata:
  type: project
---

Round two on `fix/trackf-remaining-fail-opens` (HEAD `1740459ca`), after round one fixed a
passphrase-only key-file check, a napi `format!("{result:?}")` governance mapping, an ungated
always-succeeds revocation checker, and Python/TS custody defaults.

**Why:** the branch added a v2 key-file format (passphrase commitment + file HMAC + three
labelled subkeys) whose stated guarantee is "the file did not change since custody wrote it."
Round two attacked that guarantee rather than the round-one symptoms.

**How to apply:** when reviewing any authenticated-at-rest file format in this repo, check
whether the authentication runs on every read or only at construction, and check whether any
write path re-MACs bytes it read without verifying.

## Load-bearing findings

1. `crates/scp-platform/src/file.rs` — `read_file` (723) verifies nothing. Every consumer
   (800 sign, 911 public_key, 970 destroy_key, 1063 dh_agree, 1199 import dedup, 740
   append_entry) re-reads the file with no MAC check. Two outcomes: swapping two 61-byte
   entry blocks after open redirects a handle to a different key and `sign` still returns Ok;
   and `append_entry`/`destroy_key` call `seal_file_mac` (765, 1016) over those mutated bytes,
   so custody signs the attacker's file and the tamper survives the next `open_existing`.
   Every integrity test in the file is named `..._at_construction`.
2. `decrypt_entry` (689-701), `append_entry` (743), `destroy_key` (974) slice without bounds
   checks — an externally truncated file panics instead of erroring.
3. No rollback resistance: an older validly-sealed file passes both header checks, so
   `destroy_key`'s "key material is removed from disk" is reversible. Needs out-of-band
   monotonic state; the honest fix is to state the limit in §17.8 of the persistence spec.
4. `crates/scp-transport/src/startup.rs:49-61, 79-82` — `env_or` swallows a parse failure, so a
   typo'd `SCP_RELAY_BIND_ADDR` silently binds `0.0.0.0:9000`. Asymmetric with the branch's own
   "a bad storage value is terminal" thesis.
5. `crates/scp-ffi/src/identity.rs:827-828` — `dirs_home` falls back to `"."` when `$HOME` is
   unset, and `FileKeyCustody::new` create-or-open silently mints a fresh empty store when the
   key file is absent.
6. No mechanical check keeps the Python/Swift/TypeScript governance-outcome lists ⊇ the Rust
   variant list. The Rust side is exhaustive by construction; the three SDK lists are not.

## Verified sound (do not re-litigate)

- Chosen-file attack fails closed: the commitment is `HMAC(argon2id(pass, salt), label)`, so an
  attacker who cannot guess the passphrase cannot author a file the victim opens.
- Header transplant fails closed: the salt is inside the MAC and feeds the derivation.
- `governance_action_result_name` has no wildcard arm; all 29 names match all three SDK enums today.
- `execute_governance_action` checks an `executed_proposals` replay marker before dispatch, so
  the new fail-closed SDK parse cannot cause a double execution on retry.
- napi and UniFFI both reject `"in_memory"` custody on a non-`testing` build.
- No non-dev dependency enables `scp-protocol/testing` or `scp-ffi-common/testing`.
- `--ephemeral` (the only in-memory blob path) is rejected on a shipped `scp-node` build.

See [[pr-trackf-remaining-fail-opens]] for the round-one record.
