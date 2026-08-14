# #1909 native AAD — open() hash-consistency guard (b8d1a7676) — CLEAN

Commit `b8d1a7676` (parent `84b029e88`). provider.rs (scp-runtime crypto/mls).

## What landed
- `84b029e88`: bind RAW `inner.context_id` string in sender-layer AAD (§9.16.1), not `hex::encode(context_id)`. Adds `seal` hash-consistency assert. Changes `open` signature to take `context_id_str`. Adds `seal_open_binds_raw_context_id_string_not_hex` (provider) + `raw_context_string_aad_differs_from_hex_of_hash` (encrypt.rs).
- `b8d1a7676` (under review): mirror assert in `open` (`context_id_bytes(str) != *context_id → CryptoFailed`), placed FIRST in the with_context closure before outer deserialization. Adds `open_rejects_...` test. ADJUSTS the negative case of `seal_open_binds_raw...` from AEAD-rejection proof → guard-rejection proof.

## Verdict: SOUND, no findings.
- Guard condition not inverted; same CryptoFailed variant as seal; no unwrap/panic; fires before any decrypt/store work.
- Production caller messaging_helpers.rs:2742 passes `(context_id_bytes(s), s, blob)` — guard satisfied by construction; "unreachable" comment accurate.
- TEST ADJUSTMENT not weakening: AEAD-level "hex AAD fails to verify" property is INDEPENDENTLY held by `raw_context_string_aad_differs_from_hex_of_hash` in encrypt.rs (both-direction cross-decrypt failure). So adjusting the provider neg-case to hit the guard loses nothing.
- Adjusted provider test STILL fails on a §9.16.1 revert: full revert (AAD=hex, guards gone) → neg-case `expect_err` fails (open would succeed) AND pos-case `.expect(succeed)` fails (raw AAD vs hex-sealed → AEAD mismatch). Both break.
- `open_rejects` non-vacuous: bob ctx exists (with_context returns Some → closure runs → guard first). `bogus_outer=[0xAB;64]` + `assert_eq!` on exact msg "context_id_str does not hash..." — if guard absent, OuterEnvelope::from_bytes(garbage) yields a deserialization-error msg, failing assert_eq. Valid proof guard runs ahead of AEAD.
- Neg-case non-vacuous: `context_id_bytes(hex_of_32bytes)=SHA256(hex)` ≠ ctx_id (plain SHA-256, not preimage). Guard genuinely fires.
- Fixtures migrated correctly: `setup_alice_bob_two_party` now derives id from TEST_CTX_STR; string-driven tests use `setup_two_party_for_ctx_string(s)` and pass same s to open. No test passes for the wrong reason.
- All 3 tests pass at b8d1a7676.

## GOTCHA recorded
- bug-catcher cwd resets between Bash calls → bare `git show`/`grep`/`git log` without explicit `cd <worktree>` can hit the WRONG worktree (main/another). Caused a FALSE "test deleted" alarm here. ALWAYS `cd /Users/.../worktrees/<name>` first or use absolute -C. Verify worktree HEAD == the commit under review before trusting greps.
