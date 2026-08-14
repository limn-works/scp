---
name: adr057-prereq4-release-err-decrypt
description: ADR-057 Prereq-4 reframe — release-build (debug-assertions off) is the fail-closed anchor for browser MLS decrypt on tampered ciphertext; fuzz_mls_decrypt evidences it. SOUND.
metadata:
  type: project
---

# ADR-057 Prereq-4 — release build (not panic=unwind) as decrypt fail-closed anchor (#1444)

Branch `fix/adr057-prereq4-release-err-decrypt`. VERDICT: SOUND. Reframes the (infeasible) `panic=unwind` browser build to: shipped `--release` build compiles OUT openmls's decrypt `debug_assert!` → `process_message` returns typed `Err` on tampered ciphertext → `MlsError::DecryptionFailed` → browser `[SCP-CRYPTO-4010]`. Pinned by root `Cargo.toml` `[profile.release] debug-assertions=false` + new `fuzz/fuzz_targets/fuzz_mls_decrypt.rs` + CI `fuzz-mls-decrypt` job (`-O`).

## Load-bearing openmls facts (verified in 0.8.1 source)
- The only attacker-reachable panic on the decrypt path is `debug_assert!(false, "Ciphertext decryption failed")` at `openmls-0.8.1/src/framing/private_message_in.rs:136`, on the CONTENT `aead_open` failure. It is CONTENT-TYPE-AGNOSTIC — fires before `deserialize_ciphertext_content` dispatches app-vs-commit (line 144). So an APPLICATION-message tamper reaches the exact same panic line a tampered commit would.
- Sender-data decryption (`sender_data()`, line 87-96) maps AeadError cleanly — NO debug_assert, no panic.
- `ciphertext_sample()` (schedule/mod.rs:962) samples the HEAD (`&ciphertext[0..hash_length]`, 32B) of the content ciphertext to derive the sender-data key/nonce. THEREFORE tampering the TAIL leaves sender-data derivation intact → sender-data AEAD succeeds → content AEAD fails → reaches the debug_assert. The fuzz target's tail-XOR strategy is cryptographically correct for reaching the target line (for small tamper lengths).

## Threat-model scoping (the one honesty note)
- The StagedCommit / tree-KEM merge path (HPKE path-secret decryption) is only reached AFTER outer AEAD succeeds → requires an AEAD-VALID frame → a malicious MEMBER (insider), NOT a relay. A relay cannot forge an AEAD-passing frame. So that path is NOT relay-reachable and correctly out of Prereq-4's untrusted-relay scope. The fuzz target gives it ZERO coverage (all garbage/tampered inputs fail outer AEAD). MEDIUM: ADR's universal wording "the only attacker-reachable panic ... is a debug_assert!" should explicitly scope out the insider AEAD-valid-malformed-commit path to avoid over-claim (research flagged tree-KEM path as "unproven" — it's unproven AND out-of-scope, not covered).

## cargo-fuzz `-O` mechanics (point-2 crux)
- cargo-fuzz injects `-Cdebug-assertions -Coverflow-checks` UNLESS `-O`/`--release` is passed (rule: `!release || debug_assertions`). With `-O` and no `-a`, no injection → `[profile.release] debug-assertions=false` governs → OFF. So `-O` IS the operative switch; the profile pin is belt-and-suspenders + greppable-invariant guard against a future `debug-assertions=true` override. CI job runs BOTH `cargo fuzz run` and `cmin` with `-O`. Job fires on `0 3 * * *` nightly cron (exists in fuzz.yml) + workflow_dispatch. Empirically the target ran locally (~900 untracked corpus entries in fuzz/corpus/fuzz_mls_decrypt/, no crash artifact); only `.gitkeep` committed.

## No regression (point 4)
All 4 catch_unwind sites (decrypt/decrypt_with_sender_key/decrypt_with_sender_did/decrypt_with_membership_changes) RETAINED — bodies byte-identical, only comments changed. Error mapping to MlsError::DecryptionFailed unchanged. `[SCP-CRYPTO-4010]` mapping in scp-client-wasm/src/error.rs untouched. catch_unwind now correctly reframed as defense-in-depth for native/debug builds (no-op on release wasm).
