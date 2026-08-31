---
name: custody-vocabulary-pr2415
description: Bug-catcher findings on PR #2415 (spec/custody-vocabulary-names-the-backend) — Deserialize bypasses ScpKeyCustodyAttestation::derive, three bridges return three codes for the same key-file failure, Swift/Kotlin SDK docs name a code their bridge never returns.
metadata:
  type: project
---

PR #2415 replaced the key-custody vocabulary across scp-did, scp-platform, the three FFI bridges, and four SDKs.

Findings that recurred as *patterns* worth watching in this codebase:

**Private fields + derived `Deserialize` is not an invariant.** `ScpKeyCustodyAttestation` (crates/scp-did/src/attestation.rs:60) makes every field private and deletes its constructor so "the struct exposes no field to write one into," then derives `Deserialize` and keeps `to_service_entry` public. `serde_json::from_str` is a public constructor that takes exactly the value the design forbids naming. The PR's own test at crates/scp-runtime/tests/agent_binding_integration.rs:727 uses it cross-crate. **Why:** a derived `Deserialize` re-opens every field a privacy-based invariant closes. **How to apply:** whenever a type's doc claims "a caller cannot name X," grep the same file for `Deserialize`, `Default`, `From`, and any `pub` field-taking constructor before believing it.

**Three bridges, one shared helper, three error codes.** `scp_ffi_common::key_file::open_default_key_file` centralizes the path and message; every bridge then maps `KeyFileError` to its own code and they diverge (PyO3 VALID_7001/IDENT_1001, NAPI VALID_7005/IDENT_1001, UniFFI VALID_7005/IDENT_1002). **Why:** deduplicating a helper does not deduplicate its error mapping; the mapping is where drift lives. **How to apply:** when a PR says "all three bridges share one function so they cannot drift," check the `map_err` arms, not the function.

**SDK doc comments get copied between bridges.** bindings/swift/Sources/SCP/Types.swift:43 and bindings/kotlin/.../Types.kt:110 both name `SCP-VALID-7001` for an unset `SCP_KEY_PASSPHRASE`; that is the PyO3 code, and both SDKs talk to UniFFI, which returns `SCP-VALID-7005`. bindings/python/scp_sdk/types.py:52 is the correct original. **How to apply:** an error code in an SDK doc is a claim about *that SDK's* bridge — verify against the bridge the SDK wraps, not the reference bridge.

**Stale module doc left behind by the same PR that falsified it.** crates/scp-platform/src/android/key_custody.rs:36 says the UniFFI callback interface "carries one custody question today," while the same PR adds `key_is_extractable` and `unlock_factor` to that interface (crates/scp-ffi/uniffi/src/lib.rs:482,497).

**FileKeyCustody has no cross-process lock; SqliteStorage does.** `open_default_key_file` hard-codes `$HOME/.scp/keys.bin`, and `FileKeyCustody` guards its whole-file read-modify-write with a per-instance `StdMutex` only, so two `Scp` instances (now reachable on all three bridges, not just PyO3) can lose an entry or point two handle maps at the same index. `decrypt_entry` (crates/scp-platform/src/file.rs:446) slices `data` with no bounds check, so a stale index panics.

Related: [[uniffi_checksum_staleness]].
