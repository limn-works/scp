---
name: pr-trackf-remaining-fail-opens
description: Attack surfaces found reviewing branch fix/trackf-remaining-fail-opens (relay blob selection, FileKeyCustody verifier, cfg gates, custody required, governance fail-closed)
metadata:
  type: project
---

Branch `fix/trackf-remaining-fail-opens`, 5 commits on aeba9c24f, reviewed 2026-08-16.

**Why:** the branch removes four fail-opens (sqlite default, silent wrong passphrase,
in-memory stores on shipped paths, `?? Executed`). I attacked each for a residual
wrong-outcome path.

**How to apply:** these are the surfaces to re-check whenever this area changes.

## Confirmed sound (do not re-litigate)
- `storage_from_env` has exactly 3 callers, all handle the error: `crates/scp-relay/src/main.rs:48`,
  `crates/scp-node/src/main.rs:303/562/594` (via `storage_from_env_or_exit`).
- `scp-relay` and `scp-node` pin all four durable blob features non-optionally in Cargo.toml,
  so the `memory` arm is never the sole compiled arm.
- `--self-host` names sqlite at its own boundary: `crates/scp-node/src/self_host.rs:2222`.
- FileKeyCustody verifier construction is sound: fresh OsRng nonce, empty message, distinct AAD
  from the entry path (entries use empty AAD), constant-time tag check.
- PyO3 (`crates/scp-ffi/src/context.rs:3919`) and UniFFI (`crates/scp-ffi/uniffi/src/bridge.rs:11393`)
  match all 29 `GovernanceActionResult` variants exhaustively with byte-identical names, so the
  new Swift throw is reachable only on bridge/SDK version skew.
- Shipped NAPI + PyO3 reject all three custody strings (`in_memory` is `#[cfg(feature="testing")]`),
  so `identityCreate` fails closed on a shipped addon whatever the caller names.

## Residual surfaces
- `crates/scp-platform/src/file.rs:114` — VERIFIER_AAD binds only a fixed string. Header
  version/salt/entry_count and each entry's index + key_type stay outside every AEAD, so an
  attacker with write access to the key file can truncate the entry set, reorder entries
  (handles are positional, `file.rs:515`), or flip an entry's key_type byte to make one 32-byte
  secret serve as both an X25519 scalar and an Ed25519 seed. Pre-existing; closable by putting
  `version‖salt‖entry_count` in the verifier AAD and `index‖key_type` in each entry AAD.
- `crates/scp-platform/src/file.rs:506` — a zero-entry key file now carries an offline
  passphrase-guess oracle it did not carry before (one Argon2id 64MiB/3-iter per guess).
- `bindings/python/scp_sdk/scp.py:724,733` — Python still defaults `custody` to `CustodyType.FILE`,
  the omit-the-field form SCP-CAPSEL-8000 forbids; TS/Kotlin/Swift now require it.
- `GovernanceActionResult.from_bridge` has zero production callers; `scp.py:1753` returns the raw
  value. TS has a type alias with no parse; Kotlin has no such type. Fail-closed is live on Swift only.
- `SCP-GOV-11000` is the GovernanceError family default (`bindings/python/scp_sdk/errors.py:198`),
  not a dedicated code; Swift throws `ScpError.Context` carrying a `SCP-GOV-` code.
- `ViolationStore` / `InMemoryViolationStore` have ZERO consumers repo-wide and are not re-exported
  from `crates/scp-protocol/src/trust/mod.rs:41`. The doc claim that a shipped build uses a
  `Storage`-backed store is unsupported — no such store exists. §9.3 of the security-model spec
  (line 951) specs a durable `RelayEquivocationViolation` record that nothing implements.
- The two new gate tests slice a fixed 120-byte source window
  (`crates/scp-ffi/common/src/trust_store.rs:404`, `crates/scp-protocol/src/trust/custody_violation.rs:754`).
  Both files repeat the cfg literal in nearby prose, and both carry `§` (2 bytes) just outside the
  window, so a doc edit can either satisfy the test from a comment or panic on a char boundary.

Related: [[no-nullifiers-in-production]], [[feedback_no_migration_prerelease]].
