---
name: scp294-custody-platform-fails-closed
description: SCP-294 made the custody string "platform" fail closed with SCP-IDENT-1003 on all three FFI bridges; audit notes, verified fail-closed gating, and the two residues found.
metadata:
  type: project
---

# SCP-294 custody naming — security audit (branch `fix/scp-294-custody-name-means-one-thing`, head 56c6a0e880)

**Fact.** `"platform"` now returns `SCP-IDENT-1003` on PyO3, NAPI, and UniFFI. It
previously built a `FileKeyCustody` (Argon2id + AES-256-GCM at `$HOME/.scp/keys.bin`)
on PyO3 while the Swift and Kotlin SDKs documented the same word as Keychain and
Android Keystore. UniFFI deleted `CustodyMethod::Platform` and `CustodyMethod::Software`
and stamps `CustodyMethod::Callback` on an injected provider, so
`Identity.custody_type()` answers `"callback"` — the string PyO3
(`crates/scp-ffi/src/identity.rs:1474`) and NAPI (`napi/src/custody.rs:437`) already
reported.

**Why:** the bridge cannot verify what substrate an injected `KeyCustodyProvider`
uses, so stamping `Platform` asserted a hardware-backed property it never observed.
`CallbackKeyCustody::custody_type` (`uniffi/src/bridge.rs:824`) forwards the
provider's self-report and maps an unrecognised string to `CustodyType::InMemory`
(least trust).

**How to apply:** when auditing custody surface again, these are the verified
fail-closed facts, each re-checkable in one grep.

- No regular `[dependencies]` table in `crates/scp-ffi/Cargo.toml`,
  `napi/Cargo.toml`, or `uniffi/Cargo.toml` names `scp-platform/testing`. The
  in-memory custody nullifier is unreachable in a shipped build; every bridge
  answers `"in_memory"` with `SCP-IDENT-1008`.
- On a shipped build every create path returns `SCP-IDENT-1059` from
  `no_pre_rotation_backend` (`crates/scp-ffi/src/identity.rs:110`,
  `#[cfg(not(feature = "testing"))]`), so no shipped build creates an identity at all.
  `"file"` custody still builds the `FileKeyCustody` before that check fires.
- `FileKeyCustody` writes the key file with `mode(0o600)` on Unix
  (`crates/scp-platform/src/file.rs:190`) and puts no key material in any error string.
- The 32-byte `testing_seed` stays in `zeroize::Zeroizing` on every path of
  `parse_custody_with_seed` in all three bridges.

## Two residues this audit found (neither blocks)

1. A shipped PyO3 build answers `("platform", seed)` with `SCP-VALID-7008` while
   NAPI and UniFFI answer `SCP-IDENT-1003`, because the
   `#[cfg(not(feature = "testing"))]` `parse_custody_with_seed` rejects the seed
   before it reads the custody name. The source comment records the divergence
   rather than fixing it. Fix: call `parse_custody_inner(custody)?` first.
2. Four error messages across three bridges assert "no shipped build creates an
   identity", and three tests assert the literal `SCP-IDENT-1059` appears in them.
   When the pre-rotation backend lands the sentence becomes false and every one of
   those tests still passes. Fix: `#[cfg]`-select the sentence the same way
   `no_pre_rotation_backend` is selected.
