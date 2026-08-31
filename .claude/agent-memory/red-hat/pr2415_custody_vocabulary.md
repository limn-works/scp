---
name: pr2415-custody-vocabulary
description: Red-team chains for PR #2415 (spec/custody-vocabulary-names-the-backend) — derived custody publication, os_keystore fail-closed, cross-bridge code divergence, and the fact that nothing publishes or reads a custody attestation.
metadata:
  type: project
---

# PR #2415 — custody vocabulary names the backend (2026-08-28)

## The load-bearing reachability fact
On a shipped (no `testing` feature) build **no bridge creates an identity at all**:
every `identity_create*` path returns `SCP-IDENT-1059` (`no_pre_rotation_backend`)
— `crates/scp-ffi/src/identity.rs:1259,1392`, `crates/scp-ffi/napi/src/scp.rs:659`.
So the entire custody surface is inert in production. Every chain below reaches
its payoff only on a `testing`-feature build, which is what the Swift README
tells developers to run ("The Quick Start above therefore runs against a
framework built with the `testing` feature").

## Chains
- **RED-1201 (HIGH, proven, honesty-not-security)** — `ScpKeyCustodyAttestation::derive`
  gives ZERO adversarial guarantee on the `os_keystore` path: the "backend" is the
  SDK consumer's own callback. `bindings/typescript/tests/identity-create-with-custody.test.ts:182-198`
  (`SignOnlyKeychain`) is a working exploit shipped in-repo: keeps raw Ed25519 seeds
  in a JS `Map`, answers `keyIsExtractable()=false` / `unlockFactor()="biometric"`
  → publishes `non-extractable-biometric`. Payoff today = 0 because nothing publishes
  or reads it; payoff becomes real the moment a reader is wired.
- **RED-1202 (INFORMATIONAL, structural)** — nothing writes and nothing reads a custody
  attestation. `ScpKeyCustodyAttestation::derive` and `DidDocument::set_custody_attestation`
  have **zero non-test callers** (`crates/scp-identity/src/dht.rs` never calls it).
  `KeyCustodyModel` has zero production consumers. `identity_published_custody` returns a
  string to the app and stops there. §27.4.4 of the attestations spec states this plainly.
- **RED-1203 (MEDIUM)** — §3.2.2 of `.docs/specs/03-identity.md:175` asserts "§27.4.4 of
  the attestations spec states that ruling in four clauses" (Alec's 2026-08-25 ruling:
  "either the platform proof is attached and verified, or the custody model reads as
  software"). §27.4.4 states no such rule — it states "There is no verifier". Dangling
  citation for the ONE reader-side control that would defang a lying attestation.
- **RED-1204 (LOW/MEDIUM)** — `scp_ffi_common::key_file::open_default_key_file`
  (`crates/scp-ffi/common/src/key_file.rs:63-88`): (a) presence-only passphrase check —
  `SCP_KEY_PASSPHRASE=` (empty) is accepted, no minimum length; (b) `home_dir()` falls
  back to `PathBuf::from(".")` when `$HOME` is unset (line 88), so a container/systemd/CI
  process writes `./.scp/keys.bin` into CWD; (c) `FileKeyCustody::new` never verifies the
  passphrase at open — a wrong one succeeds and fails later at first decrypt; a deleted
  key file silently creates a fresh empty store.
- **RED-1205 (LOW, cross-bridge divergence)** — same condition, three codes:
  - missing `SCP_KEY_PASSPHRASE`: PyO3 `VALID_7001` (`identity.rs:765` via
    `ScpPyError::validation`) vs NAPI/UniFFI `VALID_7005` (`napi/custody.rs:807`,
    `uniffi/bridge.rs:6810`). Swift `Types.swift` and Kotlin `Types.kt` both document
    `SCP-VALID-7001` while their bridge returns `7005`.
  - key-file open failure: PyO3/NAPI `IDENT_1001` vs UniFFI `IDENT_1002` (`bridge.rs:6815`).
  - `identity_published_custody` provider-throw: NAPI `IDENT_1001` (`napi/scp.rs:4446`),
    UniFFI `IDENT_1017` (`bridge.rs:10222`). TS SDK doc (`scp.ts`) claims `1017`.
    The capability matrix documents only the registry-miss half of this.
- **RED-1206 (LOW)** — no shipped platform adapter can ever publish a custody value.
  Apple: `keyIsExtractable→true` always (`AppleKeyCustody.swift:1049`) +
  `unlockFactor→"biometric"|"caller_supplied_key"` (`:1083`) — both pairs are unstatable.
  Android: `unlockFactor→"unprotected"` always. And `AppleKeyCustody` does not conform to
  the UniFFI `KeyCustodyProvider` protocol at all (10 of 11 signatures differ) — the Swift
  README says so.
- **RED-1207 (LOW)** — `CustodyMigrationTarget` serde renamed with no aliases; the four
  retired wire strings now fail to deserialize. `CustodyMigrationRequest` is a wire type,
  but every bridge drives a `NotConfiguredMigrationBackend` that errors on step 1, so
  there is no migration window to attack.
- **NON-ISSUE** — `crates/scp-ffi/napi-test-stubs` (no-op C `napi_*` stubs, incl. the new
  `napi_get_value_bool`) is a **dev-dependency only**; Cargo keeps it out of the cdylib.
  Note: NO Rust test exercises the NAPI `custody_substrate` callback path — the stubs
  would return `false`/`""` if one did.

## Reusable lessons
- **"Derived, never declared" is a type-safety property, not a trust property.** When the
  substrate is a foreign callback the participant wrote, deriving only moves the lie one
  frame outward. Always ask: who implements the trait on the adversary's machine?
- A published-value pipeline with no writer and no reader is a *vocabulary*, not a control.
  Check `grep -c` for non-test callers of the publish function before scoring any chain.
