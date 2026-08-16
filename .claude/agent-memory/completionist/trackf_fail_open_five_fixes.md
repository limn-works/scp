---
name: trackf-fail-open-five-fixes
description: Review of branch fix/trackf-remaining-fail-opens (5 fail-open fixes) — which layers each fix skipped and which identical defects survived elsewhere
metadata:
  type: project
---

Branch `fix/trackf-remaining-fail-opens` fixed five fail-opens: TypeScript custody default,
Python governance-outcome fallback, `FileKeyCustody` wrong-passphrase timing,
`storage_from_env` silent sqlite default plus its library-level `std::process::exit`, and
the `#[cfg]` gate on two in-memory stores. Reviewed 2026-08-16 at commits
`22f34e356`..`b60657185` plus the docs commit `73869dbf4`.

**Why:** the review asked whether each fix reached every layer its property spans, and
whether an identical instance of the same defect survived elsewhere in the repository.

**How to apply:** when a future pass touches any of these five properties, start from the
survivors below rather than re-deriving them.

## Survivors found (each is the same defect the branch fixed, in a layer it skipped)

- `bindings/python/scp_sdk/scp.py:724` and `:733` — `identity_create` and
  `identity_create_with_agent_key` still default `custody` to `CustodyType.FILE`. The
  persistence spec clause `SCP-CAPSEL-8000` (§17.17.1) forbids an omit-the-field form.
  The same file's `SCP.__init__` (line 428) already requires `storage`, so the rule was
  applied to one capability and not the other inside one class.
- `crates/scp-transport/src/startup.rs:250-251` — `health_check`, a `pub async fn` in a
  library, calls `std::process::exit(0)` / `exit(1)`. `shutdown_signal` at line 273 does
  the same. Both sit in the file whose `storage_from_env` the branch converted to a typed
  error, and both are called from `scp-relay` and `scp-node` binaries.
- `bindings/swift/Sources/SCP/Governance.swift:63-69` — `MemberRole.fromBridge` falls back
  to `.custom`. The UniFFI bridge returns `format!("{r:?}")` of `RoleAssignment`
  (`crates/scp-ffi/uniffi/src/bridge.rs:13262`), which never matches an enum raw value, so
  `Context.memberRole` returns `.custom` for every member, admins included. The PyO3 bridge
  emits the same Debug string; the NAPI bridge instead returns `assignment.role_name`
  (`crates/scp-ffi/napi/src/context.rs:2500`) — a three-way bridge divergence.
- `crates/scp-protocol/src/trust/attestation.rs:722` — `NoOpRevocationChecker` always
  returns `None` (not revoked), is `pub`, is re-exported through `scp-core`
  (`crates/scp-core/src/lib.rs:172`), carries no `#[cfg]`, and has zero non-test
  constructors. Its file-siblings `InMemoryDidResolver`, `InMemoryRevocationChecker`,
  `InMemoryProofResolver`, `InMemoryCaveatResolver`
  (`crates/scp-protocol/src/crypto/ucan/validate.rs:194/328/359/514`) are ungated too,
  while `InMemoryNonceTracker` at line 249 in that same file carries the exact gate the
  branch applied.

## Verified as complete, so do not re-open

- `SqliteStorage::with_passphrase` (`crates/scp-platform/src/sqlite/mod.rs:226`) already
  rejects a wrong passphrase at construction, so `FileKeyCustody` had no surviving twin.
- The prove-absence gate's `PERMITTED_ALLOWLIST` (`scripts/check-shipped-feature-graph.sh`)
  is a positive whitelist, so `scp-ffi-common/testing` and `scp-protocol/testing` stay out
  of shipped artifacts without a gate edit.
- Every caller of `storage_from_env` and `start_relay_from_env` was updated.

## Mechanism note worth reusing

Both newly gated stores carry a unit test that reads its own file through `include_str!`
and asserts the `#[cfg(any(test, feature = "testing"))]` attribute sits within 120
characters before the `pub struct` declaration. A compiled test always runs under
`cfg(test)`, where the gated type exists either way, so no runtime assertion can observe
the gate — reading the declaration site is the only way a test detects its removal.

Related: [[adr057_transport_wasm_surface_parity]].
