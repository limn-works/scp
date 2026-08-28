---
name: scp294-custody-name-one-thing
description: Review of fix/scp-294-custody-name-means-one-thing — "platform" custody fails closed on all 3 bridges; findings and what compiled clean.
metadata:
  type: project
---

# SCP-294 custody-naming review (branch `fix/scp-294-custody-name-means-one-thing`, base 5e7e5b4e67)

The change makes `"platform"` return `SCP-IDENT-1003` on the PyO3 bridge (it built a
`FileKeyCustody` before), deletes `CustodyMethod::Platform`/`::Software` from the UniFFI
bridge in favour of `CustodyMethod::Callback`, and strips the platform/software members
from each SDK's `CustodyType`.

**Why:** the review verified the Rust, the four SDK surfaces, and every added test.

**How to apply:** reuse these verdicts instead of re-deriving them; re-check only the
items listed as open.

## Verified sound (do not re-litigate)
- `parse_custody_with_seed` (testing variant): the `"file" if testing_seed.is_some()`
  guard routes all eight custody×seed combinations correctly. `"in_memory"` + seed still
  reaches `from_seed_bytes`; `"file"` with no seed falls through to `parse_custody_inner`.
- All three `match CustodyMethod` sites in `uniffi/src/bridge.rs` are exhaustive with no
  catch-all: `identity_create` (~9619), `identity_create_with_agent_key` (~17426), and
  `custody_type()` (~2731).
- `cargo check` is clean for `scp-ffi`, `scp-ffi-napi`, `scp-ffi-uniffi` in both the
  `testing` and the bare configuration. `--all-targets` without `testing` fails on
  pre-existing symbols (`DidCache`, `make_dht_with_signer`, `new_in_memory_for_test`),
  not on this change.
- `bun run check` (both tsconfigs), the four new PyO3 unit tests, the new TypeScript mock
  test, ruff, and `./gradlew :scp-kt:compileTestKotlin` all pass.
- The Swift test file compiles against `Sources/SCP/`: `ScpError.Identity(_, code)`,
  `SCP(storage: .inMemory)`, `shutdown(timeoutMillis:)`, and
  `identityCreateWithAgentKey(custody:)` all exist. `line_length` is disabled in
  `.swiftlint.yml`, so its 126-character lines pass.

## Findings that stood at review time
- `crates/scp-ffi/src/identity.rs:1650` — the `SCP-IDENT-1010` message in `identity_load`
  still tells the caller to pass `custody='platform'`, which the same file now rejects.
- No test on any bridge pairs a `testing_seed` with a non-`in_memory` custody string, so
  the arm reordering this change is named for has zero coverage.
- Six comments still promise `SCP-VALID-7009` for seed-plus-wrong-custody:
  `napi/src/scp.rs:380,401`, `src/identity.rs:738,1120`, `bindings/swift/Sources/SCP/Scp.swift:739`,
  `bindings/kotlin/.../Scp.kt:1262`. That code is now unreachable on the NAPI and UniFFI
  bridges and fires only for `"file"` + seed on PyO3.
- `.docs/architecture.md:915` keeps `custody="platform"`, which the story's own acceptance
  criterion forbids.
- `bindings/swift/README.md:29`, `bindings/kotlin/README.md:35`, and
  `docs/guides/sdk-quickstart.md:227,242` read `identity.did`; the generated UniFFI type
  declares `did()`. The quickstart line was a working `identity.did()` before this change.
- `templates/agent-tool-provider/agent.py:267` and `docs/examples/python/identity.py:21`
  call `Identity.create`, which `bindings/python/scp_sdk/identity.py` does not define.
  This change edited the comment above each call and left the call.

## Recurring pattern this review adds
A change that narrows an accepted-value set must sweep the *error messages that recommend
a value from the old set*. `identity.rs:1650` recommends the exact string
`identity.rs:815` now rejects, and both live in one file.

Related: [[uniffi-checksum-staleness]] — `bindings/swift/Sources/SCP/Internal/ScpBindings.swift`
was stale (still carried `.platform`/`.software`) for part of this review and was
regenerated mid-review. `build-xcframework.sh` regenerates it, so a stale copy never
reaches a compile that matters, but a checked-in generated file that disagrees with the
Rust enum is still worth grepping for on every `uniffi::Enum` variant deletion.
