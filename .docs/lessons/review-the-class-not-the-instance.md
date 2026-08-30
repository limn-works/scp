# Review the Class, Not the Instance

**Date:** 2026-08-30
**Source:** pull request #2415, the custody-vocabulary branch (`spec/custody-vocabulary-names-the-backend`). Two defect classes on that branch each took one commit per site, spread across as many rounds as there were sites, because each round reported the one site it had read.

## The rules

`CLAUDE.md` states both rules, and this file records the evidence behind them. Read the
statements there, not the restatement here:

- **Review the class, not the instance** — the Agents section of `CLAUDE.md`, below "Take
  every finding seriously".
- **Run the full gate set once, on the tree you are about to push** — the Change protocol
  of `CLAUDE.md`, below "Run CI locally before pushing. **Always.** No exceptions."

Alec stated both on 2026-08-30. `CLAUDE.md` quotes him verbatim and marks every sentence
derived from those words as derived.

## Class one: one changed error code, three stale assertions, three rounds

Commit `5340ade542` (2026-08-30 02:01:09 -0400) changed what
`identity_published_custody` returns on the UniFFI bridge for a DID the instance retains
no custody for. `crates/scp-ffi/uniffi/src/bridge.rs` went from `codes::IDENT_1017` to
`codes::IDENT_1001` on both of that arm's failure paths, because the registry entry for
`SCP-IDENT-1017` in `crates/scp-ffi/common/src/error_codes.rs` reserves that code for a
handle carrying no signing custody and names `SCP-IDENT-1001` for a DID an instance never
registered.

Three test sites asserted the old code. The same commit fixed one of them,
`REGISTRY_MISS_CODE` in
`bindings/kotlin/scp-kt/src/test/kotlin/works/limn/scp/CustodyCallErrorCodeTest.kt`. It
left two:

| Round | Commit | Time | Site it fixed |
|-------|--------|------|---------------|
| 1 | `5340ade542` | 02:01:09 | the Kotlin constant, alongside the bridge change |
| 2 | `4dbc415bd4` | 04:47:23 | `bridge::tests::identity_published_custody_fails_closed_without_retained_custody` in `crates/scp-ffi/uniffi/src/bridge.rs` |
| 3 | `0064e2a1fa` | 07:28:49 | `testPublishedCustodyFailsClosedForAnUnretainedDid` in `bindings/swift/Tests/SCPTests/CustodyTypeTests.swift` |

2h46m14s separated round 1 from round 2, and 2h41m26s separated round 2 from round 3.
`git grep -l -E "SCP-IDENT-1017|IDENT_1017" 5340ade542^ -- bindings crates` returns 15
files, and all three sites are among them, so one search at 02:01 would have found both
sites that rounds 2 and 3 went on to fix.

Commit `0064e2a1fa`'s message records the failure it was fixing:
`CustodyTypeTests.swift:213: error: XCTAssertEqual failed: ("SCP-IDENT-1001") is not equal
to ("SCP-IDENT-1017")`.

## Class two: two production CI lanes ran no test code, two rounds

On `ad08cb4866`, the merge base of this branch and `main`, `.github/workflows/ci.yml`
gave each bridge a production-configuration lane. `rust-test-napi-production` ran
`cargo test -p scp-ffi-napi --features server` (line 687). `rust-build-pyo3-production` ran
`cargo build -p scp-ffi --features server` (line 731) and `rust-build-uniffi-production`
ran `cargo build -p scp-ffi-uniffi --features server` (line 758). `cargo build` compiles no
test code, so no CI job ran the assertions that only a production-configuration test target
compiles: `identity::prod_custody_message_tests`, gated
`#[cfg(all(test, not(feature = "testing")))]`, on the PyO3 bridge, and the
`#[cfg(not(feature = "testing"))]` branch of
`crate::tests::build_key_custody_admits_in_memory_per_compiled_feature` on the UniFFI
bridge. Each commit message below names the item on its own bridge.

Commit `fe12eb0aea` (07:32:36) moved the PyO3 lane to
`cargo test -p scp-ffi --features server`, which put three custody fail-closed assertions
into a CI job. Its message names the NAPI lane as the twin that already ran its tests, and
names no third lane. Its diff carries `rust-build-uniffi-production` in the surrounding
context and does not change it.

Commit `77524e89f1` (10:34:31), 3h01m55s later, moved the UniFFI lane to
`cargo test -p scp-ffi-uniffi --features server`. Its message states what the earlier round
missed: "The UniFFI bridge was the one bridge of the three whose shipped-configuration
custody arms no CI lane asserted." Its message then lists seventeen items that blocked
`cargo test -p scp-ffi-uniffi --features server` before that lane could run.

## What the rounds cost

Thirteen commits carry an author date of 2026-08-30 on this branch, the first at 02:00:23
and the last at 10:34:31. Three gaps between consecutive commits exceed 90 minutes:
2h46m14s (`5340ade542` to `4dbc415bd4`), 1h51m14s (`2620f6fe57` to `acbabf4914`), and
2h30m58s (`17407d7c7f` to `77524e89f1`). The first gap separates round 1 of class one from
round 2. The third gap falls inside the 3h01m55s between round 1 and round 2 of class two.
Searching the siblings at each class's first site would have removed both. This file
attributes the 1h51m14s gap to neither class.

## Reproducing these figures

```
git fetch origin spec/custody-vocabulary-names-the-backend
git log --format='%h %ad %s' --date=iso-strict origin/main..FETCH_HEAD
git show 5340ade542 -- crates/scp-ffi/uniffi/src/bridge.rs
git show 4dbc415bd4 -- crates/scp-ffi/uniffi/src/bridge.rs
git show 0064e2a1fa -- bindings/swift/Tests/SCPTests/CustodyTypeTests.swift
git show ad08cb4866:.github/workflows/ci.yml | sed -n '660,760p'
```

Pull request #2415 had not merged when this file was written, so these hashes resolve
through the branch rather than through `main`, and a squash merge will not preserve them.

## Related

- `.docs/lessons/behavioral-invariant-must-be-asserted-on-every-bridge.md` — the same
  failure in the cryptographic layer: of the four bridges that existed then, one
  re-asserted the spec §3.7 invariant `SHA-256(revealed_key) == commitment` and three did
  not, and `ffi_conformance.rs` stayed green throughout.
- `.docs/lessons/cross-bridge-canonical-naming.md` — its section "Bridge-symmetry harness
  has an inverse-coverage blind spot" states what the second half of Alec's rule states:
  `scripts/check-bridge-symmetry.sh` validates only the operations the matrix registered,
  so an unregistered operation passes it by being absent.
