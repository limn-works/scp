---
name: issue-1933-f3-authoritative-event-log
description: Audit of branch fix/1933-f3-event-log-verify-authoritative-tree @4e52864b2 — event_log_verify/query/checkpoint rerouted to a runtime authoritative seam; verdict INCOMPLETE (Kotlin SDK untouched, no cross-bridge parity test, 3-way malformed-input code divergence)
metadata:
  type: project
---

Audited GitHub #1933 F3 branch `fix/1933-f3-event-log-verify-authoritative-tree` @ `4e52864b2`
(base `origin/main` d1ebc5ab9). Verdict: **INCOMPLETE**.

**Why:** the security fix itself is genuinely done and well done — all three native bridges call
`Supervisor::authoritative_event_log` / `unsigned_authoritative_checkpoint`, the `[0u8;32]`
fabricated-commitment defaults were purged from the runtime checkpoint producers too, and the new
absence shape restores what ADR-011 (`.docs/adrs/phase-2.md:1094-1120`) always specified
(`LeafWithProof { leaf_hash, leaf_index, inclusion_proof }`). What's missing is the *parity* half.

**Load-bearing findings worth remembering:**
- **Kotlin is the systematically-forgotten SDK on UniFFI changes.** Its generated bindings are
  gitignored (`.gitignore:28,44`; `build.gradle.kts:117-142` regenerates at build), so unlike
  Swift's checked-in `ScpBindings.swift` there is NOTHING in-repo to diff — which is exactly why
  Kotlin silently keeps stale hand-written shims. Here `CoroutineBridge.kt:1166-1169`
  `eventLogVerify(...): Boolean` is the deleted producer-set `verified` flag re-spelled, and it
  survived a PR whose whole point was deleting that flag. **Always check Kotlin explicitly on any
  UniFFI record change; absence from the diff is not evidence of correctness.**
- **PyO3 `ScpPyError::validation()` hardcodes `VALID_7001`** (`crates/scp-ffi/src/error.rs:335-340`),
  NOT `VALID_7000`. Any doc/registry row claiming "malformed input carries SCP-VALID-7000 on every
  bridge" is false for PyO3. This branch wrote exactly that claim into
  `.docs/standards/sdk-common.md:261` and `error_codes.rs:543`.
- **`ffi_conformance.rs:1358-1371` (`event_log_query_uses_shared_payload_projection`) is the
  template** for mechanically pinning "all three bridges call the ONE shared helper". When a change
  introduces a new shared seam, check whether an analogous assertion was added. Here three new
  seams landed with zero.
- **New error codes emitted but never asserted**: `CTX_2139` appears at 6 emission sites and 0 test
  assertions; the tests assert message substrings ("present in the log") instead — the ADR-059
  error-prose anti-pattern.
- **`bindings/python/scp_sdk/event_log.py:73-115`** (`_extract_root_hash`/`_extract_event_count`)
  is built entirely on the `LogSummary` fallback event this branch deleted from `event_log_query`;
  `_extract_root_hash` now always returns the 64-zero `_EMPTY_ROOT_HASH` sentinel — the same
  fabricated-root class the branch spent 830 runtime lines removing.
- `Supervisor::test_append_event` (supervisor.rs:14698) duplicates the pre-existing
  `test_append_event_log` (:14927) verbatim; only the context-id key type differs.
- The ADR-046 parity harness (`bindings/python/tests/bridge_parity/`) covers `event_log_query`
  (ops 4 and 10) but has never covered `event_log_verify`; untouched by this branch (AC5 unmet).
- **PHANTOM MATRIX MATCH — do not read a green `check-sdk-coverage.py` as proof a cell is real.**
  `scripts/check-sdk-coverage.py:329-334` maps `("EventLog","verify")` for swift AND kotlin to the
  bare alias `"verify"`. No event-log symbol by that name exists: Swift resolves to
  `bindings/swift/Sources/SCP/Auth/ScpId.swift:316` (`public static func verify(`) /
  `Platform/AppleDeviceAttestation.swift:212`; Kotlin to `auth/ScpId.kt:205`. The real symbols are
  `EventLog.proveInclusion` / `Scp.eventLogVerify` (swift) and `eventLogVerify` (kotlin). Deleting
  Swift's `EventLog.verifyInclusion` was therefore INVISIBLE to the gate. Classic
  `.docs/lessons/ast-gate-checks-definition-not-name-resolution.md`. Repointing the alias is a
  permitted coverage-TIGHTENING edit. Matrix domain `EventLog` is at
  `.docs/standards/sdk-capability-matrix.json:1063-1102` (query/verify/checkpoint/
  signed_checkpoint/checkpoint_by_did, all 4 SDKs `true`); gate reports 264 ops / 0 errors.
- `bash scripts/check-error-codes.sh` PASSES; it never reads `.docs/` (excluded) and Phase-2
  fingerprints only emitted MESSAGES, never doc comments — which is why the `keep SCP-CTX-2025`
  doc-comment bug sails through. Nothing mechanically enforces registry↔doc agreement.
- ALL 23 gates pass (ffi_conformance 48/48, pipeline_wiring 104/104, check_ready_coverage 2/2).
  `pipeline_wiring.rs` does NOT `include_str!` the PyO3/NAPI event-log sources at all, so it cannot
  assert on them without adding them. The better mechanism is a new rule in the `call_invariants[]`
  array of `sdk-capability-matrix.json` (tree-sitter-backed, already runs across
  pyo3/napi/uniffi/runtime); `call-invariants-baseline.json` explicitly permits ADDING rule ids.
- **`bridge_ratchet_baseline.json` no longer exists anywhere in the tree** — `git cat-file -e` fails
  on both HEAD and origin/main; the only surviving reference is the enforcement-file list at
  `CLAUDE.md:125`. The live bridge ratchet is `MIN_PARITY_OPERATIONS = 109` at
  `ffi_conformance.rs:1434` (215 operations in `bridge-aliases.json`). Worth correcting CLAUDE.md.
- Env: `scripts/check-pure-helpers.sh` (and any cargo gate) reports PHANTOM `E0433/E0432` on
  `UnsignedCheckpoint` / `OutletErrorSurface` unless run with an isolated `CARGO_TARGET_DIR` —
  the shared `~/.cargo/shared-target` poison. Both symbols do exist.

See [[bounded-reply-await-sweep-core]] for the same "sweep missed a sibling" failure mode.
