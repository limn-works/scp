# ADR-047 — Bridge Symmetry Enforcement (shared alias registry + multi-surface scanners)

**Status:** Accepted
**Date:** 2026-04-17
**Decider:** @alecmarcus
**Related:** ADR-034 (WASM bridge re-implementation), ADR-046 (cross-bridge runtime parity harness), ADR-045 (fuzzing governance artifact model)
**Enforcement files (this ADR):**
- `scripts/bridge-aliases.json` — single source of truth for canonical FFI operations
- `scripts/check-bridge-symmetry.sh` — portable bash + awk surface-area scanner (CI + hook)
- `crates/scp-testing/tests/integration/ffi_conformance.rs` — `syn`-based Rust AST scanner + JSON-sync assertion
- `scripts/tests/bridge-symmetry/` — fixture tests of the enforcement itself
- `.claude/settings.json` — `PreToolUse` hook wiring

## Context

SCP exposes one Rust core across four FFI bridges (PyO3, UniFFI, NAPI, wasm-bindgen). The bridges do not share code — each is a separate `proc-macro`-driven surface that re-exports a subset of the core. Surface-area symmetry across bridges is a protocol invariant: if PyO3 exposes `identity_resolve` but WASM omits it, downstream SDKs diverge and the WASM surface quietly becomes a second-class citizen. ADR-034 carves out the only legitimate asymmetry (WASM cannot expose operations requiring tokio multi-thread); every other operation MUST exist in all four bridges.

### Prior state (before this ADR)

`crates/scp-testing/tests/integration/ffi_conformance.rs` already enforced parity, but with three structural weaknesses:

1. **Hand-maintained per-bridge match arms.** `pyo3_names()` / `uniffi_names()` / `napi_names()` / `wasm_names()` returned hardcoded `&'static [&'static str]` tables. A new operation required editing four functions plus any alias table, in lockstep. Drift was silent — a missing arm produced a false pass, not a failure.
2. **Hardcoded `known_exclusions` arrays.** Exemptions (e.g., WASM-unavailable operations per ADR-034) lived inside the test file, undocumented, with no machine-readable justification.
3. **Substring scanning of bridge source.** The test read bridge source as a string and substring-matched function names. This produced false positives (matching trait method declarations, doc-comments, commented-out code) and false negatives (functions inside `#[cfg(test)] mod tests { ... }` blocks were counted as production surface).

CI caught surface-area asymmetry only after the bridge code had already been written, reviewed, and pushed. Nothing caught asymmetry at edit time. Coder agents — the adversarial actor this project's builder tenets explicitly name — routinely add a PyO3 function without siblings, ship partial work, and self-report success. Pre-push enforcement was missing.

### Motivation

Round 3 and Round 4 alignment reviews across the three-layer enforcement program (A: surface area, B: call invariants, C: runtime parity) flagged that Layer A's changes constitute a new enforcement subsystem spanning five artifacts (JSON registry, bash scanner, Rust scanner, hook configuration, CI job). This subsystem deserves a first-class decision record so future sessions do not treat any of the five artifacts as local-only plumbing that can be edited in isolation. In particular:

- The JSON registry must be the only source of canonical-operation truth. Any duplication (hand-maintained per-bridge arrays, separate exemption lists) re-introduces the drift this ADR eliminates.
- The two scanners (Rust `syn`, bash `awk`) must produce identical decisions on the same bridge source. The fixture tests in `scripts/tests/bridge-symmetry/` enforce that parity; weakening them re-opens the drift surface.
- The hook fires on every `Edit|Write|MultiEdit` tool call touching `crates/scp-ffi/`. Removing or loosening the hook matcher restores pre-ADR behavior where adversarial edits ship unchecked for many turns before CI runs.

## Decision

### 1. Single source of truth: `scripts/bridge-aliases.json`

One JSON file declares every canonical operation the bridges must expose, with per-bridge alias lists and explicit exemptions:

```json
{
  "schema_version": "1.0",
  "operations": [
    {
      "canonical": "identity_create",
      "category": "identity",
      "wasm_required": true,
      "pyo3":   ["py_identity_create"],
      "uniffi": ["identity_create"],
      "napi":   ["identity_create"],
      "wasm":   ["identity_create"]
    }
  ]
}
```

Fields:

- **`canonical`** — the stable operation name referenced by the SDK capability matrix and specs.
- **`category`** — grouping for reporting (identity, governance, messaging, …).
- **`wasm_required`** — `false` only for operations ADR-034 excludes from the WASM bridge (e.g., tokio multi-thread dependents). A `false` value is a documented exemption; the canonical operation still exists in the other three bridges.
- **`pyo3` / `uniffi` / `napi` / `wasm`** — alias lists. Multiple aliases are allowed because historical bridges (notably PyO3) use `py_`-prefixed names. Every alias must resolve to a real non-test `fn` in the corresponding bridge file, or the bridge must be declared exempt for that operation.

This file is consumed by:

- **Rust** via `include_str!("../../../../scripts/bridge-aliases.json")` + `serde_json::from_str` in `ffi_conformance.rs`. The test `aliases_json_is_in_sync_with_parity_operations` fails the build if the JSON drifts from the in-file `PARITY_OPERATIONS` ratchet.
- **Bash** via `jq` in `scripts/check-bridge-symmetry.sh`. The script enumerates operations, looks up each bridge file, and verifies at least one declared alias has a non-test `fn NAME(` definition.

### 2. AST-level parsing in both scanners

Substring scanning is replaced by real parser semantics on both sides:

- **Rust side (`ffi_conformance.rs`)** uses `syn = { version = "2", features = ["full", "visit"] }` to parse bridge source files into a syntax tree and walk function definitions. `#[cfg(test)]`-gated items are excluded via a `meta_is_test_gated(meta, under_not)` walker that handles `cfg(test)`, `cfg(any(test, …))`, `cfg(all(test, …))`, and `cfg(not(test))` correctly.
- **Bash side (`check-bridge-symmetry.sh`)** uses an awk state machine that tracks brace depth and mirrors the Rust walker's cfg semantics (`is_test_gated_cfg_segment`). The fixture tests in `scripts/tests/bridge-symmetry/fixtures/` (good-all-bridges, good-exempt-missing, bad-missing-napi, bad-alias-in-test-module-only, bad-alias-in-test-impl) exercise both scanners against identical inputs and assert identical verdicts.

`syn` adds ~8 seconds to a cold `cargo test -p scp-testing` compile. That cost is paid once per CI run and is acceptable in exchange for eliminating the substring-match false positive / false negative class.

### 3. Three enforcement surfaces

The same JSON registry drives enforcement at three surfaces:

| Surface | Mechanism | Timing |
|--------|-----------|--------|
| `cargo test -p scp-testing` | `ffi_conformance.rs` tests load JSON, parse bridges with `syn`, assert parity | Local (every developer run) + CI test job |
| CI `bridge-symmetry` job | `scripts/check-bridge-symmetry.sh` (jq + awk), plus fixture tests `scripts/tests/bridge-symmetry/run-tests.sh` | Every PR, on every push |
| Claude Code `PreToolUse` hook | `.claude/settings.json` fires `check-bridge-symmetry.sh --hook <paths>` on `Edit|Write|MultiEdit` matching `crates/scp-ffi/` | Pre-edit (blocks the edit before it is written) |

The hook blocks only on **regressions** (an alias present before the edit that the edit removes) so in-progress work can still add new functions before the sibling bridges catch up. Full surface-area parity is enforced by CI, not by the hook.

### 4. Enforcement-file hook

A second `PreToolUse` hook in `.claude/settings.json` protects the enforcement files themselves: `.claude/settings.json`, `scripts/check-bridge-symmetry.sh`, `scripts/bridge-aliases.json`. Edits to these paths (including via symlink, which is why `python3 os.path.realpath` resolution is required) are blocked by the hook with a message directing the author to raise a separate PR. This mirrors the existing CLAUDE.md enforcement-files policy and prevents an agent from silently weakening enforcement in the same PR that introduces a symmetry violation.

## Alternatives rejected

1. **Keep hand-maintained match arms.** The prior state. Rejected because silent drift across five artifacts is exactly the failure mode this ADR eliminates; no hook surface exists; exemptions are undocumented.
2. **Regenerate match arms from source via `build.rs`.** A build script reads JSON and emits `const PYO3_NAMES: &[&str] = &[...]`. Rejected because it adds a code-generation layer without removing the staleness risk — `build.rs` output still has to be kept in sync with the JSON, and the generated file becomes another artifact that drifts or is hand-edited under pressure. The direct `include_str!` + `serde_json::from_str` approach has one fewer moving part.
3. **Move enforcement entirely into Python (like Layer B's `check-call-invariants.py`).** Python has better parsing libraries than bash, and Layer B uses `tree-sitter-rust` in Python for call-ordering enforcement. Rejected for Layer A because the hook fires on every edit — a Python startup (~80–150 ms) would add perceptible latency to every tool call, while bash + `jq` + `awk` completes in under 20 ms on the observed workloads. Layer B's checks are per-PR, not per-edit, so Python's startup cost is amortized.
4. **Demote surface-area checks to CI only (no hook).** Rejected because adversarial coder agents can ship broken bridges across many edits before CI runs; the hook catches asymmetry at the first edit that introduces it. CI alone restores the pre-ADR adversary-friendly window.
5. **Single scanner (delete either the Rust `syn` scanner or the bash scanner).**
   - Deleting the Rust scanner removes `cargo test` enforcement, breaking local developer feedback loops.
   - Deleting the bash scanner removes the hook surface (Rust compilation is too slow for an edit-time hook).
   Both scanners are load-bearing. The fixture test suite in `scripts/tests/bridge-symmetry/` guarantees they produce identical verdicts.

## Consequences

### Positive

- Edit-time blocking of bridge asymmetry via the hook.
- A single JSON file is the source of truth; exemptions are auditable and documented.
- Both scanners parse at AST level, eliminating the substring-match false-positive / false-negative class.
- Fixture tests guarantee scanner parity — the bash and Rust scanners cannot diverge without a failing test.
- Adding a new operation requires exactly one edit: append an entry to `scripts/bridge-aliases.json`. The scanners pick it up automatically; CI fails the PR if any bridge is missing an alias.
- CI, local `cargo test`, and the edit-time hook all enforce the same invariant using the same registry.

### Negative

- `syn` becomes a dev-dep on `scp-testing` (~8 s cold compile). Acceptable because `scp-testing` is a test-only crate.
- The bash scanner must mirror `syn` semantics precisely. The fixture tests enforce this, but future changes to the Rust walker (e.g., new `cfg` forms) require parallel changes to the awk walker. The awk walker's limitations are documented in-file.
- One additional CI job (`bridge-symmetry`) is in the required-checks set for the merge gate. This adds approximately 30 seconds to CI wall-clock time.
- `jq` is a hard dependency for both the hook and the CI job. The CI workflow installs it explicitly (`apt-get install -y jq`). macOS developers already have `jq` via the project's `mise` toolchain or Homebrew.

## Enforcement invariants

- `scripts/bridge-aliases.json`, `scripts/check-bridge-symmetry.sh`, `scripts/tests/bridge-symmetry/**`, and `crates/scp-testing/tests/integration/ffi_conformance.rs` are named in CLAUDE.md's enforcement-files list. Weakening, removing, or adding an exemption to any of them requires explicit human approval via a separate PR. The `.claude/settings.json` enforcement-file hook blocks in-band edits.
- New canonical operations MUST be added to `scripts/bridge-aliases.json` in the same PR that adds them to any bridge. The CI `bridge-symmetry` job will fail otherwise.
- An operation is exempt from a bridge only by declaring `"<bridge>": []` or (for WASM specifically) `"wasm_required": false`. Exemptions must cite a spec reference (ADR-034 for WASM exclusions, or a spec section for others) in a PR comment or in the JSON entry's `category`.
- Both scanners MUST produce identical verdicts on the same source. The fixture tests under `scripts/tests/bridge-symmetry/fixtures/` are the enforcement mechanism; new scanner edge cases require a new fixture.

## Related

- **ADR-034** — WASM bridge re-implementation strategy. Defines which operations are legitimately absent from the WASM bridge; those operations carry `wasm_required: false` in `bridge-aliases.json`.
- **ADR-046** — Cross-bridge runtime parity harness (Layer C). Complements this ADR's surface-area enforcement with runtime equivalence: this ADR checks that the functions exist; ADR-046 checks that they produce equivalent behavior across bridges.
- **Layer B — `scripts/check-call-invariants.py`** (declarative call-precedence rules). Uses `tree-sitter-rust` to verify call-ordering invariants (e.g., "authentication MUST be checked before authorization"). Orthogonal to this ADR's surface-area scope.
- **Prior art — `scripts/check-cross-layer.sh`** — verifies every `pub fn` in `scp-runtime` has a matching FFI export. Narrower scope (one direction, one layer); this ADR extends the pattern to cross-bridge symmetry with the JSON registry and dual-scanner pattern.
- **Prior art — `scripts/check-sdk-coverage.py`** — verifies every FFI export has a matching SDK wrapper. Downstream of this ADR; once a canonical operation is enforced across all four bridges, SDK coverage closes the loop to the language SDKs.

## Acceptance criteria

1. `scripts/bridge-aliases.json` exists, contains at least `MIN_PARITY_OPERATIONS` (ratchet in `ffi_conformance.rs`) canonical operations, and validates against its schema.
2. `scripts/check-bridge-symmetry.sh` exits 0 on a clean tree, exits 1 in CI mode if any required bridge is missing an alias, and exits 2 in `--hook` mode on regressions.
3. `scripts/tests/bridge-symmetry/run-tests.sh` passes all five fixture scenarios (good-all-bridges, good-exempt-missing, bad-missing-napi, bad-alias-in-test-module-only, bad-alias-in-test-impl).
4. `cargo test -p scp-testing --test integration` runs `aliases_json_is_in_sync_with_parity_operations` and passes.
5. The CI workflow `.github/workflows/ci.yml` contains a `bridge-symmetry` job in the required-checks merge gate. Its comment cites ADR-047.
6. `.claude/settings.json` wires the `PreToolUse` hook on `Edit|Write|MultiEdit` with the `crates/scp-ffi/` path filter.
7. `.claude/settings.json` wires the enforcement-file protection hook against `.claude/settings.json`, `scripts/check-bridge-symmetry.sh`, and `scripts/bridge-aliases.json` (including via symlink, resolved with `os.path.realpath`).
8. CLAUDE.md's enforcement-files list is updated in this PR to add `check-bridge-symmetry.sh`, `bridge-aliases.json`, `check-call-invariants.py`, and `call-invariants-baseline.json`. The `.claude/settings.json` PreToolUse hook provides write-time protection in addition to the governance rule.
