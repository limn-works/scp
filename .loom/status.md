# Loom Status

## Iteration: 2026-02-28T08:30Z

### Failing Tests
None. All Rust workspace tests pass (2,370 scp-core + 40 economy_integration + 215 phase2_integration + 11 phase5_integration + 158 scp-transport + 64 scp-mcp + 45 scp-platform + 31 scp-media + 19 scp-ffi-uniffi + 11 scp-node + 4 scp-ffi-napi + 3 scp-testing + 1 scp-ffi-wasm + 11 doctests). Swift tests: 115 tests in 8 suites, all passing (`swift test` after `build-xcframework.sh --dev`).

### Uncommitted Changes
None. Working tree is clean.

### Fixed This Iteration
- **Module map mismatch**: `build-xcframework.sh` generated `framework module ScpFFI` but ScpBindings.swift expects `module scpFFI`. Fixed by using uniffi-bindgen's generated modulemap.
- **C keyword clash**: UniFFI-exported `PushProvider::register()` generated a C struct field named `register` (C storage class keyword). Renamed to `register_push()` in FFI trait.
- **Type conflicts**: Hand-written Swift wrapper types duplicated UniFFI-generated types (ScpError, Identity, UcanToken, ContextState, Message, Event, etc.). Resolved by removing duplicates and using UniFFI types directly.

### Tests Added / Updated
- `crates/scp-core/tests/phase5_integration.rs` — 11 Rust integration tests covering all four Phase 5 ADRs (SCP-104)
- 8 Swift test suites updated to match UniFFI type shapes (115 tests total)

### Tool-Gated Stories
None. LOOM_CAPABILITIES is unset; no stories were tool-gated.

### Subagent Outcomes
| Story | Result | Summary |
|-------|--------|---------|
| SCP-104 (Rust) | PASS | 11 integration tests in `phase5_integration.rs` covering bridge (ADR-023), media (ADR-024), platform (ADR-025), cross-ADR integration. |
| SCP-104 (Swift) | PASS | Resolved UniFFI type conflicts across 21 Swift files. Fixed module map and C keyword clash. `swift build` + `swift test` (115/115) pass. |

### Review Outcomes
| Story | Reviewer | Actions | Learnings |
|-------|----------|---------|-----------|
| SCP-104 | (pending) | — | — |

### Stories Completed This Iteration
- SCP-104 (gate-5, P1, critical): Phase 5 end-to-end integration test — all 9 ACs satisfied

### Commits
- `c098ac8` test(integration): add Phase 5 end-to-end integration test (SCP-104)
- `1702956` chore(prd): mark SCP-104 done, gate-5 complete
- `9759425` fix(swift): resolve UniFFI type conflicts for swift build/test (SCP-104) [merged]
- `d93beaf` fix(swift): fix module map and C keyword clash for swift build (SCP-104)

### Next Iteration Priorities
- **SCP-163**: Complete PyO3 bridge wiring for tools, UCAN, event log, MCP (gate-3, P1, major) — no blockers, pure Rust/Python work.

Still actionable (require Android hardware/SDK):
- SCP-110: Android Keystore KeyCustody (gate-6, P2)
- SCP-111: Play Integrity DeviceAttestation (gate-6, P2)
- SCP-112: FCM PushProvider (gate-6, P2)

Blocked downstream:
- SCP-113, SCP-114: blocked by SCP-110
- SCP-115-120: blocked by SCP-110/115 chain

### Notes
- gate-5 is now complete (all 21 stories done). SCP-104 was the capstone.
- Total test count: 2,982 Rust tests + 115 Swift tests, 0 failures.
- 12 stories remain. SCP-163 is high-priority and actionable. Android stories (SCP-110-120) require Android SDK/NDK.
- Lesson: UniFFI callback interface method names must avoid C keywords (`register`, `auto`, `volatile`, etc.). Documented for future reference.
