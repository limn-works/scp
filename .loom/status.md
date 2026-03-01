# Loom Status

## Iteration: 5 (2026-03-01)

### Result: SUCCESS

All 5 dispatched stories completed successfully. Tests green. Review found and fixed 1 bug (ScpViewModel.onCleared scope). All code committed.

### Commits

| Commit | Story | Description |
|--------|-------|-------------|
| `668a5e6` | — | chore: update Cargo.lock for iteration 4 dependency additions |
| `35991ea` | SCP-114 | feat(platform): create Android platform module root and re-exports |
| `e220e49` | SCP-116 | feat(kotlin): implement Flow/Channel streaming layer |
| `2548f6c` | SCP-117 | feat(kotlin): implement Android lifecycle-aware resource management |
| `45e97a9` | SCP-119 | feat(kotlin): configure Maven Central publishing |
| `622e26a` | SCP-221 | feat(swift): wire SDK wrapper functions to UniFFI bridge |
| `a5830c7` | — | chore(prd): mark SCP-114, SCP-116, SCP-117, SCP-119, SCP-221 done |
| `71f15e9` | SCP-117 | fix(kotlin): use dedicated cleanup scope in ScpViewModel.onCleared |
| `2d58fa3` | — | docs: add review learnings for SCP-116, SCP-221 |

### Failing Tests
None. Full workspace compiles and tests pass (`cargo test --workspace --exclude scp-ffi`).

### Uncommitted Changes
None.

### Fixed This Iteration
- SCP-117: ScpViewModel.onCleared() was launching cleanup on viewModelScope which is already cancelled — switched to dedicated CoroutineScope with runBlocking (commit `71f15e9`)

### Tests Added / Updated
- `bindings/kotlin/scp-sdk-kotlin/src/test/kotlin/com/limn/scp/stream/StreamsTest.kt` — 22 tests: cold streams, hot streams, ColdMessageFlow, pagination
- `bindings/kotlin/scp-sdk-kotlin-android/src/test/kotlin/com/limn/scp/android/ContextLifecycleTest.kt` — 5 tests: lifecycle flow behavior
- `bindings/kotlin/scp-sdk-kotlin-android/src/test/kotlin/com/limn/scp/android/ScpViewModelTest.kt` — 6 tests: ViewModel cleanup
- `bindings/swift/Tests/SCPTests/ToolsTests.swift` — 3 async roundtrip tests
- `bindings/swift/Tests/SCPTests/UcanTests.swift` — 6 async roundtrip tests
- `bindings/swift/Tests/SCPTests/TransportTests.swift` — 2 async roundtrip tests
- `bindings/swift/Tests/SCPTests/EventLogTests.swift` — 3 async roundtrip tests
- `bindings/swift/Tests/SCPTests/McpTests.swift` — 4 async roundtrip tests
- `bindings/swift/Tests/SCPTests/TrustTests.swift` — 2 async roundtrip tests

### Tool-Gated Stories
None.

### Subagent Outcomes

| Story | Result | Summary |
|-------|--------|---------|
| SCP-114 (Android platform module) | SUCCESS | Rust android/ module root with cfg gate, re-exports, doc modules. Kotlin PlatformAdapter factory. |
| SCP-116 (Kotlin streaming) | SUCCESS | ColdStreamFactory, HotStreamFactory, ColdMessageFlow. Fixes SCP-115 trySend/awaitClose/double-buffer issues. 22 tests. |
| SCP-117 (Android lifecycle) | SUCCESS | ContextLifecycle.kt (asLifecycleFlow extension), ScpViewModel.kt (auto-cleanup). 11 tests. |
| SCP-119 (Maven Central) | SUCCESS | maven-publish + signing plugins for both modules. Sonatype OSSRH repos. detekt.yml updates. |
| SCP-221 (Swift SDK wiring) | SUCCESS | All 6 Swift wrapper modules wired via injectable bridge closures. 18 async tests. Third attempt succeeded. |

### Review Outcomes

**SCP-116 (Kotlin streaming):**
- Learning: messageHistoryPages/eventLogPages share same FFI call (documented in CLAUDE.md)
- Learning: runBlocking in HotStreamFactory factory methods (documented in CLAUDE.md)
- Learning: Hot stream cleanup is explicit, not scope-linked (lesson file)

**SCP-117 (Android lifecycle):**
- ACTION FIXED: ScpViewModel.onCleared() used viewModelScope (already cancelled). Fixed with dedicated cleanupScope + runBlocking (commit `71f15e9`)
- Learning: viewModelScope cancelled before onCleared runs (lesson file)

**SCP-221 (Swift SDK wiring):**
- Learning: ContextBridge type aliases must match ScpBindings signatures (lesson file updated)
- Learning: noPointer constructors are test-only, never production (lesson file updated)
- Learning: Legacy UCAN wrappers manufacture fake handles, always fail in production (lesson file updated)

### Cumulative Progress (Iterations 1-5)
**Done:** SCP-092, SCP-114, SCP-116, SCP-117, SCP-119, SCP-164, SCP-210, SCP-211, SCP-212, SCP-213, SCP-216, SCP-217, SCP-218, SCP-219, SCP-221, SCP-223, SCP-227
**In-progress:** SCP-214 (9/17 criteria)
**Blocked:** SCP-038 (by SCP-214)

### Remaining Stories
- **SCP-118** (Jetpack Compose state holders) — now unblocked (SCP-116, SCP-117 done)
- **SCP-120** (Kotlin SDK conformance tests) — now unblocked

### Next Iteration Recommendations
1. **SCP-118** (Compose state holders) — unblocked, builds on SCP-116/117
2. **SCP-120** (Conformance tests) — unblocked, exercises full Kotlin SDK
3. **SCP-214** remaining criteria — UniFFI callback interface, NAPI/WASM routing
