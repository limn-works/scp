# Architecture Reviewer Memory

Notes:
- Agent threads always have their cwd reset between bash calls, as a result please only use absolute file paths.
- In your final response always share relevant file names and code snippets. Any file paths you return in your response MUST be absolute. Do NOT use relative paths.
- For clear communication with the user the assistant MUST avoid using emojis.
- Do not use a colon before tool calls. Text like "Let me read the file:" followed by a read tool call should just be "Let me read the file." with a period.

## Project Patterns

### Type alias duplication is intentional
`ContextId = String` and `Ed25519Signature = Vec<u8>` are duplicated per-module (sync, event_log, bridge, discovery, etc.). This is an established pattern -- do not flag as an issue.

### GovernanceAction lacks PartialEq
`GovernanceAction` derives only `Debug, Clone, Serialize, Deserialize` -- no `PartialEq`. Code that compares governance actions must use pattern matching and field comparisons. See `sync/conflict_resolution.rs::actions_conflict()`.

### GovernanceModelConfig has PartialEq but not Eq
Contains `f64` field (`Majority::min_participation`), so only `PartialEq` is derived.

### Sync module structure
- `sync/mod.rs` -- shared types (OfflineTier, SyncError, CatchUpStatus, SyncOutcome), constants, tier classification
- `sync/hours_offline.rs` -- Tier 1 (< 4h): relay buffering, MLS catch-up, reorder buffer, ReconnectionCoordinator
- `sync/days_offline.rs` -- Tier 2 (4h-7d): ContextSnapshot, SnapshotDelta, DeltaSyncEngine trait, delta compute/apply
- `sync/weeks_offline.rs` -- Tier 3 (> 7d): OfflineAssessment, ReJoinPlan, ReJoinExecutor trait, StatePreservation, BilateralContextRecovery, MemberResetEvent
- `sync/conflict_resolution.rs` -- Conflict resolution: metadata LWW, governance Merkle-ordered, deadlock detection, context fork

### Known issue: dual ContextSnapshot
Both `days_offline::ContextSnapshot` (12 fields, full snapshot) and `conflict_resolution::ContextSnapshot` (5 fields, minimal fork snapshot) exist. Flagged in SCP-122/124 review. The conflict_resolution version should be renamed.

### async fn in trait is NOT object-safe
`DeltaSyncEngine` uses `#[allow(async_fn_in_trait)]` with `async fn`. This is NOT object-safe despite doc comments claiming otherwise. Needs `async-trait` or `trait_variant` for `dyn` dispatch.

### Cross-module EventType additions are the #1 completeness gap
Sync module stories (SCP-122, 123, 124, 127) each require EventType additions per ADR acceptance criteria. These are defined as structs in the sync module but the actual EventType enum in `event_log/mod.rs` must also be updated. Always check `event_log/mod.rs:EventType` when reviewing sync stories.

### ReJoinExecutor follows DeltaSyncEngine pattern
`weeks_offline::ReJoinExecutor` mirrors `days_offline::DeltaSyncEngine`: `#[allow(async_fn_in_trait)]`, `Send + Sync` bound, explicit doc comment about NOT being object-safe. Both use module-local error types rather than the parent SyncError.

### UniFFI-generated bindings collide with hand-written Swift wrappers (SCP-103)
Committing real UniFFI-generated ScpBindings.swift alongside hand-written placeholder wrappers causes "invalid redeclaration" build failures. Key divergences:
- Generated ScpError uses uppercase cases (.Identity) vs Swift convention (.identity)
- Generated Message uses `payload: Data` vs hand-written `content: Data`
- Generated TransportStatus is a struct, hand-written is an enum
- Generated ContextState has 5 states (creating/active/closing/closed/expired), hand-written has 2
- Generated UcanToken is a class (object handle with raw pointer), hand-written is a struct
Any story that replaces placeholder bindings with real generated ones MUST reconcile or remove hand-written types in the same commit. See `.docs/lessons/swift/uniffi-generated-type-conflicts.md`.

### CI and local build scripts must stay synchronized for Swift
build-xcframework.sh renames `scp_ffi_uniffi.swift` to `ScpBindings.swift` and copies to `Sources/SCP/Internal/`. CI workflow writes to `Sources/SCP/` without renaming. CI module map uses `scpFFI.h` (lowercase), build script uses `ScpFFI.h` (uppercase). Always verify CI mirrors local build layout when reviewing Swift build stories.

## ADR Reference Quick Map
- ADR-029: Offline/Sync Strategy -- phase-6.md line 1227+
- ADR-030: Event Log Pruning -- phase-6.md line 1698+
- ADR-031: Multi-Admin Governance -- phase-6.md line 2273+
- Conflict resolution spec: ADR-029 section 5 (line 1409+) and ADR-031 section 7 (line 2614+)
- Required EventType additions: MemberReset, QueueDrained (ADR-029 criterion 7), GovernanceConflictDetected, GovernanceConflictResolved (ADR-031 section 7)
