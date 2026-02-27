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
- `sync/conflict_resolution.rs` -- Conflict resolution: metadata LWW, governance Merkle-ordered, deadlock detection, context fork

### Known issue: dual ContextSnapshot
Both `days_offline::ContextSnapshot` (12 fields, full snapshot) and `conflict_resolution::ContextSnapshot` (5 fields, minimal fork snapshot) exist. Flagged in SCP-122/124 review. The conflict_resolution version should be renamed.

### async fn in trait is NOT object-safe
`DeltaSyncEngine` uses `#[allow(async_fn_in_trait)]` with `async fn`. This is NOT object-safe despite doc comments claiming otherwise. Needs `async-trait` or `trait_variant` for `dyn` dispatch.

## ADR Reference Quick Map
- ADR-029: Offline/Sync Strategy -- phase-6.md line 1227+
- ADR-030: Event Log Pruning -- phase-6.md line 1698+
- ADR-031: Multi-Admin Governance -- phase-6.md line 2273+
- Conflict resolution spec: ADR-029 section 5 (line 1409+) and ADR-031 section 7 (line 2614+)
- Required EventType additions: MemberReset, QueueDrained (ADR-029 criterion 7), GovernanceConflictDetected, GovernanceConflictResolved (ADR-031 section 7)
