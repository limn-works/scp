---
name: project-1540-equivocation-review-fixes
description: #1540 checkpoint-equivocation review remediation — 15 review items fixed on feat/1540-checkpoint-equivocation-sync; commits + CI state + harness limitation
metadata:
  type: project
---

Branch `feat/1540-checkpoint-equivocation-sync` (worktree agent-a1d30b67d4e9aa5bf). Full-review-roster remediation of the reconnection/equivocation driver. 3 commits on top of 281e399a2.

**Why:** review found a HIGH (reconnect drain destroyed application events) + 9 MED/RULE/COMPILE items + nits. Fix all 15, no push/PR.

**How to apply:** when resuming #1540 or touching equivocation/reconnection, these are the load-bearing decisions.

Commits:
- 8a5e4b4aa fix(sync): equivocation evidence, replay idempotency, targeted alert drain (protocol+runtime core)
- 412e1fa9f fix(sync): non-destructive alert drain, multi-epoch catch-up, zeroized key (reconnect.rs + bridges)
- dfd802dbf test(sync): runtime equivocation dispatch + targeted-drain + SDK docs + bindings

Key design decisions:
- `ContextEvent::EquivocationDetected` GAINED `local_merkle_root` + `remote_merkle_root` [u8;32] fields. Ripples to 3 bridge `convert_event` sites (pyo3/napi/uniffi render hex), state.rs/webhook `{..}` matches unaffected.
- `PerContextState.last_seen_remote_checkpoint: HashMap<DID,(u64,u64)>` — replay-idempotency (highest event_count,timestamp per remote sender; non-newer = no-op). Added to ALL PerContextState constructors (3 in lifecycle_helpers + actor/state.rs new_random) + BOTH exhaustive destructure tests in actor/state.rs.
- New `MessagingCommand::DrainEquivocationAlerts` + handler + `Supervisor::drain_equivocation_alerts` + `ReceiveBuffer::drain_equivocation_alerts` (partition, preserves order + dropped_since_last_consume). reconnect.rs `collect_equivocation_alerts` uses it INSTEAD of total drain_events (the HIGH bug).
- Multi-epoch catch-up: `epoch_reconciliation` loops feed, retries rejected set vs advanced epoch until a pass merges nothing (OpenMLS only accepts current-epoch Commits). Threaded Phase-1 `messages` through `SyncPhaseDriver::epoch_reconciliation`/`sender_key_reacquire` (signature change; only 2 impls: RelayActorSyncDriver + MockSyncDriver) — stops triple-refetch-from-0.
- `SigningKeyBytes` in reconnect.rs = `Zeroizing<[u8;32]>` (was bare); 3 bridge callers wrap. `new()` stays const (Zeroizing move is const-ok).
- Phase-6 queue_drain doc CORRECTED: drain is a no-op end-to-end (all bridges call reconnect_contexts_no_drain; offline-enqueue producer unwired). Don't claim drain happens.

CI gotchas hit:
- pre-commit hook runs FULL workspace clippy+fmt — every commit needs whole tree clean, not just staged files.
- too_many_lines (100): extracted `record_equivocation_if_fresh` + `verify_remote_checkpoint_authenticity` from compare_remote_checkpoint; `skeleton_dispatch_messaging` from skeleton_dispatch (mirrors per-domain helpers).
- `cargo test --workspace` WITHOUT custody features fails on FfiKeyCustody::InMemory (pre-existing feature-gating; CI uses the allow_in_memory_custody feature set).
- check-cross-layer.sh flags `send_checkpoint` (pre-existing pub(crate), UNCHANGED by me) → PR-body exemption `[cross-layer: pub-crate-visibility] send_checkpoint`.

HARNESS LIMITATION (item 9 test): FullStackNetwork CANNOT do joiner→creator MLS decryption. Bob (Welcome-joined) lacks Alice's wrapping key after join, so he can't HPKE-seal his sender key to Alice (distribute returns 0 blobs); and Alice can't self-decrypt (MLS "Cannot decrypt own messages"). So the runtime test drives the forged checkpoint through the ACTOR MAILBOX (`Supervisor::compare_remote_checkpoint`) not the full MLS-decrypt wire prefix. The decrypt prefix (deliver_incoming→deliver_checkpoint_message→compare_remote_checkpoint) is pinned structurally by pipeline_wiring::b3_merkle_proof_verification_wired. Test `runtime_equivocation_dispatch_and_targeted_drain` also proves drain preserves a DegradedMode event + replay emits no 2nd alert. NOTE: replay naturally becomes `Ahead` not `Divergent` because the 1st detection appends EquivocationDetected to the log, shifting local_count — the explicit last_seen guard is defense-in-depth for rapid replays before appends settle.

Swift: ScpBindings.swift lives at `Sources/SCP/Internal/ScpBindings.swift` (git-tracked); `build-xcframework.sh --dev` regenerates it + builds macOS-only xcframework (gitignored binary). `swift build` needs the xcframework present or fails with "binary target ScpFFI does not contain a binary artifact" (infra, not source).
Kotlin: project is `:scp-kt` (JVM, has `jar`) + `:scp-kt-android` (has `assembleRelease`); generated uniffi bindings at scp-kt/.../internal/uniffi/scp/scp.kt (gitignored, regen via :scp-kt:generateUniffiBindings).
