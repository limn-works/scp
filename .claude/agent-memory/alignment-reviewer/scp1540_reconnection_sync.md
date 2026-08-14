---
name: scp1540-reconnection-sync
description: SCP-1540 checkpoint/equivocation sync-integration review — APPROVE; six-phase driver + three tiers + tier-(a)-only equivocation; compare_checkpoints deletion closes #1216
metadata:
  type: project
---

# SCP-1540 — Checkpoint generation + equivocation detection wired into sync/reconnection — APPROVE (2026-06-14)

Branch `feat/1540-checkpoint-equivocation-sync`, worktree `agent-a1d30b67d4e9aa5bf`, HEAD `281e399a2` (~10 commits, +3174/-409, 33 files).

**Why:** #1540 (P2 implementation-gap): checkpoint machinery (`generate_checkpoint`/`maybe_create_checkpoint`/`force_create_checkpoint`/`compare_checkpoints`) was fully built but NEVER called from any reconnection/sync/close path. This PR wires it.

**How to apply (verdict + the load-bearing facts):**

- **Six-phase protocol (§23.3) + three tiers (§23.1):** `RelayActorSyncDriver` in `crates/scp-ffi/common/src/reconnect.rs:198-410` implements all 6 `SyncPhaseDriver` phases. `reconnect_contexts` (reconnect.rs:701) runs Tier-1 via six-phase loop, Tiers 2/3 via SnapshotTransport/ResetTransport. Driver lives at FFI/SDK relay-client layer (not actor) because actor `ContextTransportProvider` is send-only + QUERY-since owned by TransportManager — restated in ADR-029 addendum (phase-6.md, additive, supersedes ADR-029 §2 AC 2).

- **Equivocation tier-(a) scoping (§9.9.3 / §23.7) — CORRECT.** `compare_remote_checkpoint` (queries_helpers.rs:724-847) keys equivocation STRICTLY on `Equal` event-count + different Merkle root, emits ONLY local `ContextEvent::EquivocationDetected` (tier a). PR adds NO signed `EquivocationAlert` MLS message, NO proof/conflicting_hashes/relay_url, NO equivocation_policy enforcement (tier b correctly omitted). The one `EquivocationAlert` literal (reconnect.rs:176) is an in-process report carrier (`SyncEvent::EquivocationDetected`) — evidence:None, zeroed roots, never signed/wired.

- **#1216 closure — bug-condition eliminated, but closing-RATIONALE is inaccurate.** On origin/main `compare_checkpoints` had ZERO prod callers (only its own def+tests in sync/mod.rs). Deleted + unified `ConsistencyCheckpoint` to re-export from scp-event-log. PR closes #1216. BUT: the deleted free fn returned `Option<EquivocationAlert>` and had NO `epoch==None⇒FullyCaughtUp` short-circuit; that condition actually lived in the epoch-reconciliation path (`hours_offline.rs reconcile_epoch:1231` → `(None,_)⇒Failed("epoch state unavailable")`), which was ALREADY correct on main. So close is valid on "fn deleted + condition unreachable" grounds, but commit msg mischaracterizes WHAT was deleted. Flagged as non-blocking provenance nit. LESSON: when a PR claims "deleting X closes bug #N", verify the bug condition actually lived in X — don't trust the commit message's mechanism.

- **ACs all met:** interval checkpoints (50 events/10min) via `create_checkpoint_if_due` wired in `finalize_send` (messaging_helpers.rs:1692); close checkpoint via `force_create_checkpoint_fields` (lifecycle_helpers.rs:525); tampered-log test `reconnect_detects_forged_divergent_checkpoint`; Consistent arm structural. Cosigned-checkpoint AC PRE-EXISTS in governance layer (`CosignedCheckpoint`, `validate_checkpoint_cosignatures`, governance_integration.rs AC-15) — orthogonal, not dropped. #1535 `Behind` seam (queries_helpers.rs:781-805) correctly left as documented named integration point (NOT a stub).

- **WASM exemption honest:** bridge-aliases.json + matrix document WASM has no scp-runtime/Supervisor/actor + no in-core relay QUERY (ADR-034); records constrained JS-driven alternative. Same precedent as context_subscribe/identity_create_with_custody.

- **Integration matrix FULL:** Rust core → PyO3/NAPI/UniFFI → 4 SDKs → pipeline assertion `b3_reconnect_drives_checkpoint_exchange` + capability matrix + bridge-aliases.

Reusable pattern: "deleting dead fn X closes bug #N" claims — independently verify (1) X truly had zero prod callers (git grep on origin/main, exclude self-file/tests), and (2) the bug CONDITION is unreachable everywhere on HEAD, separately from whether X is where the bug lived. The two can diverge.
