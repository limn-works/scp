---
name: changerole-orchestration-1877-slice1
description: API review of the #1877 ChangeRole shared-orchestration trait seam (ContextStateView/ContextStateMut/orchestrate_change_role) — APPROVED with one LOW finding
metadata:
  type: project
---

Reviewed branch `feat/changerole-shared-orchestration` (HEAD b800910c7), first #1877 convergence slice. New INTERNAL cross-crate trait seam in scp-protocol: `context::orchestration::{ContextStateView, ContextStateMut, orchestrate_change_role<S: ContextStateMut>}`. Hosts ChangeRole protocol logic once; native (`NativeChangeRoleState` in scp-runtime governance_helpers.rs) and WASM (`WasmChangeRoleState` in scp-ffi/wasm/manager.rs) implement the trait. Goal: kill native/WASM transcription drift that false-positives §9.9.3 cross-platform equivocation.

Verdict: APPROVED. Design is sound — this is the textbook "host logic once, adapt per-bridge state" shape.

**Why:** The seam is genuinely well-built; over-flagging it would be wrong.
**How to apply:** When the future `HardActionContext` generalization (AddMember/RemoveMember family) comes through for review, reuse these findings as the baseline.

Findings:
- LOW (only real one): `ContextStateView::event_count()` is dead trait surface. `orchestrate_change_role` never calls it; the ONLY caller is the orchestration's own mock unit test. Conformance test + all bridge parity use the FREE fn `scp_event_log::tree::event_count`, not the trait method. Its doc falsely claims "callers that assert leaf-count parity across bridges" use it — none do. Fix: drop it (ContextStateView shrinks to is_active+has_member), or doc it honestly as a HardActionContext seed.
- Observation: actor_did/did are adjacent bare &str DIDs → transposition risk (wrong leaf actor, provenance corruption not crash). Acceptable for 2-caller internal seam; doc disambiguates; both call sites correct. If newtypes ever added, do it at the HardActionContext generalization, not retrofit now.

Positives worth carrying forward:
- `type Error` + error-constructor methods (member_not_found_error/inactive_error) is the RIGHT shape: each bridge owns its Error (native ContextError, WASM ScpWasmError + CTX_2013/CTX_2015 codes) while orchestration owns WHEN to reject. Shared enum or Into-conversion would be worse. Don't suggest "simpler" shared-error alternatives.
- persist_fail_closed is a no-op on BOTH real bridges: WASM has no store; native's real fail-closed persist rides INSIDE assign_role's commit_class_s_keep. Contract = "persistence completes no later than persist_fail_closed returns." HardActionContext author must preserve this or an action that doesn't self-persist in its verb-hook could append leaf ahead of durable commit.
- Empty-payload RoleAssigned leaf (EventPayload::default(), data==[]) is the cross-bridge convergence invariant; role rides only the buffer event, never the durable leaf. Timestamp = signed proposal created_at, never local clock (§7.3.1/§9.9.3).
- Generalization fit is clean — nothing commits against HardActionContext; assign_role is the correct per-action axis of variation. sync/MLS-free assumption (mod.rs:16-18) is the thing to revisit if membership family brings MLS/async.
