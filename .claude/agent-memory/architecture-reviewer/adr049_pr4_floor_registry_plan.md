---
name: adr049-pr4-floor-registry-plan
description: ADR-049 PR-4 Supervisor-owned floor registry (non-authoritative follower) PLAN review vs origin/main 6e7cd3066 — APPROVED w/ 1 required change (recv-seq mirror-forward value acquisition)
metadata:
  type: project
---

PR-4 = Supervisor.floors registry as NON-AUTHORITATIVE FOLLOWER (cryptographer-blessed corrected scope). Reviewed the REGROUNDED plan (`~/.claude/plans/adr049-pr4-floor-registry-REGROUNDED.md`, supersedes `-plan.md`) as a PLAN (no code). All line refs verified vs origin/main = 6e7cd3066 (local tree 1620de983 is a divergent *(ceiling) branch — IGNORE).

**Why:** first step of A1/A6 crypto-by-move; Class-M per-sender floors can't live in PerContextState (die on actor unwind → reopen §23.17.4 replay), must move to Arc<Supervisor>. PR-4 writes-only; PR-6 = atomic read-authority switch + mirror-delete + enforce-move; PR-7+ = key move.

**How to apply (verified sound):**
- Registry placement: `floors: DashMap<[u8;32], ContextFloors>` on Supervisor (:1172), init in new (:1616) next to crash_windows (:1240 — real DashMap precedent, entry() mutation at 4172/4268). Decision-12 allow-lists DashMap as read primitive (ADR-049:282). Entry-scoped mutation correctly does NOT take write_lock (Decision-2 write_lock guards multi-field ArcSwap, ADR-049:49). Class-M-survives-unwind sound (deps.rs:137-139 Decision-9 note). Bundling sender_epochs+recv_sequence into one ContextFloors = defensible locality (recv overshoot ceiling reads epoch floor → shared entry-guard).
- Handle invariant (Inv-3, runtime CLAUDE.md:99): 6 accessors take &[u8;32], forward to supervisor, return NO ContextActorHandle. CORRECT token choice: per-context &[u8;32] is the "registry fan-out" category, which handle.rs:61 AXIS comment EXPLICITLY exempts from the per-identity &OwnedIdentityDid rule (that rule is for caller-isolation per-identity ops). `lookup` (:601) stays the sole sanctioned ContextActorHandle yield.
- Seams verified: create seed @ provider.rs:2586 (self.contexts.insert), restore seed additive-post-merge @ lifecycle_helpers.rs:1734 (do NOT rewire deps.crypto.export_*/validate_and_merge_* :1744/1750/1767/1784 — stay provider-authoritative). Mirror-forward via deps.supervisor (deps.rs:152) from handlers respects actor→SupervisorHandle boundary.
- Enforcement discipline sound: pipeline_wiring.rs:1051 §23.17 + provider suites (:4217-4727) stay green, ADD-only. check-handle-affinity.sh exists. No FFI/SDK surface; SnapshotFloorRegression already bridge-mapped. NOT DOA.

**THE ONE REQUIRED CHANGE (seam #3 completeness gap):** recv-seq mirror-forward @ messaging_helpers.rs:2905 has NO access to the `next:(u64,u64)` it must pass to check_and_advance_recv_sequence. `open()` (provider.rs:1970) advances recv_sequence_tracker INTERNALLY (:2108) but returns `OpenResult::Application(OpenedEnvelope{inner, sender_did})` — surfaces sender_did but NOT (epoch,sequence). Plan §5 names the seam as if the value is in hand; it isn't. Naive fix = re-export via deps.crypto.export_recv_sequence_floors(ctx) per message = O(senders) HashMap clone on deliver_incoming, which is a Decision-14-GATED operation (<15%, ADR-049:398). Plan must specify the acquisition mechanism + account for its perf cost. NOTE: sender-epoch seams (set_checked :1657/:1715, rotate_sender_key :1463) do NOT have this gap — epoch is a direct arg in scope. Gap is isolated to the recv twin.

VERDICT: architecturally sound; APPROVED once the recv-seq mirror-forward value-acquisition mechanism is specified.
