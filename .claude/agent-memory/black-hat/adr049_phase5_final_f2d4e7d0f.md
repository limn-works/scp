---
name: adr049-phase5-final-f2d4e7d0f
description: ADR-049 Phase 5 FINAL adversarial review (actor-per-context/saga/crypto) @ origin/main f2d4e7d0f — findings by severity
metadata:
  type: project
---

# ADR-049 Phase 5 FINAL adversarial review @ f2d4e7d0f

Pinned worktree scp-wt-phase5. Actor-per-context + cross-context saga + watchdog/respawn.

## HIGH — #2060 epoch-desync gap STILL LIVE (reconnection-driven MLS Update un-gated)
- `crates/scp-ffi/common/src/reconnect.rs:439-472` distributor swallows `transport.send` Err to a warn, returns `Ok(true)` while local epoch already advanced. NO pending_commits, NO commit_fault, NO retry.
- `handlers/lifecycle.rs:681-729` handle_issue_mls_update_actor advances mls_epoch via class_c_view, returns bytes to out-of-layer caller.
- Contrast: execute_remove_member/rotate/leave/recovery_advance_epoch route through keep_broadcast_failure (fail-closed). execute_add_member + execute_reset_member are COALESCED best-effort (documented residual governance_helpers.rs:2472-2489).
- Weaponization: victim runs §9.12 PCS recovery on reconnect; a network blip OR hostile relay drops the single Update Commit; victim reports recovery success but group stays on compromised epoch → attacker with pre-recovery keys keeps read access. Zero backstop.

## HIGH (architectural) — relay-ACK-then-drop defeats commit_fault for ALL paths
- `try_broadcast_commit` (governance_helpers.rs:5450) treats `send_message -> Ok(())` = broadcast success, but Ok = RELAY ACCEPTED, not member-received. No member-level ACK/delivery receipt anywhere.
- A hostile relay that ACKs then drops → pending_commits never populated, commit_fault never set, retry never fires — even for the "fail-closed" Remove/Rotate/Recovery paths. commit_fault guards transport UNREACHABILITY, not relay CENSORSHIP.
- Victim kept on stale keys gets NO real-time signal (CommitBroadcastPending/Failed are committer-local, NOT in Merkle log). Only indirect defense = reconnect equivocation/checkpoint compare (reconnect.rs:395), at reconnect not real-time. No epoch-freshness challenge exists.

## MEDIUM — "actors cannot reach sibling actors" is review-enforced, NOT compile-time (doc overclaims)
- `ActorDeps.supervisor` is a `pub` field (deps.rs:152). `SupervisorHandle::lookup` returns a sibling `ContextActorHandle` and is `pub(in crate::context)` (handle.rs:598). Handlers live at crate::context::actor::handlers::* = DESCENDANTS of crate::context → they CAN name lookup.
- handle.rs:580-587 doc claims "handler bodies under actor/handlers/ ... cannot name this method" — FALSE as Rust visibility. handle.rs:705-713 claims returning ContextActorHandle "breaks the capability-reduction contract" but lookup already does and is handler-reachable.
- NOT a runtime exploit (attacker can't inject Rust into a handler); it's a defense-in-depth / doc-accuracy finding: the "compile-time property" / "mechanical contract" is actually convention+review. No current handler abuses lookup (only timer helpers in ttl_close/governance_helpers call it). find_shared_context/is_member are fully `pub` on the handle → handler-reachable cross-context membership enumeration (metadata; intended for trust recovery).
- Fix: gate lookup behind a marker only timer-helper modules hold, or move it off SupervisorHandle.

## MEDIUM — permanent per-context DoS on 3 panics/60s (sticky poison)
- supervisor.rs:747-751 CRASH_WINDOW_MS=60_000, CRASH_POISON_THRESHOLD=3. Sticky `poisoned` flag never cleared by eviction. Per crash_windows key. After poison, actor despawned + NOT respawned → ContextPoisoned. Only operator clear_poison / (re)create / process restart recovers.
- Attacker-induced-panic leg is WELL-DEFENDED (clippy deny unwrap/expect/panic/todo/unimplemented crate-wide + check-handler-no-panic.sh bans panic/assert family in handlers/). BUT denylist not positive guarantee: clippy::indexing_slicing + arithmetic_side_effects NOT enabled (restriction group) → a raw buf[i]/buf[a..b] on attacker bytes in actor-reachable code would panic uncaught. None found on primary untrusted paths (rmp_serde returns Result), but unaudited third-party panics (openmls) also on actor task. Any single reachable indexing panic on untrusted input = permanent DoS.
- Clock-absent misconfig (supervisor.rs:2260): now_ms=0 collapses sliding window into LIFETIME 3-crashes-ever budget.

## LOW / DEFENDED
- **Vector 1 (MAX_PENDING_COMMITS=50 queue-full → commit_fault DoS):** fail-closed by design. External attacker CANNOT force a victim's node to produce 50 failing commits (commits come from victim's own gov/lifecycle ops). Relay-Err path fail-closes only the COMMITTER after up to 1h (MAX_COMMIT_AGE_SECS=3600) or 20 retries. Recovery = operator acknowledge_commit_fault (governance_helpers.rs:356). Intended safety behavior.
- **Send-sequence reuse across crash (sequence.rs:12-20):** NOT a keystream-reuse break. Sender-layer AEAD nonce is RANDOM OsRng per invocation (provider.rs:137-138, sender_keys/encrypt.rs:58-59), not counter-derived. A crash-reused (epoch,sequence) AAD → honest receiver rejects duplicate seq (self-inflicted msg drop), no confidentiality loss.
- **OwnedIdentityDid capability:** unforgeable — pub(super) issue_for_actor + private did field + explicit non-derives (identity_capability.rs). Sound. reissue takes no DID param (clones held). Cannot fabricate cross-identity token.
- **Coalesced persist_snapshot is a NO-OP at HEAD (actor/mod.rs:519-532)** + class_c_view does no persist (class_s.rs:3200). BUT build_snapshot_from_state snapshots WHOLE state (Class-S + Class-C), and every commit_class_s_keep persists the whole thing synchronously (messaging_helpers.rs:2582). So Class-C piggybacks on next Class-S persist; only a pure-Class-C-only-then-crash loses those mutations (safe direction: commit_fault clear lost = stays closed). Robustness gap: the "≤50ms Class-C durability" the docs promise is fictional; safety rests entirely on correct Class-S/Class-C field classification (a mis-classified security field in Class-C = silently non-durable, no backstop).
- **Respawn:** no double-live-actor (watchdog join.await + bootstrap_spawn_lock serialize). No mailbox replay (in-flight cmds lost → ActorBusy). Snapshot restore only (no event-log replay). Active-state gate is behavioral fencing, not generation/crypto token.
- **At-least-once caller retry (no idempotency token on commands):** double-apply possible for non-idempotent cmds, BUT security-critical ones self-dedup (executed_proposals check governance_helpers.rs:5264; spending nonce consume; recv-sequence dedup). Residual only for genuinely non-idempotent non-security cmds.
- **crash_windows key namespacing:** hex context-id vs `kp::{did}` disjoint (`:` not hex). Soft spot: doc says keys are "hex or original id strings" — if any path ever keyed a raw attacker-chosen id starting `kp::` it aliases KP budget. None found. A CrashKey newtype would make it sound-by-construction.

## MEDIUM/HIGH — NeedsRepair strands CALLER escrow even when NO side committed (verified)
- Saga is CO-RESIDENT ONLY (cross-node deferred SCP-SAGA-13053, supervisor.rs:7269). Prepare/Commit are in-process oneshot messages, NOT wire envelopes → no capturable envelope for external forge/replay TODAY.
- Bug: commit_with_retry exhaustion sets `reached_needs_repair=true` UNCONDITIONALLY (supervisor.rs:7094-7096). drain_terminal_reservation (5816-5848) then HOLDS caller's Prepare-A escrow via hold_external_for_repair() on that flag alone — justification comment "operation may have partially committed — B executed and charged" (5810-5812).
- But the SAME exhaustion path handles the "Commit-B never landed, logs clean, no divergence marker" branch (7133-7139, divergence_marker_plan None). In that branch nothing executed/charged, yet escrow stays RESERVED indefinitely pending operator repair. Justification is FALSE here.
- Weaponization: a malicious/faulty TARGET exposing a tool over an APPROVED bidirectional interface whose Commit-B executor deterministically errors (commit_b_first_execute Err → SCP-SAGA-13057, output stashed only after success → all 3 retries fail) strands EVERY caller's escrow. Griefing/funds-lock DoS (caller opted into interface; not theft; operator-recoverable). Fix: gate hold on committed_b_tool_invoked_event_id.is_some() — void+refund as clean abort when no side committed. Escalate to §6.2.4 intent.

## Saga forge/replay + gating (co-resident model)
- Prepare has NO signature. Auth = non-crypto gates: FFI caller-principal binding (identity_registry_contains + is_member, tools.rs:1051), supervisor gate1 is_member (5613), gate2 has_established_tool_interface bidirectional consent (5637), Prepare-B checks (saga.rs:1066). UCAN rebind/confused-deputy defense (validate_ucan_rebind saga.rs:1127) is a NO-OP for ungated tools (ucan_proof_id=None) → zero crypto caller binding, relies on channel-auth.
- Replay dedup checked-before-mutation: Prepare-B nonce (16B, per-context-B, NOT bound to caller_did/tool, shared 10k cache, aggregate window not bounded by per-interface ceiling — saga.rs:120-134 concedes), Commit-B/Commit-A keyed by SagaId. Cross-target (A,B)→C blocked by target_context_id check (SCP-SAGA-13014, saga.rs:1089). Receipt binds pair but SagaId is NOT a signed field (bound transitively via tool_invoked_event_id).
- FORWARD OBLIGATION: cross-node transport MUST sign the Prepare envelope (saga.rs:1344-1357 flags asserted_timestamp_ms caller-asserted, exactly-once "holds by construction" only because no capturable wire envelope). Unshipped, not a live hole.
- check-saga-gating-granularity.sh = tripwire, NOT a granularity proof. Denylist (name×type product, evadable by obscure field name / scalar type e.g. Mutex<u128>, AtomicPtr) + positive presence checks P1-P6. Does NOT verify extractor returns correct {caller,target} set (under-reserving {caller} only passes P1-P5). P6 only greps 4 test NAMES exist — gut test bodies, still passes. Non-convergent-denylist class (CLAUDE.md warns); header honest it's a tripwire; real guarantee delegated to CI integration tests the gate can't run.
