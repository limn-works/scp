---
name: project-saga-gating-id-form-aliasing
description: ADR-049 §3a per-participant-context-set saga gating uses a HashSet<String> whose members mix two non-equal context-id string forms — a cross-saga-type overlap aliasing risk to check on any saga-set work
metadata:
  type: project
---

ADR-049 §3a / spec §5.15.4 saga concurrency gating: `Supervisor::reserved_saga_contexts: Mutex<HashSet<String>>`, reserved atomically at `start_saga` via `try_reserve_context_set`, released by `SagaSetReservation` RAII drop on every terminal (incl. NeedsRepair) + panic-unwind. Set computed by `saga_participant_context_set(&SagaInput)` in `crates/scp-runtime/src/context/supervisor/supervisor.rs`.

**ID-FORM ALIASING GAP (latent overlap-miss):** the set mixes TWO non-equal string forms of the same context id:
- `StandingPairCreate` reserves `generate_standing_context_id()` = `format!("standing-{}", hex(digest))` — the `"standing-"`-PREFIXED display string.
- `CrossContextToolInvocation` / `BroadcastHostingHandshake` reserve `hex::encode(context_id)` — RAW 64-hex, no prefix.

Spec §5.15.8: "The 32-byte `derived_context_id`... is the raw digest before prefix and hex." Spec §6.2.4 + broadcast-hosting id-form clause: a standing-context host/target carries the RAW digest, "NOT the `standing-`-prefixed display string." So a hosting/cross-context saga that shares a standing context with a standing-pair-create saga reserves `hex(digest)` while the create saga reserves `"standing-"+hex(digest)` → strings never equal → **overlap NOT detected, two sagas on the same context run concurrently.** The CI gate (`check-saga-gating-granularity.sh`) is structural (presence of field/extractor/overlap-reject) and does NOT catch this. Fix: canonicalize the set to ONE id form (raw `hex(digest)`) before insert.

**Why the Mutex<HashSet> + #[allow(clippy::disallowed_types)] is JUSTIFIED, not a defect:** clippy.toml bans `std::sync::Mutex` because holding its guard across `.await` suspends the OS thread. Both critical sections (reserve: lock→contains→insert→drop; release-on-drop: lock→remove→drop) are purely synchronous, never hold across await. A `tokio::sync::Mutex` would be strictly worse here (async-aware lock on a non-await section). Workspace `await_holding_lock = "deny"` is the dynamic backstop. Single supervisor-wide Mutex is NOT a contention regression vs the old AtomicBool: held only on the cold saga reserve/release path, never on a per-command read path.

CI gate `scripts/check-saga-gating-granularity.sh` is durable: granularity-keyed (NEG = saga-named scalar guard types incl. renamed `Mutex<()>`/`Semaphore`; POS = field+extractor+overlap-reject presence), self-testing (3 fixtures a/b/c), in CLAUDE.md never-weaken list. FFI ordering clause is armed-but-vacuous until a `start_*_saga` export lands under crates/scp-ffi/ — correctly forward-defines the prerequisite without implementing FFI.
