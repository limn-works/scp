---
name: adr049-pr6-read-authority
description: ADR-049 PR-6 plan review — floor read-authority flip provider→supervisor registry; dual ContextCryptoState structs; dissolution sequence
metadata:
  type: project
---

ADR-049 PR-6 = atomic read-authority switch: the Supervisor floor registry (`supervisor/floors.rs`) becomes the authoritative home for sender-epoch + recv-sequence floors; the provider mirror is deleted. Grounded on origin/main 5d8074734 (PR-4 #2109). Plan file: `/Users/alec/.claude/plans/adr049-pr6-read-authority-plan.md`.

**Why:** ADR-049 Decision 9 — Class-M epoch/replay floors must outlive actor-task unwind, so they move onto a supervisor-owned registry. Documented dissolution sequence (deps.rs:124 ActorDeps doc): PR-6 moves FLOORS to supervisor registry; PR-7 moves KEYS onto `ContextCryptoState` inside `PerContextState`.

**How to apply (durable facts for future ADR-049 reviews):**
- TWO structs named `ContextCryptoState`: (1) `crypto/mls/provider.rs:269` — legacy provider state, PR-6 deletes its `recv_sequence_tracker`; (2) `context/actor/state.rs:470` — actor-shape state (has its OWN `recv_sequence_tracker` + `sender_key_store` + `sender_key_epoch`), the PR-7 target. On main the state.rs:470 fields are DORMANT SCAFFOLD (only Default/Debug/tests touch them) — not a live second home, so PR-6's "single home" claim holds. After PR-6, state.rs:470 recv_sequence_tracker doc is stale (still claims it hosts the deliver-path recv-floor read via `open`) — PR-7 must reconcile.
- `decrypt_and_dispatch` (messaging_helpers.rs:2915) is the correct authoritative gate seam: holds BOTH `deps.crypto` + `deps.supervisor`; already calls `check_and_advance_recv_sequence` (~2943) + `check_and_advance_sender_epoch` (~2978) as non-fatal followers. Provider stays Supervisor-free (returns (key,epoch), never calls supervisor) — decoupling preserved.
- `ActorDeps` (deps.rs:124) carries BOTH `crypto: Arc<MlsCryptoProvider>` AND `supervisor: SupervisorHandle`. So all ~14 production `deps.crypto.export_crypto_state` callers can trivially read pass-through floors from `deps.supervisor.export_*`. builder.rs:1223/1230 + supervisor.rs:18280 are TESTS using a raw provider (no supervisor) — they pass literal/empty floors, not a handle.
- Provider validate_and_merge_recv_sequence_floors at provider.rs:~2959 reads recv_sequence_tracker.clone() — inside a twin method PR-6 deletes wholesale (not a missed reader).

**My verdict:** architecturally sound as one atomic PR. Key refinement: prep items (a) ReceiveFloor newtype, (b) impl From<FloorAdvanceError> for ContextError, (c) Supervisor::remove_member_floors definition+handle, (d) export_crypto_state pass-through-param no-op refactor (callers STILL source provider) are ALL safely splittable as prior prep PRs — none flips read-authority or the restore sink. True irreducible atomic core = flip@seams + mirror-delete + restore-sink relocation (§1E2) + registry-authoritative merge. This shrinks the hard-to-review diff ~40% without weakening the D1/D2 guarantee.
