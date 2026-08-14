---
name: adr049-pr7-crypto-move-efdaa6546
description: ADR-049 PR-7 atomic crypto-state move pass-2 artifact-faithfulness review at efdaa6546 — ALIGNED, 2 stale-comment findings
metadata:
  type: project
---

# ADR-049 PR-7 Atomic Crypto Move — pass-2 @ `efdaa6546` (2026-07-16) — ALIGNED (2 LOW stale-comment)

Branch `feat/adr049-pr7-atomic-crypto-move`, HEAD `efdaa6546` (2 commits on origin/main). PR moves MLS steady-state crypto (seal/open/sender-key/advance_epoch/rotate/remove_member/mls_encrypt_management/export/restore/drain) off `MlsCryptoProvider` onto actor-owned `PerContextState`; deletes provider copies; routes all prod callers through actor.

**Verified FAITHFUL (ADR/PRD ↔ code):**
- §15 `take_crypto_state` one-way "NOT sliceable": provider.rs:702 DashMap::remove(contexts)+taken_context_ids.insert; with_context returns "context state owned by actor" post-take. Prod callers lifecycle_helpers.rs:1779, outlets/invoke.rs:8319.
- §9 residual (send-gen rides Class-C, reuse_guard authenticity-only, #2149 tracked): heartbeat handler messaging.rs:1201/1210 reports Outcome::ok_mutated/err_mutated (matches "heartbeat seal now reports mutated" claim).
- §15 recovery seal respawn-then-actor-seal: supervisor.rs:4056 recovery_send_notification_direct — respawn_from_snapshot (acquires bootstrap_spawn_lock internally) then mailbox dispatch; non-64-hex fails closed "no MLS group"; NO retained provider seal.
- §15 Class-C receiver shape: ContextCryptoState::seal(&mut self,...,aad_sequence) state.rs:1666 (caller-reserved seq param, field-granular). H6 single reserve: one SequenceReservation::reserve on send path (messaging.rs:718).
- floors note: context/supervisor/floors.rs exists (ContextFloors); recv_sequence_tracker DORMANT retained (state.rs:471/2137).
- Enforcement repoint FAITHFUL not weakened: pipeline_wiring.rs adds STATE_SRC, repoints seal/open asserts to moved code, ADDS provider_steady_state_crypto_methods_are_deleted (11 methods) + adr049_pr7 answer wiring. check-deleted-primitives.sh untouched (generic ban list, not a seal scan).
- #2129 streaming-saga amendment: byte-identical main↔PR (rebase preserved), lives §6.2/§3a, orthogonal to PR-7 §9. "seal phase" there = ADR-061 receipt-seal, NOT MLS message-seal. No contradiction.
- New CLAUDE.md tenet (no dev/test stand-in masking prod): compliant — seed_identity_private_state_group is test-only (mod tests, recovery.rs:2115); recovery fails closed in prod; H4 dispose_secrets zeroizes whole crypto material.

**FINDINGS (2, LOW/informational — stale in-code annotations, neither trips CI, ADR/PRD themselves faithful):**
- F1 state.rs:1652-1655 `#[allow(dead_code, reason="production callers...wire in as the atomic-core seams land; until then...")]` — STALE; PR-7 wires all 5 methods (seal→messaging_helpers.rs:252, open→:3086, mls_encrypt_management→lifecycle_helpers.rs:539, handle_sender_key_request, dispose_secrets). allow likely now unnecessary — verify clippy before removing.
- F2 provider.rs:316-325 "# Scope — infrastructure only. Commit 12b.2a does NOT move any production state...no production site calls take_crypto_state yet; the legacy seal/open path continues to operate on contexts[ctx_id]. Commit 12b.2b is the first site..." — STALE; take_crypto_state now prod-called and legacy provider seal/open DELETED.

Pattern: interim-commit-ladder annotations ("commit N is first to wire", "until seams land") that the atomic-core PR itself supersedes are the phantom-provenance class to grep for in a final-atomic-move PR. Pass-1 was clean quadruple-zero; these 2 are what pass-2 surfaced.
