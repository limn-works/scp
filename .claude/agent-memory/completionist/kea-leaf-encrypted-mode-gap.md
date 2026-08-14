---
name: kea-leaf-encrypted-mode-gap
description: KeyEpochAdvance event-log leaf is emitted broadcast-only despite spec §5.14.10 mandating both modes; encrypted sender-key rotations emit no leaf
metadata:
  type: project
---

Spec `.docs/specs/05-contexts.md:1591` (§5.14.10) declares `KeyEpochAdvance { sender_did, epoch }` "shared across both Encrypted and Broadcast modes."

**Fact:** As of PR #2218 (`fix/rotate-all-author-keys-epoch-advance`), ALL three `EventType::KeyEpochAdvance` emission sites are broadcast-only:
- `broadcast_helpers.rs:276` (block_broadcast_subscriber)
- `broadcast_helpers.rs:736` (unsubscribe_broadcast)
- `governance_helpers.rs:872` (shared helper `emit_key_epoch_advance_best_effort`, used by execute_revoke ban + execute_rotate_content_keys broadcast)

Encrypted-mode `PerContextState::rotate_sender_key` sites bump `local_sender_key_epoch()` but emit NO leaf: `governance_helpers.rs:1085` (execute_revoke H7 write-revoke), `governance_helpers.rs:2818` (MLS reset), `lifecycle_helpers.rs:415` (leave). This is an ADR-007 sender-key epoch advance that §5.14.10 says should log a KeyEpochAdvance.

**Why:** genuine spec↔code divergence, pre-existing (not introduced by #2218). PR #2218 round-1 flagged it and deferred as "pre-existing"; round-2 confirmed there is NO tracking mechanism (no code comment at the encrypted sites, no issue, no #[ignore] test). That untracked-deferral state is itself the finding per CLAUDE.md "no deferral."

**How to apply:** when reviewing any KEA / sender-key-epoch work, check whether the encrypted-mode gap got closed or at least tracked. Distinct from `RecoveryEpochAdvanced` (MLS *group*-epoch during §9.12 trust recovery, actor_did="system:recovery") — that's a different event type; don't conflate. The code is the side that diverged (spec is authority) — fix flows down, never edit §5.14.10 to say "broadcast only."
