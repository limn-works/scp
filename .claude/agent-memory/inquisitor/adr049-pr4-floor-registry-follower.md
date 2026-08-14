---
name: adr049-pr4-floor-registry-follower
description: ADR-049 PR-4 (supervisor floor registry) verified CODE-sound as a write-only follower; the load-bearing premise PR-6 will flip
metadata:
  type: project
---

ADR-049 PR-4 (commit 26a5820dd, "Supervisor-owned floor registry — non-authoritative follower") was CODE-verified sound against its reviewed plan (adr049-pr4-floor-registry-REGROUNDED.md).

**Why (the load-bearing premise):** The registry is WRITE-ONLY in PR-4. Nothing reads `Supervisor.floors` for enforce/capture/merge. That is what makes the cryptographer's D1 (Inv-2 bypass) / D2 (rollback window) INAPPLICABLE — merge-home and enforcement-home both stay on `MlsCryptoProvider` (`recv_sequence_tracker` + `SenderKeyStore.epochs`). Verified: every `.floors` access lives in `context/supervisor/floors.rs` (registry impl + tests) plus one comment in `handle.rs`; zero reads in provider/messaging/lifecycle/governance enforcement paths.

**How to apply (PR-6 review):** PR-6 flips read-authority ONTO the registry and deletes the provider mirrors. The moment `check_and_advance_*`'s RESULT is enforced, three things become security-load-bearing that are only liveness today:
- the single-writer gate→key-insert co-serialization (PR-4 comment says security is the structural single-`entry()` guard, single-writer is liveness-only — re-check whether PR-6 needs a STRUCTURAL guard, not the code comment);
- the follower `Err` swallow (non-fatal log-and-drop in PR-4) must flip to FAIL-CLOSED;
- `OpenedEnvelope.receive_floor` (added in PR-4, populated from the just-advanced `(epoch,sequence)` inside `open()`) — verify PR-6 still does NOT read it for enforcement beyond the intended path.
Read-authority switch CANNOT split from mirror-delete + enforce-move or D1/D2 return. Confirm the PR-6 unit is atomic.

**Coverage note (non-issue, pre-checked):** plan §5 cited set_checked sites provider.rs:1657 AND :1715 as remote-epoch mirror seams. :1657 is inside `process_incoming_sender_key` (covered by the live seam in `decrypt_and_dispatch` Management arm). :1715 is inside `store_member_sender_key`, which has NO production runtime caller (only test/fullstack harness) — so production remote-epoch coverage is complete, not a gap.

Related: [[MEMORY]] operating reminders.
