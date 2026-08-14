---
name: adr049-pr6-prepC-floors-merge
description: API review of ADR-049 PR-6 Prep C — Supervisor floor-registry validating merge widened bool→MergePolicy; APPROVED with one transient provider-twin divergence
metadata:
  type: project
---

ADR-049 PR-6 Prep C (`feat/adr049-pr6-prepC-registry-authoritative-merge`, commit 6df8ec56f). Verdict: APPROVED with observations. All surface is `pub(in crate::context)` — runtime-internal, NOT SDK/FFI.

What changed: `Supervisor::validate_and_merge_epoch_floors` + `_recv_sequence_floors` (and their `SupervisorHandle` forwards) widened `trusted_local: bool` → `policy: MergePolicy` (reused from `scp_protocol::crypto::sender_keys`), implemented the real §23.17.2 fail-closed two-pass merge, added `remove_member_floors(ctx, did)` + fan-out.

**Why:** Understand this slice's design so the later "atomic read-authority switch" review can check the swap is clean.

**How to apply:**
- bool→enum is CORRECT (enums-over-booleans); reusing the scp-protocol `MergePolicy` (vs a runtime-local twin) is the right coherence choice — same §23.17.2 semantics back both the pure `SenderKeyStore::merge_incoming_epochs` and this registry.
- KEY divergence to watch: three homes for this merge. Pure `merge_incoming_epochs` = `MergePolicy` + `SenderKeyError`; provider twin `crypto/mls/provider.rs:2763/2946` = STILL `trusted_local: bool` + `ContextError` (aggregate error); registry twin (this PR) = `MergePolicy` + `FloorAdvanceError` (single first-failure). Registry is now AHEAD of the provider in shape. The bool→MergePolicy mapping is now DUPLICATED: once inside the provider, once in `lifecycle_helpers::restore_crypto_state_with_floor_guard` (`follower_seed_policy`). Same caller calls both twins with different param shapes. Transitional (provider slated for deletion at the swap), documented, reconciled via `From<FloorAdvanceError> for ContextError`. Do NOT push widening the provider — that's atomic-core scope.
- `remove_member_floors` vs `remove_context_floors`: parallel naming, extra `did` arg disambiguates, misuse-resistant. `did: &str` is stringly-typed but CONSISTENT with all sibling advance methods.
- recv merge has a doc-only call-ordering precondition (must run epoch merge first so `sender_epochs[did]` is populated for the ceiling); fail-open direction is safe (absent → ceiling 0+MAX_EPOCH_ADVANCE, conservative). Caller order is correct. Typestate here would be over-engineering.
- `max_advance` is a param on the epoch fn but hardcoded `MAX_EPOCH_ADVANCE` in the recv fn; always called with the constant everywhere. Mirrored across all homes, so coherent though slightly surprising.
- Docs are honest: "authoritative-CAPABLE" (merge logic complete, read-authority NOT flipped, follower-seed Result log-and-dropped). No overclaiming.
