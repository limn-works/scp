---
name: eventlog-phase2-notification-window-import
description: BLACK-301 — notification-window observed_at floor bypassed on untrusted import path (Phase-2 substrate swap, HEAD 4cad781e5)
metadata:
  type: project
---

# BLACK-301: notification-window floor bypass on import_context

**Why:** Commit 4cad781e5 added a non-backdatable floor `max(effective_at, observed_at + PERIOD)` to `PendingEconomicPolicyChange::is_effective` / `PendingCeilingModification::is_effective` to stop a proposer backdating `created_at` and collapsing the §19.3 24h / §5.3.2 ceiling notification window. The floor's security rests on `observed_at` being "THIS member's local clock at commit-processing time" — non-backdatable.

**The gap:** `observed_at` is a serialized field of `PendingEconomicPolicyChange`/`PendingCeilingModification` (state.rs:236/299, both Serialize/Deserialize). It rides inside `ContextSnapshot` (state.rs:538) which is exported `ExportScope::Full` VERBATIM (export_import.rs:845) and imported VERBATIM on the untrusted-peer path (lifecycle_helpers.rs:1788-1789). The import block is the explicit untrusted-snapshot sanitization boundary (C3/H10 wipe approved_proposals/budget/nonce, re-pin creation_timestamp to local now at 1756) — but `observed_at` slips through with the EXPORTER's value. Exporter is the attacker (threat model: "untrusted peer snapshot → Invariant 3", lines 1598/1613). Signature (validate_export_for_import) binds observed_at to exporter identity but does NOT make it honest.

**Chain:** malicious creator builds Full export with pending_economic_policy_change {malicious payee/fees, created_at backdated ≥PERIOD so effective_at≤now, observed_at backdated ≥PERIOD so floor≤now}, signs legitimately (is creator), victim imports → validate passes → first apply-tick `is_effective(now)`=true (both terms ≤ now) → new economic policy active with ZERO notification, violating §19.3. Same for ceiling (§5.3.2 silent capability lowering). apply at governance_helpers.rs:443/492.

**Contrast — restore path (lifecycle_helpers.rs:2232) is CORRECT:** `trusted_local` respawn of own snapshot must carry observed_at verbatim (re-pinning on crash-restart would let a crash-loop re-arm the window forever).

**Fix:** on the IMPORT path only, re-pin `observed_at` to `deps.clock.now_secs()` for any imported pending change (same treatment as creation_timestamp_secs at 1756). Or drop pending changes on import entirely (public scope already sets them None at export_import.rs:747-748).

**Severity HIGH.** Not covered by fix commit's tests (only in-process gate + preserve_order guard). Reachable via FFI export_context/import_context (scp-ffi/src/context.rs:2816/2967).

## Confirmed clean (merge-gating)
- Export merkle verification (validate_export_for_import steps 3-5): signed snapshot.event_log_merkle_root is sole authoritative binding, ct_eq vs recomputed RFC-6962 root. Item-3 removal of unsigned envelope mirror is zero-loss. CLEAN.
- merge_consequence_events (consequence.rs:739): shared native/WASM, MessageSent-only Source-2 gating preserves leaf convergence. Sequence numbering `next_seq + idx` (line 888) is gappy not "dense/contiguous" as doc claims — but sequence is evidence-only (not read by matches_trigger), self-consistent across both impls. LOW doc-accuracy nit only.
- tree.rs leaf_hash extraction + pub: behavior-identical, 0x00/0x01 domain sep intact, tag 59 retired as stable gap. CLEAN.
- governance freeze backdating: accepted (liveness-only, needs 2 colluding signers, never grants capability). CLEAN.
