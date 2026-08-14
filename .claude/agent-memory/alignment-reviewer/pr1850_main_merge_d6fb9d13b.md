---
name: pr1850-main-merge-d6fb9d13b
description: PR #1850 event-log Phase-2 substrate after merging origin/main (#1852 ADR-039 #agent persona) @ d6fb9d13b — ALIGNED, 0 findings
metadata:
  type: project
---

# PR #1850 post-merge integration review @ `d6fb9d13b` (2026-06-21) — ALIGNED

Worktree `eventlog-phase2`, branch `feat/eventlog-unification-phase2-substrate`. Reviewed the MERGE of origin/main (#1852 shared-DID #agent persona / ADR-039) into the event-log substrate branch — verifying neither PR's intent dropped/contradicted. Scope = merge commit `5df11a2ee` + 3 post-merge fixups (`82fbef9dd`, `118f3318c`, `d6fb9d13b`), NOT the full branch.

**Why:** orchestrator landing PR #1850; needed assurance the origin/main merge preserved both substrate convergence and ADR-039 wiring.
**How to apply:** if re-reviewing this branch, the merge is clean; future findings would be in the substrate body, not the integration.

0 findings. All 3 claims verified:

1. **Event-log changes still satisfy ADR-011 amendment + §9.9.3/§6.2.4 post-merge.** Merge commit touched ZERO event-log files (disjoint from #1852: FFI resolvers + governance KeyResolver + primitives). Taxonomy intact at 77 closed variants (`event_type_taxonomy_is_closed_at_77_distinct_variants` test). Both `CrossContextToolInvoked` (tag 76) / `CrossContextDivergenceMarker` (tag 77) present and documented as "convergent, commit-ordered durable leaf — NOT per-author-excluded" (phase-2.md:943-948 carve-out). `eventlog_convergence.rs` test untouched by merge.

2. **ADR-039 #agent-persona wiring preserved.** #1852 changed `KeyResolver` from `Fn(&DID)` → `Fn(&DID, SigningKeyId)` (governance/mod.rs:88; doc handles "no #agent key when requested" → None). Live pipeline (messaging_helpers.rs): send stamps `signing_key_id: signer.signing_key_id()` (:183); verify reads `inner.signing_key_id` + resolves via 2-arg resolver (:310-311); dispatch maps `SigningKeyId::Active→MessageSigner::Active`, `Agent→Agent` (:774-776). ZERO stale 1-arg closures repo-wide. Fixup `118f3318c` correctly adapted 2 test closures to `|_, _|`.

3. **Security fix `82fbef9dd` (divergence_marker_plan) aligns with §6.2.4/§9.9.3.** Removed the `asserted_nonce`/`asserted_timestamp_ms` fallback (caller-ASSERTED = untrusted/proposer-controlled, forbidden by §6.2.4 *Recorded timestamp*). Now `let prepared_b = ctx.prepared_b.as_ref()?;` then `marker_nonce = prepared_b.recorded_nonce`, `committed_timestamp_secs = prepared_b.recorded_timestamp_ms/1000` — verified B staged provenance ONLY. Caller (supervisor.rs:6323 `if let Some(plan)`) handles None/skip. Regression test `divergence_marker_plan_refuses_without_verified_commit_b` (:16001). Test helper updated (`d6fb9d13b`) to set prepared_b.

**Sound asymmetry noted (not a finding):** `asserted_nonce`/`asserted_timestamp_ms` still legitimately used at supervisor.rs:6876 (CommitA correlation token — nonce IS the public wire value B copies per §6.2.4) and :7299-7306 (`xctx_prepared_evidence_bytes` pre-Prepare-B fallback — the PreparingB replay arm only ABORTS, never re-drives Commit, so never signs from these). Marker path (post-commit, signed convergent leaf) must use verified provenance; prepared-evidence path (pre-commit, abort-only) may fall back. The fix correctly distinguished the two.

No conflict markers anywhere in crates/. Build/gates green per prompt (not re-run).
