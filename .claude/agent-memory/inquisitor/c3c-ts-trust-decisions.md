---
name: c3c-ts-trust-decisions
description: c3c-ts branch — 5 human-locked C3c trust/capability decisions interrogated for fidelity + stale premise; all sound. Founder-leaf, verify-on-ingest symmetry, optional-capability diagnostic, required presenting_agent_did.
metadata:
  type: project
---

# c3c-ts five locked decisions — fidelity verdicts (review 2026-06-29)

Branch `c3c-ts` (ADR-057, §7.2.4, §7.3.2, ADR-011 amendment). WASM removed (3 native bridges).
All five locked calls verified faithful to artifacts; no stale premise found. Notes for re-check:

1. **Verify-on-ingest symmetry (attestation + challenge_results).** `verify_challenge_verification`
   (challenge.rs) mirrors the attestation resolver-based path; both wired in
   `trust_store.rs::populate_and_aggregate`/`verified_attestations` with a CLOSED allowlist
   `is_verification_rejection` (drop forgery, propagate infra fault). Context revocation list
   seam closed for attestations via `RevocationStateChecker` → `verify_and_cache_with_revocation`.
   **Asymmetry is sound, not a gap:** challenge ingest checks signature ONLY; freshness is
   enforced at CONSUMPTION (`admission.rs:109` — `cv.passed && cv.expires_at > current_time`),
   and the signature binds `expires_at` so it can't be extended. Attestation freshness lives at
   ingest (TTL/refresh) because of the cache model. Re-check: if a challenge-result consumer is
   added that does NOT check `expires_at`, the signature-only ingest becomes a replay hole.

2. **Founder MemberJoined leaf.** Added in `builder::create_context` (Step 8) at the convergent
   `creation_timestamp_secs` (NOT local now()), subject==actor==creator, role "admin". Emitted
   EXACTLY ONCE: builder::create_context has a single caller (`lifecycle_helpers::create_context`,
   the production supervisor create path); import/restore (`export_import.rs`) replays existing
   leaves and never re-runs create_context. Right fix vs. alternative (special-casing the founder
   in the derivation): pushes the special case into emission (one leaf) so the duration rule stays
   a single uniform "interval opens on MemberJoined". No double-count (ContextCreated is not a
   membership leaf; context_creation_count keys on ChildContextCreated). Convergent-by-construction
   but committer-local until receive-side replication lands — consistent with tightened §7.3.2.
   Minor re-check: role="admin" assumes lifecycle seeds creator as admin in ALL governance models.

3. **Participation record computed once in Rust.** `Supervisor::participation_record` →
   pure-core `compute_participation_record`; both SDKs (trust.py `_participation_record_from`,
   scp.ts `participationRecord`) call the bridge op and PROJECT — never re-aggregate. Faithful.

4. **`presenting_agent_did` required + fail-closed (gate AND diagnostic).** Sound, not over-reach:
   it feeds the step-5 audience/key-scope check that runs in BOTH modes; defaulting to token `aud`
   makes audience a tautology (`aud==aud`) → trust inflation. Required-field matches runtime
   (agent-first tenet: required choices as required fields). Empty/whitespace treated as absent →
   validation error.

5. **§7.3.2 anchoring tightened to committer-local-until-ADR-051** + Sybil/diagnostic threat notes.
   This resolved the divergence I flagged pre-branch (see [[participation-anchoring-premise]]).
   `attestation_count` correctly recast as credential-layer (§7.4), NOT Merkle-anchored,
   verifier-relative. No phantom `AttestationPublished` EventType.

Also clean: `evaluate_ucan` `required_capability: Option<&CapabilityUri>` (intrinsic-validity mode)
is fail-closed — `None` only SKIPS step-6 grant-match, never flips a bool true; `within_ceiling`
still enforces the all-att ceiling. ADR-057 gate-vs-diagnostic separation is a security property
(folding structure into the throwing gate would burn the nonce on every probe).
