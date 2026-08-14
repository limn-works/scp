---
name: attestation-credential-layer-amendment-03d0eca8c
description: Review of attestation=credential-layer spec/ADR amendment (commits 916d1be23 + 03d0eca8c, branch c3c-ts) — ALIGNED
metadata:
  type: project
---

Spec/ADR amendment encoding LOCKED decision: attestations are credential-layer artifacts (DID-doc/relay/cache §7.4), revocable, verifier-relative, NEVER context-log/Merkle leaves. `attestation_count` = credential-layer on-demand count, NOT Merkle-anchored. Separately role_progression/participation_duration leaves gain `subject_did` payloads (RoleAssignedPayload, membership-change payload). NO EventType variant added/removed.

**Verdict: ALIGNED.** Faithfully encodes the decision; no over/under-shoot. Files: spec 07 (§7.3.1/§7.3.2/§7.3.2.1/§7.4.1/§7.4.4), spec 09 (§convergent-log-requirement), phase-2.md (ADR-011 amendment), ADR-051.

**GOTCHA: commits NOT on the checked-out branch.** Branch c3c-ts-work HEAD = 1620de983; 916/03d are NOT ancestors. MUST grep the committed blobs via `git grep PATTERN 03d0eca8c -- path` (03d is the tip, descendant of 916). Working-tree grep shows PRE-amendment text and misleads.

**Grep evidence (all clean at 03d):** every "attestation" in a convergent/MLS-commit-ordered/event-class list (ADR-051:13, spec07:156, spec09:823) now EXCLUDES attestation. `AttestationPublished` survives only in negating prose ("There is no AttestationPublished event type"). EventType enum = 75 variants, no Attestation* variant — confirms "no variant added/removed". Cross-refs §7.4.1/§7.4.4/§7.3.2.1/§7.4/§9.8.2 all resolve. §25 has no attestation-as-event vectors.

**Finding #5 (pre-existing, NOT introduced):** phase-2.md:992 prose says "77-variant set" but enum has 75 variants (confirmed at HEAD 1620de983 too — present before amendment, untouched by both commits). Amendment's "variant count is unchanged" is CONSISTENT (75→75); the 77 prose was already stale. Off-by-2, unrelated to this change.

**Minor downstream wrinkles (forward-flow, not docs defects):**
1. code `crates/scp-protocol/src/trust/participation.rs` still maps `attestation_history` from `ToolVerified` events ("attestation-adjacent") and extracts target_did from JSON `target_did` field — diverges from amended spec (credential-layer source; RoleAssignedPayload.subject_did). Expected: amendment is the prerequisite SPEC that lands first; code follows (no-migration end-state model). Report as the gap the amendment opens, not a fault.
2. ADR-011 amendment says the 3 leaves "were previously empty-payload" — runtime appends them with payloads today (extract_target_did parses target_did), so "empty-payload" is slightly loose but the leaf-preimage-bump reasoning holds for the canonical RoleAssignedPayload shape.
3. §7.3.2.1 example JSON shows `attestation_count: 5` (source-agnostic; fine).
