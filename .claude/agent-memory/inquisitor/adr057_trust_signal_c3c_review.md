---
name: adr057-trust-signal-c3c-review
description: Inquisition of ADR-057 structured trust/capability validation + C3c SDK parity (branch feat/actor-2c-xctx-tool-saga, HEAD c4075916d)
metadata:
  type: project
---

# ADR-057 structured trust validation + C3c SDK parity (4-binding)

Reviewed branch `feat/actor-2c-xctx-tool-saga` @ `c4075916d`. Decisions interrogated and verdicts:

- **Re-validation-on-read for challenge results + attestations** — SOUND. Both consumption
  points (`aggregate_trust_input` aggregate.rs:507; `check_capability_requirements`
  admission.rs:135) and ingest (`populate_and_aggregate` / `verified_attestations` in
  ffi/common/trust_store.rs) all run `verify_challenge_verification` / re-verify attestations.
  No production raw consumer remains (only test seeds + the wrapped reads). Symmetric across
  both credential types. Persistent SQLCipher store would otherwise serve a once-valid signal
  forever — the read-path filter closes that fail-open.
- **attestation_count = credential-layer, not convergent event** — SOUND, and it *removes*
  pre-existing phantom provenance: old spec §7.3.2 counted `AttestationPublished` events, but
  NO such EventType variant ever existed (confirmed: grep of scp-event-log enum). New spec
  sources it from credential layer (verifier-relative, never Merkle-anchored). Convergence
  rule "derived record convergent iff trigger convergent" holds — attestation issuance isn't
  convergent.
- **Founder MemberJoined at creation timestamp** — SOUND. builder.rs::create_context appends
  founder join (actor==subject==creator) at `creation_timestamp_secs` (same convergent value
  as ContextCreated). Production path reaches it via lifecycle_helpers::create_context:1411.
  Without it founder duration computed 0. Honest about committer-local-until-ADR-051.
- **ucan_evaluate (diagnostic) vs validate_ucan (gate)** — SOUND security property, NOT
  redundant. Share step-helpers but differ: gate throws + `check_and_record` (burns nonce) +
  mandatory capability; diagnostic structured + `check_replay` (read-only) + optional
  capability (Decision 2a). Folding them = nonce-burn DoS or loss of fail-closed (ADR rejected-alt 2).
- **CanonicalizationFailed variant** — SOUND, real closed-by-construction improvement.
  `is_verification_rejection` is a positive allowlist; the dedicated variant de-overloads
  InvalidEventData/ChallengeSigningFailed so no infra fault can collide with a per-entry
  drop. Direction is fail-safe (an unlisted error propagates, never silently accepts).
- **4-binding SDK parity (evaluate_trust/ucanEvaluate/participation_record)** — SOUND,
  coherent. All four SDKs expose idiomatic wrappers; Python prose-parser replaced by single
  `_coded_bridge_error` chokepoint keyed on stable `[SCP-CAT-NNNN]` code (ADR-057 Decision 4).
  Removes a pile of "lands in SDK-parity PR" deferrals (does the work, per no-deferral tenet).

## RESOLVED (was OPEN) — attestation_count_anchored placement
Prior open finding: spec §7.3.2.1 listed `attestation_count_anchored` on the SIGNED
ParticipationProfile struct; code only had it on the unsigned facts projection. FIXED in
commit 62e84ccb0 (2026-06-30): §7.3.2.1 moved the flag out of the signed struct listing +
added prose stating the signed profile does NOT carry it (permanently-false constant → would
be a tamperable field on a signed struct); it lives on the unsigned facts/BehavioralRecord
projection. Field count corrected eleven→twelve in SCP-303; §7.4.1 sharpened: a Sybil-
resistant admission gate MUST use the independence-scored threshold path (sybil_policy), NOT
an AttestationCount participation requirement (raw self-issuable count). Spec/code agree. SOUND.

## Round 2 (HEAD 7e0f22894, 2026-06-30) — new delta commits interrogated
Subject-binding + fail-closed hardening. All SOUND except one coherence QUESTION:
- **subject_did bound in challenge verify-on-read** (98311ce1b) — SOUND. `verify_challenge_
  verification` now takes expected-subject; aggregate.rs read path threads `ctx.subject_did`.
  Read path uses bare `.is_ok()` (drops on rejection OR infra fault); documented sound ONLY
  because resolver is total/pure (IdentityDidPublicKeyResolver, no network), explicit MUST-
  revisit note if a networked resolver is swapped. Ingest keeps the is_verification_rejection
  classifier because revocation-check there is fallible. Divergent handling deliberate+
  documented (different fallibility profiles), not rot.
- **verify_participation_requirements subject binding** (caff1e32d/c30cd443c/d25e1cec4) —
  SOUND + right altitude. Step-0 filter subject_did==expected_subject (fail-closed) in pure
  core; EmptyExpectedSubject guard at trust boundary; FFI bridges run full validate_did. §7.4
  caveat coherent: subject-binding enforced vs signer-legitimacy still caller's job.
- **Swift/Kotlin verifyParticipationRequirements twin DELETION** (e00846c92) — SOUND, delete
  right vs rename. Twins did client-side threshold math with NO sig/subject/freshness →
  attacker profile returned true; name-collided secure UniFFI path. Rename preserves a footgun
  with zero capability the secure path lacks. Deletion clean (no orphan refs; Participation.kt
  gone). Kotlin keeps a Scp-method delegating to secure free fn; Swift exposes the free fn
  directly — per-SDK idiom, both secure-routed.
- **challenge req/resp canonicalization propagation** (7e0f22894) — SOUND, fail-closed on-
  merit. Replaced jcs::to_vec().unwrap_or_default() (empty bytes silently drop parameters/
  result from signed digest = fail-open, sig-collision) with ChallengeSigningFailed error
  propagation. Restores symmetry with sibling canonical_challenge_verification_bytes.

## OPEN FINDING (QUESTION — coherence/drift): check_capability_requirements unwired + half-
hardened. Commit 98311ce1b threaded subject_did through BOTH admission siblings, but:
(1) verify_participation_requirements got EmptyExpectedSubject guard + FFI export + matrix
entry (line 646) + validate_did at 3 bridges; (2) check_capability_requirements got the
subject param but NO empty-subject guard (admission.rs has 0 is_empty()), NO FFI export, NO
matrix entry, ZERO production callers — grep of runtime/ffi/bindings (non-test) empty; only
own unit tests + scp-core lib.rs:128 re-export. Runtime enforces admission via broadcast_
admission/template policy + UCAN (validate/evaluate_ucan), not this §7.3.4 challenge gate. So
a dead admission primitive was hardened half-way while its live sibling got full treatment.
Fails integration checklist cells 1 (no ContextManager caller) + 5 (no matrix entry). Root
question: is challenge-based capability admission meant to be wired (completeness gap) or is
it vestigial parallel to UCAN admission (dead decision)? Same-commit divergent treatment is
the tell. Re-check on any future FFI export of check_capability_requirements.
