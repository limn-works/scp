---
name: adr049-pr7-crypto-move-premises
description: ADR-049 PR-7 atomic-crypto-move fix premises — the "belt-and-suspenders" double-KP-validate is a real DOA finding; the other three fixes are sound
metadata:
  type: project
---

ADR-049 PR-7 (atomic crypto move onto the actor) — re-review of the *fix* premises
(branch feat/adr049-pr7-atomic-crypto-move). Verdicts:

- **Identity binding (SOUND).** Reject `request.requester_did != sender_did` rather than
  removing the payload field. The field is NOT vestigial: it is a *signed* wire field
  (`compute_request_hash` covers it) and is the sole authenticated identity in the
  BROADCAST path (requests travel outside MLS). The shared pure `handle_sender_key_request`
  gates membership+block on `requester_did`; binding it to the MLS-authenticated
  `sender_did` in the encrypted path keeps ONE gating impl. Removing the field would be a
  wire+signature change — itself DOA-in-the-other-direction.
- **Wire-wrap answer (SOUND).** Wrap the pull-answer in `SenderKeyDistributionMessage::KeyResponse`
  so it matches the receiver (`decrypt_and_dispatch` → `from_bytes`) and the PUSH path.
  Correct to make the outlier conform, not to loosen the receiver to accept two shapes.
- **Double KP-validate "belt-and-suspenders" (UNSOUND premise — the finding).** Root fix:
  make `MlsBackend::validate_key_package` return the authenticated credential DID (widen
  `ValidatedKeyPackage` — backend.rs:96 — with `credential_did`, extracted from the
  already-`validated` leaf in production_backend.rs:~482). Today join_context
  (lifecycle_helpers.rs:843) and execute_add_member (governance_helpers.rs:1235) call
  `deps.mls.validate_key_package` (deserialize + `.validate()` + hardened lifetime +
  SCP_CIPHERSUITE guard, DID DISCARDED) and THEN re-run full crypto validation via
  `scp_mls::group::key_package_in_did` (group.rs:708 — same `.validate()` + same lifetime,
  minus the ciphersuite guard) only to extract the DID. This REGRESSED the pre-PR single
  `validate_key_package(did, kp)` that validated-and-bound in one pass. Redundant crypto
  re-check = "negative value, not defense-in-depth" per root CLAUDE.md. The type's own doc
  says it exists "so handler code can re-serialize … without re-running validation" — yet
  the code re-runs validation. Only 2 production callers; widening the return is bounded and
  makes both call sites simpler.
- **§9 send-generation residual (SOUND, minor coherence QUESTION).** PR-7 moved the MLS group
  from supervisor-owned Class-M (crash-surviving) to actor-owned Class-C (≤50ms rollback), so
  the own-leaf send generation can rewind on a panic-respawn. Disclosed honestly (NOT claimed
  closed), tracked #2149, corrected from a DOA epoch-advance-on-respawn to a floor+burn-forward
  (mirrors the existing `sender_key_epoch` Class-M backstop). Mitigation is real: RFC 9420
  reuse_guard (2⁻³²) + inner SCP random per-message nonce ⇒ MLS-layer AUTHENTICITY only, no
  confidentiality break. Nit: §9's "Forbidden — Class C for security-critical monotonic state"
  bullet and the new "Known residual" bullet don't cross-reference, so the ADR reads as
  self-contradictory to a fresh reader; add a one-line pointer. Also confirm #2149 is real/
  prioritized (the "No deferral" tenet bites).
