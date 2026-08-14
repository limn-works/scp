# PR #1850 Phase-2 substrate — divergence-marker fix + #1852 integration (HEAD 44f2ebeda) — 2026-06-21

Merge-base = b5bf4aafe (#1852 ADR-039 wire-in). Reviewed two NEW security surfaces. CLEAN, no blocking findings; one defense-in-depth observation.

## 1. divergence_marker_plan fix (82fbef9dd) — FULLY CLOSED
- supervisor.rs:7127 divergence_marker_plan now does `let prepared_b = ctx.prepared_b.as_ref()?;` and sources marker nonce (7174) + timestamp (7182) SOLELY from prepared_b.recorded_*. Removed the `map_or(asserted_*, ...)` untrusted fallback.
- SOLE non-test caller = supervisor.rs:6323 inside dispatch_commit_phase NeedsRepair arm, on the LIVE in-memory ctx (prepared_b populated since Commit-B landing ⇒ Prepare-B ran). `?`-None ⇒ warn + no marker (6326).
- Recovery/replay paths (recover_committing_entry/recover_needs_repair_entry/recover_preparing_b_entry) DO NOT call divergence_marker_plan — they use reconstruct_xctx_prepared for reversal/Abort{None} only, never emit a convergent leaf. PreparingB/PreparingA re-drive ONLY aborts, never re-Commits.
- Remaining asserted_* consumers verified to never reach a signed convergent leaf:
  - dispatch_xctx_prepare_b (6465) passes asserted_* into PrepareB for B to stage (B re-derives/copies); not a leaf source.
  - xctx_prepared_evidence_bytes (7308) asserted fallback → CrossContextToolInvocationPrepared journal evidence consumed ONLY for participant-set reconstruction + reversal/abort keying, never a leaf.
- Regression test divergence_marker_plan_refuses_without_verified_commit_b (16011): prepared_b=None ⇒ None.

## 2. #1852 signing_key_id VM selector — NO SPOOFING
- signing_key_id IS in signed canonical-hash preimage: inner/mod.rs:557 CanonicalField::VarBytes(signing_key_id.as_bytes()), length-prefixed (domain "SCP-INNER-ENVELOPE-V1:"). Bound to signature → cannot be flipped post-sign.
- Send: build_encrypted_envelope (messaging_helpers.rs:183) stamps signing_key_id = signer.signing_key_id() and signs with signer.key() — BOTH from one MessageSigner ⇒ persona/key cannot disagree. create_inner_envelope_raw (sign.rs:125,149) writes SAME params.signing_key_id into struct field AND hash ⇒ wire field == signed value, no desync.
- Receive: verify_and_unwrap (messaging_helpers.rs:310-316) resolves key by (sender_did, inner.signing_key_id) via 2-arg KeyResolver, verifies sig against THAT key. Claim #agent + sign with #active ⇒ resolver returns #agent key ⇒ verify fails. Forging persona requires the claimed VM's private key.
- DID binding: deliver path (messaging_helpers.rs:1176) rejects inner.sender_did != MLS-authenticated sender_did (credential-spoof defense) BEFORE verify_and_unwrap; sender_did used for resolution == authenticated identity. Full chain MLS cred → sender_did → signed inner.sender_did → (DID,VM) key → sig.
- #[serde(default)] on signing_key_id (inner/mod.rs:216): applied before hash recompute on BOTH sides ⇒ absent-field and explicit-Active both → Active preimage, no desync. Tests: verify_rejects_tampered_signing_key_id (sign.rs:675), different_signing_key_ids_produce_different_signatures (710), serde default (760).
- KeyResolver type (governance/mod.rs:88) = Arc<Fn(&DID,SigningKeyId)->Option<VerifyingKey>>. Runtime resolver is caller-injected (deps.key_resolver). Pre-existing: production FFI resolvers hardcode Active/None (DID-doc VM keys not yet wired) — NOT this diff's regression.

## OBSERVATION (defense-in-depth, MEDIUM-spirit, NOT blocking)
- supervisor.rs:6886 the caller-side CrossContextToolInvoked LEAF nonce is sourced from ctx.asserted_nonce (proposer-controlled), not prepared_b.recorded_nonce — same call-ordering-not-types pattern the 82fbef9dd fix just hardened on the marker path. Bounded: nonce is a public correlation token (not auth-bearing), asserted==recorded on live path (B copies verbatim). A divergence breaks §6.2.4 nonce-joined provenance edge (auditability), not auth/injection. Project pinned this as an invariant in commit 44f2ebeda. Could be hardened to source from prepared_b.recorded_nonce for type-symmetry with the marker.
