---
name: adr049-2j-ffi-slice-cef1c681d
description: ADR-049 Phase 2J FFI slice (reserve+join+invite_member, FFI-02 §5.12.3/§5.13.3) alignment review at cef1c681d — ALIGNED w/ 3 artifact-drift findings
metadata:
  type: project
---

# ADR-049 Phase 2J FFI Slice Alignment Review @ `cef1c681d` (branch feat/adr049-2j-ffi-slice)

Diff `origin/main...HEAD` (59 files, +14343/-573). Exposes joiner FFI (`reserve_key_package` + `context_join_from_welcome`) + creator-side `invite_member` across PyO3/NAPI/UniFFI + Python/TS/Swift/Kotlin. Implements FFI-02 Option A signed §5.12.3 InvitationBundle + §5.13.3 0xFF02 rule-8 creator_did binding.

**Verdict: ALIGNED at code layer; NEEDS DISCUSSION on 3 artifact-drift items (no code correctness blocker).**

## CONFIRMED ALIGNED
- §5.12.3.1 sign preimage EXACT match: `SCP-INVITATION-BUNDLE-V1 || ctx_id || creator_did || relay_hash || welcome_hash || key_material_hash || genesis_params_hash || metadata_snapshot_hash`, genesis_params_hash=SHA-256(JCS(context_params)), §9.5.1 length-prefix on ctx_id/creator_did, Fixed32 hashes raw (invitation_bundle.rs:186-228).
- Join verifies in order: HPKE-open (AEAD-bound to ctx_id/creator_did hints) → decode → bundle.verify(#active sig) → verify_structural_consistency → hint==bundle cross-check → verify_scp_context_binding (0xFF02 rule-8 creator_did) BEFORE any authority install (supervisor.rs ~10990-11400). Matches amended spec validation steps 1-6.
- Per-identity axis invariant RESPECTED: reserve/join/invite are genuinely-`pub` bare-DID Supervisor entrypoints, custody at bridge (axis b), NOT OwnedIdentityDid actor-internal (axis a). ADR §5 placement-invariant + conventions.md `my_*`=actor-internal / plain-verb=bridge + new lesson correctly codify it. Fix flowed spec→code (correct direction, explicitly documented — NO code-informs-spec inversion).
- 0xFF01 (scp_wrapping_key) vs 0xFF02 (scp_context_params) no collision; JCS canonicalization consistent across bundle + 0xFF02 (was msgpack, now RFC-8785 per §9.5 mandate).
- KP-DID binding added: execute_add_member calls validate_key_package(did, kp) before add.
- Multi-member desync ROOT-FIXED: execute_add_member now broadcasts the epoch-advancing Commit via try_broadcast_commit_or_enqueue (parity w/ remove/reset) — was buffered-never-sent.
- "default ceiling lacks governance:propose" is NOT a spec gap: admin role grants it additively (spec §5:225 beyond ceiling); member_has_capability (class_s.rs:1571) checks granted member_capabilities NOT ceiling; flagship test `invite_member_round_trip_stands_up_a_bidirectional_joiner` passes. No artifact fix needed.
- §5.7/§7.3.7 "authentication orthogonal to visibility" amendments internally consistent (MemberOnly econ-policy payee still creator-signed inside HPKE bundle).

## FINDINGS (artifact drift / phantom provenance — MEDIUM)
1. **ADR-049 deferred (line 419) misdescribes the gap.** Claims creator-side "add-member → Welcome" is "not-yet-built" and gates tripwire-flip/legacy-deletion on it — but `invite_member` IS that operation, landed + FFI-exported (matrix+pipeline_wiring) this slice. "Landed (FFI slice)" (418) omits invite_member entirely. Real remaining gap = cross-process KeyPackage publish/discovery + governed multi-member invite (#2027/#2029). Update ADR.
2. **ADR-049 line 418 + error_codes VALID_7150 doc** claim the bridge "rejects a non-Encrypted context up front" on JOIN — false now: up-front bridge mode-check removed (params travel inside sealed bundle), broadcast reject moved into runtime at ConfirmConsume (PyO3 context.rs comment). Stale claim. (invite_member DOES reject Encrypted-only up front at supervisor.rs:10580 — but that's runtime+invite side.)
3. **VALID_7150 is DEAD** — defined error_codes.rs:886 w/ doc describing up-front bridge reject, ZERO references repo-wide. Remove or wire (no-dead-code/no-stubs tenet).

## OBSERVATIONS (LOW)
- §5.7 now lists consequence_rules as structural always-visible, but StructuralMetadata struct (metadata.rs, carried in bundle metadata_snapshot for §5.12.2 auto-accept) does NOT carry consequence_rules — auto-accept can't evaluate them from snapshot (joiner still gets+enforces via full context_params). Confirm intended.
- Scope: #2029 (generic governance AddMember prod-add: add_member(None)→prod error) is PRE-EXISTING (old `let Some(bytes) = ... else Err` preserved in provider.rs) — defensible to defer. #2027 (voting-context invite) spec-consistent to defer — §5.12.3 bundle mechanics governance-agnostic; honest RequiresGovernanceApproval{proposal_id:None} return is forward-compatible, not DOA. "no deferral" tenet tension → human ruling.
