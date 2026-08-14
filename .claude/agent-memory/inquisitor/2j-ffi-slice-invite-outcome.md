---
name: 2j-ffi-slice-invite-outcome
description: ADR-049 2J FFI slice — RequiresGovernanceApproval{None} is a phantom-success placeholder; return Err until #2027. Plus latent member:invite-vs-governance:propose gate question.
metadata:
  type: project
---

Interrogation of `feat/adr049-2j-ffi-slice` (HEAD cef1c681d), 2026-07-05.

**Central finding — UNSOUND as shipped: `InviteMemberOutcome::RequiresGovernanceApproval { proposal_id: None }`.**
- `invite_member` on any non-SingleAdmin (voting) context returns `Ok(RequiresGovernanceApproval{None})` — supervisor.rs:10600. Test M3 (spawn_from_welcome_tests.rs:2547) asserts it: member_count stays 1, no proposal, no add. Nothing is deferred; the invite is DROPPED.
- Why unsound: (1) phantom-success — caller/LLM reads the doc ("first-class SUCCESS outcome … deferred to a governance vote") and waits for a vote that will never happen; today's None-outcome is indistinguishable from #2027's future real-proposal outcome. (2) `proposal_id` is ALWAYS None, "reserved" for #2027 — the exact placeholder/None-field shape CLAUDE.md forbids. (3) DOA public surface: the variant + always-None field are baked into 4 SDKs (PyO3/napi kind-tag; UniFFI/Swift/Kotlin native enum); #2027 must REINTERPRET None→Some and "dropped"→"pending" = replacing a shipped decision.
- Fix (cheap, before merge): return `Err(ContextError)` "governed-context invites not yet implemented (#2027)". Honest (invite did NOT happen), no placeholder field, and #2027 becomes purely ADDITIVE (introduces the success variant with a never-None proposal_id). Collapses the FFI kind-tag/enum to a single "sealed" case today = a real simplification.

**Premise verdicts:**
- Routing invite through the actor governance gate (propose_governance_action_checked → AddMember, SingleAdmin auto-executes) = SOUND, spec-grounded (§5.9 line 501, §5 line 437: member-add is a governance action). Fixes the prior off-mailbox `deps.crypto.add_member` 4-defect path (no Commit broadcast, no role_state, off-mailbox race, zero authz). Decision-on-merit.
- LATENT QUESTION: the gate checks `governance:propose` + admin-identity (SingleAdminEngine::propose NotAdmin), NOT `member:invite` — though the spec defines `member:invite` as a distinct capability (§5 lines 87/225). No live divergence (SingleAdmin admin holds both); #2027's arbitrary-role work MUST reconcile which capability gates invite.
- KP-capability fix (9fe3b4c9b): SOUND. Decouples 0xFF02 *capability* (valn0502, no key material) from 0xFF01 wrapping-key *leaf ext*; declares 0xFF02 unconditionally so KPs are context-joinable. valn0107 only constrains present-ext⟹declared. Makes join SUCCEED where it previously failed; exposes pre-existing #2032 (no prod wrapping-key writer → joinable ≠ can-decrypt).
- FLAG-1 ceiling resync (3 bridges): register default `&[]` then sync authenticated ceiling post-spawn = sound ordering (reversible precheck before irreversible KP burn; authed ceiling only known post-open). 3 spellings (PyO3 helper, napi helper, UniFFI inline+CTX_2040) = inherent per-bridge triplication of ONE op, NOT drift. Acceptable. Nit: synced ceiling is genesis (stale per #2028), labeled "AUTHENTICATED" (true but not "current").

**Re-scope issues — all sound (separate/pre-existing, not sunk-cost punts):**
- #2029 (AddMember(None) never does real prod MLS add) — pre-existing root cause the branch FIXED for the invite path (KP on command envelope); generic AddMember + execute_reset_member remain. Real fix done, remainder filed.
- #2028 (Welcome-join installs stale genesis params, no evolution replay) — model-wide, pre-existing, affects all joins + import.
- #2032 (prod KPs carry no wrapping key) — pre-existing, exposed by 9fe3b4c9b.
- #2027 (governed invitations + GenesisAttestation) — genuinely large separate feature.
Nothing kept in the slice that should have been filed. Enforcement additions (check-sdk-coverage mappings, ffi-export-allowlist getter entries) are minimal/necessary, not over-built.
