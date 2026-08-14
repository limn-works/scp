---
name: scp1866-direct-execute-quorum-bypass
description: SCP-1866 governance direct-execute quorum-bypass fix review at 8ff63571a — ALIGNED, verified in detached worktree
metadata:
  type: project
---

# SCP-1866 Direct-Execute Quorum-Bypass Fix @ `8ff63571a` (2026-06-23) — ALIGNED

Review target = commit range `a632c731a..8ff63571a` (6 commits, 42 files +1798/-820).

**Core fix:** governance direct-execute was a quorum bypass — caller supplied a full `GovernanceProposal` (PyO3/UniFFI/NAPI) or `(initiatorDid, proposalId, actionJson)` (WASM, which even minted a RANDOM proposal id via `generateProposalIdHex()`). Caller could fabricate an `Approved` proposal or substitute an action. Fix = execute BY tracked `proposal_id` only; runtime resolves authoritative proposal from `engine.get_proposal(proposal_id)` (set `Approved` only at genuine quorum). Uniform `(handle, proposal_id_hex)` across all 4 bridges + 4 SDKs.

**Verified ALIGNED (0 findings):**
- Trust boundary sound: native `execute_governance_action(state, deps, ctx, &ProposalId, Option<&DID>)` resolves proposal from engine, rejects untracked (PermissionDenied), checks status==Approved on ENGINE-retained proposal, context-id match, replay (`executed_proposals`), commit-fault. `executor_did=None` (direct path) → resolved from `proposal.proposer_did`.
- WASM `execute_governance_action(ctx, initiator, executor, proposal_id)` drops the `action` param; resolves `tracked.action` from pending/resolved_proposals. Bridge `context_execute_governance(handle, proposal_id_hex)` resolves proposer, passes it for BOTH initiator+executor → subject==executor==proposer on direct path (#205 advancement for direct path; quorum-path subject divergence remains tracked under #205, correctly out of scope).
- Strict hex: `validate_proposal_id_hex` (common) returns `[u8;32]`; WASM `parse_proposal_id_bytes` replaces old `hex::decode().unwrap_or_default()` zero-pad/truncate (which could mint divergent leaf proposal_id breaking cross-platform Merkle equivocation). CTX_2040 parity: UniFFI/NAPI/WASM via structured `code:` field; PyO3 embeds "SCP-CTX-2040" in PyValueError message string (different mechanism, same code string).
- Provenance verified: ADR-031 §8 (phase-6.md:2749) DOES say leaf "records proposal ID, action, executor DID". Spec §7.3.1 (07-...:125,127,133) DOES say "committing member" + consequence "subject == DID". No phantom provenance.
- Integration checklist complete: runtime fn → actor handler (governance.rs `payload.proposal_id` + `None`) → 4 bridges → 4 SDK wrappers (Py/Swift/Kotlin/TS all `proposal_id_hex`) → pipeline_wiring.rs 2 new assertions (positive: resolve from engine/tracked-state; negative: must NOT accept `&GovernanceProposal`/`action:&GovernanceAction`) → capability-matrix.json notes updated. No empty cells.
- `TestInsertMember` seam properly `#[cfg(feature="testing")]` at every layer (command, dispatch, mod.rs fallback, supervisor); never FFI-reachable. Legit (single-node test can't drive real AddMember — needs DID-published identity).
- Tests pass (verified in detached worktree at 8ff63571a): 3 governance_integration direct_execute (incl. genuine 2/3 Majority quorum w/ real Ed25519 keys, execute-once + replay-reject), 3 pipeline_wiring execute_governance assertions, WASM wasm32 build clean.

**GOTCHA (cost ~30min): worktree HEAD was `b321248e1` (a release-CI branch WITHOUT the fix), NOT the review target `8ff63571a`.** `git show 8ff63571a:file` reads the right content but plain `sed`/`grep`/`cargo build` on the worktree read the WRONG (HEAD) version + uncommitted WIP (commands.rs re-adding `executor_did` w/ a capability-check design = a LATER iteration). Symptom: `grep` showed old line-2644 manager.rs while `git show` showed line-3077; `cargo build` failed on `payload.proposal` E0609. FIX: always `git rev-parse HEAD` first; if it != review target, `git worktree add --detach /tmp/x <sha>` and build/test THERE. The prompt said "READ-ONLY" + gave HEAD `8ff63571a` but the actual checkout had drifted.
