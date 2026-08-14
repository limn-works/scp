---
name: sec1866-direct-execute-trust-3fb78a5da
description: SEC-1866 governance direct-execute hardening review (FIX B identity_did removal + FIX C strict WASM proposal_id hex) at 3fb78a5da — ALIGNED, 1 stale-comment nit
metadata:
  type: project
---

# SEC-1866 direct-execute trust hardening @ `3fb78a5da` (2026-06-23) — ALIGNED

Range `c9db30486..3fb78a5da` (3 commits, 34 files +496/-173). Two security-review fixes:
- **FIX B**: removed divergent `identity_did` param → uniform `(handle, proposal_id_hex)` direct-execute across 4 bridges (PyO3/UniFFI/NAPI/WASM) + 4 SDKs. WASM consequence subject now resolved from tracked proposer (was caller) → completes #205 convergence.
- **FIX C**: strict WASM `validate_proposal_id_hex` (32-byte) at bridge boundary + `parse_proposal_id_bytes` (replaced `hex::decode().unwrap_or_default()` zero-pad) + `ScpWasmError::proposal_id()` routing malformed id to CTX_2040 (parity with native PyO3/NAPI/UniFFI which all surface malformed id as SCP-CTX-2040).

**Verified ALIGNED:**
- Native `execute_governance_action(executor_did: Option<&DID>)` direct path (`None`) resolves executor = `proposal.proposer_did` (governance_helpers.rs:4551) AND enforces consequences with `member_did: &proposal.proposer_did` (4414/4431). WASM now passes `(&proposer_did, &proposer_did)` for (initiator/subject, executor) → byte-identical. Matches ADR phase-6.md:2932/2950 canonical sig + §8 "executor DID" + spec §7.3.1 (07-trust:121-131, "subject == Carol's DID" governance-action subject).
- Capability-matrix note (sdk-capability-matrix.json:790) accurately rewritten to uniform shape + "no caller identity/subject; both resolved from proposer".
- pipeline_wiring assertion (scp-testing, NOT scp-runtime) strengthened: now asserts `!entry_sig.contains("identity_did")` — strictly stronger.
- identity_did removal = clean end state, consistent with no-migration/pre-release rule. No orphaned callsites (grep clean). UniFFI checksum regenerated 14006→15010 (correct).
- propose/approve/reject/withdraw/get_proposal now also call validate_proposal_id_hex at WASM boundary (defense-in-depth; only execute was the security fix but coverage extended consistently).

**1 finding (INFORMATIONAL, non-blocking):** consequence.rs ~1272 test `cross_impl_governance_action_executed_direct_stamps_proposer_wasm` comment "EXACTLY what the fixed `context_execute_governance` direct entry does: ... execute with auth-subject = caller, executor = proposer" is STALE post-FIX-B — bridge now passes `(proposer, proposer)`, not `(caller, proposer)`. Test still valid (leaf actor_did = executor, subject-independent) but prose misdescribes current bridge call. Phantom-provenance nit.

LESSON: when a fix changes a bridge call's arg semantics, grep test-body comments that narrate "EXACTLY what the bridge does" — they drift silently because the test still compiles/passes (the assertion targeted a subject-independent property).
