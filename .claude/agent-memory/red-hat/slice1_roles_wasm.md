---
name: slice1-roles-wasm
description: WASM slice1-roles (#1877) attack assessment — send-seq rollback clean; threshold/majority eligibility divergence is the live finding
metadata:
  type: project
---

# WASM slice1-roles (#1877) — branch slice1-roles, HEAD 3e1cc9a6b (2026-06-24)

Slice adopts the SHARED `ContextRoleState` into WASM `PerContextState` (commit 6c730b606). This closes the historical RED-801 suspension-cosmetic bug: WASM `member_has_capability` (manager.rs:611) now delegates to `ContextRoleState::member_has_capability` which checks suspension first. Same role/ceiling/suspension logic as native.

**Why:** Convergence work bringing WASM to native parity on roles/governance.
**How to apply:** When reviewing WASM governance/roles, the per-cap suspension/ceiling logic is now shared core — don't re-flag it. The divergence surface moved to the WASM-LOCAL governance TALLY layer (quorum + voter eligibility), which is NOT shared.

## Send-path seq rollback (commit headline) — CLEAN, no finding
- `send_message` (manager.rs:~2090): reserves seq pre-encrypt, rolls back via `saturating_sub(1)` + removes fresh-`0` entry on ANY encrypt-closure failure. Mirrors native `MembershipState::rollback_sequence_number`.
- AAD-collision REBUTTED: sender layer (`encrypt_sender_layer`, scp-protocol/.../encrypt.rs) uses a RANDOM 12-byte OsRng nonce per call; (epoch,seq) bound as AAD only, NOT as nonce. Seq reuse alone does NOT cause GCM keystream/nonce reuse. A failed send transmits no ciphertext anyway.
- Receiver-desync REBUTTED: WASM `decrypt_message` (manager.rs:2233) takes epoch+sequence as CALLER PARAMS, keeps NO receiver-side expected-seq counter, no replay/dedup keyed by seq. The sidecar is sender-side numbering only.
- Coverage complete: only fallible work after reservation is the encrypt closure (rolled back) + infallible `push_event` + infallible `dispatch_consequences_for_subject` (returns usize, runs after record). `publish_broadcast` increment is followed only by infallible push_event (no rollback needed, correct) and stores plaintext base64 (no AEAD surface).
- New test `send_message_failure_does_not_advance_sequence_wasm` passes; mutation-verified.

## FINDING RED-1101 (MEDIUM, native↔WASM §9.9.3 divergence): governance voter-eligibility + quorum basis
WASM governance tally diverges from native's engines:
- `propose_governance_action` (manager.rs:4878) gates ONLY on `governance:propose`; `approve_governance_proposal` (manager.rs:5079) gates ONLY on `governance:vote`. NEITHER checks `threshold_signers.contains(did)` or any frozen eligible-voter set.
- `threshold_signers` (manager.rs:391) is used ONLY by AddSigner/RemoveSigner/ModifyThreshold + export/import. NEVER consulted in the vote tally.
- `governance_quorum` (manager.rs:4856): "majority"=`members.len()/2+1`, "unanimity"=`members.len()`, "threshold"=`(threshold_value, members.len())` — all over LIVE current membership, no min-participation gate.
- Native `multisig.rs` (MultisigEngine): rejects non-signer proposer (line 233 NotEligible) and non-signer voter (lines 338/418/497 NotEligible); tallies against FROZEN `signers`. Native `majority.rs` MajorityVoteEngine: `eligible_voters` "frozen at engine", quorum `approvals > eligible/2` PLUS min-participation `votes_cast*10000/eligible >= min_participation_bps`. Native model carries `eligible_voters`/`signers` snapshot; WASM does not.
- Reachable: `governance` string stored raw from `params["governance"]` with NO validation (manager.rs:1562) — threshold/majority/unanimity all live. `admin` role holds `governance:vote` via full ceiling; multi-admin is a supported state (TransferAdmin demotes-all-then-promotes-one). A non-signer admin's vote is counted by WASM, rejected by native → divergent `GovernanceActionExecuted` Merkle leaves → §9.9.3 equivocation-detection breakage. Also membership change between propose and crossing-vote re-bases the WASM quorum (live members) while native uses frozen set.
- UNTESTED: every WASM governance test uses `single_admin` (quorum=0 auto-execute). The multi-admin tally path has zero coverage.
- Single-instance caveat: WASM has NO remote vote-ingestion path; proposals/votes live only in the local instance. So this is a native↔WASM CONVERGENCE divergence (mixed-bridge context), NOT an in-WASM multi-party split-brain.

## Cleared (no finding)
- TransferAdmin (manager.rs:4129): demotes-all-admins-then-promotes-new_admin; final promote infallible-by-construction (built-in role, ceiling-filtered). No zero-admin window. creator_did immutable (UCAN root/export signer). Reject-non-member before mutation. Native-equivalent.
- Export/import (manager.rs:6680+): enforces exporter_did==creator_did (SCP-CTX-2093), non-empty Ed25519 sig verify_strict against creator-resolved key (NOT envelope key), HMAC defense-in-depth self-imports. Non-creator import + key-substitution rebutted.
- Suspension bypass: closed by shared ContextRoleState (send_message + publish_broadcast both gate via suspension-aware member_has_capability).
