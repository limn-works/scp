---
name: wasm-transfer-admin-convergence
description: WASM TransferAdmin convergence to native (commit d05e8ad7d) closes prior RED-W01 zero-admin/creator_did-strand chain; full re-assessment
metadata:
  type: project
---

# WASM TransferAdmin Convergence Assessment (commit d05e8ad7d, 2026-06-24)

Commit `d05e8ad7d` rewrites WASM `TransferAdmin` arm (`crates/scp-ffi/wasm/src/manager.rs:4055-4096`) to converge with native `execute_transfer_admin` (`crates/scp-runtime/src/context/governance_helpers.rs:1828`).

**RED-W01 (prior MEDIUM, from wasm_slice1_roles_export_import.md) — CLOSED.**
- Old WASM code: unconditional `creator_did = new_admin` + role-promote only if already member → zero-admin vacancy + export-signer stranded on non-member.
- New code: reject non-member BEFORE mutation (`!members.contains` → CTX_2015, manager.rs:4073); collect EVERY `role_name=="admin"` holder, demote each to "member", promote new_admin to "admin"; NEVER writes creator_did. Byte-equivalent to native.

**Why all variants are closed:**
- creator_did is the immutable export signer / UCAN root / HMAC id / exporter_did. New arm has NO creator_did write site.
- Export verify-key ALWAYS resolved from `role_state.creator_did` (common/src/export_verify.rs:6,101), never envelope. Import enforces `exporter_did==creator_did` (manager.rs:6611) + verify_strict + version gate + missing-sig reject. Gaining admin via transfer gives ZERO export-signing authority.
- Self/existing-admin/multi-admin transfers all converge to exactly one admin. No zero/two-admin residue.
- Partial-state risk from removed rollback = NONE: `assignments ⊆ members` by construction (every assignments.insert in roles.rs guarded by members.contains), so demote loop can't hit MemberNotInContext; built-in admin/member caps==ceiling so validate_role_definition can't fail.

**Prior chains re-confirmed closed:**
- Sequence sidecar × AEAD: WASM msg encryption rides OpenMLS (crypto/group.rs), RFC9420 secret-tree nonces, NOT the (epoch,sequence) sidecar (AAD/replay only). TransferAdmin touches only role_state. No nonce/key reuse path.
- RED-801 (suspension cosmetic) CLOSED: WASM member_has_capability (manager.rs:628) now delegates to shared ContextRoleState::member_has_capability (roles.rs:1544) which checks suspended_capabilities FIRST. governance:propose gating respects suspension. Promotion retains suspensions (prune_suspensions_to_role_grants retains full-ceiling admin caps).

**Residual (native-equivalent, deprioritized):** WASM governance is caller-DID-trusted — no wire-sig verification on votes/proposals (`signature: Vec::new()`, manager.rs:4863). Pre-existing, not widened by this change.

**Tests:** 403/403 scp-ffi-wasm host tests pass incl. 2 new TransferAdmin tests (member-promote + nonmember-reject), both through real propose_governance_action auto-execute path. NOTE: `--target wasm32-unknown-unknown` test build fails on pre-existing `scp_identity` unresolved-crate in identity.rs:6087,6116 test code (unrelated).

**Verdict: no non-creator-reachable chain. Genuine security convergence.**
