---
name: review-wasm-governance-mls-eviction-f761c7d2b
description: CLEAN review of fix/wasm-governance-mls-eviction @f761c7d2b — WASM RemoveMember cryptographic MLS eviction + self-removal own-leaf-skip no-op parity; zero findings
metadata:
  type: project
---

# WASM governance MLS-eviction + self-removal own-leaf-skip (f761c7d2b) — CLEAN, ZERO findings

Branch fix/wasm-governance-mls-eviction HEAD f761c7d2b, task #227. SUPERSEDES the b98c5b1a9 / 97c351df9 reviews in MEMORY.md index — this is the same fix line with the ADDED self-removal own-leaf-skip (`leaf_index_for_did` now skips `own_leaf_index()`).

## What the change does
WASM governance RemoveMember now cryptographically evicts from the MLS group (previously: governance-strip-only, removed member kept group keys + could decrypt). Returns eviction commit hex for JS/relay distribution.

## Fail-closed ordering (manager.rs dispatch_remove_member ~3451) — AIRTIGHT
existence check (contains_key, NO removal, preserves CTX_2015) → governance_remove_from_group (ONLY fallible step, `?` → CRYPTO_4011 with member fully present) → governance_remove_sender_key (infallible drop+zeroize) → governance_rotate_sender_key (infallible in-place zeroize+regen) → strip members/F5(suspended_capabilities,read_exclusion_list)/broadcast → append_log_event MemberLeft (infallible, errors only console-logged). No window where member gone-from-governance-but-in-MLS-group.

## Self-removal own-leaf-skip (group.rs leaf_index_for_did)
Byte-parity with native scan (provider.rs ~1041/1060): skip `own_leaf_index()`, BasicCredential::try_from + WasmScpCredential::from_bytes + did==. Own-DID → None → empty-commit no-op → dispatch PROCEEDS to strip+append (matches native self-removal). Without the skip, OpenMLS rejects remove_member(own_index)=CannotRemoveSelf → member KEPT with no MemberLeft leaf → §9.9.3 tree::root divergence. Missing-leaf (non-self) → None → no-op (governance authoritative). GroupDestroyed → Err (fails closed). Non-self member still resolved + evicted.

## WASM SAFER than native parity-wise
Native remove_member_sender_key + rotate_sender_key are FALLIBLE (fail_close_remove_member handling); WASM equivalents are INFALLIBLE → no post-eviction-pre-strip failure window in WASM. Both run rotate even on missing-leaf no-op (consistent).

## Post-dispatch desync window analyzed — NOT reachable (non-finding)
execute_governance_action success branch does `parse_proposal_id_bytes(proposal_id)?` + `encode_governance_action_executed_payload?` AFTER eviction. parse_proposal_id_bytes == scp_ffi_common::validate_proposal_id_hex, already called at the public boundary (context.rs context_execute_governance) BEFORE the method → re-validation of already-validated value, cannot fail. Encode is shared positional MessagePack of an action dispatch already matched on. Matches native (encodes payload before append). Defense-in-depth, not a gap.

## Commit-hex / leak
Commit hex = public MLS Commit (HPKE-sealed path secrets, no key leak). local_sender_key zeroized in place before regen. SenderKey: ZeroizeOnDrop.

## Relay-or-fork gap documented 3 layers
context.rs doc + wasm.ts + scp.ts: WASM has no transport (ADR-034), caller MUST relay commit or MLS group silently forks. Empty commit = broadcast/unencrypted or no-leaf. Pre-existing sender-key non-distribution gap noted, orthogonal (MLS epoch advance is the lockout).

## Verification (all green)
- cargo test -p scp-ffi-wasm --lib: 373 passed (incl evicted_member_cannot_decrypt_after_removal_and_rotation decrypt-proof, 4 group tests, 5 manager dispatch tests: noop_non_member/noop_self_did/keeps_governance_when_mls_fails/encrypted_commit_hex/self_did_encrypted/broadcast_path)
- cargo test -p scp-runtime --test wasm_conformance --features testing remove_member: 2 passed (cross_impl_remove_member_leaf_is_empty_and_precedes_executed)
- cargo clippy -p scp-ffi-wasm --target wasm32-unknown-unknown: clean

OBS (non-finding, parity-consistent): neither native nor WASM strips threshold_signers on removal (pre-existing, both sides same).
