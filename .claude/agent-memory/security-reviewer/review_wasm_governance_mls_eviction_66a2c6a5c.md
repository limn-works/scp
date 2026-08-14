---
name: review-wasm-governance-mls-eviction-66a2c6a5c
description: CLEAN review of fix/wasm-governance-mls-eviction @66a2c6a5c — adds self-DID short-circuit (own_did derived from leaf) to the MLS-eviction line; zero findings
metadata:
  type: project
---

# WASM governance MLS-eviction + self-DID short-circuit (66a2c6a5c) — CLEAN, ZERO findings

Branch fix/wasm-governance-mls-eviction HEAD 66a2c6a5c, task #227. SUPERSEDES f761c7d2b review. ONLY new commit vs f761c7d2b: 66a2c6a5c (group.rs +221, state.rs +43, all the rest of the diff vs origin/main is the already-reviewed f761c7d2b line).

## What 66a2c6a5c adds
A native-parity **self-DID short-circuit** in `WasmMlsGroup::remove_member_by_did` (group.rs:347): `if self.own_did()? == member_did { return Ok(Vec::new()); }` BEFORE the leaf scan. Mirrors native provider.rs:1041 (`member_did == self.local_did`). Closes a dup-DID-tree divergence: a SECOND leaf carrying the local DID (added via normal add path w/ fresh signing key — OpenMLS keys leaves by signature key, not DID) would, under own-leaf-skip-only, be resolved + evicted by WASM, advancing the epoch, while native evicts NEITHER leaf → §9.9.3 tree::root divergence. Short-circuit returns before scan → neither evicted → parity.

## own_did() (group.rs:203) — KEY divergence from native, analyzed CLEAN
Native compares against stored `self.local_did` field. WASM has no such field (no persistent state across create_group/join_from_welcome), so `own_did()` DERIVES the local DID at call time from the committer's own leaf: `own_leaf_index()` (infallible LeafNodeIndex, openmls 0.8.1 mod.rs:326) → scan members() for member.index==own_index → BasicCredential::try_from → WasmScpCredential::from_bytes → .did. Correct for creator (leaf 0) AND Welcome-joined member (non-zero leaf) — both proven by tests own_did_returns_local_member_did_for_creator / _for_welcome_joined_member.
- FAIL-CLOSED both ways: own_did returns Err on GroupDestroyed (group None) or undecodable own-leaf cred (unreachable — you're always a member of your own group; error string "own leaf not found" is dead but harmless). Err propagates via `?` → dispatch keeps member. No fail-OPEN path.
- The `own_did()? == member_did` is a string compare; no widening/normalization that could false-match a different DID.

## Fail-closed dispatch ordering (manager.rs dispatch_remove_member ~3450) — UNCHANGED, still AIRTIGHT
existence check (contains_key, NO removal, CTX_2015) → if crypto.is_some(): governance_remove_from_group (ONLY fallible step, ? → CRYPTO_4011 w/ member fully present) → infallible governance_remove_sender_key(drop+ZeroizeOnDrop) → infallible governance_rotate_sender_key(in-place zeroize+regen) → THEN ctx.members.remove + F5 strip (suspended_capabilities.remove, read_exclusion_list.remove) + broadcast block_author + push MemberLeft event + append_log_event(MemberLeft, executor_did, EMPTY payload, ts). No gone-from-gov-but-in-MLS-group window. crypto.is_none() (broadcast/unencrypted) → empty commit, proceeds (native non-MLS no-op parity).

## Self-removal full-path parity (TWO mechanisms, both present)
1. self-DID short-circuit (NEW, group.rs:347) — own-DID → Ok(empty) before scan.
2. own-leaf skip in leaf_index_for_did (group.rs:270, retained) — own_index continue.
Either → empty commit → dispatch PROCEEDS to strip gov + append MemberLeft (matches native execute_remove_member self-removal). Without skip OpenMLS rejects remove_member(own_index)=CannotRemoveSelf → member KEPT no leaf → divergence.

## Commit-hex / leak — CLEAN
commit hex = public MLS Commit (HPKE-sealed path secrets, no key leak). Returned to JS for relay distribution (intended; WASM no transport ADR-034). local_sender_key zeroized in place before regen; SenderKey ZeroizeOnDrop. Empty commit = no MLS / no leaf / self no-op. context.rs+wasm.ts+scp.ts doc the relay-or-fork gap (3 layers, doc-only, from f761c7d2b).

## Verification (all green)
- cargo test -p scp-ffi-wasm --lib: 379 passed (was 373 @f761c7d2b; +6 new: own_did creator/joiner/destroyed, short_circuit_before_scan, self_did_does_not_evict_duplicate_leaf, governance_remove_self_did_no_op_in_dup_did_tree). incl evicted_member_cannot_decrypt_after_removal_and_rotation.
- cargo clippy -p scp-ffi-wasm --target wasm32-unknown-unknown (CI lib cmd): CLEAN.
- cargo test -p scp-runtime --test wasm_conformance --features testing remove_member: 2 passed.
- GOTCHA: clippy `--all-targets` on wasm32 FAILS at identity.rs:6116 `scp_identity::DidRotationEvent` — PRE-EXISTING (untouched by branch; last touched by merged #1774; identical refs on origin/main; CI uses lib-only clippy). Orthogonal to MLS eviction.

ZERO findings across injection/auth/secrets/leakage.
