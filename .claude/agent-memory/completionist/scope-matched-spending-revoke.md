---
name: scope-matched-spending-revoke
description: Completeness review of commit 904f6d3dc — §19.5 scope-matched spending-UCAN revocation (global DID store, verify-before-revoke, union gate). Verdict COMPLETE, 2 LOW.
metadata:
  type: project
---

# §19.5 scope-matched spending-UCAN revocation — commit 904f6d3dc

**Verdict: COMPLETE** (2 LOW-severity notes, neither a functional gap).

**Branch topology gotcha:** 904f6d3dc is a divergent feature branch off merge-base
e406c15c5 (parent = spec commit 72817f104). NOT an ancestor of HEAD 1620de983. Working
tree lacks all its changes — verified entirely via `git show 904f6d3dc:...`. See
[[verify-against-commit-not-worktree]].

## Spec (72817f104 amends §19.5 / §19.6.1)
Global-scope (`scp:spending:*`) spending UCAN revoked in ctx A must be unspendable in
ctx B. Route by SpendingScope: Context→per-context Class-S set; Global→DID-scoped durable
store `identity/{did}/revoked_spending_ucans/`. Gate = UNION. Verify-before-revoke
(signature + iss==aud, side-effect-free). Local per-instance durable, no cross-device.
`SpendingUcanRevoked` leaf carries scope + CID.

## Coverage matrix (all cells filled)
- Tier a verify-before-revoke: `spending::verify_spending_ucan_genuine` (header.validate +
  is_spending_ucan + iss==aud + validate_key_scope + verify_signature; reuses validate::
  primitives, skips nonce/expiry) → `economy_logic::verify_spending_ucan_genuine_or_error`
  (SCP-ECON-12066) → called in supervisor.revoke_spending_ucan BEFORE either store. ✓
- Tier b scope routing: `spending::spending_scope_of` → match Context/Global. ✓
- Tier c context Class-S: EconomyCommand::RevokeSpendingUcan (now carries `scope`) →
  economy.rs handler → fail-closed persist + leaf. ✓
- Tier d global store consulted by gate: `store/revoked_spending_ucans.rs`
  (RevokedSpendingUcanStore trait + ProtocolRepository impl, load_all/record) → supervisor
  `revoked_spending_ucan_store` OnceLock + `global_revoked_spending_cids` ArcSwap →
  `hydrate_revoked_spending_ucans` wired into restore_on_startup (propagated with `?` =
  fail-closed) → ActorDeps.global_revoked_spending_cids → gate. ✓
- Union gate: `ContextRevocationChecker{revoked_cids, global_revoked_cids}` is_revoked =
  per-ctx OR global. Threaded through EnforceEconomyRequest + validate_spending_ucan_or_error
  + enforce_economy. ALL call sites populate it keyed by charged DID: send
  (messaging_helpers), join (lifecycle_helpers→enforce_join_economy in lifecycle_logic),
  tools (tools_helpers), saga §7 revalidation (saga.rs validate_ucan_rebind). ✓
- FFI: PyO3 (build_revoked_spending_ucan_store → Option by storage), napi + uniffi
  (protocol_repository.revoked_spending_ucan_store(), always Some via bridge_runtime
  ProtocolRepoVariant). All 3 `ucan_revoke` now pass ENCODED TOKEN (not precomputed CID).
  ✓ WASM N/A. ✓
- Event: SpendingUcanRevokedPayload gains `scope`; both paths emit (ctx via handler, global
  best-effort in supervisor). Round-trip test. ✓
- Capability matrix `revoke`=true×4 UNCHANGED (SDK signature identical, routing internal) —
  no matrix/pipeline_wiring update needed. pipeline_wiring.rs has zero economy assertions
  (pre-existing; nothing to extend). ✓
- Tests: 4 supervisor integration (global cross-ctx before-fail/after-pass, ctx-isolation,
  forged-reject-no-store-mutation, restart-via-hydration) + store units + verify units +
  payload round-trip. ✓

## LOW findings
1. Artifact divergence (fix spec per one-way flow): §19.5 says verification "uses the
   read-only nonce probe," but `verify_spending_ucan_genuine` skips nonce ENTIRELY. Code
   rationale sound (probe enforces ±5min freshness ⇒ would reject any token >5min old at
   revoke). Substantive requirement (side-effect-free, never burn a nonce) is MET; spec
   sentence is imprecise — reword to "does not consult the nonce tracker at all."
2. scp-node self_host.rs passes `None` for the store. scp-node's ONLY supervisor is the
   co-located deploy/publish loopback (create_context + publish_assets; no economic_policy,
   no send-with-spending, no enforce_economy anywhere in scp-node src). N/A today; latent —
   if scp-node ever hosts paid-action contexts, global revocation is un-recordable (Global
   revoke → NotInitialized = fail-closed). Store is trivially wireable from the node's
   durable backend if that day comes.

Related: [[spending-ucan-revoke-actor-gate]] (the prior per-context-only slice this
completes).
