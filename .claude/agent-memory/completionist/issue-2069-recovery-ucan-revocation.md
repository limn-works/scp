---
name: issue-2069-recovery-ucan-revocation
description: Adjudication of branch fix/2069-f2-revoke-ucans-fail-closed @46d18af7a against GitHub issue #2069 (§9.12 compromise-recovery UCAN revocation is inert) — verdict INCOMPLETE, nullifier removed but capability absent
metadata:
  type: project
---

Branch `fix/2069-f2-revoke-ucans-fail-closed` @46d18af7a does **NOT** close #2069. It severs
the nullifier and leaves the capability honestly absent — a correct but strictly partial move.

**Why:** #2069 demands (A) a scope+timestamp-aware revocation predicate at BOTH gates, or (B)
CID enumeration at recovery time, plus a regression test proving a token from key K is rejected
at `validate_ucan` AND the paid-action spending gate after K is recovered. The branch does
neither; it makes `ProductionRecoveryBackend::revoke_ucans` return
`Err(UcanRevocationUnwired)` unconditionally.

Verified facts (re-verify against HEAD before reusing):
- Neither gate changed: `crates/scp-protocol/src/crypto/ucan/revoke.rs:431` and
  `crates/scp-runtime/src/context/economy_logic.rs:132` are untouched by the branch diff and
  remain exact-CID lookups.
- Zero new `{key_scope, revoked_before_ts}` store/type/field in `git diff origin/main...HEAD`.
- Marker string `"recovery:{ctx}:scopes=..:before=.."` is gone from shipped code (survives only
  in a rustdoc at `crates/scp-runtime/src/identity/recovery.rs:1851`).
- **Whole §9.12 orchestrator is production-dead.** `ProductionRecoveryBackend` is constructed
  ONLY inside its own `#[cfg(test)]` module (starts :2262); `CompromiseRecoveryOrchestrator` /
  `execute_recovery` have zero non-test callers. All three FFI bridges fail closed with
  `SCP-IDENT-1022` before ever building an orchestrator (`crates/scp-ffi/src/identity.rs:2641`
  — pre-existing on main).
- With the shipped backend, `execute_recovery` can now NEVER return `Ok`: step 4
  (`rotate_key_packages`) also fails closed and its error short-circuits ahead of the
  `AllContextsFailed` guard (`recovery.rs:1294`).
- Doc claim "`governance.revoked_spending_ucan_cids` has 41 references and ZERO writes,
  permanently empty by construction" is substantively TRUE (only 2 `.insert()` sites, both in
  `supervisor.rs`'s `#[cfg(test)]` module at :23085/:24395), but literally imprecise — those two
  writes exist, and `lifecycle_helpers.rs:2606` carries the set in from a signed export.
- Doc claim "`ucan_revoke` → `core_revoke_ucan` is a live shipped write path" is TRUE across
  all three bridges (PyO3 `scp-ffi/src/ucan.rs:756`, NAPI `napi/src/ucan.rs:702`, UniFFI
  `uniffi/src/bridge.rs:15757`), read back by `BridgeRevocationChecker`
  (`scp-ffi/common/src/resolvers.rs:701`).

**How to apply:** treat #2069 as OPEN. The remaining work is the revocation-model change
(blanket predicate at both gates + a runtime-side write path, #2072) plus the two-gate
regression test. Do not accept "fail-closed" as closure for an issue whose ask is a mechanism.

Related: [[bounded-reply-await-sweep-core]] (same lesson — verify the sweep, not the self-report).
