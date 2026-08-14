---
name: sdk-coverage-failclosed-parity-8c0713499
description: Review of fix/sdk-coverage-fail-closed-and-parity (HEAD 8c0713499) — gate fail-closed + cross-SDK parity + ADR-051; HIGH on identityMigrate doc/test
metadata:
  type: project
---

# fix/sdk-coverage-fail-closed-and-parity @ 8c0713499 (2026-06-19) — NEEDS DISCUSSION (1 HIGH + 2 LOW)

Base 0c8f0b065. 4 changes: (1) MlsCryptoProvider stale doc-comments, (2) cross-SDK parity (TS: 5 identity-lifecycle methods + 4-layer evaluateTrust + bridge evaluateTrust; Python: economy_verify_payment_receipts + discover), (3) check-sdk-coverage.py fail-closed, (4) ADR-051 Proposed.

**Why:** SDK cross-language parity goal + completeness/enforce-mechanically tenets.
**How to apply:** see findings; HIGH is a spec-contradiction baked into a mock test.

## HIGH — identityMigrate doc + test encode WRONG migration semantics (contradicts ADR-003 §4b)
- TS `SCP.identityMigrate` doc (scp.ts): "Migrates an identity to a fresh `#active` key while preserving DID continuity ... (same DID, migrated key)."
- `identity-lifecycle.test.ts:137` asserts `expect(migrated.did).toBe(identity.did)`.
- REALITY (ADR-003 §4b line 375; NAPI identity.rs:782 migrate() → migrate_identity → MigrationOutcome{new_identity,...}; line 833 `let new_did = new_identity.did.clone()`; removes OLD, registers NEW): migration mints a NEW DID (pre-rotation key becomes new `#0` Identity Key), `alsoKnownAs` forwarding on OLD doc, produces a `DidRotationEvent`. It is NOT a `#active` rotation and does NOT preserve the DID — that's `rotateKey`.
- Wrapper also drops the caller's MANDATORY obligation (bridge.ts:658 BridgeIdentityHandle.rotationEventJson doc + spec §3.2.1 step-4b) to distribute rotationEventJson to active members.
- Mock test passes only because mock echoes a fixed handle; asserts a false invariant. This is phantom-correctness (gaming a test to lock in wrong behavior) — the class CLAUDE.md guards against.
- FIX: rewrite doc to "creates a NEW DID via pre-rotation reveal, returns rotation event caller MUST distribute"; surface rotationEventJson on the Identity wrapper; correct test to assert NEW-DID + rotation-event presence.

## Verified ALIGNED
- MlsCryptoProvider doc-comments: accurate. No crypto trait exists (grep empty) — inherent methods; "default impl/override" language was stale, correctly removed.
- Gate fail-closed: ran on branch worktree → EXIT 0, 221 ops, unmatched-true=0, false-w/o-exempt=0, coverage-exempt=1. WARNING→ERROR for true-cell-no-symbol is real teeth; `coverage_exemptions` is a closed allowlist requiring written reason (aligns with closed-allowlist guidance). `_EXTRA_ALIASES` deep-merges (append-only, never overrides).
- Alias honesty (gate passing proves AST found them; spot-checked): governance_approve, contextGovernanceApprove, McpClient, withSqlite(Scp.kt:1704), economy_verify_payment_receipts(scp.py:1686), discover(discovery.py:104) ALL real on branch. add_relay_url underlying claim TRUE: uniffi TransportManager.addRelay (bridge.rs:2781/2777 "Generated as class TransportManager in both Swift and Kotlin"); python transport_add_relay + ts transportAddRelay resolve via alias.
- TS 4-layer evaluateTrust: faithful port of python trust.py evaluate_trust (classification prefixes, _PASSED_BEFORE map, optimistic-then-falsify, catch-only UcanPermissionError/ContextError). actor_did snake_case filter matches python.
- Python discover: module-level free fn (context_discover is #[pyfunction] free export) — consistent with create_query/normalize_address pattern.
- ADR-051 diagnosis ACCURATE vs §9.7.4.1 §3-§5: substrate isolation IS required; cited source lines verify (PyO3 identity.rs:819 InMemoryPreRotationCustody; UniFFI generate_ephemeral_ed25519_seed + honest "Substrate isolation NOT yet satisfied" comment; import_ed25519_signing_key fail-closed). Status Proposed, open questions for review — correct artifact-flow (ADR before code).

## LOW
1. ADR-051 coverage_exemptions cites bindings/kotlin/.../internal/uniffi/scp/scp.kt — that generated UniFFI file is NOT committed (build-time). Claim is true post-generation but path is unverifiable from source; `addRelay` appears nowhere in committed Kotlin. Consider citing the Rust source (bridge.rs:2781) instead.
2. economy_verify_payment_receipts wrapper doc correctly warns "invalid-but-reachable receipt still carries ok==true, inspect valid/all_valid not ok" — good misuse-resistance note; verify the per-bridge result shape actually matches across SDKs if/when TS/Swift/Kotlin add it (currently python-only addition).

## LESSON (reusable)
The sdk-coverage-verifier subagent read the WORKING TREE which was on `main`, NOT the branch — it reported "_EXTRA_ALIASES/coverage_exemptions don't exist" + "14 dead aliases", ALL void (those are main's old ALIASES table + WARNING gate). Confirmed via `git rev-parse --abbrev-ref HEAD`=main. FIX: for gate/script reviews, create `git worktree add --detach /tmp/x <branch>` and run the tool THERE; never trust a reviewer whose findings contradict your own git diff. (Matches feedback_reviewers_check_branch + lesson_isolation_worktree.)
