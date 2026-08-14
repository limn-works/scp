---
name: pr1850-eventlog-phase2-merge-44f2ebeda
description: PR #1850 event-log Phase-2 substrate + clean merge of origin/main #1852 (ADR-039 #agent persona) @ 44f2ebeda — ALIGNED, 0 blocking
metadata:
  type: project
---

PR #1850 alignment review @ HEAD `44f2ebeda` (2026-06-21). Worktree eventlog-phase2. **ALIGNED, 0 blocking misalignments.**

**Structure:** origin/main `b5bf4aafe` IS the #1852 merge commit and is an ancestor of HEAD. Two-dot diff vs origin/main is huge ONLY because merge-base = b5bf4aafe; the real new work past it = merge commit `5df11a2ee` + 3 post-merge saga commits (82fbef9dd guard, d6fb9d13b test, 118f3318c KeyResolver 2-arg test fix, 44f2ebeda nonce-equality doc) + post-merge supervisor.rs (46 lines).

**Verified aligned:**
- Taxonomy closed at **77** variants (test `event_type_taxonomy_is_closed_at_77_distinct_variants` pins it; pruning.rs classification table covers all 77). CrossContextToolInvoked=tag76, CrossContextDivergenceMarker=tag77. lib.rs:93 header reads "77" (NOT stale — earlier Read-tool snapshot showed "76" but on-disk is correct; ALWAYS re-verify Read snapshots against disk/sed).
- Spec coherent: §6.2.4 defines both CrossContext* variants + dual-log recording + divergence-marker preimage (SCP-XCTX-DIVERGENCE-V1 separator §9.5.1). §25 KAT confirms 77 + tags 76/77. ADR-011 amendment exclusion taxonomy (phase-2.md 911-975) explicitly carves CrossContextToolInvoked OUT of the per-author exclusion (commit-ordered, convergent, canonical).
- Convergence-preimage safety: canonical Event has exactly 7 fields, NO signing_key_id (ADR-011 §706 honored). ADR-039 #agent persona signing_key_id lives on the MESSAGE/envelope path (messaging.rs), not in the Merkle leaf bytes — the two PRs compose correctly (leaf signed by resolved persona key, persona id resolved from DID doc by verifier, not in leaf).
- Exclusions enforced: MessageReceived + EquivocationDetected have ZERO append sites in scp-runtime/src.
- Substrate swap complete: no SCP-EXPORT-ENTRY/EventLogEntry impl in runtime; only 2 NEGATING comments ("not a hash-chain head", RFC 6962 tree::root, ADR-050) — correct.
- #1852 intent preserved post-merge: resolvers.rs present, KeyResolver Fn(&DID, SigningKeyId) 2-arg, signing_key_id in messaging pipeline, test closures adapted.
- Cross-layer exemptions (e9c7c558a) map to real cross-crate pub fns: token_revoked_payload (scp-protocol/crypto/ucan/revoke.rs:619), merge_consequence_events (scp-protocol/trust/consequence.rs:744).
- No #NNNN issue-refs introduced in event-log core scope (the bindings/ #NNNN in two-dot diff are pre-existing merge-base artifacts in untouched Python/Swift/TS files).

**Already-dispositioned (did not re-raise):** nonce-equality invariant (44f2ebeda), divergence-marker provenance guard (82fbef9dd), dormant cross-member replication, dismissed #[test] crypto FPs.

**Observation (non-blocking, NOT raised as finding):** phase-2.md illustrative `pub enum EventType` code block (lines 743-839) enumerates only 63 variants and ends at AppUnbound — does NOT list the 2 CrossContext* variants nor several others; it is an illustrative ADR block, NOT the authoritative taxonomy (the crate enum + the closed-set test + §25 + §6.2.4 are authoritative and mutually consistent). ADR illustrative-vs-crate gap, not an enforced-contract contradiction.
