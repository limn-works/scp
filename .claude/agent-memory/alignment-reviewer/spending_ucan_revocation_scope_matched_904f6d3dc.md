---
name: spending-ucan-revocation-scope-matched-904f6d3dc
description: Alignment review of scope-matched spending-UCAN revocation — spec 72817f104 §19.5/§19.6.1 vs code 904f6d3dc; phantom-sync corrected, one nonce-probe spec drift
metadata:
  type: project
---

# Scope-matched spending-UCAN revocation — spec 72817f104 + code 904f6d3dc (2026-07-08) — ALIGNED w/ 1 spec fix

**Why:** Prior spec amendment 905cc349b claimed the global revocation store "rides the identity/{did}/ ProtocolRepository sync that carries the spending ledger" — phantom convergence (no cross-device identity sync exists; spending_ledger unimplemented #2070). 72817f104 was the correction to the honest LOCAL model. This review verified the correction landed and the code matches.

**How to apply:** If re-reviewing this slice or §19 economic-governance revocation, the findings below are the state as of 904f6d3dc.

GOTCHA (topology): review target commits 72817f104 (spec) + 904f6d3dc (code) are NOT ancestors of the worktree HEAD (1620de983, a "ceiling" line). The checked-out `.docs/specs/19-economic-governance.md` shows the STALE pre-amendment text (§19.5 short "Revocation:" para, §19.6.1 row still "UCAN token ID, revocation reason"). MUST read via `git show 904f6d3dc:<path>`, never the working tree. Spec IS ancestor of code (spec 01:03, code 03:03 same day) → artifact-flow spec→code respected.

Phantom-sync check: PASS. §19.5 (904f6d3dc) line 448 explicitly "no cross-instance/cross-device propagation ... and none is claimed"; global store keyed `identity/{did}/revoked_spending_ucans/{cid}` described as instance-LOCAL ProtocolRepository, blast radius bounded by 24h expiry (§9.5). No lingering "rides the identity sync" phrasing. 905cc349b not in code lineage.

Code↔spec verified pairs:
- verify-before-revoke: `verify_spending_ucan_genuine` (scp-protocol crypto/ucan/spending.rs:410) = header.validate + is_spending_ucan + iss==aud + validate_key_scope + verify_signature. Reuses shared primitives.
- scope routing: supervisor.rs revoke_spending_ucan (:3482) parses SpendingScope; Context→EconomyCommand::RevokeSpendingUcan→Class-S set; Global→RevokedSpendingUcanStore.record + ArcSwap cache (write-locked) + best-effort leaf.
- union gate: ContextRevocationChecker.is_revoked (economy_logic.rs:145) = per-context OR charged-DID global set.
- store: revoked_spending_ucans.rs key `identity/{did}/revoked_spending_ucans/{cid}`, mirrors adapter_credentials, hydrate at startup.
- payload: SpendingUcanRevokedPayload{token_cid, scope} (scp-event-log payload.rs:198) matches §19.6.1 (scope URI + CID, no reason).

FINDING (MODERATE spec drift — code correct, fix the SPEC): §19.5 line 434 says verification "uses the read-only nonce *probe*" and "reuses ... validate_spending_ucan_signed". Code DELIBERATELY OMITS the nonce probe + expiry (spending.rs:398 doc: ±5min freshness would reject any token >5min old at revoke time — a human revokes tokens granted hours ago). Spec's positive "it uses the read-only nonce probe" is inaccurate and could mislead a future impl into re-adding the freshness-rejection bug. Spec should say verify-before-revoke checks ONLY signature+iss==aud+key-scope, NOT nonce/expiry.

FINDING (MINOR/consistency): §19.5 line 443 "a revocation therefore does not converge across context members" is in tension with line 429 ("convergent governance state") and §19.6.1 line 514 ("commit-ordered and convergent"). For CONTEXT scope the Class-S CID + leaf DO converge to members; what is payer-local is ENFORCEMENT (only payer runs gate) and the GLOBAL authoritative store. Reword to separate data-convergence from enforcement-locality.

OBSERVATION: leaf-emit asymmetry — Context path (economy.rs handler) surfaces append failure to reply; Global path (supervisor.rs) fully best-effort `let _=`. Both keep authoritative store fail-closed. Spec says "MUST emit"; both treat leaf as post-authoritative audit. Acceptable.
