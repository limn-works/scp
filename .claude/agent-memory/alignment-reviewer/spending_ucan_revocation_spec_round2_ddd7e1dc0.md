---
name: spending-ucan-revocation-spec-round2-ddd7e1dc0
description: Round-2 re-review of §19.5/§19.6.1 spending-UCAN revocation spec-vs-code after fix commits f0a99f5e4/ddd7e1dc0 — 1 residual finding
metadata:
  type: project
---

# Spending-UCAN Revocation Spec Round-2 @ ddd7e1dc0 (2026-07-08) — 1 RESIDUAL FINDING

Target: `git show ddd7e1dc0:.docs/specs/19-economic-governance.md` §19.5/§19.6.1 vs code. Fix commits `f0a99f5e4` (accuracy) + `ddd7e1dc0` (GC-split). NOTE: main-repo HEAD had moved to 1620de983; read code via `git show ddd7e1dc0:` explicitly.

**FINDING (MODERATE, spec-only, internal contradiction):** §19.5 line 434 opening clause survived the fix UNCHANGED and now self-contradicts line 439 (added by same commit) + the code. Line 434 says verify-before-revoke reuses "the SAME verification the paid-action gate performs (`validate_spending_ucan_signed`)". But `validate_spending_ucan_signed` is the FULL gate pipeline (nonce probe Step G + expiry Step E + revocation + delegation-chain). The revoke path actually calls `verify_spending_ucan_genuine` (spending.rs:418) → `verify_spending_ucan_genuine_or_error` (economy_logic.rs:232) ← from `Supervisor::revoke_spending_ucan` (supervisor.rs:3594). That fn does ONLY header.validate + is_spending_ucan + iss==aud + validate_key_scope + verify_signature — NO nonce/expiry/revocation. Line 439 correctly says "checks only signature, iss==aud, key scope; deliberately does NOT run the nonce check (not even the read-only probe) OR the expiry check." So 434 and 439 conflict. Fix: line 434 should name `verify_spending_ucan_genuine` and drop "the SAME verification the paid-action gate performs" (gate does strictly more). The spec NEVER names the real fn. Root cause: f0a99f5e4 rewrote the middle+tail of the paragraph but left the opening clause verbatim from the pre-fix (wrong) version. Line 427 correctly names `validate_spending_ucan_signed` as the GATE pipeline — that one is fine.

**VERIFIED ALIGNED (cite pairs):**
- #1 nonce wording (line 439): matches verify_spending_ucan_genuine — ✓ (but see finding re 434).
- #2 convergence (line 451 "Data convergence (differs by scope)"): separates context-scoped (converges via Class-S set + convergent SpendingUcanRevoked leaf) from global (DID-scoped, local, non-convergent); enforcement stays payer-only. ✓
- #3 GC-split: global store (line 436) expiry-GC pruned on insert (record_revoked_spending_ucan→prune_moot_revoked_spending_ucans) AND hydration (load_all_revoked_spending_ucans deletes moot) — revoked_spending_ucans.rs:143/172/224. Per-context Class-S (line 437) NOT time-GC'd — GovernanceState.revoked_spending_ucan_cids is plain HashSet<String> (state.rs:890), no pruning. Module doc revoked_spending_ucans.rs:35-62 correctly scopes GC to global-only. ✓ ACCURATE, not over-claim.
- #4 false "self-limiting": line 434 now NEGATES it ("does NOT make them self-limiting"); only appears inside negating sentence. Also negated in spending.rs:404 + store module doc. ✓ removed.
- #5 SpendingUcanRevokedPayload (payload.rs:198): fields token_cid + scope = spec §19.6.1 line 522 "SpendingScope and revocation CID"; no reason field. Global best-effort-to-requesting-context + non-authoritative attribution documented (supervisor.rs:3505-3512, spec line 524). ✓
- Per-context flood NOT claimed solved: line 437 "residual remains and is not closed here ... separate convergent mechanism, tracked as its own work item; this section does not claim to solve it." ✓ (points at #2072, doesn't assert fix).

Verdict: NEEDS DISCUSSION — one spec-text fix (line 434 opening clause). Code fully aligned.
