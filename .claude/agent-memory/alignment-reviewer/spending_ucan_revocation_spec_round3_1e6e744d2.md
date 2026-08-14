---
name: spending-ucan-revocation-spec-round3-1e6e744d2
description: Round-3 re-review §19.5 spending-UCAN revocation — round-2 findings fixed; NEW gap = fail-closed-on-unhydrated undocumented + code cites non-existent "§19.5 invariant 1a/3a/3b"
metadata:
  type: project
---

# Spending-UCAN Revocation Spec Round-3 @ branch tip fe092f890 (2026-07-08) — NEEDS DISCUSSION (1 MODERATE gap)

Branch worktree-agent-a32cd09f9850dfdd7. Doc commit 1e6e744d2 + authz commit 854fd24c6 (SCP-ECON-12069 membership gate) + earlier f9c9dc0da/15b70616f (fail-closed hydration). Read code+spec via `git show fe092f890:`.

**RESOLVED from round-2/prior:**
- #1 (§19.5:434 self-contradiction): FIXED. New text names `verify_spending_ucan_genuine` (sig+iss==aud+key-scope), frames it as reusing shared `crypto/ucan/validate.rs` PRIMITIVES the gate's fuller `validate_spending_ucan_signed` also uses, "deliberately NARROWER... neither nonce probe nor expiry." Consistent w/ :439. ✓
- #2/4d (per-context "bounded by authz" over-claim): FIXED in spec §19.5:437 AND store module doc (revoked_spending_ucans.rs:71-88): now "accepted-unbounded convergent property, NOT bounded by authz; membership=defense-in-depth on WHO can flood, not a size bound; principled bound=separate mechanism issue #2072." Does NOT claim to solve #2072. ✓
- #3 hydrate-ordering doc: ACCURATE — `restore_on_startup` calls `hydrate_revoked_spending_ucans().await?` as VERY FIRST step, before restore_all_contexts + replay_unresolved_sagas (fail-closed by construction). Field doc "Hydrated at STARTUP not construction" accurate. ✓
- #3 from_handle→from_encrypted_handle: ACCURATE — from_handle<S:Storage> sets store None (supervisor.rs:1508); from_encrypted_handle<S:EncryptedStorage> sets Some (:1534). ✓

**FINDING (MODERATE, spec gap / phantom provenance) — #4:** The fail-closed-on-unhydrated GLOBAL-scope invariant is IMPLEMENTED + enforced in code but NOT described in spec §19.5. Code: `GlobalRevocationHydration` enum (NotConfigured/Hydrated=status_known→may proceed; NeedsHydration/Failed=unknown→fail closed); `ContextRevocationChecker.global_scope_status_unknown` (required field, no default) makes `is_revoked()` return true at the single shared chokepoint (economy_logic.rs:158-176); computed in `validate_spending_ucan_or_error` (:221) + saga xctx re-validation; `ActorDeps::global_revocation_status_known` (deps.rs:276). Spec §19.5:455 hydration paragraph states ONLY the happy path ("hydrated from the durable store at instance startup") — silent on: configured-but-unhydrated / hydration-failed global cache MUST reject global-scope spends (incl. contexts joined after failed hydration). Also multiple code docs cite "spec §19.5, invariant 1a / 3a / 3b" but §19.5 enumerates NO numbered invariants — broken provenance (code→non-existent spec item). FIX: add fail-closed-on-unhydrated invariant to §19.5 + enumerate referenced invariants (or drop the "invariant N" citations). This is the flip side of over-claim: code grounds itself in a spec item that isn't there. Coordinator Q#4 answer: spec SHOULD describe it; currently does NOT (a gap, nothing inaccurate written).

**LOW (precision):** §19.5:437 "authorized ONLY for the token's issuer, the scope-context creator, or a current context member" reads as 3 independent sufficient roles, but code (economy.rs handle_revoke_spending_ucan) = creator OR (issuer AND member): non-member issuer rejected (12069), non-issuer/non-creator member rejected (12067). As "ONLY for" upper-bound not false, but could mislead. Practically-authorized = token issuer (if member) or scope-context creator.

Verdict: NEEDS DISCUSSION. Items #1-#3 fully resolved; #4 is a spec gap.
