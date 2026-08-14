# OwnedIdentityDid sole-minter gate + doc/governance reconcile (worktree sole-minter, HEAD b369d707a)

Reviewed 2026-06-17. Gate `scripts/check-owned-identity-did.py` rewritten to a frozen-shape POSITIVE WHITELIST (1120 lines, down from 2217 on main; lesson cites a ~6000-line peak across the prior ~17-pass arc). Real scan PASS; self-test 35 REJECT + 5 ACCEPT all green.

## Verdict: SOUND for its remit. ONE LOW doc-accuracy finding.

### Gate invariant (correct + complete for a definition-shape gate)
- A1 module-item positive whitelist (use* / 1 struct OwnedIdentityDid / 1 inherent impl / 1 #[cfg(test)] mod tests); ANY other item kind rejected BY KIND (type-alias, free fn, 2nd/trait/path-qualified impl, const/static/macro). Categorical closer — alias/path-qualification cannot evade.
- A2 struct shape: vis EXACTLY `pub(in crate::context)`, single PRIVATE `did: DID`, attrs bare inert built-ins only (no derive — closes all forbidden derives incl one hidden behind interleaved `///` because attrs read from grammar not adjacency).
- A3 impl shape: inherent only, target final-segment OwnedIdentityDid, impl-block attrs inert, BODY positive-whitelist (only function_item + trivia — macro_invocation/const/type/static in impl body rejected BY KIND), EXACTLY {issue_for_actor(pub(super),1 by-val param,->Self), reissue(&self,->Self), as_did(&self,->&DID)}. Modifier subset {const} (reject unsafe/async/extern/gen). Ref-return normalized (path-qualified &scp_identity::DID == &DID).
- A4 location-based name-agnostic struct-literal ban outside the 3 method bodies + test-mod span.
- A5 real-parse TOP-LEVEL `#![deny|forbid(unsafe_code)]` in supervisor/mod.rs (commented/nested-in-fn rejected).
- Type-system division of labor is the ACTUAL boundary: `pub(super)` issue_for_actor + private field + crate `#![forbid(unsafe_code)]` (lib.rs:21) + `#![deny(unsafe_code)]` (supervisor/mod.rs:40). Gate is defense-in-depth over ONE file's definition only.
- My adversarial probes (extern crate, cfg_attr derive, nested-fn minter in method body, macro in method body, forge fn in cfg(test) mod, cfg(test) extra method in prod impl) all behaved correctly. Accepted cases (nested-fn/macro in method body, test-mod forge) are type-system-confined and outside the gate's stated remit — NOT gaps.

### LOW finding (doc over-permits vs gate): reissue/as_did visibility
- Spec §9.4.1 pt1 + ADR-049 §5 line 103 say reissue/as_did MUST be "inherited-private OR pub(in crate::context)".
- Gate REQUIRES EXACTLY `pub(in crate::context)` (method_spec uses REQUIRED_STRUCT_VIS) — rejects inherited-private (proved by probe).
- Worse: inherited-private `reissue` would NOT COMPILE — it's called cross-module from crate::context::actor::deps.rs:264 (clone_for_spawn). So "inherited-private" is not just gate-mismatched, it's a non-viable option for reissue. (as_did called only within supervisor/handle.rs:288/309 so it alone would compile private, but docs lump them.)
- Gate stricter than docs = safe (no security hole), but ADR claims "the CI gate enforces this definition-level allowed-set" implying parity. FIX: tighten spec/ADR to "exactly pub(in crate::context)" (matches reality + gate). Real impl already uses pub(in crate::context) for both (identity_capability.rs:130,142).

### OBSERVATION: lesson "6,000+ lines" is a peak-across-prior-arc figure, not the diff parent (main=2217). Historical narrative, not a diff error.

### Governance docs: SOUND, not self-contradictory
- CLAUDE.md adds check-owned-identity-did.py to protected enforcement list (correct) + anti-over-engineering paragraph (sound/bounded/non-redundant/proportionate + review-pass convergence signal).
- simplifier.md BLOCKER mandate for non-convergent/redundant enforcement — sound.
- NOT in tension with security posture: lesson point 1 "Do not over-apply this" explicitly preserves bounded definition-SIDE checks (same-file type-alias ban) as legitimate; calls over-cutting the "equal-and-opposite failure". The carve-out prevents the policy from being weaponized to delete genuinely-needed sound checks. Fixture `positive` ACCEPT mirrors real type exactly (faithful oracle).
