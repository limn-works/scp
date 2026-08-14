---
name: owned-identity-gate-declaring-file-has-macros
description: check-owned-identity-did.py macro rule — declaring file uses assert_eq! so "ban all macros there" false-fails; ban macro_rules defs + cap-type-referencing invocations only
metadata:
  type: project
---

`scripts/check-owned-identity-did.py` (ADR-049 Phase 2E `OwnedIdentityDid` capability gate): when adding the macro blind-spot rule (FIX-B), a literal "ban ANY macro in the declaring file" implementation false-FAILS production.

**Why:** the declaring file `crates/scp-runtime/src/context/supervisor/identity_capability.rs` has a `#[cfg(test)] mod tests` that legitimately calls `assert_eq!(token.as_did(), &did)` — those are `macro_invocation` nodes. The Phase-2E re-review task asserted the file "currently has NO macros"; that premise was wrong (assert macros count).

**How to apply:** the false-fail-free declaring-file macro rule is: FAIL any `macro_rules!` DEFINITION there, plus any macro INVOCATION whose text references the `OwnedIdentityDid` token — NOT every invocation. Plain `assert_eq!`/`assert!`/`tracing::warn!` that don't name the cap type are fine. The crate-wide sub-rule (anywhere under src/) only fails macros whose body synthesizes an `impl …OwnedIdentityDid`. Always run the real scan (`python3.12 scripts/check-owned-identity-did.py`) — not just `--self-test` — after touching any rule, because the fixture won't surface a production-file-specific false-positive.

Also in that session: tightened `_takes_raw_did` from `\b[Dd][Ii][Dd]\w*` (false-positived `Didier`/`did_handle`) to `\b(?:DID|Did(?:Id)?)\b`; the mint-name-squat it ostensibly guarded is already caught by the NAME allowlist (G.0), so the broad tail bought nothing.
