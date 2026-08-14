---
name: project-owned-identity-did-gate-rule-k
description: OwnedIdentityDid CI gate (ADR-049 §5) rule structure A–K; rule K mint-call containment model and scope
metadata:
  type: project
---

`scripts/check-owned-identity-did.py` (~3924 lines, Python + tree-sitter, NOT bash) is the `OwnedIdentityDid` capability-token CI gate enforcing ADR-049 §5 / spec §9.4.1. It is an enforcement file — only ADDITIVE coverage-expansion is a permitted modification.

**Why:** the cap token proves an actor owns an identity; forging one defeats cross-identity isolation. Gate is mechanical defense-in-depth over the source-text surface; the PRIMARY boundary is the Rust type system (`issue_for_actor` is `pub(super)`, field `did` private, `#![forbid(unsafe_code)]`).

**Rule map (A–K):**
- A=location pin (declaring file only), B=struct name-vis `pub(in crate::context)`, C=forbidden derives, D=forbidden manual + custom-trait mints, E=private fields, F.1–F.5=struct-only (rejects type-alias/enum/union/generic), G=closed inherent allowlist {issue_for_actor, reissue, as_did} BY NAME (closes BLACK-G01 return-disguise), H=struct-literal construction allowlist (module-privacy closure), I=in-file nested-mod ban, J=by-value cap-return ban (subtree), **K=mint-call containment**.
- **Rule K** (commit 9abd6e41a): bans every CODE REFERENCE to `issue_for_actor` in the supervisor subtree (`crates/scp-runtime/src/context/supervisor/`) except: (a) the mint's own `fn` definition, (b) the one call in `Supervisor::build_actor_deps` (structural check: enclosing fn name + impl target == `Supervisor`), (c) `#[cfg(test)]`. Also bans `use …issue_for_actor as X` rename. AST-node-keyed (`identifier`/`scoped_identifier`), immune to comments/strings. Model = "gate the operation not the output" — categorically closes return-type disguises (assoc-type/trait-method projection, `impl Sized` opaque) that rule J (return-type-text-keyed) can't fully see.
- Scope bound is correct: rule K's `rel.startswith(SUPERVISOR_SUBTREE_REL)` == the mint's `pub(super)` reachability.

**How to apply:** when reviewing changes to this gate, verify additive-only (every removed `decls` tuple-unpack must be replaced by a WIDER tuple). Self-test `--self-test` exercises 46 modes incl. 4 rule-K (assoc-type/trait-method/opaque/use-rename); CI runs it before the real scan. Fixture: `scripts/tests/owned-identity-did-fixture.rs`.

**Known doc gap (as of 2e-followup branch):** rule K has NO top-level `(K)` header in the "WHAT THIS CHECKS" enumeration (A–J have headers); the COVERS list in COVERAGE BOUNDARY omits K; exit-code-1 docstring omits K's failure mode. Functionally complete + self-tested, but the canonical rule enumeration under-documents K. Flag on any future review.

Real code (`identity_capability.rs`): `issue_for_actor` `pub(super) const fn(DID)->Self`; `reissue` `pub(in crate::context) fn(&self)->Self`; `as_did` `pub(in crate::context) const fn(&self)->&DID`. All match spec/ADR/gate exactly.
