---
name: owned-identity-did-gate-removal
description: P6 review — deleting check-owned-identity-did.py gate, replacing with #![deny(non_local_definitions)]; boundary holds vs untrusted code but lint overclaims coverage
metadata:
  type: project
---

# OwnedIdentityDid gate deletion (worktree p6-bh @ b8b648339)

The source-text CI gate `scripts/check-owned-identity-did.py` (+ fixtures + CI job) was DELETED, replaced by `#![deny(non_local_definitions)]` in `crates/scp-runtime/src/context/supervisor/mod.rs`. Capability = `pub(in crate::context) struct OwnedIdentityDid { did: DID }`, minter `pub(super) const fn issue_for_actor`, plus `reissue(&self)` / `as_did(&self)`.

**Why:** the team's position — type system (private field + pub(super) ctor + crate forbid(unsafe_code)) + 2 module lints + code review supersede a bespoke scanner.

**How to apply (verified with compiling PoCs, CARGO_TARGET_DIR=/tmp/p6bh, cargo build -p scp-runtime):**

- BOUNDARY HOLDS vs untrusted `crate::context::actor::handlers`: struct-literal (E0451 private field), direct `issue_for_actor` (E0624 pub(super)), body-nested impl (E0451), nested-module-in-fn from handlers (E0451 — handler tree not a descendant of identity_capability). reissue takes no DID. No untrusted forgery compiles.
- FINDING (doc overclaim, NOT reachable exploit): `non_local_definitions` covers ONLY the body-nested-IMPL form. These "second minter inside identity_capability.rs" forms COMPILE CLEAN with no lint: (1) body-nested free fn, (2) body-nested module, (3) top-level trait-impl minter `trait Forger{fn forge(d:DID)->Self} impl Forger for OwnedIdentityDid` (= the BLACK-G01 vector the deleted gate was built to catch). All require editing the review-owned 155-line file → acceptable/review-owned, not review-invisible.
- LINT SCOPING: `#![deny(non_local_definitions)]` is scoped to where the offending impl is WRITTEN, not where the type is defined. A body-nested impl in actor::handlers produced only a WARNING, not the denied error (forgery stopped by private field, not lint). Lint protects only descendants of supervisor/.
- Net: gate removal downgrades mechanical coverage of in-file second-minter forms to human review. Recommend tightening mod.rs/identity_capability.rs docs to stop claiming the lint is a complete mechanical backstop (a future maintainer could merge a trait-impl minter believing CI catches it).
