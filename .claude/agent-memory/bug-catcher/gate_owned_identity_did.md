# check-owned-identity-did.py gate — known blind spots (reviewed 2026-06-17)

Gate: `scripts/check-owned-identity-did.py` (tree-sitter-rust positive-whitelist for OwnedIdentityDid def shape).
Branch chore/owned-identity-sole-minter-gate HEAD ede6df05e. Self-test + real scan + ruff + pyright all pass.

Findings (in the A3 per-method signature matcher, lines ~628-675):
- **HIGH false-neg: receiver mode unchecked.** `_fn_param_kinds` returns tree-sitter node TYPE; `&self`, `&mut self`, by-value `self` are ALL kind `self_parameter`. So `reissue(&mut self)` / `reissue(self)` / `as_did(&mut self)` all ACCEPT though A3 requires exactly `&self`. Fix: emit `self_parameter:&self` etc. (text-disambiguated).
- **MEDIUM false-neg: fn modifiers unchecked.** No inspection of `function_modifiers` node. `unsafe fn issue_for_actor`, `async fn reissue`, `extern "C" fn reissue` all ACCEPT. unsafe-mint directly contradicts A5 deny(unsafe_code).
- **MEDIUM false-pos: path-qualified ref return.** Line 665 normalizes path only when `"::" in ret and "&" not in ret`. `as_did -> &scp_identity::DID` has both → not normalized → REJECTED (but field `did: scp_identity::DID` is accepted — asymmetric). Fix: strip leading `&`/lifetime then final-segment.
- **LOW false-pos: cfg(all(test)).** `_attr_args` (lines 316-329) only extracts top-level token_tree identifiers; `cfg(all(test))` → `['all']`, `test` nested deeper unseen → mod tests rejected. Need recursive `_attr_args_deep` for `_mod_has_cfg_test` ONLY (not for derive detection).
- **LOW false-neg: A5 nested inner-attr.** `_has_deny_unsafe_code` uses `_walk` over whole tree; a `#![deny(unsafe_code)]` nested inside a fn body in mod.rs satisfies it though it's block-scoped not module-wide. Fix: iterate `root.children` (top-level) only.

ROOT CAUSE pattern: docstring claims "EXACT signature" but self-test only asserts REJECT/ACCEPT outcome; NO fixtures probe receiver-mode, fn-modifiers, or path-qualified returns → exactness gaps uncaught. When reviewing tree-sitter gates that match node KIND: verify node-kind != semantic-distinction (self_parameter collapses 3 receiver modes; modifiers live in a separate child node).
