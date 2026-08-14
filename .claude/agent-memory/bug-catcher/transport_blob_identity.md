
## check-owned-identity-did.py _shadows_before item-scope (Jun 2026, commit e5a2d9c34)
- HIGH false-positive REGRESSION: the four item arms (const/static/fn/use) were lifted OUT of the `n.start_byte < before_byte` guard and matched UNCONDITIONALLY over the whole-body walk. But `_walk` recurses into ALL descendant scopes (nested blocks, nested fn bodies, closures). Rust ITEM names are block-scoped, NOT whole-fn — a `const owning_did` inside a nested `{}` block / nested helper fn / closure / if-block does NOT shadow the outer-scope mint (rustc-confirmed: mint still uses the real param). Gate flags the legit mint anyway → production-fails false positive on idiomatic Rust.
- NEW regression for POST-mint nested-scoped items (old byte-guard skipped them); pre-mint nested-block items were already FP pre-commit.
- Fix: only match an item as a shadow if it is a DIRECT statement of the SAME block scope as the mint (or an enclosing block up to fn body), not any descendant block/fn/closure. The "order-independent over the WHOLE block scope" claim is true only for items at the mint's own block level.
- macro/glob bans (_body_has_macro_invocation/_body_has_glob_use) walk whole body → catch nested ones too (over-broad fail-closed = SAFE direction, no FN).
- Not currently CI-blocking (production build_actor_deps has no nested same-named item) but latent gate fragility.
