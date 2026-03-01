# Delegation Chains Require Full Validation at Every Link

**Rule**: When walking a delegation chain (UCAN proofs, certificate chains, authorization chains), every intermediate token must be validated with the same rigor as the leaf token -- including expiry, revocation, and signature verification. Checking only structural linkage (aud/iss matching, signature) is insufficient.

**Context**: The UCAN `verify_chain_recursive` function verified parent tokens for signature validity, aud/iss linkage, and circular delegation, but did not check parent token expiry or revocation. This meant revoking a root delegation token had no effect on downstream delegated tokens -- the revocation was invisible to the chain walker. Spec section 7.2 explicitly requires "Token hasn't expired" and "Token hasn't been revoked" for all tokens in the chain, but the implementation only enforced these at the leaf level (steps 10 and 11 of the validation pipeline).

**Fix**: Thread the `RevocationChecker` through the recursive chain walker and call `verify_expiry` and revocation checks on each parent token during traversal.

**Lesson**: When a validation pipeline has N steps and a recursive component, audit whether the recursive component applies all N steps or only a subset. Structural checks (linkage, signatures) are the obvious ones to implement recursively; temporal checks (expiry) and state checks (revocation) are easy to overlook because they feel like "leaf-level concerns" -- but they apply to every link.
