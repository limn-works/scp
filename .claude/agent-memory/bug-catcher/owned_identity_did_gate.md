# check-owned-identity-did.py gate (ADR-049 §5) — review notes

Tree-sitter AST gate over the `OwnedIdentityDid` capability type.
File: scripts/check-owned-identity-did.py. Fixture: scripts/tests/owned-identity-did-fixture.rs.
CI job `owned-identity-did` (ci.yml ~L318) runs --self-test then real scan; always runs.

## Reviewed commit cbff86a64 (harden gate + fix doc anchors)
Added: F.3 enum reject, F.4 union reject (union_item now collected), F.5 generic reject
(_is_generic_decl keys on type_parameters field), reissue/as_did accessor-vis bound
(_is_context_visibility regex, whitespace-tolerant), dynamic self-test mode message.
Repointed all ADR-049 anchors to §5 (real heading "### 5. OwnedIdentityDid: ...").
Spec §9.4.1 point-1 + ADR §5 reissue-bound sentence added; spec<->ADR now consistent.

## Verdict: NO BUGS. Self-test = 29 modes PASS, real scan PASS, ruff check PASS.
Probed correct: each non-struct form fails via own branch; generic struct/enum/union/tuple/
const-generic/lifetime-only/multiline rejected; _is_context_visibility rejects
crate::context::handlers, crate::contextual, mycrate::context, pub(crate), pub; accepts
spaced crate :: context; accessor-vis flags pub/pub(crate)/pub(self) reissue/as_did, not the
pub(super) mint; generic doesn't suppress field/other checks.

## Non-defects noted
- Substring containment 'forbidden derive' in 'forbidden derive(s): Deserialize' in
  REQUIRED_FIXTURE_FAILURES is benign — both modes independently triggered by fixture.
- ruff format --check would reformat script BUT pre-existing on main AND not CI-enforced
  (ci.yml L606 runs with working-directory bindings/python; repo-root scripts/ out of scope).
- pub(self) reissue rejected as too-broad: fail-closed, not a hole.
