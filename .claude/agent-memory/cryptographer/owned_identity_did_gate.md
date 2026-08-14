# OwnedIdentityDid capability-token CI gate (scripts/check-owned-identity-did.py)

Type-system cap token (ADR-049 §5, spec §9.4.1). Mint = `pub(super) issue_for_actor` (sole arbitrary-DID minter); `reissue(&self)` clones held token; field `did` module-private; struct name-vis `pub(in crate::context)`; `#![forbid(unsafe_code)]`. Gate = defense-in-depth over SOURCE TEXT (tree-sitter AST). Primary boundary is the type system, NOT the gate.

## Branch chore/2e-gate-followup (HEAD 86c50b530) — rule J + cfg(test) exempt
Rule J = BY-VALUE CAP-RETURN BAN across whole supervisor subtree (`SUPERVISOR_SUBTREE_REL`). Flags any `function_item` whose return_type mentions cap NOT solely behind `&`. EXEMPT: top-level inherent `issue_for_actor`/`reissue` in declaring file + `#[cfg(test)]` items. Closes the literal-free re-export of the mint that rules H (struct-literal scanner) and G (inherent-only) miss.

## VERIFIED COMPLETE (empirically, via _return_mentions_cap_by_value probes)
- direct `-> Cap`, `Option<Cap>`, `Box<dyn Fn(DID)->Cap>`, `impl Fn()->Cap`, `fn(DID)->Cap`, `impl Iterator<Item=Cap>`, `(Cap,u8)` ALL flagged. The task's "6th way" (closure/future returning `impl Fn()->Cap` whose body calls mint) IS CLOSED.
- `&Cap` / `impl Fn()->&Cap` correctly NOT flagged — a borrow can't mint; only owned Cap is the capability. Right boundary.
- Operator overloads (Deref::deref/Index::index) return `&Target` by contract → can't yield owned cap; also on rule-D forbidden-impl blocklist anyway.
- reissue exemption SOUND + non-wideable: rule G independently forces `reissue` to take `&self` and NOT a raw DID. Possession of `&self` proves prior supervisor attestation; clone ≡ holding token twice. No arbitrary mint.
- cfg(test) exemption SOUND: `_attr_is_cfg_test` correctly treats only all()-reached `test` as exempt; pervasive `cfg(any(test, feature="testing"))` (ships in testing-feature build) is NOT exempt. `#[cfg(test)]` items never linked into shipped cdylib/staticlib → outside handler-reachable TCB.

## RESIDUAL FORGERY — associated-type-projection return (MEDIUM, confirmed by staging real file in subtree, gate PASSED)
`_is_associated_type` (line 833) EXCLUDES `impl Carrier for u8 { type Out = OwnedIdentityDid; }` from F.2 alias ban claiming "creates no -> Out forgery vector." WRONG. A handler-reachable `pub(in crate::context) fn forge(d: DID) -> <u8 as Carrier>::Out { OwnedIdentityDid::issue_for_actor(d) }` in any supervisor-subtree file: rule J keys on return_type TEXT = `<u8 as Carrier>::Out` (no cap tail) → MISS; rule D inspects trait-impl function_items not `type Out=` bindings → MISS; rule H no struct literal → MISS; F.2 explicitly excludes → MISS. Staged `_probe_assoc_forge.rs` under supervisor/ → `check PASSED` exit 0. Same as `Self::Out` projection inside a cap impl. Fix options: (a) collect associated-type bindings whose RHS tail is the cap and ban a fn returning a projection that resolves to such a binding, or (b) make rule J resolve `<_ as Trait>::Assoc` / `Self::Assoc` projections against in-tree `type Assoc = Cap` bindings. The F.2 exclusion rationale at lines 237-240 / 838-841 is the root defect.
