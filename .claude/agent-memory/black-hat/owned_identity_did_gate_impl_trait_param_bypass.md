---
name: owned-identity-did-gate-impl-trait-param-bypass
description: BLACK-G02 — check-owned-identity-did.py build-site exemption param-count is laundered by non-DID-tail owning-param types (impl Trait / dyn / assoc-type / wrapper), letting an added attacker:DID param mint a cross-identity cap
metadata:
  type: project
---

# BLACK-G02: build-site param-count laundering via non-`DID`-tail owning param

**Gate:** `scripts/check-owned-identity-did.py` (rule K build-site exemption,
`_mint_call_arg_is_owning_did` + `_param_type_tail`). Commit `aac240349`.

**Bug:** the exemption identifies the "owning binding" by counting params whose
TYPE tail-identifier == literal `DID` and requiring EXACTLY ONE. The generic-fn
case is closed (refuses exemption if `function_item` has `type_parameters`).
But argument-position `impl Trait` is ANONYMOUS generics with NO `type_parameters`
node, and `_param_type_tail` only handles type_identifier/scoped/generic_type —
it returns None for `bounded_type`/`abstract_type` (`impl Into<DID>`),
`dynamic_type` (`&dyn AsRef<DID>`), associated-type (`<Self as OwnId>::T`), and
any renamed wrapper (`&DidWrap`).

**Forgery (gate exits 0):** change owning param to a non-`DID`-tail type and add
a second `attacker: DID` param; mint `issue_for_actor(attacker.clone())`. Now
`attacker` is the SOLE DID param → wrongly pinned as owning binding → EXEMPT.
The cap flows into `ActorDeps.owned_identity` → actor holds a valid
`OwnedIdentityDid` for a DID it does not own = cross-identity break.

All 4 owning-param spellings PASS the gate: `impl Into<DID>+Clone`, `&dyn AsRef<DID>`,
`<Self as OwnId>::T`, `&DidWrap`. Single-param form fails CLOSED (0 DID params →
exemption refused), so forgery REQUIRES the added second DID param (arity change).

**Root fix:** in `_mint_ref_exempt_build_actor_deps`, refuse exemption if ANY
param type is `bounded_type`/`abstract_type`/`dynamic_type`/associated-type (mirror
the generic-`type_parameters` ban), OR assert the owning param's type tail is
EXACTLY `DID` (positive check) rather than counting DID params. The self-test
mode `build_site_generic_param_mint` covered `<...>` on the fn but NOT arg-position
`impl Trait` — add fixture modes for all 4 spellings.

**Repro pattern:** mutate supervisor.rs build_actor_deps sig+mint, run gate, revert.
Type system is PRIMARY (mint stays pub(super)); this is the defense-in-depth net
failing to catch an insider edit in review.
