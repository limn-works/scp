---
name: gate-owned-identity-did-e5a2d9c34
description: Adversarial review of check-owned-identity-did.py at commit e5a2d9c34 (build-site mint shadow detection). NO compiling forgery found; type-system primary defense sound.
metadata:
  type: project
---

# OwnedIdentityDid cap gate — commit e5a2d9c34 (ADR-049 §5)

Reviewed `scripts/check-owned-identity-did.py` (5823 lines, 85 self-test modes) + the type-system primary defense in `crates/scp-runtime/src/context/supervisor/identity_capability.rs`.

**Why:** gate is defense-in-depth; the PRIMARY defense is the type system.
**How to apply:** when re-reviewing this gate, do NOT re-report the closed vectors below; focus on whether a COMPILING forgery escapes.

## Type-system primary defense (the real backstop — SOUND)
- `issue_for_actor(did: DID)->Self` is `pub(super)` → reachable ONLY from `crate::context::supervisor` module. Handlers live in `crate::context::actor` → compiler refuses. SOLE arbitrary-DID mint.
- field `did` PRIVATE → no struct literal `OwnedIdentityDid{did}` outside identity_capability.rs.
- `reissue(&self)->Self` (pub(in crate::context)): clones held DID only, no raw-DID param → can't forge a DIFFERENT DID. Handlers hold only their own token.
- `as_did(&self)->&DID`: read-only of own DID; can't mint (no From<&DID>, no pub ctor).
- Only supervisor-module mint site = `Supervisor::build_actor_deps` (supervisor.rs:1420).

## Vectors TESTED — all blocked or type-system-caught (don't re-report)
1. **struct/enum/union value-namespace shadow** (`struct owning_did;` in body): GATE PASSES (walk omits struct_item/enum_item/union_item) BUT type-system catches it — unit struct has no `.clone()` → DID, and bare is type mismatch. NOT a compiling forgery. This is the one genuine gate-completeness GAP, but non-exploitable (no struct/enum/fn item yields a DID-typed value; only const/static do, both caught).
2. **post-mint const shadow** (`const owning_did:&DID` AFTER mint): CAUGHT — order-independent item-shadow walk (const/static/fn/use matched unconditionally, no byte-order guard). Compiles but gate FAILs.
3. **reissue-internal arbitrary mint** (`Self::issue_for_actor(attacker)` inside reissue): CAUGHT by rule K (only build_actor_deps may reference the mint).
4. **cfg(any(test,feature="testing")) production-active mint** in handle.rs: CAUGHT (rule J by-value-return + rule K mint-ref). `_attr_is_cfg_test` combinator-walker correctly does NOT exempt any()/not().
5. **glob-in-body** (`mod evil{...} use evil::*;`): CAUGHT — `_body_has_glob_use` fail-closed dissolves exemption. (Also glob can't shadow a param anyway.)

## Build-site exemption (`_mint_ref_exempt_build_actor_deps`) gating chain
file-pin → fn name `build_actor_deps` → direct method (function_item->declaration_list->impl_item) → non-generic → impl target tail `Supervisor` → inherent → not nested-mod → no escapable scope between → no macro in body → no glob in body → `_mint_call_arg_is_owning_did` (exactly 1 non-self param spelled `DID`, arg bare/`.clone()` pinned to its name, no shadow before). `_param_binding_name` requires pattern == exactly `identifier` (mut/ref param → None → refused).

## Conclusion: NO compiling arbitrary-DID forgery reachable from handlers. Gate exit 0 + cargo check clean never co-occurred for any forgery. Verification cycle: edit body → `/tmp/test_forge.sh` (gate + cargo check -p scp-runtime, CARGO_TARGET_DIR=/tmp/p16-bh).
