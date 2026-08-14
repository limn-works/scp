---
name: owned-identity-did-gate-use-alias-bypass
description: CRITICAL forgery bypass in check-owned-identity-did.py — `use X as Alias` import alias evades F.2 + impl-target + struct-literal detection
metadata:
  type: project
---

# OwnedIdentityDid CI gate — import-alias forgery bypass (CRITICAL)

Gate: `scripts/check-owned-identity-did.py` (ADR-049 §5 capability token).
Declaring file: `crates/scp-runtime/src/context/supervisor/identity_capability.rs`.

**Bypass:** inject into the declaring file:
```rust
use self::OwnedIdentityDid as Alias;
impl Alias { pub(in crate::context) fn forge(did: DID) -> Self { Self { did } } }
```
Gate exits 0 (PASS). Compiles AND runs — handler code in sibling `crate::context::actor`
calls `cap::OwnedIdentityDid::forge(attacker_did)` and mints a token for ANY DID.
Variants A (`-> Alias { Alias{did} }`), B (`-> Self { Self{did} }`), C (free fn
`fn forge(did)->Alias{Alias{did}}`) all bypass + compile + run.

**Root cause — 3 blind spots, all keyed on literal tail identifier `OwnedIdentityDid`:**
1. F.2 (`cap_aliases`) only collects `type_item` nodes (`type X = OwnedIdentityDid`).
   A `use ... as` import alias is a `use_declaration`/`use_as_clause`, NOT a `type_item` —
   never collected. Gate has ZERO `use`/`use_as_clause` handling (grep confirms).
2. `_impl_for_owned_identity_did` extracts impl-target tail; `impl Alias` tail = `Alias`
   != TYPE_NAME → returns None → `forge` never enters `ctor_fns` → escapes allowlist (G).
3. `_struct_expr_constructs_cap`: `Alias { did }` tail = `Alias` != TYPE_NAME and != `Self`
   → False. For `Self { did }` form, the Self-arm calls `_impl_targets_cap` on the nearest
   impl whose target tail is `Alias` != TYPE_NAME → False. Rule H never fires.

**Fix direction:** resolve `use ... as` import aliases (collect `use_as_clause` whose
path tail is `OwnedIdentityDid`, map alias->cap) and feed the alias name into
TYPE_NAME-matching for impl-target detection, struct-literal construction (rule H),
and the F.2 alias ban. Same airtight-closure logic the gate applies to `type` aliases
must extend to import aliases. Self-test needs a new fixture mode for this.

Tree-clean probe protocol: inject via python heredoc, `python3.12 scripts/check-... ; echo $?`,
`git checkout -- <file>`. rustc repro proves compile+run (single-file crate with
`mod context { mod supervisor { mod identity_capability }, mod actor }`).
