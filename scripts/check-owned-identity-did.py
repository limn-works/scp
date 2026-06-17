#!/usr/bin/env python3.12
# ruff: noqa: E501
"""AST check: enforce `OwnedIdentityDid` capability-token invariants.

---------------------------------------------------------------------------
PREREQUISITES
---------------------------------------------------------------------------
    pip install tree-sitter tree-sitter-rust

Python 3.12+. Runs offline; no network access required.

---------------------------------------------------------------------------
WHAT THIS CHECKS
---------------------------------------------------------------------------
If the `OwnedIdentityDid` type exists anywhere in `crates/scp-runtime/src/`:

  (A) It MUST be declared only in
      `crates/scp-runtime/src/context/supervisor/identity_capability.rs`.
      Any other location is a capability-leak: a handler or other
      runtime module that can name the type's constructor path can
      fabricate tokens and bypass cross-identity isolation.

  (B) The struct declaration MUST be `pub(in crate::context)`. The token
      is held by-value inside `ActorDeps` (in `crate::context::actor`) and
      passed `&OwnedIdentityDid` to `SupervisorHandle` per-identity
      methods, so actor-module code must be able to NAME the type — but
      naming is not constructing. `pub(crate)` is too broad (any module in
      `scp-runtime` could name it in places the capability model does not
      intend); `pub` leaks it to downstream crates. Both are rejected.
      The mint guarantee is enforced by check (G) on the constructor and
      check (E) on the field, NOT by this name-visibility. See ADR-049
      §5.

  (G) CLOSED ALLOWLIST over the inherent API (NOT an open
      classify-by-return-type rule). The capability type has a tiny FIXED
      inherent API. The inherent `impl OwnedIdentityDid` block(s) in the
      declaring file MUST contain ONLY these three fns, BY NAME, each with
      its required shape:
        - `issue_for_actor` — the sole mint. MUST be `pub(super)`. MUST
          take a raw-DID-typed parameter (a parameter whose type contains a
          `DID`/`Did`-prefixed token, case-insensitive). MUST NOT take
          `&self`. (Its return SHOULD be `Self`/`OwnedIdentityDid` — a
          sanity check, NOT the security boundary.)
        - `reissue` — clone path. MUST take `&self`. MUST NOT take a
          raw-DID parameter. Its VISIBILITY MUST be inherited-private or
          exactly `pub(in crate::context)` — never `pub`, `pub(crate)`, or
          any narrower path-restricted form (`pub(super)` / `pub(in
          crate::context::supervisor)`): exactly `pub(in crate::context)` is
          required so `ActorDeps::clone_for_spawn` in the sibling `actor`
          module can call it, and no wider. (Returns `Self`.)
        - `as_did` — accessor. MUST take `&self`. MUST NOT take a raw-DID
          parameter. Its VISIBILITY MUST be inherited-private or exactly
          `pub(in crate::context)` — never `pub`, `pub(crate)`, or any
          narrower path-restricted form — matching the capability struct's
          own name-visibility. (Returns `&DID`.)
        - ANY OTHER inherent fn — any name, ANY return type (including an
          aliased / `impl Trait` / `Result`-wrapped return that hides the
          capability type from a return-type-text check) — is a HARD FAIL:
          `unexpected inherent fn `X``. This is the line that closes the
          BLACK-G01 forgery: a `type OwnedCap = OwnedIdentityDid; fn
          forge(did: DID) -> OwnedCap` (or `-> impl Sized`, or `-> Result<
          OwnedCap, ()>`) is rejected because `forge` is not allowlisted —
          the NAME is the boundary, not the return text. An open
          classify-by-return-type rule would skip `forge` (its return text
          is `OwnedCap`, not `Self`/`OwnedIdentityDid`), letting a
          `pub(in crate::context)` handler mint a token for ANY DID.
      "Exactly one raw-DID mint" is folded in: only `issue_for_actor` may
      take a raw DID; `reissue`/`as_did` (or any other fn) taking a raw DID
      FAILS. The mint MUST exist — a declaring file with no
      `issue_for_actor` FAILS (renamed / gutted mint). Raw-DID detection
      matches the DID TYPE token explicitly (`DID` / `Did` / a future
      `DidId`) so a future `Did`/`DidId` rename cannot evade, while NOT
      false-matching ordinary `Did`-prefixed names (`Didier`, `did_handle`).

      The inherent allowlist is CLOSED EVEN UNDER `#[cfg(test)]`. A
      `#[cfg(test)] impl OwnedIdentityDid { fn test_helper(&self) {…} }`
      adds an inherent fn outside the allowlist and is therefore a HARD FAIL
      — by design, not oversight. A test-only inherent fn is still an
      inherent mint SURFACE (it can construct via the private field from
      inside the module), so the gate keeps the inherent API closed in test
      builds too. Test helpers MUST route through the public
      `issue_for_actor` / `reissue` / `as_did` API (as the existing
      `#[cfg(test)] mod tests` in the declaring file does — it calls
      `OwnedIdentityDid::issue_for_actor(...)` and `token.as_did()`, adding
      NO inherent fn), never add a new inherent fn under a `cfg(test)` gate.

  (H) CONSTRUCTION ALLOWLIST over struct LITERALS (the module-private-field
      closure). Rust field privacy is MODULE-scoped, NOT impl-scoped. Rules
      (A)-(G) all key on `impl OwnedIdentityDid` blocks and on the decl
      itself, so a struct literal of the cap placed OUTSIDE an allowlisted
      inherent fn — e.g. a FREE FN in the declaring file
        `pub(in crate::context) fn forge_token(did: DID) -> OwnedIdentityDid
             { OwnedIdentityDid { did } }`
      — PASSES rules (A)-(G) AND COMPILES (the private `did` field is
      reachable anywhere in the declaring module) AND is callable from handler
      code → forges a token for any DID, defeating cross-identity isolation.
      Variants: a method on a HELPER struct (`impl Forger { fn make(&self, did:
      DID) -> OwnedIdentityDid { OwnedIdentityDid { did } } }`), a closure, a
      nested fn, a trait-impl body — all in the declaring file, all
      (A)-(G)-blind, all type-system-permitted (in-module).

      Rule H finds EVERY tree-sitter `struct_expression` in the DECLARING FILE
      (`REQUIRED_PATH`) that CONSTRUCTS the cap and HARD FAILs any not
      lexically inside the body of an allowlisted constructor. A
      `struct_expression` "constructs the cap" if its type/name tail is
      `OwnedIdentityDid` (incl. a scoped `…::OwnedIdentityDid`), OR it is a
      `Self { … }` literal whose nearest enclosing `impl_item` targets
      `OwnedIdentityDid` (the real `issue_for_actor`/`reissue` use `Self { did
      … }`). For each, the gate walks UP to the nearest enclosing
      `function_item`; if that fn's name is NOT in {`issue_for_actor`,
      `reissue`} OR the fn is not inside an INHERENT `impl OwnedIdentityDid`
      block (a helper-type method, a trait-impl method, or a differently-named
      fn) → HARD FAIL. (`as_did` is NOT a constructor — it returns
      `&self.did` — so it is deliberately excluded from the construction
      allowlist.)

      This is the airtight closure: every Rust construction of the struct
      goes through a `struct_expression` (or a macro — already banned by rule
      B; or an unsafe transmute — banned by `#![forbid(unsafe_code)]`), so
      scanning all cap struct_expressions and allowing only the two inherent
      constructors covers free fns, helper-type methods, closures, nested
      fns, and trait-impl bodies UNIFORMLY. Applied REGARDLESS of
      `#[cfg(test)]` (the real test module constructs via the
      `issue_for_actor` CALL, not a struct literal, so this does not
      false-fail production). SCOPED to the declaring file: in any OTHER file
      the private-field literal would not COMPILE (not a forgery vector
      there), and a `Self { … }` in a foreign-file impl is already covered by
      location check (A) / trait-mint rule (D). The production file's only cap
      struct-literals are `Self { did }` inside `issue_for_actor` and
      `reissue`, both allowlisted, so production PASSES.

  (I) IN-FILE NESTED-MOD BAN (declaring file). Rules (G)/(H) collect every
      `impl OwnedIdentityDid` block and every cap `struct_expression` in the
      declaring file REGARDLESS of nesting (the AST walk recurses through
      `mod_item` bodies), but they classify per-file: a SECOND cap inherent
      impl hosting an allowlisted-NAMED `issue_for_actor` — hidden inside a
      nested `mod` — supplies an allowlisted name (G passes) and an inline
      `Self { … }` whose nearest enclosing fn is that allowlisted constructor
      (H's `in_allowlisted` True), so BOTH wave it through. A literal-free
      module-level wrapper can then re-export the nested mint to all of
      `crate::context`. This is the IN-FILE analogue of the
      `#[path]`-include escape (`_path_attr_escape` polices external files;
      rule I polices in-file nested-mod surfaces). The canonical production
      cap impl + its two `Self { did }` literals are TOP-LEVEL, so rule I
      HARD FAILs ANY cap inherent/trait impl, and ANY cap struct literal,
      nested under a `mod_item` in the declaring file — strictly additive.

  (J) BY-VALUE CAP-RETURN BAN (whole supervisor subtree). A fn that returns
      the cap BY VALUE — WITHOUT a struct literal, by CALLING the
      `pub(super)` mint — re-exports a mint surface that rule H (a
      construction-site scanner: no literal to see) and rule G (inherent
      methods only) both miss. Example:
        `pub(in crate::context) fn forge_for_any(d: DID) -> OwnedIdentityDid
             { OwnedIdentityDid::issue_for_actor(d) }`
      It compiles and is handler-reachable anywhere the `pub(super)` mint is
      reachable — the WHOLE `crates/scp-runtime/src/context/supervisor/`
      subtree. Rule J flags any fn (free fn, inherent method, trait method)
      whose `return_type` MENTIONS the cap by value (the cap tail — or a
      `Self` inside an inherent/trait cap impl — appears in the return type
      NOT solely behind a `&` reference, including inside
      `Option`/`Result`/`Box`/tuples/fn-returns), EXCEPT the two allowlisted
      constructors `issue_for_actor`/`reissue` IN their canonical TOP-LEVEL
      inherent cap impl IN the declaring file, and EXCEPT `#[cfg(test)]`
      items. This is the ONE rule that scans the WHOLE subtree rather than
      the declaring file alone; it is an ADDITIVE multi-file scan for ONE
      anti-pattern and does NOT weaken the declaring-file pin (`REQUIRED_PATH`)
      every other rule keys on. Production PASSES: `issue_for_actor`/`reissue`
      are exempt, `build_actor_deps` returns `ActorDeps` (cap encapsulated,
      not in the return type), `as_did` returns `&DID` (a borrow), and the
      handle.rs test mints are `#[cfg(test)]`-gated.

  (K) MINT-CALL CONTAINMENT (whole supervisor subtree). The CATEGORICAL
      closer for rule (J): instead of recognizing the cap in the EVADABLE
      return-type text — which type-level indirection (associated-type
      projection `<T as Tr>::O`, opaque `-> impl Sized`, etc.) hides from a
      syntactic match — rule K gates the dangerous OPERATION: a CALL to the
      sole arbitrary-DID mint `issue_for_actor`. Every arbitrary-DID forgery
      MUST call the mint (`reissue` only clones an already-held token), so
      banning every code reference to `issue_for_actor` across the subtree
      closes the projection/opaque return-disguise forgeries rule (J) cannot
      see. Flags any `call_expression` / value-path / `use … as` reference to
      `issue_for_actor` under `crates/scp-runtime/src/context/supervisor/`,
      EXCEPT (a) the mint's own DEFINITION, (b) the ONE legitimate call inside
      `Supervisor::build_actor_deps` — pinned to the real build-site FILE
      (`supervisor.rs`) so a fake `impl Supervisor` planted in another subtree
      file is NOT exempt — and (c) `#[cfg(test)]` code. Keys on AST identifier
      nodes, so doc-comments / string literals are never matched. Production
      PASSES: the only non-test, non-definition reference is the real
      `Supervisor::build_actor_deps` call in `supervisor.rs`.

  (C) The declaration MUST NOT carry a `derive(...)` — plain
      `#[derive(...)]` OR conditional `#[cfg_attr(..., derive(...))]` —
      listing ANY of:
      Clone, Copy, Serialize, Deserialize, Default, Hash, PartialEq,
      Eq, Borrow, From, Into, Debug, Display, Deref, AsRef.
      `cfg_attr(..., derive(X))` expands to `#[derive(X)]` at cfg-eval
      time; the two forms are equivalent as far as the capability
      boundary is concerned, and the scanner flags them equivalently by
      extracting every `derive(...)` group from each attribute's text
      regardless of outer wrapper.
      The intent of each non-derive is documented in ADR-049:
        - Clone/Copy: leaks the capability.
        - Serialize/Deserialize: smuggles it across trust boundaries.
        - Default/From/Into: fabrication without the constructor.
        - Hash/PartialEq/Eq: identity set-semantics are not a use case;
          the cap is by-value only at call sites.
        - Borrow/AsRef/Deref: erodes the `&OwnedIdentityDid` contract.
        - Debug/Display: accidental logging of identity tokens.

  (D) A `#[derive(...)]` is not the only way to expand the interface.
      A manual `impl Trait for OwnedIdentityDid { ... }` block for any
      of the forbidden traits above has the same effect — the check
      flags manual impls by walking `impl_item` nodes.
      (D, extended — CUSTOM-TRAIT MINT) A forbidden-trait BLOCKLIST is not
      enough: a CUSTOM trait whose method CONSTRUCTS the cap evades both the
      blocklist (the trait is not on it) and the inherent allowlist (G,
      which inspects only INHERENT impls). Example:
        `trait Forger { fn forge(d: DID) -> Self; }`
        `impl Forger for OwnedIdentityDid { fn forge(d: DID) -> Self {…} }`
      The check collects every TRAIT-impl method and FAILs any that EITHER
      returns `Self`/`OwnedIdentityDid` OR takes a raw `DID` parameter (an
      alternate mint surface), unless the trait is in a tiny explicit
      allowlist of safe constructing traits (currently EMPTY — no
      constructing trait is legitimate for this type). The raw-`DID`-PARAM
      arm is what makes this robust independent of return-type text: a
      return-type-aliased trait mint (`fn forge(d: DID) -> OwnedCap`) dodges
      the returns-Self classifier (BLACK-G01 for inherent fns applies equally
      to trait methods) but is caught by the param check — no legitimate trait
      method on this type consumes a raw `DID` (only the inherent
      `issue_for_actor` does).

  (E) Every field on the struct MUST be private (no `pub`,
      `pub(crate)`, or `pub(super)` on any field). A tuple-struct field
      like `struct OwnedIdentityDid(pub(crate) DidId)` lets handlers
      reach into the inner type and bypass the capability boundary.

  (F) The type MUST be a NON-GENERIC `struct` — NOT a `type` alias, NOT an
      `enum`, NOT a `union`, and NOT a generic struct. This is a POSITIVE
      struct-only assertion: the declared nominal kind is checked to be
      exactly `struct`, the declaration is checked to carry NO type/lifetime
      parameters, and every other form is rejected. The whole capability
      rests on the private-field mint invariant (check E), which is ONLY
      expressible for a `struct` — an enum's variant fields and a union's
      fields are always as visible as the type itself, and a type alias has
      no field at all.
        - (F.1) a `type OwnedIdentityDid = Did` alias — the cap NAME used
          as an alias — erases the nominal distinction and gives every
          consumer of `Did` equivalent power, defeating the capability.
          Type aliases named `OwnedIdentityDid` are banned outright.
        - (F.2) a `type X = OwnedIdentityDid` alias — NAMED something else
          but whose right-hand side IS the capability type — is ALSO banned
          (e.g. `type OwnedCap = OwnedIdentityDid;`). Such an alias is the
          return-type-alias forgery vector: a mint fn could declare
          `-> OwnedCap` to hide the capability return type. The allowlist
          (G) already rejects the forgery fn by name, but the alias itself
          must not exist — defence-in-depth. (An ASSOCIATED-type binding —
          `impl Carrier for u8 { type Out = OwnedIdentityDid; }` — is NOT a
          standalone nameable alias and is excluded: it creates no `-> Out`
          forgery vector, so it is not collected.)
        - (F.3) an `enum OwnedIdentityDid { … }` is REJECTED. The whole
          mint guarantee rests on check (E) — the single field is PRIVATE,
          so the type cannot be constructed outside the declaring module
          and the ONLY construction path is the `pub(super)`
          `issue_for_actor` mint. That invariant is INEXPRESSIBLE for an
          enum: a Rust enum's variants AND their fields are ALWAYS exactly
          as visible as the enum itself. A
          `pub(in crate::context) enum OwnedIdentityDid { Owned(DID) }`
          would let ANY `crate::context` code write
          `OwnedIdentityDid::Owned(attacker_did)` — a mint with no
          `issue_for_actor` — while the field-privacy check (E) skips it
          (E does `if kind != "struct": continue`). Because the
          private-field invariant only holds for structs, the gate HARD
          FAILs the enum form.
        - (F.4) a `union OwnedIdentityDid { … }` is REJECTED for the same
          reason. A union field's visibility cannot be made private
          INDEPENDENT of the union, and union construction
          (`OwnedIdentityDid { did: … }`) is SAFE Rust — so any
          `crate::context` handler could forge the cap with no
          `issue_for_actor`, exactly the bypass (F.3) closes for enums.
          Without (F.4) a `union_item` was never even COLLECTED by the
          decl walk, so EVERY decl-keyed check (B/E/F.3/G) silently skipped
          it while the inherent-fn allowlist still passed — a forgeable
          mint that the gate waved through. The private-field invariant is
          inexpressible for a union, so the gate HARD FAILs it.
        - (F.5) a GENERIC `struct OwnedIdentityDid<T = DID> { did: T }` (or a
          lifetime-parameterized `struct OwnedIdentityDid<'a> { did: DID, _p:
          PhantomData<&'a ()> }`) is REJECTED. The decl walk keys on the type
          NAME and, before this rule, never inspected `type_parameters`, so a
          generic form PASSED every other check. It is not an ACTIVE forgery
          (the field stays private, the mint stays `pub(super)`,
          `#![forbid(unsafe_code)]` holds), but the struct-only assertion is
          supposed to be airtight: a generic parameter loosens the
          private-field TYPE (a defaulted `did: T` lets a reviewer instantiate
          the cap over an arbitrary inner type) and invites a
          reviewer-introduced refactor that erodes the private-field invariant
          the `pub(super)` mint guarantee rests on. tree-sitter exposes the
          `<…>` list as the `type_parameters` field on the `struct_item`; the
          gate HARD FAILs any cap decl that carries one. Applied ONLY to the
          capability type's own decl — unrelated helper types are unaffected.

  (B-macro) The capability module and its neighbours MUST be macro-clean
      where the cap type is concerned. tree-sitter does NOT expand macros,
      so a mint hidden in macro-generated code is invisible to the AST walk.
      The macro rules are CATEGORY / METAVARIABLE based, NOT
      payload-recognition based — every "recognize the dangerous payload"
      heuristic (a literal `impl OwnedIdentityDid` token, a function name) is
      defeatable by a `paste!`/token-split (`impl [<Owned Identity Did>]`) or
      a metavariable macro (`impl $t` in the def, `OwnedIdentityDid` in the
      invocation). The check FAILs:
        (1) DECLARING file (`identity_capability.rs`): ANY macro DEFINITION or
            INVOCATION that is NOT inside `#[cfg(test)]` code. The production
            body is macro-free; only the `#[cfg(test)] mod tests` macros
            (`assert_eq!`, the `assert_send_sync` witness) are permitted. A
            category ban over the non-test body is robust to
            paste/token-split/metavar AND false-fail-free (the cfg(test)
            assertions are exempted by walking the macro's ancestors for a
            `#[cfg(test)]` / `#[cfg(all(test, …))]` gate).
        (2) ANYWHERE under the scan root (non-declaring files): (a) any
            `macro_definition` whose body synthesizes an `impl $<metavariable>`
            (a macro that builds an impl on a passed-in type, which could be
            the cap type), AND (b) any `macro_invocation` whose argument text
            contains a word-boundaried `OwnedIdentityDid` token (the
            metavar-mint invocation `build_mint!(OwnedIdentityDid)`), flagged
            WITHOUT requiring `impl` adjacency. The literal
            `impl …OwnedIdentityDid` synthesize check is KEPT as
            belt-and-suspenders.
      Ordinary macros that do not touch the cap type (e.g.
      `assert_eq!(token.as_did(), &did)` in the declaring file's
      `#[cfg(test)]` tests, or `tracing::warn!(…)` anywhere) are NOT flagged.

  (C-path) No `#[path = "..."]` attribute may pull a file from OUTSIDE the
      scanned source root. The scanner walks only `crates/scp-runtime/src/`;
      a `#[path = "../../tests/forge.rs"] mod x;` would pull an external file
      into the crate where an in-module mint is legal but invisible to this
      gate. The check resolves each `#[path]` target relative to its
      declaring file and FAILs if it escapes src/. The one legitimate
      `#[path]` in the crate (`key_package_actor_tests.rs`, a sibling INSIDE
      src/) resolves under src/ and is NOT flagged.

The check PASSES SILENTLY if `OwnedIdentityDid` does not exist yet —
commit 5 of the actor refactor introduces the type. Until then, this
gate is a tripwire that fires the moment the type lands in the wrong
place or with the wrong shape.

---------------------------------------------------------------------------
COVERAGE BOUNDARY (defense-in-depth limit)
---------------------------------------------------------------------------
The PRIMARY unforgeability boundary is the Rust TYPE SYSTEM, not this gate:
  - `issue_for_actor` is `pub(super)` — only supervisor-module code can mint
    a token from a raw `DID`.
  - the single field `did` is PRIVATE — no struct-literal construction
    outside the declaring module.
  - `#![forbid(unsafe_code)]` (crate-level at `lib.rs`; reinforced by
    `#![deny(unsafe_code)]` at `supervisor/mod.rs`) — no `transmute` /
    unsafe `Send` impl can fabricate a token.
These hold in ALL cases. This gate is MECHANICAL DEFENSE-IN-DEPTH over the
SOURCE-TEXT surface, catching regressions in review before they compile.

COVERS (source-text surface, via tree-sitter AST):
  - inherent fns (closed allowlist: issue_for_actor / reissue / as_did)
  - struct-literal constructions of the cap in the declaring file
    (H — construction allowlist: only issue_for_actor / reissue may build it;
    closes the module-scoped-privacy forgery — free fn / helper-type method /
    closure / nested fn / trait-impl body minting via the private field)
  - trait-impl mints (D, extended — any trait method returning the cap type)
  - macros touching the cap type (B-macro)
  - `#[path]` escapes out of src/ (C-path)
  - forbidden derives / forbidden manual trait impls (C / D)
  - `type` aliases of the cap (F.1 / F.2)
  - non-struct nominal forms: `enum` (F.3) and `union` (F.4)
  - in-file nested-mod cap impls / cap constructions in the declaring file
    (I — the in-file analogue of the `#[path]` include escape)
  - by-value cap returns anywhere under the supervisor subtree (J — a
    literal-free re-export of the `pub(super)` mint that H and G both miss)
  - mint-call references anywhere under the supervisor subtree (K — the
    categorical closer: any call / value-path / `use … as` reference to
    `issue_for_actor` outside the build site, immune to the return-type
    disguises — projection, opaque `impl Trait` — that rule J cannot see).
    The K build-site exemption is hardened against THREE forgeries that the
    bare type-tail + file pin left open:
      * a NESTED-MOD SHADOW `impl Supervisor` in `supervisor.rs` — the exempt
        `impl Supervisor` must be TOP-LEVEL (not under any in-file `mod`), so a
        shadow's mint is NOT exempt (fix 2, mirrors rule I);
      * a SECOND / ATTACKER-DID mint inside the real `build_actor_deps` — the
        per-call mint-arg check is BINDING-based, not name-based (fix 3): the
        fn must have EXACTLY ONE non-`self` `DID`-typed parameter, the exempt
        mint's sole argument must be a bare `<owning>` / `<owning>.clone()`
        PINNED to that param's binding name (NOT a constructed `DID("…")`
        literal, a non-`.clone()` method call, a reborrow, a field access, or
        another local), and that param name must NOT be shadowed/re-bound by a
        `let`/assignment before the mint. A second `DID` param (G03) or a
        `let owning_did = …` shadow (G02) therefore dissolves the exemption —
        the only value the exempt mint can consume is the unshadowed sole
        caller-supplied `&DID` parameter;
    plus a bare `use_list` member of the mint (`use self::{issue_for_actor};`,
    no `as`) is now flagged as a mint reference (fix 5).
  - the KEYSTONE escape-position ban (whole supervisor subtree): the cap in a
    by-value escape channel OTHER than a plain return / plain struct field —
    a `&mut`/`*mut` OUT-PARAM (incl. `&mut Option<…Cap…>` / `&mut Vec<…Cap…>`),
    a `static`/`const` SINK holding the cap by value, or an INTERIOR-MUTABILITY
    wrapper (`Cell`/`RefCell`/`OnceCell`/`OnceLock`/`Mutex`/`RwLock`/
    `UnsafeCell`/…<…Cap…>) handed out behind a shared `&`. This single rule
    kills the out-param exfil (K01), the static sink (K02 variant), and any
    interior-mut cell — channels rules J (return) and K (mint call) do not
    cover. It does NOT flag a plain `&OwnedIdentityDid` shared borrow, the legit
    `ActorDeps { owned_identity: OwnedIdentityDid }` plain field, or `as_did`'s
    `&DID` return. cfg(test) exempt.
  - subtree GLOB import of the capability module (`use …identity_capability::*`)
    and subtree token-REASSEMBLING macro invocations (`paste!`/`concat_idents!`)
    are banned (fix 4) — a glob hides the cap/mint name from explicit-name
    recognition, and a token-pasting macro can synthesize the mint identifier
    from split tokens the AST walk never reassembles (kills K03). cfg(test)
    exempt.
  - struct location, name-visibility, and field visibility (A / B / E)

INTENTIONALLY NOT FLAGGED (RELOCATION of an already-owned cap):
  A fn that RECEIVES an already-owned `OwnedIdentityDid` by value and merely
  RE-HOMES it — moving it into a new returned struct field, a custom wrapper
  type, or passing it by value to another call — is NOT flagged, by design.
  The closure rests on rules J / K gating the cap's SOURCE: no arbitrary-DID
  cap can be CREATED to relocate, because every creation routes through either
  `issue_for_actor` (rule K — banned outside the pinned build site) or a struct
  literal (rules H / I — only the two allowlisted constructors may build it).
  A value that was never illicitly minted cannot become an attacker token by
  being moved, so the "new returned struct field" and "custom UnsafeCell
  wrapper" relocation shapes are inert here.

OUT OF REMIT (NOT this AST gate — covered by the type system + human review):
  - build-script (`build.rs`) code generation, and
  - procedural macros that synthesize a mint at compile time.
  None exist in this crate; `cargo`'s build-script / proc-macro surface is
  reviewed separately. An AST text-walk cannot see code that does not exist
  until a build script or proc-macro runs; the type-system boundary above is
  what makes a token minted by such code still impossible without the
  `pub(super)` constructor and private field.

---------------------------------------------------------------------------
SCOPE
---------------------------------------------------------------------------
Walks every `.rs` file under `crates/scp-runtime/src/` (including tests
and submodules). Finds every `struct OwnedIdentityDid` declaration (the
ONLY permitted form), every `enum OwnedIdentityDid` and `union
OwnedIdentityDid` declaration (which it REJECTS — rules F.3 / F.4), every
`impl ... for OwnedIdentityDid`
block (collecting INHERENT fns for the allowlist and TRAIT-impl methods
for the extended trait-mint check), every `type OwnedIdentityDid = ...`
alias AND every top-level `type X = OwnedIdentityDid` alias of the
capability type, every `macro_rules!` / macro invocation that could hide a
mint touching the cap type, and every `#[path = "..."]` attribute that
escapes the scanned source root.

---------------------------------------------------------------------------
SELF-TEST
---------------------------------------------------------------------------
Run with `--self-test` to exercise the scanner against a fixture file
that contains every known bypass pattern (manual impl, pub field, type
alias of the cap type, wrong location, wrong visibility, forbidden
derive, and every allowlist bypass: a second/alternately-named mint, a
wrong-visibility mint, a non-allowlisted associated fn, a
return-type-aliased forgery, an `impl Trait`-return forgery, and a
`DidId`-param mint). CI runs `--self-test` before the real scan so the
gate fails loudly if the scanner is weakened.

Fixture: `scripts/tests/owned-identity-did-fixture.rs`.

---------------------------------------------------------------------------
USAGE
---------------------------------------------------------------------------
    python3.12 scripts/check-owned-identity-did.py
    python3.12 scripts/check-owned-identity-did.py --self-test

Exit codes:
    0  — type not yet declared, OR declared correctly
    1  — type is declared in the wrong file, with wrong struct
         name-visibility, with an inherent fn outside the
         issue_for_actor/reissue/as_did allowlist (any return type,
         including aliased / `impl Trait` returns), with a mis-shaped
         allowlisted fn (mint not `pub(super)` / not raw-DID-typed /
         taking `&self`; reissue/as_did missing `&self` or taking a raw
         DID), with an absent mint, with a forbidden derive / manual impl
         / public field, or as a `type` alias (of OR named after the cap
         type); with a cap construction or impl nested in an in-file
         `mod` (I); with a by-value cap return anywhere in the supervisor
         subtree (J); with a `use … as` alias of the cap or of the mint
         fn; with a reference to the `issue_for_actor` mint anywhere in the
         supervisor subtree outside `Supervisor::build_actor_deps` /
         `#[cfg(test)]` (K); OR --self-test did not catch all bypasses
    2  — invocation error

See ADR-049 for design context.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import tempfile
from pathlib import Path

try:
    import tree_sitter_rust as ts_rust
    from tree_sitter import Language, Parser
except ImportError:
    sys.stderr.write(
        "error: tree-sitter / tree-sitter-rust not installed.\n"
        "       pip install tree-sitter tree-sitter-rust\n"
    )
    sys.exit(2)

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent
SCAN_DIR = REPO_ROOT / "crates" / "scp-runtime" / "src"
REQUIRED_PATH = "crates/scp-runtime/src/context/supervisor/identity_capability.rs"
# The subtree (relative, posix) under which the `pub(super)` mint
# `issue_for_actor` is REACHABLE. The struct is declared `pub(super)`-minted
# in REQUIRED_PATH; `pub(super)` resolves to the parent module — the
# `supervisor` directory — so any `.rs` file under it can call the mint and
# thereby return a token by value (rule J, the by-value cap-return ban, scans
# this whole subtree, not just the declaring file). Outside this subtree the
# `pub(super)` mint is unreachable, so a by-value cap return cannot be
# produced there. Kept as a path PREFIX (posix `rel.startswith(...)`) so the
# self-test's temp staging tree — which mirrors the same relative layout —
# matches identically.
SUPERVISOR_SUBTREE_REL = "crates/scp-runtime/src/context/supervisor/"
FIXTURE_FILE = REPO_ROOT / "scripts" / "tests" / "owned-identity-did-fixture.rs"
TYPE_NAME = "OwnedIdentityDid"

FORBIDDEN_DERIVES = frozenset(
    {
        "Clone",
        "Copy",
        "Serialize",
        "Deserialize",
        "Default",
        "Hash",
        "PartialEq",
        "Eq",
        "Borrow",
        "From",
        "Into",
        "Debug",
        "Display",
        "Deref",
        "AsRef",
    }
)

# Forbidden manual-impl traits. This mirrors FORBIDDEN_DERIVES; any
# trait whose `derive` is banned is also banned via `impl`. The scanner
# also matches the common `impl Trait<...>` forms with a single type
# parameter (`From<Did>`, `Into<Did>`, `Borrow<str>`, etc.).
FORBIDDEN_IMPL_TRAITS = frozenset(FORBIDDEN_DERIVES)

# TTY coloring
if sys.stdout.isatty() and "NO_COLOR" not in os.environ:
    C_RED = "\033[31m"
    C_GREEN = "\033[32m"
    C_YELLOW = "\033[33m"
    C_DIM = "\033[2m"
    C_RESET = "\033[0m"
else:
    C_RED = C_GREEN = C_YELLOW = C_DIM = C_RESET = ""

RUST_LANG = Language(ts_rust.language())
PARSER = Parser(RUST_LANG)


# -----------------------------------------------------------------------------
# AST helpers
# -----------------------------------------------------------------------------


def node_text(node, source: bytes) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


_CONTEXT_VIS_RE = re.compile(r"^pub\s*\(\s*in\s+crate\s*::\s*context\s*\)$")


def _is_context_visibility(vis: str) -> bool:
    """True if `vis` is the `pub(in crate::context)` modifier, tolerant of
    INTERNAL whitespace variation.

    A raw byte-slice extraction of a `visibility_modifier` node yields the
    source text verbatim, so the semantically-identical valid-Rust forms
    `pub(in crate::context)` and `pub(in crate :: context)` (extra spaces
    around `::` or inside the parens) produce DIFFERENT strings. An exact
    `vis != "pub(in crate::context)"` compare false-FAILs the spaced form.
    rustfmt normalizes the spacing and the fail is fail-closed (no security
    risk — it only rejects a valid declaration), but the gate must not flag
    correct code, so we normalize internal whitespace before comparing.
    Leading/trailing whitespace is already stripped by the callers; this
    regex collapses the interior spacing.
    """
    return _CONTEXT_VIS_RE.match(vis.strip()) is not None


def _visibility_of(node, source: bytes) -> str:
    """Return the visibility modifier of a struct/enum node as a string.

    Returns '' (empty) for a private item, 'pub' for pub, 'pub(super)' etc.
    Tree-sitter puts visibility_modifier as the first child of struct_item
    when present.
    """
    for c in node.children:
        if c.type == "visibility_modifier":
            return node_text(c, source).strip()
    return ""


def _is_generic_decl(node) -> bool:
    """True if a `struct_item` / `enum_item` / `union_item` node carries a
    `type_parameters` child — i.e. it is declared GENERIC (type parameters
    OR lifetime parameters).

    tree-sitter-rust exposes the `<…>` parameter list as the
    `type_parameters` field on the item node for BOTH generic type params
    (`<T = DID>`) and lifetime params (`<'a>`); its ABSENCE means the
    declaration is non-generic. Rule (F) requires the capability type be a
    NON-GENERIC `struct`: a generic parameter loosens the private-field type
    (`struct OwnedIdentityDid<T = DID> { did: T }`) or invites a
    reviewer-introduced refactor that weakens the private-field invariant the
    `pub(super)` mint guarantee rests on. The cap's field type is fixed
    (`DID`); there is no legitimate reason for the declaration to be generic.
    """
    return node.child_by_field_name("type_parameters") is not None


def _strip_string_literals(s: str) -> str:
    """Replace every `"..."` string literal and every `r#"..."#`/`r"..."`
    raw string literal body with spaces, preserving length. This prevents
    an accidental match on `derive(...)` text that lives inside a
    doc-comment attribute's string payload (`#[doc = "derive(X)"]`) or
    any other attribute whose argument happens to be a string literal
    mentioning the word `derive`.

    Byte-string literals (`b"..."`) and char literals (`'x'`) are NOT
    attribute-relevant for `derive` extraction but are handled by the
    same pass for consistency.

    Length is preserved so that the caller's regex positions still map
    back into the original attribute text for reporting (not used
    internally here, but future-proofs the helper).
    """
    out: list[str] = []
    i = 0
    n = len(s)
    while i < n:
        ch = s[i]
        # Raw string: r"..."   or   r#"..."#  ...  r##"..."##
        if ch == "r" and i + 1 < n and (s[i + 1] == '"' or s[i + 1] == "#"):
            # Count hashes.
            hashes = 0
            j = i + 1
            while j < n and s[j] == "#":
                hashes += 1
                j += 1
            if j < n and s[j] == '"':
                # Scan until closing `"` followed by exactly `hashes` `#`s.
                k = j + 1
                closer = '"' + ("#" * hashes)
                while k < n:
                    if s[k] == '"' and s[k : k + len(closer)] == closer:
                        end = k + len(closer)
                        out.append("r")
                        out.append(" " * (end - i - 1))
                        i = end
                        break
                    k += 1
                else:
                    # Unterminated — just copy.
                    out.append(ch)
                    i += 1
                continue
        if ch == '"':
            # Regular string: scan for unescaped `"`.
            j = i + 1
            while j < n:
                if s[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                if s[j] == '"':
                    break
                j += 1
            end = min(j + 1, n)
            out.append('"')
            out.append(" " * (end - i - 2))
            out.append('"' if j < n else "")
            i = end
            continue
        if ch == "'":
            # Char literal: `'x'` or `'\n'` or lifetime `'a`. We only care
            # about delimited single-quote pairs; lifetimes are fine to
            # leave as-is (they never contain `derive`). Conservative:
            # if the next-next char is `'`, treat as char literal.
            if i + 2 < n and s[i + 2] == "'":
                out.append("' '")
                i += 3
                continue
            if i + 3 < n and s[i + 1] == "\\" and s[i + 3] == "'":
                out.append("'  '")
                i += 4
                continue
            out.append(ch)
            i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _extract_derive_groups(attr_text: str) -> list[str]:
    """Return the list of derive-identifier names collected from EVERY
    `derive(...)` group appearing inside a single attribute text,
    regardless of the outer wrapper.

    Handles:
      `#[derive(Clone, Debug)]`
      `#[derive(serde::Serialize)]`
      `#[cfg_attr(feature = "x", derive(Clone))]`
      `#[cfg_attr(all(feature = "a", not(feature = "b")), derive(Serialize, Deserialize))]`
      `#[cfg_attr(feature = "x", derive(Clone), derive(Debug))]`         (pathological — both)
      `#[cfg_attr(feature = "x", derive(Clone, Debug), allow(dead_code))]` (mixed meta)

    Non-matches (must NOT extract):
      `#[allow(derive_hash_xor_eq)]`      — `derive_hash_xor_eq` is an ident, not `derive`
      `#[my_derive(Foo)]`                 — `my_derive` has a word char before `derive`
      `#[doc = "derive(X)"]`              — `derive(X)` inside a string literal

    Strategy: strip every string literal first (so `derive(X)` inside a
    doc-comment payload cannot match), then scan for every
    `\\bderive\\s*\\(` position, then paren-balance from that opening
    paren to its matching close. Split the inner text on top-level
    commas (a depth counter suppresses commas nested inside
    `derive(serde::Serialize)`-style scoped paths that have no inner
    parens, or any exotic nested groups). For each name, drop any
    leading `path::` segments to keep only the trait tail.
    """
    attr_text = _strip_string_literals(attr_text)
    names: list[str] = []
    for m in re.finditer(r"\bderive\s*\(", attr_text):
        open_idx = m.end() - 1  # position of the `(`
        depth = 1
        i = open_idx + 1
        while i < len(attr_text) and depth > 0:
            ch = attr_text[i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            i += 1
        if depth != 0:
            # Truncated / malformed — skip this group rather than
            # misattribute identifiers. tree-sitter-level malformed
            # input would fail the parse earlier; this guard is defence
            # in depth for regex-level edge cases.
            continue
        inner = attr_text[open_idx + 1 : i - 1]

        # Split on top-level commas (depth-aware; there shouldn't be
        # nested parens inside a `derive(...)` group in practice, but
        # the balanced walker is cheap and future-proof).
        depth2 = 0
        buf: list[str] = []
        current: list[str] = []
        for ch in inner:
            if ch == "(" or ch == "[" or ch == "{":
                depth2 += 1
                current.append(ch)
            elif ch == ")" or ch == "]" or ch == "}":
                depth2 -= 1
                current.append(ch)
            elif ch == "," and depth2 == 0:
                buf.append("".join(current))
                current = []
            else:
                current.append(ch)
        if current:
            buf.append("".join(current))

        for raw in buf:
            name = raw.strip()
            # Handle paths like `serde::Serialize` — keep only the last
            # segment.
            if "::" in name:
                name = name.rsplit("::", 1)[-1]
            # Strip generic parameters if somehow present (unusual but
            # cheap to guard: `Foo<T>` -> `Foo`).
            if "<" in name:
                name = name.split("<", 1)[0].strip()
            if name:
                names.append(name)
    return names


def _preceding_derives(node, source: bytes) -> list[str]:
    """Return the union of derive identifiers from every attribute that
    precedes this item, including attributes whose outer wrapper is
    `#[cfg_attr(..., derive(...))]` (conditional-derive bypass).

    Attribute text scanning is paren-balanced: we walk every
    `derive(...)` group inside the attribute text regardless of outer
    wrapper. This catches:

      `#[derive(Clone)]`                               (plain derive)
      `#[cfg_attr(feature = "x", derive(Clone))]`      (conditional)
      `#[cfg_attr(all(...), derive(Serialize, Deserialize))]` (nested cfg)

    `cfg_attr` expands at cfg-eval time to its inner attributes; a
    build configuration that activates the feature gate produces a real
    `#[derive(...)]`. Treating the conditional form identically to the
    unconditional form closes the bypass that an outer-wrapper text
    match missed.

    Comment interleavings are skipped so attributes separated from the
    item by a doc-comment or blank line are still walked.
    """
    derives: list[str] = []
    sibling = node.prev_sibling
    while sibling is not None:
        if sibling.type == "attribute_item":
            txt = node_text(sibling, source)
            derives.extend(_extract_derive_groups(txt))
            sibling = sibling.prev_sibling
            continue
        if sibling.type in ("line_comment", "block_comment"):
            sibling = sibling.prev_sibling
            continue
        break
    return derives


# -----------------------------------------------------------------------------
# Struct field visibility
# -----------------------------------------------------------------------------


def _public_fields(node, source: bytes) -> list[tuple[int, str]]:
    """For a `struct_item`, return a list of (line, visibility_text) for
    every field whose visibility is NOT default-private.

    Handles both:
      - `struct S { pub(crate) field: T }`               named fields
      - `struct S(pub Did);`                             tuple fields
      - `struct S(pub(crate) Did, pub Did, Did);`        multi-field tuple
      - Unit struct `struct S;`                           — no fields

    Tree-sitter-rust grammar note (0.21+): named fields wrap each field
    in a `field_declaration` node inside `field_declaration_list`, with
    the `visibility_modifier` as a CHILD of `field_declaration`. Tuple
    fields, however, do NOT use an `ordered_field_declaration` wrapper —
    `ordered_field_declaration_list` has `visibility_modifier` and
    `type_identifier` (or other type nodes) as DIRECT children, separated
    by `,` punctuation. A `visibility_modifier` direct child of the list
    therefore marks a pub tuple field, even though there is no wrapper
    node to attach it to. Earlier versions of this scanner looked for an
    `ordered_field_declaration` wrapper and missed every tuple pub-field
    bypass such as `pub(super) struct OwnedIdentityDid(pub(crate) Did);`.
    """
    if node.type != "struct_item":
        return []
    publics: list[tuple[int, str]] = []
    body = node.child_by_field_name("body")
    if body is None:
        return []
    if body.type == "field_declaration_list":
        # Named fields: `{ field: T, pub(crate) field: T }`. The grammar
        # emits a `field_declaration` wrapper per field, with its own
        # `visibility_modifier` child for pub fields.
        for child in body.children:
            if child.type == "field_declaration":
                for grand in child.children:
                    if grand.type == "visibility_modifier":
                        publics.append(
                            (
                                child.start_point[0] + 1,
                                node_text(grand, source).strip(),
                            )
                        )
                        break
    elif body.type == "ordered_field_declaration_list":
        # Tuple fields: tree-sitter-rust 0.21+ emits
        #   `ordered_field_declaration_list` → (`(`, (`visibility_modifier`?, type_node, `,`?)*, `)`)
        # with NO `ordered_field_declaration` wrapper per field. Every
        # DIRECT `visibility_modifier` child of the list therefore
        # corresponds to exactly one pub tuple field. Record each one.
        for child in body.children:
            if child.type == "visibility_modifier":
                publics.append(
                    (
                        child.start_point[0] + 1,
                        node_text(child, source).strip(),
                    )
                )
    return publics


# -----------------------------------------------------------------------------
# Impl target detection
# -----------------------------------------------------------------------------


def _is_associated_type(type_item_node) -> bool:
    """True if a `type_item` node is an ASSOCIATED type binding — i.e. its
    nearest meaningful ancestor is an `impl_item` or `trait_item` (the
    `type X = …;` lives inside an `impl Trait for Ty { type X = …; }` or a
    `trait T { type X = …; }`). Such a binding is NOT a standalone, nameable
    top-level alias: `impl Carrier for u8 { type Out = OwnedIdentityDid; }`
    cannot be named as `Out` to declare a mint's return type (it is reached
    only as `<u8 as Carrier>::Out`), so it creates no return-type-alias
    forgery vector and must NOT be collected into `cap_aliases` (rule F.2).

    Tree-sitter nests an associated `type_item` under a `declaration_list`
    whose parent is the `impl_item` / `trait_item`; a top-level alias has a
    `source_file` (or plain module `declaration_list` whose parent is a
    `mod_item`) ancestry with no enclosing impl/trait. We walk parents and
    return True the moment we hit an `impl_item`/`trait_item` before any
    `mod_item`/`source_file` boundary.
    """
    parent = type_item_node.parent
    while parent is not None:
        if parent.type in ("impl_item", "trait_item"):
            return True
        if parent.type in ("source_file", "mod_item"):
            return False
        parent = parent.parent
    return False


def _impl_for_owned_identity_did(
    impl_node, source: bytes
) -> tuple[str | None, int] | None:
    """If `impl_node` is `impl Trait for OwnedIdentityDid { ... }`,
    return (trait_name, line). If it's `impl OwnedIdentityDid { ... }`
    (inherent impl, not a trait impl), return (None, line). If it is
    not an impl targeting OwnedIdentityDid, return None.

    The `trait` field in tree-sitter-rust holds the trait; `type` holds
    the concrete target.
    """
    type_node = impl_node.child_by_field_name("type")
    if type_node is None:
        return None
    # Find the tail identifier of the type. For `OwnedIdentityDid` and
    # `OwnedIdentityDid<T>` (generic, shouldn't happen here but cheap
    # to support), the tail is a type_identifier.
    tail: str | None = None
    if type_node.type == "type_identifier":
        tail = node_text(type_node, source)
    elif type_node.type == "generic_type":
        t = type_node.child_by_field_name("type")
        if t is not None and t.type == "type_identifier":
            tail = node_text(t, source)
    elif type_node.type == "scoped_type_identifier":
        name = type_node.child_by_field_name("name")
        if name is not None:
            tail = node_text(name, source)
    if tail != TYPE_NAME:
        return None

    trait_node = impl_node.child_by_field_name("trait")
    if trait_node is None:
        return (None, impl_node.start_point[0] + 1)

    # Extract the trait name. Forms:
    #   `Clone`                          type_identifier
    #   `From<Did>`                       generic_type(name=From, ...)
    #   `std::borrow::Borrow<str>`        generic_type around scoped
    #   `serde::Serialize`                scoped_type_identifier
    trait_name: str | None = None
    if trait_node.type == "type_identifier":
        trait_name = node_text(trait_node, source)
    elif trait_node.type == "generic_type":
        t = trait_node.child_by_field_name("type")
        if t is not None:
            if t.type == "type_identifier":
                trait_name = node_text(t, source)
            elif t.type == "scoped_type_identifier":
                name = t.child_by_field_name("name")
                if name is not None:
                    trait_name = node_text(name, source)
    elif trait_node.type == "scoped_type_identifier":
        name = trait_node.child_by_field_name("name")
        if name is not None:
            trait_name = node_text(name, source)
    return (trait_name, impl_node.start_point[0] + 1)


# -----------------------------------------------------------------------------
# Struct-literal construction allowlist (rule H — close the module-private
# field forgery: Rust field privacy is MODULE-scoped, not impl-scoped, so a
# free fn / helper-type method / closure / nested fn in the DECLARING FILE can
# mint via the private `did` field without going through an allowlisted
# inherent constructor. Rules A-G key on `impl OwnedIdentityDid` blocks and
# decls and would WAVE THROUGH such a construction. Rule H scans EVERY
# `struct_expression` that builds the cap type in the declaring file and HARD
# FAILs any not lexically inside an allowlisted constructor body.)
# -----------------------------------------------------------------------------


# The ONLY two fns that may CONSTRUCT the capability via a struct literal.
# `as_did` is excluded — it is an accessor (`&self.did`), it does NOT build a
# token. Both MUST be inherent fns on `OwnedIdentityDid` (enforced by rule H
# walking the construction's enclosing impl target + inherent-ness, NOT just
# the fn name — a `fn reissue` on a HELPER type, or in a TRAIT impl, does not
# count).
CONSTRUCTING_FNS: frozenset[str] = frozenset({"issue_for_actor", "reissue"})

# The SOLE arbitrary-DID minter (ADR-049 §5). `issue_for_actor(did: DID) ->
# Self` is the ONLY fn that fabricates a capability token from an arbitrary
# raw DID; `reissue(&self) -> Self` merely clones an already-held token and is
# not a forgery vector. Rule (K) — MINT-CALL CONTAINMENT — keys on a CODE
# REFERENCE to THIS name (a call / value path / `use … as` alias), not on the
# evadable RETURN-TYPE TEXT that rule (J) inspects. Every arbitrary-DID forgery
# MUST reference this name, so banning the reference everywhere except the one
# legitimate mint site closes the return-type-disguise arms race (assoc-type
# projection, trait-method projection, `impl Sized` opaque return, future
# return spellings) that rule J alone cannot.
MINT_FN_NAME: str = "issue_for_actor"

# The ONE legitimate non-test mint CALL site (ADR-049 §5): the actor-spawn
# builder `Supervisor::build_actor_deps`, which mints each actor's token for
# its own `owning_did`. Rule (K) exempts a mint reference whose nearest
# enclosing `function_item` is named this AND whose enclosing `impl_item`
# targets `Supervisor`.
BUILD_ACTOR_DEPS_FN: str = "build_actor_deps"
SUPERVISOR_IMPL_TYPE: str = "Supervisor"
# The raw-DID type the actor's owning identity is carried as. The per-call
# mint-arg check (fix 3) is BINDING-based, not NAME-based: the exempt mint may
# only consume the SOLE non-`self` parameter of `build_actor_deps` whose TYPE
# tail-identifier is this (covers `owning_did: &DID` and `owning_did: DID`). A
# second `DID`-typed parameter, or an added one carrying an attacker DID,
# dissolves the exemption (G03); a `let`/assignment shadow of that param's name
# before the mint dissolves it too (G02). Both forgeries leave the mint
# consuming an attacker-controlled value, so neither may be exempt.
DID_PARAM_TYPE: str = "DID"
# Rule K exemption (b) is additionally PINNED to the real build-site FILE, so a
# forger cannot plant a local `struct Supervisor; impl Supervisor { fn
# build_actor_deps(..) { ..issue_for_actor(..) } }` in ANOTHER subtree file and
# inherit the exemption (which — combined with a projection/opaque return that
# rule J cannot see — would otherwise re-open the mint surface). The real
# `Supervisor::build_actor_deps` lives here and nowhere else.
BUILD_SITE_REL: str = "crates/scp-runtime/src/context/supervisor/supervisor.rs"

# The declaring MODULE name. A glob `use …identity_capability::*;` (fix 4) drags
# EVERY item of the capability module — including the cap type and (transitively)
# any future re-exported mint name — into the importing module under its bare
# name, defeating the gate's explicit-NAME recognition (rules G/H/K key on the
# literal `OwnedIdentityDid` / `issue_for_actor` tail; a glob makes those names
# reachable WITHOUT a nameable `use … as` / scoped path the gate can see). The
# subtree must name what it imports EXPLICITLY so every other rule can see the
# cap/mint, so a glob whose path tail is the capability module is banned.
CAP_MODULE_NAME: str = "identity_capability"

# Token-REASSEMBLING / token-PASTING macros whose INVOCATION in the subtree can
# synthesize the mint or cap identifier from split tokens (`paste! { [<issue
# _for_actor>] }`, `concat_idents!(issue_, for_actor)`) — defeating every
# identifier-keyed rule (tree-sitter never reassembles the split tokens). Mirror
# the declaring-file macro CATEGORY ban (which is payload-agnostic): ban the
# INVOCATION of a reassembly macro anywhere in the subtree, cfg(test)-exempt.
REASSEMBLY_MACROS: frozenset[str] = frozenset({"paste", "concat_idents"})


def _type_tail_identifier(type_node, source: bytes) -> str | None:
    """Return the tail identifier of a type node — the bare type name with any
    leading `path::` segments dropped. Handles `type_identifier`
    (`OwnedIdentityDid`), `scoped_type_identifier`
    (`crate::…::OwnedIdentityDid` → `OwnedIdentityDid`), and `generic_type`
    (`OwnedIdentityDid<T>` → `OwnedIdentityDid`). Returns None for any other
    node shape.
    """
    if type_node is None:
        return None
    if type_node.type == "type_identifier":
        return node_text(type_node, source)
    if type_node.type == "scoped_type_identifier":
        name = type_node.child_by_field_name("name")
        return node_text(name, source) if name is not None else None
    if type_node.type == "generic_type":
        return _type_tail_identifier(
            type_node.child_by_field_name("type"), source
        )
    return None


def _use_alias_cap_tail(use_as_clause_node, source: bytes) -> str | None:
    """For a `use_as_clause` node (`use <path> as <Alias>`), return the
    imported `<Alias>` NAME iff the imported path's LAST `::` segment is the
    capability type, else None.

    Rust has exactly TWO type-renaming mechanisms: a `type X = T` alias (rule
    F.2, banned via `cap_aliases`) and a `use … as X` import alias (this hole).
    The latter is the symmetric forgery surface: `use self::OwnedIdentityDid as
    Alias;` makes `Alias` a second name for the cap, so an `impl Alias { … Self
    { did } }` / `impl Alias { … Alias { did } }` / a free fn `-> Alias { Alias
    { did } }` all have a tail identifier ≠ `OwnedIdentityDid` and slip rule G
    (inherent allowlist), rule H (construction scan), and `_impl_targets_cap`
    — every one of which recognizes the cap ONLY by the literal tail
    `OwnedIdentityDid` (or `Self` inside a cap impl). Banning the `use`-alias
    outright (symmetric to F.2) guarantees the cap can only ever be NAMED
    `OwnedIdentityDid`, keeping tail-identifier recognition airtight.

    tree-sitter shapes the clause's `path` field as either an `identifier`
    (when the clause lives inside a `use_list` / `scoped_use_list`, e.g.
    `use self::{OwnedIdentityDid as Alias};` or `use foo::{Bar,
    OwnedIdentityDid as Alias};`) or a `scoped_identifier` (a fully- or
    partially-qualified path, e.g. `use self::OwnedIdentityDid as Alias;`,
    `use super::OwnedIdentityDid as Alias;`, or
    `use crate::…::identity_capability::OwnedIdentityDid as Alias;`). For a
    `scoped_identifier` the LAST segment is its `name` field; for a bare
    `identifier` the whole node is the tail. We match the tail word-exactly
    (tree-sitter token boundary), so `OwnedIdentityDidExtra` does NOT match.
    Returns the alias identifier text for the diagnostic, or None.
    """
    path_node = use_as_clause_node.child_by_field_name("path")
    if path_node is None:
        return None
    if path_node.type == "identifier":
        tail = node_text(path_node, source)
    elif path_node.type == "scoped_identifier":
        name = path_node.child_by_field_name("name")
        tail = node_text(name, source) if name is not None else None
    else:
        return None
    if tail != TYPE_NAME:
        return None
    alias_node = use_as_clause_node.child_by_field_name("alias")
    return node_text(alias_node, source) if alias_node is not None else "<?>"


def _use_alias_mint_tail(use_as_clause_node, source: bytes) -> str | None:
    """For a `use_as_clause` node (`use <path> as <Alias>`), return the
    imported `<Alias>` NAME iff the imported path's LAST `::` segment is the
    MINT fn `issue_for_actor`, else None.

    This is the mint-fn analogue of `_use_alias_cap_tail` (which guards the cap
    TYPE name). Rule (K) bans every CODE REFERENCE to `issue_for_actor`; a
    `use …::issue_for_actor as m;` followed by a bare `m(d)` would dodge a scan
    that keys on the literal identifier `issue_for_actor` at the call site (the
    call is spelled `m`, not `issue_for_actor`). Banning the import alias closes
    that fn-rename residual, symmetric to the cap-type F.2-use ban: the mint can
    only ever be NAMED `issue_for_actor`, so the call-reference scan stays
    airtight.

    tree-sitter shapes the clause's `path` field as either an `identifier`
    (inside a `use_list` / `scoped_use_list`, e.g.
    `use a::b::{issue_for_actor as n};`) or a `scoped_identifier` (a qualified
    path, e.g. `use self::issue_for_actor as m;`). For a `scoped_identifier` the
    LAST segment is its `name` field; for a bare `identifier` the whole node is
    the tail. We match the tail word-exactly, so `issue_for_actor_extra` does
    NOT match. Returns the alias identifier text for the diagnostic, or None.
    """
    path_node = use_as_clause_node.child_by_field_name("path")
    if path_node is None:
        return None
    if path_node.type == "identifier":
        tail = node_text(path_node, source)
    elif path_node.type == "scoped_identifier":
        name = path_node.child_by_field_name("name")
        tail = node_text(name, source) if name is not None else None
    else:
        return None
    if tail != MINT_FN_NAME:
        return None
    alias_node = use_as_clause_node.child_by_field_name("alias")
    return node_text(alias_node, source) if alias_node is not None else "<?>"


def _use_alias_did_tail(use_as_clause_node, source: bytes) -> str | None:
    """For a `use_as_clause` node (`use <path> as <Alias>`), return the
    imported `<Alias>` NAME iff the imported path's LAST `::` segment is the
    raw-DID type `DID`, else None.

    This is the raw-DID analogue of `_use_alias_cap_tail` / `_use_alias_mint_tail`.
    The per-call mint-arg check (rule K exemption b) counts the SOLE non-`self`
    parameter whose TYPE tail-identifier is the literal `DID` to find the owning
    binding. A `use scp_identity::DID as GoodId;` import alias renames `DID` on
    the OWNING parameter so the ATTACKER parameter becomes the ONLY literal-`DID`
    param — it then gets pinned as the owning binding and the attacker DID is
    minted (G03-via-alias). Banning the import alias outright, scoped to the
    supervisor subtree (`SUPERVISOR_SUBTREE_REL`) — symmetric to the cap-type
    F.2-use ban — keeps `DID` un-renameable where the owning-param count runs, so
    the literal-`DID` param count is airtight.

    Path-node shapes mirror `_use_alias_mint_tail`: a bare `identifier` inside a
    `use_list`/`scoped_use_list`, or a `scoped_identifier` whose `name` field is
    the tail segment. Matched word-exactly, so `DIDExtra` does NOT match.
    Returns the alias identifier text for the diagnostic, or None.
    """
    path_node = use_as_clause_node.child_by_field_name("path")
    if path_node is None:
        return None
    if path_node.type == "identifier":
        tail = node_text(path_node, source)
    elif path_node.type == "scoped_identifier":
        name = path_node.child_by_field_name("name")
        tail = node_text(name, source) if name is not None else None
    else:
        return None
    if tail != DID_PARAM_TYPE:
        return None
    alias_node = use_as_clause_node.child_by_field_name("alias")
    return node_text(alias_node, source) if alias_node is not None else "<?>"


def _use_wildcard_is_cap_module(use_wildcard_node, source: bytes) -> bool:
    """For a `use_wildcard` node (the `…::*` glob of a `use_declaration`),
    return True iff the glob's PATH (the segment(s) before `::*`) ends in the
    capability module `identity_capability` — i.e. `use …identity_capability::*;`
    (fix 4).

    tree-sitter shapes a glob `use a::b::*;` as a `use_wildcard` whose child is
    a `scoped_identifier` (`a::b`) followed by `::` and `*`; for `use foo::*;`
    the child is a bare `identifier` (`foo`); for `use *;` (degenerate) there is
    no path child. We take the path child's TAIL identifier and match it
    word-exactly against the cap module name. A glob whose tail is some OTHER
    module is NOT flagged (only the capability module's glob defeats
    explicit-name recognition).
    """
    path_tail: str | None = None
    for c in use_wildcard_node.children:
        if c.type == "scoped_identifier":
            name = c.child_by_field_name("name")
            path_tail = node_text(name, source) if name is not None else None
        elif c.type == "identifier":
            path_tail = node_text(c, source)
    return path_tail == CAP_MODULE_NAME


def _is_mint_reference(node, source: bytes) -> bool:
    """True if `node` is a CODE REFERENCE to the mint fn `issue_for_actor` —
    a `call_expression`/value-path reference whose tail identifier is the mint
    name — and is NOT the mint's own DEFINITION nor a `use`-path segment.

    Recognized reference shapes (matching the empirically-confirmed grammar):
      - a `scoped_identifier` whose `name` field is `issue_for_actor` — covers
        `a::b::issue_for_actor(d)` and `Self::issue_for_actor(d)` (the call
        `function`), AND a bare VALUE path `let f = a::b::issue_for_actor;`.
      - a bare `identifier` whose text is `issue_for_actor` — covers a bare
        `issue_for_actor(d)` call and a bare value reference.

    EXCLUDED here (so this predicate fires ONLY on genuine references):
      - the DEFINITION site (exemption a): the `identifier` that is a
        `function_item`'s `name` field (`fn issue_for_actor`). A definition is
        not a reference.
      - a bare `identifier` that is a CHILD of a `scoped_identifier` — it is a
        path SEGMENT already accounted for by the enclosing scoped node
        (matching the scoped case would double-count, and a non-tail segment
        like the `a` in `a::issue_for_actor` is irrelevant anyway). We match the
        scoped node by its `name` field instead.
      - a bare-segment `identifier` inside a `use_list` / `scoped_use_list`
        that is itself part of an `as`-rename clause — the `use … as X` form is
        deferred to the `use_aliases` / mint-rename ban. NOTE: a *qualified*
        plain import (`use a::b::issue_for_actor;`) is NOT excluded — its path
        tail is a `scoped_identifier` whose `name` is the mint, so the
        scoped-identifier arm flags it as a reference (intended and correct:
        such an import enables a later bare `issue_for_actor(d)` call, so banning
        the import itself is strictly safer — and a non-aliased bare import has
        no legitimate use in the subtree).
        (fix 5) A BARE `use_list`/`scoped_use_list` MEMBER of the mint with NO
        `as` rename — `use self::{issue_for_actor};` / `use a::b::{X,
        issue_for_actor}` — IS now flagged as a reference (NOT deferred): the
        bare member re-exports the mint name into the importing module, enabling
        a later bare `issue_for_actor(d)` call exactly like the qualified plain
        import above. The `as`-rename clause (which wraps the member in a
        `use_as_clause`) is still deferred to the rename ban; a bare member's
        parent is the `use_list` / `scoped_use_list` directly, so it is
        distinguishable from the `as` form.
      - a `field_identifier` (`x.issue_for_actor`) — tree-sitter spells a
        method/field access tail as `field_identifier`, a DISTINCT node type
        from `identifier`, so it is never matched here. (Moot in practice: the
        mint is an associated fn taking `did: DID`, not `&self`, so
        `x.issue_for_actor()` cannot type-check — but excluding the node type
        keeps the predicate precise.)
    """
    if node.type == "scoped_identifier":
        name = node.child_by_field_name("name")
        return name is not None and node_text(name, source) == MINT_FN_NAME
    if node.type == "identifier":
        if node_text(node, source) != MINT_FN_NAME:
            return False
        parent = node.parent
        if parent is None:
            return False
        # Definition site: the `name` field of a `fn issue_for_actor` decl.
        if parent.type == "function_item":
            name_field = parent.child_by_field_name("name")
            if name_field is not None and name_field.id == node.id:
                return False
        # Path SEGMENT of a `scoped_identifier` (e.g. the `name` tail OR a
        # leading segment): the enclosing `scoped_identifier` arm above already
        # handles the tail; a leading segment is not a mint reference.
        if parent.type == "scoped_identifier":
            return False
        # (fix 5) BARE `use_list` / `scoped_use_list` MEMBER of the mint with NO
        # `as` rename — `use self::{issue_for_actor};` / `use a::b::{X,
        # issue_for_actor};`. The bare member's DIRECT parent is the
        # use-list node (an `as`-renamed member would be wrapped in a
        # `use_as_clause` instead, which is deferred to the rename ban). Such a
        # bare member re-exports the mint name into the importing module — a
        # reference, flagged symmetric to the qualified plain import.
        if parent.type in ("use_list", "scoped_use_list"):
            return True
        # Inside any OTHER `use` path / alias clause (`use … as`, a
        # `use_as_clause` path segment) — governed by the use-alias / rename
        # ban, not here.
        if _nearest_enclosing(node, ("use_declaration",)) is not None:
            return False
        return True
    return False


def _param_type_tail(param_node, source: bytes) -> str | None:
    """Return the TYPE tail-identifier of a `parameter` node, peeling any
    leading `&` / `&mut` references first. `&DID` → `DID`, `DID` → `DID`,
    `&crate::id::DID` → `DID`, `&Arc<Self>` → `Arc`. Returns None for a
    parameter with no type field (e.g. a bare `self_parameter`, which has no
    `type` field) or an unrecognized type node.
    """
    ty = param_node.child_by_field_name("type")
    # Peel `reference_type` (`&T`, `&mut T`, `&&T`) down to the referent.
    while ty is not None and ty.type == "reference_type":
        ty = ty.child_by_field_name("type")
    return _type_tail_identifier(ty, source)


def _param_binding_name(param_node, source: bytes) -> str | None:
    """Return the binding identifier of a `parameter`'s pattern, or None.

    A by-value pattern is the `pattern` field (`owning_did: DID` →
    `owning_did`). A typed-`self` pattern (`self: &Arc<Self>`) has a `self`
    node, not an `identifier`, so it returns None — it is never a DID param and
    never the owning binding.
    """
    pat = param_node.child_by_field_name("pattern")
    if pat is not None and pat.type == "identifier":
        return node_text(pat, source)
    return None


def _shadows_before(fn_node, name: str, before_byte: int, source: bytes) -> bool:
    """True if, anywhere inside `fn_node`'s body, the identifier `name` is
    RE-BOUND in a way that defeats name-matching of the bare mint argument — by
    a `let` declaration whose pattern binds `name`, an assignment whose
    left-hand side is the bare identifier `name`, OR a NON-`let` PATTERN BINDER
    (`match` arm, `if let`/`while let`/`let else` condition, `for` loop, closure
    parameter) whose pattern binds `name` and which ENCLOSES or LEXICALLY
    PRECEDES the mint.

    A shadow/rebind defeats name-matching: `let owning_did = make_evil();`
    before the mint makes the bare argument `owning_did` resolve to an
    attacker-controlled local rather than the caller-supplied parameter (G02).
    The SAME laundering is possible through every OTHER Rust binding form, and
    the bare `owning_did` at the mint then resolves to attacker data:

        match make_evil_did() { owning_did => issue_for_actor(owning_did.clone()) }
        if let owning_did = make_evil_did() { issue_for_actor(owning_did.clone()) }
        for owning_did in once(make_evil_did()) { issue_for_actor(owning_did.clone()) }
        (|owning_did: DID| issue_for_actor(owning_did.clone()))(make_evil_did())

    For a `let`/assignment the rebind is a STATEMENT that runs BEFORE the mint,
    so "before" is by source byte offset relative to the mint reference's
    position; a `let`/assignment AFTER the mint cannot affect the value the mint
    already consumed, so only earlier rebinds disqualify the exemption.

    For the NON-`let` binder forms the binding pattern is positioned at the head
    of a construct whose BODY CONTAINS the mint (the mint lives in the match-arm
    body / closure body / for body / if-let body). Such a binder's node starts
    BEFORE `before_byte` (the head precedes the body it encloses), so the same
    `n.start_byte < before_byte` test catches the enclosing case as well as a
    textually-earlier sibling binder. The shadowing pattern lives in the node's
    `pattern` field (`match_arm`, `let_condition`, `for_expression`) or its
    `parameters` field (`closure_expression`); these field/node names were
    confirmed empirically against the loaded tree-sitter-rust grammar
    (`if let`/`while let`/`let else` all surface a `let_condition`; `let else`
    additionally surfaces a `let_declaration`, already covered by the `let`
    arm). A POST-mint `let`/binder must still NOT disqualify the exemption, so
    the byte-order guard is preserved for all forms.

    Both `let` patterns (`identifier`, and destructuring patterns that name the
    identifier — `tuple_pattern`, `ref`/`mut`-prefixed bindings, etc.) and
    `assignment_expression` LHS identifiers are walked. Conservative by design:
    any earlier/enclosing binding of the param name dissolves the exemption.
    """
    body = fn_node.child_by_field_name("body")
    if body is None:
        return False

    def _pattern_binds(pat) -> bool:
        # Direct `identifier` pattern, or a compound pattern (tuple/ref/mut/
        # slice/struct) that contains the identifier as a bound name. Walk the
        # subtree for any `identifier` token equal to `name`. A `let` pattern
        # has no field-accesses (it is purely binding positions), so every
        # `identifier` in it is a binding.
        stack = [pat]
        while stack:
            p = stack.pop()
            if p.type == "identifier" and node_text(p, source) == name:
                return True
            stack.extend(p.children)
        return False

    # NON-`let` pattern-binder node types and the FIELD that carries their
    # binding pattern. A binder here shadows when it ENCLOSES the mint (its head
    # precedes `before_byte`) or lexically precedes it. Field/node names verified
    # empirically against the loaded grammar:
    #   `match_arm`        -> `pattern` (a `match_pattern` wrapping the binder)
    #   `let_condition`    -> `pattern` (if let / while let / let else head)
    #   `for_expression`   -> `pattern` (the loop binder)
    #   `closure_expression` -> `parameters` (`closure_parameters` of `parameter`s)
    _PATTERN_BINDER_FIELDS: dict[str, str] = {
        "match_arm": "pattern",
        "let_condition": "pattern",
        "for_expression": "pattern",
        "closure_expression": "parameters",
    }

    found = False

    def _walk(n) -> None:
        nonlocal found
        if found:
            return
        # Only consider rebinds positioned before the mint reference (a binder
        # that ENCLOSES the mint has its head before `before_byte` too).
        if n.start_byte < before_byte:
            if n.type == "let_declaration":
                pat = n.child_by_field_name("pattern")
                if pat is not None and _pattern_binds(pat):
                    found = True
                    return
            elif n.type == "assignment_expression":
                lhs = n.child_by_field_name("left")
                if (
                    lhs is not None
                    and lhs.type == "identifier"
                    and node_text(lhs, source) == name
                ):
                    found = True
                    return
            elif n.type in _PATTERN_BINDER_FIELDS:
                pat = n.child_by_field_name(_PATTERN_BINDER_FIELDS[n.type])
                if pat is not None and _pattern_binds(pat):
                    found = True
                    return
        for c in n.children:
            _walk(c)

    _walk(body)
    return found


def _mint_call_arg_is_owning_did(node, fn_node, source: bytes) -> bool:
    """True iff the exempt mint reference `node` is the FUNCTION of a
    `call_expression` whose SOLE argument is the genuine, unshadowed,
    caller-supplied owning DID of `build_actor_deps` (`fn_node`).

    This is the per-call mint-arg check (rule K exemption-(b) tightening,
    fix 3) and it is BINDING-based, not name-based. After this check, the ONLY
    value the exempt mint may consume is the very DID the actor was built for.
    The guarantee rests on three conjoined conditions:

      (1) EXACTLY ONE DID-typed parameter. Collect `build_actor_deps`'s
          parameters; the sole non-`self` parameter whose TYPE tail-identifier
          is `DID` (covers `owning_did: &DID` and `owning_did: DID`) is the
          owning binding. If ZERO or ≥2 such DID params exist, the exemption
          does NOT apply — the mint reference is flagged by rule K. This kills
          G03 (`fn build_actor_deps(&self, owning_did: &DID, attacker: DID)`
          then `issue_for_actor(attacker.clone())`): a second `DID` param makes
          the owning binding ambiguous, so no body mint can be trusted. Other
          (non-DID) parameters are ignored — they cannot carry a DID.

      (2) THE ARG IS PINNED TO THAT SOLE DID PARAM'S BINDING NAME. The call's
          single argument must be a bare `<owning>` or `<owning>.clone()` where
          `<owning>` is exactly the sole DID param's binding name — never a
          constructed `DID("…")` literal, a method call other than `.clone()`,
          a reborrow `&*x`, a field access, a different local, or an `if`/
          `match` expression. The real production call is
          `issue_for_actor(owning_did.clone())`.

      (3) NO SHADOW/REBIND of that binding before the mint. If a `let`
          declaration or an assignment re-binds the owning param's name
          anywhere in the body LEXICALLY BEFORE the mint call, the bare
          argument no longer resolves to the caller-supplied parameter, so the
          exemption is refused. This kills G02
          (`let owning_did = make_evil_did(); … issue_for_actor(owning_did.clone())`).

    With (1)+(2)+(3), an insider editing the body of `build_actor_deps` cannot
    substitute an attacker DID into the exempt mint: the only value it can pass
    is the unshadowed sole caller-supplied `&DID` parameter. The mint reference
    must be the `function` field of a `call_expression` (a bare value-path
    `let f = …::issue_for_actor;` re-exports the mint without calling it and is
    never exempt), and the argument list must contain EXACTLY ONE argument.
    """
    parent = node.parent
    if parent is None or parent.type != "call_expression":
        return False
    # `node` must be the CALL's `function` (the callee), not an argument. Compare
    # by the stable `.id` attribute — tree-sitter returns a FRESH wrapper on
    # every field access, so Python `is` is unreliable across wrappers.
    fn_field = parent.child_by_field_name("function")
    if fn_field is None or fn_field.id != node.id:
        return False
    args_node = parent.child_by_field_name("arguments")
    if args_node is None:
        return False
    arg_exprs = [c for c in args_node.children if c.is_named]
    if len(arg_exprs) != 1:
        return False
    arg = arg_exprs[0]
    # Accept `<ident>` (bare) or `<ident>.clone()` (a method call whose
    # receiver is a bare identifier and whose method is `clone`).
    ident_name: str | None = None
    if arg.type == "identifier":
        ident_name = node_text(arg, source)
    elif arg.type == "call_expression":
        fn = arg.child_by_field_name("function")
        if fn is not None and fn.type == "field_expression":
            value = fn.child_by_field_name("value")
            field = fn.child_by_field_name("field")
            if (
                value is not None
                and value.type == "identifier"
                and field is not None
                and node_text(field, source) == "clone"
            ):
                ident_name = node_text(value, source)
    if ident_name is None:
        return False
    # (1) Collect the SOLE non-`self` DID-typed parameter's binding name. Zero
    # or ≥2 DID-typed params → ambiguous owning binding → not exempt.
    params_node = fn_node.child_by_field_name("parameters")
    if params_node is None:
        return False
    did_param_names: list[str] = []
    for p in params_node.children:
        if p.type != "parameter":
            # `self_parameter` (bare `&self`) and punctuation are skipped; only
            # real `parameter` nodes carry types. A typed-`self` param
            # (`self: &Arc<Self>`) IS a `parameter` but its binding name is
            # `self` (not an `identifier`), and its type tail is `Arc`, so it
            # never counts as a DID param below.
            continue
        if _param_type_tail(p, source) != DID_PARAM_TYPE:
            continue
        binding = _param_binding_name(p, source)
        if binding is not None:
            did_param_names.append(binding)
    if len(did_param_names) != 1:
        return False
    owning_param = did_param_names[0]
    # (2) The mint arg must be pinned to THAT sole DID param's binding name.
    if ident_name != owning_param:
        return False
    # (3) No shadow/rebind of the owning param before the mint call.
    if _shadows_before(fn_node, owning_param, node.start_byte, source):
        return False
    return True


def _mint_ref_exempt_build_actor_deps(node, source: bytes, rel: str) -> bool:
    """True if a mint reference `node` is the ONE legitimate mint CALL site
    (rule K exemption b): it lives in the real build-site FILE
    (`BUILD_SITE_REL`), AND its nearest enclosing `function_item` is named
    `build_actor_deps`, AND that fn's enclosing `impl_item` targets `Supervisor`,
    AND that `impl Supervisor` is NOT nested under any in-file `mod` (a
    nested-mod `impl Supervisor` is a SHADOW that string-tail-matches the real
    type — fix 2), AND the mint CALL's sole argument is the fn's own
    `owning_did` parameter (a bare `<p>` or `<p>.clone()`, NOT a constructed
    `DID("…")` literal — fix 3 per-call mint-arg check).

    Structural AND file-pinned, NOT name-text-on-the-line: a reference is exempt
    ONLY when it lexically lives inside the REAL `Supervisor::build_actor_deps`'s
    body in `supervisor.rs` AND mints the actor's own identity. A mint call in
    any OTHER fn — even one a reviewer named `build_actor_deps` on a DIFFERENT
    impl, a real `impl Supervisor` planted in a DIFFERENT subtree file, a
    nested-mod SHADOW `impl Supervisor` in `supervisor.rs`, or a SECOND
    attacker-DID mint inside the real body — is NOT exempt. These three
    tightenings close the build-site trust hole (K01 nested-mod shadow, K02
    second/attacker-DID mint) that the bare type-tail + file pin left open.
    Verified against the real call at `supervisor.rs`:
    `issue_for_actor(owning_did.clone())` in `Supervisor::build_actor_deps`,
    whose `impl Supervisor` is top-level.
    """
    if rel != BUILD_SITE_REL:
        return False
    fn_node = _nearest_enclosing(node, ("function_item",))
    if fn_node is None:
        return False
    name_node = fn_node.child_by_field_name("name")
    if name_node is None or node_text(name_node, source) != BUILD_ACTOR_DEPS_FN:
        return False
    impl_node = _nearest_enclosing(fn_node, ("impl_item",))
    if impl_node is None:
        return False
    if (
        _type_tail_identifier(impl_node.child_by_field_name("type"), source)
        != SUPERVISOR_IMPL_TYPE
    ):
        return False
    # (fix 2) NESTED-MOD-SHADOW BAN. A `mod evil { struct Supervisor; impl
    # Supervisor { fn build_actor_deps(…) { …issue_for_actor… } } }` planted in
    # supervisor.rs string-tail-matches `Supervisor` and passes the file pin —
    # but it is a SHADOW type, not the real `Supervisor`. The canonical
    # `impl Supervisor` is TOP-LEVEL, so an enclosing `mod` means a shadow:
    # NOT exempt (its mint reference is then flagged by rule K). Mirrors rule I.
    if _nested_mod_ancestor(impl_node) is not None:
        return False
    # (fix — CLOSURE-LAUNDERED MINT) ESCAPABLE-SCOPE GUARD. The exempt mint must
    # be DIRECTLY in `build_actor_deps`'s body, NOT nested in a deferred-execution
    # scope (`closure_expression` / `async_block` / `gen_block` / nested
    # `function_item`) between the mint and `fn_node`. Without this, a mint inside
    # such a scope still has `build_actor_deps` as its nearest `function_item` and
    # would be exempt — but the closure/future can be RETURNED or STORED and
    # invoked LATER with an attacker-chosen DID, the same threat rules H/I guard
    # against at construction sites. Reuse the same `_escapable_scope_between`
    # helper: if ANY escapable scope intervenes between the mint reference and the
    # real `build_actor_deps` body, the mint is NOT exempt → rule K flags it. The
    # real production mint is a plain statement directly in the (async) fn body,
    # whose body is a `block` (not an `async_block`), so it has no intervening
    # escapable scope and stays exempt.
    if _escapable_scope_between(node, fn_node) is not None:
        return False
    # (fix 3) PER-CALL MINT-ARG CHECK. The exempt mint may only mint the actor's
    # OWN identity: its sole argument must be a bare `owning_did` parameter (or
    # `owning_did.clone()`), never a constructed `DID("attacker")` literal, a
    # field access, or another local. A second mint call in the same body that
    # forges an attacker DID is therefore NOT exempt (K02).
    return _mint_call_arg_is_owning_did(node, fn_node, source)


def _nearest_enclosing(node, kinds: tuple[str, ...]):
    """Walk PARENTS (not `node` itself) and return the first ancestor whose
    `.type` is in `kinds`, else None.
    """
    cur = node.parent
    while cur is not None:
        if cur.type in kinds:
            return cur
        cur = cur.parent
    return None


# Tree-sitter-rust node types that introduce an ESCAPABLE / DEFERRED-execution
# scope: a body that can be MOVED out of its lexically-enclosing fn and invoked
# later, elsewhere, with attacker-chosen arguments. A cap struct literal nested
# inside one of these — even when the literal's NEAREST `function_item` ancestor
# is an allowlisted constructor — is NOT a legitimate inline construction: the
# scope can capture the module-private `did` field legally (Rust field privacy
# is module-scoped) and hand a forging callable to handler code, so the
# allowlisted fn's name is no longer the boundary on WHO mints.
#
# Determined EMPIRICALLY against the loaded grammar (do not trust this list as a
# guess — it was confirmed by parsing each form and printing node types):
#   `|x| …`        / `move |x| …`        -> `closure_expression`
#   `async { … }`  / `async move { … }`  -> `async_block`
#   `gen { … }`    / `gen move { … }`    -> `gen_block`   (present in grammar)
#   a nested `fn inner(){ … }`           -> `function_item`
# A plain `block`, `if_expression`, `match`/arm, `let_declaration`,
# `call_expression`/`arguments`, `return_expression`, etc. are INLINE-executed
# (run as part of the enclosing fn's single invocation) and are deliberately
# NOT in this set — `Some(Self { did })` and `{ let t = Self { did }; t }` must
# still PASS.
#
# Belt-and-suspenders: should a future grammar revision spell an async/gen body
# as a plain `block` carrying an `async`/`gen` child TOKEN rather than a
# distinct `async_block`/`gen_block` node, `_escapable_scope_between` ALSO
# detects that shape, so the class stays closed even if the node name drifts.
ESCAPABLE_SCOPE_TYPES: frozenset[str] = frozenset(
    {
        "closure_expression",
        "async_block",
        "gen_block",
        # A nested `function_item` between the literal and the OUTER allowlisted
        # fn is itself an escapable scope. `_nearest_enclosing(..., function_item)`
        # stops at the nearest fn, so an inner fn normally BECOMES `fn_node` and
        # fails the NAME check (it is not `issue_for_actor`/`reissue`). The case
        # where the inner fn is itself NAMED `issue_for_actor`/`reissue` to
        # launder the name is NOT closed by this entry — the inner fn is then
        # `fn_node` itself (the boundary), so `_escapable_scope_between` never
        # sees it as an INTERVENING node and this `function_item` arm never
        # fires for it. That name-laundering case is closed instead by the
        # `is_impl_method` structural guard in `_construction_hit_reason` (a
        # nested fn's parent is a `block`, not an impl `declaration_list`). This
        # `function_item` entry remains load-bearing for a DIFFERENT shape: a
        # nested fn that sits BETWEEN the literal and a separate, outer
        # allowlisted `fn_node` (e.g. literal inside `fn inner()` inside a
        # closure inside `reissue`), where the nested fn is a genuine
        # intervening escapable scope on the parent chain.
        "function_item",
    }
)

# Block-introducing tokens that, if they appear as a direct child of a plain
# `block` node between the literal and the enclosing fn, mark that block as a
# deferred async/gen body (grammar-drift fallback for the case where the
# grammar does NOT emit a distinct `async_block` / `gen_block` node).
_DEFERRED_BLOCK_TOKENS: frozenset[str] = frozenset({"async", "gen"})


def _escapable_scope_between(struct_expr_node, fn_node) -> str | None:
    """Return the node-type name of the FIRST escapable / deferred-execution
    scope found on the parent chain from `struct_expr_node` UP TO (but not
    including) `fn_node`, or None if the path is all inline scopes.

    `fn_node` is the literal's nearest enclosing `function_item` (the candidate
    allowlisted constructor). Rule H is otherwise blind to a literal nested in a
    `closure_expression` / `async_block` / `gen_block` / nested `function_item`
    that sits between the literal and `fn_node`: a closure/async/gen body is a
    distinct expression node, NOT a `function_item`, so the nearest-`function_item`
    walk STEPS PAST it to the allowlisted fn and the construction PASSES — a real,
    compiling, handler-reachable forgery (e.g. a `reissue` that returns
    `Box<dyn Fn(DID) -> OwnedIdentityDid>` whose closure body forges any DID).
    This closes the WHOLE escapable-scope class, not just the closure spelling.
    """
    # NOTE: identity is compared via the stable `.id` attribute, NOT Python
    # `is`. tree-sitter-python returns a FRESH wrapper object on every `.parent`
    # access, so `cur is not fn_node` is unreliable (two wrappers for the SAME
    # underlying node compare unequal under `is`). Each node's `.id` is stable
    # across accesses, so `cur.id != fn_node.id` is the correct stop condition;
    # using `is` here false-FAILED the production `issue_for_actor`/`reissue`
    # (their own enclosing `function_item` was re-wrapped, never matched `is
    # fn_node`, and was then mis-flagged as an intervening escapable
    # `function_item`).
    fn_id = fn_node.id
    cur = struct_expr_node.parent
    while cur is not None and cur.id != fn_id:
        if cur.type in ESCAPABLE_SCOPE_TYPES:
            return cur.type
        # Grammar-drift fallback: a plain `block` whose immediate children
        # include an `async`/`gen` keyword token is a deferred body even if the
        # grammar did not wrap it in a distinct `async_block`/`gen_block`.
        if cur.type == "block":
            for child in cur.children:
                if child.type in _DEFERRED_BLOCK_TOKENS:
                    return f"{child.type} {cur.type}"
        cur = cur.parent
    return None


def _impl_targets_cap(impl_node, source: bytes) -> bool:
    """True if an `impl_item` node's target type (its `type` field) is the
    capability type — i.e. `impl … OwnedIdentityDid { … }` (inherent OR trait
    impl). Used by rule H to decide whether a `Self { … }` literal inside the
    impl constructs the cap, and whether a construction's enclosing impl is an
    inherent cap impl.
    """
    if impl_node is None:
        return False
    return _type_tail_identifier(
        impl_node.child_by_field_name("type"), source
    ) == TYPE_NAME


def _impl_is_inherent(impl_node) -> bool:
    """True if an `impl_item` is an INHERENT impl (`impl Ty { … }`), i.e. it
    has NO `trait` field. A trait impl (`impl Trait for Ty`) has a `trait`
    field. Rule H requires the allowlisted constructor live in an INHERENT
    `impl OwnedIdentityDid` block — a `fn reissue` smuggled into a TRAIT impl
    on the cap (or any trait impl) is NOT an allowlisted construction site.
    """
    return (
        impl_node is not None
        and impl_node.child_by_field_name("trait") is None
    )


def _nested_mod_ancestor(node):
    """Return the FIRST `mod_item` ancestor strictly BETWEEN `node` and the
    enclosing `source_file`, or None if `node` is at the file's TOP LEVEL
    (no intervening `mod_item`).

    Rule (I) — IN-FILE NESTED-MOD BAN. Rules (G)/(H) collect every
    `impl OwnedIdentityDid` block and every cap `struct_expression` in the
    declaring file REGARDLESS of nesting (the `walk` recurses through
    `mod_item` bodies), but the canonical PRODUCTION cap impl + its two
    `Self { … }` literals live at the declaring file's TOP LEVEL. A SECOND
    cap impl — or any cap struct literal — placed inside a nested `mod` in
    the declaring file is the in-file analogue of the `#[path]`-include
    escape (`_path_attr_escape`): an extra construction surface that a
    reviewer scanning the top-level body can miss. The nested-mod impl can
    re-host a constructor (even an allowlisted-NAMED one, `issue_for_actor`,
    which rule G/H per-file would WAVE THROUGH) and a literal-free wrapper at
    module level can re-export it to all of `crate::context`. Because the
    production cap impl/literals are TOP-LEVEL, hard-failing any cap
    inherent-impl / cap struct-literal nested under a `mod_item` in the
    declaring file is strictly ADDITIVE. We walk PARENTS and return the
    nearest `mod_item` before hitting the `source_file` boundary.
    """
    cur = node.parent
    while cur is not None:
        if cur.type == "source_file":
            return None
        if cur.type == "mod_item":
            return cur
        cur = cur.parent
    return None


def _return_mentions_cap_by_value(return_node, source: bytes, in_cap_impl: bool) -> bool:
    """True if a fn's `return_type` node MENTIONS the capability type BY
    VALUE — i.e. the cap tail identifier (`OwnedIdentityDid`, incl. a scoped
    `…::OwnedIdentityDid`) OR a bare `Self` (only when the fn is inside an
    inherent/trait impl whose target IS the cap, `in_cap_impl`) appears in the
    return type and is NOT located SOLELY behind a `&` reference.

    This is the matcher for rule (J) — the BY-VALUE CAP-RETURN ban. A fn that
    returns the cap by value re-exports a mint surface even WITHOUT a struct
    literal (it can call the `pub(super)` `issue_for_actor`), so rule H (a
    construction-site scanner that only sees struct literals) and rule G (which
    only inspects INHERENT methods on the cap) both miss it. We walk the
    `return_type` subtree; a `reference_type` (`&T` / `&mut T`) marks its
    descendants as "behind a reference" so `-> &OwnedIdentityDid` / `-> &DID`
    / `-> &Self` are NOT by-value returns (the existing `&OwnedIdentityDid`
    parameter contract relies on references being borrows, not ownership
    transfers). The cap appearing inside `Option<…>` / `Result<…>` / `Box<…>`
    / a tuple / a `dyn Fn(..) -> Cap` / a fn-pointer return IS by-value (the
    callee yields an owned token, however wrapped) and IS flagged.

    `Self` is matched as the cap ONLY when `in_cap_impl` is True so a `Self`
    return in some OTHER type's impl (or a free fn, where `Self` is
    meaningless) is not misread as a cap return.
    """
    if return_node is None:
        return False
    found = [False]

    def _rec(n, under_ref: bool) -> None:
        if n.type == "reference_type":
            # Everything inside a `&T` / `&mut T` is borrowed, not owned.
            for c in n.children:
                _rec(c, True)
            return
        if n.type in ("function_type", "abstract_type", "dynamic_type"):
            # A function-type node (`fn(..) -> T`, `dyn Fn(..) -> T`,
            # `impl Fn(..) -> T`) borrowed behind a `&` (`-> &dyn Fn() ->
            # OwnedIdentityDid`) borrows the CALLABLE, but the callable's
            # OUTPUT is OWNED — invoking it yields an owned cap token the
            # caller keeps. Recurse into the `function_type`'s `return_type`
            # field with `under_ref=False` so a cap OUTPUT is flagged even
            # when the callable itself is borrowed; the rest of the node (the
            # `parameters` input types, the `Fn`/`dyn`/`impl` head) stays at
            # the inherited `under_ref` since those are not the owned output.
            # `abstract_type` (`impl Fn(..) -> T`) and `dynamic_type` (`dyn
            # Fn(..) -> T`) wrap a `function_type`; their non-function-type
            # children carry the inherited `under_ref` and the inner
            # `function_type` re-enters this arm, resetting its own
            # `return_type`. (Rule K already flags these shapes as forgeries
            # because the body CALLS the mint; this keeps rule J's by-value
            # accuracy honest for the borrowed-callable / owned-output case.)
            ret_field = n.child_by_field_name("return_type")
            for c in n.children:
                if ret_field is not None and c.id == ret_field.id:
                    _rec(c, False)
                else:
                    _rec(c, under_ref)
            return
        if n.type in ("type_identifier", "scoped_type_identifier"):
            tail = _type_tail_identifier(n, source)
            if not under_ref and tail == TYPE_NAME:
                found[0] = True
            if not under_ref and tail == "Self" and in_cap_impl:
                found[0] = True
        for c in n.children:
            _rec(c, under_ref)

    _rec(return_node, False)
    return found[0]


# Interior-mutability / shared-cell wrapper generics that hand out an OWNED cap
# token to anyone holding a SHARED `&` reference to the wrapper — defeating the
# `&OwnedIdentityDid` shared-borrow contract (a shared borrow must be read-only,
# unable to mint). A `RefCell<…Cap…>` / `Mutex<…Cap…>` / `OnceLock<…Cap…>` etc.
# behind a `&` lets a handler `.borrow_mut()` / `.lock()` / `.take()` an owned
# token out, so the cap reaching one of these wrappers ANYWHERE (param, return,
# struct field, static) is a by-value escape channel. Determined against the
# common std interior-mutability surface; matched by the wrapper type's TAIL
# identifier so `core::cell::RefCell` / `std::sync::Mutex` are caught too.
_INTERIOR_MUT_WRAPPERS: frozenset[str] = frozenset(
    {
        "Cell",
        "RefCell",
        "OnceCell",
        "OnceLock",
        "LazyCell",
        "LazyLock",
        "Mutex",
        "RwLock",
        "UnsafeCell",
        "SyncUnsafeCell",
    }
)


def _type_escape_cap_reason(
    type_node, source: bytes, flag_by_value: bool = False
) -> str | None:
    """If `type_node` is a type in which the capability appears in an ESCAPE
    CHANNEL — behind a MUTABLE reference/pointer (`&mut`/`*mut`), inside an
    interior-mutability wrapper (`Cell`/`RefCell`/`OnceCell`/`OnceLock`/
    `Mutex`/`RwLock`/`UnsafeCell`/…<…Cap…>), or (when `flag_by_value` is True)
    PLAIN BY VALUE not behind a shared `&` — return a human reason string, else
    None.

    This is the matcher for the KEYSTONE escape-position rule (fix 1). The cap
    appearing in such a position lets a holder MINT/EXTRACT an owned token from a
    channel that rule J (plain by-value RETURN scan) and rule K (mint-CALL scan)
    do not cover: an out-param (`&mut OwnedIdentityDid`, `&mut Option<…Cap…>`),
    a `static`/`const` sink (`static …: Option<Cap>`), or an interior-mut cell
    handed out behind a SHARED `&` borrow.

    `flag_by_value` SELECTS the context:
      - False (fn param / fn return / struct field): a PLAIN by-value cap is NOT
        an escape here — a by-value param consumes the token, a by-value return
        is rule J's channel (with its constructor exemption), and a plain owning
        struct field (`ActorDeps { owned_identity: OwnedIdentityDid }`) is the
        legit by-value home. Only `&mut`/`*mut`/interior-mut occurrences flag.
      - True (`static`/`const` item): a `static`/`const` holding the cap BY
        VALUE (e.g. `static …: Option<OwnedIdentityDid>`) is itself a global
        SINK from which an owned token can be `.take()`n / moved out — flag ANY
        cap occurrence not solely behind a SHARED `&` (incl. plain by-value,
        `&mut`, `*mut`, interior-mut). A `static …: &OwnedIdentityDid` shared
        ref would be read-only and is not flagged.

    It MUST NOT flag a plain `&OwnedIdentityDid` SHARED borrow (read-only — the
    legit `SupervisorHandle` per-identity param / handle field), nor `as_did`'s
    `&DID` accessor.

    Walk the type subtree tracking, for each cap occurrence: whether it is under
    a SHARED `&` (read-only, never an escape), behind a `&mut`/`*mut`, or inside
    an interior-mut wrapper. A cap under ONLY a shared `&` and no wrapper is NOT
    an escape. A plain by-value cap is an escape ONLY when `flag_by_value`.
    """
    if type_node is None:
        return None
    hit: list[str | None] = [None]

    def _rec(n, under_shared_ref: bool, mut_escape: bool, wrapper: str | None) -> None:
        if hit[0] is not None:
            return
        if n.type == "reference_type":
            # `&T` (shared) vs `&mut T` (mutable). A `mutable_specifier` child
            # marks `&mut`. A SHARED `&` makes its descendants read-only (sets
            # under_shared_ref True, clears mut_escape/wrapper); a `&mut` sets
            # mut_escape. Either way, an enclosing-reference CLEARS any prior
            # wrapper (the reference is the new outermost indirection).
            is_mut = any(c.type == "mutable_specifier" for c in n.children)
            for c in n.children:
                if c.type == "mutable_specifier":
                    continue
                if is_mut:
                    _rec(c, False, True, None)
                else:
                    _rec(c, True, False, None)
            return
        if n.type == "pointer_type":
            # `*const T` vs `*mut T`. A `mutable_specifier` marks `*mut`.
            is_mut = any(c.type == "mutable_specifier" for c in n.children)
            for c in n.children:
                if c.type == "mutable_specifier":
                    continue
                if is_mut:
                    _rec(c, False, True, None)
                else:
                    # `*const Cap` is read-pointer; treat like a shared borrow.
                    _rec(c, True, False, None)
            return
        if n.type == "generic_type":
            head = _type_tail_identifier(
                n.child_by_field_name("type"), source
            )
            args = n.child_by_field_name("type_arguments")
            if head in _INTERIOR_MUT_WRAPPERS:
                # The cap inside this wrapper escapes regardless of any
                # enclosing shared `&` — a `&RefCell<Cap>` still yields an
                # owned token via `.borrow_mut()`. Mark wrapper, clear
                # under_shared_ref (the wrapper re-grants mutable access).
                if args is not None:
                    for c in args.children:
                        _rec(c, False, mut_escape, head)
                # The wrapper head identifier itself is not a cap occurrence.
                return
            # Non-interior-mut generic (`Option<…>`, `Vec<…>`, `Box<…>`,
            # tuple-ish): propagate the current escape context into the args so
            # `&mut Option<Cap>` / `&mut Vec<Cap>` / `Mutex<Box<Cap>>` /
            # `static …: Option<Cap>` are caught. The head is not the cap.
            if args is not None:
                for c in args.children:
                    _rec(c, under_shared_ref, mut_escape, wrapper)
            return
        if n.type in ("type_identifier", "scoped_type_identifier"):
            tail = _type_tail_identifier(n, source)
            if tail == TYPE_NAME:
                if wrapper is not None:
                    hit[0] = (
                        f"{TYPE_NAME} appears inside an interior-mutability "
                        f"wrapper `{wrapper}<…>`"
                    )
                elif mut_escape:
                    hit[0] = (
                        f"{TYPE_NAME} appears behind a `&mut`/`*mut` (an "
                        f"out-parameter / mutable-escape position)"
                    )
                elif flag_by_value and not under_shared_ref:
                    hit[0] = (
                        f"{TYPE_NAME} appears BY VALUE in a `static`/`const` "
                        f"item (a global sink an owned token can be moved out of)"
                    )
            return
        for c in n.children:
            _rec(c, under_shared_ref, mut_escape, wrapper)

    _rec(type_node, False, False, None)
    return hit[0]


def _struct_expr_constructs_cap(struct_expr_node, source: bytes) -> bool:
    """True if a `struct_expression` node CONSTRUCTS the capability type:

      - its `name` tail identifier is `OwnedIdentityDid` (covers
        `OwnedIdentityDid { … }` AND a scoped `…::OwnedIdentityDid { … }`), OR
      - its `name` is the literal `Self` AND its nearest enclosing `impl_item`
        targets `OwnedIdentityDid` (the real `issue_for_actor` / `reissue` use
        `Self { did … }`).

    A `Self { … }` whose enclosing impl targets some OTHER type, or a literal
    named after a different type (incl. an ALIAS like `OwnedCap { … }`, which
    is independently banned by rule F.2), is NOT collected here.
    """
    name_node = struct_expr_node.child_by_field_name("name")
    if name_node is None:
        return False
    tail = _type_tail_identifier(name_node, source)
    if tail == TYPE_NAME:
        return True
    if tail == "Self":
        impl_node = _nearest_enclosing(struct_expr_node, ("impl_item",))
        return _impl_targets_cap(impl_node, source)
    return False


def _construction_hit_reason(struct_expr_node, source: bytes) -> str | None:
    """Return a rule-H diagnostic reason if this cap-constructing
    `struct_expression` is NOT lexically inside the body of an allowlisted
    INHERENT constructor (`issue_for_actor` / `reissue` on
    `OwnedIdentityDid`), else None.

    The check walks UP to the construction's nearest enclosing `function_item`
    and FAILs when EITHER:
      - that fn's name is not in CONSTRUCTING_FNS (a free fn / helper method /
        differently-named fn — `forge_token`, `make`, `clone`, `from`, …), OR
      - the fn is not inside an INHERENT `impl OwnedIdentityDid` block (a
        method on a HELPER struct, or a TRAIT-impl method, even one NAMED
        `reissue`).
    A construction NOT inside any `function_item` at all (a free-standing
    module-level `OwnedIdentityDid { … }`, or one inside a closure / nested fn
    that itself sits outside an allowlisted fn) also FAILs.

    Rust field privacy is MODULE-scoped: the private `did` field is reachable
    from ANY item in the declaring module, so the type system does NOT block an
    in-module literal. Only the two allowlisted inherent constructors may build
    the capability; this rule is the source-text closure over that invariant.
    """
    label = node_text(struct_expr_node.child_by_field_name("name"), source).strip()
    fn_node = _nearest_enclosing(struct_expr_node, ("function_item",))
    if fn_node is not None:
        name_node = fn_node.child_by_field_name("name")
        fn_name = node_text(name_node, source) if name_node is not None else "<anon>"
        impl_node = _nearest_enclosing(fn_node, ("impl_item",))
        # `fn_node` must be a TRUE impl method to honor the name-allowlist. A
        # REAL inherent method's `function_item` is a direct child of the impl
        # block's `declaration_list`, so its parent chain is
        # `function_item -> declaration_list -> impl_item`. A NESTED fn (one
        # declared lexically INSIDE another fn's body — including a nested fn
        # named `issue_for_actor`/`reissue` to launder the name) has a `block`
        # as its parent, NOT a `declaration_list`, so this predicate is False
        # for it. Without this guard a nested `fn issue_for_actor(d: DID) ->
        # OwnedIdentityDid { Self { did: d } }` declared inside the real
        # constructor would (a) supply a CONSTRUCTING_FNS name, (b) resolve its
        # nearest enclosing `impl_item` to the real cap impl, and (c) never trip
        # the escapable-scope check (it IS `fn_node`, the boundary, never an
        # INTERVENING escapable node) — forging any DID and escaping as a
        # `fn`-pointer / `impl Fn`. ANDing `is_impl_method` in is strictly
        # ADDITIVE: it can only make `in_allowlisted` MORE restrictive, never
        # admit a construction the name/impl checks would have rejected.
        is_impl_method = (
            fn_node.parent is not None
            and fn_node.parent.type == "declaration_list"
            and fn_node.parent.parent is not None
            and fn_node.parent.parent.type == "impl_item"
        )
        in_allowlisted = (
            is_impl_method
            and fn_name in CONSTRUCTING_FNS
            and _impl_targets_cap(impl_node, source)
            and _impl_is_inherent(impl_node)
        )
        if in_allowlisted:
            # The literal's nearest `function_item` is an allowlisted INHERENT
            # constructor — but rule H must ALSO verify the literal is INLINE in
            # that fn's body, not nested in an escapable / deferred-execution
            # scope (closure / async block / gen block / nested fn) that sits
            # between the literal and the allowlisted fn. Such a scope can be
            # MOVED out and invoked later by handler code with an attacker-chosen
            # DID, captures the module-private `did` field legally, and forges a
            # token — defeating cross-identity isolation — while the
            # nearest-`function_item` walk steps PAST it and would otherwise PASS.
            escaped = _escapable_scope_between(struct_expr_node, fn_node)
            if escaped is None:
                return None
            return (
                f"`{label} {{ … }}` constructed inside a `{escaped}` nested "
                f"within the allowlisted constructor `{fn_name}`; an escapable "
                f"/ deferred-execution scope (closure / async block / gen block "
                f"/ nested fn) can be moved out of `{fn_name}` and invoked later "
                f"by handler code with an attacker-chosen DID — it captures the "
                f"module-private `did` field legally (Rust field privacy is "
                f"module-scoped) and forges a token, so the allowlisted fn name "
                f"is no longer the boundary on WHO mints. The cap literal MUST be "
                f"constructed INLINE in the body of `issue_for_actor`/`reissue`, "
                f"never inside a closure / async / gen / nested-fn scope"
            )
        return (
            f"`{label} {{ … }}` constructed in fn `{fn_name}` outside the "
            f"allowlisted constructors `issue_for_actor`/`reissue`; a free fn "
            f"/ other-type method / closure / trait-impl method in the "
            f"declaring module can mint via the module-private field (Rust "
            f"field privacy is module-scoped, so the type system does NOT "
            f"block an in-module literal). Only the two allowlisted INHERENT "
            f"constructors `issue_for_actor`/`reissue` may build the "
            f"capability"
        )
    return (
        f"`{label} {{ … }}` constructed outside any function (free-standing / "
        f"closure / nested-fn module-level construction); only the allowlisted "
        f"INHERENT constructors `issue_for_actor`/`reissue` may build the "
        f"capability — Rust field privacy is module-scoped, so an in-module "
        f"literal is type-system-permitted and must be gate-blocked"
    )


# -----------------------------------------------------------------------------
# Inherent-impl constructor inspection
# -----------------------------------------------------------------------------


def _inherent_fns(impl_node, source: bytes) -> list[tuple[str, str, str, str, int]]:
    """For an `impl … OwnedIdentityDid { ... }` block (inherent OR trait),
    return a list of (fn_name, visibility, params_text, return_type_text,
    line) for every `function_item` in the impl body. The caller decides how
    to use each tuple: for an INHERENT impl the closed-allowlist rule (G)
    keys on the fn NAME; for a TRAIT impl the extended rule (D) keys on the
    return type (a trait method that returns the cap type is a mint surface).

    `visibility` is '' for private, else the modifier text (`pub`,
    `pub(super)`, `pub(crate)`, `pub(in crate::context)`, ...).
    `params_text` is the raw text of the `parameters` node (including the
    surrounding parens), used to assert which fns take a raw-`DID`
    argument.
    `return_type_text` is the raw text of the `return_type` field node
    (the type after `->`), or '' when the fn has no explicit return type
    (i.e. returns `()`). For the INHERENT-impl allowlist (rule G) the return
    text is NOT the security boundary — the fn NAME is; the return text is
    used only as a SANITY CHECK on the allowlisted mint (`issue_for_actor`
    should return Self) and as the trait-mint test for rule D. This is robust
    to `const fn`, multi-line signatures, `where` clauses, and attributes
    between `impl` and `fn`: tree-sitter exposes the return type as the
    `return_type` field of the `function_item` regardless of those surface
    variations.
    """
    out: list[tuple[str, str, str, str, int]] = []
    body = impl_node.child_by_field_name("body")
    if body is None:
        return out
    for child in body.children:
        if child.type != "function_item":
            continue
        name_node = child.child_by_field_name("name")
        if name_node is None:
            continue
        fn_name = node_text(name_node, source)
        vis = ""
        for c in child.children:
            if c.type == "visibility_modifier":
                vis = node_text(c, source).strip()
                break
        params_node = child.child_by_field_name("parameters")
        params_text = node_text(params_node, source) if params_node is not None else ""
        return_node = child.child_by_field_name("return_type")
        return_type_text = (
            node_text(return_node, source) if return_node is not None else ""
        )
        out.append(
            (
                fn_name,
                vis,
                params_text,
                return_type_text,
                child.start_point[0] + 1,
            )
        )
    return out


# -----------------------------------------------------------------------------
# Macro and `#[path]` escape detection (rules B / C — close the AST-walk
# blind spots that tree-sitter cannot see through).
# -----------------------------------------------------------------------------


def _attr_is_cfg_test(attr_item_node, source: bytes) -> bool:
    """True IFF this `attribute_item` is a TEST-ONLY `cfg` gate — i.e. the
    item it gates compiles ONLY when `test` is set. Exactly those items'
    macros are exempt from the declaring-file category ban (the test
    module's `assert_eq!` / witness macros).

    A naive "`test` token appears anywhere in `cfg(...)`" predicate is
    BOOLEAN-BLIND to `not()` / `any()` and mislabels PRODUCTION gates as
    test-only:
      - `#[cfg(not(test))]`            → compiles when NOT testing (PROD)
      - `#[cfg(all(not(test)))]`       → PROD
      - `#[cfg(not(all(test)))]`       → PROD
      - `#[cfg(any(test, feature="x"))]` → PROD-active when `x` is on
        (the crate uses `#[cfg(any(test, feature = "testing"))]`
        PERVASIVELY) — a macro under such a gate compiles into production
        and would slip the gate if wrongly exempted.

    Correct predicate: a cfg is test-only IFF the `test` token is reached
    through ONLY `all(...)` combinators — with NO enclosing `not(` AND NO
    enclosing `any(`. (`cfg(test)` → exempt; `cfg(all(test, unix))` →
    exempt; `cfg(all(test, feature="x"))` → exempt; `cfg(not(test))` → NOT
    exempt; `cfg(any(test, feature))` → NOT exempt; `cfg(any(all(test), …))`
    → NOT exempt — the `any` encloses.)

    Implementation: a combinator-stack walker. For EACH `\btest\b`
    occurrence inside the `cfg(...)` text, we walk the `all|any|not(` / `(`
    / `)` tokens BEFORE it to build the enclosing-combinator stack; the
    occurrence is test-REQUIRING iff its stack contains neither `not` nor
    `any`. Return True iff at least one `test` occurrence is test-requiring.
    String literals are stripped first so a `cfg(feature = "test-x")`
    payload cannot false-match.
    """
    txt = _strip_string_literals(node_text(attr_item_node, source))
    # Must be a `cfg(...)` attribute (not `cfg_attr`, not some other attr).
    if re.search(r"\bcfg_attr\b", txt):
        return False
    m = re.search(r"\bcfg\s*\(", txt)
    if m is None:
        return False
    inner = txt[m.end() :]
    for tm in re.finditer(r"\btest\b", inner):
        stack: list[str | None] = []
        for cm in re.finditer(r"\b(all|any|not)\s*\(|\(|\)", inner[: tm.start() + 1]):
            tok = cm.group(0)
            if tok.endswith("("):
                nm = re.match(r"\b(all|any|not)\b", tok)
                stack.append(nm.group(1) if nm else None)
            elif tok == ")" and stack:
                stack.pop()
        if "not" not in stack and "any" not in stack:
            return True
    return False


def _has_preceding_cfg_test(node, source: bytes) -> bool:
    """True if `node` is directly gated by a preceding `#[cfg(test)]` /
    `#[cfg(all(test, …))]` attribute sibling.

    tree-sitter attaches an item's attributes as PRECEDING SIBLING
    `attribute_item` nodes (NOT children), exactly as `_preceding_derives`
    walks them. We step backwards over attribute/comment siblings and return
    True the moment we see a test-gating cfg attribute.
    """
    sibling = node.prev_sibling
    while sibling is not None:
        if sibling.type == "attribute_item":
            if _attr_is_cfg_test(sibling, source):
                return True
            sibling = sibling.prev_sibling
            continue
        if sibling.type in ("line_comment", "block_comment"):
            sibling = sibling.prev_sibling
            continue
        break
    return False


def _inside_cfg_test(node, source: bytes) -> bool:
    """True if `node` lives inside a `#[cfg(test)]`-gated item ANYWHERE up
    its ancestor chain — e.g. a macro invocation inside a
    `#[cfg(test)] mod tests { … }`, or inside a `#[cfg(test)] fn helper()`.

    Walks every ancestor and, for each item-like ancestor, checks whether
    that ancestor carries a preceding test-gating cfg attribute. The
    declaring file's production body is macro-free; its only macros
    (`assert_eq!`, etc.) live in the `#[cfg(test)] mod tests` module, so this
    predicate is what exempts them from the declaring-file category ban while
    keeping every production-path macro banned.
    """
    cur = node.parent
    while cur is not None:
        if cur.type in (
            "mod_item",
            "function_item",
            "impl_item",
            "trait_item",
            "block",
            "struct_item",
            "enum_item",
        ) and _has_preceding_cfg_test(cur, source):
            return True
        cur = cur.parent
    return False


def _macro_def_synthesizes_metavar_impl(text: str) -> bool:
    """True if a `macro_rules!` body synthesizes an `impl` on a passed-in
    METAVARIABLE type — an INHERENT impl (`impl $t { … }`) OR a TRAIT impl
    (`impl Trait for $t { … }`). Such a macro can be invoked with the
    capability type — `build_mint!(OwnedIdentityDid)` — to materialize an
    `impl OwnedIdentityDid { fn forge(_d: DID) -> $t { … } }` (or a trait-impl
    mint) that the AST walk never sees (the def body carries `impl … $t`, not
    the cap token; the invocation carries the cap token, not `impl`).
    Recognizing the payload (a function name, a return token) is defeatable;
    banning the CATEGORY — any macro that synthesizes an impl on a
    metavariable type — is not.

    A narrow `\\bimpl\\s+\\$` form MISSED several real synthesizer shapes:
      - `impl<T> $t`        — generic-parameterized inherent impl
      - `impl Trait for $t` — trait-impl synthesizer on a metavariable
      - `impl /*c*/ $t`     — comment between `impl` and the metavariable
    We strip comments (and string literals, so an `impl $t` mention inside a
    format string cannot false-match) first, then match a metavariable in
    inherent OR trait-impl position, tolerating an optional generic-parameter
    list and an optional `… for` clause before the `$`.
    """
    stripped = _strip_comments(_strip_string_literals(text))
    return (
        re.search(
            r"\bimpl\b(?:\s*<[^>]*>)?\s*(?:[^\n;{]*?\bfor\s+)?\$",
            stripped,
        )
        is not None
    )


def _macro_invocation_names_cap(text: str) -> bool:
    """True if a `macro_invocation`'s text contains a word-boundaried
    `OwnedIdentityDid` token (string literals stripped). This catches a
    metavar-mint invocation `build_mint!(OwnedIdentityDid)` WITHOUT requiring
    `impl` adjacency: the invocation passes the cap type INTO a macro that
    may synthesize an impl on it, so naming the cap type in ANY macro
    invocation is the risk surface — recognizing the specific generated
    payload is unnecessary (and defeatable).

    String literals AND comments are stripped first (mirroring
    `_takes_raw_did`) so the cap NAME appearing only in a macro-argument
    comment — `some_macro!(/* OwnedIdentityDid */ x)` or
    `some_macro!(x) // OwnedIdentityDid` — does NOT false-FAIL a legitimate
    invocation that never actually receives the capability type.
    """
    stripped = _strip_comments(_strip_string_literals(text))
    return re.search(rf"\b{TYPE_NAME}\b", stripped) is not None


def _macro_text_touches_cap(text: str) -> bool:
    """True if macro body/invocation TEXT contains an `impl`-adjacent
    `OwnedIdentityDid` token sequence — i.e. the macro could synthesize an
    `impl …OwnedIdentityDid` (an inherent or trait impl, including a mint).
    tree-sitter does NOT expand macros, so such an impl is invisible to the
    AST walk and must be rejected at the macro level.

    We strip string literals first so a `"impl OwnedIdentityDid"` mention
    inside a macro's format-string payload does not false-positive, then
    require BOTH an `impl` token AND the cap NAME (word-boundaried) to be
    present with `impl` appearing BEFORE the cap name (the
    `impl …OwnedIdentityDid` order). An ordinary `tracing::warn!("…")` has
    neither token and is therefore never collected; a `some_macro!(
    OwnedIdentityDid)` that names the type but has no `impl` is also not
    collected here (it cannot synthesize an impl), keeping the rule
    targeted. (Sub-case 1 — any macro AT ALL in the declaring file —
    catches the declaring-file case independently of this text test.)
    """
    stripped = _strip_string_literals(text)
    impl_m = re.search(r"\bimpl\b", stripped)
    if impl_m is None:
        return False
    name_m = re.search(rf"\b{TYPE_NAME}\b", stripped[impl_m.end() :])
    return name_m is not None


def _macro_name(node, source: bytes) -> str:
    """Best-effort macro NAME for a `macro_definition` / `macro_invocation`
    node, used only to make the declaring-file ban diagnostic name the
    offending macro (e.g. `macro `forge_via_macro!``). Purely additive to
    the diagnostic — it never affects the ACCEPT/REJECT decision.

    A `macro_definition` carries a `name` field; a `macro_invocation`'s macro
    path is its `macro` field (an `identifier` / `scoped_identifier`). We
    fall back to a leading `ident!`-style token scrape, then to "<macro>".
    """
    name_node = node.child_by_field_name("name") or node.child_by_field_name(
        "macro"
    )
    if name_node is not None:
        return node_text(name_node, source).strip()
    m = re.match(r"\s*([A-Za-z_][\w:]*)\s*!", node_text(node, source))
    return m.group(1) if m else "<macro>"


def _macro_hit_reason(
    node, source: bytes, rel: str, required_rel: str
) -> str | None:
    """Return a diagnostic reason string if a `macro_definition` /
    `macro_invocation` node must be rejected, else None.

    The macro rules are CATEGORY / METAVARIABLE based, NOT payload-
    recognition based. Earlier forms looked for the LITERAL `OwnedIdentityDid`
    token adjacent to `impl`; two evasions slipped through:
      (a) `paste::paste! { impl [<Owned Identity Did>] { … } }` in the
          declaring file — token-splitting hides the literal `OwnedIdentityDid`
          from any text search, AND
      (b) a metavar macro in a NON-declaring file:
          `macro_rules! build_mint { ($t:ty) => { impl $t { fn forge(_d: DID)
          -> $t { … } } } }` + `build_mint!(OwnedIdentityDid)` — the def body
          carries `impl $t` (no cap token), the invocation carries the cap
          token (no `impl`), so neither alone trips an `impl …Cap` text test.
    Both are closed by replacing recognition with bans:

      (1) DECLARING file (`identity_capability.rs`): BAN ALL macro
          DEFINITIONS and ALL macro INVOCATIONS that are NOT inside
          `#[cfg(test)]` code. The production body of the declaring file is
          macro-free; its only macros (`assert_eq!`, the `assert_send_sync`
          witness) live in `#[cfg(test)] mod tests`. A category ban over the
          NON-test body is robust to paste / token-split / metavar AND
          false-fail-free: the cfg(test) macros are exempted via
          `_inside_cfg_test` (an ancestor carrying a `#[cfg(test)]` /
          `#[cfg(all(test, …))]` gate).
      (2) ANYWHERE under the scan root (non-declaring files):
          (a) any `macro_definition` whose body synthesizes an
              `impl $<metavariable>` (`_macro_def_synthesizes_metavar_impl`)
              — a macro that builds an impl on a passed-in type, which could
              be the cap type; AND
          (b) any `macro_invocation` whose argument text contains a
              word-boundaried `OwnedIdentityDid` token
              (`_macro_invocation_names_cap`) — the metavar-mint invocation
              `build_mint!(OwnedIdentityDid)`, flagged WITHOUT requiring
              `impl` adjacency.
          The existing literal `impl …OwnedIdentityDid` synthesize check
          (`_macro_text_touches_cap`) is KEPT as belt-and-suspenders for a
          macro that spells the cap token literally next to `impl`.
    """
    text = node_text(node, source)
    if rel == required_rel:
        # Declaring-file CATEGORY BAN: no macros at all in the non-test body.
        # A cfg(test)-gated macro (the test module's `assert_eq!` / witness)
        # is exempt; everything else is rejected regardless of payload, which
        # is robust to paste/token-split/metavar evasions that no text search
        # could recognize.
        if _inside_cfg_test(node, source):
            return None
        kind = (
            "macro_rules! definition"
            if node.type == "macro_definition"
            else "macro invocation"
        )
        return (
            f"{kind} `{_macro_name(node, source)}` in the declaring file "
            f"({required_rel}) outside "
            f"`#[cfg(test)]` code; the capability module's production body "
            f"MUST be macro-free. tree-sitter does NOT expand macros, so a "
            f"`paste!`/token-split/metavariable macro could synthesize a "
            f"hidden mint the AST walk never sees. Only `#[cfg(test)]`-gated "
            f"macros (the test module's assertions) are permitted"
        )
    # Non-declaring files: metavariable-impl synthesizer OR an invocation that
    # passes the cap type into a macro, OR a literal `impl …Cap` synthesizer.
    if node.type == "macro_definition" and _macro_def_synthesizes_metavar_impl(
        text
    ):
        return (
            f"macro_rules! definition synthesizing an `impl $<metavariable>` "
            f"block; invoked with the capability type "
            f"(`some_macro!({TYPE_NAME})`) it materializes an "
            f"`impl {TYPE_NAME}` that tree-sitter cannot see through — a "
            f"metavariable impl-synthesizer is a hidden-mint vector and the "
            f"capability type must not be reachable by one"
        )
    if node.type == "macro_invocation" and _macro_invocation_names_cap(text):
        return (
            f"macro invocation passing {TYPE_NAME} as an argument "
            f"(`some_macro!(… {TYPE_NAME} …)`); a macro that receives the "
            f"capability type can synthesize an `impl {TYPE_NAME}` mint "
            f"invisible to the AST walk — the capability type must not be "
            f"handed to any macro"
        )
    if _macro_text_touches_cap(text):
        kind = (
            "macro_rules! definition"
            if node.type == "macro_definition"
            else "macro invocation"
        )
        return (
            f"{kind} whose body synthesizes an `impl …{TYPE_NAME}`; a "
            f"macro-generated impl is invisible to the AST walk and can hide "
            f"a mint — the capability type must not be touched by macros"
        )
    return None


def _path_attr_escape(
    attr_item_node, source: bytes, src_file: Path, scan_dir: Path
) -> str | None:
    """Return a diagnostic reason if this `attribute_item` is a
    `#[path = "..."]` whose resolved target ESCAPES the scan root, else
    None.

    The scanner only walks `crates/scp-runtime/src/`. A
    `#[path = "../../tests/forge.rs"] mod x;` pulls an EXTERNAL file into the
    crate where an in-module mint would be legal but invisible to this gate.
    We resolve the target relative to the declaring file's directory (Rust's
    `#[path]` resolution for an inline `mod x;` is relative to the file
    containing the attribute) and FAIL if the resolved path is not under
    `scan_dir`.

    The one legitimate `#[path]` in the crate points to a SIBLING file
    inside `src/` (`#[path = "key_package_actor_tests.rs"] mod tests;`),
    which resolves UNDER scan_dir and is therefore NOT flagged. An
    "escapes scan_dir" predicate is false-fail-free for it.
    """
    # An attribute_item wraps an `attribute` child; the attribute's first
    # identifier is the attr name (`path`), followed by `= "<target>"`.
    attr = None
    for c in attr_item_node.children:
        if c.type == "attribute":
            attr = c
            break
    if attr is None:
        return None
    ident = None
    value = None
    for c in attr.children:
        if c.type == "identifier" and ident is None:
            ident = node_text(c, source)
        elif c.type == "string_literal":
            value = node_text(c, source)
    if ident != "path" or value is None:
        return None
    # Strip the surrounding quotes (and any raw-string hashes) — for a plain
    # `"..."` literal, strip the first and last `"`.
    target = value
    if len(target) >= 2 and target[0] == '"' and target[-1] == '"':
        target = target[1:-1]
    if not target:
        return None
    try:
        resolved = (src_file.parent / target).resolve()
        scan_resolved = scan_dir.resolve()
    except (OSError, ValueError):
        return None
    if not _is_under(resolved, scan_resolved):
        return (
            f"`#[path = \"{target}\"]` resolves to {resolved} which ESCAPES "
            f"the scanned source root ({scan_resolved}); an external file "
            f"pulled in via `#[path]` could declare an in-module mint that "
            f"this gate never sees. `#[path]` targets MUST stay under src/"
        )
    return None


def _is_under(path: Path, root: Path) -> bool:
    """True if `path` is `root` or a descendant of it. Uses resolved paths;
    `..` segments that climb out of `root` make `is_relative_to` False.
    """
    try:
        return path == root or path.is_relative_to(root)
    except (OSError, ValueError):
        return False


# -----------------------------------------------------------------------------
# Scan
# -----------------------------------------------------------------------------


def _scan_root(scan_dir: Path, repo_root: Path) -> tuple[
    list[tuple[str, int, str, list[str], list[tuple[int, str]], str, bool]],
    list[tuple[str, int, str | None]],
    list[tuple[str, int, str, str, str, str]],
    list[tuple[str, int, str]],
    list[tuple[str, int, str, str, str, str, str]],
    list[tuple[str, int, str]],
    list[tuple[str, int, str]],
    list[tuple[str, int, str]],
    list[tuple[str, int, str]],
    list[tuple[str, int, str]],
    list[tuple[str, int, str]],
    list[tuple[str, int, str]],
]:
    """Walk scan_dir and return (decls, impls, ctor_fns, cap_aliases,
    trait_fns, macro_hits, construction_hits, use_aliases, nested_mod_hits,
    by_value_return_hits, mint_ref_hits).

    decls: list of (rel_path, line, visibility, derives, public_fields,
                    kind, generic) where kind is
                    'struct' | 'enum' | 'union' | 'type_alias' and `generic`
                    is True iff the declaration carries `type_parameters`
                    (generic type OR lifetime params). Rule (F) requires the
                    cap be a NON-GENERIC struct, so a generic struct decl is
                    HARD-FAILed even though every other check passes.
    impls: list of (rel_path, line, trait_name) where trait_name is None
           for inherent impls (which are permitted) and non-None for
           trait impls (which are rejected if the trait is forbidden).
    ctor_fns: every `function_item` inside an inherent
           `impl OwnedIdentityDid { ... }` block. Used by the closed
           allowlist rule (G) to assert the inherent impl contains ONLY
           the allowlisted methods (`issue_for_actor`, `reissue`,
           `as_did`), each with its required shape, and that any other
           inherent fn — regardless of return type — is rejected. Element
           shape: (rel_path, line, fn_name, visibility, params_text,
           return_type_text).
    cap_aliases: every `type X = …OwnedIdentityDid…;` alias whose
           right-hand side REFERENCES the capability type, regardless of
           the alias's own name. Element shape: (rel_path, line,
           alias_name). Used by the extended rule (F) to ban a return-type
           alias of the capability (e.g. `type OwnedCap = OwnedIdentityDid;`)
           — defence-in-depth against the aliased-return forgery trick.
           NOTE: a `type OwnedIdentityDid = …` alias (the cap NAME used as
           an alias) is captured by `decls` with kind 'type_alias' instead;
           `cap_aliases` is specifically for aliases NAMED something else
           whose RHS is the cap type.
    trait_fns: every `function_item` inside a TRAIT impl
           `impl SomeTrait for OwnedIdentityDid { ... }` block (trait_name
           is non-None). Rule D (FORBIDDEN_IMPL_TRAITS blocklist) catches a
           manual `impl Clone`/`impl From`/etc., but those forbidden traits
           do not return `Self`. A CUSTOM trait whose method CONSTRUCTS the
           cap — `trait Forger { fn forge(d: DID) -> Self; } impl Forger for
           OwnedIdentityDid { fn forge(d: DID) -> Self { … } }` — evades BOTH
           rule D (`Forger` is not on the blocklist) AND rule G (which only
           inspects INHERENT impls, trait_name is None). Collecting trait-
           impl methods lets the extended rule D fail any trait method that
           returns the cap type (an alternate mint surface). Element shape:
           (rel_path, line, fn_name, visibility, params_text,
           return_type_text, trait_name).
    macro_hits: every `macro_definition` / `macro_invocation` that the gate
           must reject because tree-sitter does NOT expand macros, so a mint
           hidden inside macro-generated code is invisible to the AST walk.
           Two sub-cases are collected (both as element shape (rel_path,
           line, reason)):
             (1) ANY macro_definition (`macro_rules!`) OR macro_invocation
                 in the DECLARING file (`identity_capability.rs`) — that
                 module must be macro-free so the gate's AST view of it is
                 complete. (The real declaring file has zero macros, so this
                 is false-fail-free; ordinary logging macros like
                 `tracing::warn!` would only matter if they appeared there,
                 and they do not.)
             (2) ANY macro_definition / macro_invocation ANYWHERE under the
                 scan root whose body TEXT contains an `impl`-adjacent
                 `OwnedIdentityDid` token sequence (i.e. a macro that
                 synthesizes an `impl …OwnedIdentityDid`). An ordinary
                 `tracing::warn!("…")` does NOT reference the cap type, so it
                 is not collected.
    construction_hits: every `struct_expression` in the DECLARING FILE that
           CONSTRUCTS the capability type (`OwnedIdentityDid { … }`, a scoped
           `…::OwnedIdentityDid { … }`, or a `Self { … }` whose enclosing impl
           targets the cap) but is NOT lexically inside an allowlisted INHERENT
           constructor (`issue_for_actor` / `reissue`). Rust field privacy is
           MODULE-scoped, not impl-scoped: the private `did` field is reachable
           from ANY item in the declaring module, so a free fn / helper-type
           method / closure / nested fn / trait-impl method can mint via a
           struct literal while passing every impl-keyed rule (A-G). Rule H
           closes this by scanning ALL cap-constructing struct literals and
           failing any outside the two allowlisted inherent constructors.
           SCOPED to the declaring file (`required_rel`) because in any OTHER
           file the private-field literal would not COMPILE (so it is not a
           forgery vector there), and a `Self { … }` in a foreign-file impl is
           already covered by location check (A) / trait-mint rule (D).
           Element shape: (rel_path, line, reason).
    use_aliases: every `use <path> as <Alias>;` import alias whose imported
           path's LAST `::` segment is the capability type — the SYMMETRIC
           counterpart of `cap_aliases` (rule F.2). Rust has exactly two
           type-renaming mechanisms: `type X = T` (banned via `cap_aliases`)
           and `use … as X` (collected here). A `use self::OwnedIdentityDid as
           Alias;` makes `Alias` a second name for the cap, so an `impl Alias`
           / `Alias { … }` / `Self { … }`-in-`impl Alias` / free fn `-> Alias`
           all have a tail identifier ≠ `OwnedIdentityDid` and slip rule G
           (inherent allowlist), rule H (construction scan), and
           `_impl_targets_cap` — every one of which recognizes the cap ONLY by
           the literal tail `OwnedIdentityDid` (or `Self` inside a cap impl).
           Rule F.2-use bans the import alias outright, mirroring the F.2
           `type`-alias ban EXACTLY in scope (whole-scan-tree collection +
           whole-tree enforcement), so the cap can only ever be NAMED
           `OwnedIdentityDid`. Catches the qualified path forms
           (`self::`/`super::`/`crate::…::`) AND the use-group forms
           (`use self::{OwnedIdentityDid as Alias};`, `use foo::{Bar,
           OwnedIdentityDid as Alias};`) — the `use_as_clause` is found
           wherever it nests inside a `use_list` / `scoped_use_list`. Element
           shape: (rel_path, line, alias_name).
    nested_mod_hits: (rule I) every `impl OwnedIdentityDid` block (inherent OR
           trait) and every cap-constructing `struct_expression` in the
           DECLARING FILE that is nested under a `mod_item` (i.e. NOT at the
           file's top level). The canonical production cap impl + its two
           `Self { … }` literals are TOP-LEVEL; a SECOND cap impl or any cap
           struct literal hidden inside an in-file nested `mod` is the
           in-file analogue of the `#[path]`-include escape — an extra
           construction/mint surface that rules G/H per-file would WAVE
           THROUGH (a nested-mod re-impl of `issue_for_actor` supplies an
           allowlisted name + a `Self { did }` whose nearest enclosing
           `function_item` is allowlisted, so both pass) but a literal-free
           module-level wrapper can re-export to all of `crate::context`.
           SCOPED to the declaring file (`required_rel`): in any other file
           the private-field literal would not compile and a foreign cap impl
           is caught by location check (A). Element shape: (rel_path, line,
           reason).
    by_value_return_hits: (rule J) every `function_item` ANYWHERE under the
           SUPERVISOR SUBTREE (`SUPERVISOR_SUBTREE_REL`, where the
           `pub(super)` mint is reachable) whose `return_type` MENTIONS the
           cap BY VALUE (the cap tail — or a `Self` inside an inherent/trait
           cap impl — appears in the return type NOT solely behind a `&`
           reference, including inside `Option`/`Result`/`Box`/tuples/fn
           returns), EXCEPT the two allowlisted constructors `issue_for_actor`
           /`reissue` IN their canonical top-level inherent cap impl IN the
           declaring file, and EXCEPT `#[cfg(test)]` items. Such a fn
           re-exports a mint surface WITHOUT a struct literal (it can call the
           `pub(super)` mint and return the token), so rule H (a struct-literal
           scanner) and rule G (inherent-method-only) both miss it. This is an
           ADDITIVE multi-file scan for ONE anti-pattern (by-value cap
           returns); it does NOT weaken the declaring-file pin every other
           rule keys on. Element shape: (rel_path, line, reason).
    mint_ref_hits: (rule K) every CODE REFERENCE to the sole arbitrary-DID
           minter `issue_for_actor` ANYWHERE under the SUPERVISOR SUBTREE —
           a `call_expression` function / value-path / bare call (a
           `scoped_identifier` whose `name` is the mint, or a bare mint
           `identifier`), PLUS a `use …::issue_for_actor as X;` rename alias.
           This is the CATEGORICAL closer for the by-value-return rule (J): J
           keys on the RETURN-TYPE TEXT and is evadable by type-level
           indirection (assoc-type projection `<Cz as Carry>::O`, trait-method
           projection, `impl Sized` opaque return), but EVERY such forgery still
           CALLS `issue_for_actor` — the one mint — so detecting the DANGEROUS
           OPERATION (the call) rather than the disguised return type closes the
           whole class. EXEMPT: (a) the mint's own DEFINITION (`_is_mint_reference`
           never collects the `fn issue_for_actor` name node), (b) references
           lexically inside `Supervisor::build_actor_deps` (the ONE legitimate
           mint site), and (c) `#[cfg(test)]` references (reusing rule J's
           cfg-test exemption). Doc-comments / string literals mentioning the
           mint are NOT flagged — the scan keys on `identifier` /
           `scoped_identifier` AST nodes only. Rule J is KEPT as-is (additive
           defense-in-depth for direct cap-by-value returns); rule K is strictly
           additive. Element shape: (rel_path, line, reason).
    """
    decls: list[
        tuple[str, int, str, list[str], list[tuple[int, str]], str, bool]
    ] = []
    impls: list[tuple[str, int, str | None]] = []
    ctor_fns: list[tuple[str, int, str, str, str, str]] = []
    cap_aliases: list[tuple[str, int, str]] = []
    trait_fns: list[tuple[str, int, str, str, str, str, str]] = []
    macro_hits: list[tuple[str, int, str]] = []
    construction_hits: list[tuple[str, int, str]] = []
    use_aliases: list[tuple[str, int, str]] = []
    nested_mod_hits: list[tuple[str, int, str]] = []
    by_value_return_hits: list[tuple[str, int, str]] = []
    mint_ref_hits: list[tuple[str, int, str]] = []
    escape_position_hits: list[tuple[str, int, str]] = []
    # (fix 3) Set of (rel, fn_node_id) for `build_actor_deps` fns that have
    # ALREADY had ONE exempt mint call. A second exempt-shaped mint reference in
    # the SAME fn is flagged (AT-MOST-ONE mint per build site). Persists across
    # files in the scan so the count is per-fn (fn ids are unique per parse, and
    # the rel disambiguates identical ids across files).
    seen_exempt_mint_fns: set[tuple[str, int]] = set()
    # Rel path of the ONE file allowed to declare the cap type. The same
    # relative path holds under both the real repo_root and the self-test's
    # temp staging root, so the declaring-file macro rule (B, sub-case 1)
    # keys on it identically in both.
    required_rel = REQUIRED_PATH
    if not scan_dir.is_dir():
        return decls, impls, ctor_fns, cap_aliases, trait_fns, macro_hits, construction_hits, use_aliases, nested_mod_hits, by_value_return_hits, mint_ref_hits, escape_position_hits
    for root, _, files in os.walk(scan_dir):
        for fname in files:
            if not fname.endswith(".rs"):
                continue
            full = Path(root) / fname
            rel = full.relative_to(repo_root).as_posix()
            source = full.read_bytes()
            tree = PARSER.parse(source)

            def walk(node) -> None:
                if node.type in (
                    "struct_item",
                    "enum_item",
                    "union_item",
                    "type_item",
                ):
                    name_node = node.child_by_field_name("name")
                    if name_node is not None:
                        name = node_text(name_node, source)
                        if name == TYPE_NAME:
                            vis = _visibility_of(node, source)
                            derives = _preceding_derives(node, source)
                            pubs = _public_fields(node, source)
                            kind = {
                                "struct_item": "struct",
                                "enum_item": "enum",
                                "union_item": "union",
                                "type_item": "type_alias",
                            }[node.type]
                            # Generic-arity check applies ONLY to the cap
                            # type's OWN declaration (this branch keys on the
                            # decl NAME == TYPE_NAME). A `type_parameters`
                            # child marks a generic type/lifetime param list;
                            # `type_item` aliases never carry one (and are
                            # rejected as aliases regardless), so the flag is
                            # meaningful for struct/enum/union forms.
                            generic = _is_generic_decl(node)
                            decls.append(
                                (
                                    rel,
                                    node.start_point[0] + 1,
                                    vis,
                                    derives,
                                    pubs,
                                    kind,
                                    generic,
                                )
                            )
                        elif node.type == "type_item":
                            # A `type X = …;` alias NAMED something other
                            # than the cap type. If its right-hand side
                            # REFERENCES the cap type (`type OwnedCap =
                            # OwnedIdentityDid;`), it is a return-type-alias
                            # forgery vector: a mint fn can declare
                            # `-> OwnedCap` to dodge a return-type-text
                            # check. Rule (F, extended) bans it. We match
                            # the cap NAME (word-boundaried) against the
                            # alias's `type` (RHS) field text, with string
                            # literals stripped so a doc-payload mention
                            # cannot false-positive.
                            value_node = node.child_by_field_name("type")
                            if value_node is not None and not _is_associated_type(
                                node
                            ):
                                rhs = _strip_string_literals(
                                    node_text(value_node, source)
                                )
                                if re.search(rf"\b{TYPE_NAME}\b", rhs):
                                    cap_aliases.append(
                                        (rel, node.start_point[0] + 1, name)
                                    )
                if node.type == "impl_item":
                    hit = _impl_for_owned_identity_did(node, source)
                    if hit is not None:
                        trait_name, line = hit
                        impls.append((rel, line, trait_name))
                        # (I) IN-FILE NESTED-MOD BAN. A cap `impl` (inherent
                        # OR trait) in the DECLARING FILE that is nested under
                        # a `mod_item` is the in-file analogue of the
                        # `#[path]`-include escape: a SECOND mint/construction
                        # surface that rules G/H per-file would wave through (a
                        # nested-mod re-impl of `issue_for_actor` supplies an
                        # allowlisted name + an inline `Self { did }` literal,
                        # so both pass). The canonical production cap impl is
                        # TOP-LEVEL, so this is strictly additive.
                        if rel == required_rel:
                            mod_anc = _nested_mod_ancestor(node)
                            if mod_anc is not None:
                                kind = (
                                    "trait impl"
                                    if trait_name is not None
                                    else "inherent impl"
                                )
                                nested_mod_hits.append(
                                    (
                                        rel,
                                        line,
                                        f"{kind} `impl {TYPE_NAME}` is nested "
                                        f"under a `mod` in the declaring file; "
                                        f"the canonical cap impl MUST be at the "
                                        f"file's TOP LEVEL. A nested-mod cap "
                                        f"impl is an extra mint/construction "
                                        f"surface — the in-file analogue of a "
                                        f"`#[path]` include — that the per-file "
                                        f"inherent allowlist (G) and "
                                        f"construction scan (H) wave through "
                                        f"(it can re-host an allowlisted-named "
                                        f"`issue_for_actor` with an inline "
                                        f"`Self {{ did }}`), then be re-exported "
                                        f"to all of `crate::context` by a "
                                        f"module-level wrapper. Move the impl "
                                        f"to the top level",
                                    )
                                )
                        # Inherent impls (trait_name is None) carry the
                        # constructor; record their functions so the
                        # closed-allowlist check (G) can inspect
                        # `issue_for_actor` / `reissue` / `as_did` directly.
                        if trait_name is None:
                            for (
                                fn_name,
                                vis,
                                params,
                                ret_ty,
                                fn_line,
                            ) in _inherent_fns(node, source):
                                ctor_fns.append(
                                    (rel, fn_line, fn_name, vis, params, ret_ty)
                                )
                        else:
                            # TRAIT impl (`impl SomeTrait for
                            # OwnedIdentityDid`). Record its methods so the
                            # extended rule D can fail any trait method that
                            # CONSTRUCTS the cap (returns Self) — a
                            # custom-trait mint that evades the forbidden-
                            # trait blocklist (rule D) and the inherent-only
                            # allowlist (rule G). `_inherent_fns` walks any
                            # impl body's function_items, so it works for a
                            # trait impl too.
                            for (
                                fn_name,
                                vis,
                                params,
                                ret_ty,
                                fn_line,
                            ) in _inherent_fns(node, source):
                                trait_fns.append(
                                    (
                                        rel,
                                        fn_line,
                                        fn_name,
                                        vis,
                                        params,
                                        ret_ty,
                                        trait_name,
                                    )
                                )
                if node.type in ("macro_definition", "macro_invocation"):
                    macro_hit = _macro_hit_reason(node, source, rel, required_rel)
                    if macro_hit is not None:
                        macro_hits.append(
                            (rel, node.start_point[0] + 1, macro_hit)
                        )
                # (H) Construction allowlist over struct LITERALS. Scoped to
                # the DECLARING FILE only: the cap's `did` field is
                # module-private, so a struct literal that reaches it is
                # type-system-permitted ONLY inside the declaring module — in
                # any OTHER file `OwnedIdentityDid { did }` would not compile,
                # so it is not a forgery vector there and a `Self { … }` in an
                # impl in another file is already covered by location check (A)
                # / trait-mint rule (D). Inside the declaring module a free fn
                # / helper-type method / closure / nested fn can mint via the
                # private field while passing every impl-keyed rule (A-G).
                if rel == required_rel and node.type == "struct_expression":
                    if _struct_expr_constructs_cap(node, source):
                        reason = _construction_hit_reason(node, source)
                        if reason is not None:
                            construction_hits.append(
                                (rel, node.start_point[0] + 1, reason)
                            )
                        # (I) IN-FILE NESTED-MOD BAN for cap struct LITERALS.
                        # A cap construction nested under a `mod` in the
                        # declaring file is flagged EVEN IF its nearest
                        # enclosing `function_item` is an allowlisted
                        # constructor (which keeps rule H, above, silent — a
                        # nested-mod `issue_for_actor` re-impl's inline
                        # `Self { did }` is "in_allowlisted"). The production
                        # cap literals are TOP-LEVEL; a nested-mod cap literal
                        # is an extra construction surface, so reject it on
                        # nesting alone. Additive to rule H — `_struct_expr_
                        # constructs_cap` already proved this literal builds
                        # the cap.
                        mod_anc = _nested_mod_ancestor(node)
                        if mod_anc is not None:
                            label = node_text(
                                node.child_by_field_name("name"), source
                            ).strip()
                            nested_mod_hits.append(
                                (
                                    rel,
                                    node.start_point[0] + 1,
                                    f"`{label} {{ … }}` cap construction is "
                                    f"nested under a `mod` in the declaring "
                                    f"file; the only legitimate cap struct "
                                    f"literals are the inline `Self {{ did }}` "
                                    f"in the TOP-LEVEL `issue_for_actor` / "
                                    f"`reissue`. A nested-mod cap literal is an "
                                    f"extra construction surface that rule H "
                                    f"waves through when its enclosing fn is an "
                                    f"allowlisted-named re-impl. Construct the "
                                    f"cap only at the file's top level",
                                )
                            )
                # (J) BY-VALUE CAP-RETURN BAN. Scans EVERY `function_item`
                # under the SUPERVISOR SUBTREE (where the `pub(super)` mint is
                # reachable), not just the declaring file. A fn whose return
                # type mentions the cap BY VALUE re-exports a mint surface
                # WITHOUT a struct literal (it can call the mint and return the
                # token), so rule H (struct-literal scanner) and rule G
                # (inherent-method-only) both miss it. EXEMPT: the two
                # allowlisted constructors in their canonical TOP-LEVEL inherent
                # cap impl in the DECLARING file, and `#[cfg(test)]` items.
                if (
                    node.type == "function_item"
                    and rel.startswith(SUPERVISOR_SUBTREE_REL)
                ):
                    ret_node = node.child_by_field_name("return_type")
                    if ret_node is not None:
                        impl_anc = _nearest_enclosing(node, ("impl_item",))
                        in_cap_impl = _impl_targets_cap(impl_anc, source)
                        if _return_mentions_cap_by_value(
                            ret_node, source, in_cap_impl
                        ):
                            name_node = node.child_by_field_name("name")
                            fn_name = (
                                node_text(name_node, source)
                                if name_node is not None
                                else "<anon>"
                            )
                            # Exempt the canonical constructors: allowlisted
                            # name, in the DECLARING file, inside an INHERENT
                            # cap impl that is itself TOP-LEVEL (a nested-mod
                            # re-impl is already caught by rule I and must NOT
                            # be exempted here). Anywhere else — including a
                            # same-named wrapper in another subtree file — a
                            # by-value cap return is flagged.
                            is_top_level_inherent_cap_method = (
                                impl_anc is not None
                                and _impl_is_inherent(impl_anc)
                                and in_cap_impl
                                and _nested_mod_ancestor(impl_anc) is None
                            )
                            exempt_ctor = (
                                rel == required_rel
                                and fn_name in CONSTRUCTING_FNS
                                and is_top_level_inherent_cap_method
                            )
                            # cfg(test) exemption: a `#[cfg(test)]` item is not
                            # in the production binary, so it can never be a
                            # handler-reachable forgery. `_inside_cfg_test`
                            # covers an ancestor (`#[cfg(test)] mod tests`);
                            # `_has_preceding_cfg_test` covers `#[cfg(test)]`
                            # placed DIRECTLY on this fn (the attribute is a
                            # preceding sibling of the `function_item`, never an
                            # ancestor, so `_inside_cfg_test` alone misses it).
                            if (
                                not exempt_ctor
                                and not _inside_cfg_test(node, source)
                                and not _has_preceding_cfg_test(node, source)
                            ):
                                by_value_return_hits.append(
                                    (
                                        rel,
                                        node.start_point[0] + 1,
                                        f"fn `{fn_name}` returns {TYPE_NAME} BY "
                                        f"VALUE (return type "
                                        f"{node_text(ret_node, source).strip()!r}); "
                                        f"a non-constructor fn that yields an "
                                        f"owned cap token re-exports the "
                                        f"`pub(super)` mint to its callers "
                                        f"WITHOUT a struct literal (so rule H "
                                        f"misses it) and outside an inherent "
                                        f"cap impl (so rule G misses it). The "
                                        f"ONLY fns that may return the cap by "
                                        f"value are the top-level inherent "
                                        f"`issue_for_actor` / `reissue` in the "
                                        f"declaring file. Return `&{TYPE_NAME}` "
                                        f"(a borrow) or restructure so the token "
                                        f"is not handed out by value",
                                    )
                                )
                # (KEYSTONE — escape-position ban). Across the SUPERVISOR
                # SUBTREE, flag the capability appearing BY VALUE in an escape
                # channel OTHER than a plain return / plain struct field:
                #   - an OUT-PARAM: a fn `parameter` (or `return_type`) whose
                #     type puts the cap behind a `&mut`/`*mut` (incl.
                #     `&mut Option<…Cap…>` / `&mut Vec<…Cap…>`), OR
                #   - an INTERIOR-MUT WRAPPER (`Cell`/`RefCell`/`OnceCell`/
                #     `OnceLock`/`Mutex`/`RwLock`/`UnsafeCell`/…<…Cap…>) anywhere
                #     a type appears — fn param/return, `static`/`const` item, or
                #     struct `field_declaration`.
                # This single rule kills the out-param exfil (K01), the `static`
                # sink (K02 variant), and any interior-mut cell handed out behind
                # a shared `&`. It MUST NOT flag a plain `&OwnedIdentityDid`
                # shared borrow (read-only), the `ActorDeps { owned_identity:
                # OwnedIdentityDid }` plain field, or `issue_for_actor`/`reissue`
                # returning `Self` (those are rule-J / legit-owning channels).
                # `#[cfg(test)]` items are exempt (not in the production binary).
                if rel.startswith(SUPERVISOR_SUBTREE_REL) and node.type in (
                    "parameter",
                    "static_item",
                    "const_item",
                    "field_declaration",
                ):
                    type_node = node.child_by_field_name("type")
                    # `static`/`const` items flag a PLAIN by-value cap too (a
                    # global sink a token can be moved out of); fn params /
                    # struct fields flag ONLY mut/wrapper escapes (a by-value
                    # param consumes, a plain owning field is the legit home).
                    flag_by_value = node.type in ("static_item", "const_item")
                    esc_reason = _type_escape_cap_reason(
                        type_node, source, flag_by_value=flag_by_value
                    )
                    if esc_reason is not None and not (
                        _inside_cfg_test(node, source)
                        or _has_preceding_cfg_test(node, source)
                    ):
                        kind_label = {
                            "parameter": "fn parameter",
                            "static_item": "`static` item",
                            "const_item": "`const` item",
                            "field_declaration": "struct field",
                        }[node.type]
                        escape_position_hits.append(
                            (
                                rel,
                                node.start_point[0] + 1,
                                f"{kind_label} puts the capability in a by-value "
                                f"ESCAPE position: {esc_reason}. A `&mut`/`*mut` "
                                f"out-param, a `static`/`const` sink, or an "
                                f"interior-mutability wrapper (`Cell`/`RefCell`/"
                                f"`OnceCell`/`OnceLock`/`Mutex`/`RwLock`/"
                                f"`UnsafeCell`) handed out behind a shared `&` all "
                                f"let a holder MINT or EXTRACT an owned "
                                f"{TYPE_NAME} token — a channel the by-value "
                                f"return ban (J) and the mint-call ban (K) do not "
                                f"cover. The capability may only be a plain "
                                f"return, a plain owning struct field "
                                f"(`ActorDeps.owned_identity`), or a SHARED "
                                f"`&{TYPE_NAME}` borrow (read-only). Restructure "
                                f"so no `&mut`/`*mut`/interior-mut/static channel "
                                f"carries the cap by value",
                            )
                        )
                # A fn's RETURN TYPE can ALSO be an escape position (`&mut Cap`,
                # `*mut Cap`, or an interior-mut wrapper return). Rule J already
                # bans a PLAIN by-value cap return EXCEPT the two constructors;
                # this catches the `&mut`/`*mut`/wrapper RETURN shapes (which
                # rule J's `_return_mentions_cap_by_value` deliberately treats as
                # behind-a-reference / does not classify as the wrapper escape),
                # with NO constructor exemption — a constructor has no reason to
                # return `&mut`/`*mut`/`Cell<Cap>`. cfg(test) exempt.
                if (
                    rel.startswith(SUPERVISOR_SUBTREE_REL)
                    and node.type == "function_item"
                ):
                    ret_node2 = node.child_by_field_name("return_type")
                    esc_ret = _type_escape_cap_reason(ret_node2, source)
                    if esc_ret is not None and not (
                        _inside_cfg_test(node, source)
                        or _has_preceding_cfg_test(node, source)
                    ):
                        nm = node.child_by_field_name("name")
                        fnm = node_text(nm, source) if nm is not None else "<anon>"
                        escape_position_hits.append(
                            (
                                rel,
                                node.start_point[0] + 1,
                                f"fn `{fnm}` return type puts the capability in a "
                                f"by-value ESCAPE position: {esc_ret}. A "
                                f"`&mut`/`*mut` or interior-mutability-wrapper "
                                f"return lets the caller MINT or EXTRACT an owned "
                                f"{TYPE_NAME} token (a channel rules J/K do not "
                                f"cover). Return a plain `{TYPE_NAME}` (only the "
                                f"constructors), `&{TYPE_NAME}` (a shared borrow), "
                                f"or restructure",
                            )
                        )
                if node.type == "attribute_item":
                    path_hit = _path_attr_escape(node, source, full, scan_dir)
                    if path_hit is not None:
                        macro_hits.append(
                            (rel, node.start_point[0] + 1, path_hit)
                        )
                # (F.2-use) Import-alias ban — the SYMMETRIC counterpart of the
                # F.2 `type X = OwnedIdentityDid` ban. A `use <path> as <Alias>;`
                # whose imported path's LAST segment is the cap type makes
                # `Alias` a second name for it, defeating the gate's
                # tail-identifier recognition (rule G / H / `_impl_targets_cap`
                # all key on the literal `OwnedIdentityDid` tail). Collected
                # ANYWHERE under the scan root, mirroring `cap_aliases` scope
                # EXACTLY (F.2 is whole-tree, not declaring-file-only). The
                # `use_as_clause` is found wherever it nests — top-level or
                # inside a `use_list` / `scoped_use_list` — because `walk`
                # recurses into every node.
                if node.type == "use_as_clause":
                    alias = _use_alias_cap_tail(node, source)
                    if alias is not None:
                        use_aliases.append(
                            (rel, node.start_point[0] + 1, alias)
                        )
                    # (K — use-alias residual) A `use …::issue_for_actor as X;`
                    # renames the MINT fn so a later bare `X(d)` call dodges the
                    # identifier-keyed mint-reference scan below (the call is
                    # spelled `X`, not `issue_for_actor`). Ban the rename outright,
                    # symmetric to the cap-type F.2-use ban and to the same
                    # whole-tree scope, so the mint can only ever be NAMED
                    # `issue_for_actor`. Collected ANYWHERE under the scan root —
                    # an import can re-export the `pub(super)` mint reference into
                    # any module that imports it, and the rename evasion is not
                    # subtree-bound. NOT exempted for the build-site (an aliased
                    # import is never how `build_actor_deps` names the mint — it
                    # uses the fully-qualified path) nor for cfg(test): a renaming
                    # import has no legitimate use.
                    mint_alias = _use_alias_mint_tail(node, source)
                    if mint_alias is not None:
                        mint_ref_hits.append(
                            (
                                rel,
                                node.start_point[0] + 1,
                                f"`use … as {mint_alias}` renames the mint fn "
                                f"`{MINT_FN_NAME}`; a later bare `{mint_alias}(…)` "
                                f"call would dodge the identifier-keyed "
                                f"mint-reference scan (rule K). Rust has exactly "
                                f"two renaming mechanisms (`use … as` here, "
                                f"`type`/fn-path elsewhere); banning the import "
                                f"alias keeps the sole arbitrary-DID mint always "
                                f"NAMED `{MINT_FN_NAME}` so every forgery surfaces "
                                f"as a mint reference. Call "
                                f"`{TYPE_NAME}::{MINT_FN_NAME}` by its real name "
                                f"(only in `Supervisor::{BUILD_ACTOR_DEPS_FN}`)",
                            )
                        )
                    # (fix — DID-TYPE USE-ALIAS BAN). A `use …::DID as GoodId;`
                    # in the supervisor subtree renames the raw-DID type. The
                    # per-call mint-arg check (rule K exemption b) finds the
                    # owning binding by counting the SOLE non-`self` parameter
                    # whose TYPE tail-identifier is the literal `DID`. Aliasing
                    # `DID` on the OWNING param makes the ATTACKER param the only
                    # literal-`DID` param, so IT is pinned and the attacker DID is
                    # minted (G03-via-alias). Banning the import alias keeps `DID`
                    # un-renameable in the subtree so the literal-`DID` param count
                    # is airtight — symmetric to the cap-type F.2-use ban. Scoped
                    # to the subtree (where the count runs) and cfg(test) exempt
                    # (mirroring the other subtree-scoped rules).
                    if (
                        rel.startswith(SUPERVISOR_SUBTREE_REL)
                        and not (
                            _inside_cfg_test(node, source)
                            or _has_preceding_cfg_test(node, source)
                        )
                    ):
                        did_use_alias = _use_alias_did_tail(node, source)
                        if did_use_alias is not None:
                            mint_ref_hits.append(
                                (
                                    rel,
                                    node.start_point[0] + 1,
                                    f"`use … as {did_use_alias}` renames the raw-DID "
                                    f"type `{DID_PARAM_TYPE}` in the supervisor "
                                    f"subtree. The build-site mint-arg check finds "
                                    f"the owning binding by counting the SOLE "
                                    f"non-`self` parameter whose type tail is the "
                                    f"literal `{DID_PARAM_TYPE}`; renaming "
                                    f"`{DID_PARAM_TYPE}` on the owning param lets an "
                                    f"attacker param become the only literal-"
                                    f"`{DID_PARAM_TYPE}` param and be pinned as the "
                                    f"owning binding. Banned outright (symmetric to "
                                    f"the cap-type import-alias ban) so "
                                    f"`{DID_PARAM_TYPE}` stays un-renameable where "
                                    f"the param count runs. Name `{DID_PARAM_TYPE}` "
                                    f"directly. See ADR-049 §5",
                                )
                            )
                # (fix — DID-TYPE ALIAS BAN). A `type GoodId = …DID;` alias in the
                # supervisor subtree whose RHS type tail is the raw-DID type. Same
                # threat as the `use … as` form above: it renames `DID` so the
                # owning param's type tail is no longer the literal `DID`, leaving
                # the ATTACKER param as the only literal-`DID` param to be pinned.
                # Rust has exactly two type-renaming mechanisms (`type X = T` here,
                # `use … as X` above); banning both in the subtree keeps the
                # literal-`DID` param count airtight. Scoped to the subtree, cfg
                # (test) exempt.
                if (
                    node.type == "type_item"
                    and rel.startswith(SUPERVISOR_SUBTREE_REL)
                    and not (
                        _inside_cfg_test(node, source)
                        or _has_preceding_cfg_test(node, source)
                    )
                    and not _is_associated_type(node)
                ):
                    alias_name_node = node.child_by_field_name("name")
                    rhs_node = node.child_by_field_name("type")
                    if (
                        alias_name_node is not None
                        and rhs_node is not None
                        and _type_tail_identifier(rhs_node, source)
                        == DID_PARAM_TYPE
                    ):
                        alias_name = node_text(alias_name_node, source)
                        mint_ref_hits.append(
                            (
                                rel,
                                node.start_point[0] + 1,
                                f"`type {alias_name} = …{DID_PARAM_TYPE}` is a "
                                f"`type` alias OF the raw-DID type in the supervisor "
                                f"subtree. It renames `{DID_PARAM_TYPE}` so the "
                                f"owning parameter's type tail is no longer the "
                                f"literal `{DID_PARAM_TYPE}`, leaving an attacker "
                                f"param as the only literal-`{DID_PARAM_TYPE}` param "
                                f"to be pinned by the build-site mint-arg check. "
                                f"Banned outright (symmetric to the cap-type "
                                f"`type X = {TYPE_NAME}` ban) so `{DID_PARAM_TYPE}` "
                                f"stays un-renameable where the param count runs. "
                                f"Use `{DID_PARAM_TYPE}` directly. See ADR-049 §5",
                            )
                        )
                # (fix 4 — GLOB-IMPORT BAN). A `use …identity_capability::*;`
                # glob in the subtree drags the cap type and any future
                # re-exported mint into the importing module under their bare
                # names WITHOUT a nameable scoped path / `use … as` the gate can
                # see, defeating the explicit-NAME recognition rules G/H/K rely
                # on. Force the subtree to name what it imports explicitly. The
                # `use_wildcard` is found wherever it nests. cfg(test) exempt.
                if (
                    rel.startswith(SUPERVISOR_SUBTREE_REL)
                    and node.type == "use_wildcard"
                    and _use_wildcard_is_cap_module(node, source)
                    and not (
                        _inside_cfg_test(node, source)
                        or _has_preceding_cfg_test(node, source)
                    )
                ):
                    mint_ref_hits.append(
                        (
                            rel,
                            node.start_point[0] + 1,
                            f"glob import `use …{CAP_MODULE_NAME}::*` drags the "
                            f"capability module's items (incl. {TYPE_NAME} and "
                            f"any re-exported mint) into this module under bare "
                            f"names, WITHOUT a nameable scoped path / `use … as` "
                            f"the gate can see — defeating the explicit-NAME "
                            f"recognition that rules G/H/K rely on. Import "
                            f"{TYPE_NAME} (and nothing mint-bearing) EXPLICITLY "
                            f"by name, never via a `::*` glob of the capability "
                            f"module",
                        )
                    )
                # (fix 4 — REASSEMBLY-MACRO BAN). A `paste!` / `concat_idents!`
                # INVOCATION in the subtree can synthesize the mint / cap
                # identifier from split tokens (`paste! { [<issue _for_actor>] }`),
                # which tree-sitter never reassembles — so an identifier-keyed
                # rule (G/H/K) cannot see the resulting mint. Mirror the
                # declaring-file payload-agnostic macro CATEGORY ban: reject the
                # INVOCATION of a token-reassembling macro anywhere in the
                # subtree. cfg(test) exempt.
                if (
                    rel.startswith(SUPERVISOR_SUBTREE_REL)
                    and node.type == "macro_invocation"
                    and _macro_name(node, source).split("::")[-1]
                    in REASSEMBLY_MACROS
                    and not (
                        _inside_cfg_test(node, source)
                        or _has_preceding_cfg_test(node, source)
                    )
                ):
                    mint_ref_hits.append(
                        (
                            rel,
                            node.start_point[0] + 1,
                            f"token-reassembling macro "
                            f"`{_macro_name(node, source)}!` invoked in the "
                            f"supervisor subtree; a token-pasting / "
                            f"identifier-concatenating macro can synthesize the "
                            f"mint `{MINT_FN_NAME}` or the cap `{TYPE_NAME}` "
                            f"identifier from split tokens that tree-sitter never "
                            f"reassembles, hiding the resulting mint/construction "
                            f"from every identifier-keyed rule. Such macros are "
                            f"banned in the subtree (payload-agnostic category "
                            f"ban, mirroring the declaring-file macro ban)",
                        )
                    )
                # (K) MINT-CALL CONTAINMENT. Scans EVERY code reference to the
                # sole arbitrary-DID minter `issue_for_actor` ANYWHERE under the
                # SUPERVISOR SUBTREE (where the `pub(super)` mint is reachable),
                # not just the declaring file. A reference is a `call_expression`
                # function / a value-path / a bare call to `issue_for_actor`.
                # Every arbitrary-DID forgery MUST reference the mint, so this
                # rule is IMMUNE to the return-type disguise (assoc-type
                # projection, trait-method projection, `impl Sized` opaque return)
                # that rule J — which keys on the evadable RETURN-TYPE TEXT —
                # cannot fully close. EXEMPT: (a) the mint's own DEFINITION (never
                # collected — `_is_mint_reference` excludes the `fn` name node),
                # (b) the ONE legitimate mint call inside
                # `Supervisor::build_actor_deps`, and (c) `#[cfg(test)]` code
                # (reusing the rule-J cfg-test exemption). Doc-comments / string
                # literals mentioning `issue_for_actor` are NOT flagged: the walk
                # keys on `identifier` / `scoped_identifier` AST nodes, which a
                # comment or string payload never produces.
                if rel.startswith(SUPERVISOR_SUBTREE_REL) and _is_mint_reference(
                    node, source
                ):
                    is_build_site_exempt = _mint_ref_exempt_build_actor_deps(
                        node, source, rel
                    )
                    if is_build_site_exempt:
                        # (fix 3) AT-MOST-ONE exempt mint call per
                        # `build_actor_deps`. The exemption is per-FUNCTION;
                        # without a count, the real `Supervisor::build_actor_deps`
                        # body could host a SECOND exempt-shaped mint (a second
                        # `issue_for_actor(owning_did)` re-minting / leaking the
                        # token). Track exempt refs by the enclosing fn node id;
                        # the FIRST is exempt, any SUBSEQUENT exempt-shaped ref in
                        # the SAME fn is FLAGGED. (K02 with an attacker-DID literal
                        # arg is already non-exempt via the per-call arg check, so
                        # this guards the residual: a second mint of the SAME
                        # owning_did — still a needless extra mint surface.)
                        fn_node = _nearest_enclosing(node, ("function_item",))
                        fn_key = (rel, fn_node.id if fn_node is not None else -1)
                        if fn_key in seen_exempt_mint_fns:
                            ref_text = node_text(node, source).strip()
                            mint_ref_hits.append(
                                (
                                    rel,
                                    node.start_point[0] + 1,
                                    f"SECOND exempt-shaped reference to the mint "
                                    f"`{MINT_FN_NAME}` ({ref_text!r}) inside the "
                                    f"same `{BUILD_ACTOR_DEPS_FN}`; the build-site "
                                    f"exemption permits AT MOST ONE mint call per "
                                    f"`{BUILD_ACTOR_DEPS_FN}` (the actor's own "
                                    f"`owning_did`). A second mint — even of the "
                                    f"same identity — is an extra mint surface. "
                                    f"Mint exactly once",
                                )
                            )
                        else:
                            seen_exempt_mint_fns.add(fn_key)
                    if not (
                        is_build_site_exempt
                        or _inside_cfg_test(node, source)
                        or _has_preceding_cfg_test(node, source)
                    ):
                        ref_text = node_text(node, source).strip()
                        mint_ref_hits.append(
                            (
                                rel,
                                node.start_point[0] + 1,
                                f"reference to the sole arbitrary-DID mint "
                                f"`{MINT_FN_NAME}` ({ref_text!r}); a call / value "
                                f"path to the mint fabricates a {TYPE_NAME} token "
                                f"for an ARBITRARY DID and re-exports the mint "
                                f"surface, defeating cross-identity isolation. "
                                f"This is flagged REGARDLESS of the enclosing "
                                f"fn's return type, so it closes the "
                                f"return-disguise forgeries (assoc-type / "
                                f"trait-method projection, `impl Sized` opaque "
                                f"return) that the by-value-return rule (J) "
                                f"cannot see. The ONLY non-test mint reference "
                                f"allowed is inside `Supervisor::"
                                f"{BUILD_ACTOR_DEPS_FN}` (the actor-spawn mint "
                                f"site); `#[cfg(test)]` references are exempt. "
                                f"Move the mint into "
                                f"`{BUILD_ACTOR_DEPS_FN}` or restructure so no "
                                f"other code references it",
                            )
                        )
                for c in node.children:
                    walk(c)

            walk(tree.root_node)
    return decls, impls, ctor_fns, cap_aliases, trait_fns, macro_hits, construction_hits, use_aliases, nested_mod_hits, by_value_return_hits, mint_ref_hits, escape_position_hits


def find_declarations():
    return _scan_root(SCAN_DIR, REPO_ROOT)


# -----------------------------------------------------------------------------
# Enforcement
# -----------------------------------------------------------------------------


def _returns_self(return_type_text: str) -> bool:
    """True if a fn's return-type text denotes the capability type — i.e.
    `Self` or `OwnedIdentityDid` (word-boundaried; case-insensitive on the
    `Did`/`DidId` tail ONLY — the `OwnedIdentity` prefix matches exactly —
    so a future `Did`/`DidId` alias rename of the tail cannot evade).
    Tree-sitter's `return_type` field is the BARE type after `->` (e.g.
    `Self`, `&DID`) — the `->` arrow is NOT part of the field text. We
    strip string literals first (defence-in-depth; return types do not
    normally contain string literals) before matching.

    Matches: `-> Self`, `-> OwnedIdentityDid`, `-> Option<Self>`? — note
    we deliberately match ONLY a bare `Self` / `OwnedIdentityDid` tail,
    not wrapper types: a mint returns the token by value. A
    `-> Option<OwnedIdentityDid>` would still match the inner token name,
    which is the conservative (fail-louder) choice for a security gate.
    """
    stripped = _strip_string_literals(return_type_text)
    if re.search(r"\bSelf\b", stripped):
        return True
    # `OwnedIdentity` prefix matches EXACTLY; only the `Did`/`DidId` tail is
    # matched case-insensitively (`[Dd][Ii][Dd]\w*`) so `OwnedIdentityDid` /
    # a future `OwnedIdentityDidId` alias cannot evade on tail casing.
    return re.search(r"\bOwnedIdentity[Dd][Ii][Dd]\w*", stripped) is not None


def _strip_comments(s: str) -> str:
    """Replace every `// …` line comment and `/* … */` block comment body
    with spaces, preserving length. Applied (alongside string-literal
    stripping) before the raw-`DID` parameter search so a `DID` mentioned
    only in a comment cannot false-positive a clone/accessor fn as a mint:

        fn dup(&self /* did */) -> Self     // comment-only `did`
        fn dup(&self) -> Self // pass a did  (trailing-comment `did`)

    String literals are stripped first by the caller so a `//` or `/*`
    INSIDE a string is not mistaken for a comment opener; here we operate
    on already-literal-stripped text. Block comments do not nest in Rust at
    the lexer level for our purposes (a conservative single-level scan is
    sufficient for parameter lists, which never contain real nested block
    comments).
    """
    out: list[str] = []
    i = 0
    n = len(s)
    while i < n:
        if s[i] == "/" and i + 1 < n and s[i + 1] == "/":
            # Line comment: blank to end-of-line (preserve the newline).
            j = i + 2
            while j < n and s[j] != "\n":
                j += 1
            out.append("  ")
            out.append(" " * (j - (i + 2)))
            i = j
            continue
        if s[i] == "/" and i + 1 < n and s[i + 1] == "*":
            # Block comment: blank to the closing `*/` (or EOF).
            j = i + 2
            while j < n and not (s[j] == "*" and j + 1 < n and s[j + 1] == "/"):
                j += 1
            end = min(j + 2, n)
            out.append(" " * (end - i))
            i = end
            continue
        out.append(s[i])
        i += 1
    return "".join(out)


def _takes_raw_did(params_text: str) -> bool:
    """True if a fn's parameter-list text contains a raw-DID-typed
    parameter — i.e. the DID TYPE token `DID`, `Did`, or a future `DidId`
    alias. Strips string literals AND comments first so a `DID` mentioned
    only in a default value, doc string, or `/* did */` / `// did` comment
    cannot false-positive. Catches `did: DID`, `&DID`, `scp_identity::DID`
    (the `::` is a word boundary), `Option<DID>`, and a future `DidId`.

    The pattern matches the DID type token EXPLICITLY rather than any
    `Did`-prefixed identifier: `\\b(?:DID|Did(?:Id)?)\\b`. An earlier form
    (`\\b[Dd][Ii][Dd]\\w*`) false-positived on ordinary names that merely
    START with the letters d-i-d — `Didier`, `did_handle`, `Didactic` — and
    bought little: a name-squat of the mint (e.g. `mint_didid`) is already
    rejected by the NAME allowlist (G.0), NOT by this param check, so the
    over-broad tail added false-FAIL risk without closing any real vector.
    The explicit token still catches the only realistic future rename
    (`DID` → `DidId`) without matching unrelated `Did`-prefixed words.
    """
    stripped = _strip_comments(_strip_string_literals(params_text))
    return re.search(r"\b(?:DID|Did(?:Id)?)\b", stripped) is not None


def _takes_self(params_text: str) -> bool:
    """True if a fn's parameter list has a `&self` (or `&mut self`)
    receiver. Strips string literals and comments first (defence-in-depth)
    so a `self` mentioned in a doc string / comment cannot false-positive.
    """
    stripped = _strip_comments(_strip_string_literals(params_text))
    return re.search(r"&\s*(mut\s+)?self\b", stripped) is not None


# -----------------------------------------------------------------------------
# Closed allowlist for the capability type's inherent API (rule G).
#
# `OwnedIdentityDid` has a tiny, fixed inherent API. The gate asserts the
# inherent impl contains ONLY these three methods, BY NAME, each with its
# required shape; ANY OTHER inherent fn — any name, ANY return type
# (including an aliased / `impl Trait` / `Result`-wrapped return that hides
# the capability type from a return-type-text check) — is a HARD FAIL. The
# allowlist-by-NAME is the security boundary, NOT the return-type text:
# that is precisely what closes the aliased-return forgery (`fn forge(did:
# DID) -> OwnedCap`), which a return-type classifier would skip.
#
# Each entry maps the allowlisted name to a tuple of REQUIRED-shape
# predicates checked against the fn's (visibility, params_text,
# return_type_text):
#   - "mint":        issue_for_actor — the sole raw-DID mint. MUST be
#                    `pub(super)`; MUST take a raw-DID param; MUST NOT take
#                    `&self`. (Return SHOULD be Self/OwnedIdentityDid — a
#                    sanity check, never the boundary.)
#   - "clone":       reissue — MUST take `&self`; MUST NOT take a raw-DID
#                    param. (Returns Self.)
#   - "accessor":    as_did — MUST take `&self`; MUST NOT take a raw-DID
#                    param. (Returns `&DID`.)
# Only the mint may take a raw DID; if `reissue` / `as_did` (or any other
# fn) takes a raw DID it FAILS — the "exactly one raw-DID mint" intuition,
# folded into the allowlist.
ALLOWLISTED_FNS: frozenset[str] = frozenset(
    {"issue_for_actor", "reissue", "as_did"}
)


# Trait-impl methods that may legitimately CONSTRUCT the capability type
# without being a forgery surface. Start EMPTY: no standard or custom trait
# whose method returns `Self` is a legitimate mint path for this type — the
# ONLY mint is the inherent `pub(super) issue_for_actor`. `Drop::drop` takes
# `&mut self` and returns `()` (never `Self`), so it would not trip the
# returns-Self test anyway and needs no entry. Kept as a named, documented
# allowlist so a future legitimate constructing-trait (none is foreseen)
# would be a single reviewed edit here rather than a silent gate weakening.
SAFE_CONSTRUCTING_TRAITS: frozenset[str] = frozenset()


def _enforce(
    decls: list[
        tuple[str, int, str, list[str], list[tuple[int, str]], str, bool]
    ],
    impls: list[tuple[str, int, str | None]],
    ctor_fns: list[tuple[str, int, str, str, str, str]],
    cap_aliases: list[tuple[str, int, str]],
    trait_fns: list[tuple[str, int, str, str, str, str, str]],
    macro_hits: list[tuple[str, int, str]],
    construction_hits: list[tuple[str, int, str]],
    use_aliases: list[tuple[str, int, str]],
    nested_mod_hits: list[tuple[str, int, str]],
    by_value_return_hits: list[tuple[str, int, str]],
    mint_ref_hits: list[tuple[str, int, str]],
    escape_position_hits: list[tuple[str, int, str]],
    required_path: str,
    stream=sys.stderr,
) -> bool:
    """Apply checks A-K plus the escape-position keystone. Returns True on
    FAIL, False on PASS. Writes diagnostics to `stream`. Caller must decide
    exit code and final messaging.
    """
    fail = False

    # (F) Type alias ban. Runs FIRST because an alias invalidates all
    # other checks on that declaration.
    #
    # (F.1) A `type OwnedIdentityDid = …;` alias — the cap NAME used as an
    # alias — erases the nominal distinction outright.
    for rel, line, _, _, _, kind, _ in decls:
        if kind == "type_alias":
            stream.write(
                f"{C_RED}FAIL{C_RESET}: {rel}:{line}: "
                f"{TYPE_NAME} is declared as a `type` alias; it MUST be "
                f"a `struct` (NOT an `enum`). A type alias erases the "
                f"nominal distinction and defeats the capability. "
                f"See ADR-049 §5.\n"
            )
            fail = True

    # (F.2) A `type X = OwnedIdentityDid;` alias — NAMED something else but
    # whose RHS IS the cap type. This is the return-type-alias forgery
    # vector: a mint fn declaring `-> OwnedCap` would dodge a return-type
    # classifier. The allowlist-by-name (G) already rejects the forgery fn,
    # but the alias itself must not exist — defence-in-depth.
    for rel, line, alias_name in cap_aliases:
        stream.write(
            f"{C_RED}FAIL{C_RESET}: {rel}:{line}: "
            f"`type {alias_name} = {TYPE_NAME}` is a `type` alias OF the "
            f"capability type. Such an alias lets a mint fn declare "
            f"`-> {alias_name}` to hide the capability return type from a "
            f"return-type check; it is banned outright. Use {TYPE_NAME} "
            f"directly. See ADR-049 §5.\n"
        )
        fail = True

    # (F.2-use) A `use <path> as <Alias>;` import alias whose imported path's
    # LAST segment is the cap type. Rust has exactly TWO type-renaming
    # mechanisms: `type X = T` (F.2 above) and `use … as X` (here). The
    # `use`-alias is the SYMMETRIC forgery surface: `use self::OwnedIdentityDid
    # as Alias;` makes `Alias` a second name for the cap, so an
    # `impl Alias { … Self { did } }` / `impl Alias { … Alias { did } }` / a
    # free fn `-> Alias { Alias { did } }` all have a tail identifier ≠
    # `OwnedIdentityDid` and slip rule G (inherent allowlist), rule H
    # (construction scan), and `_impl_targets_cap` — every one of which
    # recognizes the cap ONLY by the literal tail `OwnedIdentityDid` (or `Self`
    # inside a cap impl). The forgery COMPILES and is handler-reachable (the
    # private `did` field is module-scoped). Banning the import alias outright,
    # symmetric to F.2 and with the IDENTICAL whole-scan-tree scope, guarantees
    # the cap can only ever be NAMED `OwnedIdentityDid` (or `Self`), keeping
    # tail-identifier recognition airtight. See ADR-049 §5.
    for rel, line, alias_name in use_aliases:
        stream.write(
            f"{C_RED}FAIL{C_RESET}: {rel}:{line}: "
            f"`use … as {alias_name}` is an import alias OF the capability "
            f"type; it lets an `impl {alias_name}` / `{alias_name} {{ … }}` / "
            f"`Self {{ … }}`-in-`impl {alias_name}` hide the capability from "
            f"tail-identifier recognition (rules G / H key on the literal "
            f"`{TYPE_NAME}` tail); banned outright. Name {TYPE_NAME} "
            f"directly. See ADR-049 §5.\n"
        )
        fail = True

    # (F.3) The capability type MUST be a `struct` — an `enum` is REJECTED.
    #
    # The entire mint guarantee rests on check (E): the single field is
    # PRIVATE, so the type cannot be struct-literal-constructed outside the
    # declaring module, and the ONLY construction path is the `pub(super)`
    # `issue_for_actor` mint. That invariant is INEXPRESSIBLE for an enum: a
    # Rust enum's variants and their fields are ALWAYS exactly as visible as
    # the enum itself. A `pub(in crate::context) enum OwnedIdentityDid {
    # Owned(DID) }` therefore lets ANY `crate::context` code write
    # `OwnedIdentityDid::Owned(attacker_did)` — a mint with NO
    # `issue_for_actor`, defeating cross-identity isolation — while still
    # satisfying every other check (the field-privacy check E does
    # `if kind != "struct": continue` and would SKIP the enum entirely). The
    # gate requires the struct form precisely because the private-field
    # invariant only holds for structs. See ADR-049 §5.
    #
    # (F.3) is one half of the POSITIVE struct-only assertion: the cap's
    # declared nominal kind MUST be `struct`. Any non-struct nominal form
    # is rejected — `enum` here, `union` immediately below, `type` alias
    # via (F.1)/(F.2) above. Only `struct` falls through clean.
    for rel, line, _, _, _, kind, _ in decls:
        if kind == "enum":
            stream.write(
                f"{C_RED}FAIL{C_RESET}: {rel}:{line}: "
                f"{TYPE_NAME} is declared as an `enum`; it MUST be a "
                f"`struct`. The mint guarantee rests on the single field "
                f"being PRIVATE (no construction outside the declaring "
                f"module), but a Rust enum's variants and their fields are "
                f"ALWAYS as visible as the enum itself — so any "
                f"`crate::context` code could write "
                f"`{TYPE_NAME}::Owned(attacker_did)`, a mint with no "
                f"`issue_for_actor`. The private-field invariant is "
                f"inexpressible for enums. See ADR-049 §5.\n"
            )
            fail = True

    # (F.4) The capability type MUST NOT be a `union`. A union's field
    # visibility cannot be made private INDEPENDENT of the union, and
    # union construction (`OwnedIdentityDid { did: … }`) is SAFE Rust — so
    # any `crate::context` handler could forge the cap with no
    # `issue_for_actor`, exactly the bypass (F.3) closes for enums. The
    # private-field mint invariant is therefore inexpressible for a union.
    # This is the second half of the positive struct-only assertion (see
    # F.3 comment): with enum (F.3), union (here), and type-alias (F.1/F.2)
    # all rejected, ONLY a `struct` declaration passes.
    for rel, line, _, _, _, kind, _ in decls:
        if kind == "union":
            stream.write(
                f"{C_RED}FAIL{C_RESET}: {rel}:{line}: "
                f"{TYPE_NAME} is declared as a `union`; it MUST be a "
                f"`struct`. A union field's visibility cannot be made "
                f"private independent of the union, and union construction "
                f"is safe Rust, so the private-field mint invariant is "
                f"inexpressible. See ADR-049 §5.\n"
            )
            fail = True

    # (F.5) The capability type MUST be a NON-GENERIC `struct`. A generic
    # declaration — type parameters (`struct OwnedIdentityDid<T = DID> { did:
    # T }`) OR lifetime parameters (`struct OwnedIdentityDid<'a> { did: DID,
    # _p: PhantomData<&'a ()> }`) — currently satisfies every other check
    # (the field stays private, the mint stays `pub(super)`,
    # `#![forbid(unsafe_code)]` holds), so it is not an ACTIVE forgery. But
    # the struct-only assertion is supposed to be airtight: a generic
    # parameter loosens the private-field TYPE (defaulting `did: T` lets a
    # reviewer instantiate the cap over an arbitrary inner type) and invites a
    # reviewer-introduced refactor that erodes the private-field invariant the
    # `pub(super)` mint guarantee rests on. The cap's field type is fixed
    # (`DID`); there is no legitimate reason for the declaration to be
    # generic. HARD FAIL any generic cap decl. The flag is set ONLY on the
    # cap type's own decl (see `_scan_root`), so unrelated helper types are
    # unaffected.
    for rel, line, _, _, _, kind, generic in decls:
        if generic and kind in ("struct", "enum", "union"):
            stream.write(
                f"{C_RED}FAIL{C_RESET}: {rel}:{line}: "
                f"{TYPE_NAME} MUST be a non-generic `struct`; type/lifetime "
                f"parameters loosen the private-field invariant the mint "
                f"guarantee rests on. Remove the `<…>` parameter list. "
                f"See ADR-049 §5.\n"
            )
            fail = True

    # (A) Location: every decl must live at REQUIRED_PATH.
    for rel, line, _, _, _, _, _ in decls:
        if rel != required_path:
            stream.write(
                f"{C_RED}FAIL{C_RESET}: {rel}:{line}: "
                f"{TYPE_NAME} must be declared in {required_path}, "
                f"not {rel}. See ADR-049 §5.\n"
            )
            fail = True

    # (B) Struct name-visibility: pub(in crate::context) only.
    #
    # The struct must be NAMEABLE within `crate::context` (so `ActorDeps`
    # can hold it by-value and handlers can take `&OwnedIdentityDid`) but
    # MUST NOT be `pub` or `pub(crate)`. The mint guarantee does not ride
    # on this visibility — it rides on the `pub(super)` constructor (check
    # G) and the private field (check E). `pub(super)` here would be too
    # NARROW now: `ActorDeps` lives in `crate::context::actor`, a sibling
    # of `supervisor`, and could not name a `pub(super)` type.
    for rel, line, vis, _, _, _, _ in decls:
        if not _is_context_visibility(vis):
            stream.write(
                f"{C_RED}FAIL{C_RESET}: {rel}:{line}: "
                f"{TYPE_NAME} struct visibility is {vis or 'private'!r}; "
                f"must be 'pub(in crate::context)'. "
                f"'pub(crate)' is too broad (nameable beyond the context "
                f"module tree); 'pub' leaks the type to downstream crates. "
                f"The mint guarantee is enforced on the constructor "
                f"(pub(super) issue_for_actor) and the private field, "
                f"not on this name-visibility.\n"
            )
            fail = True

    # (C) Forbidden derives.
    for rel, line, _, derives, _, _, _ in decls:
        bad = [d for d in derives if d in FORBIDDEN_DERIVES]
        if bad:
            stream.write(
                f"{C_RED}FAIL{C_RESET}: {rel}:{line}: "
                f"{TYPE_NAME} has forbidden derive(s): {', '.join(sorted(set(bad)))}.\n"
                f"       Forbidden: {', '.join(sorted(FORBIDDEN_DERIVES))}.\n"
                f"       See ADR-049 §5.\n"
            )
            fail = True

    # (D) Manual impls of forbidden traits.
    for rel, line, trait_name in impls:
        if trait_name is None:
            # Inherent impl (`impl OwnedIdentityDid { ... }`). Allowed —
            # this is where the constructor lives.
            continue
        if trait_name in FORBIDDEN_IMPL_TRAITS:
            stream.write(
                f"{C_RED}FAIL{C_RESET}: {rel}:{line}: "
                f"manual `impl {trait_name} for {TYPE_NAME}` — this trait "
                f"is forbidden (same semantics as a banned derive). "
                f"Forbidden: {', '.join(sorted(FORBIDDEN_IMPL_TRAITS))}. "
                f"See ADR-049 §5.\n"
            )
            fail = True

    # (D, extended) CUSTOM-TRAIT MINT. The FORBIDDEN_IMPL_TRAITS blocklist
    # above only catches manual impls of Clone/From/etc. — traits whose
    # methods do NOT return Self and so are not a constructor. A CUSTOM trait
    # whose method CONSTRUCTS the cap evades both that blocklist (the trait
    # is not on it) AND the inherent-only allowlist (rule G inspects only
    # inherent impls). Example:
    #   trait Forger { fn forge(d: DID) -> Self; }
    #   impl Forger for OwnedIdentityDid { fn forge(d: DID) -> Self { … } }
    #
    # The flag is PARAMETER-based, not return-type-classification-only. A
    # trait method is a forbidden mint surface when EITHER:
    #   - `_returns_self(ret_ty)` — it returns the cap type (constructs it),
    #     OR
    #   - `_takes_raw_did(params)` — it takes a raw `DID` on
    #     `OwnedIdentityDid`. The ONLY legitimate raw-DID consumer is the
    #     inherent `pub(super) issue_for_actor`; a TRAIT method on this type
    #     that accepts a raw `DID` has no legitimate purpose and is an
    #     alternate mint surface. The param check closes the same hole
    #     BLACK-G01 opened for inherent fns: a return-type-aliased trait mint
    #     (`fn forge(d: DID) -> OwnedCap`) dodges `_returns_self` (its return
    #     text is the alias), but `_takes_raw_did` catches it independently of
    #     the F.2 alias backstop. Skipped only for the (currently EMPTY)
    #     SAFE_CONSTRUCTING_TRAITS allowlist.
    for rel, fn_line, fn_name, _, params, ret_ty, t_name in trait_fns:
        if t_name in SAFE_CONSTRUCTING_TRAITS:
            continue
        if _returns_self(ret_ty) or _takes_raw_did(params):
            stream.write(
                f"{C_RED}FAIL{C_RESET}: {rel}:{fn_line}: "
                f"forbidden trait-impl mint `{fn_name}` (trait `{t_name}`) "
                f"on {TYPE_NAME}: a trait method that returns "
                f"Self/{TYPE_NAME} OR takes a raw `DID` is an alternate mint "
                f"surface that evades both the forbidden-trait blocklist (the "
                f"trait is not on it) and the inherent-impl allowlist (which "
                f"inspects only inherent impls). The ONLY mint is the inherent "
                f"`pub(super) issue_for_actor`; no trait method on this type "
                f"may construct it or consume a raw DID. "
                f"See ADR-049 §5.\n"
            )
            fail = True

    # (B / C) MACRO and `#[path]` blind-spot closures. tree-sitter does not
    # expand macros, so a mint hidden in macro-generated code is invisible to
    # the AST walk; and the scanner only walks src/, so a `#[path]` escaping
    # src/ pulls in an external file where an in-module mint would be legal
    # but unseen. `_scan_root` collects both into `macro_hits`; FAIL each.
    for rel, line, reason in macro_hits:
        stream.write(
            f"{C_RED}FAIL{C_RESET}: {rel}:{line}: {reason}. "
            f"See ADR-049 §5.\n"
        )
        fail = True

    # (H) CONSTRUCTION ALLOWLIST over struct LITERALS (BLACK-G07). Rust field
    # privacy is MODULE-scoped, not impl-scoped: the cap's private `did` field
    # is reachable from ANY item in the declaring module, so a free fn /
    # helper-type method / closure / nested fn / trait-impl method in the
    # DECLARING FILE can mint a token via a struct literal —
    # `OwnedIdentityDid { did }` or a `Self { … }` inside an impl on the cap —
    # while passing EVERY impl-keyed rule (A-G), which only inspect
    # `impl OwnedIdentityDid` blocks and decls. Such a construction COMPILES
    # (the field is in-module-reachable) and is callable from handler code,
    # forging a token for any DID and defeating cross-identity isolation. Rule
    # H is the airtight closure: every Rust construction of the struct goes
    # through a `struct_expression` (or a macro — banned by rule B; or unsafe
    # transmute — banned by `#![forbid(unsafe_code)]`), so scanning ALL
    # cap-constructing struct literals in the declaring file and allowing only
    # the two inherent constructors `issue_for_actor`/`reissue` covers free
    # fns, helper-type methods, closures, nested fns, and trait-impl bodies
    # uniformly. `construction_hits` is already SCOPED to the declaring file
    # by `_scan_root` (the private-field literal cannot compile in any other
    # module). FAIL each.
    for rel, line, reason in construction_hits:
        stream.write(
            f"{C_RED}FAIL{C_RESET}: {rel}:{line}: {reason}. "
            f"See ADR-049 §5.\n"
        )
        fail = True

    # (I) IN-FILE NESTED-MOD BAN. The declaring file's canonical cap impl and
    # its `Self { … }` literals are TOP-LEVEL; a cap impl / cap construction
    # nested under an in-file `mod` is an extra mint/construction surface — the
    # in-file analogue of a `#[path]` include — that the per-file inherent
    # allowlist (G) and the construction scan (H) wave through (a nested-mod
    # re-impl supplies an allowlisted name + an inline allowlisted literal).
    # `_scan_root` already scoped this to the declaring file. FAIL each.
    for rel, line, reason in nested_mod_hits:
        stream.write(
            f"{C_RED}FAIL{C_RESET}: {rel}:{line}: {reason}. "
            f"See ADR-049 §5.\n"
        )
        fail = True

    # (J) BY-VALUE CAP-RETURN BAN. A fn that returns the cap BY VALUE
    # re-exports the `pub(super)` mint to its callers without a struct literal
    # (so rule H, a construction-site scanner, misses it) and outside an
    # inherent cap impl (so rule G, inherent-method-only, misses it). This is
    # the ONLY rule that scans the WHOLE SUPERVISOR SUBTREE (where the mint is
    # reachable) rather than the declaring file alone — `_scan_root` already
    # exempted the two canonical top-level constructors and every
    # `#[cfg(test)]` item. The declaring-file pin every other rule keys on is
    # UNCHANGED; this is an additive multi-file scan for one anti-pattern.
    # FAIL each.
    for rel, line, reason in by_value_return_hits:
        stream.write(
            f"{C_RED}FAIL{C_RESET}: {rel}:{line}: {reason}. "
            f"See ADR-049 §5.\n"
        )
        fail = True

    # (K) MINT-CALL CONTAINMENT. The CATEGORICAL closer for rule J. Rule J
    # bans a fn that RETURNS the cap by value, but keys on the evadable
    # RETURN-TYPE TEXT — defeated by type-level indirection (assoc-type
    # projection, trait-method projection, `impl Sized` opaque return, future
    # spellings). Rule K instead bans the DANGEROUS OPERATION: any code
    # reference to the sole arbitrary-DID minter `issue_for_actor`. Every
    # forgery, however it disguises its return type, MUST call the mint, so
    # this is immune to the return-type arms race. Collected over the whole
    # SUPERVISOR SUBTREE (where the `pub(super)` mint is reachable); `_scan_root`
    # already exempted (a) the mint DEFINITION, (b) the lone legitimate call in
    # `Supervisor::build_actor_deps`, and (c) `#[cfg(test)]` references, and
    # also folds in the `use … as` rename of the mint (which would otherwise
    # dodge an identifier-keyed call scan). Rule J is retained as additive
    # defense-in-depth; rule K is strictly additive. FAIL each.
    for rel, line, reason in mint_ref_hits:
        stream.write(
            f"{C_RED}FAIL{C_RESET}: {rel}:{line}: {reason}. "
            f"See ADR-049 §5.\n"
        )
        fail = True

    # (KEYSTONE) ESCAPE-POSITION BAN. Across the supervisor subtree, the cap
    # appearing BY VALUE in a `&mut`/`*mut` out-param / return, a `static`/
    # `const` sink, or an interior-mutability wrapper (`Cell`/`RefCell`/
    # `OnceCell`/`OnceLock`/`Mutex`/`RwLock`/`UnsafeCell`<…Cap…>) lets a holder
    # MINT or EXTRACT an owned token through a channel the by-value return ban
    # (J) and the mint-call ban (K) do not cover. `_scan_root` already exempted
    # `#[cfg(test)]` items and verified production has none (only shared
    # `&OwnedIdentityDid` borrows, the plain `ActorDeps.owned_identity` field,
    # and `as_did`'s `&DID` return — all permitted). FAIL each.
    for rel, line, reason in escape_position_hits:
        stream.write(
            f"{C_RED}FAIL{C_RESET}: {rel}:{line}: {reason}. "
            f"See ADR-049 §5.\n"
        )
        fail = True

    # (E) Public fields on struct.
    for rel, line, _, _, pubs, kind, _ in decls:
        if kind != "struct":
            continue
        for field_line, vis in pubs:
            stream.write(
                f"{C_RED}FAIL{C_RESET}: {rel}:{field_line}: "
                f"{TYPE_NAME} has a public field with visibility "
                f"{vis!r}. All fields MUST be private. A {vis} field on "
                f"this type lets handlers reach the inner DidId and "
                f"bypass the capability boundary. "
                f"See ADR-049 §5.\n"
            )
            fail = True

    # (G) CLOSED ALLOWLIST over the capability type's inherent API. This is
    # the REAL mint guarantee. It is a POSITIVE allowlist — NOT an open
    # "classify-by-return-type-then-check" rule. The earlier structural form
    # classified a fn as a mint by regex-matching its RETURN-TYPE TEXT for
    # `Self`/`OwnedIdentityDid`; an adversary defeated that with a
    # return-type alias (`type OwnedCap = OwnedIdentityDid; fn forge(did:
    # DID) -> OwnedCap { … }`) — `forge` was never classified as a mint
    # (its return text is `OwnedCap`, not `Self`/`OwnedIdentityDid`), so the
    # rule skipped it, and being `pub(in crate::context)` it could mint a
    # token for ANY DID from any context-module handler. The same dodge
    # worked via `-> impl Sized` and `-> Result<OwnedCap, ()>`.
    #
    # The closed allowlist removes the return-type text from the security
    # boundary entirely. `OwnedIdentityDid` has a tiny FIXED inherent API;
    # the gate asserts the inherent impl block(s) in the declaring file
    # contain ONLY these three fns, BY NAME, each with its required shape:
    #
    #   - `issue_for_actor` — the sole mint. MUST be `pub(super)`; MUST take
    #     a raw-DID param (not `&self`). (Return SHOULD be Self/
    #     OwnedIdentityDid — asserted as a sanity check, never the boundary.)
    #   - `reissue` — clone path. MUST take `&self`; MUST NOT take a raw-DID
    #     param. (Returns Self.)
    #   - `as_did` — accessor. MUST take `&self`; MUST NOT take a raw-DID
    #     param. (Returns `&DID`.)
    #   - ANY OTHER inherent fn — any name, ANY return type (including an
    #     aliased / `impl Trait` / `Result`-wrapped return that hides the
    #     cap type) — is a HARD FAIL. This is what catches `forge` / `mint2`
    #     / aliased-return forgeries: they fail because their NAME is not
    #     allowlisted, regardless of how they hide their return type/params.
    #
    # "Exactly one raw-DID mint" is folded in: only `issue_for_actor` may
    # take a raw DID. If `reissue` / `as_did` (or any other fn) takes a raw
    # DID → FAIL.
    #
    # The check runs PER DECLARATION FILE (`rel`), not globally. Production
    # code declares the type in exactly one file, so per-file and global are
    # identical there; per-file scoping lets the self-test fixture isolate
    # each bypass in its own synthetic file without one file's diagnostic
    # swallowing another's.
    fns_by_file: dict[str, list[tuple[str, int, str, str, str, str]]] = {}
    for t in ctor_fns:
        fns_by_file.setdefault(t[0], []).append(t)
    # Every file that declares the type must satisfy the allowlist contract,
    # even if it has no inherent impl at all (mint-absent → G.4).
    files_with_decls = {d[0] for d in decls}
    decl_line_by_file = {d[0]: d[1] for d in decls}

    for rel in sorted(files_with_decls | set(fns_by_file)):
        file_fns = fns_by_file.get(rel, [])
        seen_names: set[str] = set()

        for r, fn_line, fn_name, vis, params, ret_ty in file_fns:
            takes_self = _takes_self(params)
            takes_did = _takes_raw_did(params)
            seen_names.add(fn_name)

            # (G.0) Allowlist gate: ANY inherent fn whose NAME is not in the
            # allowlist is rejected outright — regardless of its return type
            # (aliased / `impl Trait` / `Result`-wrapped), visibility, or
            # params. This is the line that catches every aliased-return /
            # impl-Trait forgery (`forge`, `forge2`, `mint2`, …): the name
            # is the boundary, not the return text.
            if fn_name not in ALLOWLISTED_FNS:
                stream.write(
                    f"{C_RED}FAIL{C_RESET}: {r}:{fn_line}: "
                    f"unexpected inherent fn `{fn_name}` on the capability "
                    f"type; the allowlist is "
                    f"issue_for_actor/reissue/as_did — a new method "
                    f"requires a reviewed gate update. The allowlist is the "
                    f"security boundary: a fn outside it is rejected no "
                    f"matter how it declares its return type (alias / `impl "
                    f"Trait` / `Result`-wrapped) or params, which closes the "
                    f"aliased-return forgery (`-> OwnedCap`, `-> impl "
                    f"Sized`). "
                    f"See ADR-049 §5.\n"
                )
                fail = True
                continue

            # (G.1) `issue_for_actor` — the sole mint. MUST be `pub(super)`,
            # MUST take a raw-DID param, MUST NOT take `&self`.
            if fn_name == "issue_for_actor":
                if vis != "pub(super)":
                    stream.write(
                        f"{C_RED}FAIL{C_RESET}: {r}:{fn_line}: "
                        f"mint fn `issue_for_actor` visibility is "
                        f"{vis or 'private'!r}; must be 'pub(super)'. This "
                        f"is the mint: only supervisor-module code may "
                        f"create a token from a raw DID. A wider visibility "
                        f"lets non-supervisor code fabricate a token for an "
                        f"arbitrary DID and defeats cross-identity "
                        f"isolation. "
                        f"See ADR-049 §5.\n"
                    )
                    fail = True
                if not takes_did:
                    stream.write(
                        f"{C_RED}FAIL{C_RESET}: {r}:{fn_line}: "
                        f"mint fn `issue_for_actor` does NOT take a raw-DID "
                        f"parameter (params {params.strip()!r}). The "
                        f"allowlisted mint MUST mint from a raw `DID`; a "
                        f"name-squat of `issue_for_actor` that takes no DID "
                        f"is a shape forgery. "
                        f"See ADR-049 §5.\n"
                    )
                    fail = True
                if takes_self:
                    stream.write(
                        f"{C_RED}FAIL{C_RESET}: {r}:{fn_line}: "
                        f"mint fn `issue_for_actor` takes `&self` (params "
                        f"{params.strip()!r}); the mint is an ASSOCIATED fn "
                        f"that constructs from a raw `DID`, not a method on "
                        f"an existing token. "
                        f"See ADR-049 §5.\n"
                    )
                    fail = True
                # Sanity check only — NOT the security boundary: the mint
                # should return the cap type. A mis-shaped return is still
                # caught by the allowlist for every OTHER fn; for the mint
                # itself we flag a non-Self return as a likely shape forgery.
                if not _returns_self(ret_ty):
                    stream.write(
                        f"{C_RED}FAIL{C_RESET}: {r}:{fn_line}: "
                        f"mint fn `issue_for_actor` return type is "
                        f"{ret_ty.strip()!r}; it SHOULD return "
                        f"Self/{TYPE_NAME}. (Sanity check — the allowlist, "
                        f"not the return text, is the boundary.) "
                        f"See ADR-049 §5.\n"
                    )
                    fail = True

            # (G.2 & G.3) `reissue` / `as_did` — clone path and accessor.
            # Both MUST take `&self` and MUST NOT take a raw-DID param. Only
            # the mint may take a raw DID ("exactly one raw-DID mint", folded
            # into the allowlist). Their VISIBILITY is also bounded to the
            # gate's EXACT allowed-set: a `&self` clone/accessor MUST be
            # inherited-private (`""`) or EXACTLY `pub(in crate::context)`
            # (the same name-visibility as the struct, so the by-value clone /
            # `&DID` accessor is reachable exactly where the token itself is
            # and no wider) — never `pub`, `pub(crate)`, OR any narrower
            # path-restricted form (`pub(super)`, `pub(in crate::context::
            # supervisor)`, …). A `pub fn reissue(&self) -> Self` would let
            # downstream crates clone a held token, and a `pub(crate)` one
            # would over-expose it beyond the context module tree; a NARROWER
            # form (`pub(super)`) is ALSO rejected because `reissue` must stay
            # callable by `ActorDeps::clone_for_spawn` in the sibling `actor`
            # module, which a `pub(super)` (supervisor-only) bound would break.
            # All widen-OR-narrow the accessor/clone surface away from the
            # exact `pub(in crate::context)` boundary the struct itself is held
            # to. This
            # is inert today (the struct is `pub(in crate::context)` so a
            # wider fn vis cannot actually escape the crate), but it is a
            # defence-in-depth gap the gate must close so a future struct
            # re-export cannot silently widen these accessors.
            # Allowed accessor visibilities (the gate's EXACT allowed-set):
            # inherited-private (`""`) or EXACTLY `pub(in crate::context)`
            # (whitespace-tolerant via the same normalizer the struct-vis
            # check B uses). Every other modifier — `pub`, `pub(crate)`, AND
            # narrower path-restricted forms like `pub(super)` /
            # `pub(in crate::context::supervisor)` — is rejected.
            accessor_vis_ok = vis == "" or _is_context_visibility(vis)
            if fn_name in ("reissue", "as_did"):
                if not accessor_vis_ok:
                    stream.write(
                        f"{C_RED}FAIL{C_RESET}: {r}:{fn_line}: "
                        f"allowlisted fn `{fn_name}` visibility is "
                        f"{vis or 'private'!r}; a `&self` clone/accessor "
                        f"MUST be inherited-private or exactly "
                        f"'pub(in crate::context)', never 'pub', "
                        f"'pub(crate)', or any narrower path-restricted form. "
                        f"A wider visibility over-exposes the "
                        f"clone (`reissue`) / inner-DID accessor (`as_did`) "
                        f"beyond the context module tree the capability is "
                        f"held to. "
                        f"See ADR-049 §5.\n"
                    )
                    fail = True
                if not takes_self:
                    stream.write(
                        f"{C_RED}FAIL{C_RESET}: {r}:{fn_line}: "
                        f"allowlisted fn `{fn_name}` does NOT take `&self` "
                        f"(params {params.strip()!r}); `reissue` (clone) and "
                        f"`as_did` (accessor) MUST be `&self` methods on an "
                        f"already-held token, never associated fabrication "
                        f"paths. "
                        f"See ADR-049 §5.\n"
                    )
                    fail = True
                if takes_did:
                    stream.write(
                        f"{C_RED}FAIL{C_RESET}: {r}:{fn_line}: "
                        f"allowlisted fn `{fn_name}` takes a raw-DID "
                        f"parameter (params {params.strip()!r}); only the "
                        f"mint `issue_for_actor` may take a raw `DID`. A "
                        f"raw-`DID` argument on `{fn_name}` would make it a "
                        f"second mint path that forges tokens for "
                        f"not-already-held identities. "
                        f"See ADR-049 §5.\n"
                    )
                    fail = True

        # (G.4) The mint MUST exist. A declaring file with no
        # `issue_for_actor` means the mint was renamed or gutted — refuse a
        # shape that cannot mint under the supervisor-only guarantee. (When
        # the type is not declared at all, `decls` is empty and `main`
        # returns the pre-declaration pass before reaching `_enforce`; this
        # guard is for a declared-but-mint-stripped regression.) Only files
        # that actually DECLARE the type must host the mint — a file with a
        # stray inherent impl but no declaration is covered by check (A).
        if rel in files_with_decls and "issue_for_actor" not in seen_names:
            line0 = decl_line_by_file[rel]
            stream.write(
                f"{C_RED}FAIL{C_RESET}: {rel}:{line0}: "
                f"{TYPE_NAME} is declared but has NO `issue_for_actor` mint "
                f"fn (an inherent `pub(super)` fn that mints the token from "
                f"a raw `DID`). The mint MUST exist and be `pub(super)`; its "
                f"absence means the capability type can no longer be minted "
                f"under the supervisor-only guarantee (renamed / gutted "
                f"mint). "
                f"See ADR-049 §5.\n"
            )
            fail = True

    return fail


# -----------------------------------------------------------------------------
# Self-test
# -----------------------------------------------------------------------------


# Descriptor: (label, substring-in-stderr). Each entry names a distinct
# enforcement failure mode that MUST be triggered by the fixture. The
# substring is matched against the captured stderr diagnostics from
# `_enforce`. If a bypass fixture doesn't surface the expected
# substring, the scanner has regressed on that mode.
REQUIRED_FIXTURE_FAILURES: list[tuple[str, str]] = [
    ("forbidden_derive", "forbidden derive"),
    ("manual_impl_clone", "manual `impl Clone"),
    ("manual_impl_from", "manual `impl From"),
    # Named-struct public field — the fixture's named-struct case uses
    # `pub(crate)`. Asserts the field_declaration_list path still works.
    ("public_named_field", "public field with visibility 'pub(crate)'"),
    # Tuple-struct public field — the fixture's tuple-struct case uses
    # `pub(super)`. Asserts the NEW tuple-field detection (direct
    # `visibility_modifier` children of `ordered_field_declaration_list`,
    # no wrapper) catches `struct OwnedIdentityDid(pub(super) Did);`.
    # Before the tree-sitter-rust 0.21+ fix, this was silently missed.
    ("public_tuple_field", "public field with visibility 'pub(super)'"),
    ("type_alias", "declared as a `type` alias"),
    # Struct name-visibility bypass: a `pub`/`pub(crate)` struct (too
    # broad). With the `pub(in crate::context)` rule, anything else trips
    # the struct-visibility check (B).
    ("wrong_struct_visibility", "struct visibility is"),
    # ALLOWLIST rule (G) — a SECOND raw-DID->Self path named `issue_again`.
    # Under the closed allowlist its NAME is not allowlisted, so it is
    # rejected as an unexpected inherent fn (no return-type inspection
    # needed). The old structural rule keyed on "two raw-DID mints"; the
    # allowlist subsumes that — a second mint is just an extra fn.
    ("two_raw_did_mints", "unexpected inherent fn `issue_again`"),
    # ALLOWLIST rule (G) — alternately-NAMED raw-DID mint (`fn forge`). The
    # bypass the OLD name-keyed rule missed AND the bypass an open
    # classify-by-return-type rule missed (via a return alias). The
    # allowlist rejects `forge` purely because its NAME is not allowlisted.
    ("alternately_named_mint", "unexpected inherent fn `forge`"),
    # ALLOWLIST rule (G) — the sole mint is correctly NAMED `issue_for_actor`
    # but its visibility is wider than `pub(super)`. The allowlisted mint's
    # required shape (pub(super)) is still enforced.
    ("wrong_mint_visibility", "mint fn `issue_for_actor` visibility is"),
    # ALLOWLIST rule (G) — a non-allowlisted associated fn `dup` (returns
    # Self, no `&self`). Rejected as an unexpected inherent fn; the old
    # literal-name `reissue`/clone rule is subsumed by the allowlist.
    ("non_self_clone_path", "unexpected inherent fn `dup`"),
    # ALLOWLIST rule (G) — RETURN-TYPE-ALIASED forgery: a non-allowlisted
    # `forge` whose return type is the alias `OwnedCap` (= OwnedIdentityDid).
    # This is BLACK-G01: an open classify-by-return-type rule skips `forge`
    # (return text is `OwnedCap`, not Self/OwnedIdentityDid), but the
    # allowlist-by-NAME rejects it regardless of how the return is hidden.
    ("aliased_return_forge", "unexpected inherent fn `forge_aliased`"),
    # ALLOWLIST rule (G) — `-> impl Sized` forgery: a non-allowlisted
    # `forge2` whose return type is `impl Sized` (hides the cap type
    # entirely from any return classifier). Rejected by name.
    ("impl_trait_return_forge", "unexpected inherent fn `forge2`"),
    # ALLOWLIST rule (G) — a `DidId`-param mint. `DidId` (a future alias of
    # `DID`) is a raw-DID-typed param; the mint name-squats as a
    # non-allowlisted `mint_didid`, rejected by name. Also proves
    # `_takes_raw_did`'s `\\w*` tail catches `DidId` (a trailing `\\b` would
    # not, since `Did` is followed by `I`).
    ("didid_param_mint", "unexpected inherent fn `mint_didid`"),
    # Rule (F.2) — a `type X = OwnedIdentityDid;` alias OF the cap type
    # (named something else). Banned outright as a return-type-alias forgery
    # vector, independent of the allowlist rejecting the forgery fn.
    ("cap_type_alias", "is a `type` alias OF the capability type"),
    # Coverage gap G03 (FIX-A) — CUSTOM-TRAIT MINT. A `impl Forger for
    # OwnedIdentityDid { fn forge(d: DID) -> Self }` evades the
    # forbidden-trait blocklist (rule D) and the inherent-only allowlist
    # (rule G). The extended rule D collects trait-impl methods and FAILs any
    # returning Self. The diagnostic names the fn and the trait.
    ("custom_trait_mint", "forbidden trait-impl mint `forge` (trait `Forger`)"),
    # Coverage gap G02 (FIX-B) — MACRO-HIDDEN MINT. A `macro_rules!` whose
    # body emits `impl OwnedIdentityDid { fn forge … }` hides the mint from
    # the (macro-blind) AST walk. Rule B FAILs the macro. The fixture's
    # macro_rules definition both references the cap type AND synthesizes an
    # `impl …OwnedIdentityDid`, so it surfaces the synthesize-impl diagnostic.
    ("macro_hidden_mint", "synthesizes an `impl …OwnedIdentityDid`"),
    # Coverage gap G04 (FIX-C) — `#[path]` ESCAPE. A `#[path = "…"] mod x;`
    # whose target climbs out of src/ pulls an external file into the crate
    # where an in-module mint is invisible to this gate. Rule C FAILs a
    # `#[path]` resolving outside the scanned src root.
    ("path_escape", "ESCAPES the scanned source root"),
    # FIX-1 (BLACK-G05) — DECLARING-FILE MACRO CATEGORY BAN. A production-path
    # (non-`#[cfg(test)]`) macro invocation in `identity_capability.rs` is
    # rejected purely because it is a macro in the capability module's
    # non-test body — NO payload recognition. This closes the
    # `paste!`/token-split evasion (`impl [<Owned Identity Did>]`) that no
    # literal `impl …OwnedIdentityDid` text search could see. The cfg(test)
    # `assert_eq!` in the same file (BYPASS 10b, and the REAL production
    # tests) is exempt via `_inside_cfg_test`.
    ("declaring_file_macro_ban", "outside `#[cfg(test)]` code"),
    # FIX-1 (BLACK-G06) — `#[cfg(not(test))]` is PRODUCTION, not test-only.
    # The cfg text contains the `test` token but the gated item compiles when
    # NOT testing, so it is production code subject to the declaring-file
    # category ban. The OLD boolean-blind `_attr_is_cfg_test` mislabeled it as
    # test-gating and WRONGLY EXEMPTED it — a `paste!`/metavar mint under
    # `#[cfg(not(test))]` would compile into production and slip the gate.
    # The combinator-stack walker classifies `not(test)` as NOT test-requiring
    # (the `test` occurrence is enclosed by `not`), so the gate is non-exempt
    # and the invocation is REJECTED. The macro NAME in the diagnostic makes
    # this assertion distinct from BYPASS 10's `forge_via_macro`.
    ("declaring_file_macro_ban_not_test", "`forge_via_not_test_macro`"),
    # FIX-1 (BLACK-G06) — `#[cfg(any(test, feature = "x"))]` is PRODUCTION-
    # active when the feature is on. The crate uses
    # `#[cfg(any(test, feature = "testing"))]` PERVASIVELY; such an item
    # compiles into a production build whenever the feature is enabled and is
    # therefore subject to the declaring-file category ban. The OLD predicate
    # saw `test` and WRONGLY EXEMPTED it. The walker classifies the `test`
    # occurrence as enclosed by `any` = NOT test-requiring, so the gate is
    # non-exempt and the invocation is REJECTED. Asserted by macro NAME.
    ("declaring_file_macro_ban_any_test", "`forge_via_any_test_macro`"),
    # FIX-1 (BLACK-G05) — METAVARIABLE-MACRO MINT (non-declaring file). A
    # `macro_rules! build_mint { ($t:ty) => { impl $t { … } } }` synthesizes an
    # impl on a passed-in METAVARIABLE type; invoked `build_mint!(
    # OwnedIdentityDid)` it materializes a hidden `impl OwnedIdentityDid` mint.
    # The def body carries `impl $t` (no cap token), the invocation carries
    # the cap token (no `impl`) — neither trips a literal `impl …Cap` text
    # test. The CATEGORY rule flags the def as a metavariable impl-synthesizer.
    ("metavar_macro_def", "synthesizing an `impl $<metavariable>`"),
    # FIX-2 — ALIAS-RETURN TRAIT MINT caught by the PARAM check. A trait method
    # `fn forge_alias(d: DID) -> OwnedCap` returns an ALIAS (dodges
    # `_returns_self`) but takes a raw `DID`; the extended rule D now flags a
    # trait method that TAKES A RAW `DID`, independent of the F.2 alias
    # backstop. The trait/method names are unique so this substring can ONLY
    # be produced by the param arm (the return text is the alias, not Self).
    ("alias_return_trait_mint", "`forge_alias` (trait `ForgerAlias`)"),
    ("wrong_location", "must be declared in"),
    # Conditional-derive (`#[cfg_attr(..., derive(...))]`) bypass. The
    # outer attribute is NOT a plain `#[derive(...)]` literal, so a
    # scanner that prefix-matches on `#[derive(` misses it entirely.
    # At cfg-eval time the outer wrapper expands to a real derive,
    # minting the forbidden trait — which is why the scanner must
    # extract derive identifiers from EVERY `derive(...)` group inside
    # an attribute's text, regardless of outer wrapper. The fixture
    # adds two cases (BYPASS 8 simple, BYPASS 9 nested-predicate with
    # `all(..., not(...))`). Both go through the same
    # `_extract_derive_groups` code path, so asserting on the nested
    # case proves the simple case too.
    #
    # The substring must match ONLY on the forbidden-derive diagnostic
    # produced by the nested cfg_attr — NOT on the `Forbidden: ...`
    # recital that every manual-impl diagnostic emits (which also
    # contains `Deserialize` as a reserved word). The diagnostic
    # template `f"{TYPE_NAME} has forbidden derive(s): {', '.join(...)}"`
    # produces `forbidden derive(s): Deserialize, Serialize.` for
    # BYPASS 9 when extraction works; the word `Deserialize`
    # immediately after `derive(s): ` is impossible to produce without
    # real cfg_attr-inside-derive extraction.
    ("cfg_attr_derive", "forbidden derive(s): Deserialize"),
    # FIX-1 — ENUM FORM rejected (rule F.3). A
    # `pub(in crate::context) enum OwnedIdentityDid { Owned(DID) }` PASSED the
    # old gate (the field-privacy check E did `if kind != "struct": continue`
    # and skipped enums), yet it lets any `crate::context` code mint via
    # `OwnedIdentityDid::Owned(attacker_did)` — a Rust enum's variant fields
    # are always as visible as the enum. Rule F.3 HARD FAILs the enum form.
    ("enum_form", "is declared as an `enum`"),
    # FIX-1 (union follow-up) — UNION FORM rejected (rule F.4). A
    # `pub(in crate::context) union OwnedIdentityDid { did: ManuallyDrop<DID> }`
    # PASSED the old gate: a `union_item` was never even COLLECTED by the decl
    # walk (which took only struct/enum/type kinds), so EVERY decl-keyed check
    # (B/E/F.3/G) silently SKIPPED it while its inherent fns still passed the
    # name allowlist — a forgeable mint waved through. A union field's
    # visibility cannot be made private independent of the union, and union
    # construction is safe Rust, so the private-field mint invariant is
    # inexpressible. Rule F.4 HARD FAILs the union form on shape alone.
    ("union_form", "is declared as a `union`"),
    # FIX-2 — `reissue` / `as_did` VISIBILITY bound. A `pub fn reissue(&self)
    # -> Self` is allowlisted by name and correctly shaped (`&self`, no
    # raw-DID) but over-exposes the clone past the
    # `pub(in crate::context)` boundary. Rule G now rejects `pub` / `pub(crate)`
    # on `reissue`/`as_did`. The substring is unique to the accessor-vis arm.
    ("reissue_wrong_visibility", "allowlisted fn `reissue` visibility is"),
    # FIX-1 (GEN-01) — GENERIC FORM. A `struct OwnedIdentityDid<T = DID>` passed
    # the old gate (the decl walk keyed on the type NAME, never inspecting
    # `type_parameters`). Rule F.5 now HARD-FAILs the generic form on shape
    # alone; the substring is unique to the non-generic-struct arm.
    ("generic_form", "MUST be a non-generic"),
    # FIX-1 (BLACK-G07) — FREE-FUNCTION CONSTRUCTION. Rust field privacy is
    # MODULE-scoped, not impl-scoped, so a free fn in the DECLARING file
    # (`fn forge_token(did) -> OwnedIdentityDid { OwnedIdentityDid { … } }`)
    # mints via the module-private field WITHOUT an allowlisted inherent
    # constructor — and PASSES rules (A)-(G), which only inspect
    # `impl OwnedIdentityDid` blocks + decls. Rule H scans every
    # cap-constructing `struct_expression` in the declaring file and HARD FAILs
    # this one; the diagnostic names the enclosing fn. The substring
    # `in fn `forge_token`` is unique to this free-fn case.
    ("free_fn_construction", "in fn `forge_token`"),
    # FIX-1 (BLACK-G07) — HELPER-STRUCT METHOD CONSTRUCTION. A method on a
    # DIFFERENT struct (`impl TokenForger { fn mint_via_helper(&self, did) ->
    # OwnedIdentityDid { OwnedIdentityDid { … } } }`) constructs the cap via a
    # struct literal in the declaring file. Rule G's inherent allowlist
    # inspects only `impl OwnedIdentityDid` blocks, so a helper-type method is
    # invisible to it; rule H catches the construction. The substring
    # `in fn `mint_via_helper`` is unique to this helper-method case. Both H1
    # and H2 also carry the shared phrase `constructed in fn` / `outside the
    # allowlisted constructors`, but the fn name disambiguates them.
    ("helper_method_construction", "in fn `mint_via_helper`"),
    # FIX-1 (escapable-scope class) — CLOSURE INSIDE THE MINT. The cap literal
    # is built inside a `closure_expression` whose nearest enclosing
    # `function_item` is the EXACTLY-correct allowlisted `issue_for_actor` (so
    # rule G passes it and `in_allowlisted` is True — isolating the new
    # escapable-scope arm from the name arm). Pre-fix, the nearest-`function_item`
    # walk stepped PAST the closure to the allowlisted fn and the literal PASSED;
    # the closure captures the module-private field legally and can be moved out
    # and invoked later by handler code with an attacker-chosen DID. Rule H now
    # detects the intervening `closure_expression` and HARD FAILs. The substring
    # pins BOTH the escapable node type AND the enclosing-fn name so it can ONLY
    # be produced by the closure-in-`issue_for_actor` case.
    (
        "closure_in_mint",
        "`closure_expression` nested within the allowlisted constructor `issue_for_actor`",
    ),
    # FIX-1 (escapable-scope class) — REISSUE CLOSURE FACTORY (the finding's real
    # shape). `reissue` returns `Box<dyn Fn(Did) -> OwnedIdentityDid>`; the cap
    # literal lives in the returned closure. Rule G passes the outer `reissue`
    # (it does not constrain reissue's return type), so `in_allowlisted` is True;
    # rule H catches the intervening `closure_expression`. The `reissue`
    # enclosing-fn name disambiguates this from the mint case above.
    (
        "reissue_closure_factory",
        "`closure_expression` nested within the allowlisted constructor `reissue`",
    ),
    # FIX-1 (escapable-scope class) — ASYNC BLOCK IN CONSTRUCTOR. The cap literal
    # is built inside an `async { … }` block (an `async_block` node, NOT a
    # `function_item`) inside an allowlisted `reissue`. The future can be returned
    # / spawned and polled later — a deferred-execution forgery in the same class
    # as the closure case. Pre-fix the nearest-`function_item` walk stepped past
    # the `async_block`; rule H now detects it. The `async_block` node type
    # disambiguates this from the closure cases.
    (
        "async_block_in_constructor",
        "`async_block` nested within the allowlisted constructor `reissue`",
    ),
    # FIX-1 (nested-fn name-launder) — NESTED `issue_for_actor` INSIDE `reissue`.
    # A nested `fn issue_for_actor(d: Did) -> OwnedIdentityDid` declared lexically
    # inside the real allowlisted `reissue` constructs the cap and escapes as a
    # `fn` pointer. Pre-fix this slipped BOTH rules: the literal's nearest
    # `function_item` was the INNER fn (name in CONSTRUCTING_FNS, nearest
    # `impl_item` = the real cap impl, inherent → `in_allowlisted` True), the
    # escapable-scope check stopped AT that inner fn (it IS `fn_node`, the
    # boundary, never an INTERVENING node), and rule G — which only inspects fns
    # that are DIRECT children of the impl `declaration_list` — never saw the
    # nested fn (its parent is a `block`). The `is_impl_method` structural guard
    # now requires `fn_node`'s parent chain be
    # `function_item -> declaration_list -> impl_item`; a nested fn's parent is a
    # `block`, so the guard is False and the construction falls through to the
    # "outside the allowlisted constructors" branch naming the inner fn. The
    # substring `in fn `issue_for_actor` outside` is produced by THIS case (and
    # by any OTHER rejected construction whose nearest enclosing fn happens to
    # be named `issue_for_actor` — e.g. a TRAIT-impl method literally named
    # `issue_for_actor` constructing the cap, which also routes to the
    # "outside" branch because its impl is not INHERENT). Every such shape is
    # itself a rejected forgery, so the substring still uniquely pins a
    # nested-fn-or-equivalent name-launder; it is simply less discriminating
    # than "ONLY this fixture" — both producers are HARD FAILs.
    ("nested_fn_name_launder", "in fn `issue_for_actor` outside"),
    # FIX-1 (nested-fn name-launder, symmetric) — NESTED `reissue` INSIDE
    # `issue_for_actor`. The mirror of the above: a nested `fn reissue` inside the
    # real allowlisted `issue_for_actor`, escaping as a `fn` pointer. Same pre-fix
    # bypass mechanics, same `is_impl_method` rejection. The substring
    # `in fn `reissue` outside` is produced by THIS case (and by any other
    # rejected construction whose nearest enclosing fn happens to be named
    # `reissue` — e.g. a `reissue` trait-impl method constructing the cap);
    # every such producer is itself a HARD FAIL.
    ("nested_fn_name_launder_symmetric", "in fn `reissue` outside"),
    # FIX (use-alias rename-evasion, F.2-use) — IMPORT-ALIAS OF THE CAP via
    # `use self::OwnedIdentityDid as UseAlias;` followed by an `impl UseAlias {
    # fn forge … -> Self { Self { did } } }`. Rust has exactly two
    # type-renaming mechanisms: `type X = T` (banned by F.2) and `use … as X`
    # (this hole). The alias gives the `impl` / `Self { … }` a tail identifier
    # ≠ `OwnedIdentityDid`, so rule G (inherent allowlist), rule H
    # (construction scan), and `_impl_targets_cap` all MISS it while the
    # forgery compiles and is handler-reachable. Rule F.2-use bans the import
    # alias outright, symmetric to F.2 and with the same whole-tree scope. The
    # alias NAME `UseAlias` in the diagnostic is unique to this case.
    ("use_alias_impl", "`use … as UseAlias` is an import alias"),
    # FIX (use-alias, use-group form) — `use self::{OwnedIdentityDid as
    # UseGroupAlias};` nests the `use_as_clause` inside a `use_list`; the
    # collector walks into the list and still bans it. Proves the use-group
    # spelling is caught, not only the top-level qualified-path spelling. The
    # alias NAME `UseGroupAlias` is unique to this case.
    ("use_alias_group", "`use … as UseGroupAlias` is an import alias"),
    # FIX (rule I — IN-FILE NESTED-MOD inherent cap-impl). A SECOND
    # `impl OwnedIdentityDid` hosting an allowlisted-NAMED `issue_for_actor`,
    # hidden inside a nested `mod` in the DECLARING file. Pre-fix it PASSED:
    # the per-file inherent allowlist (G) saw an allowlisted name and the
    # construction scan (H) saw an inline `Self { … }` whose nearest enclosing
    # fn is that allowlisted `issue_for_actor` (`in_allowlisted` True). The
    # canonical cap impl is TOP-LEVEL, so rule I HARD FAILs any cap inherent
    # impl nested under an in-file `mod` — the analogue of the `#[path]`
    # include escape. The substring is unique to a nested-mod inherent cap
    # impl.
    (
        "nested_mod_inherent_impl",
        "inherent impl `impl OwnedIdentityDid` is nested under a `mod`",
    ),
    # FIX (rule I — IN-FILE NESTED-MOD cap CONSTRUCTION, non-allowlisted name).
    # A nested-mod impl whose method builds the cap via an EXPLICIT-NAME
    # `OwnedIdentityDid { … }` literal. Isolates the rule-I CONSTRUCTION arm
    # with the explicit-name label (distinct from the I1 `Self`-labelled
    # construction). The substring is unique to the explicit-name nested-mod
    # construction.
    (
        "nested_mod_construction",
        "`OwnedIdentityDid { … }` cap construction is nested under a `mod`",
    ),
    # FIX (rule J — DECLARING-FILE LITERAL-FREE by-value cap-return wrapper). A
    # free fn at the declaring file's module level that returns the cap BY
    # VALUE by CALLING the `pub(super)` mint — NO struct literal of its own, so
    # rule H (struct-literal scanner) misses it; a free fn, so rule G
    # (inherent-method-only) misses it. Rule J flags the by-value cap return.
    # The fn NAME is unique to this case.
    (
        "by_value_return_declaring_file",
        "fn `forge_by_value_wrapper` returns OwnedIdentityDid BY VALUE",
    ),
    # FIX (rule J — SUBTREE non-declaring-file by-value cap-return wrapper). A
    # free fn in ANOTHER supervisor-subtree file (NOT the declaring file)
    # returning the cap BY VALUE via the `pub(super)` mint (reachable across
    # the whole `supervisor` module tree). The declaring-file-pinned rules
    # (G/H) never look here; rule J is the ONE rule that scans the whole
    # subtree and flags it. The fn NAME is unique to this subtree-leak case,
    # PROVING the rule fires OUTSIDE the declaring file.
    (
        "by_value_return_subtree",
        "fn `leak_token` returns OwnedIdentityDid BY VALUE",
    ),
    # FIX (rule K — ASSOC-TYPE PROJECTION return disguise). `forge1` returns the
    # cap via `<Cz as Carry>::O` (an associated-type projection = the cap), so
    # rule J's return-type-TEXT scan sees no cap tail and MISSES it. The fn
    # still CALLS the sole mint `issue_for_actor` — rule K flags that call,
    # immune to the return disguise. The mint reference spelling
    # `self::OwnedIdentityDid::issue_for_actor` is UNIQUE to this fixture.
    (
        "rule_k_assoc_type_projection",
        "mint `issue_for_actor` ('self::OwnedIdentityDid::issue_for_actor')",
    ),
    # FIX (rule K — TRAIT-METHOD PROJECTION mint). `mk` returns `Self::T` (an
    # impl-set associated type = the cap), dodging rule J's return-text scan AND
    # its `_returns_self`/raw-DID trait-fn path. The body CALLS the mint —
    # rule K flags it. The spelling `mods::OwnedIdentityDid::issue_for_actor` is
    # UNIQUE to this fixture.
    (
        "rule_k_trait_method_projection",
        "mint `issue_for_actor` ('mods::OwnedIdentityDid::issue_for_actor')",
    ),
    # FIX (rule K — OPAQUE `impl Sized` RETURN). `forge3` returns `impl Sized`,
    # hiding the cap type entirely from any return classifier; rule J MISSES it.
    # The body CALLS the mint via the full canonical path — rule K flags it.
    # That spelling is UNIQUE to this fixture.
    (
        "rule_k_opaque_return",
        "mint `issue_for_actor` ('crate::context::supervisor::identity_capability::OwnedIdentityDid::issue_for_actor')",
    ),
    # FIX (rule K — USE-ALIAS RENAME RESIDUAL). `use …::issue_for_actor as
    # MintRename;` renames the mint so a later bare `MintRename(d)` would dodge
    # the identifier-keyed mint-reference scan. Rule K bans the import alias
    # outright at the `use … as` site; the alias NAME `MintRename` is UNIQUE to
    # this fixture.
    (
        "rule_k_use_rename",
        "`use … as MintRename` renames the mint fn `issue_for_actor`",
    ),
    # FIX 2 (NESTED-MOD-SHADOW build-site) — K01. A nested `mod` hosting a SHADOW
    # `struct Supervisor` whose `build_actor_deps` mints via an out-param. The
    # shadow's `impl Supervisor` string-tail-matches `Supervisor` and lives in
    # `supervisor.rs`, so PRE-FIX the build-site exemption trusted its body and
    # the mint PASSED. Fix 2 requires the exempt `impl Supervisor` be TOP-LEVEL,
    # so the nested-mod shadow is NOT exempt → rule K flags it. The mint spelling
    # `k01_shadow_mint::…` is UNIQUE to this fixture.
    (
        "build_site_nested_mod_shadow",
        "'k01_shadow_mint::OwnedIdentityDid::issue_for_actor'",
    ),
    # FIX 3 (PER-CALL MINT-ARG) — K02. The real `Supervisor::build_actor_deps`
    # in `supervisor.rs` mints an ATTACKER DID from a CONSTRUCTED `Did(…)`
    # literal, not its `owning_did` parameter. Pre-fix the exemption trusted the
    # whole body; fix 3 constrains the exempt arg to a bare param (or `.clone()`),
    # so the literal-arg mint is NOT exempt → flagged. Spelling
    # `k02_attacker_mint::…` is UNIQUE to this fixture.
    (
        "build_site_attacker_did_arg",
        "'k02_attacker_mint::OwnedIdentityDid::issue_for_actor'",
    ),
    # FIX 3 (AT-MOST-ONE mint call) — K02b. A `Supervisor::build_actor_deps`
    # mints the SAME `owning_did` TWICE; the FIRST is exempt, the SECOND is
    # flagged by the single-call check. The diagnostic phrase
    # `SECOND exempt-shaped reference` is UNIQUE to this case.
    (
        "build_site_second_mint",
        "SECOND exempt-shaped reference to the mint `issue_for_actor`",
    ),
    # FIX 3 (PER-CALL MINT-ARG — SHADOW-REBIND) — G02. The real
    # `Supervisor::build_actor_deps` SHADOWS its `owning_did` parameter with a
    # `let owning_did = make_evil_did();` BEFORE the mint, then mints the bare
    # (now attacker-controlled) `owning_did`. The name-based predecessor accepted
    # the arg because the name was still ∈ param_names; the binding-based check
    # (no `let`/assignment rebind of the owning param before the mint) refuses
    # the exemption → rule K flags it. Spelling `g02_shadow_mint::…` is UNIQUE.
    (
        "build_site_param_shadow_rebind",
        "'g02_shadow_mint::OwnedIdentityDid::issue_for_actor'",
    ),
    # FIX 3 (PER-CALL MINT-ARG — ADDED DID PARAM) — G03. The real
    # `Supervisor::build_actor_deps` declares a SECOND `DID`-typed parameter
    # (`attacker: DID`) and mints from it. The name-based predecessor accepted
    # `attacker` because it was a param name; the binding-based check requires
    # EXACTLY ONE non-`self` `DID`-typed parameter, so two DID params dissolve
    # the exemption → rule K flags the mint. Spelling `g03_added_param_mint::…`
    # is UNIQUE.
    (
        "build_site_added_did_param",
        "'g03_added_param_mint::OwnedIdentityDid::issue_for_actor'",
    ),
    # KEYSTONE (static/const by-value sink) — K02-SINK. A module-level
    # `static mut …: Option<OwnedIdentityDid>` is a global exfil sink rules J/K
    # never scan. The static/const arm flags the by-value cap. The phrase
    # `BY VALUE in a `static`/`const` item` is UNIQUE to the static arm.
    (
        "keystone_static_sink",
        "BY VALUE in a `static`/`const` item",
    ),
    # KEYSTONE (`&mut` out-param) — ESC1. A `&mut OwnedIdentityDid` fn parameter.
    # Pinned to the fixture FILE+line so it cannot be satisfied by another file's
    # identical escape phrase.
    (
        "keystone_mut_out_param",
        "keystone_mut_param.rs:12: fn parameter puts the capability in a by-value ESCAPE position",
    ),
    # KEYSTONE (interior-mutability wrapper) — ESC2. A struct field
    # `Mutex<OwnedIdentityDid>`. The wrapper phrase `interior-mutability wrapper
    # `Mutex<…>`` is UNIQUE (only this fixture uses `Mutex`).
    (
        "keystone_interior_mut_wrapper",
        "interior-mutability wrapper `Mutex<…>`",
    ),
    # KEYSTONE (`&mut Vec<…Cap…>` out-param) — ESC3. The cap behind a `&mut`
    # inside a collection generic, in the interior-mut fixture file. Pinned to
    # FILE+line (the `mut_vec_out_param` fn at line 22) to isolate the
    # `&mut`-wrapping-a-`Vec` propagation path.
    (
        "keystone_mut_vec_out_param",
        "keystone_interior_mut.rs:22: fn parameter puts the capability in a by-value ESCAPE position",
    ),
    # FIX 4 (GLOB-IMPORT ban) — K03 part. A `use …identity_capability::*;` glob
    # in the subtree. The phrase `glob import `use …identity_capability::*`` is
    # UNIQUE to this rule.
    (
        "glob_import_cap_module",
        "glob import `use …identity_capability::*`",
    ),
    # FIX 4 (REASSEMBLY-MACRO ban) — K03 part. A `paste::paste!` invocation in
    # the subtree. The phrase `token-reassembling macro `paste::paste!`` is
    # UNIQUE to this rule.
    (
        "reassembly_macro_paste",
        "token-reassembling macro `paste::paste!`",
    ),
    # FIX 5 (BARE use-list mint member) — a bare `use bare_list_src::{
    # issue_for_actor};` (no `as`). Pre-fix `_is_mint_reference` deferred EVERY
    # use-path member to the `as`-rename ban; fix 5 flags a BARE list member as a
    # mint reference. Pinned to the fixture FILE+line (the bare-list `use` at
    # line 19) so it is satisfied ONLY by the bare-member arm, not the qualified
    # re-export above it.
    (
        "bare_list_mint_member",
        "bare_list_mint_use.rs:19: reference to the sole arbitrary-DID mint `issue_for_actor`",
    ),
    # FIX 6 (POSITIVE FILE-PIN) — a fake `Supervisor::build_actor_deps` in a
    # supervisor-SUBTREE file that is NOT the real build-site `supervisor.rs`.
    # The build-site exemption is pinned to `BUILD_SITE_REL`, so this same-named
    # fn in a DIFFERENT subtree file is NOT exempt → rule K flags it. Locks the
    # file pin against a silent regression. Spelling `file_pin_mint::…` is UNIQUE.
    (
        "file_pin_non_build_site",
        "'file_pin_mint::OwnedIdentityDid::issue_for_actor'",
    ),
    # FIX A (PATTERN-BINDING SHADOW — `match` arm). The real
    # `Supervisor::build_actor_deps` re-binds `owning_did` through a `match` ARM
    # PATTERN (not a `let`/assignment) before minting the bare `owning_did`.
    # `_shadows_before` pre-fix walked only `let`/assignment; the extended check
    # treats an enclosing `match_arm` pattern binding as a shadow → not exempt →
    # rule K flags the mint. Spelling `a_match_arm_mint::…` is UNIQUE.
    (
        "build_site_match_arm_shadow",
        "'a_match_arm_mint::OwnedIdentityDid::issue_for_actor'",
    ),
    # FIX A (PATTERN-BINDING SHADOW — `if let`). The `let_condition` pattern of an
    # `if let` re-binds `owning_did`, enclosing the mint. Extended `_shadows_before`
    # treats the `let_condition` binding as a shadow → not exempt → flagged.
    # Spelling `a_if_let_mint::…` is UNIQUE.
    (
        "build_site_if_let_shadow",
        "'a_if_let_mint::OwnedIdentityDid::issue_for_actor'",
    ),
    # FIX A (PATTERN-BINDING SHADOW — `while let`). The `while let` spelling of the
    # same `let_condition` shadow; proves the while-let head too. Spelling
    # `a_while_let_mint::…` is UNIQUE.
    (
        "build_site_while_let_shadow",
        "'a_while_let_mint::OwnedIdentityDid::issue_for_actor'",
    ),
    # FIX A (PATTERN-BINDING SHADOW — `for` loop). The `for_expression` loop
    # pattern re-binds `owning_did`, enclosing the mint. Extended `_shadows_before`
    # treats the `for` binder as a shadow → not exempt → flagged. Spelling
    # `a_for_pattern_mint::…` is UNIQUE.
    (
        "build_site_for_pattern_shadow",
        "'a_for_pattern_mint::OwnedIdentityDid::issue_for_actor'",
    ),
    # FIX A (PATTERN-BINDING SHADOW — closure parameter). A `closure_expression`
    # PARAMETER re-binds `owning_did`, enclosing the mint, invoked with an attacker
    # DID. Extended `_shadows_before` treats the closure param as a shadow → not
    # exempt → flagged. (The escapable-scope guard also fires; either dissolves the
    # exemption.) Spelling `a_closure_param_mint::…` is UNIQUE.
    (
        "build_site_closure_param_shadow",
        "'a_closure_param_mint::OwnedIdentityDid::issue_for_actor'",
    ),
    # FIX B (CLOSURE-LAUNDERED MINT — escapable-scope guard). The real
    # `Supervisor::build_actor_deps` mints its OWN un-shadowed `owning_did` but
    # INSIDE a `closure_expression` it RETURNS; pre-fix the mint inherited the
    # build-site exemption (nearest `function_item` = `build_actor_deps`), yet the
    # returned closure can be invoked later with the captured token. The
    # escapable-scope guard (`_escapable_scope_between`) detects the intervening
    # closure → not exempt → rule K flags it. Spelling `b_closure_launder_mint::…`
    # is UNIQUE.
    (
        "build_site_closure_laundered_mint",
        "'b_closure_launder_mint::OwnedIdentityDid::issue_for_actor'",
    ),
    # FIX C (DID-TYPE ALIAS — sole-DID-param count defeat). A `type GoodId = DID;`
    # alias on the OWNING param plus a literal-`DID` ATTACKER param; pre-fix the
    # alias hid the owning param's `DID`-ness so the attacker param was the only
    # literal-`DID` param and was pinned. The DID-type-alias ban flags the alias
    # outright in the subtree. The alias NAME `GoodId` is UNIQUE to this fixture.
    (
        "did_type_alias_owning_param",
        "`type GoodId = …DID` is a `type` alias OF the raw-DID type",
    ),
    # FIX C (DID-IMPORT ALIAS — sole-DID-param count defeat). A
    # `use super::DID as ImportedId;` import alias on the OWNING param plus a
    # literal-`DID` ATTACKER param; same threat as the `type` form. The
    # DID-use-alias ban flags the import alias outright in the subtree. The alias
    # NAME `ImportedId` is UNIQUE to this fixture.
    (
        "did_use_alias",
        "`use … as ImportedId` renames the raw-DID type `DID`",
    ),
]

# Negative-control fn / reference markers that MUST NEVER appear in the
# self-test diagnostics. Each names a UNIQUE token that surfaces in a
# diagnostic ONLY if a passing-by-design exemption regressed:
#   - `test_only_by_value_mint` / `test_only_fn_by_value_mint` — rule J's
#     cfg(test) exemption (J3 / J3b negative controls). If either regressed,
#     the cfg(test) by-value cap return would surface a rule-J diagnostic
#     NAMING the fn.
#   - `bsite_mint_ok::OwnedIdentityDid::issue_for_actor` — rule K's build-site
#     exemption (b). The K-NEG-1 fixture's EXEMPT mint call uses this UNIQUE
#     reference spelling; rule K echoes the spelling in its `ref_text`, so the
#     spelling appears in diagnostics ONLY if exemption (b) regressed.
#   - `cfgtest_mint_ok::OwnedIdentityDid::issue_for_actor` — rule K's cfg(test)
#     exemption (c). The K-NEG-2 fixture's EXEMPT (test-gated) mint call uses
#     this UNIQUE spelling; it appears in diagnostics ONLY if exemption (c)
#     regressed.
# `do_self_test` asserts NONE of these appear on the pass path, giving the
# otherwise-silent negative controls real regression teeth (an over-eager
# scanner that flags an EXEMPT mint would be caught, not shipped green).
#   - `shared_borrow_ok` — the keystone's shared-borrow negative control. A
#     `fn shared_borrow_ok(_identity: &OwnedIdentityDid)` is a READ-ONLY shared
#     borrow (the legit `SupervisorHandle` per-identity shape) and MUST NOT be
#     flagged as an escape position. Its fn name appears in a diagnostic ONLY if
#     the keystone over-flagged a plain `&` shared borrow.
#   - `PlainFieldOk` — the keystone's plain-owning-field negative control. A
#     `struct PlainFieldOk { owned_identity: OwnedIdentityDid }` plain by-value
#     field is the cap's legit home (`ActorDeps.owned_identity`), NOT an escape.
#     The struct marker appears in a diagnostic ONLY if the keystone over-flagged
#     a plain by-value struct field.
FORBIDDEN_FIXTURE_SUBSTRINGS: tuple[str, ...] = (
    "test_only_by_value_mint",
    "test_only_fn_by_value_mint",
    "bsite_mint_ok::OwnedIdentityDid::issue_for_actor",
    "cfgtest_mint_ok::OwnedIdentityDid::issue_for_actor",
    "shared_borrow_ok",
    "PlainFieldOk",
)


def do_self_test() -> int:
    """Compile the bypass fixture into a temp `crates/scp-runtime/src/`
    layout, run the scanner, and assert every known bypass surfaces as
    a failure.

    The fixture contains multiple declarations and impls across both
    the required-path location (to trigger visibility/derive/impl/field
    failures) and a wrong location (to trigger the location check). The
    scanner re-runs with `scan_dir` rooted at the temp location.
    """
    if not FIXTURE_FILE.is_file():
        sys.stderr.write(
            f"{C_RED}error:{C_RESET} fixture missing: {FIXTURE_FILE}\n"
        )
        return 2

    # Stage the fixture into a temp directory matching the real layout.
    # The fixture file declares the required path `…/supervisor/identity_capability.rs`
    # AND a wrong-location file `…/context/handlers/bad.rs`. Split the
    # fixture by a sentinel at compile time.
    fixture_text = FIXTURE_FILE.read_text()
    # Sentinel-driven split: each file block begins with
    #     // @file: <rel-path-under-scp-runtime-src>
    # on its own line. The block runs until the next @file: or EOF.
    blocks: dict[str, list[str]] = {}
    current: list[str] | None = None
    current_name: str | None = None
    for line in fixture_text.splitlines(keepends=True):
        stripped = line.strip()
        if stripped.startswith("// @file:"):
            if current is not None and current_name is not None:
                blocks[current_name] = current
            current_name = stripped[len("// @file:") :].strip()
            current = []
            continue
        if current is not None:
            current.append(line)
    if current is not None and current_name is not None:
        blocks[current_name] = current

    if not blocks:
        sys.stderr.write(
            f"{C_RED}self-test FAILED{C_RESET}: fixture has no `// @file:` "
            f"blocks.\n"
        )
        return 1

    import io

    with tempfile.TemporaryDirectory() as tmp:
        tmp_root = Path(tmp)
        src_root = tmp_root / "crates" / "scp-runtime" / "src"
        for rel_under_src, lines in blocks.items():
            dst = src_root / rel_under_src
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_text("".join(lines))

        # Reconfigure to point at the fixture temp root.
        fx_scan = src_root
        fx_required = "crates/scp-runtime/src/context/supervisor/identity_capability.rs"
        (
            decls,
            impls,
            ctor_fns,
            cap_aliases,
            trait_fns,
            macro_hits,
            construction_hits,
            use_aliases,
            nested_mod_hits,
            by_value_return_hits,
            mint_ref_hits,
            escape_position_hits,
        ) = _scan_root(fx_scan, tmp_root)
        # Capture stderr to inspect.
        buf = io.StringIO()
        fail = _enforce(
            decls,
            impls,
            ctor_fns,
            cap_aliases,
            trait_fns,
            macro_hits,
            construction_hits,
            use_aliases,
            nested_mod_hits,
            by_value_return_hits,
            mint_ref_hits,
            escape_position_hits,
            fx_required,
            stream=buf,
        )
        diag = buf.getvalue()

    if not fail:
        sys.stderr.write(
            f"{C_RED}self-test FAILED{C_RESET}: fixture did NOT trigger "
            f"any enforcement failure — scanner is broken or fixture is "
            f"wrong.\n"
        )
        return 1

    missing: list[str] = []
    for label, substr in REQUIRED_FIXTURE_FAILURES:
        if substr not in diag:
            missing.append(f"{label}: expected substring {substr!r} not in diagnostics")

    if missing:
        sys.stderr.write(
            f"{C_RED}self-test FAILED{C_RESET}: "
            f"{len(missing)} bypass pattern(s) not detected:\n"
        )
        for m in missing:
            sys.stderr.write(f"  - {m}\n")
        sys.stderr.write("\nActual diagnostics:\n")
        sys.stderr.write(diag)
        return 1

    # Negative-control regression teeth. The REQUIRED_FIXTURE_FAILURES check
    # above only asserts that EXPECTED diagnostics are PRESENT — it discards the
    # diagnostics on the pass path, so a regressed EXEMPTION (a cfg(test) /
    # build-site mint that started being flagged) would ship GREEN. Assert that
    # NONE of the negative-control markers appear: each surfaces ONLY if a
    # passing-by-design exemption (rule J cfg(test); rule K cfg(test) /
    # build-site) over-eagerly flagged an EXEMPT mint.
    forbidden_present = [s for s in FORBIDDEN_FIXTURE_SUBSTRINGS if s in diag]
    if forbidden_present:
        sys.stderr.write(
            f"{C_RED}self-test FAILED{C_RESET}: "
            f"{len(forbidden_present)} negative-control marker(s) appeared in "
            f"diagnostics — a passing-by-design exemption regressed (an EXEMPT "
            f"cfg(test) / build-site mint was wrongly flagged):\n"
        )
        for s in forbidden_present:
            sys.stderr.write(f"  - {s!r} must NOT appear in diagnostics\n")
        sys.stderr.write("\nActual diagnostics:\n")
        sys.stderr.write(diag)
        return 1

    # Enumerate modes dynamically from the fixture labels so this message can
    # never drift from the actual enforcement set as new modes are added.
    mode_labels = ", ".join(label for label, _ in REQUIRED_FIXTURE_FAILURES)
    print(
        f"{C_GREEN}owned-identity-did self-test PASSED{C_RESET}: "
        f"fixture triggered {len(REQUIRED_FIXTURE_FAILURES)} distinct "
        f"enforcement modes ({mode_labels})."
    )
    return 0


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(
        description=(
            "AST check for OwnedIdentityDid capability invariants (ADR-049). "
            "Pre-commit-5 this passes silently."
        )
    )
    ap.add_argument("--self-test", action="store_true", help="run fixture self-test")
    args = ap.parse_args()

    if args.self_test:
        return do_self_test()

    (
        decls,
        impls,
        ctor_fns,
        cap_aliases,
        trait_fns,
        macro_hits,
        construction_hits,
        use_aliases,
        nested_mod_hits,
        by_value_return_hits,
        mint_ref_hits,
        escape_position_hits,
    ) = find_declarations()
    if (
        not decls
        and not impls
        and not cap_aliases
        and not trait_fns
        and not macro_hits
        and not construction_hits
        and not use_aliases
        and not nested_mod_hits
        and not by_value_return_hits
        and not mint_ref_hits
        and not escape_position_hits
    ):
        # Type does not yet exist AND nothing references it — this is the
        # pre-commit-5 state. (A macro touching the cap type or a trait impl
        # of it implies the type is being introduced, so those keep the gate
        # active even if the struct decl is hidden behind a macro.)
        print(
            f"{C_DIM}owned-identity-did check:{C_RESET} "
            f"type {TYPE_NAME!r} not declared yet "
            f"{C_DIM}(commit 5 of the actor PR introduces it){C_RESET}"
        )
        return 0

    fail = _enforce(
        decls,
        impls,
        ctor_fns,
        cap_aliases,
        trait_fns,
        macro_hits,
        construction_hits,
        use_aliases,
        nested_mod_hits,
        by_value_return_hits,
        mint_ref_hits,
        escape_position_hits,
        REQUIRED_PATH,
        stream=sys.stderr,
    )

    if fail:
        sys.stderr.write(
            f"\n{C_RED}owned-identity-did check FAILED{C_RESET} "
            f"({len(decls)} declaration(s), {len(impls)} impl(s) found).\n"
        )
        return 1

    print(
        f"{C_GREEN}owned-identity-did check PASSED{C_RESET}: "
        f"{len(decls)} declaration(s) in {REQUIRED_PATH}, "
        f"struct pub(in crate::context), inherent impl contains ONLY the "
        f"allowlisted fns issue_for_actor (pub(super) raw-DID mint), "
        f"reissue and as_did (&self, no raw-DID) — any other inherent fn "
        f"(any return type, incl. aliased/impl-Trait) would be rejected, "
        f"no forbidden derives, no forbidden impls, no public fields, no "
        f"`type` alias of the capability."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
