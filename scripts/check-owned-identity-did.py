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
      §"`OwnedIdentityDid` via module visibility".

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
          raw-DID parameter. (Returns `Self`.)
        - `as_did` — accessor. MUST take `&self`. MUST NOT take a raw-DID
          parameter. (Returns `&DID`.)
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

  (F) The type MUST be a `struct` (or `enum`).
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
  - trait-impl mints (D, extended — any trait method returning the cap type)
  - macros touching the cap type (B-macro)
  - `#[path]` escapes out of src/ (C-path)
  - forbidden derives / forbidden manual trait impls (C / D)
  - `type` aliases of the cap (F.1 / F.2)
  - struct location, name-visibility, and field visibility (A / B / E)

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
and submodules). Finds every `struct OwnedIdentityDid` or `enum
OwnedIdentityDid` declaration, every `impl ... for OwnedIdentityDid`
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
         type); OR --self-test did not catch all bypasses
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
    list[tuple[str, int, str, list[str], list[tuple[int, str]], str]],
    list[tuple[str, int, str | None]],
    list[tuple[str, int, str, str, str, str]],
    list[tuple[str, int, str]],
    list[tuple[str, int, str, str, str, str, str]],
    list[tuple[str, int, str]],
]:
    """Walk scan_dir and return (decls, impls, ctor_fns, cap_aliases,
    trait_fns, macro_hits).

    decls: list of (rel_path, line, visibility, derives, public_fields,
                    kind) where kind is 'struct' | 'enum' | 'type_alias'.
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
    """
    decls: list[tuple[str, int, str, list[str], list[tuple[int, str]], str]] = []
    impls: list[tuple[str, int, str | None]] = []
    ctor_fns: list[tuple[str, int, str, str, str, str]] = []
    cap_aliases: list[tuple[str, int, str]] = []
    trait_fns: list[tuple[str, int, str, str, str, str, str]] = []
    macro_hits: list[tuple[str, int, str]] = []
    # Rel path of the ONE file allowed to declare the cap type. The same
    # relative path holds under both the real repo_root and the self-test's
    # temp staging root, so the declaring-file macro rule (B, sub-case 1)
    # keys on it identically in both.
    required_rel = REQUIRED_PATH
    if not scan_dir.is_dir():
        return decls, impls, ctor_fns, cap_aliases, trait_fns, macro_hits
    for root, _, files in os.walk(scan_dir):
        for fname in files:
            if not fname.endswith(".rs"):
                continue
            full = Path(root) / fname
            rel = full.relative_to(repo_root).as_posix()
            source = full.read_bytes()
            tree = PARSER.parse(source)

            def walk(node) -> None:
                if node.type in ("struct_item", "enum_item", "type_item"):
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
                                "type_item": "type_alias",
                            }[node.type]
                            decls.append(
                                (
                                    rel,
                                    node.start_point[0] + 1,
                                    vis,
                                    derives,
                                    pubs,
                                    kind,
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
                if node.type == "attribute_item":
                    path_hit = _path_attr_escape(node, source, full, scan_dir)
                    if path_hit is not None:
                        macro_hits.append(
                            (rel, node.start_point[0] + 1, path_hit)
                        )
                for c in node.children:
                    walk(c)

            walk(tree.root_node)
    return decls, impls, ctor_fns, cap_aliases, trait_fns, macro_hits


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
    decls: list[tuple[str, int, str, list[str], list[tuple[int, str]], str]],
    impls: list[tuple[str, int, str | None]],
    ctor_fns: list[tuple[str, int, str, str, str, str]],
    cap_aliases: list[tuple[str, int, str]],
    trait_fns: list[tuple[str, int, str, str, str, str, str]],
    macro_hits: list[tuple[str, int, str]],
    required_path: str,
    stream=sys.stderr,
) -> bool:
    """Apply checks A-G. Returns True on FAIL, False on PASS. Writes
    diagnostics to `stream`. Caller must decide exit code and final
    messaging.
    """
    fail = False

    # (F) Type alias ban. Runs FIRST because an alias invalidates all
    # other checks on that declaration.
    #
    # (F.1) A `type OwnedIdentityDid = …;` alias — the cap NAME used as an
    # alias — erases the nominal distinction outright.
    for rel, line, _, _, _, kind in decls:
        if kind == "type_alias":
            stream.write(
                f"{C_RED}FAIL{C_RESET}: {rel}:{line}: "
                f"{TYPE_NAME} is declared as a `type` alias; it MUST be "
                f"a `struct` (or `enum`). A type alias erases the nominal "
                f"distinction and defeats the capability. "
                f"See ADR-049 §'Cross-identity isolation'.\n"
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
            f"directly. See ADR-049 §'Cross-identity isolation'.\n"
        )
        fail = True

    # (A) Location: every decl must live at REQUIRED_PATH.
    for rel, line, _, _, _, _ in decls:
        if rel != required_path:
            stream.write(
                f"{C_RED}FAIL{C_RESET}: {rel}:{line}: "
                f"{TYPE_NAME} must be declared in {required_path}, "
                f"not {rel}. See ADR-049 §'Cross-identity isolation'.\n"
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
    for rel, line, vis, _, _, _ in decls:
        if vis != "pub(in crate::context)":
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
    for rel, line, _, derives, _, _ in decls:
        bad = [d for d in derives if d in FORBIDDEN_DERIVES]
        if bad:
            stream.write(
                f"{C_RED}FAIL{C_RESET}: {rel}:{line}: "
                f"{TYPE_NAME} has forbidden derive(s): {', '.join(sorted(set(bad)))}.\n"
                f"       Forbidden: {', '.join(sorted(FORBIDDEN_DERIVES))}.\n"
                f"       See ADR-049 §'Cross-identity isolation'.\n"
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
                f"See ADR-049 §'Cross-identity isolation'.\n"
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
    for rel, fn_line, fn_name, _vis, params, ret_ty, t_name in trait_fns:
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
                f"See ADR-049 §'OwnedIdentityDid via module visibility'.\n"
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
            f"See ADR-049 §'OwnedIdentityDid via module visibility'.\n"
        )
        fail = True

    # (E) Public fields on struct.
    for rel, line, _, _, pubs, kind in decls:
        if kind != "struct":
            continue
        for field_line, vis in pubs:
            stream.write(
                f"{C_RED}FAIL{C_RESET}: {rel}:{field_line}: "
                f"{TYPE_NAME} has a public field with visibility "
                f"{vis!r}. All fields MUST be private. A {vis} field on "
                f"this type lets handlers reach the inner DidId and "
                f"bypass the capability boundary. "
                f"See ADR-049 §'Cross-identity isolation'.\n"
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
                    f"See ADR-049 §'OwnedIdentityDid via module visibility'.\n"
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
                        f"See ADR-049 §'OwnedIdentityDid via module visibility'.\n"
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
                        f"See ADR-049 §'OwnedIdentityDid via module visibility'.\n"
                    )
                    fail = True
                if takes_self:
                    stream.write(
                        f"{C_RED}FAIL{C_RESET}: {r}:{fn_line}: "
                        f"mint fn `issue_for_actor` takes `&self` (params "
                        f"{params.strip()!r}); the mint is an ASSOCIATED fn "
                        f"that constructs from a raw `DID`, not a method on "
                        f"an existing token. "
                        f"See ADR-049 §'OwnedIdentityDid via module visibility'.\n"
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
                        f"See ADR-049 §'OwnedIdentityDid via module visibility'.\n"
                    )
                    fail = True

            # (G.2 & G.3) `reissue` / `as_did` — clone path and accessor.
            # Both MUST take `&self` and MUST NOT take a raw-DID param. Only
            # the mint may take a raw DID ("exactly one raw-DID mint", folded
            # into the allowlist).
            if fn_name in ("reissue", "as_did"):
                if not takes_self:
                    stream.write(
                        f"{C_RED}FAIL{C_RESET}: {r}:{fn_line}: "
                        f"allowlisted fn `{fn_name}` does NOT take `&self` "
                        f"(params {params.strip()!r}); `reissue` (clone) and "
                        f"`as_did` (accessor) MUST be `&self` methods on an "
                        f"already-held token, never associated fabrication "
                        f"paths. "
                        f"See ADR-049 §'OwnedIdentityDid via module visibility'.\n"
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
                        f"See ADR-049 §'OwnedIdentityDid via module visibility'.\n"
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
                f"See ADR-049 §'OwnedIdentityDid via module visibility'.\n"
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
]


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
        decls, impls, ctor_fns, cap_aliases, trait_fns, macro_hits = _scan_root(
            fx_scan, tmp_root
        )
        # Capture stderr to inspect.
        buf = io.StringIO()
        fail = _enforce(
            decls,
            impls,
            ctor_fns,
            cap_aliases,
            trait_fns,
            macro_hits,
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

    print(
        f"{C_GREEN}owned-identity-did self-test PASSED{C_RESET}: "
        f"fixture triggered {len(REQUIRED_FIXTURE_FAILURES)} distinct "
        f"enforcement modes (derive, manual-impl Clone + From, "
        f"public named field, public tuple field, type alias, "
        f"wrong struct visibility, allowlist: second mint `issue_again`, "
        f"alternately-named mint `forge`, wrong mint visibility, "
        f"non-allowlisted assoc fn `dup`, aliased-return forgery "
        f"`forge_aliased`, `impl Sized`-return forgery `forge2`, "
        f"`DidId`-param mint `mint_didid`, `type` alias OF the cap type, "
        f"custom-trait mint `forge`/`Forger`, macro-hidden mint, "
        f"declaring-file macro category ban, metavariable impl-synthesizer "
        f"macro, alias-return trait mint via raw-DID param, "
        f"`#[path]` escape, wrong location, cfg_attr conditional derive)."
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

    decls, impls, ctor_fns, cap_aliases, trait_fns, macro_hits = find_declarations()
    if (
        not decls
        and not impls
        and not cap_aliases
        and not trait_fns
        and not macro_hits
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
