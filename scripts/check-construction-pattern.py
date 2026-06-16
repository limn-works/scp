#!/usr/bin/env python3.12
"""CI gate enforcing the ADR-052 Unified Construction Pattern.

Scans construction module files for two classes of violation:

M5 — Builder types and typestate markers are forbidden in construction modules.
     A construction module is any file matching:
       crates/*/src/config.rs
       crates/*/src/self_host.rs
       crates/*/src/*config*.rs
     In those files, flag:
       - Any `struct` whose name ends in `Builder`
       - Any unit struct that carries a typestate-marker name: a name that
         contains Has / No / With / Without / Unset (common typestate prefixes)
         or appears as a generic bound in the same file.

M1 — Boolean fields for semantic choices are forbidden in `pub struct *Config`
     structs inside construction modules.  A field is flagged when:
       - It is declared `pub <name>: bool` inside a struct whose name ends in
         `Config`
       - Its field name contains one of the semantic-choice heuristic keywords:
         enable, disable, use, skip, allow, plaintext, supports, has_
     An allowlist covers the small set of legitimate bool fields whose names
     happen to trigger the heuristic but carry truly binary semantics (see
     M1_BOOL_ALLOWLIST below).

Usage
-----
    python3.12 scripts/check-construction-pattern.py

Exit codes
----------
    0  — no violations found
    1  — one or more violations found
    2  — invocation error (run from repo root)

Enforcement surface
-------------------
This script is listed in scripts/hooks/pretooluse-enforcement-files.sh and
wired into CI (.github/workflows/ci.yml, job "construction-pattern").  It must
NOT be modified to weaken checks; only additive changes (new rule coverage,
new allowlist entries) are permitted.  See CLAUDE.md §enforcement files.

ADR reference: ADR-052 in .docs/adrs/phase-2.md; standard:
.docs/standards/construction.md (M1, M5).
"""
from __future__ import annotations

import pathlib
import re
import sys

# ---------------------------------------------------------------------------
# Construction-module file patterns (relative to repo root)
# ---------------------------------------------------------------------------

# Globs that identify construction-module files — the M5 and M1 scan scope.
# `self_host.rs` is not a *config* file but it is explicitly listed in the
# construction standard as part of the managed construction surface.
CONSTRUCTION_MODULE_GLOBS = [
    "crates/*/src/config.rs",
    "crates/*/src/self_host.rs",
    "crates/*/src/*config*.rs",
]

# ---------------------------------------------------------------------------
# M5 — Builder and typestate-marker allowlists
# ---------------------------------------------------------------------------

# Typestate-marker keyword prefixes.  A unit struct (`struct Foo;`) whose name
# *starts with* one of these (at the start or at a CamelCase word boundary) is
# considered a typestate marker.  We use regex to match at word boundaries
# (start of name or preceded by a capital that opens a new CamelCase word).
#
# Examples that should match:  HasDomain  NoDomain  HasIdentity  WithTls
#                               WithoutNat  UnsetCustody
# Examples that must NOT match: Node  Nothing  Normalized  Holder  Notable
TYPESTATE_PREFIX_RE = re.compile(
    r"^(?:Has[A-Z]|No[A-Z]|With[A-Z]|Without[A-Z]|Unset[A-Z])"
)

# Struct names that are unconditionally allowed regardless of their shape or
# naming convention.  Extend this set when a new legitimate pattern emerges.
M5_STRUCT_ALLOWLIST: frozenset[str] = frozenset(
    [
        # ExplicitIdentity is a payload struct (the data for
        # IdentitySource::Explicit), not a typestate marker.
        "ExplicitIdentity",
    ]
)

# ---------------------------------------------------------------------------
# M1 — Bool-field semantic-choice heuristic
# ---------------------------------------------------------------------------

# Field-name fragments that suggest the bool encodes a semantic choice
# (something that should be an enum variant, not a boolean flag).
SEMANTIC_BOOL_FRAGMENTS = frozenset(
    ["enable", "disable", "use", "skip", "allow", "plaintext", "supports", "has_"]
)

# Allowlist of (struct_name, field_name) pairs that are EXEMPT from M1.
# Each entry documents why the bool is truly binary rather than a semantic
# choice and therefore does NOT need an enum.
M1_BOOL_ALLOWLIST: frozenset[tuple[str, str]] = frozenset(
    [
        # `http3` in a RelayConfig-family struct: HTTP/3 support is a pure
        # on/off toggle.  If this field ever appears in a construction-module
        # struct (none currently exist), it is exempt.
        # ("RelayConfig", "http3"),
        #
        # Add future exemptions here as ("StructName", "field_name") tuples,
        # each with a one-line rationale comment.
    ]
)

# ---------------------------------------------------------------------------
# Regex helpers
# ---------------------------------------------------------------------------

# Matches a struct definition line, capturing the struct name.
# Handles: `pub struct Foo`, `struct Foo`, `pub(crate) struct Foo`.
_STRUCT_DEF_RE = re.compile(r"^\s*(?:pub(?:\([^)]+\))?\s+)?struct\s+([A-Za-z][A-Za-z0-9_]*)")

# Unit struct — struct with NO body (ends with `;` after the name, possibly
# with a generic clause).  E.g. `struct HasDomain;` `pub struct NoDomain;`
# `struct FooBuilder;`
_UNIT_STRUCT_RE = re.compile(
    r"^\s*(?:pub(?:\([^)]+\))?\s+)?struct\s+([A-Za-z][A-Za-z0-9_]*)(?:<[^>]*>)?\s*;"
)

# Matches a public field inside a struct body.
# Group 1: field name.  Group 2: field type.
# E.g. `    pub plaintext: bool,`
#      `    pub enable_foo: bool,`
_PUB_FIELD_RE = re.compile(r"^\s+pub\s+([A-Za-z][A-Za-z0-9_]*)\s*:\s*([A-Za-z][A-Za-z0-9_:<>, ]*)")

# ---------------------------------------------------------------------------
# Helper: is this struct name a typestate-marker name?
# ---------------------------------------------------------------------------

def _is_typestate_name(name: str) -> bool:
    """Return True if the struct name looks like a typestate marker.

    Matches names that START with Has/No/With/Without/Unset followed immediately
    by an uppercase letter — the canonical CamelCase typestate-marker prefix
    pattern.  This deliberately avoids false-positives on legitimate names like
    ``Node`` (starts with No but ``d`` is lowercase) or ``Holder``.
    """
    return bool(TYPESTATE_PREFIX_RE.match(name))


# ---------------------------------------------------------------------------
# Helper: does this struct name end in Builder?
# ---------------------------------------------------------------------------

def _is_builder_name(name: str) -> bool:
    return name.endswith("Builder")


# ---------------------------------------------------------------------------
# Helper: does this field name look like a semantic choice?
# ---------------------------------------------------------------------------

def _is_semantic_bool_field(field_name: str) -> bool:
    lower = field_name.lower()
    return any(frag in lower for frag in SEMANTIC_BOOL_FRAGMENTS)


# ---------------------------------------------------------------------------
# File scanner
# ---------------------------------------------------------------------------

def scan_file(path: pathlib.Path) -> list[str]:
    """Scan a single construction-module file.

    Returns a list of violation strings (empty means clean).
    Each violation is of the form:
        "<path>:<line>: <M-code> violation — <description>"
    """
    violations: list[str] = []

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        violations.append(f"{path}: ERROR — cannot read file: {exc}")
        return violations

    lines = text.splitlines()

    # Track which struct we are currently inside (for M1 scope).
    # We use a simple brace-depth counter: when depth goes to 0 we leave the
    # struct, when we find a `pub struct *Config` we enter it.
    # This is intentionally simpler than a full parser and sufficient because
    # construction-module files follow the established coding standard.

    current_config_struct: str | None = None  # name of the *Config struct we're in
    brace_depth: int = 0  # depth relative to struct body open-brace

    for lineno, raw in enumerate(lines, start=1):
        line = raw

        # ---------------------------------------------------------------
        # M5 — Builder struct check
        # ---------------------------------------------------------------
        m = _STRUCT_DEF_RE.match(line)
        if m:
            struct_name = m.group(1)

            if struct_name in M5_STRUCT_ALLOWLIST:
                pass  # explicitly exempted — no check needed

            elif _is_builder_name(struct_name):
                violations.append(
                    f"  {path}:{lineno}: M5 violation — struct {struct_name} "
                    f"(Builder type in construction module)"
                )

            else:
                # Unit-struct typestate marker?
                um = _UNIT_STRUCT_RE.match(line)
                if um:
                    uname = um.group(1)
                    if uname not in M5_STRUCT_ALLOWLIST and _is_typestate_name(uname):
                        violations.append(
                            f"  {path}:{lineno}: M5 violation — struct {uname}; "
                            f"(typestate marker in construction module)"
                        )

        # ---------------------------------------------------------------
        # M1 — Bool fields in *Config structs
        # ---------------------------------------------------------------

        # Track entering a *Config struct (update even if we also flagged M5
        # above — we want both checks on the same pass).
        struct_match = _STRUCT_DEF_RE.match(line)
        if struct_match:
            sname = struct_match.group(1)
            if sname.endswith("Config"):
                # We are entering a new Config struct context.
                # Reset depth tracking — the `{` that opens the struct body
                # may be on this line or a subsequent one; we start counting
                # from the first `{` we see after the struct declaration.
                current_config_struct = sname
                brace_depth = 0

        if current_config_struct is not None:
            # Count braces in this line to track struct body scope.
            for ch in line:
                if ch == "{":
                    brace_depth += 1
                elif ch == "}":
                    brace_depth -= 1
                    if brace_depth <= 0:
                        # Left the struct body.
                        current_config_struct = None
                        brace_depth = 0
                        break  # rest of line is outside the struct

            # Check for a `pub <field>: bool` inside the Config struct body.
            if current_config_struct is not None and brace_depth > 0:
                fm = _PUB_FIELD_RE.match(line)
                if fm:
                    field_name = fm.group(1)
                    field_type = fm.group(2).strip().rstrip(",")
                    # Only flag `bool` fields whose type is exactly `bool`.
                    if field_type == "bool" and _is_semantic_bool_field(field_name):
                        # Check allowlist.
                        if (current_config_struct, field_name) not in M1_BOOL_ALLOWLIST:
                            violations.append(
                                f"  {path}:{lineno}: M1 violation — "
                                f"{current_config_struct}.{field_name}: bool "
                                f"(semantic bool field; use an enum variant instead)"
                            )

    return violations


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    repo_root = pathlib.Path(".")

    # Verify we look like a repo root (cheap sanity check).
    if not (repo_root / "Cargo.toml").exists():
        print(
            "ERROR: check-construction-pattern.py must be run from the repo root "
            "(Cargo.toml not found).",
            file=sys.stderr,
        )
        return 2

    # Collect all construction-module files.
    files: list[pathlib.Path] = []
    for pattern in CONSTRUCTION_MODULE_GLOBS:
        files.extend(repo_root.glob(pattern))
    files = sorted(set(files))

    # Run the scanner.
    all_violations: list[str] = []
    for f in files:
        all_violations.extend(scan_file(f))

    if all_violations:
        print("FAIL: scripts/check-construction-pattern.py")
        for v in all_violations:
            print(v)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
