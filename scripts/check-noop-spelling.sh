#!/usr/bin/env bash
# check-noop-spelling.sh — one canonical CamelCase spelling of the "no-op"
# identifier prefix, repository-wide.
#
# ---------------------------------------------------------------------------
# THIS IS A HYGIENE GATE, NOT A SAFETY GATE
# ---------------------------------------------------------------------------
# Read this paragraph before you cite this gate for anything. This gate proves
# nothing about behaviour. The canonical prefix names three unrelated kinds of
# type today: types that fail closed with a typed error, types whose no-op
# behaviour is a deliberate production decision, and security nullifiers. A
# reader decides which kind a given type is by reading that type's
# implementation against the capability classification in
# .docs/specs/17-persistence-and-storage.md §17.17, never by reading its name.
#
# Two other mechanisms enforce the rule that no dev/test-only stand-in may be
# reachable on a shipped production path: the prove-absence gate in
# scripts/check-shipped-feature-graph.sh, which ADR-062 (capability injection
# and prove-absent dev backends) specifies, and the capability classification
# in .docs/specs/17-persistence-and-storage.md §17.17. A pass from this gate is
# evidence about neither.
#
# ---------------------------------------------------------------------------
# WHY IT EXISTS
# ---------------------------------------------------------------------------
# When one prefix carries two spellings, a case-sensitive search for either
# spelling returns a result set that looks complete and omits every type
# spelled the other way. A census of this repository's no-op types searched one
# spelling and reported 5 types; it omitted the 5 types spelled the other way,
# among them a no-op saga journal that the FFI `with_providers` factory wires
# in. Every census, allowlist entry, exemption review and human read that
# supports the nullifier work searches by name, so a name search has to reach
# every type.
#
# ---------------------------------------------------------------------------
# THE CRITERION
# ---------------------------------------------------------------------------
# In every file git tracks, and in every working-tree file .gitignore does not
# exclude: each occurrence of the letters n-o-o-p, in any case, immediately
# followed by an uppercase ASCII letter, MUST be spelled exactly `NoOp`.
#
# The trailing uppercase letter is what makes the occurrence an identifier
# prefix rather than the English word. Followed by a space, a hyphen or an
# underscore, the four letters are prose or a SCREAMING_SNAKE_CASE constant,
# and this gate leaves them alone. Followed by an uppercase letter, they head a
# CamelCase or camelCase identifier, and this gate governs them. The self-test
# fixture below carries a worked example of each shape, every one of them built
# from the canonical spelling at run time so that this file never contains a
# spelling it would reject.
#
# The check is closed by construction: it enumerates the whole case-variant
# space of those four letters and permits exactly one member of that space. A
# future author cannot invent a spelling the enumeration misses, because the
# enumeration already covers all 16 of them. The check therefore carries no
# exemption list and needs none. The scan excludes no path, and it reads this
# script along with every other file.
#
# ---------------------------------------------------------------------------
# HOW TO FIX A FAILURE
# ---------------------------------------------------------------------------
# Rename the identifier to the canonical spelling everywhere it appears:
# definition, impls, imports, call sites, doc comments, and prose references in
# .docs/ and the per-crate CLAUDE.md files. Change nothing else. This gate
# never asks you to change a type's behaviour, put a type behind a `cfg`, or
# delete a type.
#
# ---------------------------------------------------------------------------
# SELF-TEST
# ---------------------------------------------------------------------------
# `check-noop-spelling.sh --self-test` proves the detector is alive against a
# scratch fixture: two non-canonical spellings (an upper-CamelCase Rust type
# and a lower-camelCase JS binding) MUST be flagged, and three benign lines —
# the canonical spelling, the bare word in prose, and a SCREAMING_SNAKE_CASE
# constant — MUST NOT be. It touches only a temp dir. CI runs it before the
# real check.
set -euo pipefail

# The one permitted spelling.
CANONICAL='NoOp'

# The full case-variant space of the four letters, immediately followed by the
# uppercase letter that marks an identifier prefix.
SCAN_RE='[Nn][Oo][Oo][Pp][A-Z]'

# find_violations CMD [ARG...]
#   Runs the supplied `grep`-family command, which must emit one
#   `LOCATION:MATCH` line per occurrence (`-n -o -H`), and prints the
#   occurrences whose matched text is not the canonical spelling. This is the
#   single classification path: the repository scan and the self-test differ
#   only in which command produces the occurrences.
find_violations() {
    "$@" | grep -vE ":${CANONICAL}[A-Z]\$" || true
}

self_test() {
    echo "check-noop-spelling self-test..."
    local tmp rc=0 found expected

    # Both variants are derived from the canonical spelling rather than written
    # out, so this script never contains a spelling it rejects and therefore
    # needs no exemption for itself.
    local upper_variant lower_variant
    upper_variant="$(printf '%s' "$CANONICAL" | tr 'O' 'o')"
    lower_variant="$(printf '%s' "$CANONICAL" | tr 'A-Z' 'a-z')"

    tmp="$(mktemp -d)"

    # Lines 1-2 are true positives, lines 3-5 are the pinned false-positive
    # controls. Keep them in this order; the assertions below name line numbers.
    {
        printf 'struct %sFixture;\n' "$upper_variant"
        printf 'const %sHandler = () => {};\n' "$lower_variant"
        printf 'struct %sFixture;\n' "$CANONICAL"
        printf '// a %s helper, described in prose\n' "$lower_variant"
        printf 'const %s_TIMEOUT_MS: u64 = 0;\n' "$(printf '%s' "$CANONICAL" | tr 'a-z' 'A-Z')"
    } >"$tmp/fixture.txt"

    found="$(find_violations grep -IHnoE "$SCAN_RE" "$tmp/fixture.txt")"
    expected="$(printf '%s:1:%sF\n%s:2:%sH' "$tmp/fixture.txt" "$upper_variant" "$tmp/fixture.txt" "$lower_variant")"

    if [ "$found" = "$expected" ]; then
        echo "  [ok] both non-canonical spellings flagged, on lines 1 and 2"
        echo "  [ok] canonical spelling, prose word, and SCREAMING_SNAKE constant not flagged"
    else
        echo "  [FAIL] self-test: detector output did not match." >&2
        echo "  expected:" >&2
        printf '%s\n' "$expected" >&2
        echo "  got:" >&2
        printf '%s\n' "$found" >&2
        rc=1
    fi

    rm -rf "$tmp"
    if [ "$rc" -eq 0 ]; then
        echo "check-noop-spelling self-test PASSED"
    fi
    return "$rc"
}

main() {
    if [ "${1:-}" = "--self-test" ]; then
        self_test
        return
    fi

    # Anchor at the repository root so the scan is invocation-directory
    # independent (works from any subdirectory).
    cd "$(git rev-parse --show-toplevel)"

    echo "Checking the canonical \`${CANONICAL}\` identifier prefix spelling..."

    local violations
    # `--untracked --exclude-standard` adds files that are new in the working
    # tree but not yet staged, while still honouring .gitignore — so a local
    # run catches a violation before it is committed, and a CI run (where
    # everything is already tracked) sees exactly the same set.
    violations="$(find_violations git grep -I -n -o -E --untracked --exclude-standard "$SCAN_RE" -- .)"

    if [ -z "$violations" ]; then
        echo "check-noop-spelling: OK (every identifier prefix spelled \`${CANONICAL}\`)."
        return 0
    fi

    printf '%s\n' "$violations" | while IFS= read -r line; do
        echo "VIOLATION: $line"
    done

    cat >&2 <<EOF

ERROR: found $(printf '%s\n' "$violations" | wc -l | tr -d ' ') non-canonical spelling(s) of the no-op identifier prefix.
Spell it \`${CANONICAL}\` — capital N, lowercase o, capital O, lowercase p —
everywhere: definition, impls, imports, call sites, doc comments, and prose in
.docs/ and the per-crate CLAUDE.md files.

This gate is HYGIENE, not safety. It keeps name-based searches and censuses
able to find every no-op type; it proves nothing about whether any of them
lies to its callers. See the header of scripts/check-noop-spelling.sh.
EOF
    return 1
}

main "$@"
