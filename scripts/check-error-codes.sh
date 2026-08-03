#!/usr/bin/env bash
# check-error-codes.sh — CI gate enforcing SCP error code conformance.
#
# Phase 1: Validates every SCP error code uses a canonical prefix with a
#           number in the allocated range (sdk-common.md).
# Phase 2: Detects cross-bridge error code collisions — same code number
#           used for semantically different errors.
# Phase 3: Registry in-band uniqueness — each code literal is defined by
#           exactly one constant in error_codes.rs (one number, one purpose).
# Phase 4: Outlet 6100-6199 sub-block conformance (SCP-OUT-030, spec §5.4.4).
#           Validates the compact outlet-error registry
#           (crates/scp-protocol/src/context/outlets/error_codes.rs): every
#           live SCP-OUTLET-61NN literal is allocated there, every allocated
#           code is mapped to a class, and each of the 8 OutletErrorClass
#           variants has its literal present. Lists all 8 classes each run.
#
# Canonical prefixes and ranges:
#   SCP-IDENT-   1000-1999    SCP-CTX-     2000-2999
#   SCP-PERM-    3000-3999    SCP-CRYPTO-  4000-4999
#   SCP-TRANS-   5000-5999    SCP-OUTLET-  6000-6999
#   SCP-VALID-   7000-7999    SCP-STORAGE- 8000-8999
#   SCP-ATTEST-  9000-9999    SCP-MCP-     10000-10999
#
# Dedicated subranges:
#   SCP-GOV-     11000-11999
#   SCP-ECON-    12000-12999
#   SCP-SAGA-    13000-13999
#
# Exit 0 on success, 1 on any violation.
# Usage: ./scripts/check-error-codes.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

VIOLATIONS=0
CHECKED=0

check_code() {
    local file="$1"
    local line_num="$2"
    local code="$3"

    CHECKED=$((CHECKED + 1))

    local prefix number
    prefix="${code%-*}"   # e.g. SCP-IDENT, SCP-CTX
    number="${code##*-}"  # e.g. 1001, 2001

    if ! [[ "$number" =~ ^[0-9]+$ ]]; then
        echo "VIOLATION: $file:$line_num: $code — number part '$number' is not numeric"
        VIOLATIONS=$((VIOLATIONS + 1))
        return
    fi

    local num=$((10#$number))

    case "$prefix" in
        SCP-IDENT)    [[ $num -ge 1000 && $num -le 1999 ]] || { echo "VIOLATION: $file:$line_num: $code — IDENT range is 1000-1999"; VIOLATIONS=$((VIOLATIONS + 1)); } ;;
        SCP-CTX)      [[ $num -ge 2000 && $num -le 2999 ]] || { echo "VIOLATION: $file:$line_num: $code — CTX range is 2000-2999"; VIOLATIONS=$((VIOLATIONS + 1)); } ;;
        SCP-PERM)     [[ $num -ge 3000 && $num -le 3999 ]] || { echo "VIOLATION: $file:$line_num: $code — PERM range is 3000-3999"; VIOLATIONS=$((VIOLATIONS + 1)); } ;;
        SCP-CRYPTO)   [[ $num -ge 4000 && $num -le 4999 ]] || { echo "VIOLATION: $file:$line_num: $code — CRYPTO range is 4000-4999"; VIOLATIONS=$((VIOLATIONS + 1)); } ;;
        SCP-TRANS)    [[ $num -ge 5000 && $num -le 5999 ]] || { echo "VIOLATION: $file:$line_num: $code — TRANS range is 5000-5999"; VIOLATIONS=$((VIOLATIONS + 1)); } ;;
        SCP-OUTLET)   [[ $num -ge 6000 && $num -le 6999 ]] || { echo "VIOLATION: $file:$line_num: $code — OUTLET range is 6000-6999"; VIOLATIONS=$((VIOLATIONS + 1)); } ;;
        SCP-VALID)    [[ $num -ge 7000 && $num -le 7999 ]] || { echo "VIOLATION: $file:$line_num: $code — VALID range is 7000-7999"; VIOLATIONS=$((VIOLATIONS + 1)); } ;;
        SCP-STORAGE)  [[ $num -ge 8000 && $num -le 8999 ]] || { echo "VIOLATION: $file:$line_num: $code — STORAGE range is 8000-8999"; VIOLATIONS=$((VIOLATIONS + 1)); } ;;
        SCP-ATTEST)   [[ $num -ge 9000 && $num -le 9999 ]] || { echo "VIOLATION: $file:$line_num: $code — ATTEST range is 9000-9999"; VIOLATIONS=$((VIOLATIONS + 1)); } ;;
        SCP-MCP)      [[ $num -ge 10000 && $num -le 10999 ]] || { echo "VIOLATION: $file:$line_num: $code — MCP range is 10000-10999"; VIOLATIONS=$((VIOLATIONS + 1)); } ;;
        SCP-GOV)
            if [[ $num -ge 1000 ]]; then
                [[ $num -ge 11000 && $num -le 11999 ]] || { echo "VIOLATION: $file:$line_num: $code — GOV range is 11000-11999"; VIOLATIONS=$((VIOLATIONS + 1)); }
            fi
            ;;
        SCP-ECON)
            if [[ $num -ge 1000 ]]; then
                [[ $num -ge 12000 && $num -le 12999 ]] || { echo "VIOLATION: $file:$line_num: $code — ECON range is 12000-12999"; VIOLATIONS=$((VIOLATIONS + 1)); }
            fi
            ;;
        SCP-SAGA)
            if [[ $num -ge 1000 ]]; then
                [[ $num -ge 13000 && $num -le 13999 ]] || { echo "VIOLATION: $file:$line_num: $code — SAGA range is 13000-13999"; VIOLATIONS=$((VIOLATIONS + 1)); }
            fi
            ;;
        # SCP-CAPSEL is NOT an emitted error code. It is the capability-selection
        # *classification* taxonomy defined in .docs/specs/17-persistence-and-storage.md
        # §17.17.1/§17.17.2 (the exact defined set is 8000, 8001, 8002, 8010, 8011,
        # 8012, 8013). It is cited in source comments/rustdoc for provenance
        # (ADR-062 capability-injection work) and is deliberately absent from the
        # error-code registry (error_codes.rs, sdk-common.md; see the "ID note" at
        # §17.17.2). We validate it for range — a genuinely malformed CAPSEL code is
        # still caught — but do NOT treat it as a mis-prefixed error code.
        SCP-CAPSEL)   [[ $num -ge 8000 && $num -le 8099 ]] || { echo "VIOLATION: $file:$line_num: $code — CAPSEL classification range is 8000-8099 (§17.17.2)"; VIOLATIONS=$((VIOLATIONS + 1)); } ;;
        SCP-UNKNOWN)  ;; # Sentinel for unmapped bridge errors — allowed
        SCP-TEST)     ;; # Test sentinel — allowed
        *)
            # PRD story IDs (e.g. SCP-AB-016, SCP-PERSIST-062) use numbers
            # < 1000. Error codes start at 1000+. Skip story references.
            if [[ $num -ge 1000 ]]; then
                echo "VIOLATION: $file:$line_num: $code — non-canonical prefix '$prefix'"
                VIOLATIONS=$((VIOLATIONS + 1))
            fi
            ;;
    esac
}

cd "$REPO_ROOT"

# Scan source files for SCP error code literals.
# Matches patterns like "SCP-IDENT-1001", 'SCP-CTX-2001', `SCP-PERM-3001`
# Excludes: .git, target, build, node_modules, .docs (specs/ADRs use codes in prose),
#           sdk-common.md (the definition file itself), this script, CLAUDE.md files.
while IFS=: read -r file line_num content; do
    # Honour the inline `SCP-CODE-OK:` exemption marker. This is the only
    # mechanism by which a production-source line can carry a literal
    # canonical-prefix code that is deliberately out-of-range or
    # non-canonical: negative-test fixtures that verify the rejection path,
    # and validator self-references where the prefix appears in a
    # `starts_with` / `b"..."` byte comparison rather than as an emitted
    # code. Marker must appear on the same line; whole-file exemption is
    # intentionally not supported. Real error codes carry no marker, so this
    # cannot be used to smuggle a genuinely mis-ranged code past the gate.
    case "$content" in
        *"SCP-CODE-OK:"*) continue ;;
    esac

    # Extract all SCP codes from the line
    while [[ "$content" =~ SCP-([A-Z]+)-([0-9]+) ]]; do
        full_code="SCP-${BASH_REMATCH[1]}-${BASH_REMATCH[2]}"
        check_code "$file" "$line_num" "$full_code"
        # Remove the matched code and continue scanning the line
        content="${content#*"$full_code"}"
    done
done < <(
    grep -rnE 'SCP-[A-Z]+-[0-9]+' \
        --include='*.rs' \
        --include='*.kt' \
        --include='*.swift' \
        --include='*.py' \
        --include='*.ts' \
        --include='*.js' \
        --exclude-dir='.git' \
        --exclude-dir='.claude' \
        --exclude-dir='.docs' \
        --exclude-dir='target' \
        --exclude-dir='build' \
        --exclude-dir='node_modules' \
        --exclude='check-error-codes.sh' \
        --exclude='sdk-common.md' \
        --exclude='CLAUDE.md' \
        . 2>/dev/null || true
)

echo ""
echo "Checked $CHECKED error code occurrences."

# ---------------------------------------------------------------------------
# Phase 2: Cross-bridge error code uniqueness.
#
# Scans the 4 FFI bridge source directories for error code definitions and
# detects when the same code is used with different error messages, indicating
# a semantic collision.
#
# Only scans non-test production code. Lines containing "message:" or
# "JsError::new" with a quoted string are considered error definitions.
# Test files, assertions, and comment-only lines are excluded.
#
# Same code for same purpose across bridges is fine (e.g. SCP-VALID-7120 =
# "lock poisoned" in all 3 bridges). Different messages for the same code
# signals a collision.
# ---------------------------------------------------------------------------

COLLISION_TMPDIR=$(mktemp -d)
trap 'rm -rf "$COLLISION_TMPDIR"' EXIT

COLLISION_COUNT=0

# Scan only production FFI bridge source files (not tests).
while IFS=: read -r file line_num content; do
    # Skip test files entirely.
    # Path patterns:
    #   - `*/tests/*` covers `crates/.../tests/`, `bindings/python/tests/`, etc.
    #   - `*/src/test/*` covers Kotlin/Gradle layout
    #     (`bindings/kotlin/scp-kt/src/test/kotlin/...`).
    #   - `*Test.kt`, `*Tests.swift` cover JUnit / XCTest naming convention.
    # File suffixes: `_test.rs`, `_test.ts`, `_test.py`, `.test.ts`, `.test.js`.
    case "$file" in
        */tests/*|*/src/test/*|*Test.kt|*Tests.swift|*_test.rs|*_test.ts|*_test.py|*.test.ts|*.test.js) continue ;;
    esac

    # Skip lines inside #[cfg(test)] modules (Rust inline tests).
    # Heuristic: if the line contains assert/test macros, skip it.
    case "$content" in
        *assert_eq*|*assert!*|*assert_ne*|*matches!*|*"#[test]"*|*"#[cfg(test)]"*) continue ;;
    esac

    # Skip comment-only lines.
    trimmed="${content#"${content%%[![:space:]]*}"}"
    case "$trimmed" in
        "//"*|"///"*|"#"*|"*"*) continue ;;
    esac

    # Only process lines that define an error (contain message/Error patterns).
    #
    # KNOWN LIMITATION: the matcher is Rust-shaped. SDK-wrapper literals
    # in Python/TS/Swift/Kotlin that construct typed errors with ad-hoc
    # `SCP-...` strings (e.g., `raise IdentityError(msg, "SCP-IDENT-1050")`)
    # are NOT inspected by this Phase-2 detector. The current fingerprint
    # comparator cannot reliably distinguish "same purpose, different
    # syntax" (TS `throw new ValidationError(...)` vs Swift
    # `ScpError.Validation(msg:...)`) from "different purpose, same code".
    # SDK literals must be reviewed manually against `error_codes.rs`
    # to prevent collisions.
    case "$content" in
        *message:*|*message*format*|*JsError::new*|*Error*message*) ;;
        *) continue ;;
    esac

    while [[ "$content" =~ SCP-(IDENT|CTX|PERM|CRYPTO|TRANS|OUTLET|VALID|STORAGE|ATTEST|MCP|GOV|ECON|SAGA)-([0-9]+) ]]; do
        prefix="${BASH_REMATCH[1]}"
        number="${BASH_REMATCH[2]}"
        full_code="SCP-${prefix}-${number}"

        # Extract and normalize the error message from the line.
        msg=$(echo "$content" \
            | sed -E 's/'"$full_code"'//g' \
            | sed -E 's/\{[^}]*\}//g' \
            | sed -E 's/format!\(//g' \
            | sed -E 's/ScpError::[A-Za-z]+//g' \
            | sed -E 's/ScpPyError::[A-Za-z]+//g' \
            | sed -E 's/ScpNapiError::[A-Za-z]+//g' \
            | sed -E 's/JsError::new//g' \
            | sed -E 's/\.to_owned\(\)//g' \
            | sed -E 's/[^a-zA-Z ]/ /g' \
            | tr '[:upper:]' '[:lower:]' \
            | sed -E 's/  +/ /g' \
            | sed -E 's/^ +| +$//g')

        # Keep first 5 words as fingerprint.
        msg=$(echo "$msg" | awk '{for(i=1;i<=5&&i<=NF;i++) printf "%s ", $i}' | sed 's/ *$//')

        # Skip if too short to be meaningful.
        word_count=$(echo "$msg" | wc -w | tr -d ' ')
        if [[ "$word_count" -lt 3 ]]; then
            content="${content#*"$full_code"}"
            continue
        fi

        safe_code=$(echo "$full_code" | tr '-' '_')
        code_file="$COLLISION_TMPDIR/$safe_code"

        if [[ -f "$code_file" ]]; then
            existing=$(head -1 "$code_file")
            existing_loc=$(sed -n '2p' "$code_file")
            if [[ "$msg" != "$existing" ]]; then
                # Verify low word overlap — same semantic purpose may
                # have minor wording differences across bridges.
                overlap=0
                total=0
                for word in $msg; do
                    total=$((total + 1))
                    case " $existing " in
                        *" $word "*) overlap=$((overlap + 1)) ;;
                    esac
                done
                # Flag only when <50% word overlap.
                if [[ $total -gt 0 && $((overlap * 2)) -lt $total ]]; then
                    echo "COLLISION: $full_code used for different purposes:"
                    echo "  First seen: $existing_loc"
                    echo "    meaning: $existing"
                    echo "  Also seen: $file:$line_num"
                    echo "    meaning: $msg"
                    COLLISION_COUNT=$((COLLISION_COUNT + 1))
                fi
            fi
        else
            printf '%s\n%s\n' "$msg" "$file:$line_num" > "$code_file"
        fi

        content="${content#*"$full_code"}"
    done
done < <(
    grep -rnE 'SCP-(IDENT|CTX|PERM|CRYPTO|TRANS|OUTLET|VALID|STORAGE|ATTEST|MCP|GOV|ECON|SAGA)-[0-9]+' \
        --include='*.rs' \
        --include='*.kt' \
        --include='*.swift' \
        --include='*.py' \
        --include='*.ts' \
        --include='*.js' \
        --exclude-dir='.git' \
        --exclude-dir='.claude' \
        --exclude-dir='.docs' \
        --exclude-dir='target' \
        --exclude-dir='build' \
        --exclude-dir='node_modules' \
        --exclude='check-error-codes.sh' \
        --exclude='sdk-common.md' \
        --exclude='CLAUDE.md' \
        . 2>/dev/null || true
)

if [[ $COLLISION_COUNT -gt 0 ]]; then
    VIOLATIONS=$((VIOLATIONS + COLLISION_COUNT))
    echo ""
    echo "Found $COLLISION_COUNT error code collision(s)."
    echo "Each error code number must have a single semantic meaning across all bridges."
fi

# ---------------------------------------------------------------------------
# Phase 3: Registry in-band uniqueness.
#
# The registry (error_codes.rs) is the single source of truth mapping each
# code number to one purpose (the constant's doc-comment is normative).
# Assert that every quoted "SCP-...-NNNN" literal appears exactly once in
# the registry file — a duplicate means two constants (two purposes) claim
# the same number.
# ---------------------------------------------------------------------------

REGISTRY_FILE="crates/scp-ffi/common/src/error_codes.rs"
if [[ -f "$REGISTRY_FILE" ]]; then
    REGISTRY_DUPES=$(grep -oE '"SCP-[A-Z]+-[0-9]+"' "$REGISTRY_FILE" | sort | uniq -d || true)
    if [[ -n "$REGISTRY_DUPES" ]]; then
        while IFS= read -r dup; do
            echo "VIOLATION: $REGISTRY_FILE: $dup is defined by more than one registry constant"
            VIOLATIONS=$((VIOLATIONS + 1))
        done <<< "$REGISTRY_DUPES"
        echo "Each code number must map to exactly one registry constant/purpose."
    fi
else
    echo "VIOLATION: registry file $REGISTRY_FILE not found"
    VIOLATIONS=$((VIOLATIONS + 1))
fi

# ---------------------------------------------------------------------------
# Phase 4: Outlet 6100-6199 sub-block conformance (SCP-OUT-030, spec §5.4.4).
#
# The registry crates/scp-protocol/src/context/outlets/error_codes.rs is the
# single source of truth for the compact §5.4.4 outlet-error code set (the
# `pub const CODE_* = "SCP-OUTLET-61NN"` definitions, collected in ALL_CODES).
#
# This phase is deliberately SOUND-BY-CONSTRUCTION and lexer-free. It splits
# by language:
#
#   (0) ALLOCATE — extract the allocated 6100-6199 codes from the registry's
#       `CODE_*` const definitions (the authoritative allocated set).
#
#   (1a) RUST — forbid raw literals outside the registry. Rust code MUST
#        reference the `CODE_*` constants, never a raw "SCP-OUTLET-61NN" string
#        literal. The ONLY .rs file permitted to contain such literals is the
#        registry itself. Because no raw literal exists anywhere else, a raw
#        literal in ANY other .rs file — test or not — is a violation. This
#        needs NO #[cfg(test)] / comment discrimination (no brace-counting, no
#        lexer): the rule is a trivial grep. The rare legitimate exception (a
#        code named in a block/doc/trailing comment, or a fixture that
#        genuinely needs a reserved literal) opts out with an `SCP-CODE-OK:`
#        marker on the same line.
#
#   (1b) SDK BINDINGS (Kotlin/Swift/Python/TypeScript/JS) — the language SDKs
#        legitimately RESTATE the codes as string literals (they cannot
#        reference the Rust consts), so this is a genuine cross-language drift
#        check that `cargo test` cannot provide: every restated literal MUST be
#        in the allocated set. SDK TEST files are excluded by PATH glob (never
#        by comment/brace parsing).
#
#   (3) CLASS-LIST — print the 8 OutletErrorClass variants each run for
#       operator legibility. This is a PRINTOUT ONLY. The invariant "every
#       allocated code maps to a class" is enforced soundly IN RUST — the
#       exhaustive `error_code_to_class` match plus the
#       `all_codes_lists_exactly_the_defined_code_constants` and
#       `every_allocated_code_resolves_*` unit tests in error_codes.rs — and is
#       NOT re-parsed here (re-checking a compile-time match with awk would be
#       redundant and can only rot).
#
# WHY closed-by-construction (not a denylist). The permitted set is EXACTLY the
# registry's allocated consts — a positive whitelist that grows only when a new
# `CODE_*` constant is added to the registry. Reserved codes (6111, 6134,
# 6180-6199, …) never appear as raw literals in shipped Rust, and the check
# NEVER enumerates reserved spellings, so it cannot drift into a denylist.
# ---------------------------------------------------------------------------

OUTLET_REGISTRY="crates/scp-protocol/src/context/outlets/error_codes.rs"
OUTLET_ERRORS="crates/scp-protocol/src/context/outlets/errors.rs"

if [[ ! -f "$OUTLET_REGISTRY" ]]; then
    echo "VIOLATION: outlet registry file $OUTLET_REGISTRY not found"
    VIOLATIONS=$((VIOLATIONS + 1))
elif [[ ! -f "$OUTLET_ERRORS" ]]; then
    echo "VIOLATION: outlet errors file $OUTLET_ERRORS not found"
    VIOLATIONS=$((VIOLATIONS + 1))
else
    echo ""
    echo "Phase 4: outlet 6100-6199 sub-block conformance (§5.4.4)."

    # (0) Allocated codes. The `pub const CODE_* = "SCP-OUTLET-61NN"` definitions
    #     in the registry are the authoritative allocated set.
    ALLOCATED_CODES=$(grep -oE 'pub const CODE_[A-Z_]+: &str = "SCP-OUTLET-61[0-9][0-9]"' "$OUTLET_REGISTRY" \
        | grep -oE 'SCP-OUTLET-61[0-9][0-9]' | sort -u)
    ALLOCATED_ONELINE=" $(printf '%s' "$ALLOCATED_CODES" | tr '\n' ' ') "
    allocated_count=$(printf '%s\n' "$ALLOCATED_CODES" | grep -c . || true)
    echo "  Allocated 6100-6199 codes: $allocated_count"

    # (3) Operator legibility: print the 8 OutletErrorClass variants each run.
    #     Source of truth is the enum in errors.rs. This is a PRINTOUT ONLY —
    #     the "every allocated code maps to a class" invariant is enforced in
    #     Rust (error_codes.rs: exhaustive `error_code_to_class` match +
    #     `all_codes_lists_exactly_the_defined_code_constants` +
    #     `every_allocated_code_resolves_*` tests), never re-parsed here.
    OUTLET_CLASSES=$(awk '
        /pub enum OutletErrorClass \{/ { f=1; next }
        f && /^\}/                     { f=0 }
        f && /^[[:space:]]+[A-Z][A-Za-z0-9]+,[[:space:]]*$/ {
            name=$1; sub(/,.*/,"",name); print name
        }' "$OUTLET_ERRORS")
    echo "  OutletErrorClass variants (§5.4.4):"
    for cls in $OUTLET_CLASSES; do
        echo "    - $cls"
    done

    # (1a) RUST: no raw outlet-code literal outside the registry. Rust MUST
    #      reference the `CODE_*` constants. The registry file itself is the sole
    #      exception (it defines the consts; its #[cfg(test)] module exercises
    #      reserved ranges). A raw double-quoted literal in any other .rs file —
    #      test or not — is a violation, so no #[cfg(test)]/comment parsing is
    #      needed. `SCP-CODE-OK:` on the line opts out a rare legitimate case.
    while IFS=: read -r f ln content; do
        # Exclude the registry file itself — the sole .rs allowed to hold raw
        # sub-block literals. Anchor on the PARSED PATH FIELD ($f), not a
        # `grep -v` over the whole `path:lineno:content` line (which a raw
        # literal on a line whose *content* mentions the registry path could
        # otherwise slip past). Exact-path compare — NOT a basename --exclude —
        # because crates/scp-ffi/common/src/error_codes.rs is a DIFFERENT
        # error_codes.rs that must still be scanned.
        case "$f" in ./"$OUTLET_REGISTRY"|"$OUTLET_REGISTRY") continue ;; esac
        case "$content" in *"SCP-CODE-OK:"*) continue ;; esac
        code=$(printf '%s' "$content" | grep -oE 'SCP-OUTLET-61[0-9][0-9]' | head -1)
        echo "VIOLATION: $f:$ln: raw outlet-code literal \"$code\" in Rust outside the registry —"
        echo "    reference the CODE_* constant from $OUTLET_REGISTRY instead"
        echo "    (or add an SCP-CODE-OK: marker if this is a comment / reserved-range fixture)."
        VIOLATIONS=$((VIOLATIONS + 1))
    done < <(
        grep -rnE '"SCP-OUTLET-61[0-9][0-9]"' \
            --include='*.rs' \
            --exclude-dir='.git' \
            --exclude-dir='.claude' \
            --exclude-dir='target' \
            . 2>/dev/null || true
    )

    # (1b) SDK bindings (Kotlin/Swift/Python/TypeScript/JS): the SDKs restate the
    #      codes as string literals (they cannot reference the Rust consts), so
    #      every restated literal MUST be in the allocated set — a genuine
    #      cross-language drift check. TEST files are excluded by PATH glob only.
    #      `SCP-CODE-OK:` opts out a line (e.g. a negative-test fixture).
    #
    #      Matches BOTH double- and single-quoted literals (Python/JS/TS allow
    #      single quotes) so the gate does not depend on ruff/biome quote
    #      normalization. Explicit quote-matched alternation — not a `["']…["']`
    #      character class — so a mismatched-quote string cannot over-match.
    while IFS=: read -r f ln content; do
        case "$f" in
            */tests/*|*/Tests/*|*/test/*|*Test.kt|*Tests.swift|test_*.py|*_test.py|*.test.ts|*.test.js|*.spec.ts) continue ;;
        esac
        case "$content" in *"SCP-CODE-OK:"*) continue ;; esac
        for code in $(printf '%s' "$content" | grep -oE 'SCP-OUTLET-61[0-9][0-9]'); do
            case "$ALLOCATED_ONELINE" in
                *" $code "*) : ;;  # allocated — ok
                *)
                    echo "VIOLATION: $f:$ln: SDK outlet-code literal $code is not allocated in $OUTLET_REGISTRY (§5.4.4 6100-6199 sub-block)"
                    VIOLATIONS=$((VIOLATIONS + 1))
                    ;;
            esac
        done
    done < <(
        grep -rnE '("SCP-OUTLET-61[0-9][0-9]"|'\''SCP-OUTLET-61[0-9][0-9]'\'')' \
            --include='*.kt' \
            --include='*.swift' \
            --include='*.py' \
            --include='*.ts' \
            --include='*.js' \
            --exclude-dir='.git' \
            --exclude-dir='.claude' \
            --exclude-dir='node_modules' \
            --exclude-dir='build' \
            --exclude-dir='target' \
            . 2>/dev/null || true
    )
fi

if [[ $VIOLATIONS -gt 0 ]]; then
    echo "FAILED: $VIOLATIONS violation(s) found."
    echo "See .docs/standards/sdk-common.md for canonical prefixes and ranges."
    exit 1
else
    echo "PASSED: All error codes conform to sdk-common.md ranges."
    exit 0
fi
