#!/usr/bin/env bash
# check-error-codes.sh — CI gate enforcing SCP error code conformance.
#
# Phase 1: Validates every SCP error code uses a canonical prefix with a
#           number in the allocated range (sdk-common.md).
# Phase 2: Detects cross-bridge error code collisions — same code number
#           used for semantically different errors.
# Phase 3: Registry in-band uniqueness — each code literal is defined by
#           exactly one constant in error_codes.rs (one number, one purpose).
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

if [[ $VIOLATIONS -gt 0 ]]; then
    echo "FAILED: $VIOLATIONS violation(s) found."
    echo "See .docs/standards/sdk-common.md for canonical prefixes and ranges."
    exit 1
else
    echo "PASSED: All error codes conform to sdk-common.md ranges."
    exit 0
fi
