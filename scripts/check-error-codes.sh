#!/usr/bin/env bash
# check-error-codes.sh — CI gate enforcing SCP error code conformance.
#
# Phase 1: Validates every SCP error code uses a canonical prefix with a
#           number in the allocated range (sdk-common.md).
# Phase 2: Detects cross-bridge error code collisions — same code number
#           used for semantically different errors.
# Phase 3: Validates the SCP-TOOL-6100..6199 outlet sub-block against the
#           registry at `crates/scp-protocol/src/context/outlets/error_codes.rs`
#           per spec §5.4.4 / ADR-049 §1 / SCP-OUT-030. Also asserts every
#           registered code has a class wired into `error_code_to_class` and
#           that all 8 `OutletErrorClass` variant literals are present in
#           the registry file.
#
# Canonical prefixes and ranges:
#   SCP-IDENT-   1000-1999    SCP-CTX-     2000-2999
#   SCP-PERM-    3000-3999    SCP-CRYPTO-  4000-4999
#   SCP-TRANS-   5000-5999    SCP-TOOL-    6000-6999
#   SCP-VALID-   7000-7999    SCP-STORAGE- 8000-8999
#   SCP-ATTEST-  9000-9999    SCP-MCP-     10000-10999
#
# Dedicated subranges:
#   SCP-GOV-     11000-11999
#   SCP-ECON-    12000-12999
#
# Outlet sub-block (Phase 3):
#   SCP-TOOL-6100..6199    Outlet error taxonomy per spec §5.4.4
#                          Registry: crates/scp-protocol/src/context/outlets/error_codes.rs
#                          Classes: Protocol, Authorization, Input, Execution,
#                                   Output, Economic, Transport, Governance
#
# Exit 0 on success, 1 on any violation.
# Usage: ./scripts/check-error-codes.sh
#
# Inline exemption marker:
#   `SCP-CODE-OK: <reason>` — when present on a line, the line is skipped by
#   Phase 1 range/prefix validation AND by Phase 3 sub-block validation. Use
#   sparingly. Legitimate cases:
#     - Validator self-references where the canonical prefix appears in a
#       `starts_with` / `b"..."` byte comparison rather than as an actual
#       error code emission.
#     - Registry constant declarations (`pub const CODE_*: &str = "SCP-TOOL-NNNN"`)
#       in error_codes.rs — the literal IS the registration, not an emission.
#     - Reserved-range / reserved-gap test fixtures asserting `error_code_to_class`
#       returns `None` for unallocated codes.
#     - Legacy production emission paths flagged for migration to the typed
#       `OutletError` envelope under SCP-OUT-027 (lossy `PermissionDenied`
#       string fallback). Marker MUST cite SCP-OUT-027 so the next pass
#       removes both the marker and the legacy emission.
#   Mirrors the `SCP-DEFAULT-INSTANCE-OK` pattern from
#   `check-no-default-in-tests.sh`.

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
        SCP-TOOL)     [[ $num -ge 6000 && $num -le 6999 ]] || { echo "VIOLATION: $file:$line_num: $code — TOOL range is 6000-6999"; VIOLATIONS=$((VIOLATIONS + 1)); } ;;
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
    # Phase 1 mirrors Phase 2's test-file skip — test fixtures legitimately
    # contain out-of-range codes to verify rejection logic, and module-level
    # `#[cfg(test)]` blocks contain the same kinds of intentionally-wrong
    # codes. Without this skip, contributors would be tempted to game the
    # greedy `SCP-[A-Z]+-[0-9]+` regex via `concat!` / split string tricks.
    case "$file" in
        */tests/*|*/Tests/*|*_test.rs|*_test.ts|*_test.py|*.test.ts|*.test.js|*Tests.swift|*Test.kt) continue ;;
    esac

    # Honour the inline `SCP-CODE-OK:` exemption marker. This is the only
    # mechanism by which a production-source line can carry a literal
    # canonical prefix (e.g. validator self-references). Marker must appear
    # on the same line; whole-file exemption is intentionally not supported.
    case "$content" in
        *"SCP-CODE-OK:"*) continue ;;
    esac

    # Inline-test heuristic — mirrors Phase 2 (lines 142-152). Lines that
    # carry assertion/test-attribute markers are inside `#[cfg(test)]` blocks
    # in inline-test files, where intentionally-wrong codes are legitimate.
    case "$content" in
        *assert_eq*|*assert!*|*assert_ne*|*matches!*|*"#[test]"*|*"#[cfg(test)]"*) continue ;;
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
# "lock poisoned" in all 4 bridges). Different messages for the same code
# signals a collision.
# ---------------------------------------------------------------------------

COLLISION_TMPDIR=$(mktemp -d)
trap 'rm -rf "$COLLISION_TMPDIR"' EXIT

COLLISION_COUNT=0

# Scan only production FFI bridge source files (not tests).
while IFS=: read -r file line_num content; do
    # Skip test files entirely.
    case "$file" in
        */tests/*|*/Tests/*|*_test.rs|*_test.ts|*_test.py|*.test.ts|*.test.js|*Tests.swift|*Test.kt) continue ;;
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
    case "$content" in
        *message:*|*message*format*|*JsError::new*|*Error*message*) ;;
        *) continue ;;
    esac

    while [[ "$content" =~ SCP-(IDENT|CTX|PERM|CRYPTO|TRANS|TOOL|VALID|STORAGE|ATTEST|MCP|GOV|ECON)-([0-9]+) ]]; do
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
    grep -rnE 'SCP-(IDENT|CTX|PERM|CRYPTO|TRANS|TOOL|VALID|STORAGE|ATTEST|MCP|GOV|ECON)-[0-9]+' \
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
# Phase 3: Outlet sub-block (SCP-TOOL-6100..6199) registry conformance.
#
# Per spec §5.4.4 / ADR-049 §1 / SCP-OUT-030:
#
#   1. Read the registry at
#      `crates/scp-protocol/src/context/outlets/error_codes.rs` and extract
#      every allocated code from the `pub const CODE_<NAME>: &str =
#      "SCP-TOOL-61NN";` declarations.
#
#   2. Verify each registered code is wired into the `error_code_to_class`
#      match arms (i.e., the code constant appears in a match arm whose RHS
#      contains an `OutletErrorClass::<Variant>` literal). Catches the
#      defining-without-wiring footgun.
#
#   3. Verify all 8 `OutletErrorClass` variant literals (Protocol,
#      Authorization, Input, Execution, Output, Economic, Transport,
#      Governance) appear in the registry file. Catches drift if a variant
#      gets renamed or removed without updating the registry's match arms.
#
#   4. Walk the tree for any `SCP-TOOL-61NN` literal not in the allocated
#      set. Same skip rules as Phase 1: test files, `SCP-CODE-OK:` marker,
#      inline-test heuristic. Plus comment-only line skip mirrored from
#      Phase 2.
#
# Outputs the full class roster on every run for human auditing.
# ---------------------------------------------------------------------------

REGISTRY_FILE="crates/scp-protocol/src/context/outlets/error_codes.rs"

OUTLET_CLASSES=(
    Protocol
    Authorization
    Input
    Execution
    Output
    Economic
    Transport
    Governance
)

echo ""
echo "Phase 3: Outlet sub-block (SCP-TOOL-6100..6199) registry conformance."
echo "  Registry: $REGISTRY_FILE"
echo "  OutletErrorClass variants:"
for class in "${OUTLET_CLASSES[@]}"; do
    echo "    - OutletErrorClass::$class"
done

if [[ ! -f "$REGISTRY_FILE" ]]; then
    echo "VIOLATION: registry file $REGISTRY_FILE not found."
    VIOLATIONS=$((VIOLATIONS + 1))
fi

PHASE3_VIOLATIONS=0

if [[ -f "$REGISTRY_FILE" ]]; then
    # Step 1: Parse `pub const CODE_<NAME>: &str = "SCP-TOOL-61NN";` declarations.
    # Build parallel arrays: allocated_codes[i] / allocated_consts[i].
    allocated_codes=()
    allocated_consts=()
    while IFS=$'\t' read -r const_name code; do
        [[ -z "$const_name" ]] && continue
        allocated_consts+=("$const_name")
        allocated_codes+=("$code")
    done < <(
        grep -nE 'pub const CODE_[A-Z_]+:[[:space:]]*&str[[:space:]]*=[[:space:]]*"SCP-TOOL-61[0-9]{2}"' "$REGISTRY_FILE" \
            | sed -E 's/^[0-9]+:[[:space:]]*pub const (CODE_[A-Z_]+):[[:space:]]*&str[[:space:]]*=[[:space:]]*"(SCP-TOOL-61[0-9]{2})".*$/\1\t\2/'
    )

    if [[ ${#allocated_codes[@]} -eq 0 ]]; then
        echo "VIOLATION: registry $REGISTRY_FILE declares zero SCP-TOOL-61NN codes (regex: pub const CODE_<NAME>: &str = \"SCP-TOOL-61NN\")."
        PHASE3_VIOLATIONS=$((PHASE3_VIOLATIONS + 1))
    else
        echo ""
        echo "  Allocated codes (${#allocated_codes[@]}):"
        for i in "${!allocated_codes[@]}"; do
            echo "    ${allocated_codes[$i]}  <-  ${allocated_consts[$i]}"
        done
    fi

    # Step 2: Each registered code must be wired into a match arm whose RHS
    # contains `OutletErrorClass::<Variant>`. Implementation: confirm the
    # const name appears in at least one match arm fragment that is part of
    # an `error_code_to_class` arm — we approximate by requiring each const
    # to appear AT LEAST 2 times in the file (once in its declaration, once
    # more — typically in `error_code_to_class` plus also `ALL_CODES`,
    # `error_code_to_default_slug`, `error_code_to_retry_policy`).
    for i in "${!allocated_consts[@]}"; do
        const_name="${allocated_consts[$i]}"
        code="${allocated_codes[$i]}"
        # Count occurrences of the bare const name (token-bounded) in the file.
        usage_count=$(grep -cE "\b${const_name}\b" "$REGISTRY_FILE")
        if [[ "$usage_count" -lt 2 ]]; then
            echo "VIOLATION: registry constant $const_name ($code) is declared but never referenced — code is not wired into error_code_to_class / ALL_CODES."
            PHASE3_VIOLATIONS=$((PHASE3_VIOLATIONS + 1))
        fi
    done

    # Step 3: Every code constant must reach a match arm rhs of the form
    # `Some(OutletErrorClass::<Variant>)` — verified structurally by extracting
    # the `error_code_to_class` function body and asserting every const name
    # appears within it. Brittle to rename of the function; the function name
    # is part of the §5.4.4 contract, so a rename should be paired with a
    # script update.
    fn_body=$(awk '
        /pub fn error_code_to_class/ { in_fn = 1 }
        in_fn { print }
        in_fn && /^}$/ { exit }
    ' "$REGISTRY_FILE")

    if [[ -z "$fn_body" ]]; then
        echo "VIOLATION: $REGISTRY_FILE does not contain a `pub fn error_code_to_class` definition (registry contract requires this lookup function)."
        PHASE3_VIOLATIONS=$((PHASE3_VIOLATIONS + 1))
    else
        for i in "${!allocated_consts[@]}"; do
            const_name="${allocated_consts[$i]}"
            code="${allocated_codes[$i]}"
            if ! echo "$fn_body" | grep -qE "\b${const_name}\b"; then
                echo "VIOLATION: $code ($const_name) is declared but missing from error_code_to_class match arms — class wiring absent."
                PHASE3_VIOLATIONS=$((PHASE3_VIOLATIONS + 1))
            fi
        done
    fi

    # Step 4: All 8 OutletErrorClass variant literals must appear in the
    # registry file (proves the class enum is wired).
    for class in "${OUTLET_CLASSES[@]}"; do
        if ! grep -qE "\bOutletErrorClass::${class}\b" "$REGISTRY_FILE"; then
            echo "VIOLATION: $REGISTRY_FILE does not contain literal `OutletErrorClass::${class}` — class wiring is missing."
            PHASE3_VIOLATIONS=$((PHASE3_VIOLATIONS + 1))
        fi
    done

    # Step 5: Walk the tree for any SCP-TOOL-61NN literal not in the
    # allocated set. Skip rules mirror Phase 1 (test files, SCP-CODE-OK
    # marker, inline-test heuristic) plus Phase 2's comment-only skip.
    UNREGISTERED_HITS=0
    while IFS=: read -r file line_num content; do
        # Skip test files (same as Phase 1).
        case "$file" in
            */tests/*|*/Tests/*|*_test.rs|*_test.ts|*_test.py|*.test.ts|*.test.js|*Tests.swift|*Test.kt) continue ;;
        esac

        # Skip lines carrying the SCP-CODE-OK exemption marker.
        case "$content" in
            *"SCP-CODE-OK:"*) continue ;;
        esac

        # Skip inline-test heuristic lines (same as Phase 1).
        case "$content" in
            *assert_eq*|*assert!*|*assert_ne*|*matches!*|*"#[test]"*|*"#[cfg(test)]"*) continue ;;
        esac

        # Skip comment-only lines (mirror Phase 2).
        trimmed="${content#"${content%%[![:space:]]*}"}"
        case "$trimmed" in
            "//"*|"///"*|"//!"*|"#"*|"*"*) continue ;;
        esac

        # Skip the registry file itself — it declares constants for every
        # code, and those declarations carry SCP-CODE-OK markers already.
        # The marker check above already handles the declarations; this
        # belt-and-suspenders skip protects against a future contributor
        # forgetting the marker on a new registry constant.
        case "$file" in
            *"$REGISTRY_FILE"|"./$REGISTRY_FILE") continue ;;
        esac

        # Extract every SCP-TOOL-61NN occurrence on the line.
        remaining="$content"
        while [[ "$remaining" =~ SCP-TOOL-(61[0-9]{2}) ]]; do
            full_code="SCP-TOOL-${BASH_REMATCH[1]}"
            # Is this code in the allocated set?
            allocated=0
            for allocated_code in "${allocated_codes[@]}"; do
                if [[ "$full_code" == "$allocated_code" ]]; then
                    allocated=1
                    break
                fi
            done
            if [[ $allocated -eq 0 ]]; then
                echo "VIOLATION: $file:$line_num: $full_code is in the SCP-TOOL-6100..6199 outlet sub-block but is NOT registered in $REGISTRY_FILE."
                echo "         Either register the code in the §5.4.4 taxonomy (add a CODE_* constant + class wiring + ALL_CODES entry) or migrate the emission to use an existing CODE_* constant."
                UNREGISTERED_HITS=$((UNREGISTERED_HITS + 1))
            fi
            remaining="${remaining#*"$full_code"}"
        done
    done < <(
        grep -rnE 'SCP-TOOL-61[0-9]{2}' \
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

    if [[ $UNREGISTERED_HITS -gt 0 ]]; then
        echo "Phase 3: $UNREGISTERED_HITS unregistered SCP-TOOL-61NN occurrence(s) found."
        PHASE3_VIOLATIONS=$((PHASE3_VIOLATIONS + UNREGISTERED_HITS))
    fi
fi

if [[ $PHASE3_VIOLATIONS -gt 0 ]]; then
    VIOLATIONS=$((VIOLATIONS + PHASE3_VIOLATIONS))
    echo ""
    echo "Phase 3: $PHASE3_VIOLATIONS violation(s) in outlet sub-block conformance."
else
    echo ""
    echo "Phase 3: outlet sub-block conformant — every SCP-TOOL-61NN literal is registered and every registered code is wired to a class."
fi

if [[ $VIOLATIONS -gt 0 ]]; then
    echo "FAILED: $VIOLATIONS violation(s) found."
    echo "See .docs/standards/sdk-common.md for canonical prefixes and ranges."
    exit 1
else
    echo "PASSED: All error codes conform to sdk-common.md ranges."
    exit 0
fi
