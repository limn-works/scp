#!/usr/bin/env bash
# Enforce the ADR-057 Amendment "No back-compat / shim re-exports" rule.
#
# The Amendment (dissolve scp-primitives; extract scp-did) forbids re-exporting
# a moved or dissolved capability crate as a shim standing in for a real import
# update. Every consumer must import the owning crate directly
# (`use scp_clock::Clock`, `use scp_crypto::verify_ed25519_signature`,
# `use scp_did::DID`, `use scp_mls::…`). The ONLY sanctioned aggregation surface
# is the `scp-core` facade.
#
# This is a positive, closed check over exactly the four capability crates the
# Amendment moved/dissolved — NOT an open-ended denylist. A `pub use scp_x::` of
# one of these crates, anywhere outside (i) the owning crate itself or (ii) the
# `scp-core` facade, is a shim and fails CI.
set -euo pipefail

echo "Checking for forbidden shim re-exports (ADR-057 Amendment)..."

# Closed set of moved/dissolved capability crates whose re-export is a shim.
crates=(scp_clock scp_crypto scp_did scp_mls)

# Rust module name -> owning source directory (self re-exports are allowed).
owning_dir() {
    case "$1" in
        scp_clock)  echo "crates/scp-clock/src/" ;;
        scp_crypto) echo "crates/scp-crypto/src/" ;;
        scp_did)    echo "crates/scp-did/src/" ;;
        scp_mls)    echo "crates/scp-mls/src/" ;;
    esac
}

# The one sanctioned aggregation surface (the SDK-facing façade).
facade="crates/scp-core/src/"

violations=0

for mod in "${crates[@]}"; do
    own="$(owning_dir "$mod")"
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        file="${line%%:*}"
        # Allowed only in the owning crate and the scp-core facade.
        case "$file" in
            "$own"*|"$facade"*) continue ;;
        esac
        echo "VIOLATION: $line"
        echo "    -> shim re-export of \`$mod\`: import \`$mod\` directly at each"
        echo "       call site, or aggregate ONLY via the scp-core facade"
        echo "       (ADR-057 Amendment: no back-compat / shim re-exports)."
        violations=$((violations + 1))
    done < <(grep -rEn "pub[[:space:]]+use[[:space:]]+${mod}::" crates/*/src/ --include='*.rs' 2>/dev/null || true)
done

if [ "$violations" -ne 0 ]; then
    echo ""
    echo "ERROR: found $violations forbidden shim re-export(s) of moved/dissolved capability crates."
    exit 1
fi

echo "no-shim-reexports check passed: no forbidden \`pub use\` shims of scp_clock/scp_crypto/scp_did/scp_mls."
