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
# Scope of this check — the canonical `pub use` shim spellings only. It matches
# `pub use [::]scp_{clock,crypto,did,mls}` in whole-crate, path (`::Item`), and
# `as`-rename forms, over EVERY `src/` tree under `crates/` (including nested
# workspace members like `crates/scp-ffi/{common,napi,uniffi}/src/`). It is a
# positive, closed check over exactly the four moved/dissolved capability crates
# — NOT an open-ended denylist chasing spellings.
#
# Deliberately OUT of scope (audit-policed, not gated): exotic laundering such
# as `pub type` aliases, Cargo `package = ` rename tricks, and multi-hop alias
# chains. These are not chased here because doing so is a non-convergent
# denylist, and because the load-bearing invariants do not depend on this gate:
# acyclicity is enforced by `rustc` (a crate cycle does not compile), the wasm
# fence by the `wasm32-unknown-unknown` compile job, and the banned-dependency
# rules by `scripts/check-protocol-deps.sh`. This gate catches the obvious,
# common shim spellings early; it is defense-in-depth, not the guarantee.
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

# Scan EVERY `src/` tree under crates/, including nested workspace members
# (e.g. crates/scp-ffi/{common,napi,uniffi}/src/) that a single-level
# `crates/*/src/` glob would miss. Populated portably (no `mapfile`, so this
# runs under the macOS system bash 3.2 as well as CI's bash 4+).
src_dirs=()
while IFS= read -r d; do
    src_dirs+=("$d")
done < <(find crates -type d -name src | sort)

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
        # Match the canonical `pub use` spellings: optional leading `::`, then
        # the crate name at a word boundary so whole-crate (`pub use scp_x;`),
        # `as`-rename (`pub use scp_x as y;`), and path (`pub use scp_x::Item;`)
        # forms are all caught.
    done < <(grep -rEn "pub[[:space:]]+use[[:space:]]+(::)?${mod}\b" "${src_dirs[@]}" --include='*.rs' 2>/dev/null || true)
done

if [ "$violations" -ne 0 ]; then
    echo ""
    echo "ERROR: found $violations forbidden shim re-export(s) of moved/dissolved capability crates."
    exit 1
fi

echo "no-shim-reexports check passed: no forbidden \`pub use\` shims of scp_clock/scp_crypto/scp_did/scp_mls."
