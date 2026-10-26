#!/usr/bin/env bash
# Verify scp-protocol has no async runtime dependencies in production.
set -euo pipefail

# network_crates_in LISTING prints, one per line and sorted, the network
# crates named in LISTING, a `cargo tree --prefix none --format '{p}'` listing
# whose lines read "<crate> v<version>". A name matches only whole: `h2`
# matches "h2 v0.4.0" and not "oauth2 v4.4.2", and `hyper` matches neither
# "hyperlocal v0.9.0" nor a crate whose name merely contains it.
network_crates_in() {
    echo "$1" | grep -E '^(reqwest|hyper|hyper-util|ureq|isahc|surf|h2|rustls|tokio|async-std|smol) v' | awk '{print $1}' | sort -u || true
}

# --self-test feeds network_crates_in a canned listing with two network crates
# and three names that contain a network crate's name, and requires exactly
# the two network crates back. It runs no cargo command.
if [ "${1:-}" = "--self-test" ]; then
    canned=$'sha2 v0.10.9\noauth2 v4.4.2\nh2 v0.4.0\nhyperlocal v0.9.0\nreqwest v0.12.0'
    got=$(network_crates_in "$canned")
    want=$'h2\nreqwest'
    if [ "$got" != "$want" ]; then
        echo "ERROR: network_crates_in self-test: want [$want], got [$got]"
        exit 1
    fi
    echo "network_crates_in self-test passed: matched exactly h2 and reqwest."
    exit 0
fi

echo "Checking scp-protocol dependency tree..."

# async-trait is excluded: it's a proc-macro that generates trait impls at
# compile time and does not pull in an async runtime at run time.
#
# KNOWN LIMITATION: This check catches banned CRATE dependencies but does
# NOT catch direct std::time::SystemTime usage. SystemTime compiles on
# wasm32 but returns wrong values (epoch). The Clock trait enforcement
# (privatized free functions in scp-clock) handles that case.
# The WASM compilation check also does NOT catch SystemTime for the same
# reason — it compiles, just gives wrong results. Three complementary
# checks cover the sync invariant:
#   1. This script: no banned crate deps
#   2. check-protocol-sync.py: no async fn in production code (tree-sitter)
#   3. WASM compilation: no tokio/openmls (they don't compile on wasm32)
#   4. Clock trait: SystemTime access privatized in scp-clock
#
# `--target all` resolves the UNION of every target triple's dependency edges.
# Without it cargo evaluates each `[target.'cfg(…)'.dependencies]` table against
# the triple the runner compiles for and discards every edge whose cfg is false
# there, so a `tokio` declared under `cfg(target_os = "ios")` would be absent
# from the graph this check reads and this check would report success.
# crates/scp-protocol/Cargo.toml already carries a
# `[target.'cfg(target_arch = "wasm32")'.dependencies]` table, so the construct
# that hides an edge is in use in the very crate this gate guards. The fixture
# `assert_every_cargo_tree_resolves_every_target` in
# scripts/check-shipped-feature-graph.sh asserts this flag across every shell
# script under scripts/.
banned="tokio|scp-platform|openmls"
output=$(cargo tree -p scp-protocol --edges no-dev --target all 2>&1) || { echo "ERROR: cargo tree failed: $output"; exit 1; }
matches=$(echo "$output" | grep -iE "$banned" || true)

if [ -n "$matches" ]; then
    echo "ERROR: scp-protocol has banned dependencies:"
    echo "$matches"
    exit 1
fi

echo "scp-protocol dependency check passed: no async runtime deps."

# scp-kel computes key-event preimages, digests and routing ids
# (09-security-model.md §9.7.4.2), which a native node and the wasm32 browser
# client must compute alike. It declares future-returning methods
# (`KeyEventSigner`) and runs none, and draws the custody-probe nonce from
# getrandom: no async runtime, no MLS, no platform storage, no transport, no
# runtime crate.
echo "Checking scp-kel dependency tree..."
kel_banned="tokio|async-std|smol|futures-executor|scp-platform|openmls|scp-transport|scp-runtime"
kel_output=$(cargo tree -p scp-kel --edges no-dev --target all 2>&1) || { echo "ERROR: cargo tree failed: $kel_output"; exit 1; }
kel_matches=$(echo "$kel_output" | grep -iE "$kel_banned" || true)

if [ -n "$kel_matches" ]; then
    echo "ERROR: scp-kel has banned dependencies:"
    echo "$kel_matches"
    exit 1
fi

echo "scp-kel dependency check passed: no async runtime, MLS, storage, transport or runtime crate."

# scp-platform sits in Layer 0 (.docs/architecture.md §2.5.1, Layered
# Dependency Graph): its only SCP dependencies are the Layer 0 crates
# scp-crypto, scp-did, scp-kel and scp-sqlite-pools. An edge to any other SCP
# crate would lift it above the crates that depend on it. Every feature and
# every target is resolved, so an optional or cfg-gated edge cannot hide.
echo "Checking scp-platform SCP dependencies..."
platform_allowed="scp-crypto scp-did scp-kel scp-sqlite-pools"
platform_output=$(cargo tree -p scp-platform --edges normal,build --target all --all-features --depth 1 --prefix none --format '{p}' 2>&1) || { echo "ERROR: cargo tree failed: $platform_output"; exit 1; }
platform_deps=$(echo "$platform_output" | awk '{print $1}' | grep -E '^scp-' | grep -vx 'scp-platform' | sort -u || true)
platform_extra=""
for dep in $platform_deps; do
    case " $platform_allowed " in
        *" $dep "*) ;;
        *) platform_extra="$platform_extra $dep" ;;
    esac
done

if [ -n "$platform_extra" ]; then
    echo "ERROR: scp-platform depends on SCP crates outside Layer 0:$platform_extra"
    exit 1
fi

echo "scp-platform dependency check passed: SCP deps are a subset of {$platform_allowed}."

# jsonschema_has_no_resolve_features: a challenge schema compiles with a
# retriever that fetches nothing (spec 07 §7.3.4 step 1), and jsonschema's
# `resolve-http` and `resolve-file` features add retrievers that fetch over
# the network and read the file system. Its `default` feature turns both on.
# The inverse feature tree across the whole workspace, dev edges included,
# names every jsonschema feature any crate enables; none of the three may
# appear.
jsonschema_has_no_resolve_features() {
    local tree enabled
    tree=$(cargo tree --workspace --target all -e features -i jsonschema 2>&1) || {
        echo "ERROR: cargo tree failed: $tree"
        exit 1
    }
    enabled=$(echo "$tree" | grep -E 'jsonschema feature "(resolve-http|resolve-file|default)"' | sort -u || true)
    if [ -n "$enabled" ]; then
        echo "ERROR: jsonschema builds with a resolving feature:"
        echo "$enabled"
        exit 1
    fi
    echo "jsonschema feature check passed: no resolve-http, resolve-file or default."
}
jsonschema_has_no_resolve_features

# protocol_has_no_network_crates: scp-protocol verifies device attestations
# offline from the bytes a candidate presents (spec 09 §9.3.1), and it builds
# for wasm32, so its production graph holds no HTTP client, HTTP or TLS stack,
# or async runtime. Every target's edges are resolved, so a cfg-gated edge
# cannot hide.
protocol_has_no_network_crates() {
    local listing found
    listing=$(cargo tree -p scp-protocol --edges no-dev --target all --prefix none --format '{p}' 2>&1) || {
        echo "ERROR: cargo tree failed: $listing"
        exit 1
    }
    found=$(network_crates_in "$listing")
    if [ -n "$found" ]; then
        echo "ERROR: scp-protocol depends on network crates:"
        echo "$found"
        exit 1
    fi
    echo "scp-protocol network check passed: no HTTP, TLS or async runtime crate."
}
protocol_has_no_network_crates
