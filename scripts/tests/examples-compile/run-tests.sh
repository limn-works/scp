#!/usr/bin/env bash
# Cases for scripts/check-examples-compile.sh.
#
# THE CRITERION: the gate exits 1 when an example target fails to compile or lint, when a
# published `examples/*.rs` is no example target's source, when `cargo package --list`
# fails, or when it checked no example target; and it exits 0 on a workspace with none of
# those. Each case builds a workspace in `mktemp -d` (one crate, or two where a case needs a
# dev-dependency edge between members), copies the real gate into its `scripts/`, runs it
# there with real cargo, and asserts both the exit code and the FAIL or OK line that names
# the outcome, so a case cannot pass on the wrong outcome.
#
# The last five cases pin the gate's invocation. `--all-features` or `--features testing` on
# the clippy line turns `featuregated` green. `--examples` in place of `--example NAME` skips
# a `required-features` target and exits 0, which turns `requiredfeatures` green. One
# `cargo clippy --workspace --examples` unifies `helper`'s dev-dependency features into
# `demo`, which turns `devdepunify` green. Iterating published files in place of targets
# turns `excluded` red. An unquoted `for` loop splits `spaced` at its space and turns it red.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
GATE="$ROOT/scripts/check-examples-compile.sh"
PASSED=0
FAILED=0
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export CARGO_TARGET_DIR="$WORK/target"

# new_ws NAME [EXTRA_MANIFEST_LINES]: a workspace with one package `demo` and one example `good`.
new_ws() {
    local ws="$WORK/$1"
    mkdir -p "$ws/scripts" "$ws/demo/src" "$ws/demo/examples"
    cp "$GATE" "$ws/scripts/"
    cp "$ROOT/rust-toolchain.toml" "$ws/"
    printf '[workspace]\nmembers = ["demo"]\nresolver = "2"\n' > "$ws/Cargo.toml"
    printf '[package]\nname = "demo"\nversion = "0.1.0"\nedition = "2021"\nlicense = "MIT"\ndescription = "fixture"\n%s\n' "${2:-}" > "$ws/demo/Cargo.toml"
    echo 'pub fn f() {}' > "$ws/demo/src/lib.rs"
    echo 'fn main() {}' > "$ws/demo/examples/good.rs"
    echo "$ws"
}

# expect NAME WS WANT_EXIT WANT_LINE
expect() {
    local out code=0
    out="$(bash "$2/scripts/check-examples-compile.sh" 2>&1)" || code=$?
    if [ "$code" = "$3" ] && printf '%s\n' "$out" | grep -qF -- "$4"; then
        PASSED=$((PASSED + 1)); echo "ok   $1"
    else
        FAILED=$((FAILED + 1)); echo "FAIL $1: exit $code, want $3 with '$4'"; printf '%s\n' "$out" | tail -15
    fi
}

ws="$(new_ws clean)"
expect "clean workspace passes" "$ws" 0 "OK: 1 example target(s) compile"

ws="$(new_ws broken)"
echo 'fn main() { undefined_fn(); }' > "$ws/demo/examples/good.rs"
expect "example that does not compile" "$ws" 1 "FAIL: demo example 'good' does not compile."

ws="$(new_ws lint)"
echo 'fn main() { let unused = 1; }' > "$ws/demo/examples/good.rs"
expect "example with a warning" "$ws" 1 "FAIL: demo example 'good' does not compile."

ws="$(new_ws orphan $'autoexamples = false\n[[example]]\nname = "good"\npath = "examples/good.rs"')"
echo 'fn main() {}' > "$ws/demo/examples/orphan.rs"
expect "autoexamples = false orphan" "$ws" 1 "FAIL: demo publishes 'examples/orphan.rs'"

ws="$(new_ws decoy $'[[example]]\nname = "good"\npath = "examples/decoy/good.rs"')"
mkdir -p "$ws/demo/examples/decoy"
echo 'fn main() {}' > "$ws/demo/examples/decoy/good.rs"
expect "same-name target redirected to a decoy" "$ws" 1 "FAIL: demo publishes 'examples/good.rs'"

ws="$(new_ws nested)"
mkdir -p "$ws/demo/examples/site"
echo 'fn main() {}' > "$ws/demo/examples/site/main.rs"
printf 'autoexamples = false\n[[example]]\nname = "good"\npath = "examples/good.rs"\n' >> "$ws/demo/Cargo.toml"
expect "orphan in the examples/NAME/main.rs layout" "$ws" 1 "FAIL: demo publishes 'examples/site/main.rs'"

ws="$(new_ws badmanifest 'readme = "MISSING.md"')"
expect "cargo package --list failure" "$ws" 1 "FAIL: 'cargo package --list -p demo' failed"

# The same manifest error on a crate with no example target: `autoexamples = false` hides
# `examples/good.rs` from cargo, so a gate that reported the failure only for a package
# with targets would print no package line here, and this case would go red.
ws="$(new_ws badmanifestnotargets $'readme = "MISSING.md"\nautoexamples = false')"
expect "cargo package --list failure on a crate with no example target" "$ws" 1 "FAIL: 'cargo package --list -p demo' failed"

ws="$(new_ws empty)"
rm -r "$ws/demo/examples"
expect "no example target" "$ws" 1 "FAIL: no example target was checked"

ws="$(new_ws featuregated $'[features]\ntesting = []')"
printf 'pub fn f() {}\n#[cfg(feature = "testing")]\npub fn t() {}\n' > "$ws/demo/src/lib.rs"
echo 'fn main() { demo::t(); }' > "$ws/demo/examples/good.rs"
expect "example naming an item behind a non-default feature" "$ws" 1 "FAIL: demo example 'good' does not compile."

ws="$(new_ws requiredfeatures $'[features]\nx = []\n[[example]]\nname = "good"\nrequired-features = ["x"]')"
expect "example whose required-features are off" "$ws" 1 "FAIL: demo example 'good' does not compile."

ws="$(new_ws devdepunify $'[features]\ntesting = []')"
printf 'pub fn f() {}\n#[cfg(feature = "testing")]\npub fn t() {}\n' > "$ws/demo/src/lib.rs"
echo 'fn main() { demo::t(); }' > "$ws/demo/examples/good.rs"
printf '[workspace]\nmembers = ["demo", "helper"]\nresolver = "2"\n' > "$ws/Cargo.toml"
mkdir -p "$ws/helper/src" "$ws/helper/examples"
printf '[package]\nname = "helper"\nversion = "0.1.0"\nedition = "2021"\nlicense = "MIT"\ndescription = "fixture"\n[dev-dependencies]\ndemo = { path = "../demo", features = ["testing"] }\n' > "$ws/helper/Cargo.toml"
echo 'pub fn g() {}' > "$ws/helper/src/lib.rs"
echo 'fn main() { demo::t(); }' > "$ws/helper/examples/h.rs"
expect "feature only another member's dev-dependency turns on" "$ws" 1 "FAIL: demo example 'good' does not compile."

ws="$(new_ws excluded 'exclude = ["examples/*"]')"
expect "target whose file is excluded from publication" "$ws" 0 "OK: 1 example target(s) compile"

ws="$(new_ws spaced $'[[example]]\nname = "spaced"\npath = "examples/has space.rs"')"
echo 'fn main() {}' > "$ws/demo/examples/has space.rs"
expect "example file whose name contains a space" "$ws" 0 "OK: 2 example target(s) compile"

echo "$PASSED passed, $FAILED failed"
[ "$FAILED" -eq 0 ]
