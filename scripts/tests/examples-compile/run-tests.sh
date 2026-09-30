#!/usr/bin/env bash
# Cases for scripts/check-examples-compile.sh.
#
# THE CRITERION: the gate exits 1 when an example target fails to compile or lint, when an
# example target's source or a `.rs` file under `examples/` holds a construct the gate's
# source scan rejects, when a published `examples/*.rs` is no example target's source, when `cargo package --list`
# fails, or when it checked no example target; and it exits 0 on a workspace with none of
# those. Each case builds a workspace in `mktemp -d` (one crate, or two where a case needs a
# dev-dependency edge between members or a defect in the second package), copies the real
# gate into its `scripts/`, runs it there with real cargo, and asserts both the exit code and the FAIL or OK line that names
# the outcome, so a case cannot pass on the wrong outcome.
#
# The five cases from `featuregated` to `spaced`, `secondbroken` and `secondorphan` pin the
# gate's invocation, the cases from `cfgbody` to `platformcfg` pin its source scan, and each
# mutation below makes its case fail.
# `--all-features` or `--features testing` on the clippy line makes the gate exit 0 on
# `featuregated`, which expects exit 1. `--examples` in place of `--example NAME` skips a
# `required-features` target and makes the gate exit 0 on `requiredfeatures`, which expects
# exit 1. One `cargo clippy --workspace --examples` unifies `helper`'s dev-dependency features
# into `demo` and makes the gate exit 0 on `devdepunify`, which expects exit 1. Iterating
# published files in place of targets drops `excluded`'s only target and makes the gate exit 1
# on `excluded`, which expects exit 0. An unquoted `for` loop splits `spaced` at its space and
# makes the gate exit 1 on `spaced`, which expects exit 0. Ending the package loop after its
# first package makes the gate exit 0 on `secondbroken` and `secondorphan`, which expect exit 1.
# Dropping the source scan makes the gate exit 0 on every case from `cfgbody` to
# `hashraw`, which expect exit 1: each fixture compiles on default features. Accepting a
# platform predicate false on the host makes the gate exit 0 on `falsecfg`, accepting an
# empty `any()` does the same on `emptyany`, ending a block comment at its first `*/` does
# the same on `nestedcomment`, dropping the `include`, `#[path]`, `macro_rules` or
# `stringify` rule does the same on `include`, `pathmod`, `macrorules` or `stringify`,
dropping the U+200E and U+200F rule does the same on `lrmcfg`, `lrmcfgmacro` and `rlmpath`,
# matching `path` only directly after `[` does the same on `rawpath`, and listing `examples/` without
# following symbolic links does the same on `symlinkmod` and `symlinkdir`, matching only
# `cfg_attr` in place of every `cfg_` name does the same on `cfgselect`, dropping the
# test-name rule does the same on `testattr`, `testpath` and `testalias`, and matching only
# the attribute form `#[...test]` in place of the name does the same on `testalias`.
# The lexer cases below hold their literal in `stringify!`, so the gate exits 1 on each of
# them through the `stringify` rule too; each case also wants the feature-cfg line, and each
# mutation that follows drops that line from the output. Reading `r"` as a raw string after
# a number or a lifetime does so on `suffixnum` and `suffixlifetime`; ending a string or raw
# string at its closing quote or hash without taking its suffix does so on `suffixstring`
# and `suffixrawhash`; a char literal pattern that accepts only one-character escapes does
# so on `charhex` and `charunicode`; and refusing a raw string whose prefix follows a `#`
# token does so on `hashraw`.
# Scanning string literals or comments, rejecting a platform predicate true on the host,
# rejecting `include_str!`, rejecting a U+200E or U+200F inside a literal or comment, rejecting an identifier that merely starts with `test`,
# `bench` or `stringify`, rejecting an identifier `path` or `r#path` outside an attribute,
# refusing a raw string whose prefix follows `(` or a space, or
# matching a char literal byte by byte in place of decoding the source as UTF-8 makes the
# gate exit 1 on `platformcfg`, which expects exit 0.
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

# add_member WS NAME [EXTRA_MANIFEST_LINES]: a second package NAME with one clean example
# `ex`, listed after `demo`. NAME sorts after `demo` too, so `cargo metadata` lists it second
# whether it orders packages by member list or by name.
add_member() {
    mkdir -p "$1/$2/src" "$1/$2/examples"
    printf '[workspace]\nmembers = ["demo", "%s"]\nresolver = "2"\n' "$2" > "$1/Cargo.toml"
    printf '[package]\nname = "%s"\nversion = "0.1.0"\nedition = "2021"\nlicense = "MIT"\ndescription = "fixture"\n%s\n' "$2" "${3:-}" > "$1/$2/Cargo.toml"
    echo 'pub fn g() {}' > "$1/$2/src/lib.rs"
    echo 'fn main() {}' > "$1/$2/examples/ex.rs"
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

# Two cases put the only defect in the package `cargo metadata` lists second, so a gate
# whose package loop stops after its first iteration (a `break`, or a command in the loop
# body that drains the heredoc on stdin) exits 0 on both and turns them red.
ws="$(new_ws secondbroken)"
add_member "$ws" zeta
echo 'fn main() { undefined_fn(); }' > "$ws/zeta/examples/ex.rs"
expect "second package's example does not compile" "$ws" 1 "FAIL: zeta example 'ex' does not compile."

ws="$(new_ws secondorphan)"
add_member "$ws" zeta $'autoexamples = false\n[[example]]\nname = "ex"\npath = "examples/ex.rs"'
echo 'fn main() {}' > "$ws/zeta/examples/orphan.rs"
expect "second package publishes an orphan" "$ws" 1 "FAIL: zeta publishes 'examples/orphan.rs'"

# The dodge the cfg scan exists for: the body that names a `testing`-only item compiles only
# with the feature on, and an empty `main` stands in on default features, so the compile
# alone exits 0.
ws="$(new_ws cfgbody $'[features]\ntesting = []')"
printf 'pub fn f() {}\n#[cfg(feature = "testing")]\npub fn t() {}\n' > "$ws/demo/src/lib.rs"
printf '#[cfg(\n    feature = "testing"\n)]\nfn main() { demo::t(); }\n#[cfg(not(feature = "testing"))]\nfn main() {}\n' > "$ws/demo/examples/good.rs"
expect "example body behind a feature cfg" "$ws" 1 "FAIL: demo example 'good' holds a construct that can remove code"

ws="$(new_ws cfghelper)"
mkdir -p "$ws/demo/examples/support"
printf '#[cfg_attr(test, allow(dead_code))]\npub fn h() {}\n' > "$ws/demo/examples/support/mod.rs"
expect "helper module under examples/ with a cfg_attr predicate" "$ws" 1 "FAIL: demo 'examples/support/mod.rs' holds a construct that can remove code"

# A helper module reached through a symbolic link: rustc follows the link when it resolves
# `mod support;`, so the scan must too, whether the link is the file or its directory.
ws="$(new_ws symlinkmod $'[features]\ntesting = []')"
printf 'pub fn f() {}\n#[cfg(feature = "testing")]\npub fn t() {}\n' > "$ws/demo/src/lib.rs"
printf '#[cfg(feature = "testing")]\npub fn run() { demo::t(); }\n#[cfg(not(feature = "testing"))]\npub fn run() {}\n' > "$ws/demo/src/body.rs"
mkdir -p "$ws/demo/examples/support"
ln -s ../../src/body.rs "$ws/demo/examples/support/mod.rs"
printf 'mod support;\nfn main() { support::run(); }\n' > "$ws/demo/examples/good.rs"
expect "helper module that is a symbolic link" "$ws" 1 "FAIL: demo 'examples/support/mod.rs' holds a construct that can remove code"

ws="$(new_ws symlinkdir $'[features]\ntesting = []')"
printf 'pub fn f() {}\n#[cfg(feature = "testing")]\npub fn t() {}\n' > "$ws/demo/src/lib.rs"
mkdir -p "$ws/demo/support"
printf '#[cfg(feature = "testing")]\npub fn run() { demo::t(); }\n#[cfg(not(feature = "testing"))]\npub fn run() {}\n' > "$ws/demo/support/mod.rs"
ln -s ../support "$ws/demo/examples/support"
printf 'mod support;\nfn main() { support::run(); }\n' > "$ws/demo/examples/good.rs"
expect "helper module under a symbolically linked directory" "$ws" 1 "FAIL: demo 'examples/support/mod.rs' holds a construct that can remove code"

# The same dodge on a platform key: the body sits under a predicate false on every host
# this suite runs on (it needs a unix host, as the gate does).
ws="$(new_ws falsecfg $'[features]\ntesting = []')"
printf 'pub fn f() {}\n#[cfg(feature = "testing")]\npub fn t() {}\n' > "$ws/demo/src/lib.rs"
printf '#[cfg(not(unix))]\nfn main() { demo::t(); }\n#[cfg(unix)]\nfn main() {}\n' > "$ws/demo/examples/good.rs"
expect "example body behind a platform predicate false on the host" "$ws" 1 "      cfg(not(unix))"

ws="$(new_ws emptyany $'[features]\ntesting = []')"
printf 'pub fn f() {}\n#[cfg(feature = "testing")]\npub fn t() {}\n' > "$ws/demo/src/lib.rs"
printf '#[cfg(any())]\nfn main() { demo::t(); }\n#[cfg(not(any()))]\nfn main() {}\n' > "$ws/demo/examples/good.rs"
expect "example body behind an empty any()" "$ws" 1 "      cfg(any())"

# Block comments nest. A scanner that ends one at its first `*/` reads the rest of line 1 as
# the start of a string literal that runs to line 6, and so never sees the feature cfg.
ws="$(new_ws nestedcomment $'[features]\ntesting = []')"
printf 'pub fn f() {}\n#[cfg(feature = "testing")]\npub fn t() {}\n' > "$ws/demo/src/lib.rs"
printf '/* /* */ " */\n#[cfg(feature = "testing")]\nfn main() { demo::t(); }\n#[cfg(not(feature = "testing"))]\nfn main() {}\n// "\n' > "$ws/demo/examples/good.rs"
expect "feature cfg after a nested block comment" "$ws" 1 '      cfg(feature = "testing")'

# The next three hide the gated body in a file the scan does not open, or build the cfg
# attribute from an ident the scan does not read.
ws="$(new_ws include $'[features]\ntesting = []')"
printf 'pub fn f() {}\n#[cfg(feature = "testing")]\npub fn t() {}\n' > "$ws/demo/src/lib.rs"
printf '#[cfg(feature = "testing")]\nfn main() { demo::t(); }\n#[cfg(not(feature = "testing"))]\nfn main() {}\n' > "$ws/demo/src/body.inc"
echo 'include!("../src/body.inc");' > "$ws/demo/examples/good.rs"
expect "example that includes a file outside examples/" "$ws" 1 "      include!"

ws="$(new_ws pathmod $'[features]\ntesting = []')"
printf 'pub fn f() {}\n#[cfg(feature = "testing")]\npub fn t() {}\n' > "$ws/demo/src/lib.rs"
printf '#[cfg(feature = "testing")]\npub fn run() { demo::t(); }\n#[cfg(not(feature = "testing"))]\npub fn run() {}\n' > "$ws/demo/examples/body.inc"
printf '#[path = "body.inc"]\nmod body;\nfn main() { body::run(); }\n' > "$ws/demo/examples/good.rs"
expect "example module read through #[path]" "$ws" 1 "      #[path]"

# rustc takes `r#path` as the `path` attribute, so the module below loads `body.inc`.
ws="$(new_ws rawpath $'[features]\ntesting = []')"
printf 'pub fn f() {}\n#[cfg(feature = "testing")]\npub fn t() {}\n' > "$ws/demo/src/lib.rs"
printf '#[cfg(feature = "testing")]\npub fn run() { demo::t(); }\n#[cfg(not(feature = "testing"))]\npub fn run() {}\n' > "$ws/demo/examples/body.inc"
printf '#[r#path = "body.inc"]\nmod body;\nfn main() { body::run(); }\n' > "$ws/demo/examples/good.rs"
expect "example module read through #[r#path]" "$ws" 1 "      #[path]"

ws="$(new_ws macrorules $'[features]\ntesting = []')"
printf 'pub fn f() {}\n#[cfg(feature = "testing")]\npub fn t() {}\n' > "$ws/demo/src/lib.rs"
printf 'macro_rules! gate {\n    ($k:ident) => {\n        #[$k(feature = "testing")]\n        fn main() { demo::t(); }\n        #[$k(not(feature = "testing"))]\n        fn main() {}\n    };\n}\ngate!(cfg);\n' > "$ws/demo/examples/good.rs"
expect "cfg attribute built by a local macro" "$ws" 1 "      macro_rules!"

# `stringify!` turns its input into a `&str` without resolving it, so the body below names
# an item that does not exist on default features and the compile still exits 0.
ws="$(new_ws stringify $'[features]\ntesting = []')"
printf 'pub fn f() {}\n#[cfg(feature = "testing")]\npub fn t() {}\n' > "$ws/demo/src/lib.rs"
printf 'const _: &str = stringify! { fn body() { demo::t(); } };\nfn main() {}\n' > "$ws/demo/examples/good.rs"
expect "example body inside stringify!" "$ws" 1 "      stringify!"

# rustc lexes U+200E and U+200F as whitespace, and Perl's `\s` matches neither, so each
# fixture below holds a live `cfg(`, `cfg!(` or `#[path]` attribute that a scan joining the
# attribute's tokens with `\s` never reports. Each compiles on default features.
ws="$(new_ws lrmcfg $'[features]\ntesting = []')"
printf 'pub fn f() {}\n#[cfg(feature = "testing")]\npub fn t() {}\n' > "$ws/demo/src/lib.rs"
printf '#[cfg\xe2\x80\x8e(feature = "testing")]\nfn main() { demo::t(); }\n#[cfg\xe2\x80\x8e(not(feature = "testing"))]\nfn main() {}\n' > "$ws/demo/examples/good.rs"
expect "feature cfg joined by a U+200E" "$ws" 1 "      U+200E or U+200F outside a literal or comment"

ws="$(new_ws lrmcfgmacro $'[features]\ntesting = []')"
printf 'fn main() { let _ = cfg!\xe2\x80\x8e(feature = "testing"); }\n' > "$ws/demo/examples/good.rs"
expect "cfg! macro joined by a U+200E" "$ws" 1 "      U+200E or U+200F outside a literal or comment"

ws="$(new_ws rlmpath $'[features]\ntesting = []')"
printf 'pub fn f() {}\n#[cfg(feature = "testing")]\npub fn t() {}\n' > "$ws/demo/src/lib.rs"
printf '#[cfg(feature = "testing")]\npub fn run() { demo::t(); }\n#[cfg(not(feature = "testing"))]\npub fn run() {}\n' > "$ws/demo/examples/body.inc"
printf '#[\xe2\x80\x8fpath = "body.inc"]\nmod body;\nfn main() { body::run(); }\n' > "$ws/demo/examples/good.rs"
expect "example module read through #[path] joined by a U+200F" "$ws" 1 "      U+200E or U+200F outside a literal or comment"

# std's stable `cfg_select!` keeps only the arm whose predicate holds, and its predicates
# are not `cfg(` calls, so a scan that matched only `cfg(` would pass this file.
ws="$(new_ws cfgselect $'[features]\ntesting = []')"
printf 'pub fn f() {}\n#[cfg(feature = "testing")]\npub fn t() {}\n' > "$ws/demo/src/lib.rs"
printf 'cfg_select! {\n    feature = "testing" => { fn main() { demo::t(); } }\n    _ => { fn main() {} }\n}\n' > "$ws/demo/examples/good.rs"
expect "example body behind a cfg_select! arm" "$ws" 1 "      cfg_select"

# A non-`--test` build deletes a `#[test]` item before name resolution, so the body below
# names an item that does not exist on default features and the compile still exits 0.
ws="$(new_ws testattr $'[features]\ntesting = []')"
printf 'pub fn f() {}\n#[cfg(feature = "testing")]\npub fn t() {}\n' > "$ws/demo/src/lib.rs"
printf 'fn main() {}\n#[test]\nfn body() { demo::t(); }\n' > "$ws/demo/examples/good.rs"
expect "example body in a #[test] function" "$ws" 1 "      test-attribute name test"

ws="$(new_ws testpath $'[features]\ntesting = []')"
printf 'pub fn f() {}\n#[cfg(feature = "testing")]\npub fn t() {}\n' > "$ws/demo/src/lib.rs"
printf 'fn main() {}\n#[core::prelude::v1::test]\nfn body() { demo::t(); }\n' > "$ws/demo/examples/good.rs"
expect "example body in a path-qualified test function" "$ws" 1 "      test-attribute name test"

ws="$(new_ws testalias $'[features]\ntesting = []')"
printf 'pub fn f() {}\n#[cfg(feature = "testing")]\npub fn t() {}\n' > "$ws/demo/src/lib.rs"
printf 'use core::prelude::v1::test as check;\nfn main() {}\n#[check]\nfn body() { demo::t(); }\n' > "$ws/demo/examples/good.rs"
expect "example body in a test function under a renamed attribute" "$ws" 1 "      test-attribute name test"

# rustc lexes the `r` below as a literal suffix or a lifetime and `"\" "` as an ordinary
# string, so the feature cfg is real code. A scan that reads `r"\"` as a raw string ends it
# at the second quote and blanks the cfg inside the string that the stray quote opens.
for pre in suffixnum:1r suffixlifetime:\'r suffixstring:\"x\"r suffixrawhash:r#\"x\"#r; do
    ws="$(new_ws "${pre%%:*}" $'[features]\ntesting = []')"
    printf 'pub fn f() {}\n#[cfg(feature = "testing")]\npub fn t() {}\n' > "$ws/demo/src/lib.rs"
    printf 'const _: &str = stringify!(%s"\\" ");\n#[cfg(feature = "testing")]\nfn main() { demo::t(); }\n#[cfg(not(feature = "testing"))]\nfn main() {}\n// "\n' "${pre#*:}" > "$ws/demo/examples/good.rs"
    expect "feature cfg after the literal ${pre#*:}\"\\\" \"" "$ws" 1 '      cfg(feature = "testing")'
done

# A char literal with a multi-character escape. A scan that stops at `'\x` reads `','` as
# the char literal, and the `"` after it opens a string that swallows the feature cfg.
for lit in charhex:'\x41' charunicode:'\u{41}'; do
    ws="$(new_ws "${lit%%:*}" $'[features]\ntesting = []')"
    printf 'pub fn f() {}\n#[cfg(feature = "testing")]\npub fn t() {}\n' > "$ws/demo/src/lib.rs"
    printf 'fn main() { let _ = (%s,%s); body(); }\n#[cfg(feature = "testing")]\nfn body() { demo::t(); }\n#[cfg(not(feature = "testing"))]\nfn body() {}\n// "\n' "'${lit#*:}'" "'\"'" > "$ws/demo/examples/good.rs"
    expect "feature cfg after the char literal '${lit#*:}'" "$ws" 1 '      cfg(feature = "testing")'
done

# A `#` token before `r"` leaves a raw string, so rustc reads `r"\"` as a raw string that
# ends at its second quote and the feature cfg as real code. A scan that refuses the raw
# string there reads `"\");` as an ordinary string and blanks the cfg inside it.
ws="$(new_ws hashraw $'[features]\ntesting = []')"
printf 'pub fn f() {}\n#[cfg(feature = "testing")]\npub fn t() {}\n' > "$ws/demo/src/lib.rs"
printf 'const _: &str = stringify!(#r"\\");\n#[cfg(feature = "testing")]\nfn main() { demo::t(); }\n#[cfg(not(feature = "testing"))]\nfn main() {}\n// "\n' > "$ws/demo/examples/good.rs"
expect "feature cfg after the raw string #r\"\\\"" "$ws" 1 '      cfg(feature = "testing")'

ws="$(new_ws platformcfg)"
cat > "$ws/demo/examples/good.rs" <<'RS'
// #[cfg(feature = "testing")] in a comment is not a predicate.
/* nor cfg(test) in a /* nested */ block comment, nor include!("x.rs") */
fn main() {
    let s = "#[cfg(feature = \"testing\")]";
    let c = '"';
    #[cfg(unix)]
    {
        let _ = (s, c);
    }
    #[cfg(not(any(windows, target_os = "windows",)))]
    {
        let _ = (s, c);
    }
    let _ = cfg!(all(target_family = "unix", not(windows)));
    let _ = (include_str!("good.rs"), r#"cfg(windows) "include" macro_rules"#);
    let _ = ("cfg_select! { _ => {} } #[test]", tested(), testing(), benches());
    let _ = (r"cfg(windows) \", br#"cfg(windows)"#, cr"cfg(windows) \", c"cfg(windows)");
    let r#path = stringify_all();
    let _ = (path, "stringify!(x) #[path = \"x\"]");
    let _ = ('\x41','"', '\u{41}','"', b'\x7f','"', 'é','"', "cfg(windows)");
    let _ = ("cfg‎(windows) #[‏path]", '‎', r"‏");
}
// cfg‎(windows) and #[‏path] in a comment are not attributes.
// cfg_if! and #[bench] in a comment are not constructs either.
#[inline]
fn tested() -> u8 { 0 }
#[must_use]
fn testing() -> u8 { 0 }
fn benches() -> u8 { 0 }
fn stringify_all() -> u8 { 0 }
RS
expect "platform predicates true on the host, and scan text in strings and comments" "$ws" 0 "OK: 1 example target(s) compile"

echo "$PASSED passed, $FAILED failed"
[ "$FAILED" -eq 0 ]
