#!/usr/bin/env bash
# run-tests.sh — exercise scripts/check-workflow-compile-steps.py against canned
# workflow directories.
#
# WHAT THIS TESTS.
#   * Check 1 (rust-cache groups) fails a step that names no `shared-key`, a step that
#     names `key` beside `shared-key`, a step that names no `save-if`, a group whose
#     every member has `save-if: false`, a group with two writers — counted across two
#     workflow files, because the cache cap is per repository — and a writer whose
#     `save-if` does not name `refs/heads/main`. It passes a group with one writer on
#     main and readers at `false`, including a writer whose `save-if` is a matrix
#     expression, and it passes a job that restores two groups through two rust-cache
#     steps, both at `false` — the shape a job takes when one command reads build-mode
#     artifacts and another reads check-mode ones — and the check counts each step in
#     its own group. It counts a `shared-key`
#     holding `${{ matrix.<axis> }}` as one group per axis value: it passes such a
#     writer whose groups each have one writer, fails a literal second writer of one of
#     those groups, fails a key naming an axis the job's matrix gives no list, and
#     fails a templated key whose matrix carries `include` or `exclude`.
#   * Check 2 (uniffi-bindgen steps) fails a `cargo run` with no profile or target flags
#     whose `--library` sits under `target/<triple>/release` (the second-compile shape
#     from build-xcframework.sh and the Swift job of build-matrix.yml), one whose
#     `--library` sits under `target/release` (the Android job's path that no step
#     produced), one that passes no `--library`, one under the custom `--profile
#     ci-bridge` whose `--library` sits under `target/<triple>/release`, and one under
#     the built-in `--profile test` whose `--library` sits under `target/test`. It passes a
#     `cargo run` whose flags name the library's directory, with `--release --target`,
#     with `--profile release` behind a `+toolchain` selector, with `--profile ci-bridge
#     --target` reading `target/<triple>/ci-bridge`, with a bare `cargo run` reading
#     `target/debug`, with `--profile test` reading `target/debug` and `--profile bench`
#     reading `target/release`, and it joins backslash-continued lines before reading a command.
#   * Check 3 (group coverage) fails a reader that compiles a feature the writer does
#     not, a reader that compiles in check mode against a build-mode writer, a reader
#     whose command names a shell variable its script never sets, a reader whose
#     CARGO_* environment differs from the writer's, and a group whose only writer sits
#     in a workflow no push or schedule on main starts, including one a push starts
#     only for tags. It fails a group whose reader runs on merge-queue runs and that only
#     a schedule writes, and a compile-only twin script whose cargo commands differ
#     from the gate script it stands in for. It passes a reader whose commands the
#     writers of the groups it restores compile, on the same OS family, and a reader
#     running `cargo test --doc` against a writer running it with `-- --list`.
#   * Check 4 (push runs) fails a job a push runs that writes no cache and that no
#     writer needs, a writer that runs tests (`cargo nextest run` without `--no-run`,
#     `wasm-pack test` without `-- --list`, a Gradle `test` task), one that lints with
#     `-- -D warnings`, one that runs a repository gate script, one that uses an action
#     outside setup, cache, upload and build, and a companion job whose `if:` differs
#     from the job it accompanies. It passes a push that runs only a producer, the job
#     it needs, check-draft beside `changes`, and a cache-warm workflow that compiles
#     every reader's command.
#
# Each case is a directory under ./fixtures/ that the check reads through
# `--workflows-dir`, and through `--repo-root` from the case's `repo/` directory when it
# has one. Exit 0 when every case matches its expectation, 1 otherwise.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
CHECK="$REPO_ROOT/scripts/check-workflow-compile-steps.py"
FIXTURES_DIR="$SCRIPT_DIR/fixtures"

PYTHON="python3"
command -v python3.12 >/dev/null 2>&1 && PYTHON="python3.12"

if [[ ! -f "$CHECK" ]]; then
    echo "ERROR: $CHECK does not exist" >&2
    exit 1
fi

# Fixture definitions — the three arrays stay in sync by position.
FIXTURES=(
    "good-groups-and-bindgen"
    "bad-cache-no-shared-key"
    "bad-cache-key-beside-shared-key"
    "bad-cache-no-save-if"
    "bad-cache-no-writer"
    "bad-cache-two-writers-across-files"
    "bad-cache-writer-off-main"
    "bad-bindgen-second-compile"
    "bad-bindgen-path-nothing-wrote"
    "bad-bindgen-no-library"
    "good-cache-matrix-key"
    "bad-cache-matrix-key-second-writer"
    "bad-cache-matrix-key-no-axis"
    "bad-cache-matrix-key-include"
    "bad-cache-matrix-key-exclude"
    "bad-bindgen-custom-profile-release-path"
    "bad-bindgen-test-profile-own-name"
    "bad-cache-reader-extra-feature"
    "bad-cache-reader-check-mode"
    "bad-cache-reader-unset-variable"
    "bad-cache-reader-env-differs"
    "bad-cache-writer-never-triggered"
    "bad-cache-writer-step-output-gated"
    "bad-cache-no-push-writer"
    "bad-cache-writer-tags-only-push"
    "bad-script-twin-differs"
    "good-push-runs"
    "bad-push-runs-gate-job"
    "bad-push-runs-test"
    "bad-push-runs-clippy-deny"
    "bad-push-runs-wasm-test"
    "bad-push-runs-gate-script"
    "bad-push-runs-gradle-test"
    "bad-push-runs-unknown-action"
    "bad-push-runs-companion-if"
)
EXPECTED_EXITS=(
    "0"
    "1"
    "1"
    "1"
    "1"
    "1"
    "1"
    "1"
    "1"
    "1"
    "0"
    "1"
    "1"
    "1"
    "1"
    "1"
    "1"
    "1"
    "1"
    "1"
    "1"
    "1"
    "1"
    "1"
    "1"
    "1"
    "0"
    "1"
    "1"
    "1"
    "1"
    "1"
    "1"
    "1"
    "1"
)
EXPECTED_SUBSTRINGS=(
    "OK: 6 rust-cache step(s) in 3 group(s)"
    "names no \`shared-key\`"
    "names both \`key\` and \`shared-key\`"
    "names no \`save-if\`"
    "has no step whose save-if is not false"
    "has 2 steps whose save-if is not false"
    "does not name refs/heads/main"
    "writes target/debug/ and the \`--library\` it reads is target/aarch64-apple-darwin/release/libscp_ffi_uniffi.dylib"
    "writes target/debug/ and the \`--library\` it reads is target/release/libscp_ffi_uniffi.so"
    "passes no \`--library\`"
    "OK: 2 rust-cache step(s) in 2 group(s)"
    "cache group 'optional-transport' has 2 steps whose save-if is not false"
    "names matrix axis 'group', which the job's \`strategy.matrix\` gives no list"
    "of a \`strategy.matrix\` carrying include, so this check"
    "of a \`strategy.matrix\` carrying exclude, so this check"
    "writes target/aarch64-apple-darwin/ci-bridge/ and the \`--library\` it reads is target/aarch64-apple-darwin/release/libscp_ffi_uniffi.dylib"
    "writes target/debug/ and the \`--library\` it reads is target/test/libscp_ffi_uniffi.so"
    "reader compiles \`cargo test --features=a/x,a/y -p=a [in .]\`, and no writer"
    "reader compiles \`cargo clippy --features=a/x -p=a [in .]\`, and no writer"
    "names shell variable(s) FEATURES that no assignment earlier in its script sets"
    "restore under different values of CARGO_PROFILE_DEV_DEBUG"
    "no leg writes it on a run of refs/heads/main that a push or a schedule starts"
    "the rust-cache step writing group 'workspace-debug' waits on an earlier step's output"
    "no leg writes it on a push to refs/heads/main"
    "cache group 'release': no leg writes it on a run of refs/heads/main"
    "stands in for scripts/check-examples-compile.sh in every cache-group writer"
    "OK: 5 job(s) a push to refs/heads/main can run"
    "job lint can run on a push to refs/heads/main, writes no cache"
    "\`cargo nextest run -p a --features x\` is a cargo command that runs tests or lints"
    "\`cargo clippy -p a -- -D warnings\` is a cargo command that runs tests or lints"
    "\`wasm-pack test --node crates/a\` runs wasm tests"
    "\`bash scripts/check-examples-compile.sh\` runs \`bash\`, which this check does not know"
    "runs Gradle task(s) :a:test that are not compile"
    "uses actions/download-artifact@v4 on a push"
    "job check-draft runs on a push as the companion of job changes"
)

passed=0
failed=0

for i in "${!FIXTURES[@]}"; do
    name="${FIXTURES[$i]}"
    expected_exit="${EXPECTED_EXITS[$i]}"
    expected_substr="${EXPECTED_SUBSTRINGS[$i]}"
    fixture_root="$FIXTURES_DIR/$name"

    if [[ ! -d "$fixture_root" ]]; then
        echo "FAIL [$name]: fixture directory $fixture_root does not exist" >&2
        failed=$((failed + 1))
        continue
    fi

    args=(--workflows-dir "$fixture_root")
    if [[ -d "$fixture_root/repo" ]]; then
        args+=(--repo-root "$fixture_root/repo")
    fi
    set +e
    output="$("$PYTHON" "$CHECK" "${args[@]}" 2>&1)"
    actual_exit=$?
    set -e

    if [[ "$actual_exit" != "$expected_exit" ]]; then
        echo "FAIL [$name]: exit $actual_exit, expected $expected_exit" >&2
        echo "$output" >&2
        failed=$((failed + 1))
        continue
    fi
    if [[ "$output" != *"$expected_substr"* ]]; then
        echo "FAIL [$name]: output lacks '$expected_substr'" >&2
        echo "$output" >&2
        failed=$((failed + 1))
        continue
    fi
    echo "PASS [$name]"
    passed=$((passed + 1))
done

# The good fixture reports every good shape it holds; a case that passed for the wrong
# reason (a parser that saw no step at all) would print zero counts, so hold the
# bindgen count too.
set +e
good_output="$("$PYTHON" "$CHECK" --workflows-dir "$FIXTURES_DIR/good-groups-and-bindgen" 2>&1)"
set -e
if [[ "$good_output" == *"OK: 6 uniffi-bindgen step(s)"* ]]; then
    echo "PASS [good-groups-and-bindgen counts six bindgen steps]"
    passed=$((passed + 1))
else
    echo "FAIL [good-groups-and-bindgen counts six bindgen steps]: $good_output" >&2
    failed=$((failed + 1))
fi
# Check 3 compares four readers there: job doc in both groups and the two fuzz legs
# that do not write. Zero would mean it read no command.
if [[ "$good_output" == *"OK: 4 cache-group reader(s)"* ]]; then
    echo "PASS [good-groups-and-bindgen compares four readers]"
    passed=$((passed + 1))
else
    echo "FAIL [good-groups-and-bindgen compares four readers]: $good_output" >&2
    failed=$((failed + 1))
fi

echo "workflow-compile-steps: $passed passed, $failed failed"
[[ "$failed" -eq 0 ]]
