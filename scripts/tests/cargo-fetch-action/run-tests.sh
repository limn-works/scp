#!/usr/bin/env bash
#
# Cases for `.github/actions/cargo-fetch/fetch.sh`, the step every Rust job in
# `.github/workflows/` runs before its first cargo command that reads the registry.
#
# WHAT THE STUBS REPLACE. `cargo` and `sleep` are stubs on PATH, so no case downloads a
# crate or waits out a backoff. The stub cargo fails its first `STUB_FAIL_FETCHES`
# `fetch` calls with the error chain cargo printed in run 38171293381
# (`Could not resolve host: index.crates.io`), and records every call with the
# `CARGO_NET_RETRY` and `CARGO_NET_OFFLINE` it saw. The stub sleep records the seconds it
# was asked to wait.
#
# WHAT EACH CASE PROVES. The fetch runs `cargo fetch --locked` with `CARGO_NET_RETRY=10`,
# retries a failed attempt and stops at the first success, waiting 10, 20 and 40 seconds
# between four attempts; after the last failed attempt it exits non-zero with cargo's error
# chain in a `::error::` line and writes nothing to `$GITHUB_ENV`; after a success it runs an
# offline `cargo metadata --locked --all-features` and only then appends
# `CARGO_NET_OFFLINE=true` to `$GITHUB_ENV` and `cargo-home=<$CARGO_HOME, else
# $HOME/.cargo>` to `$GITHUB_OUTPUT`; a failed offline metadata fails the step and
# writes nothing; a toolchain argument reaches every cargo call as `+<toolchain>`; and it
# refuses, before fetching anything, a missing directory, a directory with no Cargo.lock, a
# `CARGO_NET_OFFLINE` already in the environment, a missing `$GITHUB_ENV` or
# `$GITHUB_OUTPUT`, neither `CARGO_HOME` nor `HOME`, a malformed
# toolchain name or delay, and a cargo that cannot report its version.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
FETCH="$REPO_ROOT/.github/actions/cargo-fetch/fetch.sh"

if [[ ! -f "$FETCH" ]]; then
    echo "ERROR: $FETCH does not exist" >&2
    exit 1
fi

TMP_PARENT=$(mktemp -d)
trap 'rm -rf "$TMP_PARENT"' EXIT

passed=0
failed=0

report() {
    local name=$1 rc=$2 detail=$3
    if [[ $rc -eq 0 ]]; then
        echo "PASS: $name"
        passed=$((passed + 1))
    else
        echo "FAIL: $name — $detail"
        failed=$((failed + 1))
    fi
}

STUB_BIN="$TMP_PARENT/bin"
mkdir -p "$STUB_BIN"

cat > "$STUB_BIN/cargo" <<'STUB'
#!/usr/bin/env bash
printf '%s|%s|%s\n' "${CARGO_NET_RETRY:-}" "${CARGO_NET_OFFLINE:-}" "$*" >> "$STUB_STATE/calls"
args=("$@")
[[ ${args[0]:-} == +* ]] && args=("${args[@]:1}")
case "${args[0]:-}" in
    -V)
        if [[ -n ${STUB_VERSION_FAILS:-} ]]; then
            echo "error: toolchain '1.98.0-x86_64-unknown-linux-gnu' is not installed" >&2
            exit 1
        fi
        echo "cargo 1.98.0 (stub)"
        exit 0
        ;;
    fetch)
        count=$(( $(cat "$STUB_STATE/fetches" 2>/dev/null || echo 0) + 1 ))
        echo "$count" > "$STUB_STATE/fetches"
        if (( count <= ${STUB_FAIL_FETCHES:-0} )); then
            cat >&2 <<'ERR'
    Updating crates.io index
error: failed to get `rusqlite` as a dependency of package `scp-sqlite-pools v0.1.0-beta.2 (/work/crates/scp-sqlite-pools)`

Caused by:
  unable to update registry `crates-io`

Caused by:
  download of config.json failed

Caused by:
  [6] Couldn't resolve host name (Could not resolve host: index.crates.io)
ERR
            exit 101
        fi
        exit 0
        ;;
    metadata)
        if [[ -n ${STUB_METADATA_FAILS:-} ]]; then
            echo "error: no matching package named \`wasm-bindgen\` found (offline)" >&2
            exit 101
        fi
        echo '{}'
        exit 0
        ;;
esac
echo "stub cargo: unexpected call: $*" >&2
exit 99
STUB

cat > "$STUB_BIN/sleep" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$1" >> "$STUB_STATE/sleeps"
STUB

chmod +x "$STUB_BIN/cargo" "$STUB_BIN/sleep"

case_number=0
# Runs fetch.sh in a fresh state directory against a fresh checkout holding a Cargo.lock
# in WORKDIR (default `.`). Sets OUT, RC, STATE, CHECKOUT and ENVFILE. The first argument is
# the directory argument passed to fetch.sh, the second the toolchain argument; the rest
# are VAR=value pairs for the environment of that one run. `GITHUB_ENV=<absent>` runs with
# no GITHUB_ENV, `GITHUB_OUTPUT=<absent>` with no GITHUB_OUTPUT. HOME is the checkout and
# CARGO_HOME is unset unless a pair sets it. Sets OUTFILE to the GITHUB_OUTPUT file.
run_fetch() {
    local directory=$1 toolchain=$2
    shift 2
    case_number=$((case_number + 1))
    STATE="$TMP_PARENT/state-$case_number"
    CHECKOUT="$TMP_PARENT/checkout-$case_number"
    ENVFILE="$STATE/github_env"
    OUTFILE="$STATE/github_output"
    mkdir -p "$STATE" "$CHECKOUT/fuzz" "$CHECKOUT/no-lock"
    : > "$STATE/calls"
    : > "$ENVFILE"
    : > "$OUTFILE"
    printf 'version = 4\n' > "$CHECKOUT/Cargo.lock"
    printf 'version = 4\n' > "$CHECKOUT/fuzz/Cargo.lock"
    local env_args=(HOME="$CHECKOUT")
    local pair with_env=1 with_output=1
    for pair in "$@"; do
        if [[ $pair == "GITHUB_ENV=<absent>" ]]; then
            with_env=0
        elif [[ $pair == "GITHUB_OUTPUT=<absent>" ]]; then
            with_output=0
        else
            env_args+=("$pair")
        fi
    done
    if (( with_env )); then env_args+=(GITHUB_ENV="$ENVFILE"); fi
    if (( with_output )); then env_args+=(GITHUB_OUTPUT="$OUTFILE"); fi
    OUT=$(cd "$CHECKOUT" && env -u CARGO_NET_OFFLINE -u GITHUB_ENV -u GITHUB_OUTPUT -u CARGO_HOME -u CARGO_FETCH_RETRY_DELAY_SECONDS \
        PATH="$STUB_BIN:$PATH" STUB_STATE="$STATE" ${env_args[@]+"${env_args[@]}"} \
        bash "$FETCH" "$directory" "$toolchain" 2>&1)
    RC=$?
}

fetch_calls() { command grep -c '|fetch --locked$' "$STATE/calls"; }
any_fetch() { command grep -q 'fetch' "$STATE/calls"; }
sleeps() { tr '\n' ' ' < "$STATE/sleeps" 2>/dev/null | sed 's/ $//'; }
env_written() { [[ $(cat "$ENVFILE") == "CARGO_NET_OFFLINE=true" ]]; }
output_is() { [[ $(cat "$OUTFILE") == "cargo-home=$1" ]]; }

# 1. A fetch that succeeds at once: one attempt, CARGO_NET_RETRY=10, an offline metadata
#    after it, and CARGO_NET_OFFLINE=true appended to GITHUB_ENV.
run_fetch . ""
rc=1
if [[ $RC -eq 0 && $(fetch_calls) -eq 1 ]] &&
    command grep -qx '10||fetch --locked' "$STATE/calls" &&
    command grep -qx '|true|metadata --locked --all-features --format-version 1' "$STATE/calls" &&
    env_written && output_is "$CHECKOUT/.cargo" && [[ ! -s $STATE/sleeps ]]; then
    rc=0
fi
report "a first-attempt success fetches once with CARGO_NET_RETRY=10, proves offline metadata, sets CARGO_NET_OFFLINE, and outputs HOME/.cargo" $rc \
    "rc=$RC calls=$(tr '\n' ';' < "$STATE/calls") env=$(cat "$ENVFILE") output=$(cat "$OUTFILE") out=$OUT"

# 2. The metadata proof runs after the fetch, and the variable is written only after both.
rc=1
fetch_line=$(command grep -n 'fetch --locked' "$STATE/calls" | head -n 1 | cut -d: -f1)
metadata_line=$(command grep -n 'metadata' "$STATE/calls" | head -n 1 | cut -d: -f1)
[[ -n $fetch_line && -n $metadata_line && $fetch_line -lt $metadata_line ]] && rc=0
report "the offline metadata runs after the fetch" $rc "calls=$(tr '\n' ';' < "$STATE/calls")"

# 3. Two failed attempts then a success: three attempts, waits of 10 and 20 seconds.
run_fetch . "" STUB_FAIL_FETCHES=2
rc=1
[[ $RC -eq 0 && $(fetch_calls) -eq 3 && $(sleeps) == "10 20" ]] && env_written && rc=0
report "two DNS failures then a success retry with backoff 10, 20 and stop" $rc \
    "rc=$RC fetches=$(fetch_calls) sleeps=$(sleeps) out=$OUT"

# 4. Every attempt fails: four attempts, waits of 10, 20 and 40, cargo's error chain in a
#    ::error:: line, cargo's exit status, and nothing written to GITHUB_ENV.
run_fetch . "" STUB_FAIL_FETCHES=99
rc=1
if [[ $RC -eq 101 && $(fetch_calls) -eq 4 && $(sleeps) == "10 20 40" && ! -s $ENVFILE ]] &&
    command grep -q '^::error title=cargo-fetch::.*failed on all 4 attempts.*Could not resolve host: index.crates.io' <<<"$OUT" &&
    ! command grep -q metadata "$STATE/calls"; then
    rc=0
fi
report "four failed attempts exit with cargo's status and error chain and leave cargo online" $rc \
    "rc=$RC fetches=$(fetch_calls) sleeps=$(sleeps) env=$(cat "$ENVFILE") out=$OUT"

# 5. The retry delay is configurable, and doubles from the value given.
run_fetch . "" STUB_FAIL_FETCHES=99 CARGO_FETCH_RETRY_DELAY_SECONDS=3
rc=1
[[ $RC -ne 0 && $(sleeps) == "3 6 12" ]] && rc=0
report "CARGO_FETCH_RETRY_DELAY_SECONDS=3 waits 3, 6, 12" $rc "sleeps=$(sleeps)"

# 6. A toolchain argument reaches every cargo call, and a working directory is honoured.
run_fetch fuzz nightly-2026-05-03 CARGO_HOME=/opt/cargo-home
rc=1
if [[ $RC -eq 0 ]] && env_written && output_is /opt/cargo-home &&
    [[ $(command grep -c '+nightly-2026-05-03 ' "$STATE/calls") -eq $(wc -l < "$STATE/calls" | tr -d ' ') ]] &&
    command grep -q 'attempt 1 of 4: cargo +nightly-2026-05-03 fetch --locked in fuzz' <<<"$OUT"; then
    rc=0
fi
report "toolchain nightly-2026-05-03 and directory fuzz reach every cargo call, and a set CARGO_HOME is the output" $rc \
    "rc=$RC calls=$(tr '\n' ';' < "$STATE/calls") output=$(cat "$OUTFILE") out=$OUT"

# 7. An offline metadata that fails after a good fetch fails the step and leaves cargo online.
run_fetch . "" STUB_METADATA_FAILS=1
rc=1
# The backticks are literal text in the message, not a command substitution.
# shellcheck disable=SC2016
if [[ $RC -ne 0 && ! -s $ENVFILE && ! -s $OUTFILE ]] &&
    command grep -q '^::error title=cargo-fetch::.*offline `cargo metadata --locked --all-features`.*wasm-bindgen' <<<"$OUT"; then
    rc=0
fi
report "a failed offline metadata fails the step and writes no CARGO_NET_OFFLINE" $rc "rc=$RC out=$OUT"

# 8-16. Refusals: each exits non-zero with a ::error:: line naming its case, runs no fetch,
#        and writes nothing to GITHUB_ENV or GITHUB_OUTPUT.
refusal() {
    local name=$1 pattern=$2
    local rc=1
    if [[ $RC -ne 0 && ! -s $ENVFILE && ! -s $OUTFILE ]] && ! any_fetch &&
        command grep -q "^::error title=cargo-fetch::.*$pattern" <<<"$OUT"; then
        rc=0
    fi
    report "$name" $rc "rc=$RC calls=$(tr '\n' ';' < "$STATE/calls") out=$OUT"
}
run_fetch "" ""
refusal "no working directory argument is refused" "needs a working directory"
run_fetch absent ""
refusal "a missing working directory is refused" "absent is not a directory"
run_fetch no-lock ""
refusal "a working directory with no Cargo.lock is refused" "holds no Cargo.lock"
run_fetch . "" CARGO_NET_OFFLINE=false
refusal "a CARGO_NET_OFFLINE set before the fetch is refused" "CARGO_NET_OFFLINE is already 'false'"
run_fetch . "" "GITHUB_ENV=<absent>"
refusal "a missing GITHUB_ENV is refused" "GITHUB_ENV is '', not a writable file"
run_fetch . "" "GITHUB_OUTPUT=<absent>"
refusal "a missing GITHUB_OUTPUT is refused" "GITHUB_OUTPUT is '', not a writable file"
run_fetch . "" HOME=
refusal "no CARGO_HOME and no HOME is refused" "Neither CARGO_HOME nor HOME is set"
run_fetch . 'nightly;rm -rf /'
refusal "a malformed toolchain name is refused" "is not a rustup toolchain name"
run_fetch . "" CARGO_FETCH_RETRY_DELAY_SECONDS=soon
refusal "a non-numeric retry delay is refused" "is not a whole number"

# 17. A cargo that cannot report its version is a toolchain fault: one -V call, no fetch,
#     no retry.
run_fetch . "" STUB_VERSION_FAILS=1
rc=1
if [[ $RC -ne 0 && ! -s $ENVFILE && $(wc -l < "$STATE/calls" | tr -d ' ') -eq 1 && ! -s $STATE/sleeps ]] &&
    command grep -q '^::error title=cargo-fetch::cargo -V failed.*is not installed' <<<"$OUT"; then
    rc=0
fi
report "a cargo that cannot report its version fails at once without fetching or retrying" $rc \
    "rc=$RC calls=$(tr '\n' ';' < "$STATE/calls") out=$OUT"

echo
echo "$passed passed, $failed failed"
[[ $failed -eq 0 ]]
