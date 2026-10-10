#!/usr/bin/env bash
#
# Cases for `.github/actions/rust-toolchain/install.sh`, the step every Rust job in
# `.github/workflows/ci.yml` runs before its first cargo command.
#
# WHAT THE STUBS REPLACE. `rustup`, `rustc` and `sleep` are stubs on PATH, so no case
# downloads a toolchain or waits out a backoff. The stub rustup fails its first
# `STUB_FAIL_INSTALLS` `toolchain install` calls with the error chain rustup printed on
# 2026-10-10 (`Connection timed out (os error 110)`, then a stack backtrace), and records
# every call it receives. The stub sleep records the seconds it was asked to wait.
#
# WHAT EACH CASE PROVES. The install retries a failed download and stops at the first
# success; it makes at least three attempts and waits 10, 20 and 40 seconds between them;
# after the last failed attempt it exits non-zero with rustup's error chain in a
# `::error::` line and sets no override; it asks rustup for the minimal profile plus only
# the components and targets it was given; it sets the override on the toolchain file's own
# directory; and it refuses, before installing anything, a missing file, a file with no
# channel, and a `RUSTUP_TOOLCHAIN` in the environment, and refuses, after installing, an
# override rustup rejected and a `rustc -V` that does not report the installed toolchain.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
INSTALL="$REPO_ROOT/.github/actions/rust-toolchain/install.sh"

if [[ ! -f "$INSTALL" ]]; then
    echo "ERROR: $INSTALL does not exist" >&2
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

cat > "$STUB_BIN/rustup" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$STUB_STATE/calls"
case "$1 $2" in
    "toolchain install")
        count=$(( $(cat "$STUB_STATE/installs" 2>/dev/null || echo 0) + 1 ))
        echo "$count" > "$STUB_STATE/installs"
        if (( count <= ${STUB_FAIL_INSTALLS:-0} )); then
            cat >&2 <<'ERR'
info: syncing channel updates for 1.98.0-x86_64-unknown-linux-gnu
error: component download failed for cargo-x86_64-unknown-linux-gnu

Caused by:
    0: error sending request for url (https://static.rust-lang.org/dist/2026-08-20/cargo-1.98.0-x86_64-unknown-linux-gnu.tar.xz)
    1: tcp connect error
    2: Connection timed out (os error 110)

Stack backtrace:
   0: <rustup::download::DownloadError as anyhow::context::ext::StdError>::ext_context::<&str>
ERR
            exit 1
        fi
        exit 0
        ;;
    "override set")
        exit "${STUB_OVERRIDE_STATUS:-0}"
        ;;
    "run "*)
        printf '%s\n' "${STUB_TOOLCHAIN_RUSTC:-rustc 1.98.0 (88d9e12ae 2026-08-18)}"
        exit 0
        ;;
esac
echo "stub rustup: unexpected call: $*" >&2
exit 99
STUB

cat > "$STUB_BIN/rustc" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "${STUB_RESOLVED_RUSTC:-rustc 1.98.0 (88d9e12ae 2026-08-18)}"
STUB

cat > "$STUB_BIN/sleep" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$1" >> "$STUB_STATE/sleeps"
STUB

chmod +x "$STUB_BIN/rustup" "$STUB_BIN/rustc" "$STUB_BIN/sleep"

case_number=0
# Runs install.sh in a fresh state directory against a toolchain file in a fresh checkout
# directory. Sets OUT, RC, STATE and CHECKOUT. Extra arguments are VAR=value pairs for the
# environment of that one run.
run_install() {
    local toolchain_body=$1 components=$2 targets=$3
    shift 3
    case_number=$((case_number + 1))
    STATE="$TMP_PARENT/state-$case_number"
    CHECKOUT="$TMP_PARENT/checkout-$case_number"
    mkdir -p "$STATE" "$CHECKOUT"
    : > "$STATE/calls"
    if [[ $toolchain_body != "<absent>" ]]; then
        printf '%s\n' "$toolchain_body" > "$CHECKOUT/rust-toolchain.toml"
    fi
    OUT=$(cd "$CHECKOUT" && env -u RUSTUP_TOOLCHAIN PATH="$STUB_BIN:$PATH" STUB_STATE="$STATE" "$@" \
        bash "$INSTALL" rust-toolchain.toml "$components" "$targets" 2>&1)
    RC=$?
}

install_calls() { command grep -c '^toolchain install ' "$STATE/calls"; }
override_calls() { command grep -c '^override set ' "$STATE/calls"; }

PIN='[toolchain]
channel = "1.98.0"
components = ["clippy", "rustfmt", "rust-analyzer"]
targets = ["wasm32-unknown-unknown", "aarch64-apple-ios"]'

# ── 1: first attempt succeeds ───────────────────────────────────────────────────────
run_install "$PIN" "clippy,rustfmt" "wasm32-unknown-unknown"
first_call=$(command grep -m1 '^toolchain install ' "$STATE/calls")
want_call="toolchain install 1.98.0 --profile minimal --no-self-update --component clippy --component rustfmt --target wasm32-unknown-unknown"
[[ $RC -eq 0 && $(install_calls) -eq 1 && ! -s $STATE/sleeps.missing ]]
report "a first attempt that succeeds exits 0 after one install" $? "rc=$RC installs=$(install_calls) out: $OUT"
[[ $first_call == "$want_call" ]]
report "the install asks for the minimal profile plus only the components and targets given" $? "called: '$first_call', wanted: '$want_call'"
override_call=$(command grep -m1 '^override set ' "$STATE/calls")
want_override="override set 1.98.0 --path $(cd "$CHECKOUT" && pwd -P)"
[[ $override_call == "$want_override" ]]
report "the override is set on the toolchain file's own directory" $? "called: '$override_call', wanted: '$want_override'"
[[ ! -f $STATE/sleeps ]]
report "a first attempt that succeeds waits for nothing" $? "slept: $(cat "$STATE/sleeps" 2>/dev/null | tr '\n' ' ')"

# ── 2: empty lists add no component and no target ───────────────────────────────────
run_install "$PIN" "" ""
first_call=$(command grep -m1 '^toolchain install ' "$STATE/calls")
[[ $RC -eq 0 && $first_call == "toolchain install 1.98.0 --profile minimal --no-self-update" ]]
report "empty component and target lists install the minimal profile alone" $? "rc=$RC called: '$first_call'"

# ── 3: a failed first attempt is retried and the second succeeds ───────────────────
run_install "$PIN" "" "" STUB_FAIL_INSTALLS=1
[[ $RC -eq 0 && $(install_calls) -eq 2 && $OUT == *"installed on attempt 2 of 4"* ]]
report "a failed first attempt is retried and the second attempt's success exits 0" $? "rc=$RC installs=$(install_calls) out: $OUT"
[[ $(tr '\n' ' ' < "$STATE/sleeps") == "10 " ]]
report "the retry waits 10 seconds before the second attempt" $? "slept: $(tr '\n' ' ' < "$STATE/sleeps" 2>/dev/null)"

# ── 4: three failures, success on the fourth ────────────────────────────────────────
run_install "$PIN" "" "" STUB_FAIL_INSTALLS=3
[[ $RC -eq 0 && $(install_calls) -eq 4 ]]
report "three failed attempts still end in an install on the fourth" $? "rc=$RC installs=$(install_calls) out: $OUT"
[[ $(tr '\n' ' ' < "$STATE/sleeps") == "10 20 40 " ]]
report "the waits double: 10, 20, 40 seconds" $? "slept: $(tr '\n' ' ' < "$STATE/sleeps" 2>/dev/null)"

# ── 5: every attempt fails ──────────────────────────────────────────────────────────
run_install "$PIN" "" "" STUB_FAIL_INSTALLS=99
error_line=$(command grep '^::error' <<< "$OUT")
[[ $RC -ne 0 && $(install_calls) -eq 4 ]]
report "an install that fails on every attempt exits non-zero after four attempts" $? "rc=$RC installs=$(install_calls)"
[[ $error_line == *"failed on all 4 attempts"* && $error_line == *"Connection timed out (os error 110)"* && $error_line == *"component download failed"* ]]
report "the last failure's ::error line carries rustup's error chain" $? "error line: $error_line"
[[ $error_line != *"Stack backtrace"* ]]
report "the ::error line leaves out the stack backtrace" $? "error line: $error_line"
[[ $(override_calls) -eq 0 ]]
report "an install that never succeeded sets no override" $? "calls: $(tr '\n' ';' < "$STATE/calls")"

# ── 6: refusals before any install ─────────────────────────────────────────────────
run_install "$PIN" "" "" RUSTUP_TOOLCHAIN=stable
[[ $RC -ne 0 && $(install_calls) -eq 0 && $OUT == *"RUSTUP_TOOLCHAIN=stable is set"* ]]
report "a RUSTUP_TOOLCHAIN in the environment is refused before any install" $? "rc=$RC installs=$(install_calls) out: $OUT"

run_install "<absent>" "" ""
[[ $RC -ne 0 && $(install_calls) -eq 0 && $OUT == *"does not exist"* ]]
report "a missing toolchain file is refused before any install" $? "rc=$RC out: $OUT"

run_install '[toolchain]
components = ["clippy"]' "" ""
[[ $RC -ne 0 && $(install_calls) -eq 0 && $OUT == *"names no [toolchain] channel"* ]]
report "a toolchain file with no channel is refused before any install" $? "rc=$RC out: $OUT"

run_install "$PIN" "" "" RUST_TOOLCHAIN_RETRY_DELAY_SECONDS=soon
[[ $RC -ne 0 && $(install_calls) -eq 0 ]]
report "a retry delay that is not a whole number is refused before any install" $? "rc=$RC out: $OUT"

# ── 7: refusals after the install ──────────────────────────────────────────────────
run_install "$PIN" "" "" STUB_OVERRIDE_STATUS=1
[[ $RC -ne 0 && $OUT == *"rustup override set 1.98.0"*"failed"* ]]
report "an override rustup rejects fails the step" $? "rc=$RC out: $OUT"

run_install "$PIN" "" "" "STUB_RESOLVED_RUSTC=rustc 1.98.1 (48a229cea 2026-09-17)" "STUB_TOOLCHAIN_RUSTC=rustc 1.98.1 (48a229cea 2026-09-17)"
[[ $RC -ne 0 && $OUT == *"not version 1.98.0"* ]]
report "a rustc -V reporting another version than the numbered channel fails the step" $? "rc=$RC out: $OUT"

run_install "$PIN" "" "" "STUB_RESOLVED_RUSTC=rustc 1.98.0 (ffffffff 2026-08-18)"
[[ $RC -ne 0 && $OUT == *"something outranks the override"* ]]
report "a rustc -V that differs from the installed toolchain's own rustc fails the step" $? "rc=$RC out: $OUT"

NIGHTLY='[toolchain]
channel = "nightly-2026-09-28"'
run_install "$NIGHTLY" "" "" "STUB_RESOLVED_RUSTC=rustc 1.100.0-nightly (abc 2026-09-27)" "STUB_TOOLCHAIN_RUSTC=rustc 1.100.0-nightly (abc 2026-09-27)"
[[ $RC -eq 0 ]]
report "a dated nightly passes when rustc -V matches that toolchain's own rustc" $? "rc=$RC out: $OUT"

run_install "$NIGHTLY" "" "" "STUB_RESOLVED_RUSTC=rustc 1.98.0 (88d9e12ae 2026-08-18)" "STUB_TOOLCHAIN_RUSTC=rustc 1.100.0-nightly (abc 2026-09-27)"
[[ $RC -ne 0 ]]
report "a dated nightly fails when rustc -V answers with another toolchain" $? "rc=$RC out: $OUT"

echo ""
echo "rust-toolchain-action cases: $passed passed, $failed failed"
[[ $failed -eq 0 ]]
