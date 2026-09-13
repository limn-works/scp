#!/usr/bin/env bash
# run-tests.sh — hold `scripts/fix-round-check.sh` to its two contract clauses.
#
# WHAT THIS TESTS, and why each case exists.
#
#   * THE REFUSAL. The script exits non-zero and starts no cargo command when the compiler
#     answering in this repository is not the version `rust-toolchain.toml` names. Case 1
#     puts a compiler reporting 1.2.3 on PATH and asserts both halves: the exit code, and
#     an empty invocation log from the stub cargo. The second half is the one that matters,
#     because a script that reports the mismatch and compiles anyway produces a result on
#     the wrong compiler while printing a line that says so, which
#     `.docs/lessons/pin-the-rust-toolchain-or-ci-drifts-from-local.md` records as the
#     failure that blocked the merge queue: a clippy run on a compiler the repository does
#     not name exits 0 and proves nothing.
#
#   * THE PROPAGATION. A non-zero exit from any step is a non-zero exit from the script.
#     Case 2 makes the stub cargo exit 1 on `check` and asserts that the script exits
#     non-zero and names the compile step as failed. Case 3 makes the same stub cargo exit
#     0 on every subcommand and asserts that the script exits 0 and names the compile and
#     format steps as passing. Case 3 exists so case 2 is not vacuous: without it, a script
#     that always failed would satisfy case 2.
#
# WHAT THE STUBS REPLACE, and what stays real. The cases replace `cargo`, `rustc`, and
# `rustup` with scripts on a PATH this harness leads with, because the contract clauses
# above are about what the script does with those three programs' answers, and a real
# `cargo check` of this workspace costs between ten minutes and an hour on a developer
# machine. Everything else stays real: case 3 runs the 28 enforcement gates
# `scripts/fix-round-check.sh` names against this repository's own files, so a gate the
# list names but the repository does not hold fails this test rather than being skipped.
#
# WHY THE PINNED VERSION IS READ RATHER THAN WRITTEN. Case 2 and case 3 need a `rustc` that
# agrees with the pin. The harness reads the channel out of `rust-toolchain.toml` at run
# time, so raising the pin does not turn these two cases into copies of case 1.
#
# Usage: bash scripts/tests/fix-round-check/run-tests.sh
# Exit: 0 when every case passes, 1 otherwise.

set -uo pipefail

if ! cd "$(dirname "$0")/../../.."; then
    printf 'run-tests: could not enter the repository root, so no case ran.\n' >&2
    exit 1
fi
REPO_ROOT=$(pwd -P)
SCRIPT="$REPO_ROOT/scripts/fix-round-check.sh"

if [[ ! -f $SCRIPT ]]; then
    printf 'run-tests: %s does not exist, so no case ran.\n' "$SCRIPT" >&2
    exit 1
fi

PIN_CHANNEL=$(sed -nE 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' "$REPO_ROOT/rust-toolchain.toml" | head -n 1)
if [[ -z $PIN_CHANNEL ]]; then
    printf 'run-tests: rust-toolchain.toml names no channel, so the cases have no version to agree with.\n' >&2
    exit 1
fi

REAL_CARGO=$(command -v cargo 2>/dev/null || true)
if [[ -z $REAL_CARGO ]]; then
    printf 'run-tests: cargo is not on PATH, and the stub delegates every subcommand but `check` to it, so no case ran.\n' >&2
    exit 1
fi

FAILURES=0
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# Build a stub directory and run the script with it leading PATH.
#
#   $1 the version string the stub `rustc` reports
#   $2 the exit code the stub `cargo` returns for `cargo check`
#
# The stub `cargo` intercepts `check` alone, returning $2, and hands every other subcommand
# to the real cargo this harness found before it led PATH with the stub. Delegating rather
# than answering keeps `cargo metadata`, `cargo fmt --check`, and the eleven `cargo tree`
# resolutions inside `scripts/check-shipped-feature-graph.sh` reading this repository, so
# case 3 fails when one of them rejects the tree. None of the three compiles anything. The
# stub appends its argument list to `$WORK/<case>/cargo.log`, so a case can assert that no
# cargo command ran.
#
# `rustc` and `rustup` are written as two separate files on purpose:
# `scripts/check-resolved-rustc.sh` skips its comparison only where the two names read one
# file that rustup installed, and two distinct files put it on the path that compares.
run_case() {
    local case_name=$1 rustc_version=$2 cargo_check_rc=$3
    local dir="$WORK/$case_name"
    mkdir -p "$dir/bin"

    cat > "$dir/bin/rustc" <<EOF
#!/usr/bin/env bash
printf 'rustc %s (0000000000 2020-01-01)\n' "$rustc_version"
EOF

    cat > "$dir/bin/rustup" <<'EOF'
#!/usr/bin/env bash
# A rustup that answers nothing. `scripts/check-resolved-rustc.sh` reads a failing
# subcommand as proof of nothing and compares the compiler, which is what these cases want.
exit 1
EOF

    cat > "$dir/bin/cargo" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$dir/cargo.log"
if [ "\$1" = "check" ]; then exit $cargo_check_rc; fi
exec "$REAL_CARGO" "\$@"
EOF

    chmod +x "$dir/bin/rustc" "$dir/bin/rustup" "$dir/bin/cargo"

    PATH="$dir/bin:$PATH" bash "$SCRIPT" scp-clock > "$dir/out.txt" 2>&1
    printf '%s' $? > "$dir/rc.txt"
}

report() {
    local name=$1 ok=$2 detail=$3
    if [[ $ok -eq 0 ]]; then
        printf '  ok   %s\n' "$name"
    else
        printf '  FAIL %s — %s\n' "$name" "$detail" >&2
        FAILURES=$((FAILURES + 1))
    fi
}

printf 'fix-round-check tests (pin %s)\n' "$PIN_CHANNEL"

# ── Case 1: the refusal ──────────────────────────────────────────────────────────────
run_case wrong-toolchain 1.2.3 0
rc=$(cat "$WORK/wrong-toolchain/rc.txt")
if [[ $rc -eq 0 ]]; then
    report "case 1 exits non-zero on a compiler the pin does not name" 1 "the script exited 0"
else
    report "case 1 exits non-zero on a compiler the pin does not name" 0 ""
fi
if [[ -s "$WORK/wrong-toolchain/cargo.log" ]]; then
    report "case 1 starts no cargo command" 1 "the stub cargo ran: $(tr '\n' '|' < "$WORK/wrong-toolchain/cargo.log")"
else
    report "case 1 starts no cargo command" 0 ""
fi
if grep -q '1\.2\.3' "$WORK/wrong-toolchain/out.txt"; then
    report "case 1 names the compiler it found" 0 ""
else
    report "case 1 names the compiler it found" 1 "the output never mentions 1.2.3"
fi

# ── Case 2: the propagation ──────────────────────────────────────────────────────────
run_case failing-compile "$PIN_CHANNEL" 1
rc=$(cat "$WORK/failing-compile/rc.txt")
if [[ $rc -eq 0 ]]; then
    report "case 2 exits non-zero when cargo check fails" 1 "the script exited 0"
else
    report "case 2 exits non-zero when cargo check fails" 0 ""
fi
if grep -q 'compile FAILED' "$WORK/failing-compile/out.txt"; then
    report "case 2 names the compile step as failed" 0 ""
else
    report "case 2 names the compile step as failed" 1 "the summary holds no 'compile FAILED': $(tail -n 3 "$WORK/failing-compile/out.txt")"
fi
if grep -q '^check ' "$WORK/failing-compile/cargo.log"; then
    report "case 2 ran cargo check" 0 ""
else
    report "case 2 ran cargo check" 1 "the stub cargo log holds no check invocation"
fi

# ── Case 3: the control ──────────────────────────────────────────────────────────────
run_case passing "$PIN_CHANNEL" 0
rc=$(cat "$WORK/passing/rc.txt")
if [[ $rc -eq 0 ]]; then
    report "case 3 exits 0 when every step passes" 0 ""
else
    report "case 3 exits 0 when every step passes" 1 "the script exited $rc; output tail: $(tail -n 6 "$WORK/passing/out.txt")"
fi
if grep -q 'compile ok' "$WORK/passing/out.txt" && grep -q 'format ok' "$WORK/passing/out.txt"; then
    report "case 3 names the compile and format steps as passing" 0 ""
else
    report "case 3 names the compile and format steps as passing" 1 "the summary holds neither 'compile ok' nor 'format ok': $(tail -n 3 "$WORK/passing/out.txt")"
fi
if grep -q 'gates 28/28 passed' "$WORK/passing/out.txt"; then
    report "case 3 ran all 28 gates against this repository" 0 ""
else
    report "case 3 ran all 28 gates against this repository" 1 "the summary holds no 'gates 28/28 passed': $(tail -n 3 "$WORK/passing/out.txt")"
fi

# ── Case 4: an unknown crate ─────────────────────────────────────────────────────────
#
# Naming a package the workspace does not hold has to fail rather than check a smaller set,
# because a fix agent that mistypes a crate name would otherwise read a green result that
# compiled none of its edits.
mkdir -p "$WORK/unknown-crate/bin"
cat > "$WORK/unknown-crate/bin/cargo" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$WORK/unknown-crate/cargo.log"
if [ "\$1" = "check" ]; then exit 0; fi
exec "$REAL_CARGO" "\$@"
EOF
cat > "$WORK/unknown-crate/bin/rustc" <<EOF
#!/usr/bin/env bash
printf 'rustc %s (0000000000 2020-01-01)\n' "$PIN_CHANNEL"
EOF
cat > "$WORK/unknown-crate/bin/rustup" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
chmod +x "$WORK/unknown-crate/bin/cargo" "$WORK/unknown-crate/bin/rustc" "$WORK/unknown-crate/bin/rustup"
PATH="$WORK/unknown-crate/bin:$PATH" bash "$SCRIPT" scp-not-a-crate > "$WORK/unknown-crate/out.txt" 2>&1
rc=$?
if [[ $rc -eq 0 ]]; then
    report "case 4 rejects a package the workspace does not hold" 1 "the script exited 0"
else
    report "case 4 rejects a package the workspace does not hold" 0 ""
fi

printf '\n'
if [[ $FAILURES -eq 0 ]]; then
    printf 'fix-round-check tests: every case passed.\n'
    exit 0
fi
printf 'fix-round-check tests: %d assertion(s) failed.\n' "$FAILURES" >&2
exit 1
