#!/usr/bin/env bash
# run-tests.sh — exercise all four checks in `scripts/check-toolchain-wiring.sh` against
# canned repositories.
#
# WHAT THIS TESTS.
#   * Check 1 fails when a file Docker builds from a `rust` base image does not carry the
#     ASSERT-PINNED-RUSTC block verbatim, and stays silent when it does. "Verbatim" means
#     the three lines, in order, unbroken: a file keeping one line of the block, and a file
#     holding all three in reverse order, each fail. Those two cases exist because
#     `grep -F` splits a pattern holding newlines into one pattern per line and matches
#     when any single one matches, so the earlier `grep -qzF` comparison passed both.
#   * Check 1 decides which files Docker builds by path: a basename Docker builds
#     (`Dockerfile`, `Dockerfile.<suffix>`, `<prefix>.Dockerfile`, and the `Containerfile`
#     spellings), and the BUILT_FROM_DOCUMENTATION list. Prose that only quotes a container
#     build carries no assertion, and the cases below cover both directions: a quotation the
#     gate's QUOTES_A_CONTAINER_BUILD list names passes, and one neither list names fails
#     with the message that asks its author which of the two it is. A quotation entry naming
#     a file Docker builds by name is a contradiction the gate reports.
#   * Check 1's classification search matches a whole `FROM` instruction written to
#     Dockerfile's grammar, so a Markdown line opening "from rust sources by uniffi."
#     reports nothing, while a real FROM instruction under a name Docker does not build —
#     with a `--platform` flag, with a digest, or bare — still asks its author to classify
#     the file.
#   * Check 2 fails when the `toolchain` filter does not hold the pin, when an output of
#     the `changes` job does not OR that filter in, when the `fuzz` filter drops `fuzz/**`,
#     when a root-level file is listed in no filter and declared in no exemption, and when a
#     cargo configuration file at any depth is routed by no filter entry. Each job that
#     compiles a crate of this workspace is guarded by such an output, and the `ci` job that
#     aggregates every other job's result counts a skipped job as a pass, so an unrouted
#     change merges unbuilt.
#   * Check 2 reads every workflow whose jobs a paths filter guards, not `ci.yml` alone.
#     The cases write a second workflow that compiles on the pin and hold the gate to
#     reporting the same two defects there; a workflow that declares no paths-filter step
#     and a workflow whose extension GitHub Actions does not run report nothing; and a
#     repository where no workflow declares a paths-filter step fails rather than passing.
#   * Check 3 fails when `.mise.toml` names a Rust version source — a `rust` key under the
#     `tools` table, or `rust-toolchain.toml` registered through
#     `idiomatic_version_file_enable_tools`. mise then exports one `RUSTUP_TOOLCHAIN` for
#     the whole repository, which overrides `fuzz/rust-toolchain.toml` and puts every
#     `cargo fuzz` command on the workspace's stable compiler. One case per TOML spelling
#     of that key holds the gate's parse to all eight spellings mise resolves, and three
#     further cases cover a tool whose name merely holds the letters `rust`, the setting
#     naming a tool other than rust, and a document TOML rejects.
#   * Check 4 fails when `RUSTUP_TOOLCHAIN` holds a value, which replaces the toolchain file
#     entirely, and when the compiler answering in the repository reports a version other
#     than the channel the pin names. It passes, and says so, in the one state where running
#     the compiler would make rustup install the pin: rustup dispatching the `rustc` on
#     PATH, no directory override redirecting the repository, and rustup's toolchain list
#     holding no entry for the channel. Five cases hold that toolchain list empty, or make
#     rustup unable to print it, and put a disagreeing compiler on PATH anyway — under an
#     override on the repository, under an override on its parent, installed by something
#     other than rustup, dispatched by a mise shim that selects a version at exec time,
#     and behind a rustup whose subcommands exit 1 printing nothing — because each one is
#     a state an earlier revision of `scripts/check-resolved-rustc.sh` exited 0 on. One
#     more holds the list empty under an override on an unrelated directory whose path
#     shares a prefix with the repository, which the skip still covers, and one proves the
#     comparison passes a mise-dispatched compiler that answers with the pinned version. Check 4 fails closed
#     when the pin is absent, when the pin names no channel, and when
#     `scripts/check-resolved-rustc.sh` is absent. Every other case in this file runs with a
#     compiler that agrees with the pin, so each one also proves check 4 stays silent then.
#     One state has no case: `rustc` absent from PATH, which a canned repository cannot
#     produce without also taking `bash`, `sed`, and `grep` off PATH.
#
# HOW EACH CASE IS BUILT. `run_case` makes a temporary directory, writes the gate and
# `scripts/check-resolved-rustc.sh` into `scripts/`, runs `git init` so the gate's
# `git grep` search and its file listings have a work tree, and writes the case's `ci.yml`,
# `.mise.toml`, `rust-toolchain.toml`, optional `Dockerfile`, optional extra root file, and
# every path in EXTRA_FILES. It also writes a `rustc` and a `rustup` into `stub-bin/` and
# leads PATH with that directory, so check 4 reads the case's answers rather than the
# toolchain of whoever runs this harness. By default it links `rustc` to `rustup`, which is
# how rustup installs the `rustc` that dispatches through it; two cases link both names to
# a file named `mise`, which is how mise installs its shims; and one case writes
# the two as separate files, which is what a compiler another installer put ahead of
# rustup's directory on PATH looks like. The gate `cd`s to its own parent's parent, so that
# directory becomes its repository root. No canned repository holds
# `templates/personal-relay/README.md`, the one path BUILT_FROM_DOCUMENTATION names, so
# every case also proves that a list entry naming an absent file reports nothing.
#
# Exit 0 when every case matches its expectation, 1 otherwise.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
CHECK="$REPO_ROOT/scripts/check-toolchain-wiring.sh"

if [[ ! -f "$CHECK" ]]; then
    echo "ERROR: $CHECK does not exist" >&2
    exit 1
fi

TMP_PARENT=$(mktemp -d)
trap 'rm -rf "$TMP_PARENT"' EXIT

passed=0
failed=0

# ── The canned repository ────────────────────────────────────────────────────────────
#
# Three generators produce every case's repository, so a case differs from the passing one
# by exactly the defect it names.
#
#   OMIT_OUTPUT     — the name of one `changes` output that reads the `toolchain` filter
#                     literally instead of OR-ing it in, or "" to leave every output whole.
#   OMIT_FILTER     — "<filter> <entry>" drops one path entry from one filter, "<filter> *"
#                     drops the filter and its header, "" drops nothing.
#   MISE_SOURCE     — "none" writes a `.mise.toml` naming no Rust version source, "tools"
#                     writes a `rust` key under `[tools]`, "idiomatic" writes the
#                     `idiomatic_version_file_enable_tools` setting, "absent" writes no file.
#   EXTRA_ROOT_FILE — one more root-level file to create, or "" for none.
#   EXTRA_FILES     — path and producer-function name, in pairs, for files below the root.
#                     `run_case` creates each parent directory.
#   GATE_TRANSFORM  — the name of a function that rewrites the gate on its way into the
#                     canned repository, or "" to copy the gate unchanged. One case uses it
#                     to put a name Docker builds into the gate's own quotation list, which
#                     no repository file can do.
#   PIN_CHANNEL     — the channel the canned `rust-toolchain.toml` names, or "" to write
#                     the file with no `channel` key. PIN_PRESENT="no" writes no file.
#   STUB_RUSTC      — the version the canned `rustc` on PATH reports, or "" to make it
#                     exit 1 printing nothing, which is how a mise shim answers in a
#                     directory whose `.mise.toml` mise has not trusted.
#   STUB_RUSTUP     — the channel the canned `rustup toolchain list` reports as installed,
#                     or "" to report an empty list.
#   STUB_RUSTUP_BROKEN — "yes" makes every canned `rustup` subcommand exit 1 printing
#                     nothing, which is the other half of the untrusted-directory state.
#                     "no" leaves each subcommand answering.
#   STUB_RUSTC_INSTALLER — "rustup" links the canned `rustc` to the canned `rustup`, which
#                     is how rustup installs a `rustc` that dispatches through it. "mise"
#                     renames the canned `rustup` to `mise` and links both `rustc` and
#                     `rustup` to it, which is how mise installs its shims — two names, one
#                     file, and the file is not rustup. "other" writes `rustc` as its own
#                     file, which is what a compiler Homebrew or a distribution package
#                     installed ahead of rustup's directory on PATH looks like.
#   STUB_OVERRIDE   — the directory the canned `rustup override list` reports an override
#                     for: "none" reports "no overrides", "root" reports the canned
#                     repository, "parent" reports the directory holding it, and
#                     "elsewhere" reports an unrelated absolute path.
#   CASE_RUSTUP_TOOLCHAIN — the value of `RUSTUP_TOOLCHAIN` in the gate's environment. The
#                     empty string leaves the variable holding nothing, which the gate reads
#                     the same way it reads an unset variable, so no case has to unset it.
#   COPY_RESOLVED_RUSTC — "no" leaves `scripts/check-resolved-rustc.sh` out of the canned
#                     repository, which is the one defect no file's contents can express.
OMIT_OUTPUT=""
OMIT_FILTER=""
MISE_SOURCE="none"
EXTRA_ROOT_FILE=""
EXTRA_FILES=()
GATE_TRANSFORM=""
PIN_PRESENT="yes"
PIN_CHANNEL="1.98.0"
STUB_RUSTC="1.98.0"
STUB_RUSTUP="1.98.0"
STUB_RUSTUP_BROKEN="no"
STUB_RUSTC_INSTALLER="rustup"
STUB_OVERRIDE="none"
CASE_RUSTUP_TOOLCHAIN=""
COPY_RESOLVED_RUSTC="yes"

RESOLVED_RUSTC_CHECK="$REPO_ROOT/scripts/check-resolved-rustc.sh"
if [[ ! -f "$RESOLVED_RUSTC_CHECK" ]]; then
    echo "ERROR: $RESOLVED_RUSTC_CHECK does not exist" >&2
    exit 1
fi

# The canned repository's rustup and rustc. Check 4 asks rustup which toolchains it holds
# and which directories it overrides before it runs rustc, so a case controls all three
# answers and no stub reaches the network or the real rustup directory.
#
# `emit_stub_rustup` writes one file that answers as both commands, dispatching on the name
# it was invoked under, because that is the shape rustup and mise each install: rustup links
# `~/.cargo/bin/rustc` to `~/.cargo/bin/rustup`, and mise links both of its shims to the
# `mise` binary. Check 4 reads the two names as one file when their bytes match, so a case
# that wants a compiler outside rustup writes `rustc` as its own file instead.
emit_stub_rustup() {
    local override_dir="$1"
    printf '#!/usr/bin/env bash\n'
    printf 'case "$(basename "$0")" in\n'
    if [[ -n $STUB_RUSTC ]]; then
        printf '  rustc) echo "rustc %s (0123456789 2026-08-18)"; exit 0 ;;\n' "$STUB_RUSTC"
    else
        # A mise shim in a directory whose `.mise.toml` mise has not trusted exits 1 and
        # prints its error on stderr, so the canned compiler answers with nothing.
        printf '  rustc) exit 1 ;;\n'
    fi
    printf 'esac\n'
    if [[ $STUB_RUSTUP_BROKEN == "yes" ]]; then
        # The same untrusted-directory state for the `rustup` name: every subcommand
        # exits 1 with empty stdout, which an earlier revision of
        # `scripts/check-resolved-rustc.sh` read as an empty override list and an empty
        # toolchain list.
        printf 'exit 1\n'
    fi
    printf 'if [ "${1:-}" = "toolchain" ] && [ "${2:-}" = "list" ]; then\n'
    if [[ -n $STUB_RUSTUP ]]; then
        printf '  echo "%s-x86_64-unknown-linux-gnu (default)"\n' "$STUB_RUSTUP"
    else
        # bash rejects a `then` with no command after it, and a stub that dies on a syntax
        # error prints nothing, which check 4 would read as rustup holding no toolchain —
        # the very answer the empty list is supposed to give for its own reason. `:` keeps
        # the stub parseable and prints nothing.
        printf '  :\n'
    fi
    printf 'fi\n'
    printf 'if [ "${1:-}" = "override" ] && [ "${2:-}" = "list" ]; then\n'
    if [[ -n $override_dir ]]; then
        printf '  printf "%%s\\t%%s\\n" "%s" "1.97.1-x86_64-unknown-linux-gnu"\n' "$override_dir"
    else
        printf '  echo "no overrides"\n'
    fi
    printf 'fi\n'
}

emit_stub_rustc() {
    printf '#!/usr/bin/env bash\n'
    printf 'echo "rustc %s (0123456789 2026-08-18)"\n' "$STUB_RUSTC"
}

emit_pin() {
    printf '[toolchain]\n'
    [[ -n $PIN_CHANNEL ]] && printf 'channel = "%s"\n' "$PIN_CHANNEL"
    printf 'components = ["clippy", "rustfmt"]\n'
}

# Every output the canned `changes` job declares. `fuzz` is last and is the one output the
# gate exempts, because `fuzz-build` compiles from `fuzz/` on a different toolchain file.
CANNED_OUTPUTS=(rust python typescript typescript-wasm scaffold-typescript-web kotlin swift)

emit_outputs() {
    printf '    outputs:\n'
    local name
    for name in "${CANNED_OUTPUTS[@]}"; do
        if [[ $name == "$OMIT_OUTPUT" ]]; then
            printf '      %s: ${{ steps.filter.outputs.%s }}\n' "$name" "$name"
        else
            printf '      %s: ${{ steps.filter.outputs.%s == '"'"'true'"'"' || steps.filter.outputs.toolchain == '"'"'true'"'"' }}\n' \
                "$name" "$name"
        fi
    done
    printf '      # The exempt lane: it compiles from `fuzz/` on `fuzz/rust-toolchain.toml`.\n'
    printf '      fuzz: ${{ steps.filter.outputs.fuzz }}\n'
}

# emit_filter <name> <entry>...
#
# Writes one filter block. Each block opens with a comment line and a blank line, and the
# entries alternate the two quote styles YAML accepts, so every case reads the gate's
# extractor against all three shapes its `sed` parses.
emit_filter() {
    local name=$1
    shift
    [[ "$name *" == "$OMIT_FILTER" ]] && return 0
    printf '            %s:\n' "$name"
    printf '              # A comment inside a filter block, which the extractor skips.\n'
    printf '\n'
    local entry quote index=0
    for entry in "$@"; do
        [[ "$name $entry" == "$OMIT_FILTER" ]] && continue
        if (( index % 2 == 0 )); then quote="'"; else quote='"'; fi
        printf '              - %s%s%s\n' "$quote" "$entry" "$quote"
        index=$((index + 1))
    done
}

emit_ci() {
    printf 'name: CI\njobs:\n  changes:\n    runs-on: ubuntu-latest\n'
    emit_outputs
    cat <<'YAML'
    steps:
      - uses: dorny/paths-filter@v3
        id: filter
        with:
          filters: |
YAML
    emit_filter toolchain 'rust-toolchain.toml' '.cargo/**'
    # `Dockerfile` and `.mise.toml` are the root-level files every canned repository holds,
    # so the `rust` filter routes the first and the gate's exemption list covers the second.
    emit_filter rust 'crates/**' 'Dockerfile' 'deny.toml'
    emit_filter python 'bindings/python/**'
    emit_filter typescript 'bindings/typescript/**'
    emit_filter typescript-wasm 'bindings/typescript-wasm/**'
    emit_filter scaffold-typescript-web 'scaffolds/typescript-web/**'
    emit_filter kotlin 'bindings/kotlin/**'
    emit_filter swift 'bindings/swift/**'
    emit_filter fuzz 'crates/scp-protocol/**' 'fuzz/**'
    # A second job, so the gate's output reader stops at the end of the `changes` job
    # rather than reading another job's outputs as this one's.
    cat <<'YAML'
  rust-clippy:
    needs: changes
    if: needs.changes.outputs.rust == 'true'
    runs-on: ubuntu-latest
    outputs:
      unrelated: ${{ steps.other.outputs.unrelated }}
    steps:
      - run: cargo clippy
YAML
}

emit_mise() {
    case "$MISE_SOURCE" in
        none)
            printf '# mise names no Rust version source. rustup reads the toolchain file of\n'
            printf '# whichever directory a command runs in.\n[tools]\nbun = "1.3.9"\n"cargo:cargo-fuzz" = "latest"\n'
            ;;
        # The eight TOML spellings that put a `rust` key in the `tools` table. Measured
        # against mise 2026.2.22, `mise current rust` prints 1.97.1 for each one, and the
        # `grep -E '^[[:space:]]*"?rust"?[[:space:]]*='` the gate ran before matched the
        # first three and the last one and reported OK for the middle four.
        tools)
            printf '[tools]\nbun = "1.3.9"\nrust = { version = "stable", targets = "wasm32-unknown-unknown" }\n'
            ;;
        tools-plain)
            printf '[tools]\nbun = "1.3.9"\nrust = "1.97.1"\n'
            ;;
        tools-quoted-key)
            printf '[tools]\nbun = "1.3.9"\n"rust" = "1.97.1"\n'
            ;;
        tools-subtable)
            printf '[tools]\nbun = "1.3.9"\n\n[tools.rust]\nversion = "1.97.1"\n'
            ;;
        tools-quoted-subtable)
            printf '[tools]\nbun = "1.3.9"\n\n[tools."rust"]\nversion = "1.97.1"\n'
            ;;
        tools-dotted-key)
            printf 'tools.rust = "1.97.1"\n\n[env]\nCARGO_TERM_COLOR = "always"\n'
            ;;
        tools-dotted-inside-tools)
            printf '[tools]\nbun = "1.3.9"\nrust.version = "1.97.1"\n'
            ;;
        tools-array)
            printf '[tools]\nbun = "1.3.9"\nrust = ["1.97.1"]\n'
            ;;
        # A tool whose name holds the four letters `rust` and is not the `rust` tool. mise
        # installs a cargo package here, and rustup still resolves each directory.
        tools-name-contains-rust)
            printf '[tools]\nbun = "1.3.9"\n"cargo:rustfilt" = "latest"\n'
            ;;
        idiomatic)
            printf '[settings]\nidiomatic_version_file_enable_tools = ["rust"]\n\n[tools]\nbun = "1.3.9"\n'
            ;;
        idiomatic-top-level)
            printf 'idiomatic_version_file_enable_tools = ["rust"]\n\n[tools]\nbun = "1.3.9"\n'
            ;;
        idiomatic-other-tool)
            printf '[settings]\nidiomatic_version_file_enable_tools = ["node"]\n\n[tools]\nbun = "1.3.9"\n'
            ;;
        malformed)
            printf '[tools\nrust = "1.97.1"\n'
            ;;
        absent) : ;;
        *)
            echo "ERROR: unknown MISE_SOURCE '$MISE_SOURCE'" >&2
            exit 1
            ;;
    esac
}

# A repository whose ci.yml routes everything and whose .mise.toml names no Rust source.
# Cases that are not about check 2 or check 3 use these, so their only finding can come
# from check 1.
routing_ok() {
    # A prefix assignment on a function call persists in the caller in some bash
    # versions and not others, so assign on its own line and leave no doubt about
    # which cases run against the complete filter set.
    OMIT_OUTPUT=""
    OMIT_FILTER=""
    emit_ci
}

mise_ok() {
    MISE_SOURCE="none"
    emit_mise
}

# run_case <name> <expected exit> <required substring|""> <ci producer> <mise producer> [dockerfile producer]
#
# A required substring of "" asserts only that the gate printed no FAIL line, which covers
# every message it can produce.
run_case() {
    local name=$1 want_exit=$2 want_msg=$3 ci_producer=$4 mise_producer=$5 docker_producer=${6:-}
    local root output actual_exit ok=1

    root="$TMP_PARENT/$name"
    mkdir -p "$root/scripts" "$root/.github/workflows" "$root/stub-bin"
    if [[ -n $GATE_TRANSFORM ]]; then
        "$GATE_TRANSFORM" < "$CHECK" > "$root/scripts/$(basename "$CHECK")"
    else
        cp "$CHECK" "$root/scripts/"
    fi
    [[ $COPY_RESOLVED_RUSTC == "yes" ]] && cp "$RESOLVED_RUSTC_CHECK" "$root/scripts/"
    [[ $PIN_PRESENT == "yes" ]] && emit_pin > "$root/rust-toolchain.toml"

    # Check 4 resolves this repository's root with `pwd -P`, and `rustup override list`
    # prints the path rustup canonicalized when someone set the override, so the canned
    # override names the physical path too. On macOS `$TMPDIR` sits under a symlink, and a
    # logical path would miss the comparison the case exists to exercise.
    local root_physical override_dir=""
    root_physical=$(cd "$root" && pwd -P)
    case $STUB_OVERRIDE in
        root) override_dir="$root_physical" ;;
        parent) override_dir=$(dirname "$root_physical") ;;
        elsewhere) override_dir="$root_physical-a-different-checkout" ;;
    esac

    emit_stub_rustup "$override_dir" > "$root/stub-bin/rustup"
    chmod +x "$root/stub-bin/rustup"
    # A stub bash rejects prints nothing and exits non-zero, and check 4 reads an empty
    # `rustup toolchain list` as rustup holding no pinned toolchain, so a syntax error in
    # the stub would make every skip case pass for a reason the case never states.
    if ! bash -n "$root/stub-bin/rustup"; then
        echo "ERROR: the canned rustup for case $name is not valid bash" >&2
        exit 1
    fi
    if [[ $STUB_RUSTC_INSTALLER == "rustup" ]]; then
        ln -sf rustup "$root/stub-bin/rustc"
    elif [[ $STUB_RUSTC_INSTALLER == "mise" ]]; then
        # mise installs both of its shims as links to the `mise` binary, so the canned
        # `rustup` becomes the file `mise` and both names link to it: `cmp` reads one
        # file behind the two names, and the symlink chain from `rustup` ends on a file
        # whose name is not `rustup`.
        mv "$root/stub-bin/rustup" "$root/stub-bin/mise"
        ln -sf mise "$root/stub-bin/rustup"
        ln -sf mise "$root/stub-bin/rustc"
    else
        emit_stub_rustc > "$root/stub-bin/rustc"
        chmod +x "$root/stub-bin/rustc"
    fi
    git -C "$root" init -q
    "$ci_producer" > "$root/.github/workflows/ci.yml"
    "$mise_producer" > "$root/.mise.toml"
    [[ -s "$root/.mise.toml" ]] || rm -f "$root/.mise.toml"
    [[ -n $docker_producer ]] && "$docker_producer" > "$root/Dockerfile"
    [[ -n $EXTRA_ROOT_FILE ]] && printf 'contents\n' > "$root/$EXTRA_ROOT_FILE"
    local i
    if (( ${#EXTRA_FILES[@]} > 0 )); then
        for (( i = 0; i < ${#EXTRA_FILES[@]}; i += 2 )); do
            mkdir -p "$root/$(dirname "${EXTRA_FILES[i]}")"
            "${EXTRA_FILES[i + 1]}" > "$root/${EXTRA_FILES[i]}"
        done
    fi

    # The canned `stub-bin` leads PATH so check 4 reads the case's rustup and rustc rather
    # than the ones running this harness, and `RUSTUP_TOOLCHAIN` carries the case's value
    # rather than whatever the harness's own shell holds.
    output=$(PATH="$root/stub-bin:$PATH" RUSTUP_TOOLCHAIN="$CASE_RUSTUP_TOOLCHAIN" \
        bash "$root/scripts/$(basename "$CHECK")" 2>&1)
    actual_exit=$?

    if [[ -n "$want_msg" ]] && ! grep -Fq -- "$want_msg" <<< "$output"; then
        echo "FAIL [$name]: output missing required substring: $want_msg" >&2
        ok=0
    fi
    if [[ -z "$want_msg" ]] && grep -Fq -- "FAIL" <<< "$output"; then
        echo "FAIL [$name]: output contains a FAIL line, and the case expects none" >&2
        ok=0
    fi
    if [[ $actual_exit -ne $want_exit ]]; then
        echo "FAIL [$name]: gate exited $actual_exit, expected $want_exit" >&2
        ok=0
    fi

    if [[ $ok -eq 1 ]]; then
        echo "PASS [$name]: exit=$actual_exit"
        passed=$((passed + 1))
    else
        echo "---- output begin ----" >&2
        echo "$output" >&2
        echo "---- output end ----" >&2
        failed=$((failed + 1))
    fi
}

# ── Check 2: the pin reaches every lane, and every root file is classified ───────────

run_case "everything-routed" 0 "" routing_ok mise_ok

# One case per output the canned `changes` job declares. Dropping the OR from one output
# leaves that lane skipping on a pull request that raises the pin.
for output_name in "${CANNED_OUTPUTS[@]}"; do
    OMIT_OUTPUT="$output_name"
    OMIT_FILTER=""
    run_case "output-${output_name}-drops-the-toolchain-or" 1 \
        "the 'changes' job's '$output_name' output does not read steps.filter.outputs.toolchain" \
        emit_ci mise_ok
done
OMIT_OUTPUT=""

# The `fuzz` output reads its own filter alone in every case above, and the gate accepts
# that, because `fuzz-build` compiles on `fuzz/rust-toolchain.toml`. The passing case
# already proves it; this comment records that the exemption is deliberate.

# The `toolchain` filter keeps its other entry and drops the pin, which reaches check 2a's
# second branch. The case below drops the filter and its header, which reaches the first.
OMIT_FILTER="toolchain rust-toolchain.toml"
run_case "toolchain-filter-omits-the-pin" 1 \
    "the 'toolchain' paths filter does not list rust-toolchain.toml" emit_ci mise_ok

OMIT_FILTER="toolchain *"
run_case "toolchain-filter-absent-entirely" 1 \
    "declares no 'toolchain:' paths filter with path entries" emit_ci mise_ok

OMIT_FILTER="fuzz fuzz/**"
run_case "fuzz-filter-omits-the-fuzz-tree" 1 \
    "the 'fuzz' paths filter does not list fuzz/**" emit_ci mise_ok

OMIT_FILTER="fuzz *"
run_case "fuzz-filter-absent-entirely" 1 \
    "declares no 'fuzz:' paths filter with path entries" emit_ci mise_ok

OMIT_FILTER="rust *"
run_case "rust-filter-absent-entirely" 1 \
    "declares no 'rust:' paths filter with path entries" emit_ci mise_ok

# A root-level file the `rust` filter stops listing. The gate reads the root of the git
# tree, so it reports the file rather than an entry someone forgot to declare.
OMIT_FILTER="rust deny.toml"
EXTRA_ROOT_FILE="deny.toml"
run_case "root-file-listed-in-no-filter" 1 \
    "deny.toml sits at the repository root and neither the 'rust' filter nor the 'toolchain' filter" \
    emit_ci mise_ok

OMIT_FILTER=""
EXTRA_ROOT_FILE=""

# A root-level file nobody has classified. This is the case a list of required entries
# could not have: the file is new, so no list names it, and the gate finds it by
# enumerating the tree.
EXTRA_ROOT_FILE="clippy-extra.toml"
run_case "new-root-file-is-unclassified" 1 \
    "clippy-extra.toml sits at the repository root" emit_ci mise_ok

# A root-level file the gate's own exemption list declares unread.
EXTRA_ROOT_FILE="README.md"
run_case "root-file-declared-unread" 0 "" emit_ci mise_ok
EXTRA_ROOT_FILE=""

# ── Check 2a/2b: a second workflow whose jobs a paths filter guards ──────────────────
#
# The criterion binds every workflow that guards a job with a paths filter, and the gate
# enumerates them from the tree rather than reading `ci.yml` alone. `.github/workflows/
# docs.yml` is the workflow that made the difference: its `rust-docs` job runs
# `cargo doc --workspace --document-private-items`, which compiles every crate on the
# pinned compiler, and its filter listed no toolchain file, so a pull request that raised
# the pin skipped it while the gate printed OK.
#
# Each case below writes the second workflow through EXTRA_FILES, which puts it below the
# repository root, so check 2c's root-file enumeration does not report it and check 2's
# workflow loop is the only source of a finding.

# A second paths-filtered workflow wired the way `docs.yml` is: one `toolchain` filter
# holding the pin, and the one output OR-ing that filter in.
docs_workflow_routes_the_pin() {
    cat <<'YAML'
name: SDK Docs
jobs:
  changes:
    runs-on: ubuntu-latest
    outputs:
      docs: ${{ steps.filter.outputs.docs == 'true' || steps.filter.outputs.toolchain == 'true' }}
    steps:
      - uses: dorny/paths-filter@v3
        id: filter
        with:
          filters: |
            toolchain:
              - 'rust-toolchain.toml'
              - '.cargo/**'
            docs:
              - 'crates/scp-runtime/src/**'
  rust-docs:
    needs: changes
    if: needs.changes.outputs.docs == 'true'
    runs-on: ubuntu-latest
    steps:
      - run: cargo doc --workspace --document-private-items
YAML
}
EXTRA_FILES=(".github/workflows/docs.yml" docs_workflow_routes_the_pin)
run_case "second-paths-filtered-workflow-routes-the-pin" 0 "" routing_ok mise_ok

# The same workflow with its output reading its own filter alone. A pull request that
# raises the pin then skips `rust-docs`, the one job that runs rustdoc over the workspace.
docs_workflow_output_drops_the_or() {
    cat <<'YAML'
name: SDK Docs
jobs:
  changes:
    runs-on: ubuntu-latest
    outputs:
      docs: ${{ steps.filter.outputs.docs }}
    steps:
      - uses: dorny/paths-filter@v3
        id: filter
        with:
          filters: |
            toolchain:
              - 'rust-toolchain.toml'
              - '.cargo/**'
            docs:
              - 'crates/scp-runtime/src/**'
  rust-docs:
    needs: changes
    if: needs.changes.outputs.docs == 'true'
    runs-on: ubuntu-latest
    steps:
      - run: cargo doc --workspace --document-private-items
YAML
}
EXTRA_FILES=(".github/workflows/docs.yml" docs_workflow_output_drops_the_or)
run_case "second-workflow-output-drops-the-toolchain-or" 1 \
    "docs.yml: the 'changes' job's 'docs' output does not read steps.filter.outputs.toolchain" \
    routing_ok mise_ok

# The same workflow whose `toolchain` filter keeps its other entry and drops the pin.
docs_workflow_omits_the_pin() {
    docs_workflow_routes_the_pin | grep -v "^              - 'rust-toolchain.toml'$"
}
EXTRA_FILES=(".github/workflows/docs.yml" docs_workflow_omits_the_pin)
run_case "second-workflow-toolchain-filter-omits-the-pin" 1 \
    "docs.yml: the 'toolchain' paths filter does not list rust-toolchain.toml" \
    routing_ok mise_ok

# The same workflow with no `toolchain` filter at all, which is how `docs.yml` stood
# before this check read it.
docs_workflow_declares_no_toolchain_filter() {
    docs_workflow_routes_the_pin | grep -v -e "^            toolchain:$" \
        -e "^              - 'rust-toolchain.toml'$" -e "^              - '.cargo/\*\*'$"
}
EXTRA_FILES=(".github/workflows/docs.yml" docs_workflow_declares_no_toolchain_filter)
run_case "second-workflow-declares-no-toolchain-filter" 1 \
    "docs.yml declares no 'toolchain:' paths filter with path entries" routing_ok mise_ok

# A workflow whose jobs no paths filter guards. Every job in it runs on every pull request,
# so a pin change reaches each one and the workflow needs no `toolchain` filter.
workflow_without_a_paths_filter() {
    cat <<'YAML'
name: CodeQL
jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: github/codeql-action/init@v3
      - run: cargo build --workspace
YAML
}
EXTRA_FILES=(".github/workflows/codeql.yml" workflow_without_a_paths_filter)
run_case "workflow-without-a-paths-filter-needs-no-toolchain-filter" 0 "" routing_ok mise_ok

# A disabled workflow. GitHub Actions runs a file under `.github/workflows/` whose
# extension is `.yml` or `.yaml`, so this one starts nothing and the gate leaves it out
# even though it declares a paths-filter step and routes no toolchain file.
EXTRA_FILES=(".github/workflows/pr-review.yml.disabled" docs_workflow_declares_no_toolchain_filter)
run_case "disabled-workflow-is-not-checked" 0 "" routing_ok mise_ok
EXTRA_FILES=()

# No workflow declares a paths-filter step. The gate reports that rather than passing over
# a repository whose routing it could not read.
ci_without_a_paths_filter_step() {
    routing_ok | grep -v '^      - uses: dorny/paths-filter@v3$'
}
run_case "no-workflow-declares-a-paths-filter-step" 1 \
    "no workflow under .github/workflows/ declares a dorny/paths-filter step" \
    ci_without_a_paths_filter_step mise_ok

# ── Check 2c: cargo configuration files, which sit below the root ────────────────────
#
# Cargo reads `.cargo/config.toml` out of every ancestor of the directory a command runs
# in, so each such file sets rustflags for every cargo command below it. The root-file
# enumeration cannot see one, because its path holds a slash; the cases below cover the
# separate enumeration that does. `.cargo/config.toml` at this repository's root selects
# getrandom's wasm backend, and no filter routed it until the case below existed.

cargo_config_wasm_rustflags() {
    cat <<'TOML'
[target.wasm32-unknown-unknown]
rustflags = ['--cfg', 'getrandom_backend="wasm_js"']
TOML
}

EXTRA_FILES=(".cargo/config.toml" cargo_config_wasm_rustflags)
OMIT_FILTER="toolchain .cargo/**"
run_case "cargo-config-routed-by-no-filter" 1 \
    ".cargo/config.toml is a cargo configuration file, which cargo reads for every command run below its directory" \
    emit_ci mise_ok

# The same file with the glob entry restored. `.cargo/**` names no path exactly, so this
# case is what proves the gate matches a `<prefix>/**` entry against a path under it.
OMIT_FILTER=""
run_case "cargo-config-routed-by-a-glob-entry" 0 "" emit_ci mise_ok

# The spelling cargo read before 1.39 and still accepts. The gate enumerates it under the
# same rule, so dropping the glob entry reports it too.
cargo_config_legacy_name() {
    printf '[build]\nrustflags = ["-C", "target-cpu=native"]\n'
}
EXTRA_FILES=(".cargo/config" cargo_config_legacy_name)
OMIT_FILTER="toolchain .cargo/**"
run_case "extensionless-cargo-config-routed-by-no-filter" 1 \
    ".cargo/config is a cargo configuration file" emit_ci mise_ok

# A cargo configuration file under a directory no filter routes. Its rustflags reach every
# cargo command run below `deploy/`, and no lane runs when it changes alone.
OMIT_FILTER=""
EXTRA_FILES=("deploy/.cargo/config.toml" cargo_config_wasm_rustflags)
run_case "nested-cargo-config-under-an-unrouted-directory" 1 \
    "deploy/.cargo/config.toml is a cargo configuration file" emit_ci mise_ok

# A cargo configuration file inside the tree the `rust` filter's `crates/**` entry routes.
# A pull request that edits it runs the Rust lane already, so the gate reports nothing.
EXTRA_FILES=("crates/scp-mls/.cargo/config.toml" cargo_config_wasm_rustflags)
run_case "nested-cargo-config-routed-by-the-rust-filter" 0 "" emit_ci mise_ok
EXTRA_FILES=()

# ── Check 3: mise names no Rust version source ───────────────────────────────────────
#
# Every spelling below puts the key `rust` in the table `tools`, and mise 2026.2.22
# resolves each one. The gate parses the document and reads that key, so one case per
# spelling holds the parse to the whole set rather than to the four a line matcher read.

# The one producer every case below passes to `run_case`, and the global it reads. Naming
# the spelling in a global rather than in a closure keeps each case one line long.
MISE_SOURCE_UNDER_TEST=""
emit_mise_under_test() {
    MISE_SOURCE="$MISE_SOURCE_UNDER_TEST"
    emit_mise
}

# mise_source_case <spelling> <case name> <expected exit> <required substring|"">
mise_source_case() {
    MISE_SOURCE_UNDER_TEST=$1
    run_case "$2" "$3" "$4" routing_ok emit_mise_under_test
}

names_a_rust_key="gives the rust tool a version: its 'tools' table holds a 'rust' key"

mise_source_case tools "mise-names-a-rust-tool-inline-table" 1 "$names_a_rust_key"
mise_source_case tools-plain "mise-names-a-rust-tool-plain-string" 1 "$names_a_rust_key"
mise_source_case tools-quoted-key "mise-names-a-rust-tool-quoted-key" 1 "$names_a_rust_key"
mise_source_case tools-subtable "mise-names-a-rust-tool-in-a-subtable" 1 "$names_a_rust_key"
mise_source_case tools-quoted-subtable "mise-names-a-rust-tool-in-a-quoted-subtable" 1 "$names_a_rust_key"
mise_source_case tools-dotted-key "mise-names-a-rust-tool-through-a-dotted-key" 1 "$names_a_rust_key"
mise_source_case tools-dotted-inside-tools "mise-names-a-rust-tool-dotted-inside-tools" 1 "$names_a_rust_key"
mise_source_case tools-array "mise-names-a-rust-tool-as-an-array" 1 "$names_a_rust_key"

# A tool name holding the letters `rust` is not the `rust` tool, and the gate reads the key
# rather than the letters.
mise_source_case tools-name-contains-rust "mise-names-a-tool-whose-name-contains-rust" 0 ""

registers_the_pin="registers rust-toolchain.toml as a mise version source"
mise_source_case idiomatic "mise-registers-rust-toolchain-toml-under-settings" 1 "$registers_the_pin"
mise_source_case idiomatic-top-level "mise-registers-rust-toolchain-toml-at-the-top-level" 1 "$registers_the_pin"

# The same setting naming a tool that is not rust. rustup still resolves each directory.
mise_source_case idiomatic-other-tool "mise-registers-an-idiomatic-file-for-another-tool" 0 ""

# A document no TOML parser accepts. The gate reports the parse failure rather than
# passing over a file it could not read.
mise_source_case malformed "mise-config-is-not-a-toml-document" 1 \
    "is not a TOML document tomllib accepts"

mise_absent() {
    MISE_SOURCE="absent"
    emit_mise
}
run_case "mise-config-absent" 1 \
    ".mise.toml does not exist" routing_ok mise_absent

# ── Check 1: every container build asserts the compiler it resolved ──────────────────
#
# The block below is written out literally rather than read from the gate, so that
# changing the gate's ASSERT_BLOCK without changing these cases fails here.

docker_carries_the_block() {
    cat <<'DOCKER'
FROM rust:slim-bookworm AS chef
WORKDIR /app
COPY rust-toolchain.toml rust-toolchain.toml
RUN pin="$(sed -nE 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' rust-toolchain.toml | head -n 1)"; \
    got="$(rustc --version | cut -d' ' -f2)"; \
    [ -n "$pin" ] && [ "$got" = "$pin" ] || { echo "image resolved rustc '$got'; rust-toolchain.toml names '$pin'" >&2; exit 1; }
RUN cargo install cargo-chef

FROM chef AS builder
COPY . .
RUN cargo build --release
DOCKER
}
run_case "container-carries-the-assertion" 0 "" routing_ok mise_ok docker_carries_the_block

# A whole-context copy to a destination other than `.`. A check that read COPY lines
# rejected this legitimate recipe; requiring the assertion block accepts it, because the
# block is what proves the compiler.
docker_copies_context_elsewhere() {
    cat <<'DOCKER'
FROM rust:bookworm AS builder
WORKDIR /build
COPY . /build
RUN pin="$(sed -nE 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' rust-toolchain.toml | head -n 1)"; \
    got="$(rustc --version | cut -d' ' -f2)"; \
    [ -n "$pin" ] && [ "$got" = "$pin" ] || { echo "image resolved rustc '$got'; rust-toolchain.toml names '$pin'" >&2; exit 1; }
RUN cargo build --release
DOCKER
}
run_case "container-copies-context-to-another-path" 0 "" routing_ok mise_ok \
    docker_copies_context_elsewhere

# The block ends the file, with no trailing content after its last line. `$(cat file)`
# drops the trailing newline, so the gate drops the one the heredoc puts on ASSERT_BLOCK;
# this case fails if it stops doing that.
docker_ends_with_the_block() {
    cat <<'DOCKER'
FROM rust:slim-bookworm AS builder
WORKDIR /app
COPY rust-toolchain.toml rust-toolchain.toml
RUN pin="$(sed -nE 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' rust-toolchain.toml | head -n 1)"; \
    got="$(rustc --version | cut -d' ' -f2)"; \
    [ -n "$pin" ] && [ "$got" = "$pin" ] || { echo "image resolved rustc '$got'; rust-toolchain.toml names '$pin'" >&2; exit 1; }
DOCKER
}
run_case "container-ends-with-the-assertion" 0 "" routing_ok mise_ok docker_ends_with_the_block

docker_omits_the_block() {
    cat <<'DOCKER'
FROM rust:slim-bookworm AS builder
WORKDIR /app
COPY rust-toolchain.toml rust-toolchain.toml
RUN cargo build --release
DOCKER
}
run_case "container-omits-the-assertion" 1 \
    "does not carry the ASSERT-PINNED-RUSTC block verbatim" routing_ok mise_ok \
    docker_omits_the_block

# The assertion gutted down to one of its three lines, with the comparison and the
# `exit 1` replaced by an echo. `grep -qzF` matched this, because it split the three-line
# pattern into three patterns and matched on the one line that survived.
docker_keeps_one_line_of_the_block() {
    cat <<'DOCKER'
FROM rust:slim-bookworm AS builder
WORKDIR /app
COPY rust-toolchain.toml rust-toolchain.toml
RUN pin="$(sed -nE 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' rust-toolchain.toml | head -n 1)"; \
    got="$(rustc --version | cut -d' ' -f2)"; \
    echo "resolved $got, pin $pin"
RUN cargo build --release
DOCKER
}
run_case "container-keeps-one-line-of-the-assertion" 1 \
    "does not carry the ASSERT-PINNED-RUSTC block verbatim" routing_ok mise_ok \
    docker_keeps_one_line_of_the_block

# All three lines present and out of order, which no shell would run as the assertion.
# `grep -qzF` matched this too, because its split patterns carry no order.
docker_reverses_the_block() {
    cat <<'DOCKER'
FROM rust:slim-bookworm AS builder
WORKDIR /app
COPY rust-toolchain.toml rust-toolchain.toml
RUN [ -n "$pin" ] && [ "$got" = "$pin" ] || { echo "image resolved rustc '$got'; rust-toolchain.toml names '$pin'" >&2; exit 1; }
    got="$(rustc --version | cut -d' ' -f2)"; \
RUN pin="$(sed -nE 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' rust-toolchain.toml | head -n 1)"; \
RUN cargo build --release
DOCKER
}
run_case "container-reverses-the-assertion-lines" 1 \
    "does not carry the ASSERT-PINNED-RUSTC block verbatim" routing_ok mise_ok \
    docker_reverses_the_block

# The pin reaches a stage that never compiles. A check that read COPY lines passed this;
# requiring the assertion in the file catches it, and the assertion itself would fail the
# build in the stage that does compile.
docker_pin_reaches_only_the_runtime_stage() {
    cat <<'DOCKER'
FROM rust:slim-bookworm AS builder
WORKDIR /app
COPY crates crates
RUN cargo build --release

FROM debian:bookworm-slim AS runtime
COPY rust-toolchain.toml /doc/rust-toolchain.toml
DOCKER
}
run_case "container-pins-only-a-stage-that-never-compiles" 1 \
    "does not carry the ASSERT-PINNED-RUSTC block verbatim" routing_ok mise_ok \
    docker_pin_reaches_only_the_runtime_stage

# A stage that inherits from an earlier one, or from a non-rust image, names no `rust`
# image and needs no assertion of its own.
docker_names_no_rust_image() {
    cat <<'DOCKER'
FROM debian:bookworm-slim AS runtime
COPY --from=builder /app/target/release/scp-relay /usr/local/bin/scp-relay
DOCKER
}
run_case "container-names-no-rust-image" 0 "" routing_ok mise_ok docker_names_no_rust_image

# A `Dockerfile` whose keyword carries leading whitespace and lowercase letters. Docker
# accepts both, so the gate's assertion requirement has to reach this file. The name rule
# discovers it whatever its `FROM` lines look like, and the matcher then reads them.
docker_indents_a_lowercase_from() {
    cat <<'DOCKER'
  from rust:slim-bookworm AS builder
WORKDIR /app
COPY rust-toolchain.toml rust-toolchain.toml
RUN cargo build --release
DOCKER
}
run_case "container-indents-a-lowercase-from" 1 \
    "does not carry the ASSERT-PINNED-RUSTC block verbatim" routing_ok mise_ok \
    docker_indents_a_lowercase_from

# ── Check 1: which files Docker builds, and which only quote one ─────────────────────

# The names `docker build` reads. Each lives below the repository root, so check 2c's
# root-file enumeration does not report it and check 1 is the only source of a finding.
EXTRA_FILES=("deploy/Dockerfile.relay" docker_omits_the_block)
run_case "suffixed-dockerfile-name-needs-the-assertion" 1 \
    "does not carry the ASSERT-PINNED-RUSTC block verbatim" routing_ok mise_ok

EXTRA_FILES=("deploy/relay.Dockerfile" docker_omits_the_block)
run_case "prefixed-dockerfile-name-needs-the-assertion" 1 \
    "does not carry the ASSERT-PINNED-RUSTC block verbatim" routing_ok mise_ok

EXTRA_FILES=("deploy/Containerfile" docker_omits_the_block)
run_case "containerfile-name-needs-the-assertion" 1 \
    "does not carry the ASSERT-PINNED-RUSTC block verbatim" routing_ok mise_ok
EXTRA_FILES=()

# Prose quoting a container build, which nobody builds. An earlier revision of the gate
# searched every file in the tree for a line-initial `FROM` and demanded the assertion from
# whatever it found, so this document failed a required check that runs on every pull
# request. The gate now asks its author to classify it.
doc_quotes_a_container_build() {
    cat <<'DOC'
# How the relay image resolves its compiler

The builder stage opens on a Rust base image:

```dockerfile
FROM rust:bookworm AS builder
WORKDIR /build
```

The tag names a Debian release, so the copied-in pin decides the compiler.
DOC
}

EXTRA_FILES=(".docs/adrs/adr-099-container-build.md" doc_quotes_a_container_build)
run_case "prose-quoting-a-container-build-is-unclassified" 1 \
    "holds a FROM line naming a 'rust' base image, and neither list in this gate classifies it" \
    routing_ok mise_ok

# The same document at the one path the gate's QUOTES_A_CONTAINER_BUILD list names. The
# gate reads that list, so the document needs no assertion and reports nothing.
EXTRA_FILES=("scripts/tests/toolchain-wiring/run-tests.sh" doc_quotes_a_container_build)
run_case "prose-declared-a-quotation-carries-no-assertion" 0 "" routing_ok mise_ok
EXTRA_FILES=()

# Prose whose block a reader is told to save and build. `templates/personal-relay/README.md`
# is the path BUILT_FROM_DOCUMENTATION names, so the assertion requirement reaches it.
doc_recipe_without_the_assertion() {
    cat <<'DOC'
# Personal relay

Save the block below as `Dockerfile`, then build it from the repository root.

```dockerfile
FROM rust:bookworm AS builder
WORKDIR /build
COPY . .
RUN cargo build --release
```
DOC
}
EXTRA_FILES=("templates/personal-relay/README.md" doc_recipe_without_the_assertion)
run_case "documented-recipe-without-the-assertion" 1 \
    "does not carry the ASSERT-PINNED-RUSTC block verbatim" routing_ok mise_ok

doc_recipe_with_the_assertion() {
    cat <<'DOC'
# Personal relay

Save the block below as `Dockerfile`, then build it from the repository root.

```dockerfile
FROM rust:bookworm AS builder
WORKDIR /build
COPY . .
RUN pin="$(sed -nE 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' rust-toolchain.toml | head -n 1)"; \
    got="$(rustc --version | cut -d' ' -f2)"; \
    [ -n "$pin" ] && [ "$got" = "$pin" ] || { echo "image resolved rustc '$got'; rust-toolchain.toml names '$pin'" >&2; exit 1; }
RUN cargo build --release
```
DOC
}
EXTRA_FILES=("templates/personal-relay/README.md" doc_recipe_with_the_assertion)
run_case "documented-recipe-with-the-assertion" 0 "" routing_ok mise_ok
EXTRA_FILES=()

# A SQL query whose `FROM` clause opens a line. The matcher requires the token `rust`
# followed by a tag, a digest, ` AS <name>`, or the end of the line, so `rust_crates` does
# not match and the file needs no entry in either list.
sql_selects_from_a_table() {
    cat <<'SQL'
SELECT id, name
FROM rust_crates
WHERE published_at > now();
SQL
}
EXTRA_FILES=("crates/scp-node/queries/crates.sql" sql_selects_from_a_table)
run_case "sql-from-clause-is-not-a-container-build" 0 "" routing_ok mise_ok
EXTRA_FILES=()

# ── Check 1: an English sentence is not a FROM instruction ───────────────────────────
#
# Docker's FROM instruction permits nothing after the image reference but `AS <name>`, so
# the matcher anchors at the end of the line. An earlier expression ended at
# `([[:space:]]|$)` and accepted any text after the image, so a Markdown line opening
# "from rust sources by uniffi." failed `enforcement / toolchain wiring` — the check every
# pull request runs — and its author's ways out were to declare the prose a quotation of a
# container build or to rewrap the paragraph. The phrase "from Rust" opens a sentence in
# fifteen tracked files of this repository, and where a paragraph wraps decides whether one
# of them starts a line.
prose_sentence_opens_with_from_rust() {
    cat <<'DOC'
# How the Swift bindings are produced

`build-xcframework.sh` generates the Swift API
from rust sources by uniffi.
The generated files are not checked in.
DOC
}
EXTRA_FILES=(".docs/standards/swift-bindings.md" prose_sentence_opens_with_from_rust)
run_case "prose-sentence-opening-with-from-rust-is-not-a-container-build" 0 "" \
    routing_ok mise_ok
EXTRA_FILES=()

# The narrowing drops no container build, and these three cases hold the matcher to that.
# Each writes a real FROM instruction into a file whose name Docker does not build, so the
# gate reaches it through the classification search alone and asks its author to classify
# it. A regression in the expression turns each of them green.
container_build_under_an_unconventional_name() {
    cat <<'DOCKER'
FROM rust:slim-bookworm AS builder
WORKDIR /app
RUN cargo build --release
DOCKER
}
EXTRA_FILES=("deploy/relay-image" container_build_under_an_unconventional_name)
run_case "container-build-under-an-unconventional-name-is-unclassified" 1 \
    "holds a FROM line naming a 'rust' base image, and neither list in this gate classifies it" \
    routing_ok mise_ok

container_build_with_a_platform_flag() {
    printf 'FROM --platform=$BUILDPLATFORM rust:1.98.0-slim-bookworm AS builder\n'
}
EXTRA_FILES=("deploy/relay-image" container_build_with_a_platform_flag)
run_case "container-build-with-a-platform-flag-is-unclassified" 1 \
    "holds a FROM line naming a 'rust' base image, and neither list in this gate classifies it" \
    routing_ok mise_ok

container_build_pinned_by_digest() {
    printf 'FROM ghcr.io/library/rust@sha256:9f2c1e4b7a\n'
}
EXTRA_FILES=("deploy/relay-image" container_build_pinned_by_digest)
run_case "container-build-pinned-by-digest-is-unclassified" 1 \
    "holds a FROM line naming a 'rust' base image, and neither list in this gate classifies it" \
    routing_ok mise_ok
EXTRA_FILES=()

# The gate's quotation list naming a file Docker builds by name. No repository file can
# produce this case, so the transform below writes the entry into the gate itself. The gate
# reports the contradiction, and the name rule still demands the assertion from that file.
gate_declares_a_dockerfile_a_quotation() {
    awk '{ print } /^read -r -d .. QUOTES_A_CONTAINER_BUILD/ { print "Dockerfile" }'
}
GATE_TRANSFORM=gate_declares_a_dockerfile_a_quotation
run_case "quotation-list-cannot-name-a-file-docker-builds" 1 \
    "whose basename is a name Docker builds" routing_ok mise_ok docker_omits_the_block
GATE_TRANSFORM=""

# ── Check 4: the compiler this shell resolves ────────────────────────────────────────
#
# Every case above runs with a canned rustc reporting the canned pin's channel and a canned
# rustup holding it, so each one also proves that check 4 stays silent when the compiler
# agrees. The cases below vary one answer at a time.

# `RUSTUP_TOOLCHAIN` replaces the toolchain file entirely, so the gate fails on the variable
# holding a value. This case's rustc reports the pinned version, which is what makes the
# case prove that the version the variable selects does not excuse it: the pin's components
# and targets are gone either way.
CASE_RUSTUP_TOOLCHAIN="stable"
run_case "rustup-toolchain-set-while-the-compiler-matches" 1 \
    "RUSTUP_TOOLCHAIN=stable is set in this environment" routing_ok mise_ok
CASE_RUSTUP_TOOLCHAIN=""

# The compiler answers with another version, which is the drift that blocked the merge
# queue: a local clippy run reports nothing the pinned release's clippy reports.
STUB_RUSTC="1.97.1"
run_case "resolved-compiler-disagrees-with-the-pin" 1 \
    "rustc in this directory is 1.97.1, and rust-toolchain.toml names 1.98.0" \
    routing_ok mise_ok
STUB_RUSTC="1.98.0"

# rustup dispatches the rustc on PATH, no override redirects this directory, and rustup
# holds no pinned toolchain, so no compiler has resolved here and rustup installs the channel
# the file names on first use. The gate passes and says which of the two it did, so a reader
# never takes the skip for a comparison. This is the state of a CI runner for a job that
# compiles nothing, and the canned rustc reports a mismatching version to prove the gate
# never ran it.
STUB_RUSTUP=""
STUB_RUSTC="1.97.1"
run_case "rustup-holds-no-pinned-toolchain" 0 \
    "rustup holds no 1.98.0 toolchain" routing_ok mise_ok
STUB_RUSTUP="1.98.0"
STUB_RUSTC="1.98.0"

# ── The states the skip must not swallow ─────────────────────────────────────────────
#
# Each case below holds rustup's toolchain list empty, or makes rustup unable to print it,
# which is what one or another earlier revision of `scripts/check-resolved-rustc.sh` read
# as "no compiler has resolved here". In each one a compiler the pin does not name answers
# anyway, or no compiler can answer at all, so the gate compares rather than skipping.

# `rustup override set` selects a toolchain for a directory and its children ahead of the
# toolchain file, and installs it as it sets it, so the checkout resolves a compiler that
# rustup's toolchain list does not hold under the pinned channel.
STUB_RUSTUP=""
STUB_RUSTC="1.97.1"
STUB_OVERRIDE="root"
run_case "directory-override-selects-a-compiler-the-pin-does-not-name" 1 \
    "rustc in this directory is 1.97.1, and rust-toolchain.toml names 1.98.0" \
    routing_ok mise_ok
STUB_OVERRIDE="none"
STUB_RUSTUP="1.98.0"
STUB_RUSTC="1.98.0"

# An override on a parent directory reaches every directory below it, which is the sentence
# `rustup help override` states: "any time `rustc` or `cargo` is run inside that directory,
# or one of its child directories, the override toolchain will be invoked."
STUB_RUSTUP=""
STUB_RUSTC="1.97.1"
STUB_OVERRIDE="parent"
run_case "override-on-a-parent-directory-reaches-this-one" 1 \
    "rustc in this directory is 1.97.1, and rust-toolchain.toml names 1.98.0" \
    routing_ok mise_ok
STUB_OVERRIDE="none"
STUB_RUSTUP="1.98.0"
STUB_RUSTC="1.98.0"

# An override on an unrelated directory whose path shares a prefix with this one leaves this
# directory alone, so the skip still holds. Without this case a check that matched the path
# as a bare prefix would pass every other case in this file.
STUB_RUSTUP=""
STUB_RUSTC="1.97.1"
STUB_OVERRIDE="elsewhere"
run_case "override-on-an-unrelated-directory-leaves-this-one-alone" 0 \
    "rustup holds no 1.98.0 toolchain" routing_ok mise_ok
STUB_OVERRIDE="none"
STUB_RUSTUP="1.98.0"
STUB_RUSTC="1.98.0"

# A compiler some other installer put ahead of rustup's directory on PATH answers without
# consulting rustup and downloads nothing, so the gate reads its version rather than reading
# rustup's empty toolchain list as an absent compiler.
STUB_RUSTUP=""
STUB_RUSTC="1.97.1"
STUB_RUSTC_INSTALLER="other"
run_case "compiler-outside-rustup-answers-with-another-version" 1 \
    "rustc in this directory is 1.97.1, and rust-toolchain.toml names 1.98.0" \
    routing_ok mise_ok
STUB_RUSTC_INSTALLER="rustup"
STUB_RUSTUP="1.98.0"
STUB_RUSTC="1.98.0"

# A mise shim dispatches both names through one file, and that file selects a toolchain of
# its own each time it runs: it reads mise's configuration at that moment and exports
# `RUSTUP_TOOLCHAIN` into the compiler it executes, which the gate's own environment never
# shows. The gate's environment here holds no `RUSTUP_TOOLCHAIN`, the canned repository's
# `.mise.toml` names no Rust version, rustup's toolchain list is empty, and no override
# redirects the directory — every fact of the skip except the dispatcher's name — and the
# compiler still answers with a version the pin does not name, because a mise configuration
# in an ancestor directory names it. An earlier revision of
# `scripts/check-resolved-rustc.sh` accepted any one file behind both names, took the skip,
# and exited 0 in this state.
STUB_RUSTC_INSTALLER="mise"
STUB_RUSTUP=""
STUB_RUSTC="1.97.1"
run_case "mise-shim-selects-a-version-at-exec-time" 1 \
    "rustc in this directory is 1.97.1, and rust-toolchain.toml names 1.98.0" \
    routing_ok mise_ok
STUB_RUSTC_INSTALLER="rustup"
STUB_RUSTUP="1.98.0"
STUB_RUSTC="1.98.0"

# The same mise dispatch with a compiler that answers the pinned version. The gate never
# skips behind a dispatcher that is not rustup, so it compares, and the comparison passes —
# a machine that runs every command through mise shims is not failed for the shims alone.
STUB_RUSTC_INSTALLER="mise"
STUB_RUSTUP=""
STUB_RUSTC="1.98.0"
run_case "mise-shim-resolves-the-pinned-version" 0 \
    "rustc 1.98.0 in this directory is the version rust-toolchain.toml names" \
    routing_ok mise_ok
STUB_RUSTC_INSTALLER="rustup"
STUB_RUSTUP="1.98.0"
STUB_RUSTC="1.98.0"

# Every rustup subcommand exits 1 printing nothing, and so does `rustc`, which is the
# state mise puts every shimmed command into in a directory whose `.mise.toml` it has not
# trusted — where every fresh `git worktree add` of this repository starts. An earlier
# revision of `scripts/check-resolved-rustc.sh` read the empty stdout as an empty override
# list and an empty toolchain list, took the skip, and exited 0 on a machine whose Rust
# tooling could not run at all. The gate compares instead, and the comparison reports that
# no version was readable.
STUB_RUSTUP_BROKEN="yes"
STUB_RUSTC=""
run_case "rustup-subcommands-fail-and-no-compiler-answers" 1 \
    "rustc ran but printed no version this script could read" \
    routing_ok mise_ok
STUB_RUSTUP_BROKEN="no"
STUB_RUSTC="1.98.0"

# The rustup subcommands fail the same way while a compiler answers with a version the pin
# does not name, so the comparison the failing subcommands force reports the mismatch.
STUB_RUSTUP_BROKEN="yes"
STUB_RUSTC="1.97.1"
run_case "rustup-subcommands-fail-while-a-compiler-disagrees" 1 \
    "rustc in this directory is 1.97.1, and rust-toolchain.toml names 1.98.0" \
    routing_ok mise_ok
STUB_RUSTUP_BROKEN="no"
STUB_RUSTC="1.98.0"

# The pin is unreadable. Both cases fail closed rather than reporting a compiler that
# matches nothing.
PIN_PRESENT="no"
run_case "pin-file-absent" 1 \
    "rust-toolchain.toml does not exist, so this directory names no Rust version" \
    routing_ok mise_ok
PIN_PRESENT="yes"

PIN_CHANNEL=""
run_case "pin-file-names-no-channel" 1 \
    "rust-toolchain.toml names no [toolchain] channel" routing_ok mise_ok
PIN_CHANNEL="1.98.0"

# The script holding the comparison is absent. The gate reports that rather than counting
# check 4 as passed, which is what `.docs/lessons/coverage-gates-must-fail-closed.md`
# requires of every check here.
COPY_RESOLVED_RUSTC="no"
run_case "resolved-rustc-check-absent" 1 \
    "scripts/check-resolved-rustc.sh does not exist" routing_ok mise_ok
COPY_RESOLVED_RUSTC="yes"

echo ""
echo "toolchain-wiring cases: $passed passed, $failed failed"
[[ $failed -eq 0 ]]
