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
#
#   * Check 4 fails when the workflow's verdict job — the job whose own `if:` names one of
#     GitHub Actions' four status check functions — leaves a job out of its `needs:` list,
#     reads no result for a job it does name, names a job the workflow does not declare,
#     reads a result for a name no job carries, or declares no `needs:` the gate can read.
#     Two such jobs in one workflow is a case of its own, because the gate cannot then tell
#     which one branch protection requires. Cases cover the two remaining `needs:`
#     spellings GitHub Actions accepts — a flow sequence and a single scalar — and every
#     other case in this file writes a `ci.yml` declaring no verdict job at all, which is
#     the shape check 4 leaves alone. A workflow whose only job is its verdict job gets a
#     case of its own: the set of other jobs is empty there, and the gate has to report the
#     unknown names rather than abort on a `grep` that matched nothing.
#   * Checks 2e and 4 read the parsed workflow, so a rewording GitHub Actions reads
#     identically produces the same verdict as the spelling it replaces. One case per
#     rewording: `${{ always() }}`, `always() && …`, a folded scalar holding `always()`,
#     `${{ !cancelled() }}`, `${{ !failure() }}`, and a quoted `"if":` key each name a
#     verdict job; a trailing comment on the `ci:` header and job keys written at six
#     spaces leave that job in the listing; `${{ join(needs.*.result, ' ') }}` reads the
#     result of every job the `needs:` list names; and a paths-filtered job whose `if:`
#     sits below its `steps:` still names its lane. An `if:` naming none of the four status
#     check functions names no verdict job, which is the one direction that stays silent. A
#     workflow no YAML parser accepts fails rather than passing.
#
# HOW EACH CASE IS BUILT. `run_case` makes a temporary directory, writes the gate into
# `scripts/`, runs `git init` so the gate's `git grep` search and its file listings have a
# work tree, and writes the case's `ci.yml`, `.mise.toml`, optional `Dockerfile`, optional
# extra root file, and every path in EXTRA_FILES. The gate `cd`s to its own parent's parent,
# so that directory becomes its repository root. No canned repository holds
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
#   SCRIPT_JOB      — "<lane>[ <lane>…]|<line>" appends one more job to the canned `ci.yml`,
#                     guarded by an `if:` that ORs those lanes and holding `<line>` as its
#                     one step. "" appends no such job. Check 2e reads the pair of that
#                     job's lanes and the `scripts/` paths its lines name.
#   SWIFT_FILTER_EXTRA — one more path entry appended to the canned `swift` filter, or ""
#                     for none. A case routes the script it appended by setting this.
#   IF_PLACEMENT — where that job writes its own `if:` key: "above" puts it before
#                     `steps:`, "below-steps" after the last step. GitHub Actions reads the
#                     same job either way, so a case that changes only this must produce
#                     the same verdict.
OMIT_OUTPUT=""
OMIT_FILTER=""
MISE_SOURCE="none"
EXTRA_ROOT_FILE=""
EXTRA_FILES=()
GATE_TRANSFORM=""
SCRIPT_JOB=""
SWIFT_FILTER_EXTRA=""
IF_PLACEMENT="above"

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
    if [[ -n $SWIFT_FILTER_EXTRA ]]; then
        emit_filter swift 'bindings/swift/**' "$SWIFT_FILTER_EXTRA"
    else
        emit_filter swift 'bindings/swift/**'
    fi
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
    emit_script_job
}

# The extra paths-filtered job check 2e reads. `SCRIPT_JOB` holds the lanes its `if:` ORs
# and the one step line it carries, separated by `|`.
emit_script_job() {
    [[ -n $SCRIPT_JOB ]] || return 0
    local lanes=${SCRIPT_JOB%%|*} step=${SCRIPT_JOB#*|} lane condition=""
    for lane in $lanes; do
        if [[ -n $condition ]]; then
            condition="$condition || "
        fi
        condition="${condition}needs.changes.outputs.$lane == 'true'"
    done
    printf '  gate-job:\n    needs: changes\n'
    # No lane means no `if:` at all, which is the job shape check 2e leaves alone: a job
    # nothing guards runs on every pull request.
    if [[ -n $condition && $IF_PLACEMENT == "above" ]]; then
        printf '    if: %s\n' "$condition"
    fi
    printf '    runs-on: ubuntu-latest\n    steps:\n%s\n' "$step"
    # YAML mapping keys carry no required order, so GitHub Actions reads the same job when
    # its `if:` sits below `steps:`. A gate that collected lanes from the lines above
    # `steps:` collected none here and dropped the job from check 2e.
    if [[ -n $condition && $IF_PLACEMENT == "below-steps" ]]; then
        printf '    if: %s\n' "$condition"
    fi
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
    mkdir -p "$root/scripts" "$root/.github/workflows"
    if [[ -n $GATE_TRANSFORM ]]; then
        "$GATE_TRANSFORM" < "$CHECK" > "$root/scripts/$(basename "$CHECK")"
    else
        cp "$CHECK" "$root/scripts/"
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

    output=$(bash "$root/scripts/$(basename "$CHECK")" 2>&1)
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

# ── Check 2e: the scripts a paths-filtered job runs ──────────────────────────────────
#
# A script a filtered job runs is a file whose text decides what that job asserts, so a
# pull request that edits only the script has to make the job run. Two jobs in `ci.yml`
# failed that when this check was written: `swift-bindings-fresh` ran
# `scripts/check-swift-bindings-fresh.sh` behind a `swift` filter listing no `scripts/`
# path, and `python-lint` ran `scripts/check-python-falsy-optionals.py` behind a `python`
# filter listing none either.

# The defect itself: one lane guards the job, and that lane lists no `scripts/` path.
SCRIPT_JOB="swift|      - run: bash scripts/check-swift-bindings-fresh.sh"
run_case "filtered-job-runs-a-script-no-filter-routes" 1 \
    "the 'gate-job' job names scripts/check-swift-bindings-fresh.sh, and none of the paths filters that guard it (swift) lists that path" \
    emit_ci mise_ok

# The same job with the script listed in the filter that guards it.
SWIFT_FILTER_EXTRA="scripts/check-swift-bindings-fresh.sh"
run_case "filtered-job-script-listed-in-its-own-filter" 0 "" emit_ci mise_ok
SWIFT_FILTER_EXTRA=""

# A job whose `if:` ORs three lanes runs when ANY of them is true, so one lane listing the
# path is enough. `bridge-parity-kotlin` in `ci.yml` has that shape.
SCRIPT_JOB="python kotlin swift|      - run: bash scripts/check-swift-bindings-fresh.sh"
SWIFT_FILTER_EXTRA="scripts/check-swift-bindings-fresh.sh"
run_case "multi-lane-job-needs-one-lane-to-list-the-script" 0 "" emit_ci mise_ok
SWIFT_FILTER_EXTRA=""

# The same three-lane job with no lane listing the path. The gate names all three lanes so
# the author can pick which filter to extend.
run_case "multi-lane-job-with-the-script-in-no-lane" 1 \
    "none of the paths filters that guard it (python kotlin swift) lists that path" \
    emit_ci mise_ok

# A `scripts/` path a comment inside the job names, which the job does not run. `ci.yml`'s
# own `changes` job comments name this gate, so counting comment lines would fail the
# repository on its own documentation.
SCRIPT_JOB="swift|      # See scripts/check-swift-bindings-fresh.sh for what this asserts.
      - run: swift build"
run_case "script-named-only-in-a-comment-demands-no-entry" 0 "" emit_ci mise_ok

# A job no paths filter guards runs on every pull request, so the script it runs needs no
# filter entry. Check 2e binds the filtered jobs alone.
SCRIPT_JOB="|      - run: bash scripts/check-swift-bindings-fresh.sh"
run_case "unfiltered-job-running-a-script-needs-no-entry" 0 "" emit_ci mise_ok

# The same defect with the job's `if:` written below its `steps:` key. YAML mapping keys
# carry no required order, so GitHub Actions runs the job the `swift` filter guards either
# way, and the finding must be the one the "above" placement produces. A gate that read a
# job's lanes only from the lines above `steps:` found no lane here, dropped the job from
# check 2e, and printed the OK line for a workflow holding the defect this case names.
SCRIPT_JOB="swift|      - run: bash scripts/check-swift-bindings-fresh.sh"
IF_PLACEMENT="below-steps"
run_case "filtered-job-writes-its-if-below-steps" 1 \
    "the 'gate-job' job names scripts/check-swift-bindings-fresh.sh, and none of the paths filters that guard it (swift) lists that path" \
    emit_ci mise_ok

# The same placement with the script routed. The lane the gate reads out of the misplaced
# `if:` has to be the `swift` lane and not some other, so this case holds the placement to
# producing no finding once the `swift` filter lists the path.
SWIFT_FILTER_EXTRA="scripts/check-swift-bindings-fresh.sh"
run_case "if-below-steps-with-the-script-routed" 0 "" emit_ci mise_ok
SWIFT_FILTER_EXTRA=""
IF_PLACEMENT="above"
SCRIPT_JOB=""

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

# ── Check 4: the workflow's verdict job observes every job in the workflow ───────────
#
# Every case above writes a `ci.yml` whose jobs are `changes` and `rust-clippy` and no
# verdict job, so check 4 stays silent there and each of those cases also proves that a
# workflow declaring no verdict job reports nothing. The cases below append one.
#
# `emit_verdict_job` writes the job's `needs:` list and the names its shell reads
# separately, so a case can make the two disagree — which is the defect
# `.github/workflows/ci.yml` held: its `ci` job named 49 jobs and read the same 49
# results while the workflow declared 52, leaving `check-draft` and `changes` — the
# upstream of every other job — out of both.
#
#   NEEDS_STYLE — "block" writes the `needs:` list as a block sequence, "flow" as a flow
#                 sequence on the key's own line, "scalar" as a single job name, and
#                 "absent" writes no `needs:` key at all.
#   IF_STYLE    — how the verdict job spells its `if:`: "bare" writes `if: always()`,
#                 "interpolated" writes `if: ${{ always() }}`, "conjunction" writes
#                 `always() && ...`, "folded" writes a `>-` block scalar whose
#                 continuation lines hold `always()`, "not-cancelled" writes
#                 `${{ !cancelled() }}`, "not-failure" writes `${{ !failure() }}`,
#                 "quoted-key" writes the key itself in quotes as `"if": always()`, and
#                 "no-status-function" writes an `if:` naming none of GitHub Actions' four
#                 status check functions. Every spelling but the last names the same job,
#                 so a case that changes only IF_STYLE must produce the same verdict.
#   HEADER_COMMENT — "yes" writes the verdict job's header as `  ci:  # …`, "no" writes it
#                 bare. A trailing comment is YAML a parser drops and a line matcher chokes
#                 on, and dropping the job from the listing hid both the aggregator and the
#                 job the aggregator has to name.
#   KEY_INDENT  — how many spaces the verdict job's own keys sit at, "4" or "6". YAML fixes
#                 no depth for a nested mapping, so GitHub Actions reads the same job at
#                 either.
#   RESULT_STYLE — how the verdict job reads its dependencies' results: "per-job" writes one
#                 `${{ needs.<job>.result }}` for each name, "object-filter" writes the one
#                 expression `${{ join(needs.*.result, ' ') }}`, which GitHub Actions
#                 expands over the job's whole `needs:` context.
NEEDS_STYLE="block"
IF_STYLE="bare"
HEADER_COMMENT="no"
KEY_INDENT="4"
RESULT_STYLE="per-job"

# emit_verdict_job <needs names> <result names>
emit_verdict_job() {
    local needs=$1 results=$2 name joined="" pad step_pad
    pad=$(printf '%*s' "$KEY_INDENT" "")
    step_pad="$pad  "
    if [[ $HEADER_COMMENT == "yes" ]]; then
        printf '  ci:  # the job branch protection requires\n'
    else
        printf '  ci:\n'
    fi
    case "$IF_STYLE" in
        bare) printf '%sif: always()\n' "$pad" ;;
        interpolated) printf '%sif: ${{ always() }}\n' "$pad" ;;
        conjunction) printf "%sif: always() && github.event_name != 'schedule'\n" "$pad" ;;
        folded)
            printf '%sif: >-\n' "$pad"
            printf "%s  github.event_name == 'push' ||\n" "$pad"
            printf '%s  always()\n' "$pad"
            ;;
        not-cancelled) printf '%sif: ${{ !cancelled() }}\n' "$pad" ;;
        not-failure) printf '%sif: ${{ !failure() }}\n' "$pad" ;;
        quoted-key) printf '%s"if": always()\n' "$pad" ;;
        no-status-function) printf "%sif: github.event_name == 'push'\n" "$pad" ;;
        *)
            echo "ERROR: unknown IF_STYLE '$IF_STYLE'" >&2
            exit 1
            ;;
    esac
    case "$NEEDS_STYLE" in
        block)
            printf '%sneeds:\n' "$pad"
            for name in $needs; do printf '%s  - %s\n' "$pad" "$name"; done
            ;;
        flow)
            for name in $needs; do
                if [[ -n $joined ]]; then joined="$joined, "; fi
                joined="$joined$name"
            done
            printf '%sneeds: [%s]\n' "$pad" "$joined"
            ;;
        scalar)
            printf '%sneeds: %s\n' "$pad" "$needs"
            ;;
        absent) : ;;
        *)
            echo "ERROR: unknown NEEDS_STYLE '$NEEDS_STYLE'" >&2
            exit 1
            ;;
    esac
    printf '%sruns-on: ubuntu-latest\n%ssteps:\n' "$pad" "$pad"
    printf '%s- name: Check job results\n%s  run: |\n' "$step_pad" "$step_pad"
    if [[ $RESULT_STYLE == "object-filter" ]]; then
        printf "%s    results=( \${{ join(needs.*.result, ' ') }} )\n" "$step_pad"
    else
        printf '%s    results=( \\\n' "$step_pad"
        for name in $results; do
            printf '%s      "${{ needs.%s.result }}" \\\n' "$step_pad" "$name"
        done
        printf '%s    )\n' "$step_pad"
    fi
    printf '%s    for r in "${results[@]}"; do\n' "$step_pad"
    printf '%s      if [[ "$r" == "failure" || "$r" == "cancelled" ]]; then exit 1; fi\n' "$step_pad"
    printf '%s    done\n' "$step_pad"
}

verdict_complete() {
    routing_ok
    emit_verdict_job "changes rust-clippy" "changes rust-clippy"
}

run_case "verdict-job-observes-every-job" 0 "" verdict_complete mise_ok

NEEDS_STYLE="flow"
run_case "verdict-job-needs-written-as-a-flow-sequence" 0 "" verdict_complete mise_ok
NEEDS_STYLE="block"

# The `scalar` spelling with one dependency. The workflow declares one other job, so the
# single name is the complete list.
verdict_scalar_single_dependency() {
    OMIT_OUTPUT=""
    OMIT_FILTER=""
    # `changes` alone plus the verdict job: `emit_ci` always writes `rust-clippy` too, so
    # this case keeps both and names them through the two-name block list instead. The
    # scalar spelling is exercised by the case below, which omits a job deliberately.
    routing_ok
    emit_verdict_job "changes" "changes"
}
NEEDS_STYLE="scalar"
run_case "verdict-job-needs-written-as-a-scalar-omitting-a-job" 1 \
    "does not name these jobs in its 'needs:' — rust-clippy" \
    verdict_scalar_single_dependency mise_ok
NEEDS_STYLE="block"

# The defect `ci.yml` held. `changes` computes every paths-filter output, so its failure
# skips every lane, and a verdict job that does not read its result reports green.
verdict_omits_the_changes_job() {
    routing_ok
    emit_verdict_job "rust-clippy" "rust-clippy"
}
run_case "verdict-job-omits-the-changes-job" 1 \
    "does not name these jobs in its 'needs:' — changes" \
    verdict_omits_the_changes_job mise_ok

# The half-wired shape: the job waits for `changes` and then never reads its result, so
# the dependency orders the run and decides nothing.
verdict_needs_a_job_it_never_reads() {
    routing_ok
    emit_verdict_job "changes rust-clippy" "rust-clippy"
}
run_case "verdict-job-needs-a-job-whose-result-it-never-reads" 1 \
    "never reads the result of these jobs — changes" \
    verdict_needs_a_job_it_never_reads mise_ok

# A misspelled name. `needs.rust-tests.result` for a job named `rust-clippy` evaluates to
# the empty string, and a verdict job that fails on 'failure' and 'cancelled' accepts it.
verdict_reads_a_name_no_job_carries() {
    routing_ok
    emit_verdict_job "changes rust-clippy" "changes rust-clippy rust-tests"
}
run_case "verdict-job-reads-a-name-no-job-carries" 1 \
    "declares no job by them — rust-tests" \
    verdict_reads_a_name_no_job_carries mise_ok

verdict_needs_a_name_no_job_carries() {
    routing_ok
    emit_verdict_job "changes rust-clippy rust-tests" "changes rust-clippy"
}
run_case "verdict-job-needs-a-name-no-job-carries" 1 \
    "names these in its 'needs:' and this workflow declares no job by those names — rust-tests" \
    verdict_needs_a_name_no_job_carries mise_ok

# No `needs:` at all. GitHub then starts the job immediately, and every result it reads is
# the empty string. The gate fails rather than reading that as complete coverage.
NEEDS_STYLE="absent"
run_case "verdict-job-declares-no-needs" 1 \
    "declares no 'needs:' this gate can read" verdict_complete mise_ok
NEEDS_STYLE="block"

# Two verdict jobs. The gate cannot tell which one branch protection requires, so it
# reports that rather than choosing one and checking it.
two_verdict_jobs() {
    routing_ok
    emit_verdict_job "changes rust-clippy" "changes rust-clippy"
    printf '  ci-mirror:\n    if: always()\n    needs:\n      - changes\n'
    printf '    runs-on: ubuntu-latest\n    steps:\n      - run: echo "${{ needs.changes.result }}"\n'
}
run_case "workflow-declares-two-verdict-jobs" 1 \
    "declares two jobs whose 'if:' names one of GitHub Actions' status check functions" \
    two_verdict_jobs mise_ok

# The `if:` spellings. A verdict job stays a verdict job through every one of them, so
# each case below omits `changes` and expects the same finding the bare spelling produces.
# Matching only the one line `if: always()` turns each of these green, which would let an
# author un-gate the aggregator by rewrapping its condition. GitHub Actions runs a job
# guarded by `!cancelled()` or by `!failure()` after a dependency fails, exactly as it runs
# one guarded by `always()`, so those two report a verdict to branch protection too.
for if_style in interpolated conjunction folded not-cancelled not-failure quoted-key; do
    IF_STYLE="$if_style"
    run_case "verdict-job-spells-its-if-as-$if_style" 1 \
        "does not name these jobs in its 'needs:' — changes" \
        verdict_omits_the_changes_job mise_ok
done
IF_STYLE="bare"

# The other direction: a job whose `if:` names none of GitHub Actions' four status check
# functions is not a verdict job, because GitHub applies an implicit `success()` to it and
# never runs it once a dependency fails or skips. The gate leaves it alone even though it
# omits `changes`.
IF_STYLE="no-status-function"
run_case "job-whose-if-names-no-status-function-is-not-a-verdict-job" 0 "" \
    verdict_omits_the_changes_job mise_ok
IF_STYLE="bare"

# A trailing comment on the verdict job's header. YAML carries the comment and drops it at
# parse time, so GitHub Actions reads the same `ci` job — while a line matcher requiring
# the header to end at the colon listed no such job, which left the aggregator unrecognised
# and left every job the aggregator has to name out of the set it is compared against.
HEADER_COMMENT="yes"
run_case "verdict-job-header-carries-a-trailing-comment" 1 \
    "does not name these jobs in its 'needs:' — changes" \
    verdict_omits_the_changes_job mise_ok
run_case "verdict-job-header-comment-with-every-job-observed" 0 "" verdict_complete mise_ok
HEADER_COMMENT="no"

# The verdict job's own keys at six spaces. YAML fixes no depth for a nested mapping, so
# GitHub Actions reads the same job, and a matcher anchored on four spaces read neither its
# `if:` nor its `needs:`.
KEY_INDENT="6"
run_case "verdict-job-writes-its-keys-at-six-spaces" 1 \
    "does not name these jobs in its 'needs:' — changes" \
    verdict_omits_the_changes_job mise_ok
run_case "verdict-job-at-six-spaces-observing-every-job" 0 "" verdict_complete mise_ok
KEY_INDENT="4"

# `${{ join(needs.*.result, ' ') }}` in place of one expression per job. GitHub Actions
# expands the object filter over the job's own `needs:` context, so the job reads the
# result of every name that list carries, and the gate compares the `needs:` list against
# the workflow's jobs. A gate requiring a literal `needs.<name>.result` recognised no
# verdict job at all here and printed its OK line.
RESULT_STYLE="object-filter"
run_case "verdict-job-reads-results-through-the-object-filter" 0 "" verdict_complete mise_ok
run_case "object-filter-does-not-excuse-a-missing-needs-entry" 1 \
    "does not name these jobs in its 'needs:' — changes" \
    verdict_omits_the_changes_job mise_ok
RESULT_STYLE="per-job"

# A second workflow whose only job is its verdict job. The set of other jobs is then
# empty, and every name that job reads is unknown. The case exists for what the gate does
# on the way to saying so: `grep -vxF` matches nothing, and under `set -euo pipefail` an
# unguarded pipeline there aborts the whole gate before it prints anything, which reads as
# a crash rather than as a finding. Check 4 skips this workflow's paths-filter checks
# because it declares no `dorny/paths-filter` step, so the finding below is the only one
# it can produce.
solo_verdict_workflow() {
    cat <<'YAML'
name: Release
jobs:
  release-gate:
    if: always()
    needs:
      - build
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ needs.build.result }}"
YAML
}
EXTRA_FILES=(".github/workflows/release.yml" solo_verdict_workflow)
run_case "verdict-job-is-the-workflows-only-job" 1 \
    "declares no job by those names — build" routing_ok mise_ok
EXTRA_FILES=()

# A workflow no YAML parser accepts. The gate reads a workflow's jobs by parsing it, and a
# parse that fails answers none of the six questions checks 2e and 4 ask, so the gate
# reports the parser's own refusal rather than passing over the file.
unparsable_workflow() {
    cat <<'YAML'
name: Release
jobs:
  release-gate:
    if: always()
   needs: build
YAML
}
EXTRA_FILES=(".github/workflows/release.yml" unparsable_workflow)
run_case "workflow-no-yaml-parser-accepts" 1 \
    "the gate cannot read the jobs of .github/workflows/release.yml" routing_ok mise_ok
EXTRA_FILES=()

echo ""
echo "toolchain-wiring cases: $passed passed, $failed failed"
[[ $failed -eq 0 ]]
