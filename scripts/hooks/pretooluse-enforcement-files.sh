#!/usr/bin/env bash
# PreToolUse hook: block in-band edits to enforcement files. Invoked from
# `.claude/settings.json`. Factored out of the JSON body so shell
# escaping is auditable and the hook is testable in isolation.
#
# Enforcement files are listed in `PROTECTED_REPO_RELATIVE_PATHS` below. A
# tool call that would modify one of those paths — directly OR via a
# symlink that resolves to one — is blocked. Local edits to enforcement
# must go through a dedicated PR so CI can re-verify the enforcement
# surface.
#
# Path matching is EXACT against the canonical absolute path under the
# repo root: `${repo_root}/<protected-relative-path>`. Fixture copies of
# enforcement files (e.g. test fixtures under
# `scripts/tests/bridge-symmetry/fixtures/*/scripts/bridge-aliases.json`)
# are deliberately NOT matched — they are test data, not the live
# enforcement surface, and editing them does not weaken the gate.
# Worktree edits resolve `${repo_root}` to the worktree root (the worktree's
# own enforcement files), which is the correct local-protection scope.
#
# Input: tool-use JSON on stdin (Claude Code's PreToolUse payload shape).
# Exits 0 to allow, non-zero to block.
#
# Fails CLOSED on any of:
#   * `jq` not installed / unable to parse the payload
#   * `python3.12` not available (system `python3` is the Xcode stub
#     per project CLAUDE.md and cannot be trusted for realpath)
#   * `git rev-parse --show-toplevel` fails (cannot anchor protected paths)
#   * A direct OR symlink-resolved path matches a protected canonical path

set -euo pipefail

# Enforcement-file paths RELATIVE to the repo root. Matched after resolution
# to absolute realpath, so symlink redirection can't bypass. Any new
# enforcement surface added to the project must append here.
PROTECTED_REPO_RELATIVE_PATHS=(
    ".claude/settings.json"
    "scripts/check-bridge-symmetry.sh"
    "scripts/bridge-aliases.json"
)

tool_json=$(cat)

# Claude Code's PreToolUse matcher is treated as substring/regex and can fire
# this hook on tools other than Edit/Write/MultiEdit (e.g. Bash). Those payloads
# have no `tool_input.file_path`, so the jq -er below would fail and the script
# would fail-closed with non-JSON stderr — which Claude Code's hook-output
# validator then rejects. Validate our preconditions explicitly and no-op
# otherwise.
tool_name=$(printf '%s' "$tool_json" | jq -r '.tool_name // ""')
case "$tool_name" in
    Edit|Write|MultiEdit) ;;
    *) exit 0 ;;
esac

paths=$(
    printf '%s' "$tool_json" \
        | jq -er '
            [
                (.tool_input.file_path // empty),
                ((.tool_input.edits // [])[]?.file_path)
            ]
            | map(select(. != null and . != ""))
            | unique
            | .[]
        ' 2>/dev/null
) || {
    echo "enforcement-file hook: jq failed to parse tool_input; failing closed" >&2
    exit 2
}

command -v python3.12 >/dev/null 2>&1 || {
    echo "ENFORCEMENT ERROR: python3.12 required for hook realpath resolution" \
         "(symlink bypass protection) — per project CLAUDE.md, system" \
         "python3 is the Xcode stub and must not be used" >&2
    exit 2
}

# Anchor protected paths against the repo root so a fixture file named
# `bridge-aliases.json` deeper in the tree does not collide with the live
# enforcement surface. `git -C "$(dirname ...)" rev-parse --show-toplevel`
# returns the worktree root when this hook runs inside a worktree, which
# is the correct local-protection scope (each worktree owns its own copy
# of the enforcement surface).
repo_root=$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel 2>/dev/null) || {
    echo "ENFORCEMENT ERROR: hook cannot resolve repo root via git;" \
         "failing closed" >&2
    exit 2
}

# Resolve protected paths to their canonical absolute form ONCE. We compare
# the (also-realpath'd) input path against these canonical forms below.
PROTECTED_ABSOLUTE_PATHS=()
for rel in "${PROTECTED_REPO_RELATIVE_PATHS[@]}"; do
    canon=$(python3.12 -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' \
        "$repo_root/$rel" 2>/dev/null) || {
        echo "ENFORCEMENT ERROR: hook realpath failed for $repo_root/$rel" >&2
        exit 2
    }
    PROTECTED_ABSOLUTE_PATHS+=("$canon")
done

check_path() {
    local p="$1"
    for protected in "${PROTECTED_ABSOLUTE_PATHS[@]}"; do
        if [[ "$p" == "$protected" ]]; then
            echo "enforcement file protected: $p" >&2
            echo "CI will re-check bridge symmetry, but local edits to" \
                 "enforcement files should go through a separate" \
                 "dedicated PR." >&2
            exit 2
        fi
    done
}

while IFS= read -r p; do
    [[ -z "$p" ]] && continue
    # Resolve the input path to its canonical form. This also handles
    # symlinks so `ln -s scripts/check-bridge-symmetry.sh /tmp/x` followed
    # by an edit of `/tmp/x` can't bypass the guard.
    rp=$(python3.12 -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' "$p" 2>/dev/null) || {
        echo "ENFORCEMENT ERROR: python3.12 realpath failed for $p; failing closed" >&2
        exit 2
    }
    [[ -n "$rp" ]] && check_path "$rp"
done <<< "$paths"

exit 0
