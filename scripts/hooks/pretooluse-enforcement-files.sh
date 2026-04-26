#!/usr/bin/env bash
# PreToolUse hook: block in-band edits to enforcement files. Invoked from
# `.claude/settings.json`. Factored out of the JSON body so shell
# escaping is auditable and the hook is testable in isolation.
#
# Enforcement files are listed in `PROTECTED_SUFFIXES` below. A tool call
# that would modify one of those paths — directly OR via a symlink that
# resolves to one — is blocked. Local edits to enforcement must go
# through a dedicated PR so CI can re-verify the enforcement surface.
#
# Input: tool-use JSON on stdin (Claude Code's PreToolUse payload shape).
# Exits 0 to allow, non-zero to block.
#
# Fails CLOSED on any of:
#   * `jq` not installed / unable to parse the payload
#   * `python3.12` not available (system `python3` is the Xcode stub
#     per project CLAUDE.md and cannot be trusted for realpath)
#   * A direct OR symlink-resolved path matches a protected suffix

set -euo pipefail

# Enforcement-file suffixes — matched against both the raw path and the
# realpath-resolved form so symlink redirection can't bypass. Any new
# enforcement surface added to the project must append here.
PROTECTED_SUFFIXES=(
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

check_path() {
    local p="$1"
    for sfx in "${PROTECTED_SUFFIXES[@]}"; do
        if [[ "$p" == *"$sfx" ]]; then
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
    check_path "$p"
    # Resolve symlinks so `ln -s scripts/check-bridge-symmetry.sh /tmp/x`
    # followed by an edit of `/tmp/x` can't bypass the guard.
    rp=$(python3.12 -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' "$p" 2>/dev/null) || {
        echo "ENFORCEMENT ERROR: python3.12 realpath failed for $p; failing closed" >&2
        exit 2
    }
    if [[ -n "$rp" && "$rp" != "$p" ]]; then
        check_path "$rp"
    fi
done <<< "$paths"

exit 0
