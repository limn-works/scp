#!/usr/bin/env bash
# PreToolUse hook: run `scripts/check-bridge-symmetry.sh --hook` against any
# FFI bridge paths the incoming Edit/Write tool is about to touch. Invoked
# from `.claude/settings.json`; factored out of that JSON body so shell
# escaping is auditable, paths with metacharacters don't get mangled by
# three layers of JSON + shell quoting, and the hook is testable in
# isolation (`bash scripts/hooks/pretooluse-bridge-symmetry.sh < fixture.json`).
#
# Input: tool-use JSON on stdin (Claude Code's PreToolUse payload shape).
# Exits 0 to allow the tool call, non-zero to block it.
#
# Fails CLOSED on any of:
#   * `jq` not installed / unable to parse the payload
#   * Any FFI-touching path in the payload fails bridge-symmetry
#
# Provenance: ADR-046 adversarial round 12 MINOR-3. The CI job
# (`check-bridge-symmetry`) is the enforced gate; this hook is a
# local-edit tripwire.

set -euo pipefail

tool_json=$(cat)

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
    echo "bridge-symmetry hook: jq failed to parse tool_input; failing closed" >&2
    exit 2
}

ffi_paths=()
while IFS= read -r p; do
    [[ -z "$p" ]] && continue
    [[ "$p" == *"crates/scp-ffi/"* ]] && ffi_paths+=("$p")
done <<< "$paths"

[[ ${#ffi_paths[@]} -eq 0 ]] && exit 0

: "${CLAUDE_PROJECT_DIR:?CLAUDE_PROJECT_DIR must be set}"
exec bash "$CLAUDE_PROJECT_DIR/scripts/check-bridge-symmetry.sh" --hook "${ffi_paths[@]}"
