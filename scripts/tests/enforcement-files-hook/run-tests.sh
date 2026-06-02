#!/usr/bin/env bash
# run-tests.sh — regression matrix for the PreToolUse enforcement-file hook
# (`scripts/hooks/pretooluse-enforcement-files.sh`).
#
# The hook blocks in-band edits/writes to protected enforcement files via
# Edit/Write/MultiEdit AND Bash. Its Bash branch heuristically detects write
# verbs and redirections; the matrix below locks that behavior so a future
# change cannot silently regress a block into an allow (or wrongly block a
# read). It is the automated counterpart to the manual verification the hook
# was developed against.
#
# Each case asserts the hook's exit code for a crafted PreToolUse JSON payload:
#   exit 2 -> BLOCK   exit 0 -> ALLOW (or no-op)
#
# Scope note: the hook is defense-in-depth, not a full shell parser. These
# cases cover the CLAIMED write classes and the read forms that must stay
# allowed; documented best-effort gaps (variable/command substitution, base64,
# `-i` after a sed script, indirect writes via intermediate scripts) are out of
# scope here exactly as they are out of scope for the hook — CI's canonical
# bridge-symmetry / pure-helpers / fmt / clippy gates re-verify any landed
# change regardless.
#
# Exit 0 if every case passes, 1 on any failure.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
HOOK="$REPO_ROOT/scripts/hooks/pretooluse-enforcement-files.sh"

if [[ ! -f "$HOOK" ]]; then
    echo "ERROR: hook not found at $HOOK" >&2
    exit 1
fi

# A protected file and a non-protected file, as repo-root-absolute paths (the
# Edit/Write branch matches on canonical absolute paths anchored at repo root).
PROTECTED_ABS="$REPO_ROOT/scripts/bridge-aliases.json"
PROTECTED_HOOK_ABS="$REPO_ROOT/scripts/check-pure-helpers.sh"
UNPROTECTED_ABS="$REPO_ROOT/README.md"
# A fixture copy of a protected basename — must NOT be treated as protected
# (it is test data, not the live enforcement surface).
FIXTURE_ABS="$REPO_ROOT/scripts/tests/bridge-symmetry/fixtures/bad-alias-undecorated-fn/scripts/bridge-aliases.json"

PASS=0
FAIL=0

# check <expected_exit> <description> <json_payload>
check() {
    local expected="$1" desc="$2" payload="$3" rc=0
    printf '%s' "$payload" | bash "$HOOK" >/dev/null 2>&1 || rc=$?
    if [[ "$rc" == "$expected" ]]; then
        echo "PASS [$desc]: exit=$rc"
        PASS=$((PASS + 1))
    else
        echo "FAIL [$desc]: expected exit=$expected, got exit=$rc" >&2
        FAIL=$((FAIL + 1))
    fi
}

bash_payload() { printf '{"tool_name":"Bash","tool_input":{"command":%s}}' "$(json_str "$1")"; }
edit_payload() { printf '{"tool_name":"%s","tool_input":{"file_path":%s}}' "$1" "$(json_str "$2")"; }
# MultiEdit carries no top-level file_path — the hook extracts edits[].file_path.
multiedit_payload() {
    printf '{"tool_name":"MultiEdit","tool_input":{"edits":[{"file_path":%s}]}}' "$(json_str "$1")"
}
# Minimal JSON string encoder (handles the quotes/backslashes our payloads use).
json_str() { printf '%s' "$1" | python3.12 -c 'import json,sys; print(json.dumps(sys.stdin.read()))'; }

B="scripts/bridge-aliases.json"
H="scripts/check-pure-helpers.sh"

echo "== Bash branch: writes must BLOCK (exit 2) =="
check 2 "redirect >"            "$(bash_payload "echo x > $B")"
check 2 "redirect >|"           "$(bash_payload "echo x >| $B")"
check 2 "redirect >> append"    "$(bash_payload "echo x >> $B")"
check 2 "tee"                   "$(bash_payload "echo x | tee $H")"
check 2 "tee -a"                "$(bash_payload "echo x | tee -a $H")"
check 2 "mv onto target"        "$(bash_payload "mv /tmp/x $B")"
check 2 "cp onto target"        "$(bash_payload "cp /tmp/x $H")"
check 2 "cat redirect"          "$(bash_payload "cat /tmp/x > $B")"
check 2 "python -c write"       "$(bash_payload "python3.12 -c open('$B','w')")"
check 2 "sed -i"                "$(bash_payload "sed -i s/a/b/ $B")"
check 2 "sed -i'' (BSD)"        "$(bash_payload "sed -i'' s/a/b/ $B")"
check 2 "sed -i.bak"            "$(bash_payload "sed -i.bak s/a/b/ $B")"
check 2 "sed --in-place"        "$(bash_payload "sed --in-place s/a/b/ $B")"
check 2 "sed -n -i '' (reorder)" "$(bash_payload "sed -n -i '' 1p $B")"
check 2 "sed -ni (combined)"    "$(bash_payload "sed -ni 1p $B")"

echo "== Bash branch: reads must ALLOW (exit 0) =="
check 0 "cat read"              "$(bash_payload "cat $B")"
check 0 "grep read"             "$(bash_payload "grep foo $B")"
check 0 "jq read"               "$(bash_payload "jq . $B")"
check 0 "sed -n read"           "$(bash_payload "sed -n 1,5p $B")"
check 0 "sed -e read (no -i)"   "$(bash_payload "sed -e s/x/y/ $B")"
check 0 "node read arg"         "$(bash_payload "node check.js $B")"
check 0 "python script read"    "$(bash_payload "python3.12 validate.py $B")"
check 0 "ls"                    "$(bash_payload "ls -la scripts/")"
check 0 "unrelated command"     "$(bash_payload "echo hello")"

echo "== Edit/Write branch =="
check 2 "Edit protected"        "$(edit_payload Edit "$PROTECTED_ABS")"
check 2 "Write protected hook"  "$(edit_payload Write "$PROTECTED_HOOK_ABS")"
check 0 "Edit non-protected"    "$(edit_payload Edit "$UNPROTECTED_ABS")"
check 0 "Edit fixture copy"     "$(edit_payload Edit "$FIXTURE_ABS")"
check 2 "MultiEdit protected"   "$(multiedit_payload "$PROTECTED_ABS")"
check 0 "MultiEdit non-protected" "$(multiedit_payload "$UNPROTECTED_ABS")"

echo "== Fail-closed =="
check 2 "malformed JSON"        'not json {{{'
check 2 "Write no file_path"    '{"tool_name":"Write","tool_input":{}}'
check 0 "non-matched tool"      '{"tool_name":"Read","tool_input":{"file_path":"/tmp/x"}}'

echo
echo "enforcement-files-hook tests: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]]
