#!/usr/bin/env bash
# Cases for the migration-guide half of scripts/check-examples-typecheck.sh.
#
# THE CRITERION: the gate exits 1 when a Python or TypeScript block of a live guide under
# `.docs/migration/` fails to type-check against the SDK source in this tree, when a guide
# has no `**Status:**` line, when a fence never closes, when a skip marker has no reason or
# does not sit directly above a Python or TypeScript fence, or when no guide exists; and it
# exits 0 when every block it checks type-checks, printing one line for every block it
# skipped, every block in a language it does not check, and every guide that is not live.
# Each case builds a repository in `mktemp -d`, copies the real gate and its
# `scripts/examples-typecheck/` files into it, links `bindings/python` and
# `bindings/typescript` to this tree's SDK sources, and asserts the exit code and the
# output line that names the outcome, so a case cannot pass on the wrong outcome.
#
# Mutations each case catches: dropping the guide step makes the gate exit 0 on
# `removedpy` and `removedts`, which call the removed `in_memory` custody value and expect
# exit 1. Honouring a marker that a blank line separates from its fence makes the gate exit 0
# on `detachedmarker`; accepting an empty reason does so on `emptyreason`; accepting a marker
# above a Swift block does so on `markerswift`. Treating a guide with no status line as live
# or as not live does so on `nostatus`. Dropping the unclosed-fence rule does so on
# `unclosed`. Dropping the empty-guide-list rule does so on `noguide`. Type-checking a guide
# that is not live, or a skipped block, makes the gate exit 1 on `pass`, whose not-live guide
# and skipped blocks call removed API; and silencing the SKIP, NOT CHECKED or GUIDE NOT LIVE
# lines fails `pass` on its output assertions.
#
# Setup: the gate's own (mypy and pytest for python3.12, and `bun install` in
# `bindings/typescript`).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
PASSED=0
FAILED=0
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# new_repo NAME: a repository holding the gate, one trivial site per language, and no guide.
new_repo() {
    local repo="$WORK/$1"
    mkdir -p "$repo/scripts/examples-typecheck" "$repo/docs/examples" "$repo/.docs/migration" \
        "$repo/bindings"
    cp "$ROOT/scripts/check-examples-typecheck.sh" "$repo/scripts/"
    cp "$ROOT/scripts/examples-typecheck/mypy.ini" "$ROOT/scripts/examples-typecheck/tsconfig.base.json" \
        "$ROOT/scripts/examples-typecheck/guide_blocks.py" "$repo/scripts/examples-typecheck/"
    ln -s "$ROOT/bindings/python" "$repo/bindings/python"
    ln -s "$ROOT/bindings/typescript" "$repo/bindings/typescript"
    printf 'count: int = 1\n' > "$repo/docs/examples/site.py"
    printf 'export const count: number = 1;\n' > "$repo/docs/examples/site.ts"
    git -C "$repo" init --quiet
    echo "$repo"
}

commit() {
    git -C "$1" add -A
    git -C "$1" -c user.email=fixture@example.invalid -c user.name=fixture commit --quiet -m fixture
}

# run_case NAME REPO WANT_EXIT LINE...: runs the gate in REPO and asserts its exit code and
# that its output holds every LINE as a fixed string.
run_case() {
    local name=$1 repo=$2 want=$3
    shift 3
    local out rc
    set +e
    out=$(bash "$repo/scripts/check-examples-typecheck.sh" 2>&1)
    rc=$?
    set -e
    local problem=""
    [[ $rc -eq $want ]] || problem="exit $rc, wanted $want"
    local line
    for line in "$@"; do
        [[ $out == *"$line"* ]] || problem+="${problem:+; }output lacks: $line"
    done
    if [[ -z $problem ]]; then
        echo "PASS $name"
        PASSED=$((PASSED + 1))
    else
        echo "FAIL $name: $problem"
        printf '%s\n' "$out" | tail -n 30 | sed 's/^/    /'
        FAILED=$((FAILED + 1))
    fi
}

LIVE='# Fixture guide

**Status:** live — fixture.
'

# pass: checked blocks type-check; skipped blocks, a Swift block and a not-live guide call
# removed API and are reported, never checked.
repo=$(new_repo pass)
cat > "$repo/.docs/migration/good.md" <<EOF
$LIVE
<!-- examples-typecheck: skip: Before, showing the deleted Identity.create -->
\`\`\`python
from scp_sdk import Identity
identity = Identity.create(custody="in_memory")
\`\`\`

\`\`\`python
from scp_sdk import SCP, CustodyType


async def create() -> None:
    async with SCP(storage={"type": "in_memory"}) as scp:
        await scp.identity_create(CustodyType.ENCRYPTED_FILE)
\`\`\`

<!-- examples-typecheck: skip: Before, showing the deleted Identity.create -->
\`\`\`typescript
import { Identity } from "@limn-works/scp-ts";
await Identity.create({ custody: "in_memory" });
\`\`\`

\`\`\`ts
import { SCP } from "@limn-works/scp-ts";
const scp = new SCP({ storage: { type: "in_memory" } });
await scp.identityCreate("encrypted_file");
\`\`\`

\`\`\`swift
let scp = SCP()
\`\`\`
EOF
cat > "$repo/.docs/migration/old.md" <<'EOF'
# Retired guide

**Status:** retired

```python
this is not python
```
EOF
commit "$repo"
run_case pass "$repo" 0 \
    "SKIP .docs/migration/good.md:6 (python): Before, showing the deleted Identity.create" \
    "CHECK .docs/migration/good.md:11 (python) as guide_good_L11.py" \
    "SKIP .docs/migration/good.md:21 (typescript): Before, showing the deleted Identity.create" \
    "CHECK .docs/migration/good.md:26 (ts) as guide_good_L26.ts" \
    "NOT CHECKED .docs/migration/good.md:32 (swift)" \
    "GUIDE NOT LIVE .docs/migration/old.md: status 'retired'" \
    "1 Python and 1 TypeScript guide block(s), type-check against the SDK"

# removedpy: a Python block with no marker passes the removed `in_memory` custody value.
repo=$(new_repo removedpy)
cat > "$repo/.docs/migration/guide.md" <<EOF
$LIVE
\`\`\`python
from scp_sdk import SCP


async def create() -> None:
    async with SCP(storage={"type": "in_memory"}) as scp:
        await scp.identity_create("in_memory")
\`\`\`
EOF
commit "$repo"
run_case removedpy "$repo" 1 \
    "guide_guide_L5.py:11: error: Argument 1 to \"identity_create\" of \"SCP\" has incompatible type" \
    "FAIL: a site or guide block above calls SDK API that does not type-check"

# removedts: a TypeScript block with no marker passes the removed `in_memory` custody value.
repo=$(new_repo removedts)
cat > "$repo/.docs/migration/guide.md" <<EOF
$LIVE
\`\`\`typescript
import { SCP } from "@limn-works/scp-ts";
const scp = new SCP({ storage: { type: "in_memory" } });
await scp.identityCreate("in_memory");
\`\`\`
EOF
commit "$repo"
run_case removedts "$repo" 1 \
    "guide_guide_L5.ts(8,26): error TS2345" \
    "FAIL: a site or guide block above calls SDK API that does not type-check"

# detachedmarker: a blank line separates the marker from its fence.
repo=$(new_repo detachedmarker)
cat > "$repo/.docs/migration/guide.md" <<EOF
$LIVE
<!-- examples-typecheck: skip: Before -->

\`\`\`python
x = 1
\`\`\`
EOF
commit "$repo"
run_case detachedmarker "$repo" 1 \
    "FAIL: .docs/migration/guide.md:5: the skip marker is not directly above an opening fence"

# emptyreason: a marker with no reason.
repo=$(new_repo emptyreason)
cat > "$repo/.docs/migration/guide.md" <<EOF
$LIVE
<!-- examples-typecheck: skip:  -->
\`\`\`python
x = 1
\`\`\`
EOF
commit "$repo"
run_case emptyreason "$repo" 1 \
    "FAIL: .docs/migration/guide.md:5: a marker must read '<!-- examples-typecheck: skip: REASON -->' with a non-empty REASON"

# markerswift: a marker above a block this gate never checks.
repo=$(new_repo markerswift)
cat > "$repo/.docs/migration/guide.md" <<EOF
$LIVE
<!-- examples-typecheck: skip: Before -->
\`\`\`swift
let scp = SCP()
\`\`\`
EOF
commit "$repo"
run_case markerswift "$repo" 1 \
    "FAIL: .docs/migration/guide.md:5: the skip marker sits above a swift block, which this gate never checks"

# nostatus: a guide with no status line.
repo=$(new_repo nostatus)
printf '# Guide\n\n```python\nx = 1\n```\n' > "$repo/.docs/migration/guide.md"
commit "$repo"
run_case nostatus "$repo" 1 \
    "FAIL: .docs/migration/guide.md: no '**Status:**' line"

# unclosed: a fence that never closes.
repo=$(new_repo unclosed)
printf '%s\n```python\nx = 1\n' "$LIVE" > "$repo/.docs/migration/guide.md"
commit "$repo"
run_case unclosed "$repo" 1 \
    "FAIL: .docs/migration/guide.md:5: the fence opened here never closes"

# noguide: no guide under .docs/migration/.
repo=$(new_repo noguide)
commit "$repo"
run_case noguide "$repo" 1 \
    "FAIL: git ls-files found no guide under .docs/migration/"

echo "examples-typecheck cases: $PASSED passed, $FAILED failed"
[[ $FAILED -eq 0 ]]
