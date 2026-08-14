# A Lenient Suffix Matcher Becomes a Bypass Channel When the Gate Fails-Closed

**Context**: `scripts/check-sdk-coverage.py` matched matrix operations to SDK symbols
using, among other strategies, a lenient `name.endswith(op)` comparison. While the gate
only *warned* on misses, this was cosmetically harmless — a loose match at worst suppressed
a warning nobody acted on.

**Problem**: When the gate was promoted to fail-closed (exit 1 on unmatched `true` cells),
the same `endswith` match became a **bypass channel**. ~23 fabricated operation names
passed because they collided, as suffixes, with common verbs already present in real
symbols — `send`, `sign`, `verify`, etc. A fake op named `foo_send` "matched" any real
method ending in `send`. The gate reported green on capabilities that did not exist.

**Root cause**: Match leniency that is acceptable in an advisory check is unacceptable in
an enforcing one. A warning-only gate's false negatives cost nothing; a fail-closed gate's
false negatives are exactly the holes it was built to close. Promoting warn→error without
re-auditing the acceptance conditions silently inverts the cost of every loose match.

**Rule**: Before promoting any check from warning to fail-closed, audit **every acceptance
condition** for bypass vectors under the new semantics. Specifically:
- Replace substring/suffix/prefix matches with exact or anchored matches (full symbol name,
  or a structurally-derived canonical name), unless the lenient form is provably injective.
- Enumerate the verbs/tokens that loose matching could collide on, and confirm none of them
  let a fabricated name pass.
- Treat "this match was fine when we only warned" as evidence it needs re-examination, not as
  evidence it's safe.

Related: `.docs/lessons/ast-gate-checks-definition-not-name-resolution.md` (name-based
matching is alias-evadable; match definitions/structure, not strings) and
`.docs/lessons/fail-closed-gate-escape-hatch-must-be-verified.md` (the companion lesson from
the same PR — escape hatches must be closed by construction).
