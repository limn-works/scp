# Re-verify a Finding Before You Report It, Because Your Own Agents May Have Fixed It

**Source:** SCP-294, the custody-naming story (pull request #2414).
**Applies to:** any orchestrator that reads a file early, dispatches agents that edit
that file, and then reports findings from the early read.

## What happened

Early in the session an orchestrator read
`bindings/swift/Sources/SCP/Internal/ScpBindings.swift` and found a tracked,
UniFFI-generated `CustodyMethod` enum declaring `case platform` and `case software`,
with a converter mapping discriminant 3 to `.software`. The Rust enum had just lost
both variants, so Rust would write 3 for `External` while the generated Swift decoded 3
as `.software`.

The orchestrator recorded that as a known gap, carried it through a review round, wrote
it into the pull-request body, and reported it to its coordinator as work left to do.

It was already fixed. A coder agent had regenerated the bindings and the fix rode in the
first commit. Regenerating the file from the release dylib produced a byte-identical
result, and `git show HEAD:<path> | grep -c "case platform"` returned 0. The reported
gap did not exist at any point after that commit.

## Why the ordinary safeguards missed it

The finding was true when it was read. Nothing later contradicted it in the
orchestrator's context, because the agent that fixed it reported "regenerated the
bindings" among two hundred other lines, and the orchestrator's own verification passes
were scoped to the custody parsers rather than to the generated file. A stale finding
reads exactly like a live one: it cites a real path, a real line, and a real symbol.

## The rule

**A finding you did not re-verify against the current head is a hypothesis, not a
finding.** Before a finding reaches a report, a pull-request body, or a hand-off, re-run
the check that produced it against `HEAD` — not against your memory of the file.

Three cheap checks catch this class:

- `git show HEAD:<path> | grep -c '<symbol>'` for a claim that a symbol is present or
  absent. It reads the committed state, not the working tree and not your context.
- For a generated file, regenerate it into a temporary directory and `diff`. A zero-line
  diff proves the tracked file is current; it also proves the generator runs, which a
  grep does not.
- `git log -p --since=<when you read it> -- <path>` to see whether anything touched the
  file between your read and your report.

## The sharper version of the rule

The risk rises with the number of agents editing the same tree. An orchestrator that
dispatches agents is reading a moving target, and every finding it holds decays. Treat
the age of a finding the way you treat the age of a cache entry: the longer you have held
it, and the more writes have landed since, the less it is worth without a re-read.

A gap reported as open when it is closed costs a reviewer a full investigation, and it
teaches the reader that the report's other claims may also be stale.
