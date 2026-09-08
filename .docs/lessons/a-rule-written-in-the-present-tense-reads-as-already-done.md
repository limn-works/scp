# A rule written in the present tense reads as already done

Pull request #2293, the concrete-prose writing standard, added this sentence to the
agent-execution rules in `CLAUDE.md`:

> The same rule governs the standing agent definitions in `.claude/agents/`: each one
> states its verdict criterion, and its review dimensions serve that criterion as evidence
> rather than replacing it.

Twenty-nine agent definitions sat in that directory when the sentence merged. Twenty of
them held neither the word "verdict" nor the word "criterion" anywhere in the file:
`chronicler.md` held two sections, `## Artifact Structure` and `## Your Responsibilities`,
and neither said what the agent must confirm before it reports anything. The same commit
added the requirement to
`.claude/agents/README.md` in the imperative — "When you write or edit an agent definition,
satisfy both requirements" — which binds the next author and repairs nothing already
written.

## Why the two sentences behave differently

The README sentence tells an author what to do, so an author who reads it and does nothing
has left work undone. The `CLAUDE.md` sentence describes a state, so an agent that reads it
concludes the work is finished and stops looking. An auditor asked whether the agent
definitions comply reads the description, takes it as the repository's state, and closes
the audit. An agent editing `chronicler.md` sees no criterion there, sees `CLAUDE.md`
asserting that every definition has one, and infers that the recipe in front of it is the
criterion — which is the exact substitution the paragraph containing that sentence was
written to forbid.

## The rule

When you write a rule about artifacts that already exist, write it in one of two shapes and
never in the third:

- **The imperative**, addressed to the next author: "state the criterion in the file." It
  never claims anything about the files already written.
- **The present-tense description, made true in the same commit and held by a check**: fix
  every existing artifact, add a gate that reads the whole population, and name the gate in
  the sentence. `scripts/check-agent-verdict-criterion.sh` does that for the sentence above.
- **The present-tense description on its own** is the shape to avoid. It reads as a report
  of finished work, and no reader can distinguish it from one.

A check that carries such a sentence enumerates its population and fails when the
population is empty. `scripts/check-agent-verdict-criterion.sh` fails when
`.claude/agents/` matches no agent file, because a check that reads no file reports success
about nothing — the same false guarantee a dev stand-in ships on a production path.
`.docs/lessons/a-gate-enumerates-its-population-and-reads-the-parse.md` records that
failure in its own setting.
