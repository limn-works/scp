# A Rule Written in the Present Tense Reads as Already Done

Pull request #2293 added to the root instructions: "The same rule governs the standing agent
definitions in `.claude/agents/`: each one states its verdict criterion…". Twenty of the
twenty-nine agent definitions then in that directory stated no criterion. An auditor reading
the sentence takes it as the repository's state and closes the audit, and an agent editing a
non-compliant definition infers that the recipe in front of it is the criterion.

## The rule

When you write a rule about artifacts that already exist, use one of two shapes:

- **The imperative, addressed to the next author:** "state the criterion in the file." It
  claims nothing about the files already written.
- **The present-tense description, made true in the same commit and held by a check:** fix
  every existing artifact, add a gate that reads the whole population, and name the gate in
  the sentence. `scripts/check-agent-verdict-criterion.sh` holds the sentence above.

Never write the present-tense description on its own; no reader can tell it from a report of
finished work. A check that carries such a sentence fails when its population is empty, as
`scripts/check-agent-verdict-criterion.sh` does when `.claude/agents/` holds no agent file.
