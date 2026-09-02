# A bad passage, and its rewrite

Read this before you write prose for this repository. It shows one passage that breaks
`.docs/standards/concrete-prose.md`, names every rule it breaks, and gives the rewrite.

This lesson constructs the passage, in the register an agent used in a review
conversation. The passage argues that the maintainers should delete row 10 of a table
that encodes a provenance hash over JSON. This lesson invented row 10 and that table.
Both section numbers the passage cites resolve in this repository, so a reader can open
each one. A human reading a passage written this way cannot tell what the argument is.

## The passage

> My reasoning was weaker than the real argument. Both rationales I gave you indict the
> envelope exactly as hard as the attestation, so neither justified cutting only one. The
> decisive argument is self-contained: §24.3.3 claims "JSON is not used on any
> provenance-hash path" — and that claim is false while row 10 exists, because the
> provenance hash is defined over JSON while the event log serializes MessagePack. Cutting
> row 10 is what makes the spec's own claim true. No §24.3.5 reasoning needed.

## What fails, sentence by sentence

| Text | Rule it breaks | What the reader loses |
|---|---|---|
| "My reasoning was weaker than the real argument." | Report, do not appraise. Delete modifiers a reader cannot check. | The whole sentence appraises the author's own earlier work and carries no claim. "Weaker" has no scale, and "the real argument" names nothing. |
| "indict the envelope exactly as hard as the attestation" | Resist metaphor. | Rationales do not indict anything. The literal claim — each rationale applies equally to three rows, so no rationale selects one row — disappears behind the figure. |
| "justified cutting only one" | Give every verb its object. | "Cutting" has no agent and no source. The reader cannot tell who cuts what out of which artifact. |
| "§24.3.3 claims" and "No §24.3.5 reasoning needed" | Never reference by an identifier alone. | Neither citation names its spec. A reader without both section numbers memorized must open the spec before the sentence resolves. |
| "the provenance hash is defined over JSON" | Active voice. | The passive hides the definer. Row 10 defines the hash, and row 10 is the thing under discussion, so the sentence deletes its own subject. |
| "while the event log serializes MessagePack" | No contradictory readings. | "While" reads as either "during the time that" or "whereas". Both readings survive, and they support different conclusions. |
| "Cutting row 10 is what makes the spec's own claim true." | Active voice. Concision. | The cleft construction deletes the agent and spends six words reaching the verb. |
| "The decisive argument is self-contained" | Report, do not appraise. | "Decisive" and "self-contained" rate the argument instead of stating it. The next clause has to state it anyway. |

## The rewrite

> I gave you two rationales for deleting row 10. Both rationales apply equally to the
> envelope row and to the attestation row. Neither rationale tells you to delete row 10
> and keep the other two rows.
>
> A third argument does tell you to delete row 10. The provenance system spec says, in
> §24.3.3, dual recording, that "JSON is **not** used on any provenance-hash path". Row 10
> makes the spec's claim false. Row 10 defines the provenance hash over a JSON encoding.
> Every other provenance-hash path in the protocol serializes with MessagePack. A verifier
> that obeys row 10 therefore hashes JSON on a path the spec reserves for MessagePack.
> Delete row 10 and the spec's claim becomes true. I did not use counterparty privacy in
> provenance, §24.3.5 of the same spec, anywhere above.

Every sentence in the rewrite names its own subject. The rewrite answers three questions
the original left open: which rows the two failed rationales cover, what defines the
provenance hash, and why row 10's JSON encoding contradicts the spec's MessagePack
requirement.

## The failure mode this example names

The author appraised their own reasoning, then replaced the argument with a metaphor. An
author who opens by rating their own previous answer has stopped writing about the subject
and started writing about the answer, so the next sentence carries a figure instead of the
claim.

Watch for the opening move. When a sentence starts by grading earlier work — "my reasoning
was weaker", "the real argument is", "to be precise" — delete that sentence and start at
the claim.
