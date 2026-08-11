# Worked example: a passage that passed review and failed the reader

The Prose rules in `CLAUDE.md` list nine ways a sentence fails. This file works one real
passage through all nine, because a rule read in the abstract does not change what an
author writes, and a rewrite next to its original does.

Alec flagged this passage. An agent wrote it while explaining why one row of a table
should come out of a spec.

## The passage

> My reasoning was weaker than the real argument. Both rationales I gave you indict the
> envelope exactly as hard as the attestation, so neither justified cutting only one. The
> decisive argument is self-contained: §18.11.13.2 claims "no decryption, no MessagePack,
> no AEAD, no key" — and that claim is false while row 10 exists, because the provenance
> hash is defined over MessagePack while the document serves JSON. Cutting row 10 is what
> makes the spec's own claim true. No §24.3.5 reasoning needed.

Every sentence reads fluently. A reader who already knows the answer follows it. A reader
who does not know the answer cannot reconstruct who did what to what, which is the
criterion the passage has to meet.

## What fails, sentence by sentence

| Text | Rule it breaks | What the reader loses |
|---|---|---|
| "My reasoning was weaker than the real argument." | Report, do not appraise. Delete modifiers a reader cannot check. | The whole sentence appraises the author's own earlier work and carries no claim. "Weaker" has no scale, and "the real argument" names nothing. |
| "indict the envelope exactly as hard as the attestation" | Resist metaphor. | Rationales do not indict anything. The literal claim — each rationale applies equally to three rows, so no rationale selects one row — disappears behind the figure. |
| "justified cutting only one" | Give every verb its object. | "Cutting" has no agent and no source. The reader cannot tell who cuts what out of which artifact. |
| "§18.11.13.2 claims" and "No §24.3.5 reasoning needed" | Never reference by an identifier alone. | Neither citation names its spec. A reader without both section numbers memorized must open two files before the sentence resolves. |
| "the provenance hash is defined over MessagePack" | Active voice. | The passive hides the definer. Row 10 defines the hash, and row 10 is the thing under discussion, so the sentence deletes its own subject. |
| "while the document serves JSON" | No contradictory readings. | "While" reads as either "during the time that" or "whereas". Both readings survive, and they support different conclusions. |
| "Cutting row 10 is what makes the spec's own claim true." | Active voice. Concision. | The cleft construction deletes the agent and spends six words reaching the verb. |
| "The decisive argument is self-contained" | Report, do not appraise. | "Decisive" and "self-contained" rate the argument instead of stating it. The next clause has to state it anyway. |

## The rewrite

> I gave you two rationales for cutting row 10. Neither one holds, because each applies to
> the envelope row and the attestation row just as well as it applies to row 10, so
> neither tells you which single row to cut.
>
> Here is the argument that holds, and it needs nothing outside §18.11.13.2 of the
> addressability and deployment spec. That section claims the verifier performs "no
> decryption, no MessagePack, no AEAD, no key". Row 10 makes that claim false: row 10
> defines the provenance hash over a MessagePack encoding, whereas the document the
> verifier reads is JSON, so any verifier that honors row 10 must run MessagePack after
> all. Once you cut row 10, §18.11.13.2's claim becomes true. The argument never reaches
> §24.3.5, counterparty privacy in provenance.

The rewrite runs longer by a few words and answers three questions the original left open:
which rows the failed rationales cover, who defines the provenance hash, and why a JSON
document contradicts a MessagePack definition.

## The failure mode this example names

The author appraised their own reasoning, then compressed the actual argument into
metaphor. Those two moves travel together. An author who opens by rating their previous
answer has turned attention toward the answer's quality and away from its content, and the
compressed figure follows because the sentence is no longer carrying the argument.

Watch for the opening move. When a sentence starts by grading earlier work — "my reasoning
was weaker", "the real argument is", "to be precise" — delete that sentence and start at
the claim.
