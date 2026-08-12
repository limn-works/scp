# A bad passage, and its rewrite

Read this before you write prose for this repository. It shows one passage that breaks
`.docs/standards/concrete-prose.md`, names every rule it breaks, and gives the rewrite.

An agent wrote the passage in a review conversation. The agent was arguing that the
maintainers should delete row 10 from a table in the addressability and deployment spec.
The human reading it could not tell what the argument was.

## The passage

> My reasoning was weaker than the real argument. Both rationales I gave you indict the
> envelope exactly as hard as the attestation, so neither justified cutting only one. The
> decisive argument is self-contained: §18.11.13.2 claims "no decryption, no MessagePack,
> no AEAD, no key" — and that claim is false while row 10 exists, because the provenance
> hash is defined over MessagePack while the document serves JSON. Cutting row 10 is what
> makes the spec's own claim true. No §24.3.5 reasoning needed.

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

The author appraised their own reasoning, then replaced the argument with a metaphor. An
author who opens by rating their own previous answer has stopped writing about the subject
and started writing about the answer, so the next sentence carries a figure instead of the
claim.

Watch for the opening move. When a sentence starts by grading earlier work — "my reasoning
was weaker", "the real argument is", "to be precise" — delete that sentence and start at
the claim.
