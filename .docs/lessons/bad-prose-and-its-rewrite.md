# A bad passage, and its rewrite

Read this before you write prose for this repository. It shows one passage that breaks
`.docs/standards/concrete-prose.md`, names every rule it breaks, and gives the rewrite.

An agent wrote the passage in a review conversation. The agent was arguing that the
maintainers should delete row 10 from a table in the addressability and deployment spec.
The human reading it could not tell what the argument was.

The passage and its rewrite both cite §18.11.13.2 of the addressability and deployment
spec. `main` does not carry that section: the §18.11 subsections of
`.docs/specs/18-addressability-and-deployment.md` end at §18.11.12, Site Configuration.
The review that produced this passage was reading a proposed section that has not merged,
so a reader who opens that spec today finds no §18.11.13.2 and no row 10. The one citation
in the passage that resolves on `main` is §24.3.5, counterparty privacy in provenance, in
`.docs/specs/24-provenance-system.md`. Read the two §18.11.13.2 citations as a record of
what the agent wrote, and read the rewrite for how it names its spec before giving the
section number.

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

> I gave you two rationales for deleting row 10. Both rationales apply equally to the
> envelope row and to the attestation row. Neither rationale tells you to delete row 10
> and keep the other two rows.
>
> A third argument does tell you to delete row 10. The addressability and deployment spec
> says, in §18.11.13.2, that a verifier performs "no decryption, no MessagePack, no AEAD,
> no key". Row 10 makes the spec's claim false. Row 10 defines the provenance hash over a
> MessagePack encoding. A verifier reads a JSON document. A verifier that obeys row 10
> therefore runs MessagePack. Delete row 10 and the spec's claim becomes true. I did not
> use counterparty privacy in provenance, §24.3.5, anywhere above.

Every sentence in the rewrite names its own subject. The rewrite answers three questions
the original left open: which rows the two failed rationales cover, what defines the
provenance hash, and why a JSON document contradicts a MessagePack definition.

## The failure mode this example names

The author appraised their own reasoning, then replaced the argument with a metaphor. An
author who opens by rating their own previous answer has stopped writing about the subject
and started writing about the answer, so the next sentence carries a figure instead of the
claim.

Watch for the opening move. When a sentence starts by grading earlier work — "my reasoning
was weaker", "the real argument is", "to be precise" — delete that sentence and start at
the claim.
