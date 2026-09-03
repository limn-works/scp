# A bad passage, and its rewrite

Read this before you write prose for this repository. It shows one passage that breaks
`.docs/standards/concrete-prose.md`, names every rule it breaks, and gives the rewrite.

An agent wrote the passage in a review conversation. The agent was arguing that the
maintainers should delete row 10 from a table in the addressability and deployment spec.
The human reading it could not tell what the argument was.

The passage also cites a section that does not exist. `.docs/specs/18-addressability-and-deployment.md`
numbers §18.11 up to §18.11.12 and stops there, and no commit in this repository's history
added or removed §18.11.13.2 [no such section], so no reader can open it or check the
sentence the passage quotes from it. The rewrite below therefore drops that citation and
cites two sections a reader can open.

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
| "§18.11.13.2" | Never reference by an identifier alone: the rule asks that the reader can find the thing. | The addressability and deployment spec numbers §18.11 up to §18.11.12 and carries nothing past it. A reader who opens the file to check the quoted sentence cannot tell whether the spec lost a section or the author invented one. |
| "the provenance hash is defined over MessagePack" | Active voice. | The passive hides the definer. Row 10 defines the hash, and row 10 is the thing under discussion, so the sentence deletes its own subject. |
| "while the document serves JSON" | No contradictory readings. | "While" reads as either "during the time that" or "whereas". Both readings survive, and they support different conclusions. |
| "Cutting row 10 is what makes the spec's own claim true." | Active voice. Concision. | The cleft construction deletes the agent and spends six words reaching the verb. |
| "The decisive argument is self-contained" | Report, do not appraise. | "Decisive" and "self-contained" rate the argument instead of stating it. The next clause has to state it anyway. |

## The rewrite

> I gave you two rationales for deleting row 10. Both rationales apply equally to the
> envelope row and to the attestation row. Neither rationale tells you to delete row 10
> and keep the other two rows.
>
> A third argument does tell you to delete row 10. Row 10 defines the provenance hash over
> a MessagePack encoding, which the provenance system spec makes normative in §24.3.3, dual
> recording. A verifier reads a JSON document, because the feed endpoint of the
> addressability and deployment spec, §18.11.3, serves JSON. A verifier that obeys row 10
> therefore runs a MessagePack decoder over a JSON document. Delete row 10 and a verifier
> needs no MessagePack decoder. I did not use counterparty privacy in provenance, §24.3.5,
> anywhere above.

Every sentence in the rewrite names its own subject, and every section number in it opens
to a heading that exists. The rewrite answers three questions the original left open: which
rows the two failed rationales cover, what defines the provenance hash, and why a JSON
document contradicts a MessagePack definition.

`scripts/check-doc-citations.py` checks the property the passage broke, over the files that
tell agents how to write: `.docs/standards/`, `.docs/lessons/`, `.claude/agents/`, and
`CLAUDE.md`. It reads every `§N.M` citation in those files and fails when the citation
names a section its spec file does not contain. A file may cite a section that no longer
exists by writing the reference once followed by the literal marker `[no such section]`,
as this file does above and as the saga-admission lesson,
`.docs/lessons/saga-admission-and-topology-guards.md`, does for the withdrawn broadcast
hosting handshake.

## The failure mode this example names

The author appraised their own reasoning, then replaced the argument with a metaphor. An
author who opens by rating their own previous answer has stopped writing about the subject
and started writing about the answer, so the next sentence carries a figure instead of the
claim.

Watch for the opening move. When a sentence starts by grading earlier work — "my reasoning
was weaker", "the real argument is", "to be precise" — delete that sentence and start at
the claim.
