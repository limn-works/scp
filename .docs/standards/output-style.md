# Output style

These rules govern every sentence you write for a human reader: chat responses, specs,
ADRs, PRD stories, commit bodies, pull-request descriptions, code comments, review
findings, README text, and artifact copy.

Read this file before you write prose for this repository. `CLAUDE.md` points here and
adds nothing of its own.

**The criterion:** a reader who does not already know the answer can reconstruct, from the sentence alone, who did what to what, and why. When a reader has to already know the answer in order to parse the sentence, the sentence has failed, however well it reads. Every rule below is a way that sentences fail this criterion. Satisfying all of them still does not satisfy the criterion, so check the criterion itself last. `.docs/lessons/bad-prose-and-its-rewrite.md` shows one passage that breaks these rules, names every rule it breaks, and gives the rewrite.

- **Write concretely.** Give every transitive verb its explicit direct object. Name the owner behind every possessive. State how each clause relates to the clause beside it.
- **Write every sentence in the active voice.** Put the actor in the subject position. Write "the gate rejects an unsigned frame," not "unsigned frames are rejected." A passive verb lets the writer omit the actor, and the rule above forbids that omission. When you do not know which component acted, write that you do not know it.
- **Simple past for past events.** "marked", not "was marking".
- **Name the referent.** No "that job", "this pattern", "that asymmetry".
- **Objects have no intentions and no strength.** A comma does not do a job.
- **One idea per sentence.** When a sentence balances on "and", split it and cut whichever half is decoration.
- **Never join two clauses with a bare comma when a logical relation connects them.** Write the relation out with `because`, `so`, `when`, `after`, `although`, or `which means`. After a comma splice, the reader cannot tell whether the second clause causes the first, follows it in time, or merely accompanies it.
- **"Each verb gets its own object, no zeugmas"** (Mike, 2026-07-29, verbatim). Rewrite "returns home wearing his blood and a self-defense story" as "returns home covered in his blood, and tells the police that she killed him in self-defense."
- **"Resist metaphorical, poetic, or analogical language"** (Mike, 2026-07-29, verbatim). Replace each metaphor and each poetically compressed phrase with the literal claim it stands for. Write "kinship reveals appear in 7% of 1970s twist films and in 11% of 1980s twist films," not "the mode steps up and never falls back."
- **Give every statistic an explicit denominator.** Write "23% of the twist films we catalogued from the 1920s," not "23% of twist films."
- **Report what happened. Do not appraise it.** Delete "cleanly", "nicely", "elegant", "unfortunately", "interestingly", "I think", "it is worth noting", and "great question". When a judgment is the point of the sentence, name the criterion and cite the evidence: write "this reaches an in-memory backend on a production path, which §17.17 of the persistence spec forbids," not "this feels wrong."
- **Never reference anything by an identifier alone.** Name the thing first, then give the identifier so the reader can find it. Write "ADR-062, capability injection", not "ADR-062". Write "§17.17 of the persistence spec, which classifies a capability as durability-only or as a nullifier", not "§17.17". Write "pull request #2293, the CLAUDE.md prose rules", not "#2293". Write "SCP-046, the streaming-saga seal state machine", not "SCP-046". A reader who has not memorized the ledger learns nothing from a bare number, and has to open the artifact before finishing your sentence. This rule binds every kind of identifier: issue and pull-request numbers, ADR numbers, spec and section numbers, story IDs, commit hashes, branch names, and task IDs.
- **Delete every modifier a reader cannot check.** Keep "129-line" and "two consecutive", because a reader can count them. Delete "robust", "comprehensive", "significant", "proper", "simply", "just", "very", and "actually". Delete any description that changes neither what the reader believes nor what the reader does next.
- **Write the shortest sentence that still obeys every rule above.** Delete a word when deleting it takes no agent, no object, no denominator, and no connective out of the sentence. Delete preamble, restatements of the question, narration of your own process, hedges, and praise. Never shorten a sentence by deleting its subject, its object, or the word that states how its clauses relate. When you cannot shorten a sentence without deleting one of those three, leave the sentence long.
- **Write to ISO 24495-1:2023, Plain language — Part 1: Governing principles and guidelines.** ISO 24495-1 sets four reader-centred principles: the reader finds what they need, understands what they find, uses what they understand, and receives only what is relevant to them. Judge each sentence by what its reader can do after reading it, not by how the sentence sounds. This binds conversation exactly as it binds artifacts.
- **Ten forbidden constructions.** In each one, the writer puts a rhetorical move where a claim belongs. Delete it and write the claim.
  1. **Comparative definition** — "[abc], and it's [x] than a [y]".
  2. **Adjective reinforcement** — "sound and bounded".
  3. **Callout** — "[abc], and it's worth naming".
  4. **Introductory patterns**.
  5. **Hedging**.
  6. **Decoration** — an em-dash aside that carries no new fact.
  7. **Compliance narration** — "[abc], and I'm not [x]ing [y]". Write "Two unanswered questions:", not "Two questions remain unanswered, and I am not deciding either."
  8. **Maxims**.
  9. **"X rather than Y" closers**.
  10. **Smuggled definite article** — using "the" to reference something otherwise unnamed.
- **Check every sentence before you send it.** Ask seven questions: have I hidden a subordinate relation? Have I dropped a subject or an object? Does a passive verb hide who acted? Have I appraised the work instead of reporting it? Have I referenced anything by a bare identifier? Have I used any of the ten forbidden constructions? Does this sentence admit two contradictory readings? If any answer is yes, rewrite the sentence.
- **Why this rule exists:** in the poetically compressed register — "The asylum frame arrives", "Amy authors her own death and grades the coverage", "returns home wearing his blood and a self-defense story" — the writer deletes the agent, the object, and the causal link. Two contradictory readings then survive, and the reader cannot tell which one the writer meant.
