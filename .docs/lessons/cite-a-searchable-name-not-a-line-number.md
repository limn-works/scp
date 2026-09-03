# Cite a searchable name, never a line number

## What happened

§27 of the attestations spec, `.docs/specs/27-attestations.md`, cited source files and
sibling artifacts 304 times, and every citation took the form `` `path:NNN` ``. Nine days
after the section merged, 85 of its 227 distinct anchors named a line holding different
content than the line the author read: 66 of 150 unique `crates/**.rs` anchors and 19 of
77 unique `.docs/**` anchors. One anchor for a five-field struct declaration landed on a
line inside a doc-comment example. One anchor supporting a claim about a `ViolationStore`
requirement landed on a blank line.

No other spec in `.docs/specs/` used that citation form, so §27 was the only file whose
evidence decayed this way.

## Why a line number decays

A line number records where a target sat in one file at one commit. Every insertion above
that line moves the target, and nothing in the repository re-points the citation when the
target moves. The citation keeps its confident form while it names the wrong line, so a
reader who follows it reads the wrong content and cannot tell that the citation broke.

That failure is worse than an absent citation. An absent citation tells a reader to search.
A broken citation tells a reader that the claim rests on text the reader just read, and the
reader then judges the claim against the wrong evidence.

A citation that decays this way converts a Consolidated statement — one that quotes a cited
artifact — into an unverifiable assertion. `CLAUDE.md` names that outcome phantom
provenance: text that appears grounded in an artifact while diverging from it.

## The rule

Cite a name a reader can search for, and name the file that holds it:

- a symbol — `` `ScpCustodyViolationAttestation` (`crates/scp-protocol/src/trust/custody_violation.rs`) ``
- a heading or a section number — `` §9.7.1 of the security spec (`.docs/specs/09-security-model.md`) ``
- a constant, a domain separator, or any other literal the target declares
- a verbatim quotation of the sentence the claim rests on, when the target carries no name

Never append `:NNN` to a path, and never write `#L123`. When the target carries no name,
quote it: a quotation survives every edit that does not change the quoted text, and an edit
that does change the text is exactly the edit a reader needs to notice.

The rule that forbids a commit hash in a durable artifact forbids a line number for the same
reason. Both encode a repository state that the next merge invalidates, and neither carries
a signal that it went stale.

## Evidence a reader can check

Compare any `` `path:NNN` `` citation in a durable artifact against the file it names, at
the tip of `main`, some weeks after the artifact merged. Count how many anchors still hold
the content the author cited.
