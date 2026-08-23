# A Fix That Absorbs a Documentation Workstream Cannot Converge

A fix that made one example compile on a shipped build grew to 1,204 inserted lines
across 37 files. Nineteen review rounds later the branch was still producing findings, and
in the nineteenth round a reviewer falsified three claims that the two newest commits had
added. Deleting every sentence about a subsystem the branch never modified ended the loop
that fixing individual sentences could not.

## The Rule

**A change may document the surface it modifies. It may not document a subsystem it only
reads.** When a fix needs to explain adjacent behavior, state the mechanism the fix
depends on and stop. Explaining that mechanism across every bridge and SDK is a separate
workstream, and adopting it silently converts a reviewable fix into an unreviewable one.

The test: for each sentence added, does the branch change the code the sentence describes?
When the answer is no for most of the diff, the branch has absorbed someone else's work.

## What happened

The task was a security fix: bump `rustls-webpki` past three certificate-validation
advisories, delete their `deny.toml` ignore entries, and stop one example from needing a
test-only feature to compile. Pull request #2382, which cleared the Rust 1.98.0 clippy
lints and named the Rust version in one file, took the `rustls-webpki` bump and the three
`deny.toml` deletions into main first. This branch then rebased onto that commit, so the
branch carries no line of the advisory fix and delivers only the example half. The example
fix required one true sentence about why a shipped build cannot create an identity.

That one sentence became thirty. Each round a reviewer found a surface where the same
explanation was missing, or wrong, or scoped differently, and each fix added surfaces.
The identity fail-closed behavior belongs to the ADR-062 severing workstream. This branch
never modified it. It only described it — on ten bridge and SDK doc comments, four SDK
methods, two operator guides, and an error-code registry.

## Universals about provenance are the specific trap

The sentences that kept failing all had one shape: a claim about **who** could have
produced a state.

> the reload branch fires only against a directory a `testing` build already seeded

A reviewer falsified it by writing an external consumer crate on default features, calling
`DidMethod::create` with its own `PreRotationCustody`, and minting a real `did:dht:`
identity. `PreRotationCustody` is public and unsealed, and `DidMethod::create` takes
`&impl PreRotationCustody`, so any consumer can seed that directory. Three rounds
falsified three spellings of this same claim, each time by construction rather than by
reading.

**State the precondition, never the provenance.** The durable form names what must be true
of the state:

> the reload branch needs a directory that already holds an identity record, and a custody
> holding that record's key handles

That sentence survives a consumer who seeds the directory, because it never claimed nobody
could. It is also the more useful sentence: a reader wanting the reload branch to work now
knows what to arrange.

A `publish = false` manifest key does not narrow the claim either — a path dependency
ignores it, which is how the falsifying consumer compiled against a bridge-internal crate.

## Why the review loop could not catch this

Every round's findings were real, and fixing each one was correct in isolation. The loop
failed because the findings were *symptoms of the scope*, not of the sentences. A reviewer
asked to attack an artifact reports what is wrong with the artifact; it takes a different
question — should this artifact be here at all — to end the loop.

CLAUDE.md already names the signal: more than about three review passes surfacing a new
spelling of the same defect means the approach is non-convergent, and the instruction is to
stop and reframe rather than grind. Nineteen rounds is not a thorough review. It is a
missed signal, and the cost was 700 lines that had to be removed anyway.

## How to apply

- Before adding explanatory prose to a surface, check whether the branch changes that
  surface. When it does not, the prose belongs to whoever owns that surface.
- When a fix seems to require explaining a subsystem on many surfaces, that requirement is
  the evidence the subsystem's documentation is a workstream. File it; do not adopt it.
- Write preconditions on state. A sentence claiming what only some build could have done
  is falsifiable by anyone who writes a consumer, and public unsealed traits mean someone
  can.
- Count review rounds on one artifact. Three rounds of new spellings is the stop signal.
