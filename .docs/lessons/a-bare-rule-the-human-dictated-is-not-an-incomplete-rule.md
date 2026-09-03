# A bare rule the human dictated is not an incomplete rule

`.docs/standards/concrete-prose.md` lists eleven forbidden constructions. Seven of the
eleven carry a definition or an example. Four carry only a name: introductory patterns,
hedging, maxims, and "X rather than Y" closers. Alec dictated all four names on
2026-08-11 and supplied no definition for any of them.

Two agents have now read the four bare names as a defect.

The first agent wrote definitions and examples for introductory patterns and hedging. A
later commit deleted both, because Alec had dictated the names and the agent had invented
the instances. CLAUDE.md states the governing rule: codify the rule the human dictated,
never the rule plus an example list you wrote.

The second agent filed a post-merge review finding against pull request #2293, the
concrete-prose standard, arguing that four bare names give an author no way to answer the
standard's own pre-send check. That agent proposed writing the four definitions, which is
the move the earlier commit had already reverted.

## What each agent got wrong

Both agents treated the enumeration as the test. The standard already stated its criterion
one line above the list: the writer puts a rhetorical move where a claim belongs. Under
that criterion the four bare names are indicators — they tell a reader where to look — and
the criterion decides membership. An agent who reads the list as the test finds four
entries that decide nothing, concludes the standard is unfinished, and writes the missing
contract itself.

CLAUDE.md names this failure in the Caulfield rule: write the criterion, then label the
indicators as indicators. An indicator list presented as a criterion invites the next
reader to supply the criterion, and the criterion that reader supplies carries the
human's authority without the human's meaning.

## The evidence that the enumeration cannot be the test

Item 9 of the list forbids "X rather than Y" closers. Read as a test, item 9 forbids four
sentences that the same pull request added to CLAUDE.md, among them "treat it as a signal
rather than as missing information". A test that rejects the binding text of the commit
that introduced it is not a test. Under the criterion those four sentences pass, because
in each one the contrast carries the claim.

## The rule

When a human dictates a rule as a bare name, state the criterion the name serves and mark
the name as an indicator. Do not supply the definition the human withheld. A definition an
agent invents binds every later reader as though the human had written it, and no later
reader can tell the two apart.

When you find a rule with no definition, look one line up for the criterion before you
conclude the rule is incomplete.
