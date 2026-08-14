# A Fail-Closed Gate's Escape Hatch Must Be Closed By Construction

**Context**: `scripts/check-sdk-coverage.py` was hardened to fail-closed (exit 1) on any
capability-matrix `true` cell whose code can't be found, and an escape hatch was added —
a `coverage_exemptions` field in `sdk-capability-matrix.json` that lets an SDK declare a
capability exempt with a prose reason.

**Problem**: The exemption was validated only by *presence of prose*. The adversarial
reviewer proved it forgeable: a fabricated capability name plus any reason string =
green CI. A prose "reason" check verifies nothing — it is a free pass spelled as a
justification. The whole point of fail-closed (turning a warning into an error) is
defeated the moment the error has a text-only bypass.

**Root cause**: An escape hatch on a fail-closed gate is itself part of the gate's
soundness boundary. If the hatch is satisfiable by attacker-controlled free text, the
gate is no more sound than before it was hardened — it just *looks* enforced.

**Rule**: An exemption must be verified against something the author cannot trivially
fabricate, not against prose.

For the SDK coverage gate specifically: an exemption for SDK X on capability C is only
valid if **at least one other SDK has `true` for C without an exemption** — i.e. the
capability is proven real by a genuine implementation somewhere. If *every* SDK with
`true` for C carries an exemption, the capability is unproven and the gate must **fail**.

Generalize: when you add an escape hatch to a fail-closed check, ask "what stops me from
writing the magic words and bypassing this?" If the answer is "nothing — the words are
the check," the hatch is forgeable. Tie the exemption to an independently-verifiable fact
(another real implementation, a cross-referenced symbol, a cryptographic artifact), so
the hatch is closed by construction.

See also `.docs/lessons/test-whitelist-masks-ci-red.md` (a narrowed local view is not the
authoritative gate) and `.docs/lessons/lock-free-read-invariant.md` (closed-by-construction
> denylist-chasing). The CLAUDE.md "non-convergent enforcement" guidance applies: a gate
should be a positive whitelist of permitted shapes, not a hatch that accepts any spelling.
