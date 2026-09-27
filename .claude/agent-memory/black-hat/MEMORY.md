# Black Hat Agent Memory

Attack shapes that produced real findings in this codebase. Check these first.

- **Caller-supplied key material used as verification material.** A bridge that verifies a caller's attestation against a caller's key answers `true` to whoever supplies both. Check every `verify_*(&caller_key)` signature.
- **An identifier used as a security key without issuer scoping.** A revocation list, cache, or dedup map keyed on a free-form id lets one party's record govern another party's record. Check what a `check_*` implementation discards (a `_issuer` parameter is the tell).
- **A pure verifier with zero production callers.** A shipped verify function nobody calls is a false guarantee to any reader of the type signature. Grep for callers outside test modules before crediting a fix.
- **Metadata a subject declares about itself feeding a trust score.** Shared memberships, endorsements, freshness stamps, and verifier names inside a self-signed record raise a score without an independent signature. Penalties that only lower a score let "declare nothing" earn the maximum.
- **Self-certifying DIDs make sybil identities free.** A resolver that extracts a public key from a DID string admits any freshly generated keypair at zero cost, so a count of distinct DIDs is not a count of distinct parties.
- **Counting events that target a DID instead of events by it.** A consequence rule that counts actions targeting a member lets anyone who can create those actions trigger automated penalties against an innocent member.
- **A boolean bridge return collapsing distinct verdicts.** Degraded, absent, forged, and rotated all become one `false`, and the caller cannot tell them apart.
- **A resolver closure that ignores its key-id argument.** A resolver written as `|did, _| lookup(did)` returns one key for both `#active` and `#agent`, so an agent-signed message verifies as the human's. Check that every production resolver branches on `SigningKeyId`.
- **Security state that lives only in memory.** A nonce set, a sequence high-water mark, or a dedup map held in memory resets on process restart, actor respawn, or browser page reload, which reopens replay for the token's remaining lifetime.
- **A gate that iterates only over what already exists.** A call-invariant rule keyed on a caller name reports nothing when that caller is deleted, so it cannot detect a removal.
- **An alias list widened until a fail-closed stub satisfies a symmetry check.** Adding a declining stub's name to a canonical operation's alias list weakens that assertion rather than widening its coverage.
- **A coverage gate that folds type names into runtime symbols.** When an extractor collects interface and type-alias names alongside functions, a type named like the operation (`MemberRole` for `member_role`) satisfies the gate after every runtime implementation is deleted.
- **A textual prefix-strip ahead of a substring gate.** Deleting `~/.claude/...` tokens before a basename check lets `..` traversal, a symlink under the prefix, `HOME=` rebinding, `{~/x,repo/f}` braces, and `$(basename ~/.claude/f)` launder a repo write. Test each against the old gate.
