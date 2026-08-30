# An "Awaiting Upstream" Advisory Ignore Is a Claim About a Date

**Problem**: `deny.toml` suppressed three rustls-webpki advisories with the justification
"Awaiting upstream rustls-webpki patch". rustls-webpki had published the patch for all
three four months before anyone read the file again, and every requirement on that crate in
this workspace was semver-compatible with the fixed release, so
`cargo update -p rustls-webpki --precise <fixed>` moved one lockfile entry and nothing else.
Until then the relay kept linking a version that accepts a URI name constraint it should
reject, accepts a wildcard-asserting certificate under a permitted DNS-name constraint, and
panics on a syntactically valid empty `BIT STRING` in a certificate revocation list's
`onlySomeReasons` extension before that list's signature is verified.

**Root cause**: the justification states a fact about the world on the day somebody wrote
it, and the file does not age with the world. An operator reading `deny.toml` to learn which
advisories this repository still carries reads "no fix exists" and leaves every entry
suppressed.

## Rules

- **An ignore entry whose justification is the absence of a fix is a claim to re-check
  against the advisory database's `patched` range, not a decision to record once.** Re-check
  every such entry whenever you touch the file, and delete the ones the upstream has since
  fixed.
- **Write the justification so a reader can check it.** Name the upstream release that would
  clear the entry, or the reason no release can. "Awaiting upstream" names neither, so
  nothing in the entry tells a later reader how to decide whether it still holds.
- **Deleting the entry is the fix, and the audit is the enforcement.**
  `cargo deny check advisories` — which the `rust-deny` job runs, guarded by a filter that
  lists `deny.toml` and `Cargo.lock` — fails if the lock ever resolves a vulnerable version
  again, so the entry does not need to stay behind as a reminder.
