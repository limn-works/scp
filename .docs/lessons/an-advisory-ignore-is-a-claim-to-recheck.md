# An Advisory Ignore Is a Claim to Re-Check, and a Local `cargo deny` Sees Less Than CI

## An "awaiting upstream" ignore goes stale silently

`deny.toml` suppressed three rustls-webpki advisories with the justification "Awaiting
upstream rustls-webpki patch". The patch had shipped four months earlier and a lock-only
`cargo update -p rustls-webpki --precise 0.103.13` fixed all three, while the relay kept
linking a version that panicked on a crafted certificate revocation list before verifying its
signature.

- **An ignore whose justification is the absence of a fix is a claim to re-check against the
  advisory's `patched` range whenever you touch `deny.toml`.** Delete the entries upstream has
  since fixed.
- **Write the justification so a reader can check it:** name the release that would clear the
  entry, or the reason no release can.
- **Never write "do not delete this entry."** The reader who obeys it never runs the
  `cargo update --dry-run` that shows the mask is unnecessary.

## A local run is a lower bound on what CI reports

A local `cargo deny check advisories` (cargo-deny 0.19.0, advisory database fetched that day)
reported RUSTSEC-2026-0097 as `advisory-not-detected` while `Cargo.lock` resolved an affected
rand release; the `Rust / deny` job, which runs `EmbarkStudios/cargo-deny-action`, reported
the same advisory as `error[unsound]` against the same lockfile. The cause of the difference
is unknown. So before deleting an ignore entry, open its record under
`~/.cargo/advisory-db/`, read the `patched` range, and delete only when one of these holds:

1. `cargo update --dry-run -p <crate>@<locked version>` moves the crate into the patched
   range. Run the update and delete the entry. An ignore is keyed by advisory ID, so it masks
   every affected major line in the lock at once; update each one.
2. `cargo tree -i <crate>` prints nothing, so nothing reaches the advisory.

Otherwise the entry stays, and its comment names the release that clears it.

`fuzz/Cargo.lock` is a second lockfile that resolves the workspace crates through path
dependencies, and no CI job runs `cargo deny` against it. Repeat every lock-only fix inside
`fuzz/`.
