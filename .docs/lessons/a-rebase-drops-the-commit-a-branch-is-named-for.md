# A Rebase Drops the Commit a Branch Is Named For, and Corrects Nothing Else

**Date:** 2026-08-23
**Source:** branch `fix/rustls-webpki-advisories`. Pull request #2382, which cleared the
Rust 1.98.0 clippy lints and named the Rust version in one file, took the `rustls-webpki`
0.103.10 -> 0.103.13 bump and the deletion of the RUSTSEC-2026-0098, RUSTSEC-2026-0099,
and RUSTSEC-2026-0104 ignore entries into `main`. This branch then rebased onto that
commit, and the advisory commit it had carried is now an ancestor of neither `main` nor
the branch, because `main` already carried the same edits to both files. The branch
name, the pull-request description, and one lesson in `.docs/lessons/` went on naming
the advisory fix as this branch's contract.

## The Rule

**After a rebase, measure the branch's diff against its new base, and reconcile every
artifact that describes the branch against that measurement.** A rebase drops a commit
whose patch the new base already carries. It rewrites no artifact: not the branch name,
not the pull-request title or description, not prose on the branch that cites the dropped
work.

The check is one command:

```sh
git diff origin/main...HEAD --numstat
```

Every file-level claim any artifact makes about the branch has to name a file on that
list. A description that names `Cargo.lock` while the list does not is a false record, and
it costs a reviewer the whole review: approving a certificate-validation fix against a
diff that touches no certificate-validation code examines an empty set.

## Why a line-by-line review misses it

A reviewer reading the diff checks each changed line, and the dropped change has no line
for a comment to sit on. The claim lives in the pull-request description, above every
file. Nineteen review rounds on this branch produced findings about sentences inside the
diff. The sentence that named work outside the diff survived all of them, and a reviewer
found it only by running `--numstat` and reading the file list against the description.

## How to apply

- Run the `--numstat` diff against the new base immediately after any rebase, and read the
  file list rather than the summary count.
- Rewrite the pull-request description from that file list, not from the previous
  description.
- Grep the branch's own prose for the dropped work. A branch that documents its reasoning
  cites the commit it lost.
- When the branch name states a contract the branch no longer carries, say so in the first
  paragraph of the description. A reader who cannot rename the branch can still be told
  the name is stale.
