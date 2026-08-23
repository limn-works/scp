# A Published Package Carries the Grant, Not a Pointer to One

**Date:** 2026-08-23
**Source:** branch `ci/release-pipeline-multiregistry` — review of the
`publish-spm` job in `.github/workflows/release.yml`

## The Rule

When a release job assembles a package out of a subset of this repository, the
`LICENSE` file it writes MUST be the license text `LICENSING.md` assigns to that
subset, and it MUST name no file the package does not contain.

This repository splits licensing across four root files: `LICENSE` summarizes the
structure and points at the other three, `LICENSING.md` holds the component table,
`LICENSE-APACHE` grants the SDK and the bindings their terms, and `LICENSE-AGPL`
grants `scp-node` its terms. Only `LICENSE-APACHE` and `LICENSE-AGPL` carry a
grant. `LICENSE` and `LICENSING.md` describe where the grants live, which makes
them useless to a package that carries neither file.

## Context

The `publish-spm` job builds the `limn-works/scp-swift` mirror from
`bindings/swift/Package.dist.swift`, the Swift sources, and one license file. It
ran `git rm -rqf .` to clear the mirror and then `cp ../LICENSE LICENSE`, so the
published package's only license file was the nine-line pointer. That file reads
`See LICENSING.md for the full structure, FAQ, and rationale` and
`Client SDK and bindings   Apache License 2.0 (LICENSE-APACHE)`, and the mirror
contained neither `LICENSING.md` nor `LICENSE-APACHE`.

A Swift developer who added the package and opened `LICENSE` would have found two
dangling references and no grant, and a license scanner would have reported the
package as unlicensed — while `LICENSING.md` line 10 assigns the bindings Apache
2.0.

## The Fix

The job copies the grant itself:

```sh
cp ../LICENSE-APACHE LICENSE
```

`scripts/check-release-pipeline.py` enforces the rule mechanically. It reads
`LICENSING.md`, finds the table row whose component cell names the bindings, takes
that row's markdown link target, and requires the `publish-spm` job to copy that
exact file — and exactly one file — to the mirror's `LICENSE`. Relicensing the
bindings in `LICENSING.md` moves the requirement with them, because the gate reads
the table rather than a file name written into the gate.
