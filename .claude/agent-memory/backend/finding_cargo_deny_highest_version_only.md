---
name: finding-cargo-deny-highest-version-only
description: cargo-deny reports a RUSTSEC advisory against only the HIGHEST version of a duplicated crate — bumping a direct dep can turn the gate green while unsound copies still ship via transitive deps
metadata:
  type: project
---

`cargo deny check advisories` evaluates a RUSTSEC advisory against only the
**highest** version of a crate that appears multiple times in the graph. Lower
duplicate versions that are equally affected are silently never reported.

Proven empirically on 2026-08-14 with cargo-deny 0.20.2 (the version
`EmbarkStudios/cargo-deny-action@v2` pins) against RUSTSEC-2026-0253 (`lru`
use-after-free, patched `>= 0.18.2`):

- Workspace graph had `lru` 0.12.5 (via `aws-sdk-s3`) + 0.16.3 (via `mainline`
  and our direct dep). Only **0.16.3** was reported.
- An isolated scratch crate depending on `lru = "=0.12.5"` alone reported
  **two** errors (RUSTSEC-2026-0253 and RUSTSEC-2026-0002) — so 0.12.5 is
  genuinely affected; the workspace run simply suppressed it.
- After bumping our direct dep to 0.18.2 the graph held 0.12.5 + 0.16.3 +
  0.18.2 and `cargo deny check` went **green** — while both unsound copies
  still compiled into the shipped binaries.

**Why:** the gate's silence is not proof of absence. A dependency bump that
merely adds a patched version on top of unpatched duplicates produces a
false-green — the exact "nullifier lies, absence is detectable" failure the
no-stand-ins tenet warns about.

**How to apply:** whenever a RUSTSEC fix is a version bump, check
`cargo tree -i <crate>@<version>` (or `grep -n 'name = "<crate>"' -A2
Cargo.lock`) for *every* copy in the lock, not just the flagged one. State
plainly which copies remain and which upstreams pin them. Never report an
advisory as "cleared" on the strength of a green `cargo deny` alone.

Also note: local `cargo-deny 0.19.0` did not detect RUSTSEC-2026-0253 **at
all** (informational `unsound` advisory). Always match the CI binary version —
download it from the cargo-deny GitHub releases rather than trusting the
locally-installed one. See [[feedback-verify-ci-tool-version-matches]].
