# A First Run That Passes Can Be Your Own Leftover State

**Date:** 2026-08-22
**Source:** branch `fix/rustls-webpki-advisories` — a run of
`crates/scp-node/examples/website.rs` appeared to refute a reviewer's finding, and
had reused an identity an earlier run persisted.

## The Rule

When a run is meant to exercise first-boot behaviour, point every state directory the
program reads at an empty one. Otherwise the run takes a load branch and never reaches
the branch that creates state, and a pass proves only that the second run works.

A reviewer reported that `crates/scp-node/examples/website.rs` compiles and still
fails at runtime. Running it printed `Site is live — open: http://localhost:18099/`,
which reads as a refutation. It was not one. The run reused an identity an earlier
run had already persisted under `$XDG_DATA_HOME/scp/node`, so it took the load
branch and never reached the branch that creates one.

Pointing `XDG_DATA_HOME` at an empty directory reproduced the report exactly:

```
$ XDG_DATA_HOME=/tmp/fresh PORT=18101 cargo run -q -p scp-node --example website
Error: NodeBuild("identity error: no production pre-rotation custody backend
available; pre-rotation recovery custody is not yet implemented — see #1729 / RFC #2130")
exit 1
```

`host_site` asks for `IdentitySource::Persisted`. Creating a new identity needs a
`PreRotationCustody` backend, and `grep -rn "impl.*PreRotationCustody for" crates/`
returns exactly one implementation, the test-harness
`InMemoryPreRotationCustody`. So a shipped build fails closed rather than mint a
nullifier-backed identity — the no-stand-ins tenet working as designed, and a fact
the example's own "Run this, then open the printed URL" instruction did not carry
until this branch added it.

When a run is supposed to exercise first-boot behaviour, point every state
directory the program reads at an empty one. A first run that finds a persisted identity takes the load branch, so it never
reaches the branch that creates one.
