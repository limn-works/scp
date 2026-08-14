# `OwnedIdentityDid`: an unforgeable capability the compiler enforces

## What it is

`OwnedIdentityDid` (`context/supervisor/identity_capability.rs`) is the token that proves
an actor's identity *owns* it. It is minted once per actor at spawn time inside
`Supervisor::build_actor_deps`, held **by value** in `ActorDeps`, and passed **by
reference** (`&OwnedIdentityDid`) to the `SupervisorHandle` methods that touch
per-identity state. There is no `&DID`-keyed surface an actor can reach — the only
identity an actor can read is the one that owns it. This is how cross-identity isolation
(ADR-049 §5, spec §9.4.1) is enforced: not by runtime checks, but by making the wrong
thing unconstructible.

## Why it is unforgeable — and why there is no CI gate

The guarantee "a token for a given DID only exists if supervisor-module code created it"
rides on **two type-system facts**, not on a scanner:

1. The constructor `issue_for_actor` is `pub(super)` — only supervisor-module code can
   mint a token from a raw `DID`. Handler code in `context/actor/handlers/` cannot name the
   path; the compiler refuses.
2. The single field `did` is **private** — so no struct-literal `OwnedIdentityDid { did }`
   is possible outside the module either.

The struct's *name* is `pub(in crate::context)` (wider than the constructor) so that
`ActorDeps` can hold it and handlers can take a `&`. That widening is safe precisely
because (1) + (2) make **nameable ≠ constructible**: actor code can hold or borrow a
token, but has no path to *mint* one. The struct must never be `pub`/`pub(crate)`.

**Forbidden traits** (the header enumerates them, each with a reason): no `Clone`/`Copy`
(would leak the capability), no `Serialize`/`Deserialize` (would smuggle it across a trust
boundary), no `Default`/`From`/`Into` (fabrication without the blessed constructor), no
`Hash`/`PartialEq`/`Eq`, no `Borrow`/`AsRef`/`Deref` (erodes the `&OwnedIdentityDid`
contract), no `Debug`/`Display` (accidental logging of an identity token). The only two
methods besides the mint are `reissue(&self)` — clones the *already-attested* DID for a
spawned child, takes no `DID` param, so it cannot forge for an identity the caller does not
already hold — and `as_did(&self) -> &DID`, read-only, which cannot reconstruct the proof.

This capability deliberately has **no bespoke source-text CI gate**. The residual threat is
an insider editing this one file — but that same insider could edit a scanner or its CI
wiring, so a scanner adds *zero* marginal security over the type system, two module lints
(`#![deny(unsafe_code)]` and `#![deny(non_local_definitions)]` in `supervisor/mod.rs`), and
review of a tiny frozen file. That full reasoning — including why a 6,000-line scanner over
this exact type was built and then deleted — is
`ast-gate-checks-definition-not-name-resolution.md`. This lesson is its concrete
capability; that lesson is the general rule.

## Cross-refs

- ADR-049 §5 (capability reduction), spec §9.4.1 (four-point unforgeability criterion).
- `ast-gate-checks-definition-not-name-resolution.md` — why no scanner guards this file.
- `actor-per-context-pattern.md` — the `Send` requirement on `ActorDeps` this token meets.
