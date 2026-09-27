# Security Reviewer Memory

## Security design rules this codebase has learned the hard way
- **A proposer-signed timestamp is tamper-evident but proposer-chosen.** Anchoring a notification window on `proposal.created_at + PERIOD` let a proposer backdate `created_at` and collapse the 24-hour window. The fix floors the window on the applying member's own clock (`observed_at`, captured at commit) and keeps the convergent `effective_at` for the durable leaf. On import of an untrusted export, re-pin `observed_at` to the importer's clock (the export's creator signs whatever it likes); on self-restore, keep it verbatim, or a crash loop re-arms the window forever.
- **A record only the receiver can mint must not enter the durable log.** An equivocation record is receiver-minted and unauthenticated by the sender, so appending it would diverge honest members' Merkle roots and trigger false equivocation. Keep it buffer-only with in-memory dedup.
- **Verify the signature before anti-replay state advances.** Advancing a sequence tracker on an unverified message lets a forger poison it.
- **A message held in a reorder buffer needs its signature and access key rechecked at delivery,** not only its sender's membership.
- **`derive(Debug)` on a struct holding `Zeroizing<T>` prints the secret.** `Zeroizing<T>` forwards `Debug` to `T`. Write a redacting `Debug` impl for every type that holds key material or a passphrase.
- **Secret bytes that cross into JavaScript cannot be zeroized.** Key bytes returned to a JS `Array<number>` stay on the JS heap; minimize every path that surfaces secret bytes to TypeScript.
- **A three-way merge can keep the weaker side.** When a security feature exists on one parent only, conflict resolution may silently drop it. Diff security-load-bearing files against both parents, not only against the merge base.

## Recurring review findings
- A hash, signature preimage, or HKDF `info` built from concatenated variable-length fields with no length prefix or domain separator allows a boundary-shift collision.
- A freshness check that tests only staleness; check the future bound too.
- A signed wire type without `#[serde(deny_unknown_fields)]`.
- A key-protocol request (sender key or access key) without a nonce and dedup, replayable inside its freshness window.
- `Some(empty_set)` passed at an FFI boundary where `None` was meant, which turns "no ceiling" into "nothing allowed" (or the reverse). Convert empty collections to `None` at the boundary.
- A public entry point that forwards to an internal function with `check_capability: false` becomes a capability bypass for any holder of the handle.
- An error-string classifier that uses `includes()` instead of `startsWith()` on a start-anchored prefix lets attacker-controlled text inside a message steer the classification.
- A readiness or concurrency flag (`AtomicBool`) set before an `.await` and cleared after it, with no RAII guard, stays set forever when the awaited future panics or returns early.
- Two mutexes on one struct acquired in opposite orders on two paths.
- A load-modify-store on shared storage with no atomicity or caller-side serialization.
- A security-relevant doc comment that contradicts the code (a config doc saying "0-RTT enabled" beside code that disables it) invites the next author to "fix" the code to match.
- PyO3: never hold a `DashMap` shard guard across a call that can take the GIL; clone the `Arc` out first.
