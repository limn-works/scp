---
name: relayres004-relay-write-path-5b89baada
description: SCP-RELAYRES-004 relay WRITE path (branch worktree-agent-ac667e2f552c34a31 @5b89baada) — round-2 confirming pass; all 5 round-1 mandates verified resolved, 3 new findings on the fix-round surface
metadata:
  type: project
---

Round-2 API review of the SCP-RELAYRES-004 relay WRITE path (issue #482), branch
`worktree-agent-ac667e2f552c34a31` @ `5b89baada`, 9 commits.

**All five round-1 mandates verified resolved from code** (not self-report):
`RepublishEntry.did` field deleted in favour of a derived `did()`; `HealingPublisher::heal`
6 positionals → `(did, stale_layer, &DidRecordV1)`; the `bound_relay_count() > 0`
construction-time gate deleted (arm unconditionally enabled, publish fails closed per tick);
`did_key_routing_id`/`did_record_routing_id` placed beside `did_routing_id` with a symmetric
root re-export; `blob_ttl` → `blob_ttl_secs` plus a dedicated `IdentityError::DidRecordFramingFailed`.
The "one key→routing_id derivation" claim is TRUE at HEAD — all four production sites call the
shared helper; the only recompositions left are deliberately-documented test oracles.

**Verdict: NEEDS REVISION on three new items.**

1. **PRD/code drift the branch itself introduced.** The branch added 8 `bound_relay_count()`
   references to `.docs/prds/relay-did-resolution.json` (lines 240/244/254/345/349/353/412/414)
   while the accessor has zero code hits — including the *next* slice SCP-RELAYRES-006's
   machine-verifiable ACs. Round-1 asked to drop the *gate*, not the *accessor*. Cheapest fix:
   expose `TransportRelayPublisher::bound_relay_count()` delegating to the existing
   `BoundRelays::len()`, used for observability only, never for gating.
2. **`RelayPublishOutcome` invariant is doc-only.** `accepted`/`attempted` are `pub usize` with
   no constructor, so an external `RelayPublisher` impl can return `Ok(RelayPublishOutcome {
   accepted: 0, attempted: 0 })` — and `is_complete()` (`accepted >= attempted`) reports that as
   fully healthy, resetting the republish loop's failure counter. `NonZeroUsize` for `accepted`
   makes the documented "always >= 1 in Ok" structural.
3. **Asymmetric root re-export.** `RelayQuerier`/`RelayQueryRecord` (READ half) are root-exported
   from `scp-identity`; `RelayPublisher`/`RelayPublishOutcome` (WRITE half) are not — the exact
   argument this PR wrote into the routing-id family's re-export comment.

Recurring pattern worth carrying forward: this codebase's reviews converge fastest when a
"documented invariant" is challenged into a *typed* invariant (`DidRecordV1` making unframed
bytes unrepresentable, derived-`did()` removing two-source-of-truth). Apply the same test to any
new struct with `pub` fields and a doc-stated range constraint.

Related: [[cross-sdk-shape-parity]].
