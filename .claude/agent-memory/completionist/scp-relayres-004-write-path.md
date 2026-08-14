---
name: scp-relayres-004-write-path
description: SCP-RELAYRES-004 relay WRITE path @5b89baada — code COMPLETE (F1/F2/F3 all fixed), but the PRD diverged from its own branch (phantom bound_relay_count, stale 008)
metadata:
  type: project
---

# SCP-RELAYRES-004 (relay WRITE path) — double-zero confirming pass @ `5b89baada`

Branch `worktree-agent-ac667e2f552c34a31`, 9 commits, PRD `.docs/prds/relay-did-resolution.json`.

**Verdict: INCOMPLETE — code side clean, ARTIFACT side diverged.**

## Round-1 findings, all genuinely fixed
- **F1 (dead relay arm)** — the one-shot `bound_relay_count()` latch AND the method itself were
  deleted (`36358fc17`). Arm is now unconditionally scheduled; `TransportRelayPublisher::publish`
  fails closed per tick with `IdentityError::RelayPublishFailed`. Proven by
  `relay_arm_self_heals_when_a_relay_is_bound_after_start` (`start_paused`, bind after start,
  advance 31s past backoff, assert frame published).
- **F2 (§3.10.6 warning suppressed)** — `grep -n disable_relay crates/scp-node/src/self_host.rs` = 0;
  production config wires the layer-disabled callback and keeps both layers enabled.
- **F3 (DHT read-back entry sourcing)** — `DidMethod::publish` now returns `RepublishEntry`;
  `PublishedDidRecord` watch slot; `self_did_republish_entry` and `dht_client.resolve` gone from
  self_host.rs.

All 7 ACs of 004 verified met. fmt/clippy/tests green for scp-identity + scp-transport + scp-node.

## The finding that made it INCOMPLETE: PRD phantom symbol
`bound_relay_count()` appears **8× in the PRD** (004 ×4, 006 ×4, 007 ×2) and **0× in the code**.
The story was rewritten in `4f6c247d3` against the mid-branch state, then `36358fc17` deleted the
method — the artifact was never re-synced. 006 AC3/AC7 and 007 AC4/AC6 are unimplementable as
written. This is the exact phantom-provenance class the rewrite existed to retract, reintroduced
in the same PR.

Also: **SCP-RELAYRES-008 (pending) is stale** — its AC1 and AC5 are already satisfied by 004's
own commits, and its root-cause narrative is false at HEAD.

Also: **SCP-CAPINJECT-011** is `status: pending` in `adr062-capability-injection.json` while all
six ACs are satisfied on `origin/main` — and 004 lists it in `blockedBy`.

## Reusable lessons
- **When a branch rewrites its own PRD mid-flight, re-diff the artifact against the FINAL code.**
  A story rewritten at commit N is evidence about commit N, not about HEAD. Grep every symbol the
  story names against HEAD; a story-named symbol with 0 code hits is a finding.
- **Symbol-count grep across the whole PRD file, not just the story under review** — a deleted API
  poisons every downstream pending story that cites it.
- Env gotcha: `cargo test -p scp-node` **requires `--features testing`** (`DhtMode::Memory` is
  `#[cfg(feature = "testing")]`). Without it you get a bogus E0599 that looks like a branch break;
  it is pre-existing on main. Use an isolated `CARGO_TARGET_DIR` (shared-target poison).
