---
name: durable-leaf-timestamp-sourcing
description: Every durable event-log leaf takes its timestamp from a convergent value, never the appending member's now(); the per-class sourcing rules to reuse at a new append site
metadata:
  type: project
---

The event log is convergent (RFC 6962 Merkle tree, leaf = `SHA-256(0x00 ‖ rmp_serde(Event))`),
so §9.9.3 equivocation detection needs honest members to hash byte-identical leaves. A leaf
stamped with each member's local `now()` diverges between honest members and reads as
equivocation. Every durable append site therefore takes a value every member already holds.

**Sourcing rules (reuse for a new append site):**
- Governance-executed leaves and conflict leaves: `proposal.created_at` (signed, replicated).
- `GovernanceFreezeExpired`: `freeze_start + FREEZE_TIMEOUT_SECONDS`, captured before
  resolution clears the freeze.
- Deferred ceiling or economic-policy application: `pending.effective_at`.
- `ContextTombstoned`: `migration.grace_period_end`.
- TTL `ContextExpired` / `ContextClosed`: `state.ttl.timer.deadline_unix_secs`.
- Membership and commit-lifecycle leaves: the committer's clock, which equals the outgoing
  commit envelope's `created_at`; receivers copy it.
- `ContextCreated`: the creator's creation time (`creation_timestamp_secs`).
- Durable consequence leaves: `convergent_consequence_timestamp` in
  `scp_protocol::trust::consequence` (the latest-sequence evidence timestamp).
- Receive path: the inbound envelope's `inner.timestamp`, which is in milliseconds; divide by
  1000.

A value that is both a convergent leaf base and an authorization-window gate needs both
concerns split: the leaf keeps the convergent base, and the gate adds a local floor with
`max(...)` (see the notification-window rule in security-reviewer's memory).

**Cross-crate coupling:** the consequence and token-revoked leaf payloads are
`serde_json::json!` values whose bytes depend on sorted key order, which holds only while no
crate in the workspace enables `serde_json`'s `preserve_order` feature. A new dependency that
enables it through feature unification changes leaf bytes and breaks the known-answer tests.
