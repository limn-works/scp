---
name: ban-evasion-2088-durable-ban
description: #2088 durable ban-evasion fix review (f030cdab5) — durable banned_subscribers record; residual gap for never-subscribed read-revoked members
metadata:
  type: project
---

# #2088 durable ban fix (base 760fe22a9 → f030cdab5)

Fix: `BroadcastContext.banned_subscribers: HashSet<String>` — durable per-context ban record independent of `subscribers` roster and runtime `read_exclusion_list`.

- Written by `governance_ban_subscriber` (protocol mod.rs:1570), called from `execute_revoke` Read/Both branch (governance_helpers.rs:923). Cleared ONLY by `governance_unban_subscriber` (mod.rs:1626) via RestoreAccess (governance_helpers.rs:1075). Both gated on `MemberBan` in ceiling. Teardown paths (leave_context, unsubscribe_broadcast/remove_subscriber) do NOT touch it — CONFIRMED.
- Structural guard at the sole roster-add chokepoint `BroadcastContextClassCParts::subscribe` (mod.rs:738), before dup check + insert (line 768 only prod insert). register_subscriber funnels through it. Runtime gate also in broadcast_helpers.rs:104 before roster mutation.
- Persisted via `BroadcastContextSnapshot.banned_subscribers` (#[serde(default)]), rides Class-S ContextSnapshot fail-closed persist (commit_class_s_keep). serde-default downgrade NOT a risk: snapshots are local persistence, never attacker-supplied wire data.
- §5.9 no over-eviction preserved: read-revoke keeps membership, suspends only messages:read. Both gates (is_banned AND read_exclusion_list) fire = defense-in-depth.

## RESIDUAL (MEDIUM, reported): never-subscribed read-revoked member
`governance_ban_subscriber` early-returns MemberNotFound (mod.rs:1554) if DID not currently in `subscribers`; caller SWALLOWS it (governance_helpers.rs:927). So for a broadcast-context MEMBER who holds a replayable `messages:read` UCAN but was NOT a subscriber at ban time (e.g. author, co-admin granted read who deferred subscribing), NO durable ban is recorded — only `read_exclusion_list` (self-clearable via leave). Fix's own comment (broadcast_helpers.rs:97-100) concedes this population. Attack: RevokeAccess{Read} on such a member → self-leave clears read_exclusion_list → replay retained read UCAN → re-subscribe. Same #2088 laundering, reopened for that population. Fix: record ban unconditionally in execute_revoke{Read} (new record_ban insert) independent of subscriber presence. Primary attack (active subscriber) IS fully closed.
