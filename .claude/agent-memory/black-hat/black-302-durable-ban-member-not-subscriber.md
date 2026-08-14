---
name: black-302-durable-ban-member-not-subscriber
description: BLACK-302 — #2088 durable-ban fix does NOT record a ban when RevokeAccess{Read} targets a member who is not currently a broadcast subscriber; laundering path remains open
metadata:
  type: project
---

# BLACK-302 — durable-ban gap for member-not-subscriber (#2088 fix)

The #2088 fix (commit f030cdab5) added `banned_subscribers: HashSet<String>` to
`BroadcastContext`, written by `governance_ban_subscriber`, cleared only by
`governance_unban_subscriber` (RestoreAccess). It correctly closes the ORIGINAL
BLACK-301 (ban a live subscriber -> self-leave -> replay).

**Residual hole:** `governance_ban_subscriber` (crates/scp-protocol/src/context/broadcast/mod.rs:1554)
returns `MemberNotFound` and records NOTHING if the DID is not currently in
`bc.subscribers`. The runtime `execute_revoke` (crates/scp-runtime/src/context/governance_helpers.rs:927)
SWALLOWS that `MemberNotFound`. But `read_exclusion_list.insert` runs first
(governance_helpers.rs:920). So a RevokeAccess{Read} against a member-not-subscriber
sets only `read_exclusion_list` (self-leave-clearable at lifecycle_helpers.rs:342)
and NO durable ban -> exact BLACK-301 laundering reopens.

**Reachable member-not-subscriber targets** (membership and bc.subscribers are
DISTINCT sets; subscribe adds both, unsubscribe removes both, ban/restore keep
membership but not subscription):
- Context creator/admin: added to `membership` as "admin" at creation
  (lifecycle_helpers.rs:1493) but NOT a broadcast subscriber. Always available;
  a co-admin / quorum can RevokeAccess{Read} on the creator.
- Any member after a ban->RestoreAccess cycle who has not re-subscribed:
  execute_restore (governance_helpers.rs:1066-1116) restores read cap + clears
  read_exclusion_list + un-bans, keeps membership, does NOT re-add to subscribers.
  A subsequent re-ban fails to record the durable ban.
- Authors who are also members but never subscribed.

Open broadcast makes it worse: re-subscribe needs no UCAN at all.

The coder's own comment (broadcast_helpers.rs:98-101) ACKNOWLEDGES these members
("not yet in banned_subscribers if never a broadcast subscriber") and wrongly
relies on read_exclusion_list to catch them — but self-leave clears exactly that.

**Fix direction:** record the durable ban on RevokeAccess{Read} regardless of
current subscriber status (ban the DID unconditionally, or gate on membership not
subscription); do not swallow MemberNotFound in a way that drops the ban.

Confirmed sound: single-actor-per-context serializes ban-write vs gate-read (no
TOCTOU); register_subscriber funnels through the guarded subscribe chokepoint;
snapshot round-trip preserves banned_subscribers (serde-default only affects
pre-existing old snapshots, not attacker-forceable at runtime).
