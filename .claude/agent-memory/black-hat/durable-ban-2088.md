---
name: durable-ban-2088
description: BLACK-303 serve-path ban bypass and closed status of BLACK-301/302 durable broadcast ban (#2088)
metadata:
  type: project
---

# Durable broadcast ban (#2088) — adversarial status

Commit under review: 7308365f1 (round-2 fixes). NOTE: worktree HEAD is a
different branch (ceiling docs) — always `git show 7308365f1:<file>`, local
line numbers do NOT match.

## Architecture
- `banned_subscribers: HashSet<String>` on `BroadcastContext` (protocol). Durable
  ban record. Survives self-leave AND admin RemoveMember. Cleared ONLY by
  `governance_unban_subscriber` (via authority `RestoreAccess`, quorum-approved).
- SUBSCRIBE chokepoint is guarded twice: runtime `subscribe_broadcast`
  (broadcast_helpers.rs ~104 `is_banned` + ~113 `read_exclusion_list`) AND
  protocol `BroadcastContextClassCParts::subscribe` (mod.rs:738 `banned_subscribers`).
- `read_exclusion_list` (runtime, AccessState) is CLEARED on self-leave
  (lifecycle_helpers leave_context) and admin RemoveMember (execute_remove_member).
  That clearing is the laundering vector #2088 exists to defeat.

## CLOSED (confirmed)
- BLACK-301 (subscriber → leave → re-subscribe): banned_subscribers survives leave;
  subscribe guard rejects. Also block_list on every author survives. CLOSED.
- BLACK-302 (member/non-subscriber → leave → re-subscribe replay): subscribe guard
  rejects; and at serve path a plain member is neither subscriber nor author →
  handle_key_request roster check denies. CLOSED.
- Goal 2 (Finding 2 new hole): NONE. execute_restore_access widened only the
  NothingToRestore predicate (added `durably_banned`). Actor authz unchanged =
  quorum-approved proposal + MemberBan ceiling. No self-service un-ban.
- Goal 3 (ban→leave→re-add via AddMember): execute_add_member never touches
  banned_subscribers/unban. Re-added banned DID still rejected at subscribe. CLOSED.
- Goal 4 (Write-only revoke): governance_ban_subscriber called ONLY in Read|Both
  arm; Write-only calls block_author, never inserts banned_subscribers. Correct.
- Goal 5 (snapshot): to_snapshot clones banned_subscribers, from_snapshot restores.
  Survives restart. Sound.

## OPEN — BLACK-303 (serve-path parity gap)
The durable ban is enforced ONLY at subscribe. The broadcast key-request SERVE
path `handle_broadcast_key_request` (broadcast_helpers.rs ~758-792) checks
`local_dids` + `read_exclusion_list` then delegates to
`bc.handle_key_request` (mod.rs:1975) which checks block_list + roster(subscriber
OR author) + has_ucan. NEITHER consults `banned_subscribers`.

Attack: a read-banned DID that is a broadcast AUTHOR (in self.authors) — includes
the always-seeded context creator (manager_methods.rs:203 add_author(creator)) —
reads broadcast content after the ban:
1. Read-scope revoke (or ban-then-reauthor) → banned_subscribers set,
   read_exclusion set, BUT non-subscriber path skips block_list, and author stays
   in self.authors (governance_ban_subscriber early-returns before block loop).
2. Self-leave → leave_context clears read_exclusion, but bc.unsubscribe(author) is
   a no-op (MemberNotFound ignored) so authorship in self.authors SURVIVES.
3. Key request → serve path: read_exclusion empty (cleared) → passes; not in any
   block_list; IS an author → GRANT. Decrypts despite is_banned==true.
Gated by needing author status (admin-mediated: Read-scope choice or later write
grant), so weaker attacker-control than 301/302, but violates the stated
invariant "read-ban denies broadcast read, cleared ONLY by RestoreAccess".
Serve path is UNTESTED for banned-author-post-leave (tests only cover re-subscribe).

Fix: add `banned_subscribers` consult to handle_broadcast_key_request (parity with
subscribe), not just read_exclusion_list.
