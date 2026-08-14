---
name: gated-broadcast-subscribe-38ba6a0f7
description: Review of the gated-broadcast-subscribe UCAN enforcement fix (commit 38ba6a0f7); found a real re-subscribe-after-ban replay hole
metadata:
  type: project
---

# Gated broadcast subscribe UCAN enforcement (commit 38ba6a0f7)

Fix makes gated `messages:read` UCAN enforcement REACHABLE at broadcast subscribe:
handler `handle_subscribe_broadcast` (crates/scp-runtime/src/context/actor/handlers/broadcast.rs)
now builds a real `ValidationContext` (mirrors `saga::validate_ucan_rebind`) and threads UCAN
through PyO3/NAPI/UniFFI bridges (parse_ucan at boundary, fail-closed None→None).

**SOUND:** ValidationContext sources correct (ceiling=role_state.ceiling context-wide,
creator_did, revoked_spending_ucan_cids, KeyResolverDidResolver, cloned InMemoryProofResolver,
audience=subscriber). context_id binding authoritative (self.context_id). Bridge parse no-panic.
Cross-context / wrong-signer / wrong-audience / missing-UCAN all rejected. Tests cover these.

**HIGH FINDING (re-subscribe-after-ban replay):** admission path (protocol `subscribe` +
runtime `subscribe_broadcast`) does NOT consult `read_exclusion_list` or the member's suspended
`MessagesRead` capability. `execute_revoke` (Read scope, governance_helpers.rs) records revocation
in read_exclusion_list + capability suspension + `governance_ban_subscriber` (which REMOVES the
DID from `subscribers`), and does NOT add the UCAN CID to revoked_spending_ucan_cids. So a banned
member replays the SAME still-valid messages:read UCAN: duplicate-subscriber reject no longer fires
(roster entry removed by ban), revocation-CID check misses (wrong set), ceiling still admits
MessagesRead (context-wide, suspension is per-member) → re-admitted to roster + spurious MemberJoined
leaf + participation corruption. The code comment's claim that replay is "neutralised structurally
by the duplicate-subscriber reject" is FALSE for the post-ban/post-unsubscribe case.
Content confidentiality is defended in depth at SERVE time (broadcast_helpers.rs:744 consults
read_exclusion_list on SenderKeyRequest), but the admission boundary + audit integrity are not.
FIX: subscribe must reject DIDs in read_exclusion_list / with suspended MessagesRead. Not a
nonce-tracker issue — a stateful tracker wouldn't help (legit unsub→resub reuses nonce).
