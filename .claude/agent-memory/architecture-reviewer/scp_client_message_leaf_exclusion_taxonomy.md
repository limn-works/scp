---
name: scp-client-message-leaf-exclusion-taxonomy
description: scp-client browser driver mints per-author MessageSent Merkle leaves on send+receive, violating ADR-011 exclusion taxonomy §2 — root cause of the ADR-057 T3 convergent-timestamp window/floor churn
metadata:
  type: project
---

# scp-client mints per-author message leaves the spec excludes

The ADR-057 in-browser participant driver (`crates/scp-client`) appends a
durable `MessageSent` Merkle leaf on BOTH send (`client.rs` send_message) and
receive (`client.rs` receive_message, the "mirror-on-receive"). The native
runtime does the OPPOSITE and the spec forbids it.

**Why:** ADR-011 amendment **exclusion taxonomy §2** (`.docs/adrs/phase-2.md`
~L956-969): `MessageSent` is *per-author application activity*, per-author
sequenced, **no global order** → excluded from the canonical Merkle log,
surfaced only as a local `ContextEvent`. Native enforces this:
`messaging_helpers.rs` `deliver_plaintext_or_announcement` returns `None` (never
appends on receive); `finalize_send` (~L2111) emits only `ContextEvent::MessageSent`,
no durable leaf ("M12 / ADR-051 §6"). The spec's real convergent ordering for
these is **ADR-051 causal-DAG** (each event references observed DAG heads; every
member linearizes identically), NOT a per-author timestamp. §25 KAT vectors
carry no MessageSent leaf.

**How to apply:** The convergent-committer-timestamp apparatus (AAD binding +
receiver-clock plausibility window + any proposed per-sender monotonic floor)
exists ONLY to make the browser's receiver-minted message leaf converge — a
problem native/spec dissolved by exclusion. Leaf hash (`tree.rs` leaf_hash over
serialize(event)) includes `sequence`+`prev_hash`, so append order is fully
load-bearing; `context.rs` append_log_event assigns sequence=local event_count →
arrival-order-dependent → convergent for messages ONLY under total delivery order
(MVP dumb-pipe test harness; a real untrusted relay — #1975's whole goal — has
none). Membership `MemberJoined` leaves ARE legitimately convergent (MLS
commit-ordered) and stay. Root-cause fix: exclude application messages from the
durable log (match native), remove the receiver-clock window (straddling honest
clocks → opposite accept/reject → MLS-epoch partition on add-Commits = targeted
eviction), keep the authenticated AAD timestamp only for commit-ordered
membership leaves. A convergent per-committer floor is optional hardening only.
