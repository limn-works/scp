# Broadcast Hosting-Handshake Saga §5.14.13 (PR#1897, feat/2c-pr5-broadcast-handshake) -- 2026-06-25

HEAD c356e1ffa. Files: broadcast/mod.rs (+474), broadcast/hosting_handshake.rs (new signed types),
actor/handlers/broadcast_saga.rs (new, 941 lines: prepare_a/prepare_b/commit_b/commit_a),
supervisor.rs (start_broadcast_hosting_handshake_saga + dispatch_bcast_*).

## Verdict: 1 MEDIUM anti-griefing gap; rest of the 7-item checklist SOUND.

### MEDIUM -- blocked-but-subscribed party can reserve saga slot before rejection
- supervisor.rs start_broadcast_hosting_handshake_saga (~5453-5503): pre-reserve gates check
  is_member(host) + is_member(broadcast). NO block-list check pre-reserve. Per-author block does NOT
  remove from subscriber roster (§5.14.8), so a blocked party is still a member => passes both gates,
  reserves the per-context-set saga slot, only rejected at Prepare-B block-list check (post-reserve,
  broadcast_saga.rs:488). Requirement was "blocked party rejected BEFORE any reservation." Impact:
  transient (Prepare-B failure -> abort -> RAII release), so contention/DoS amplification not permanent
  wedge. Block-list lives in actor state; supervisor would need a query to check pre-reserve.

### SOUND (verified):
1. Authorize-before-reserve: both is_member gates BEFORE try_reserve_context_set. Non-subscriber rejected
   pre-reserve (SCP-SAGA-13162/13163). (Block-list gap above is the one exception.)
2. Confused-deputy gated UCAN: Prepare-B re-validates messages:read UCAN re-bound to subscriber_did via
   full ADR-016 pipeline incl. REVOCATION (validate_gated_read_ucan, presenting_agent_did=subscriber_did).
   B is authoritative; Prepare-A host check is non-authoritative by design. Signature also re-verified at
   Prepare-B bound to subscriber_did (DID-resolved Active key, verify_strict).
3. Aggregate cap: check_aggregate_cap sums over OTHER live entries (excludes requesting pair correctly for
   renewal net-charge), both caps independent. Per-grant max_subscribers range [1,1M] but aggregate default
   100k dominates => single ceiling grant cannot fan out unbounded.
4. expires_at_ms: lower bound clamped.expires_at_ms<=now_ms rejected (covers 0 too); upper clamped to
   now_ms+max_grant_lifetime_ms. validate() rejects 0 at sign. Lifetime ceiling relative to grant instant.
5. Reservation release every terminal: RAII _reservation released on Committed/Aborted/panic-unwind.
   Abort clears saga_pending on both sides (handlers::saga::abort). Orphaned staged slot != accepted_host
   (no authorization). NeedsRepair keeps escrow intentionally (none for bcast). No orphan forwarding reg.
6. routing-stripped: NO forwarding impl in this diff -- only policy granted/persisted. ForwardingPolicy enum
   payloadless; inner signed envelope untouched by construction. Not exercised here.
7. REPLAY SOUND: bcast_request_nonce_dedup TTL = SAGA_NONCE_DEDUP_TTL_SECS = 2*skew = 600s, DELIBERATELY
   2x the ±300s freshness window. Probed the seen_at(wall) vs timestamp_ms(self-asserted) clock divergence:
   to escape dedup before freshness expiry needs first-process now1 < T-300, but freshness requires
   now1 >= T-300 => impossible. The 2x-skew TTL precisely closes it. Nonce recorded under same fail-closed
   persist as slot (KEEP direction for dedup, RESTORE for slot). Class-S persisted (crash survival).
   Re-grant would also supersede same (host,sub) accepted_hosts key (not additive).

### NOTES
- Prepare-A holds_read uses (member_capabilities has MessagesRead/Write) || membership.contains -- broad
  fallback, but host-axis only; B-side authoritative at Prepare-B. Not a gap.
- Context-id is collision-resistant digest; "same id different context" confused-deputy not attacker-
  constructible; saga_id (UUIDv4) anchors Commit idempotency. No generation-token gap like Phase 3 xctx.
- canonical_hash preimages length-prefixed + domain-separated (SCP-BCAST-HOST-REQ/GRANT-V1); OptVarBytes
  ucan absent=SHA256(0x00) sentinel != present-empty. Grant nonce ECHOES request (never independently
  drawn/dedup'd). Good.
