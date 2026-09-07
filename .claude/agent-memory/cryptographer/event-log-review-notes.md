---
name: event-log-review-notes
description: Reviewed-and-approved event-log changes — signed context-export root binding (16a2cd42b) and PseudonymAnnounced taxonomy removal (f438acf0f), incl. the scp-event-log test-feature gotcha
metadata:
  type: project
---

# Signed context-export (`export_import.rs`, `16a2cd42b`) — APPROVE

Removed the unsigned envelope `ContextExport.merkle_root` field and the step-6
self-check. SOUND and strictly stronger.

- Signed preimage: `SHA-256("SCP-CONTEXT-EXPORT-V1:" ‖ scope.tag_byte() ‖ JCS(snapshot))`.
  `snapshot.event_log_merkle_root` is INSIDE `JCS(snapshot)`, therefore signed.
- Step 5 (recompute the RFC 6962 root over `event_log_data` via
  `recompute_event_log_root` — renamed from `verify_merkle_chain` — then `ct_eq`
  against the signed root) is the sole authoritative binding.
- Step 6 compared an attacker-writable envelope copy against the signed copy. Both are
  attacker-visible and it was trivially satisfiable, so it gated nothing.
- Coverage: prefix truncation is rejected in `append_unsigned_event` (seq / prev_hash);
  suffix / middle / reorder / substitution / forgery all fail on root mismatch.
- `exporter_did == creator_did` and `verify_strict` unchanged.
- Empty log signs `[0u8; 32]`, not an unsigned sentinel — no all-zeros bypass.
- The removed field was never in the hash → no second-preimage or domain-separation regression.

# `PseudonymAnnounced` removal (`f438acf0f`) — APPROVE

- Taxonomy 76 → 75; tag 59 RETIRED as a gap (no renumber), so every other
  `event_type_tag` is stable → §25 KAT 32/33 root `39e50b87` byte-unchanged (verified).
- `EventType` serializes by NAME-string via `rmp_serde` (no int repr), so the removal
  cannot shift other leaves.
- Convergence RESTORED: the receive path `deliver_plaintext_or_announcement` returns
  `None` for ALL 3 arms; the `Some`-append channel is DEAD in prod.
- The 3 non-convergent classes (`MessageReceived`, `EquivocationDetected`,
  `PseudonymAnnounced`) have NO `EventType` variant → type-level un-appendable.
- All prod append sites are sender-authored (`MessageSent`) or commit/governance-driven.

**GOTCHA**: a bare `cargo test -p scp-event-log` FAILS 116 tests — hex `did:key` is
gated behind the `scp-primitives` `testing` feature (`identity.rs:118`). Run with
`--features testing`.
