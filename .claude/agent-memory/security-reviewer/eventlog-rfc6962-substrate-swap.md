# Event Log RFC-6962 Substrate Swap (branch @bf9266777, 2026-06-19)

Runtime event log moved off the bespoke SCP-EXPORT-ENTRY hash-CHAIN onto
`scp_event_log` RFC-6962 Merkle substrate (`tree::append_unsigned_event`,
`tree::root`, `tree::leaf_hash`). `state.merkle_tree` twin DELETED; proof seam
now goes straight to provider's canonical tree via `with_log`. CLEAN review,
0 findings above Observation.

## Verified-sound properties
- **Export integrity STRENGTHENED**: `verify_merkle_chain` replays every Event
  through `append_unsigned_event` (validates sequence==running-count AND
  prev_hash chain), returns `tree::root`. Prefix-truncation now REJECTED outright
  (non-zero seq on entry[0] fails); suffix-truncation yields different root → ct_eq
  vs signed `event_log_merkle_root` rejects. Truncation forgery CLOSED, not just
  detected (was only "detected, suffix-tolerant" on old hash-chain). Tests cover
  prefix/suffix/middle-remove/tamper-link + full validate_export pipeline.
- **Domain sep intact**: `leaf_hash` = SHA-256(0x00 ‖ rmp_serde(Event)); interior
  0x01. Factored out, shared by append/append_unsigned/export-verify. No 2nd-preimage.
- **Proof seam sound**: prove_inclusion/consistency build against provider's own
  tree (no replay, no twin). `sync_merkle_tree`+`push_leaf_raw` path GONE — kills
  the old risk that twin built from precomputed entry.hash could diverge.
- **Equivocation moved in-memory is CORRECT, not a weakening**: a receiver-minted
  EquivocationDetected leaf is NOT sender-authenticated → appending it would make
  two honest receivers compute divergent roots and false-positive §9.9.3. Alert
  still surfaced via receive_buffer + broadcast event_tx (forensic roots carried);
  §9.9.4 "never silently discard" preserved. Dedup = per-sender HashSet<(count,root)>,
  bounded MAX_SEQUENTIAL_COMMITS; keying on root (not count) catches distinct forged
  roots at same height. Non-durability across respawn = re-alert-once (alert, not
  suppress) — acceptable. Sole-dedup now (durable-length backstop gone) but sound.
- **MessageReceived removal safe**: grep confirms NO consequence/participation/authz
  reader filters on a durable MessageReceived leaf. Enforcement reads governance/
  membership leaves (still durable). event_log_entries_for_consequences = "Source 1".
- **Unsigned append OK**: signing is at higher layer (checkpoint cosig SCP-CHECKPOINT-V2,
  export Ed25519 sig). Matches WASM model (.docs/lessons/unsigned-event-mcp-bridge.md).
- **Cross-platform leaf parity**: native + WASM both use shared
  `scp_event_log::payload::consequence_event_payload` (sorted-key JSON, BTreeMap,
  no preserve_order) + shared leaf_hash. Convergence by construction.
- **Convergent leaf timestamps**: committer-assigned / TTL-deadline / creation-anchored,
  never per-member now(). Restore path `anchor_deadline_to_creation:false` = honest
  forward step (ADR-051), only residual non-convergence — same as existing MEDIUM.
- ADR-011 amendment (phase-2.md L913+) committed: exclusion taxonomy lists
  MessageReceived/EquivocationDetected/PseudonymAnnounced/PaymentReceived. Provenance intact.
- PseudonymAnnounced EventType REMOVED; tag 59 retired as a gap (tags stay byte-stable). Sound.

## Observation only (not a finding)
- `consequence_event_payload` uses `serde_json::to_vec(&value).unwrap_or_default()`
  → empty data on ser-failure. Inputs are &str/usize (cannot fail); deterministic
  so native+WASM fail identically (no divergence). Non-exploitable.
- payment_history now sliding-window over bounded ring (DEFAULT_BUFFER_CAPACITY,
  oldest-evicted), not authoritative ledger; lost on respawn. Documented; store-backed
  full ledger "not yet wired". Auditability reduction is by-design per ADR-011 amendment.
