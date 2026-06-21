# Event-log unification Phase 2 (substrate swap) review

Branch feat/eventlog-unification-phase2-substrate, HEAD 964f186.

## HIGH — buffered-message post-delivery regression (messaging_helpers.rs)
- `deliver_plaintext_or_announcement` changed `NotAnnouncement` return from
  `Some("MessageReceived")` to `None` (to suppress non-authenticated Merkle
  leaf appends, §9.9.3 — correct intent).
- BUT all 4 buffered/drained-message call sites (lines ~2220, 2301, 2412, 2524)
  gate `run_buffered_post_delivery` on `if let Some(event_name)`.
- Net effect: for BUFFERED/out-of-order application messages, velocity
  tracking, consequence evaluation, AND `checkpoint_events_since += 1` are now
  SKIPPED (pseudonym announcements still return Some, so they still run it).
- The in-order path (`deliver_message_and_drain_buffered` lines 2552-2592)
  correctly KEPT velocity+consequence+checkpoint running unconditionally after
  removing the append — proving the buffered path is an inconsistent oversight.
- `run_buffered_post_delivery` doc literally says "Bug fix: velocity, ...,
  consequence evaluation, and checkpoint increment apply to buffered messages
  too." Phase 2 reintroduces exactly that bug for buffered app messages.
- Fix: decouple post-delivery from the append. Run velocity/consequence/
  checkpoint for buffered app messages regardless of whether a durable event
  is minted. Either change the helper to return an enum (Append/NoAppend) and
  always call post-delivery, or make `run_buffered_post_delivery` take an
  `Option<EventType>` and skip only the append when None.

## Verified CORRECT (no bug)
- WarningCount trigger requires event_type==GovernanceAction, but runtime
  appends GovernanceActionExecuted/AccessRevoked — REMAPPED to GovernanceAction
  bucket in governance_logic::event_log_entries_for_consequences. Wired E2E.
- consequence.rs payload_target_did: rmp-array-first then JSON then legacy. JSON
  object bytes start with `{`=0x7B=positive fixint in rmp, so read_value returns
  Integer not Array → falls through. No collision.
- prune off-by-one: TruncatedEventLog drops [..prune_count], tail=[prune_count..]
  = total-prune_count. debug_assert validates. Correct.
- verify_merkle_chain: replays via append_unsigned_event (validates seq+prev_hash),
  returns tree::root. Strictly stronger. Empty-bytes→[0u8;32] only for Public
  (signed root also [0;32]); empty-Vec→SHA256("") matches provider. Consistent.
- merkle_tree field removal clean; proof seam via with_log. local_count from
  event_log_entries().len() (no MessageReceived leaves) → honest receivers agree.
- record_equivocation_if_fresh: (count,root) set bounded at MAX_SEQUENTIAL_COMMITS,
  re-emits-when-full intentional. Correct.

## LOW — misleading doc on prune_before_checkpoint (event_log.rs:400-403)
- Claims "leaf hashes (and proof paths) remain identical to the pre-prune tree"
  but truncate_log_keeping_tail RE-CHAINS prev_hash (first tail event→GENESIS),
  which CHANGES every tail leaf hash. Matches TruncatedEventLog semantics but
  the comment overclaims. Not functional.

## LOW — FFI event_type string now Debug-form of variant (common/event_log.rs)
- event_type_label = format!("{:?}", variant). e.g. TtlExtended (was TTLExtended
  in some JSON payloads). Surfaced+filter use same label so internally consistent;
  may change SDK-visible filter strings. Pre-release, no migration. Acceptable.
