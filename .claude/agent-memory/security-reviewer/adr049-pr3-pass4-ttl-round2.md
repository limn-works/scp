# ADR-049 PR-3 pass-4 TTL delta round-2 (feat/adr049-pr3-live-timers, HEAD ae3bcc7b1 over 21a93a88e)

Round-2 of the 4 pass-4 commits (ae965aa53 H1/H2, 6de30e6b9 M1/M2, 447456d9c M3, ae3bcc7b1 L1/is_terminal).
NOTE: MAIN worktree is on a DIVERGED branch (1620de983) — must use `git show feat/adr049-pr3-live-timers:<path>`, NOT Read/grep of working tree.

## NEW findings

### HIGH — M3 clamp bypass via non-genesis / empty event log (export_import.rs derive_extension_bound + lifecycle_helpers.rs ~2502)
- `history_complete = entries.first().event_type == ContextCreated`. If the exported log does NOT begin with a ContextCreated leaf (empty log, or a re-anchored tail whose seq-0 first entry is any non-genesis event), history_complete=false → import clamp SKIPPED → over-long ttl_deadline_secs honoured VERBATIM. This is exactly the window-extension equivocation M3 set out to close.
- Reachable: `recompute_event_log_root` returns Ok([0;32]) for empty, and accepts any valid seq/prev_hash-chained log regardless of entry[0].event_type. Nothing on import (line 2093 only skips importing empty log) requires a genesis ContextCreated leaf. handle.params comes wholesale from the creator-signed export.
- Covert attack: creator keeps params.ttl=1h (honest/visible), sets ttl_deadline_secs=1yr, exports a log without genesis. Clamp skipped → importer arms 1yr. Matters most for Ephemeral/Summary imports (the scopes the clamp runs for) because TTL expiry DESTROYS keys there → keys retained past convergent window = confidentiality window extension.
- SIBLING bypass: even WITH genesis (history_complete=true), derive_extension_bound trusts ANY TtlExtended leaf's new_deadline_unix with NO authorization/signature check. Creator forges a TtlExtended leaf → derived_ub inflates to the forged value → clamp allows it.
- Decode is panic/DoS-safe (error-mapped rmp_serde, filter_map .ok(), .max()→None, saturating_add). Minor: log decoded twice (validate + derive_extension_bound).
- FIX DIRECTION: for TTL bound, clamp pruned/non-genesis logs DOWN to creation+params.ttl (fail-safe) rather than verbatim; and/or require genesis-complete log for TTL-bearing imports; and/or verify TtlExtended leaves carry valid governance approval.

### MEDIUM — H1 gate `memory_scope != Full` is over-broad (lifecycle_helpers.rs 2469 import + 3072 restore)
- Gate skips TTL re-arm for ALL Full contexts. But broadcast contexts MUST be Full (spec §5 L487; memory_scope.rs:487) AND may carry a ttl — `templates.rs` has validate_public/gated/paid_broadcast_with_ttl_passes tests: Full+ttl is a first-class, tested config.
- CREATE path (finalize_create, ~1671) arms purely on ttl.is_some() with NO Full check → broadcast/created Full+ttl expire at creation. Restore/import SKIP them (Full) → they NEVER re-expire after restart/import → outlive their window. Asymmetry INTRODUCED by the H1 fix (pre-fix all paths armed on ttl.is_some()).
- Discriminator the fix should have used: promotion clears deadline (deadline_unix_secs=None); broadcast/created Full+ttl have a RECORDED deadline (Some). Gate on "Full AND persisted deadline None" (promotion signature), not on Full alone.
- Blast radius: Full retains keys on expiry (no key destruction), so this is lifecycle-enforcement loss (Active-state past intended TTL), not a key/confidentiality bypass. Test coverage gap: only the promoted (deadline=None) case is tested (restore_promoted_context_does_not_re_expire).

## OK / RESOLVED
- L1 (leaf-gated-on-persist, ttl_close_helpers.rs handle_ttl_expiry): Phase-2 ContextExpired append gated on persist_result.is_ok(). No "leaf present but state not durable" path. Documented residual is the SAFE direction (state durable/terminal, leaf possibly absent = provenance gap; restore skips non-Active, B8 refuses re-create → no resurrection).
- M2 (relay-before-append + bounded retry, ttl.rs finalize_close + finish_ttl_expiry_io + actor/mod.rs): completeness-critical leaf appended FIRST; best-effort relay delete bounded by RELAY_DELETE_BUDGET(5s) < HANDLER_TIMEOUT(30s). Keys destroyed synchronously in Phase 1 BEFORE relay op → encryption-as-access-control upheld. Backoff exponential base 5s cap 5min, saturating shift(≤32)+saturating_mul+.min → no overflow/spin. Operator error! rate-limited at threshold 12 & multiples; logs context_id(public)+retries+backoff+result, no key/secret leak. StallingTransport regression test present.
- Round-1 obs (orphaned keys on crash-during-retry) = pass-4 L4 accepted residual: AGREE not a bypass (ciphertext unreadable, context terminal, restore skips non-Active, B8 refuses re-create). Storage-hygiene only.
- is_terminal() (protocol/context/mod.rs): exhaustive match Expired|Closed|Tombstoned=true, others incl Poisoned=false. Byte-equivalent to prior matches!. Refactor neutral.
- H2 (reset_ttl_timer no-op on deadline=None): correct, avoids arming ~1970. FFI reset ops fire-and-forget, doc-only changes across PyO3/NAPI/UniFFI/Swift — no behavioral change.
- supervisor.rs prod change: B8 respawn precheck now snapshot.state.is_terminal() — equivalent.
