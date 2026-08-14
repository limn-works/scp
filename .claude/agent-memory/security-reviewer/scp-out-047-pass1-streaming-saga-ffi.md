---
name: scp-out-047-pass1-streaming-saga-ffi
description: SCP-OUT-047 pass-1 PyO3 cross-context streaming-saga FFI review (3f5a906ec) — 1 MEDIUM (recover missing invoker-ownership check), rest auth-sound
metadata:
  type: project
---

# SCP-OUT-047 pass 1 — PyO3 streaming-saga FFI (3f5a906ec, worktree scp-wt-047)

Reviewed 3 new exports in crates/scp-ffi/src/outlet_stream.rs + shared driver
common/src/streaming_saga.rs. Reused helpers in outlets.rs.

## SOUND (verified by tracing code, not comments)
- open ORDER correct: validate inputs → enforce_caller_principal_binding (hosted-axis via
  identity_registry_contains + is_member(caller_context_id)) BEFORE validate_outlet_ucan
  (which consumes nonce) and BEFORE saga drive. Caller never envelope-asserted.
- UCAN validated against TARGET context B (validate_outlet_ucan passes target_context_id);
  caveats resolved from parsed/validated UCAN (TokenNbCaveatResolver); caveats_binding computed
  from validated ucan_cid + fresh uuid v7 request_id; value_caveat_binding = Some iff has_caveats
  (never None-drops the §7.3.8 gate).
- Descriptor fields all runtime-side: operator_signer from TARGET operator custody, invoker_pk
  from caller custody, request_id fresh, identity.context_id/outlet_id are validated bridge params.
  Caller supplies asserted_nonce/timestamp/chain_depth = §6.2.4 freshness (validated by B), NOT
  descriptor fields.
- open error paths: receiver registered only AFTER saga drive Ok; drive-Err returns before insert
  (no receiver/partial-registration leak). No fallible step between handle and insert (runtime
  returns handle.receiver field directly — no receiver()-None strand risk unlike same-context open).
- registry per-instance (runtime.rs outlet_streaming_saga_registry), cleared on shutdown.
- error messages carry codes/slugs/DIDs (public) + bounded PlatformError; custody sign maps to
  bounded StreamSignerCustodyCategory (no key leak).

## FINDING #1 (MEDIUM, must-fix before pass 2/3)
outlet_streaming_saga_recover_truncated_close_impl (outlet_stream.rs ~1491) authenticates the
reconnect caller with ONLY identity_registry_contains(caller_did) = "any identity hosted by this
instance" — it does NOT check caller_did == entry.invoker_did. StreamingSagaEntry.invoker_did is
pinned but DEAD (grep: never read anywhere). So any co-resident hosted identity (not the opener)
can force-recover ANY saga in the registry by saga_id → recover_streaming_saga_truncated_close
(supervisor.rs:6822) does CommitBStreamSettle + settle_outlet_stream_via_actor (MOVES MONEY, bills
invoker/credits operator over durable prefix) + marks saga Committed. This is a state-changing
"steer" that CRITICAL #1 exists to gate — its same-context sibling `terminate` (a mere close, no
money) DOES enforce caller==invoker via authorized_control. Asymmetry is backwards: the
money-moving op has weaker auth than the benign one. Bounded by: single-tenant model, no
double-settle (witness→settlement None on replay), durable-prefix ceiling. Fix = compare caller_did
to entry.invoker_did (field already pinned for this). Untested (e2e only covers unhosted-caller +
unknown-saga on recover).

## OBSERVATION
poll_next takes NO caller_did param → no ownership check (a co-resident identity that learns a
saga_id can drain/steal/disrupt another principal's stream). Consistent with same-context
outlet_stream_poll_next precedent + single-consumer receiver, but note the asymmetry vs
grant/cancel/terminate. Document why poll differs if intended.
