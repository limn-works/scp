# SCP-RELAYRES-002 relay READ-path fix -- CONFIRM RE-REVIEW (15c543de3) -- 2026-08-03

RESOLVED. Prior MEDIUM (temp-subscription leak on cancellation) CLOSED; CRITICAL fix (send_request
consumed the ref_id-bearing query_complete -> collect loop ran to deadline -> composer 5s cancel ->
zero candidates) introduces no new security issue. File: crates/scp-transport/src/native/client.rs.

- LEAK CLOSED: QueryScopeGuard::drop removes subscription (total, sync `subscriptions.remove(&rid)`)
  on EVERY exit incl. external cancellation (composer 5s timeout drops future). pending removed
  best-effort via try_write (Drop can't .await); residual harmless (ref_id monotonic, self-cleans on
  terminal dispatch). Test query_raw_cancellation_cleans_up_subscription proves it.
- NO LEAK WINDOW pre-guard: pending inserted under one write lock (block releases), then only SYNC ops
  (mpsc::channel, subscriptions.insert -- neither awaits) before guard is armed. No .await => no
  cancellation point => pending can't orphan. Collision path removes pending then returns (no guard).
- NO NEW DoS: pending entries only client-created (one per query), relay cannot grow them. cap=Some(16)
  for query_raw bounds candidate set (break at len>=cap incl. post-terminator drain). `query` path uses
  limit=None -> unbounded-until-terminator/30s deadline, but channel bounded mpsc(256) + PRE-EXISTING
  (old query had no cap either). ref_id monotonic across reconnect (next_ref_id never reset) => no reuse.
- NO CORRELATION-CONFUSION: terminator routes by ref_id (dispatch pending.remove), blobs by routing_id
  (subscription) -- disjoint namespaces, can't cross. Malicious relay CAN early-terminate the correct
  in-flight query (it knows the on-wire ref_id) = availability only, results re-verified downstream;
  inherent to untrusted-relay model, not new. Blob integrity SHA256(blob)==blob_id checked in dispatch;
  garbage blobs to temp sub dropped at caller BEP44 verify.
- VERIFY PATH UNCHANGED: transport-layer only. query_raw returns unverified blobs (caller BEP44-verifies);
  query filter_maps OuterEnvelope::from_bytes (downstream verify). No change to verification.
- biased select drains buffered blobs before terminator; post-terminator try_recv drain = belt+suspenders.
