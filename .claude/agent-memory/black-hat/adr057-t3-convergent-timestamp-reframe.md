---
name: adr057-t3-convergent-timestamp-reframe
description: ADR-057 T3 (#1975) re-attack — committer-timestamp AAD auth + MessageSent-exclusion reframe; the timestamp-window partition primitive is GONE, one residual clock verdict (KeyPackage Lifetime) remains on membership path
metadata:
  type: project
---

# ADR-057 T3 convergent-timestamp reframe (branch fix/1975-committer-timestamp-auth, HEAD 85f8ec09c)

Re-attack of the reframe that (a) authenticated the convergent committer timestamp
into MLS AAD and (b) excluded MessageSent from the convergent Merkle log.

**Verdict: the receiver-clock-window partition primitive I previously proved is GONE.**
`decrypt_with_membership_changes` adopts the AAD timestamp verbatim — no window, no floor.
Two honest members with different clocks receiving the same add-Commit merge identically
(proven by `multi_party_convergence.rs::three_party_add_commit_converges_across_all_members`,
distinct TestClock offsets, identical roots).

**Residual (real, pre-existing, MLS-inherent, LOW-MED):** `validate_key_package_lifetime(kp.life_time(), clock)`
in `crates/scp-mls/src/encrypt.rs` (~line 765) remains a per-receiver clock-dependent verdict on the
membership path. A KeyPackage near `not_after` + honest clock skew ⇒ one receiver merges (epoch N+1),
another rejects pre-merge (stays epoch N) = the exact partition-on-epoch-advance the ADR's own
reasoning condemns. NOT introduced by T3 (from Prereq-1) and openmls itself checks lifetime, so
MLS-inherent — cannot be removed without disabling MLS lifetime validation. Corroborated by the test's
own guardrail comment (multi_party_convergence.rs:42-48): offsets "kept small (seconds) so every minted
KeyPackage Lifetime stays valid." The slice's claim of "no per-receiver clock verdict" is not fully literal.

**Confirmed clean:**
- AAD-iff-adds gate keys off `added_dids` from `staged_commit.add_proposals()` (actual merged adds, not a spoofable flag). No proposal-type confusion; add+remove hits Remove-refusal first.
- No-add self-update: `committer_timestamp_secs = None`, merges (fixes prior BLACK-T3-03 self-update-fails-closed).
- Absurd-but-convergent timestamp (0 / u64::MAX): stored verbatim in leaf, no arithmetic in-scope; convergent. Same property native path already had. Downstream `scp-event-log/src/pruning.rs:540` does `event.timestamp < cutoff` but pruning is not wired into the browser driver.
- MessageSent → local event_buffer via `push_event` (NOT `append_log_event`); never on wire; drain-echo is local-only, no relay-observable state, no replay.
- Snapshot v2 BufferedEvent: 2-variant serde enum (fails closed on unknown); huge sequence_number is local display metadata, doesn't feed send-sequence tracker or convergent root; restore validates event_log_root vs recomputed.
- Forged AAD ⇒ AEAD tag break ⇒ DecryptionFailed pre-merge (tested). Missing AAD on add ⇒ ConvergentTimestampMissing pre-merge, epoch unchanged (tested).
- No enforcement/CI files touched. Cargo.toml adds scp-mls as plain `use` (not pub-use shim) for SCP-CRYPTO-4040 error code.

Minor: `forged_add_commit_aad_is_decryption_failed` flips the LAST byte (tag region) not an AAD-field
byte — proves frame auth but a surgical AAD-only flip would be a stronger proof of AAD binding specifically.
