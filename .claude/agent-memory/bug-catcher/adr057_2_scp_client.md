---
name: adr057-2-scp-client
description: ADR-057 Slice 2 scp-client participant driver review — builds clean, but multi-party convergence design gap + cosmetic test claims
metadata:
  type: project
---

# ADR-057 Slice 2 — scp-client participant driver (branch feat/adr057-2-scp-client @566dbe288)

New crate `crates/scp-client/`: single-threaded synchronous SCP participant driver over scp-mls.
Builds/clippy/wasm32 all CLEAN (native + wasm32-unknown-unknown, -D warnings). Tests: scp-client 5/5,
scp-mls 109/109 (incl new key_package_in_did_recovers_embedded_did). No tokio/runtime/identity dep
(mechanical wasm fence holds). No SystemTime/Instant/narrowing-cast in driver — clock injected (u64 now_secs).
HashMap iteration never feeds a leaf/hash. Sender-key §9.16 double-encryption pipeline correct; epoch
ceiling enforced before replay tracker; tracker advanced only after successful decrypt (good).

**Findings (no crashes/unwraps — all design/coverage):**

1. **HIGH (design, masked by 2-party-only test): existing members never record a received add-Commit's
   MemberJoined leaf or membership.** `ScpClient::receive_message` Inbound::Control arm (client.rs:429)
   returns Ok(false) and does NOTHING to event log or `members`. Design doc (client.rs:391) explicitly says
   only the joiner records the leaf (via replayed log). For 3+ parties this diverges: Alice creates → adds Bob
   (converge) → adds Carol (Alice/Carol log = 3 leaves incl Joined(Carol); Bob processes Commit via
   receive_message → no leaf → Bob stuck at 2 leaves). Bob's Merkle root permanently diverges from Alice/Carol
   AND Bob's `members` never gains Carol. AddMemberOutput.event_log only ever goes to the new joiner, never to
   existing members. The §9.9.3 convergence the crate advertises holds ONLY for 2 parties.

2. **MEDIUM: "process-commit" capability has ZERO test coverage.** Crate-root + client.rs docs list
   "process-commit" as a proven capability. The 2-party test is degenerate — Alice's Commit has no recipient
   (only existing member is the adder), so Inbound::Control is never returned through receive_message in any
   test. The MLS-merge-on-receive path is untested. (Same root cause as #1.)

3. **MEDIUM: "different clocks per party" claim is COSMETIC.** two_party_exchange.rs gives Bob a different
   clock (1_650_000_000 vs Alice 1_700_000_000) and claims this proves convergence is clock-independent. But
   Bob's clock is read ZERO times in the test: Bob's path is gen-keypackage / join (replays verbatim) /
   receive (uses passed committer ts) / drain / close — never now_secs(). Test would pass identically with
   equal clocks. A real proof needs Bob to SEND (so Bob stamps its own clock and Alice must converge via Bob's
   committer ts). Only Alice sends.

4. **LOW (provenance): ADR-057 has NO .docs artifact.** Cited everywhere in code (scp-client, scp-mls,
   runtime, node) but absent from .docs/adrs/ (gap: 052/053/055/057 all missing). ADR-055 similarly cited,
   absent. Per CLAUDE.md "artifacts are the system of record / broken provenance is a bug." May be authored in
   a sibling slice PR — flag, don't block.

5. **LOW (dead): ClientError::NotApplicationMessage** (error.rs:43) defined, never constructed. Public variant
   so clippy won't flag.

**Seam additions CLEAN:** scp-mls key_package_in_did (validates protocol version w/ throwaway provider, reads
unverified BasicCredential→ScpCredential.did; doc correctly warns "advisory until add succeeds") + pub re-export
SignatureKeyPair from openmls_basic_credential. Minimal, no existing scp-mls test broken.

**Genuine proof verdict:** the AEAD assertion (Bob recovers exact 50-byte plaintext) is real, not vacuous — a
broken decrypt yields error/garbage, not the exact string. 2-party convergence (equal leaf hashes + equal root)
is genuinely proven. But the test does NOT prove what its prose claims for multi-party or clock-independence.

---

## Round 2 (@d8b4e4c82) — FIX RE-REVIEW: HIGH + both MEDIUMs RESOLVED, no new defect. CLEAN.
- **HIGH fixed.** New `scp-mls::encrypt::decrypt_with_membership_changes` (+ `InboundChange` enum) recovers
  added/removed DIDs from the staged commit BEFORE merge (Add proposals' KeyPackage leaf creds; Remove proposals'
  pre-merge tree creds). `receive_message`'s old `Inbound::Control` no-op replaced by `Inbound::Commit` arm that
  appends `MemberJoined(actor=committer_did, payload=empty, ts=transported committer_timestamp_secs)` per added
  DID + `add_member_record`. Matches committer's own `add_member` leaf (client.rs:277) byte-for-byte; joiner
  replays full event_log verbatim. `AddMemberOutput.committer_timestamp_secs` now transports T (like SendOutput
  for messages). seq+prev_hash recomputed from current log via `append_log_event` (context.rs:197) — convergence
  invariant holds. Order differs (committer record-then-append vs existing append-then-record) but
  add_member_record never touches the event log → root unaffected.
- **App-message receive** stamps transported ts (client.rs:439), not receiver clock. send_message reads
  `self.clock.now_secs()` (client.rs:381) → Bob's distinct TestClock genuinely read now (cosmetic-clock MEDIUM
  resolved).
- **3-party test** non-vacuous: leaf_count==3 ×3, identical leaf HASHES + root + membership for Alice/Bob/Carol
  (Bob = existing member). Pre-fix fails (Control arm appended nothing; also wouldn't compile). reciprocal-send
  test: Bob SENDS stamping HIS clock (asserts ==1_650_000_000), Alice/Carol converge via transported ts, 3
  distinct clocks. (process-commit MEDIUM resolved.)
- **Remove-guard** `UnsupportedMembershipChange` checked BEFORE add loop → fails closed, no partial append, no
  panic. MLS already merged inside decrypt_message (doc'd deliberately-failed state). OK per Slice 2 scope.
- **No new bugs.** catch_unwind around process_message (wasm panic=unwind), proper error mapping, no unwrap on
  malformed. Multi-add loop defensive but driver only emits single-add commits (latent, no producer). credential_to_did
  = pure refactor, identical semantics. scp-mls `decrypt_with_sender_did` now has ZERO external callers (scp-runtime
  has its OWN encrypt.rs/DecryptedContent — `super::encrypt`, NOT scp_mls) → no runtime behavior change. key_package_in_did
  now runs full KeyPackageIn::validate (authenticated DID, no advisory window) — strengthening.
- LOW#5 resolved: NotApplicationMessage replaced by UnsupportedMembershipChange (constructed). LOW#4 (ADR-057 .docs
  artifact) out of this diff's scope.
- **Build/test:** build + clippy -D warnings + wasm32 check all clean; nextest 2268 passed / 2 skipped
  (scp-client+scp-mls+scp-runtime/testing); 6 new tests PASS.
