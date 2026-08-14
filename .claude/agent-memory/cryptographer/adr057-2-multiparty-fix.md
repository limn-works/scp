---
name: adr057-2-multiparty-fix
description: ADR-057 Slice 2 scp-client multi-party convergence FIX (566dbe288->d8b4e4c82) — crypto-sound, no regression, APPROVE
metadata:
  type: project
---

# ADR-057 Slice 2 multi-party add-Commit convergence fix — REVIEWED d8b4e4c82

Delta `566dbe288...d8b4e4c82` (prior single-party pass APPROVED 566dbe288). RE-REVIEW VERDICT: crypto-SOUND, NO REGRESSION, APPROVE. 115/115 scp-mls + scp-client (incl 2 new multi_party_convergence integration + 3 new encrypt seam tests + 1 crypto_state classify test); wasm32 check clean both crates; clippy zero warnings.

**Why:** Pre-fix, an existing member's `Inbound::Control` arm silently DROPPED add-Commits → its event log + membership set permanently diverged from committer/joiner in any 3+ party context.

**The fix (5 parts, all sound):**
1. NEW seam `scp-mls/src/encrypt.rs decrypt_with_membership_changes` + `InboundChange` enum. Replaces `decrypt_with_sender_did` on the client decrypt path. For a StagedCommit it recovers added DIDs from `staged_commit.add_proposals()[].add_proposal().key_package().leaf_node().credential()` and removed DIDs from `staged_commit.remove_proposals()[].remove_proposal().removed()` leaf index mapped to `g.members()` **BEFORE** `merge_staged_commit`. ORDER VERIFIED: process_message → recover added (validated KPs) → recover removed (pre-merge tree lookup) → merge_staged_commit → return. Removed-DID lookup is correctly pre-merge (removed leaf still present until merge).
2. ADDED-DID AUTHENTICITY: openmls 0.8.1 `process_message` fully validates a Commit incl all referenced Add-proposal KeyPackages (KP sig + embedded LeafNode sig + lifetime + caps) BEFORE producing the StagedCommit. A Commit carrying a forged/unsigned Add → process_message returns Err → mapped to DecryptionFailed before any DID extracted. So recovered added DIDs are cryptographically authenticated, not advisory. (Doc comment in seam is correct.)
3. REMOVED-DID NON-ATTRIBUTION: removed leaf index → credential read from the existing member's OWN current (pre-merge) MLS tree, which is the cryptographically-shared group state. A malicious committer cannot make a member attribute a removal to the wrong DID — the index→credential map is the member's own validated tree, not committer-supplied.
4. CONVERGENT LEAF byte-identity: committer `add_member` (client.rs:278) self-appends MemberJoined{actor=self.signer.did(), payload=empty, ts=clock.now_secs()→transported as AddMemberOutput.committer_timestamp_secs}. Existing member `receive_message` Commit arm appends MemberJoined{actor=committer_did recovered from VALIDATED MLS sender leaf credential, payload=empty, ts=transported committer_timestamp_secs}. Committer DID derivation matches: create/join embed the SAME ScpCredential.did the signer is built from, so MLS-sender-credential DID == committer self-stamped actor_did. seq+prev_hash recomputed locally from current log (convergence invariant). Joiner replays committer's exact leaf verbatim. Three-way byte-identical. add_member uses `core::slice::from_ref` = exactly ONE Add proposal = exactly one leaf; existing-member loop appends one leaf per added_did → leaf counts cannot diverge.
5. REMOVE-GUARD fail-closed: `if !removed_dids.is_empty()` → `ClientError::UnsupportedMembershipChange` raised BEFORE any add-leaf append. A mixed add+remove Commit writes ZERO leaves (no partial/divergent state). MLS group already merged inside decrypt_message; context deliberately left failed so caller surfaces the gap rather than proceeding on a diverged log. Guarding (not implementing) removal for Slice 2 = safe: a guarded member just can't process that Commit, fails closed, no security hole.

**Out-of-order delivery:** NOT a security issue. Convergence-by-replay needs in-order processing; out-of-order fails CLOSED via append_unsigned_event prev_hash/sequence chain validation (context.rs:157 replay_event / :197 append_log_event compute seq=event_count + prev_hash=last leaf). An out-of-order or forged leaf can't chain → EventLogError reject. Liveness/convergence-stall, not exploitable desync.

**No new key exposure:** delta scan for println/log/secret/to_bytes etc → sole hit is `plaintext: app_msg.into_bytes()` = the intended return payload, not a log. No logging primitives added.

**group.rs key_package_in_did doc HARDENED (prior LOW resolved):** body now runs full `KeyPackageIn::validate` (leaf sig + KP sig + version + Lifetime) and doc now states cryptographic authentication + "no weaker advisory window" — doc matches code. (Prior pass flagged doc UNDERSTATED; now accurate.)
