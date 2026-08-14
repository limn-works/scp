---
name: adr063-provenance-bearing-projection
description: ADR-063 provenance-bearing projection branch (worktree-agent-a90070b75ca058cee @ d100be081) — interrogation verdict; V2/attestation design sound, but the GitHub escalation predates the ADR's own Decision-3 reversal and asks the maintainer to ratify the reversed design.
metadata:
  type: project
---

Interrogation of branch `worktree-agent-a90070b75ca058cee` @ `d100be081` (14 commits over `origin/main`
`16b9ed8d0`). Docs-only: ADR-063, `.docs/prds/provenance-bearing-projection.json` (16 stories/3 gates),
spec deltas 05/09/10/13/18/25, sketch, technical-overview, 2 audits, 1 lesson.

**Verdict: INTERROGATE FURTHER.** The crypto design (V2 ciphertext-binding signature; author
`ContentAttestation` inside the AEAD; delete `open_broadcast_trusted`) is SOUND and the premises hold.
The failures are at the seams.

## Load-bearing verified facts (re-verify before reuse)
- V1 preimage covers 8 fields, no plaintext/ciphertext/content hash, no `signing_key_id`
  (`crates/scp-protocol/src/crypto/sender_keys/broadcast.rs:441-460`). Finding 1 is REAL.
- `open_broadcast` (`broadcast.rs:620`): 3 callers, all `#[cfg(test)]`. `open_broadcast_trusted`
  (`:670`): 4 production callers (`scp-node/src/projection.rs:1474/:1934/:2310`,
  `scp-node/src/lib.rs:1258`). `open_broadcast_content` (`:695`): zero callers.
  `BroadcastReplayDetector` (`:766`): test-only. Finding 2 is REAL.
- `compute_provenance_hash(None)` literal at `scp-runtime/src/context/broadcast_helpers.rs:399` and
  `messaging_helpers.rs:410`; `build_broadcast_envelope` takes no provenance param ⇒ NO production
  broadcast can carry provenance today.
- Feed + per-message handlers never call `deserialize_broadcast_content` — they base64 raw plaintext
  (`projection.rs:1489-1498`, `:1949-1958`). Only `site_handler`/`commit_deploy` check the magic.

## BLOCKERS found
1. **Every GitHub artifact predates the ADR's own reversal and was never re-synced.** Reversal commit
   `63413544d` is 2026-08-11T00:10:09Z; #2294/#2295 and the #2135/#2284 comments are all 23:45–23:46Z.
   #2294 (P0, the maintainer ask) is titled "...published epoch decoding key..." and asks Alec to
   ratify publishing the epoch broadcast key — the design ADR-063 §Decision 3 now reverses as *wrong*.
   It also asks him to ratify items 1 and 3 that §Ratification now says need no signature, and OMITS
   the only item §Ratification says does (`ContentAttestation` as a required `BroadcastContent` member
   + 2nd domain separator). PRD `blockedByIssues:[2294]` therefore points at an unanswerable issue.
   This is the ADR's own thesis failing in the ADR's own turn, inverted.
2. **No origin→author-DID anchor exists.** §18.3.2 says `.well-known/scp` is NOT self-certifying;
   self-host uses a self-signed cert; `SiteConfig` has no author DID; DID docs have no domain proof
   (`also_known_as` is overwritten by migration). A browser learns the author DID only from the node.
   New §10.12.11 text ("provenance ... is what makes the transport story sufficient"; "Tampering
   with served bytes is always detectable") is false for that population. SCP-PROVSERVE-9000 says
   "the *named* DID" — written to what the mechanism delivers, not to the ruling.
3. **§18.11.13.4 contradicts §18.11.6 in the same commit** — "no per-author-block or epoch-purge
   interaction" vs the new §18.11.6 MUST propagating per-author blocks to the attestation endpoint
   (implemented by PBP-007), and vs its own next paragraph on purged epochs.
4. **ADR-062's G1 `allow_unencrypted_storage` nullifier: named, declared untracked, deliberately not
   filed.** 3× in `scripts/check-shipped-feature-graph.sh` (`:62/:77/:89`) whose header claims ZERO
   nullifiers. The agent filed 3 issues that night and declined the 4th as "outside subject matter."
5. **Feed/per-message `content` is undefined vs `body_sha256`** — §18.11.3 keeps
   `"<base64-encoded decrypted content>"`; §18.11.13.2 step 4 hashes `body`. Verification is
   unspecified on 2 of the 4 surfaces the guarantee is normative over. PBP-005 doesn't touch it.

## Other findings
- `ContentAttestation { author_did, signing_key_id, body_sha256, signature }` re-states three values
  already on the envelope/ContentMetadata, with NO must-equal rule and no statement of which copy
  feeds the preimage — the IPNS dual-field shape Decision 4 claims is "closed by construction"
  (Decision 4 only closes *cross-message* splicing). Minimal shape is the bare signature.
- `ProjectedContext.keys: HashMap<u64, BroadcastKey>` (`projection.rs:376`) — the accidental
  single-author primitive the ADR names as the root of the bad key URL. URL removed; primitive kept;
  no story fixes it. Lookups never compare `BroadcastKey.author_did` to `envelope.author_did`.
- Sibling misnomers untouched by Decision 2's principle: `push_leaf_raw`
  (`scp-event-log/src/lib.rs:700`, reached from shipped napi FFI), `set_unchecked`
  (`sender_keys/mod.rs:355`, installs peer-supplied keys, guarded only by a string-search assertion
  in `pipeline_wiring.rs:1219` — the anti-pattern ADR-063 condemns), `append_unsigned_event`
  (`scp-event-log/src/tree.rs:164`, pub, zero prod callers, its own doc says delete it).
- PBP-004 (P0, the live-forgery fix) `blockedBy: SHB-008` in another PRD. SHB-008 hoists only a *pure
  sync document→key extraction*; it builds no DID-resolution path, so PBP-004's stated rationale
  ("would build two DID-resolution paths") is inaccurate. Dedup preference, not a compiler constraint.
- PBP-009's ACs never require the verifier to recompute `provenance_hash` from the served
  `provenance` ⇒ a node-substituted provenance would pass the PRD's verifier.
- Story IDs `PBP-002B/009B/010A-D` violate `.docs/standards/prd.md` L11 (`PREFIX-NNN`). Validator
  has no ID regex, so CI is silent.

## Not findings (do not re-litigate)
- #2284's two-option fork was inherited but correctly *reframed* — "a content-binding signature is
  required either way" holds; Alt 2 beats Alt 1 on the six enumerated disclosure harms. Sound.
- Scope is PROPORTIONATE, not a scope explosion, and one self-reversal is convergence, not grinding.
- `provenance_hash` is not a misnomer — it does hash provenance.
