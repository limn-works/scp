---
name: adr062-slice11-scpr-frame
description: ADR-062 Slice 11 SCPR relay-frame spec/story/ADR — re-review @ ea4f90bb8 (v2 branch) ALIGNED; prior artifact-flow finding fixed upstream
metadata:
  type: project
---

# ADR-062 Slice 11 (SCPR relay public-record frame) — re-review @ `ea4f90bb8` (2026-08-01) — ALIGNED, 0 findings

Branch `docs/adr062-011-scpr-frame-v2`; diff `origin/main...` (commit `ea4f90bb8`, 1 past prior-reviewed `522cdae73`) = 4 files: ADR-062 (line 157 fix), `.docs/prds/adr062-capability-injection.json` (SCP-CAPINJECT-011), `.docs/specs/03-identity.md`, `.docs/specs/09-security-model.md` (§9.10.12).

**PRIOR FINDING (from 522cdae73 review) — NOW FIXED UPSTREAM:** ADR-062 line 157 (Rollout Slice-11 bullet) said "`NoOpRelayQuerier` → test-harness-only" — contradicted ratified correction #7 + §Decision 5. `ea4f90bb8` rewrites it to "demote only the test double `InMemoryRelayQuerier`… `NoOpRelayQuerier` stays a shipped production arm (the honest not-a-DID-source case, §10.4)." Fix originated in the upstream ADR (correct artifact-flow direction). Verified NO other ADR line contradicts: 41 (§Decision 5 table: fix col = "real MultiRelayQuerier", never says NoOp removed), 93 (remediation = implement real querier), 125 (NoOp "ships honestly as DHT-only interim"), 168 (relay arm flips NoOp→real MultiRelayQuerier; NoOp not deleted). None claim NoOp becomes test-harness-only. Consistent.

**Model A (NEW in ea4f90bb8) — verified NOT unratified scope drift.** Because ratified constraints already fix SCPR as a RAW blob (NOT OuterEnvelope, NOT MLS-encrypted, self-cert by BEP44 sig), and the existing `TransportAdapter::send/query` is `OuterEnvelope`-typed (traits.rs) + `native/adapter.rs` deserializes every blob as OuterEnvelope, a raw SCPR blob cannot ride that path. Model A's `publish_raw`/`query_raw` (`Vec<u8>`) SDK-side pair is the mechanism §Decision 5's "implement the real MultiRelayQuerier per §3.10.12" LOGICALLY REQUIRES — not scope creep. Spec is careful: "the RELAY is unchanged; the SDK transport adapter gains a public-record raw-blob path" (relays already store opaque blobs via `ClientMessage::Publish`/`RelayMessage::Blob`). Refines original "no protocol changes" → "no RELAY protocol changes; one SDK-side addition" (more honest, not broader protocol). "Alternative rejected" section correctly rejects storing bare bencode BEP44 mutable item (k is DID-derivable; §9.5.1 house discipline; multi-kind family). Wrapping public DID in encrypted OuterEnvelope would be nonsensical (no MLS group for arbitrary-DID resolution) — Model A is the only sound choice.

**BEP44 order fix:** old §3.10.5 said "value concatenated with sequence number" (value-then-seq, WRONG); new says seq-precedes-value `3:seqi<seq>e1:v<value>` per BEP44 canonical `bencode(salt?, seq, value)` — matches authoritative BitTorrent BEP44. Correct downstream fix from authoritative source.

**Determinism rules (new §9.10.12, 5 normative rules):** version-before-body, kind-before-body+reject-unrecognized, value_len bound-check with widened arith (no `82+value_len` overflow), exact-length equality (reject truncation AND trailing bytes), decode-and-verify at ONE site. Sound, bounded (positive grammar), reinforces ratified constraint #3.

**Machine-verifiability / provenance:** validate-prd exits 0 on branch worktree (16 files, 437 stories). blockedBy [] (forward-only). Story sources all resolve verbatim: §Decision-5 heading, §3.10.12, §9.10.12, §17.17.2, §10.4. All prose §refs resolve (§9.5.1/.6.1/.10.2/.16.1/.18.8/.18.11, §10.4/.5, §18.2.2A/.5.1, §3.10.2/.4/.5/.6/.7/.8/.12). SCPR constants in §9.18.8 next to SCPM magic (pre-accepted placement). No fabricated story refs (all SCP-CAPINJECT-NNN real), no phantom #NNNN, no CRYPTO-22.

GOTCHA: this agent's worktree checkout LACKS the PRD file entirely (branched off older base) — running `validate-prd.py` in-place validates the WRONG tree (370 stories, story absent). MUST `git worktree add --detach <scratch> origin/<branch>` and validate there (437 stories, story present).
