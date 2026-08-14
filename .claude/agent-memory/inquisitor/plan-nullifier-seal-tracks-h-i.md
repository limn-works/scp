---
name: plan-nullifier-seal-tracks-h-i
description: Audit of ~/.claude/plans/nullifier-seal-and-crate-split-plan.md Tracks H (provenance-bearing projection) and I (identity resolution), decisions 1-22 — which survived scrutiny and which are invented/already-built.
metadata:
  type: project
---

Audit @ `origin/main` `16b9ed8d0`, 2026-08-11. Tracks H+I were produced in one long orchestrator↔maintainer
session and are the least-grounded material in that plan. Verdict: **the technical findings are solid; the
provenance narratives are not, and five decisions propose things that already exist.**

## Do not re-litigate — CONFIRMED
- **Broadcast forgery is real.** `build_broadcast_signing_payload` (`broadcast.rs:441-460`) binds 8 fields,
  none of them content; `compute_provenance_hash` covers only `DataProvenance` (no content hash in the
  struct). Key holder keeps every signed field + nonce identical, re-encrypts under same key/nonce/AAD,
  valid tag. The struct doc at `:159-160` claims "the nonce ... prevent[s] content substitution by
  broadcast key holders" — **false**. Root decision is ADR-038 (Decided, `phase-6.md:3051`), which
  correctly banned a *plaintext* hash (confirmation oracle) and was over-generalized in code into "no
  content binding at all." §9.9.1's "A relay CANNOT modify messages" is likewise false for broadcast.
- `open_broadcast` 0 prod callers; `open_broadcast_trusted` exactly 4 (`projection.rs:1474/1934/2310`,
  `scp-node/src/lib.rs:1258`); `open_broadcast_content` 0. `FeedMessage` (`projection.rs:1388`) carries no
  signature and no provenance.
- **Provenance is dead on every production broadcast**: `compute_provenance_hash(None)` hardcoded at
  `scp-runtime/.../broadcast_helpers.rs:399` and `messaging_helpers.rs:410`. Track H never notes this.
- **No SDK-side broadcast receive path exists** (scp-client / scp-client-wasm / bindings: zero
  `BroadcastEnvelope`). Only node projection consumes envelopes.
- Track I facts: 1281 B minimal doc (mode; compact 1103; no compression); BEP44 1000 B; zero client-side
  size check; `did:dht:z`+52=53 (did:dht wants no `z`); no `pkarr` dep (only `mainline` 6);
  `from_json` bare `serde_json::from_str`; no `MAX_DID_DOCUMENT_SIZE`; `resolver.rs:577`
  `Ordering::Equal => None` (no byte-identity check, no warn — §3.10.4 MUST violated).
- Track H's **cut is correct**: no browser/stackless-consumer requirement was ever stated by anyone.
  #2139 names SCP agents as the only consumer.

## Reversal-grade findings
- **The "guarantee it" verbatim ruling is in NO GitHub artifact.** #2294 (same workstream) says so
  explicitly. The plan's "recorded in exactly one place: a comment on #2135" is false twice over — #2135's
  comment is an *agent's third-person restatement*, and the substance is ALSO in **open Discussion #2139**
  ("**Decision: guarantee it.**", under "The maintainer's stance / decisions"). The ruling was never lost;
  #2284's "no spec, ADR, story, or issue" excludes Discussions. Real defect: a Discussion is not an
  artifact, and #2139 self-labels "no conclusions are asserted here" while asserting one.
- **D8 `CanonicalField::Absent` ALREADY EXISTS** (`canonical.rs:80`), used in 5 production files.
- **D7 replay detector ALREADY EXISTS** — `BroadcastReplayDetector` (`broadcast.rs:766`), exact semantics,
  bounded 10k authors, **zero production callers**.
- **D9 cuts spec text that is not on main** — "makes the transport story sufficient" was written by this
  same workstream in worktree commit `cd73594f7`, 2026-08-10 19:48, ~1 day before.
- **D4 "in place" is blocked**: §9.5.1 — adding a field requires a version increment; §13.2.2 has already
  spent `SCP-BROADCAST-ENVELOPE-V2:` on a *different* field list. Four mutually inconsistent preimage
  definitions on main (§5.14.5, §9.5.2, §13.2.2, sketch.md:488) + a phantom `content_hash` in
  technical-overview.md; only §5.14.5 matches code; no §25 KAT arbitrates (that is #2296).
- **D13 "no new wire field" is false** — `key_epoch: u64` is non-optional (`broadcast.rs:180`); optionality
  changes serde, the preimage (`:451`), the AEAD AAD (§5.14.5), and `SigningPayloadFields`.
- **D15 vs D20 is UNRESOLVED IN THE PLAN.** No key-history record appears anywhere in the plan, the specs,
  or GitHub (searched). D21's pointer rule names only device-attestation + broadcast-context list.
  D15 (verify against `#retired-*` forever) contradicts **ADR-003 §4a** (`phase-1.md:359`) which bounds
  retained retired ACTIVE keys to 2 *for the exact reason D20 reimposes*. No `MAX_RETIRED_ACTIVE_KEYS`
  exists in code — the unbounded retention D15 leans on is an unimplemented-bound bug, not a decision.
- **D20's provenance collapses.** `11-prior-art.md` is a survey; item 5 is the only entry in its list with
  no `§` cross-ref; ADR-003:281 *already* says JSON-LD, so §18.2.2A "overrode" nothing. D20 is also
  contradicted by the plan's own "Open — one encoding or two."
- **Track I's "nobody filed the cause" is FALSE.** ADR-039 (`phase-1.md:1275`, Decided): "DID documents are
  already ~1,140 bytes with 2 VMs (BEP44 v1 payload limit is 1,000 bytes, requiring bencode packing)."
  Cause + fix were recorded in phase 1 and never implemented. The missing thing is a mechanical size gate
  (#1656, falsely closed), not a membership rule.
- **D16 "`#0` is offline" — NOT FOUND**; §3.2.1 describes an online "device holding #0." Offline custody
  attaches to the pre-rotation key.
- **D15's "DID Core §9.7 is normative" — FALSE.** W3C DID Core §9 is marked non-normative and §9.7 says
  *removing* the VM is the primary rotation mechanism — the opposite of retaining `#retired-*`.
- **D19 scope understated**: `did:dht:z` is normative in ADR-003 (format decl + 3 migration invariants),
  in §9.7.1's `did:dht:z*` enforcement prefix, in 24 doc files (34 hits in §25 test-vectors) and 337 code
  files. ADR-046's regex is *not implemented anywhere* (1 hit repo-wide, ADR prose).
- **D1 misses its upstream**: the "shares the node's custody" phrase is also in **ADR-053**
  (`phase-2.md:1918`), which §10.17 enacts; ADR-053:1926 says the node "holds custody and resolves DIDs."
  Amending §10.17 alone is an artifact-flow inversion. D1's "node holds nothing" also contradicts the
  plan's own accepted cost at line 315.
- **D12's §18.11.2.1 "author consent" — the word appears nowhere in §18.11**; the section's own examples
  are governance *overriding* the author.

## Number corrections
~90 `publish_document` tests → **~60 tests / 69 call sites**. "gzipped DNS packet" → did:dht uses **RFC1035
§4.1.4 name compression + bencode**, not gzip. 1281 B is the *mode* for a doc with only
`PreRotationCommitment`; §18.2.2A:151 requires ≥1 `SCPRelay` entry, so the spec-minimal doc is ~1463 B.

## Unbounded-growth inventory (stronger than the plan's size argument)
`SCPBroadcastContext` is the only unbounded-cardinality service collection in `DidDocument` (siblings
capped: `MAX_IDENTITY_LINK_ATTESTATIONS=64`, `MAX_RETIRED_AGENT_KEYS=2`). `ScpDeviceAttestation`
(`document.rs:273`) stores a base64 raw token with no cap and **appears in no spec** — violating
§18.2.2A:153 "One of the types in §18.2.2."
