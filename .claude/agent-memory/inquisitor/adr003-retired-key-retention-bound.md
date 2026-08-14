---
name: adr003-retired-key-retention-bound
description: ADR-003 §4a/§4a′ "2 most recent retired keys, pruned for DHT size" — UNSOUND. Never a human decision, back-filled to fix a false "mirrors" claim, arithmetically incapable, and the VMs it bounds are forbidden by spec §18.2.2A and non-verifying by §9.7.1.
metadata:
  type: project
---

Interrogated 2026-08-11 at `origin/main`. Verdict: **UNSOUND — REVERSE**. Do not re-litigate the
provenance; it is fully traced below. If someone proposes implementing the missing active-key
prune to "close the gap," that is the wrong direction — the gap is the correct behavior and the
ADR text is the defect.

## Provenance (fully traced, primary sources)
- The active-key bound was **NOT** in ADR-003. Added 2026-03-04 by PR **#274** (ADR-039,
  commit `b1455a07f`) — five months before the §3.10 relay/DHT bifurcation (`8824be49a`,
  2026-08-02).
- Causal chain: `claude[bot]` review 20:24:40Z flagged agent-key accumulation → agent bounded it
  at 2 and wrote it "mirrors" active rotation (**false** — active had no bound) → `claude[bot]`
  20:32:28Z flagged the false "mirrors" and offered *either* fix → the agent applied **both**
  (removed "mirrors" AND back-filled the bound into ADR-003 §4a). Pure symmetry propagation.
- **Zero human input.** No human comment on #274. All 15 reviews `COMMENTED`, none `APPROVED`.
  The number `2` has no recorded derivation anywhere.
- The bound lives only in an **acceptance criterion**. ADR-003's Decision/Rationale never mention
  retention, and ADR-003 has no Alternatives section for it.

## Why the premise fails (four independent reasons)
1. **Arithmetically incapable.** ADR-039 (phase-1.md:1275) itself: doc is "already ~1,140 bytes
   with 2 VMs (BEP44 v1 payload limit is 1,000 bytes)". Over budget with ZERO retired keys.
2. **No spec ever authorized retained keys.** §18.2.2A field table: `verificationMethod` … "**No
   other verification methods permitted**" beyond `#0`/`#active`/`#agent` (added 2026-03-07,
   3 days *after* the bound, never reconciled). §9.7.4 and §3.2.1 both describe **replacement**,
   not retirement. Specs govern ADRs — the effective bound is **0**, not 2.
3. **"For historical verification" has no consumer.** §9.7.1 check 1 (09-security-model.md:634):
   a verifier "MUST NOT accept an attestation signed by any `#retired-*` verification method."
   The only code touching `#retired-*` (`crates/scp-mls/src/keypackage_attestation.rs:724-800`)
   is a **rejection** path, which treats absent and retired **identically**. Rotation-is-revocation
   (§9.12) is the design. Every rotation path says re-sign / re-issue.
4. **Maintainer's bifurcation hypothesis is REFUTED.** §3.10.5: "Both layers receive **identical**
   document bytes"; §9.10.12 repeats byte-identity. Code confirms: `publish_document`
   (`crates/scp-identity/src/dht.rs:830-846`) does `document.to_json()` → those exact bytes are
   the BEP44 `value`. No DNS-packet encoding, no compression, no reduced DHT subset, **no size
   check**. No `pkarr`/`simple-dns` dependency exists — ADR-003's Implementation section
   (pkarr v5, ~300 lines DNS encoding) is unimplemented.

## Live contradictions in the artifact set (the real root cause: no settled size model)
- §3.10.2: "DID documents range from 2-30KB … 256KB. Well within bounds." (impossible as BEP44)
- §3.10.5 + §9.10.12: byte-identical value to both layers ⇒ effective cap 1,000 bytes
- §11 prior-art:175 (2026-03-04, `dd762f84d`): "DNS packet encoding on DHT … **the relay layer
  carries the full document**" — explicit per-layer divergence, contradicting §3.10.5
- §9.10.12 permits `len(value)` ≤ 262039 — a frame valid on relays but unpublishable to the DHT,
  silently breaching the §3.10.6 anti-segmentation MUST. No code enforces 1,000.

Plus a **fourth** model: `.docs/specs/26-conformance-suite.md:60` (CONF-003) — "Old `#active` key
is **absent**. Messages signed with old key still verify against the old key (**retained by
recipients**)." A recipient-side key archive that does not exist (§9.11 TOFU only alerts on change).

Open issue **#2297** (alecmarcus, 2026-08-12) already names the transport/size root cause and the
foreclosed hybrid — but says **nothing** about retired keys. Its fix item 1 ("membership criteria
for the DID document — bootstrap-required inline vs fetched-after pointer, bounded by what") is
where the retired-key question belongs.

## Worked precedent the project already has
`.docs/specs/07-trust-validation-and-capabilities.md:684` — protocol authority key rotation uses a
**90-day grace**, old key valid for artifacts published before rotation. Two different answers to
the same problem in one system.

## Measured sizes (pretty JSON, what actually ships — recomputed, no test pins any of these)
`#0`+`#active`+PreRotationCommitment = **1281 B**; +`#agent` = **1732 B**; +1 SCPRelay = 1918 B;
+2 `#retired-N` = 2528 B; +2+2 = 3150 B. BEP44 cap 1000 B. Pruning saves ~311 B/key against a
budget already exceeded by 281–732 B at creation. Oversize surfaces as `mainline` error 205 →
mapped to `PutQueryError::Timeout` → `DhtPublishFailed("… Timeout")`, retried forever at 30-min
backoff. ~90 `publish_document` tests run against size-unlimited `InMemoryDhtClient`.

## Code state
`crates/scp-did/src/document.rs`: `MAX_RETIRED_AGENT_KEYS = 2` (:282), `prune_retired_agent_keys`
(:1143) matches only `retired-agent-`; `retire_active_key` (:882) has **no** prune. The doc-comment
at :925-928 asserts "retired-key history remains auditable" — an accidental premise no artifact
establishes and §9.7.1 forbids relying on. `.docs/prds/main.json:735,758` (the implementing story)
carries no retention bound, which is why the code never grew one.
