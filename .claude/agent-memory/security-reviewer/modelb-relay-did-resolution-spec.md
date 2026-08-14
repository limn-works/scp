---
name: modelb-relay-did-resolution-spec
description: Review of "Model B" DID relay-resolution SPEC change (validating SCP-native relays, single-slot; feat @ /private/tmp/scp-relay-modelb). Fixes Slice 11's HIGH findings but has 1 HIGH slot-exclusivity gap + 1 MEDIUM limit:1 inconsistency.
metadata:
  type: project
---

# Model B relay DID resolution — SPEC review (2026-08-02)

Diff: `git diff origin/main -- .docs/specs/03-identity.md .docs/specs/09-security-model.md
.docs/specs/10-infrastructure-and-self-hosting.md .docs/white-paper.md` in /private/tmp/scp-relay-modelb.
Model B = SCP-native relays VALIDATE DID-record blobs on PUBLISH (BEP44 verify + DID→routing_id
binding + single highest-seq slot); foreign transports store opaque; client always re-verifies
with DID-derived key. Frame redesign: SCPR multi-kind (magic+version+kind, value_len-prefixed,
82B fixed) -> minimal DidRecordV1 (version+public_key[32]+seq+sig[64]+trailing value, 105B fixed,
NO magic/kind — DID routing_id domain is the discriminant). Directly fixes my Slice-11 audit
(adr062-slice11-relay-did-resolution.md) whose bottom line was "relay layer CANNOT meet §3.10.8
without relay-side verify + single highest-seq slot."

## Finding 1 — HIGH: slot-exclusivity gap defeats "flood inert" for NON-FRAME junk
- Existing relay storage (ADR-004 / phase-1.md AC: PUBLISH "accept an opaque blob associated with
  routing_id"; QUERY returns BLOB stream default 100/max 1000; content-hash keyed) stores MULTIPLE
  blobs per routing_id. Slice-11 confirmed no per-routing-id cap.
- §3.10.2 single-slot rule + §3.10.8 "flood inert" argument ONLY enumerate outcomes for a junk
  *frame* (fails sig/binding -> rejected; seq ≤ stored -> rejected). They NEVER address a junk
  *non-frame* blob PUBLISHed at the DID routing_id. Under the multi-blob baseline that blob is
  stored opaquely, co-resides with the slot, and QUERY{limit:1} may return it INSTEAD of the slot
  (ordering unspecified) => flood NOT inert. Same eviction attack as Slice-11 Finding 1, just with
  "non-frame blob" not "extra frame."
- Relay can't invert SHA-256 to know a routing_id is DID-domain until a valid frame arrives => an
  attacker can PRE-SEED opaque junk before the victim's first publish; slot establishment must EVICT
  it, and post-establishment the relay must REJECT non-frame/invalid publishes at a slot-bearing
  routing_id. None specified.
- Close: spec must state DID-routing-id SLOT-EXCLUSIVITY (reject any PUBLISH that isn't a
  binding-valid seq-advancing frame at a slot-bearing routing_id; evict opaque blobs on slot
  establish; QUERY returns ONLY the slot). Also likely a companion ADR-004 update (NOT in this diff).
  Sound + implementable, just absent — but it's the CENTRAL claim so must close before impl.

## Finding 2 — MEDIUM: limit:1 contradicts "handles multiple returned blobs" for non-validating
- §3.10.2 QUERY block hardcodes limit:1. But §3.10.2, §3.10.4 step 5, §9.10.12 all say non-validating
  storage is handled by resolver "highest-seq-valid selection ... handles multiple returned blobs"
  / "if more than one valid record is returned." Under limit:1 a non-validating relay returns ONE
  relay-chosen (possibly junk) blob; within-relay multi-candidate sifting NEVER fires. Contradiction.
- Choice A (limit:1 everywhere): reword — non-validating relay returns one relay-chosen blob, pure
  best-effort, recovery via validating relays/DHT/multi-relay (matches §3.10.8 residual, which IS
  honest). Choice B: send bounded limit>1 for non-validating (re-inherits Model A window eviction,
  acceptable since best-effort). Current text straddles both = overclaim.

## Verified sound (report as positives)
- Client-always-verifies AIRTIGHT: §3.10.4 step4 + §9.10.12 "Framing outside signed authority" +
  properties bullet + tenet all say frame public_key MUST NOT be trusted; verify vs DID-derived key.
  Second-preimage resistance blocks frame-key substitution even relay-side.
- Equal-seq byte-identical idempotency SAFE: only genuine (public) bytes qualify; refresh aids
  availability; superseded seq rejected outright (no stale-pinning after rotation).
- Discriminant robust: version 0x01 ≠ MessagePack map marker (0x80-8f/de/df) + DID→routing_id binding
  => context OuterEnvelope never false-positives; no new wire type. No new leak (pubkey already public).
- Anti-rollback: §3.10.7 highest-seq monotonic owner-only + relay strictly-higher-seq replace. Sound.
- Tenet clarification ACCURATE: untrusted-not-content-blind, never encrypted content, DiD not trust
  dep; BRIDGE_REGISTER §10.12.4 precedent (Ed25519 + same binding on control plane) is real.
- OBS DoS: relay Ed25519-verify-per-PUBLISH is bounded (BEP44/BRIDGE_REGISTER precedent) but spec
  should gate it behind existing per-IP PUBLISH rate limit + do cheap structural+binding(SHA-256)
  checks before the Ed25519 verify (reorder §3.10.2 steps 1↔2).
