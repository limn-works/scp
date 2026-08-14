---
name: adr063-provenance-bearing-projection
description: Black-hat design attack on ADR-063 (provenance-bearing projection) + provenance-bearing-projection PRD, branch worktree-agent-a90070b75ca058cee @ d100be081. 12 findings; top 3 are design-level breaks the ADR does not consider.
metadata:
  type: project
---

Attacked ADR-063 + spec deltas 05/09/10/13/18/25 + `.docs/prds/provenance-bearing-projection.json` (16 stories).
Design proposes: `BroadcastEnvelope` V2 signature binding `SHA-256(encrypted_content)` + `signing_key_id`;
delete `open_broadcast_trusted`; author `ContentAttestation` over plaintext body served at
`/.well-known/scp/attest/<blob_id>`.

**Why:** the V2 forgery fix itself is sound (a broadcast-key holder can no longer substitute content).
The breaks are all in the *HTTP guarantee* layer and its imported premises.

**How to apply:** if this design is revisited, these are the load-bearing gaps.

## Design-level breaks (not implementation bugs)

1. **`#active` rotation = total archive deletion.** §9.7.1 check 1 / §9.12 verify against the *current*
   verification method only, and §9.12 explicitly *rejected* an `attestations_valid_after` watermark —
   a decision made for short-lived KeyPackage attestations with a lifetime cap and a re-issuance path.
   ADR-063 imports that model onto permanent archival artifacts with neither. Rotating `#active`
   (routine custody migration, or mandatory compromise recovery) invalidates every ContentAttestation
   and every V2 envelope signature ever minted, and SCP-PROVSERVE-9002 then forbids serving any of it.
   Attacker play: steal `#active`, publish something damaging; the victim's only remedy nukes their site.
2. **The verification procedure is not executable from the served document.** §18.11.13.2's preimage
   position 10 is `provenance_hash`, but the attestation document carries `provenance` as JSON and no
   `provenance_hash`. §24.3.3 is normative: `provenance_hash = SHA-256(rmp_serde::to_vec(DataProvenance))`,
   positional MessagePack over 12 fields incl. `Duration` + enums, and "JSON is **not** used on any
   provenance-hash path." Consumer cannot rebuild the preimage. Step 6 says "*read* provenance" — never
   "verify" — so served provenance is unauthenticated in practice.
3. **Serving `provenance` violates §24.3.5.** "Raw DIDs MUST NOT appear in exported provenance data …
   regardless of the source context's counterparty_policy." Public HTTP is export. And because
   `provenance_hash` is *signed*, the node cannot pseudonymize on export without breaking verification —
   §24.3.5's requirement becomes unimplementable.

## Residual attacks (assume the fix ships as designed)

4. **Undetectable deploy rollback.** Attestation binds `path` but not `deploy_id`; `DeployManifest`
   (`crates/scp-node/src/projection.rs:133`) is entirely unsigned node-local state; `rollback_deploy`
   is a supported API. Retraction is impossible — a retracted page stays verifiably "authored by you"
   forever. `deploy_id` also leaks publicly in the site ETag `"<deploy_id>:<content_hash>"`.
5. **Path / content-type confusion.** The 6-step consumer procedure never compares `path` or
   `content_type` from the attestation against the requested URL / served `Content-Type`. Serve an
   attested `text/plain` blob as `text/html` → stored XSS with a passing provenance check.
6. **No enforcing consumer on the surface it protects.** `Link` headers are "an affordance, not the
   guarantee." A stripping proxy/CDN/MITM leaves a browser with no signal. SCP-PROVSERVE-9001's
   "absence is positive evidence" needs an out-of-band anchor (the `_aidp` DNS TXT the ADR surveyed
   and then declined) so a consumer knows the origin *should* be SCP-projected.
7. **Byte-fidelity cost dropped from Alt 2's accounting.** The ADR's own external-convention table
   names RFC 7797 §5.1/§8 byte-fidelity as "the sharpest cost of any plaintext-plus-detached-signature
   design" — then omits it from chosen-Alt-2 costs. Any transforming intermediary (minify, `sub_filter`,
   transcoding) yields a false "forged" verdict.
8. **Cross-author path hijack.** `commit_deploy` (`crates/scp-node/src/lib.rs:1258`) filters blobs by
   `metadata.deploy_id` only, never by author. Any co-author in a projected context can claim `/index.html`.
9. **Subscriber-portable authenticated leak.** The attestation is inside the ciphertext, so every
   broadcast-key holder ($5/mo subscriber) can extract a *publicly verifiable* proof of authorship for
   gated/paid plaintext. Converts "a subscriber can leak" into "a subscriber can publish an unforgeable
   author-signed copy." Universal non-repudiation for confidential broadcast content — not examined.
10. **Replay-detector DoS.** `BroadcastReplayDetector::check_and_advance` is monotonic per author;
    PBP-003 wires it into `open_broadcast_content_verified`, which PBP-004 puts on random-access read
    paths. Two GETs (high sequence first) unpublish the whole archive.
11. **Decision 2 "not expressible" is overstated.** `BroadcastKey::key()` and `SenderKey::as_bytes()`
    stay `pub`, the AAD formula is normative spec text, `decrypt_envelope` survives as a private helper —
    reconstruction is ~10 lines, and the ADR forbids any gate. Also `open_broadcast(&VerifyingKey)`
    type-enforces "*a* key", not "*the author's* key".
12. **Bundled custody voids the anti-forgery half for the primary shape** (§10.17). Decision 6 admits
    this, but §10.12.11 still calls provenance "what makes the transport story sufficient."
