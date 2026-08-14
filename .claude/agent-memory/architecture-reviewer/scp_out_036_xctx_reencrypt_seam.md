---
name: scp-out-036-xctx-reencrypt-seam
description: SCP-OUT-036 cross-context outlet-stream re-encryption location — Option 1 (delivery-seam MLS reuse) validated SOUND vs Option 3 (new chunk-delivery layer)
metadata:
  type: project
---

DESIGN VALIDATION @ scp-wt-slice3 main 88c98c23b. SCP-OUT-036 (best-effort cross-context *outlet stream*, §6.2.5) blocked on WHERE per-recipient chunk re-encryption lives. **Verdict: Option 1 SOUND + complete; Option 3 (design a new cross-context chunk-delivery mechanism) would build the forbidden relay primitive. NO missing layer.**

The apparent contradiction — §5.4.5:568 "a shared-member bridge re-encrypts each chunk per-recipient as it crosses" vs §6.2.5:300 "the shared-member local SDK seam ... never a new relay primitive" — dissolves once you use the spec's OWN vocabulary: §6.2.0 mechanism-1 DEFINES "shared-member bridging" as "the human's SDK is the transport." So "the bridge" in §5.4.5:568 = the SDK seam, NOT the runtime fn `invoke_outlet_cross_context`. §5.4.5:568 is the OUTLIER sentence; it must be reconciled TO the other three anchors, not the reverse.

Four dispositive anchors that make Option 1 correct:
1. §6.2.5:300 "Transport leg ... shared-member local SDK seam ... never a new relay primitive."
2. §6.3 "human as bridge ... local coordination ... requires no network-level mechanism."
3. Same-context precedent: `invoke_outlet` (invoke.rs:3386/3409) returns `Result<mpsc::Receiver<OutletStreamChunk>>` — PLAINTEXT chunks in-process to the SDK. Never MLS-sealed, never reaches scp-node/transport.
4. **Unary saga precedent (decisive), §6.2.5:319:** cross-context OUTPUT goes to the INVOKER on the receipt (output BYTES on `SCP-XCTX-RECEIPT-V1`); A's event log records ONLY `output_hash` (32B) — "keeps the caller log free of a large or sensitive payload." There is NO runtime-level per-recipient re-encryption even in the mature unary saga. Streaming mirrors it: A's log records `stream_manifest_hash` (32B), chunks return to the invoker.

Why no missing layer: shared-member bridging = ONE human H member of both A+B; H's SDK is the in-process confluence. The two legs decompose into (1) intra-B delivery to H (existing B transport) + (2) intra-A delivery from H (existing §5.14/§9.16 MLS message transport). The "cross-context" step is purely H's in-process plaintext handoff (decrypt B chunk / re-seal for A). NO chunk ever needs a new cross-context wire primitive — exactly why §6.2.5:300 forbids one. Plaintext-in-H's-process is SANCTIONED (H legitimately reads B's output + is an A member; same trust model as same-context `invoke_outlet` + §6.3). "as it crosses" = as it enters A's delivery = at the SDK seal-as-A-message step. MLS group key IS the "per-recipient" mechanism (no per-individual encryption in MLS). Signed chunk (SCP-OUTLET-CHUNK-SIG-V1) becomes the plaintext payload of an A-context app message; receiver reassembles by chunk `sequence` + re-derives manifest (AC7), so transport reorder is tolerated — delivery need NOT be stream-aware.

ADR-057 fence: PASS. Fence = "scp-mls/browser MUST NOT depend on scp-runtime" + "cross-context saga COORDINATION stays in scp-runtime / node-delegated; browser participates, does not coordinate." The bridge lives in scp-runtime (node-side) exactly where the fence puts coordination; browser's only role is RECEIVING a normal A-context message (decrypt via scp-mls) — already supported. No new browser dependency.

Forward-compat 046 saga / 047 FFI: PASS. §6.2.5:366 saga = "the §6.2.4 envelope extended with a seal phase"; it ADDS a durable-frontier sink ALONGSIDE the same forward-as-produced sink ("two parallel sinks"). Re-encryption LOCATION is unchanged best-effort→saga; saga adds receipt/escrow/durable-capture on top (all node-side runtime). HEAD 88c98c23b already lands "streaming SagaPreparedState + MerkleFrontier serde (OUT-046 prep)" confirming the two-sink direction. FFI (047) = poll_next delivers plaintext chunk to local SDK = same model.

REQUIRED for the reword to be legitimate (not paper over): (a) NAME the mechanism — delivery-into-A = seal each signed chunk as an A-context app message over existing §5.14/§9.16 transport; do NOT leave "the seam re-encrypts" abstract (abstract = prose-policed confidentiality = re-invites the forbidden bespoke primitive); (b) state the plaintext-confluence trust basis; (c) AC2 reword — the returned `Receiver<OutletStreamChunk>` yields PLAINTEXT chunks to the shared-member invoker; relocate "re-encrypted for the invoker's context" to the delivery seam (a plaintext `Receiver<OutletStreamChunk>` structurally CANNOT be "re-encrypted" — the current AC2 wording is internally false). Flow is upstream-correct (fix §5.4.5:568 + AC2 BEFORE code), consistent with ADR-061, not phantom provenance.
