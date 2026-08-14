---
name: scp-out-036-reencrypt-locus-reconcile
description: SCP-OUT-036 cross-ctx outlet-stream re-encryption locus — prior NEEDS-SPEC-OWNER reword now LANDED & ALIGNED @bcc9016f5 (3 LOW residual)
metadata:
  type: project
---

# UPDATE @ bcc9016f5 (feat/outlet-xctx-036-bridge, scp-wt-slice3, 2026-07-14) — prior NEEDS-SPEC-OWNER concern RESOLVED → ALIGNED

Reword LANDED after crypto+architecture+alignment review, done RIGHT (spec-first, additive, no weakening). My original fear (a hand-wave letting plaintext reach A's non-invoker members / A's log) is FORECLOSED:
- §5.4.5:568 now NAMES mechanism precisely: bridge = SDK seam (§6.2.0, "not a relay primitive"); runtime returns plaintext IN-PROCESS to the shared-member invoker ONLY (member of BOTH B and A — sanctioned, mirrors same-ctx invoke_outlet + unary-saga output-to-invoker-as-bytes/log-records-output_hash-only, §6.2.4); delivery to A's OTHER members = A-context MLS application message SEALED under A's group key over §9.7/§9.8/§9.16 (group key IS the per-recipient re-encrypt, no new relay primitive); A's log records ONLY 32-byte stream_manifest_hash (never plaintext); operator SCP-OUTLET-CHUNK-SIG-V1 preserved end-to-end, never re-signed. Encryption-as-access-control + context-isolation tenets UPHELD.
- New §5.4.5:570 "Verification source at the crossing (normative)" = faithful streaming analog of §6.2.4:276 Caller-authentication rule: verify operator chunk sig against pinned governed-descriptor operator_pk/B-context_id/caveats_binding (§6.2.0.1), NEVER bridge-supplied values. Threat (malicious bridge substituting verification inputs) articulated.
- AC2 falsehood FIXED: plaintext Receiver no longer claims "re-encrypted chunks"; return type = plaintext OutletStreamChunk, re-encryption relocated to delivery-seam AC. AC10 seal-for-A mechanically tests non-A-member-can't-decrypt + A-member-recovers-with-operator-sig-intact. AC11 verify-against-pinned. AC12 zero-escrow reject-paid-Action faithful to ADR-061:64 (escrow settlement is saga-unique).
- Citation CORRECT: §9.7 (Group Key Mgmt MLS)/§9.8 (Message Security)/§9.16 (Sender-Side Key Layer) are right home for encrypted-ctx MLS app msg; prior wrong §5.14 Broadcast PURGED from spec+story. §5.14 still in COMMIT MESSAGE body only (immutable, cosmetic).
- 3 LOW residual (non-blocking, no weakening): (1) sources[] omits §9.7/§9.8/§6.2.4 though prose+spec cite them (has §9.16); (2) story prose "§9.8/§9.16" vs spec "§9.7/§9.8/§9.16" asymmetry; (3) stale §5.14/§9.16 in commit message contradicts corrected artifacts.
- VERDICT: ALIGNED. Faithful precise reconciliation, not a weakening. 036 still pending impl (grep invoke_outlet_cross_context = 0) ⇒ nothing unblocked-under-pressure.

---
# ORIGINAL ENTRY (superseded above; reword hadn't landed yet)

# SCP-OUT-036 cross-context outlet-streaming re-encryption locus (validation @ scp-wt-slice3, 88c98c23b, 2026-07-14)

Asked to validate an artifact-flow "reconciliation" (Option 1): reword §5.4.5:568 ("A shared-member bridge re-encrypts each chunk per-recipient as it crosses") + SCP-OUT-036 AC2, to relocate re-encryption from the runtime bridge fn to the shared-member SDK delivery seam, motivated by verified fact that outlet chunks are plaintext in-process (only crypto = operator per-chunk SCP-OUTLET-CHUNK-SIG-V1).

**Verdict: NEEDS-SPEC-OWNER** (not ALIGNED). Reasoning:

1. **No genuine contradiction.** §5.4.5:568 attributes re-encryption to "a shared-member **bridge**"; §6.2.0 (06:20) DEFINES bridge = the human's local SDK seam ("The human's SDK is the transport"). §6.2.4:300's transport ("shared-member local SDK seam … never a new relay primitive") is that SAME seam. Both sentences already describe one mechanism: bridge holds both MLS keys, opens B-sealed chunks, seals-for-A on entry to A (ordinary context-message MLS path). They cohere as-written.

2. **Premise conflates two code paths.** "plaintext in-process" is the BUILT same-context pump (stream.rs/dispatch.rs, SCP-OUT-033/034/035). §5.4.5:568 governs the UNBUILT cross-context bridge — `invoke_outlet_cross_context` grep = ZERO (SCP-OUT-036 status:pending). No false claim exists; using the same-context observation to reweaken the cross-context crypto sentence = code-informs-spec anti-pattern (phantom provenance).

3. **Weakening risk.** Guarantee that must survive: chunk data entering ctx A is MLS-sealed under A's keys (encryption-as-access-control / context-isolation = core tenet, "the security boundary"). Vaguer reword invites plaintext to remote-A members / A event-log record. Reword also CONFLICTS with story AC2 (returned mpsc::Receiver "chunks re-encrypted for the invoker's context") → would force a 2nd patch.

4. **Citation fix:** prompt's "§6.2.5:300" is actually §6.2.4:300 (§6.2.5 starts at 345). "No new relay primitive" is the §6.2.4 SAGA transport-leg rule.

5. **036 tests ZERO encryption.** All 10 ACs verify forwarding/schema/dual-log(append_outlet_invoked_verified, ChunksBilledMismatch)/chain_depth/error-codes. "re-encrypted" is prose-only (title/desc/AC2); AC2's check is `grep 'fn invoke_outlet_cross_context'` (decl existence). Completeness finding: a "re-encrypting bridge" story with no seal test cannot mechanically enforce its claimed boundary.

6. **ADR-057 fence.** MLS seal/open IS a participant (SDK) op; node-colocated bridge → runtime fn == SDK seam (distinction collapses); only browser-delegated participant makes locus bite → ADR territory, not story-time reword.

**Right move:** don't reword unilaterally. Likely NO change needed (sentences cohere). If precision wanted → ADR-061 amendment → §5.4.5 → SCP-OUT-036, additive (pin participant-seal locus, one group-seal per recipient ctx not per-member), never weakening sealed-for-A. Add a 036 AC asserting A-context sealing. SCP-OUT-036 pending ⇒ nothing blocked, no unblock pressure to justify a code-agent crypto-locus edit.

Related: [[scp_out_046_pra_writethrough_541a89e3b]] (streaming saga seal phase = SCP-OUT-046, distinct from this best-effort mode), [[adr061_provenance_restored_fa8e5eb79]].
