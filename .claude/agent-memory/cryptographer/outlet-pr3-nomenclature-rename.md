---
name: outlet-pr3-nomenclature-rename
description: outlet PR3 tool→outlet wholesale rename (feat/outlet-report-pr3 @4e6fb43ef) — byte-safe on signed/hashed paths; CORRECTION Merkle leaf hashes rmp_serde NAME not numeric tag
metadata:
  type: project
---

# outlet PR3 tool→outlet rename crypto/consensus review (43c741f61..4e6fb43ef)

VERDICT: SOUND on all signed/hashed paths within-version. NO CONFIRMED regression. All KATs pass live.

KEY CORRECTION to common mental model: The Merkle LEAF hash does NOT hash the numeric event_type_tag. `leaf_hash = SHA-256(0x00 || rmp_serde::to_vec(event))` serializes the whole Event incl `event_type: EventType`, and **rmp-serde 1.3.1 encodes unit enum variants by NAME as fixstr** (empirically: ToolInvoked→`ab 54..` 11-byte str, OutletInvoked→`ad 4f..` 13-byte str). So renaming variants DOES change leaf bytes for renamed types (OutletInvoked/OutletRegistered/CrossContextOutletInvoked...). The numeric tag (`event_type_tag`, tree.rs:402) is used ONLY in the SIGNING preimage `compute_event_canonical_hash` (SCP-EVENT-V1:), never the Merkle leaf. Applied in lockstep across single source of truth (scp-event-log; WASM removed, scp-client reuses it) → within-version convergence holds; hard break vs any pre-rename persisted logs (acceptable pre-release — regenerated vectors are the acknowledgment).

Findings by focus area:
1. event_type_tag UNCHANGED: OutletRegistered=9,Updated=10,Invoked=11,Verified=12,InterfaceEstablished=13,Removed=55,CrossContextOutletInvoked=76,DivergenceMarker=77 — byte-identical to old Tool* positions. No renumber.
2. Event-id string "OutletInvoked:" LOCKSTEP: 6 emit format! (saga.rs:1469, supervisor.rs:6819/20511/20614/20679/21485) + 5 decode strip_prefix (summary.rs:89, supervisor.rs:20368/21229/21331/21435); ZERO "ToolInvoked:" remain. This string IS on signing path (receipt outlet_invoked_event_id, and divergence committed_event_id) but sign==verify both derive it at runtime.
3. 4 vectors all correct+pass: vector_32/33 — ALL 9 leaves changed via prev_hash CASCADE from leaf0 AppBound payload capabilities `tool:invoke:*`→`outlet:call:*`; NONE of the 9 use a renamed EventType (sole input delta = capability string). receipt_preimage_is_byte_exact SELF-RECOMPUTING (fixture 18→20 "evt-tool-invoked-1"→"evt-outlet-invoked-1", hand-hash matches). kat_invitation_bundle_signing_hash 222a→a6b5 (ContextParams field `pub tools`→`pub outlets`, plain rename, JCS key tools→outlets in genesis_params_hash). vector_28 SELF-RECOMPUTING (offer-id tool-abc123→outlet-abc123, buf 73→75, manual Sha256 cross-check).
4. Signing domains byte-UNCHANGED (only doc prose): SCP-OUTLET-REGISTRATION-V2, SCP-OFFER-ID-V1, SCP-XCTX-RECEIPT-V1, SCP-XCTX-DIVERGENCE-V1, SCP-EVENT-V1, SCP-CHALLENGE-*-V1. Historical SCP-TOOL-REGISTRATION-V1 preserved intact (hash.rs:60 retired-marker + runtime test_vectors.rs:1303).
5. No by-name enum serialization regresses signed bytes: CommittedSide by numeric tag (Caller=0/Target=1, variants not renamed); challenge_type via challenge_type_tag=uri.to_string() but DATA-derived per-record (outlet_integrity() name "tool-integrity"→"outlet-integrity" only affects NEWLY-minted records; old records self-describe + verify). SCP-TOOL-6xxx→SCP-OUTLET-6xxx are ERROR CODE strings not signing domains.
