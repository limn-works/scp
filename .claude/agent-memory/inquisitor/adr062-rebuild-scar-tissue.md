---
name: adr062-rebuild-scar-tissue
description: ADR-062 rebuild (real-backends/test-harness-only-nullifiers, reverted the residue-reframe) — scar-tissue hunt; confirms SCP-CAPINJECT-002 depends on unaccepted ADR-054 + finds the vanished §9.7.4.1 §5 ceremony
metadata:
  type: project
---

# ADR-062 REBUILD scar-tissue hunt @ branch docs/adr-062-capability-injection (HEAD 71659b057, NOT pushed)

The rebuild REVERTED the prior "backend-pending-residue" reframe (reverts 46aa0751c/1ab46c8cd etc.) and now says "build the real pre-rotation backend NOW, no deferral." Governing spec §17.17 (SCP-CAPSEL-8000..8013) is NEW on this SAME branch (0 matches origin/main); §17.17.2 names ADR-062 by number → spec+ADR co-authored, "upstream/unchanged" framing overstates independence.

**Why:** orchestrator asked to VERIFY+EXPAND the finding that SCP-CAPINJECT-002 depends on ADR-054 (Status: Proposed, 3 open Qs) and to hunt all other scar tissue.
**How to apply:** re-check these before ADR-062 is marked Accepted or the PRD executes.

## CONFIRMED load-bearing scars (ranked)
1. **CRITICAL — SCP-CAPINJECT-002 schedules implementation of ADR-054 which is Status: Proposed, unaccepted.** ADR-054's OWN "Alternatives" line: "acceptance authorizes the implementation workstream" — so by its own terms code is not authorized. Q2 (backend minimum) is resolved FROM INSIDE ADR-062 §4 ("resolving ADR-054 Q2 toward: encrypted-offline is the floor") = downstream-resolves-upstream artifact-flow INVERSION. Q3 (does §9.7.4.1 need a callback-custody clause) is UNRESOLVED — punted to PRD story action-item #1 ("Resolve ADR-054 Q3 ... FIRST"), i.e. the P0 story's first step is upstream-ADR work. No mechanical gate: story `blockedBy` = ["SCP-CAPINJECT-000"] only; "ADR-054 accepted" is prose in a description field, not a blocker (ADRs aren't stories). HONEST PATH: accept ADR-054 first → resolve Q2 INSIDE ADR-054 (or human) → resolve Q3, land any §9.7.4.1 clause spec-first → THEN build.
2. **HIGH — the rest of ADR-054 vanished into "interface-ready future work, not a deferral."** SCP-CAPINJECT-002 ships ONLY the encrypted-offline codec (§4 "Medium" tier, 1 of 6 approved methods) + the FFI seam. ADR-054 §2 hardware backends (Secure Enclave/StrongBox/FIDO2/cloud/Shamir/BIP39) + §3 the §9.7.4.1 §5 SELECTION CEREMONY ("MUST present the user with custody options, ordered") + §6 post-rotation re-selection are in NO story, NO gate, NO tracking. Spec §5 is a hard MUST over PLURAL options; one backend = degenerate one-option "menu" whose §5-compliance is unassessed. Completeness-baseline violation dressed as "not a deferral (interface complete now)." PRD's 4 "selection/enclave/shamir" hits are all in prose EXCLUDING them. Fix: add explicit stories/gates OR scope 002 to full ADR-054.
3. **MED-HIGH — scp-node NodeConfig.dht Memory default exempted as a BARE non-goal, no justification.** §17.17.3 makes the DHT-nullifier rule universal ("every provider capability"); E1 eliminates the CLIENT in-memory DHT twin; but ADR non-goal = "No change to NodeConfig.dht Memory default" with zero rationale. The justification EXISTS and a PRIOR pass verified it (node DhtMode::Memory = fail-SAFE "do not publish" / §3.10.6 legible opt-out, config.rs:202/289/493 — NOT the fail-OPEN silent-false-success client nullifier). Rebuild dropped the reasoning → reads as inherited-unexamined boundary. Cheap fix: state WHY node-Memory ≠ the client nullifier.
4. **MED — #1733 closed-as-folded at Slice 0, but its goals 3-4 (fixtures testing-gated + CI enforcement = G1) don't land until Slice 3.** SCP-CAPINJECT-000 action item "close #1733 as folded"; G1 is Slice 3. Premature closure — if Slice 3 slips, #1733 closed with enforcement unshipped. Fix: close at Slice 3.

## Downgraded on evidence (NOT scars)
- Device attestation "capability simply absent/Unsupported in shipped SDK" (Decision 3) is SPEC-BLESSED: §9 line 187 "Device attestation ... is an optional SDK-level trust signal ... Its absence is expected." No hardware-free real backend can exist (software attestation IS the nullifier) = real external constraint. VALID deferral — but ADR under-cites it ("Axis A=0" instead of §9:187 optional/absence-expected). LOW: fix the citation.

## Minor
- `in_memory/` module name is a MECHANISM name housing only SOME in-memory types (storage/push); nullifier in-memory types (custody/attestation/pre-rotation) stay in `testing/`. Honest split axis is durability-vs-nullifier, not in-memory-ness. Slice-0 AC also puts InMemoryStorage in the `testing` union "for convenience" = dual-home.
- DHT "Pkarr always-used baseline" wording mildly tensions §17.17.3 "must select DHT backend explicitly"/8000 no-default; ClientDhtConfig probably satisfies explicit-construction but reconcile the wording.
- Ecosystem-convention section (rustls/webauthn-rs/OWASP/Signal SVR/Apple ADP/OpenMLS) does external-authority persuasion that §17.17 already grounds; risks inherited-premise framing.
