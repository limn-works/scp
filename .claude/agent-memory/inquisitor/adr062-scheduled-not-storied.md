---
name: adr062-scheduled-not-storied
description: ADR-062 capability-injection — the "scheduled slices, not yet storied" scar-tissue pattern and the Swift/Kotlin-only native-backend asymmetry
metadata:
  type: project
---

ADR-062 (`.docs/adrs/ADR-062-capability-injection-and-prove-absent-dev-backends.md`) realizes spec §17.17
(capability-selection mandatory/fails-closed/never-default) for FOUR nullifier capabilities: DHT, key custody,
device attestation, pre-rotation custody. PRD `adr062-capability-injection.json` = 9 stories (SCP-CAPINJECT-000..008).

**Recurring scar-tissue pattern to watch in this project's ADRs: "scheduled slices … not yet storied."**
ADR-062 discloses E2 credentials (HIGH, hardcoded `InMemoryCredentialStore`), E3 blob (`impl Default → in_memory`,
a live SCP-CAPSEL-8011 violation), E4 relay-querier (`NoOpRelayQuerier`, likely nullifier) as "subsequent slices
(not yet storied)" (ADR §Rollout last bullet; PRD `description`). This calls unstoried work "scheduled," which
contradicts "artifacts are the system of record." The severity-ordering argument (E5-now/E2-later, §Decision 5)
justifies SEQUENCE, not OMISSION of the story. The no-deferral + completeness tenets say: story them now (gates can
sequence after Slice 6). E2 is also left unclassified (nullifier vs durability-only) against SCP-CAPSEL-8010's
"every dev arm MUST be classified." **Why:** this is the exact deferral-dressed-as-decision the scar-tissue defense
targets. **How to apply:** whenever an ADR says "scheduled/subsequent slice, not yet storied" for a capability with
a live spec violation, that is a finding, not a residual note.

**Second finding: native-backend asymmetry.** Slices 7 (Swift) / 8 (Kotlin) implement hardware pre-rotation
backends (Secure Enclave/StrongBox/FIDO2). NO story for Python or TypeScript. §4's Highest method (FIDO2 USB) is
reachable from desktop Python/TS, so their §5 interactive menu is permanently single-option (encrypted-offline) —
empty Python/TS cells in the native-backend matrix. 7/8 are also P1/major while 0-6 are P0/critical (soft-deferral
signal on a completeness-tenet project).

**Verified SOUND (do not re-litigate):** `allow_in_memory_custody` deletion is a correct root-cause fix of the
use-case-named-switch misnomer; enum-not-`Arc<dyn>` seam is correct (RPITIT not object-safe); the reject-and-revert
of "weaken SCP-CAPSEL-8012 + document residue" stays rejected; ADR-054 is genuinely **Accepted 2026-07-14**
(maintainer delegation), OQ2/OQ3 resolved with per-profile floors — ADR-062 cites it correctly and does not
re-decide it; device-attestation decline traces to real spec authority (§9 "attestation absence is expected");
node `DhtMode::Memory` default kept with a sound opposite-fail-safe-direction argument (node no-publish = fail-safe;
client no-publish = fail-open). §17.17 was co-authored with the ADR in one commit but honestly disclosed (force
rests on §17.17.3's argument, not age).
</content>
</invoke>
