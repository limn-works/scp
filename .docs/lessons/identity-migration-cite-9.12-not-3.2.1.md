# `identity_migrate` Cites §9.12 and ADR-003 §4b, Not §3.2.1

> **Dating note (2026-09-02):** this lesson describes `migrate_identity` and the pre-rotation model as `09-security-model.md` §9.7.4.1 and §9.12 read before the key-event-log recovery amendment. Under the amended §9.7.4.2 a `RootRecovery` installs a fresh root and never installs the revealed key, the commitment is domain-separated under `"SCP-PREROTATION-COMMITMENT-V1:"`, and the "Partial-publish recovery" paragraph is replaced by R10. The lesson's principle stands; its spec citations are historical.

**Problem**: the identity spec defines two migration operations. They look alike on the SDK
surface, they share the verb "migrate", and they cite different sections because they do
different things. Citing the custody-migration section for the new-DID operation sends a
fresh agent to the DID-preserving custody swap and past the pre-rotation reveal, which is a
phantom-provenance trap.

| Operation | What it does | Cites |
|-----------|--------------|-------|
| `identity_migrate` / `identityMigrate` | Creates a new DID by revealing the pre-rotation key, and returns a `DidRotationEvent`. This is Identity Key migration. | §9.12 of `09-security-model.md`, Compromise Recovery Protocol, plus ADR-003 §4b, DID creation |
| `identity_execute_custody_migration` / `identityExecuteCustodyMigration` | Moves custody to a different key-storage substrate and preserves the identity's DID. | §3.2.1 of `03-identity.md`, Key Custody Migration Protocol |

## Rules

- **The new-DID and pre-rotation-reveal call cites §9.12 and ADR-003 §4b.** The
  DID-preserving custody swap cites §3.2.1. Do not conflate them.
- **Verify a citation against the behavior, not against the name.** Ask whether the DID
  changes. §9.7.4.1 of `09-security-model.md`, Pre-Rotation Key Custody, holds the custody
  requirements the reveal depends on.
- **Keep the citation identical across every SDK binding.** A divergence between the Python
  and TypeScript doc-comments for one operation is a finding.
