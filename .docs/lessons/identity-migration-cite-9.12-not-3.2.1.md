# Two Migration Operations Cite Two Cases of the Key Custody Migration Protocol

**Problem**: the identity spec defines two migration operations. They look alike on the SDK
surface, they share the verb "migrate", and they cite different cases because they change
different keys. Citing the operational-key case for the root-change operation sends a fresh
agent past the pre-rotation reveal, which is a phantom-provenance trap.

| Operation | What it does | Cites |
|-----------|--------------|-------|
| `identity_migrate` / `identityMigrate` | Changes the root set by revealing a standing pre-rotation key, and returns the key event. | Key Custody Migration Protocol, §3.2.1 of `03-identity.md`, case 2; Root-Authority Recovery and Fork Precedence, §9.7.4.2 of `09-security-model.md` |
| `identity_execute_custody_migration` / `identityExecuteCustodyMigration` | Moves the Active Signing Key to a different key-storage substrate. | Key Custody Migration Protocol, §3.2.1 of `03-identity.md`, case 1 |

## Rules

- **Cite the case, not the verb.** Both operations sit under the Key Custody Migration
  Protocol, §3.2.1 of `03-identity.md`: the root change is case 2 and the operational-key
  move is case 1.
- **Verify a citation against the behavior, not against the name.** Ask which key the
  operation changes. The identifier changes in neither case (`09-security-model.md`
  §9.7.4.2 R2), so the identifier separates nothing.
- **Keep the citation identical across every SDK binding.** A divergence between the Python
  and TypeScript doc-comments for one operation is a finding.
