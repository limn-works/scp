# Two Migration Operations Cite Two Cases of the Key Custody Migration Protocol

Two SDK operations share the verb "migrate" and change different keys:

| Operation | What it does | Cites |
|---|---|---|
| `identity_migrate` / `identityMigrate` | Changes the root set by revealing a standing pre-rotation key, and returns the key event | §3.2.1 of `03-identity.md`, Key Custody Migration Protocol, case 2; §9.7.4.2 of `09-security-model.md`, Root-Authority Recovery and Fork Precedence |
| `identity_execute_custody_migration` / `identityExecuteCustodyMigration` | Moves the Active Signing Key to another key-storage substrate | §3.2.1 of `03-identity.md`, Key Custody Migration Protocol, case 1 |

Citing the operational-key case for the root-change operation sends a reader past the
pre-rotation reveal. Decide a citation by asking which key the operation changes, not by the
name: the identifier changes in neither case (`09-security-model.md` §9.7.4.2 R2). Keep the
citation identical in every binding's doc comment.
