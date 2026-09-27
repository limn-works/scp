# `identity_migrate` Cites §9.12 and ADR-003 §4b, Not §3.2.1

Two SDK operations share the verb "migrate" and do different things:

| Operation | What it does | Cites |
|---|---|---|
| `identity_migrate` / `identityMigrate` | Creates a new DID by revealing the pre-rotation key and returns a `DidRotationEvent` | §9.12 of `09-security-model.md`, Compromise Recovery Protocol, and ADR-003 §4b |
| `identity_execute_custody_migration` / `identityExecuteCustodyMigration` | Moves custody to another key-storage substrate and keeps the DID | §3.2.1 of `03-identity.md`, Key Custody Migration Protocol |

Citing §3.2.1 for the new-DID operation sends a reader to the DID-preserving swap and past the
pre-rotation reveal. Decide a citation by asking whether the DID changes, not by the name, and
keep the citation identical in every binding's doc comment. §9.7.4.1 of
`09-security-model.md`, Pre-Rotation Key Custody, holds the custody requirements the reveal
depends on.
