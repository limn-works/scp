# Collaborative Workspace Template

Multi-party governed workspace over SCP with role-based access control,
shared outlets, UCAN capability delegation, and governance.

## What this demonstrates

- **Identity**: Admin identity with agent key binding (ADR-039)
- **Governed context**: Encrypted workspace with `single_admin` governance,
  a capability ceiling that governance may change, and a TTL
- **Roles**: Admin, Moderator, Member, Observer -- each with a scoped
  capability set enforced via UCAN tokens
- **Outlets**: Registration, verification (test vectors), and capability-gated
  invocation via scoped UCAN tokens
- **Governance**: Role changes, member removal, and TTL extension through
  `contextGovernancePropose` and `contextProposeTtlExtension`, executed at
  once under single-admin governance
- **UCAN delegation**: Minting role-scoped tokens, delegating subsets to
  other participants, and validating tokens before outlet invocation
- **Messaging**: Sends from two members over the relay transport
- **Trust evaluation**: Querying behavioral records from the event log
- **Event log**: Querying events, Merkle checkpoints, and inclusion proofs

## Roles

| Role | Token capabilities |
|------|-------------|
| Admin | Full ceiling -- read, write, role assign, invite, remove, outlet register/query, governance propose/vote |
| Moderator | Read, write, invite, outlet query, governance propose/vote |
| Member | Read, write, outlet query |
| Observer | Read only |

The four roles are protocol-defined (spec section 5.5); governance assigns
one to each participant with a `ChangeRole` action. Each participant then
receives a UCAN token whose capability set matches the table above, defined
in `ROLE_CAPABILITIES` in `participant.ts`. Outlet invocation requires a
valid UCAN token with the `outlet:query:{outletId}` capability.

## Governance

The template uses `single_admin` governance, where the admin's proposals
execute immediately. To demonstrate multi-party voting:

1. Change `governance` in `contextParams` to `"threshold"`, `"majority"`,
   or `"unanimity"`
2. Use `scp.contextGovernancePropose(ctx, actionJson, proposerDid)` to submit proposals
3. Other admins call `scp.contextGovernanceApprove(ctx, proposalIdHex, voterDid)` or
   `scp.contextGovernanceReject(ctx, proposalIdHex, voterDid)` to vote
4. When quorum is reached, the action executes

A voting-governed context cannot use `inviteMember` yet: governed-context
invitations are not implemented, and the call throws.

Governance actions include: `AddMember`, `RemoveMember`, `ChangeRole`,
`RegisterOutlet`, `RemoveOutlet`, `ModifyCeiling`, `CloseContext`, `ExtendTtl`,
`TransferAdmin`, `CreateChildContext`, `SuspendAccess`, `RevokeAccess`,
and more (ADR-031).

## How to customize

**Change the governance model**: Set `governance` to `"threshold"`,
`"majority"`, or `"unanimity"` in `contextParams`.

**Change role tokens**: Edit `ROLE_CAPABILITIES` in `participant.ts`. Each set
must stay within the workspace ceiling.

**Register different outlets**: Use `defineOutletDefinition()` with your own
schemas and `kind` (`"query"` or `"action"`), and pass the result to
`scp.outletRegister(ctx, definition)`. An action outlet takes an
`outlet:call:{outletId}` capability.

**Add economic policy**: Set `economicPolicy` in `contextParams` with a
JSON string conforming to the `EconomicPolicy` schema (spec section 19).

**Switch to broadcast mode**: Set `mode: "Broadcast"` in `contextParams`
for one-to-many publishing instead of encrypted group messaging.

## Running

The `"os_keystore"` custody request of spec `03-identity.md` §3.2.2 reaches a
host key store only through a provider, so `src/index.ts` exports
`runWorkspace(custody, relayUrl, storagePassphrase)`, which takes a
`KeyCustodyProvider` that your application implements over its own key store.
One SCP instance hosts every participant, so that provider holds every
participant's keys.

```
bun install
bun run check
```

Call it from your application:

```typescript
import { runWorkspace } from "./src/index";

await runWorkspace(myProvider, "wss://relay.example.com", process.env.SCP_STORAGE_PASSPHRASE ?? "");
```

## File structure

```
src/
  index.ts        -- Main workspace workflow
  participant.ts  -- Participant lifecycle helpers (add, remove, role change)
```
