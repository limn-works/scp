# Collaborative Workspace Template

Multi-party governed workspace over SCP with role-based access control,
shared tools, UCAN capability delegation, and governance voting.

## What this demonstrates

- **Identity**: Admin identity with agent key binding (ADR-039)
- **Governed context**: Encrypted workspace with `single_admin` governance,
  role definitions, capability ceiling, and TTL
- **Roles**: Admin, Moderator, Member, Observer -- each with a scoped
  capability set enforced via UCAN tokens
- **Tools**: Registration, verification (test vectors), and capability-gated
  invocation via scoped UCAN tokens
- **Governance**: Proposal lifecycle (`proposeGovernanceAction`,
  `approveGovernanceProposal`, `rejectGovernanceProposal`), immediate
  execution under single-admin, and multi-admin voting
- **UCAN delegation**: Minting role-scoped tokens, delegating subsets to
  other participants, and validating tokens before tool invocation
- **Trust evaluation**: Querying behavioral records from the event log
- **Event log**: Querying events, Merkle checkpoints, and inclusion proofs

## Roles

| Role | Capabilities |
|------|-------------|
| Admin | Full ceiling -- read, write, invite, remove, tool register/invoke, governance propose/vote |
| Moderator | Read, write, invite, tool invoke, governance propose/vote |
| Member | Read, write, tool invoke |
| Observer | Read only |

Roles are defined in `ContextParams.roles` at context creation and enforced
through UCAN tokens minted per participant. Each participant receives a token
whose capability set matches their role. Tool invocation requires presenting
a valid UCAN token with the `tool:invoke:{toolId}` capability.

## Governance

The template uses `single_admin` governance where the admin's proposals
execute immediately. To demonstrate multi-party voting:

1. Change `governance` in `contextParams` to `"threshold"`, `"majority"`,
   or `"unanimity"`
2. Use `ctx.proposeGovernanceAction(actionJson)` to submit proposals
3. Other admins call `ctx.approveGovernanceProposal(proposalIdHex)` or
   `ctx.rejectGovernanceProposal(proposalIdHex)` to vote
4. When quorum is reached, the action auto-executes

Governance actions include: `AddMember`, `RemoveMember`, `ChangeRole`,
`RegisterTool`, `RemoveTool`, `ModifyCeiling`, `CloseContext`, `ExtendTtl`,
`TransferAdmin`, `CreateChildContext`, `BlockAuthor`, `RevokeReadAccess`,
and more (28 total per ADR-031).

## How to customize

**Change the governance model**: Set `governance` to `"threshold"`,
`"majority"`, or `"unanimity"` in `contextParams`.

**Add custom roles**: Extend `WORKSPACE_ROLES` and `ROLE_CAPABILITIES`
(in `participant.ts`) with custom capability sets.

**Register different tools**: Use `defineToolDefinition()` with your own
schemas and pass to `ctx.registerTool()`.

**Add economic policy**: Set `economicPolicy` in `contextParams` with a
JSON string conforming to the `EconomicPolicy` schema (spec section 19).

**Switch to broadcast mode**: Set `mode: "Broadcast"` in `contextParams`
for one-to-many publishing instead of encrypted group messaging.

## Running

```
bun install
bun run start
```

## File structure

```
src/
  index.ts        -- Main workspace workflow
  participant.ts  -- Participant lifecycle helpers (add, remove, role change)
```
