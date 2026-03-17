[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / evaluateInvitation

# Function: evaluateInvitation()

> **evaluateInvitation**(`paramsJson`, `inviterDid`, `identityDid`, `policyJson?`, `spendingJson?`, `trustedDids?`): `Promise`\<[`InvitationEvaluationResult`](../interfaces/InvitationEvaluationResult.md)\>

Defined in: [src/context.ts:1413](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L1413)

Evaluates a context invitation through the sequential pipeline.

Runs the 4-step evaluation pipeline:
1. **Template check** -- validates params match the claimed template.
2. **Economic policy check** -- verifies spending capability for paid contexts.
3. **Auto-accept check** -- evaluates trust, TTL cap, and rate limit.
4. **Agent prompt** -- falls through if no auto-accept matches.

## Parameters

### paramsJson

`string`

JSON-serialized `ContextParams` from the invitation.

### inviterDid

`string`

DID string of the identity sending the invitation.

### identityDid

`string`

DID string of the local identity receiving the invitation.

### policyJson?

`string`

Optional JSON-serialized `AutoAcceptPolicy`.

### spendingJson?

`string`

Optional JSON-serialized `SpendingContext`.

### trustedDids?

readonly `string`[]

Optional array of trusted DID strings.

## Returns

`Promise`\<[`InvitationEvaluationResult`](../interfaces/InvitationEvaluationResult.md)\>

The evaluation result with the pipeline decision.

## Throws

If pipeline evaluation fails.

## Throws

If input validation fails.
