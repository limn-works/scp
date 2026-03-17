[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / BehavioralRecord

# Interface: BehavioralRecord

Defined in: [src/types.ts:445](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L445)

Behavioral record computed from a context event log.

## Properties

### governanceActionsAgainst

> `readonly` **governanceActionsAgainst**: `number`

Defined in: [src/types.ts:455](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L455)

Governance actions targeting this participant.

***

### governanceActionsBy

> `readonly` **governanceActionsBy**: `number`

Defined in: [src/types.ts:453](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L453)

Governance actions initiated by this participant.

***

### participationCount

> `readonly` **participationCount**: `number`

Defined in: [src/types.ts:447](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L447)

Number of messages sent or actions taken.

***

### participationDurationSeconds

> `readonly` **participationDurationSeconds**: `number`

Defined in: [src/types.ts:449](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L449)

Duration of participation in seconds.

***

### toolInvocations

> `readonly` **toolInvocations**: `Readonly`\<`Record`\<`string`, `number`\>\>

Defined in: [src/types.ts:451](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L451)

Tool invocations keyed by tool ID.
