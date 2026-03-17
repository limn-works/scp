[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / AggregatedTrustInput

# Interface: AggregatedTrustInput

Defined in: [src/trust.ts:125](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/trust.ts#L125)

Aggregated trust input for agent-level evaluation.

Contains verified attestations, participation record, challenge results,
consequence structure, and threshold counts.

## Properties

### challenge\_results

> **challenge\_results**: readonly `Record`\<`string`, `unknown`\>[]

Defined in: [src/trust.ts:131](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/trust.ts#L131)

Challenge-response results (Layer 3).

***

### consequence\_structure

> **consequence\_structure**: readonly `Record`\<`string`, `unknown`\>[]

Defined in: [src/trust.ts:133](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/trust.ts#L133)

Consequence rules (Layer 4).

***

### participation\_record

> **participation\_record**: `Readonly`\<`Record`\<`string`, `unknown`\>\>

Defined in: [src/trust.ts:129](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/trust.ts#L129)

Participation record (Layer 2).

***

### threshold\_counts

> **threshold\_counts**: `Readonly`\<`Record`\<`string`, readonly \[`number`, `number`\]\>\>

Defined in: [src/trust.ts:135](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/trust.ts#L135)

Threshold counts per attestation type: [met, required].

***

### verified\_attestations

> **verified\_attestations**: readonly `Record`\<`string`, `unknown`\>[]

Defined in: [src/trust.ts:127](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/trust.ts#L127)

Verified attestations (Layer 3).
