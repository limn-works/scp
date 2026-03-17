[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / AggregationInput

# Interface: AggregationInput

Defined in: [src/trust.ts:98](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/trust.ts#L98)

Input parameters for trust aggregation.

Contains all the data needed to compute an aggregated `TrustInput`
for a subject DID within a context.

## Properties

### attestorSets?

> `optional` **attestorSets**: `Readonly`\<`Record`\<`string`, `unknown`\>\>

Defined in: [src/trust.ts:112](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/trust.ts#L112)

Attestor information per attestation type.

***

### cachedAttestations?

> `optional` **cachedAttestations**: readonly `Record`\<`string`, `unknown`\>[]

Defined in: [src/trust.ts:114](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/trust.ts#L114)

Cached attestations to pre-populate the trust store.

***

### challengeResults?

> `optional` **challengeResults**: readonly `Record`\<`string`, `unknown`\>[]

Defined in: [src/trust.ts:116](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/trust.ts#L116)

Challenge results to pre-populate the trust store.

***

### consequenceRules?

> `optional` **consequenceRules**: readonly `Record`\<`string`, `unknown`\>[]

Defined in: [src/trust.ts:108](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/trust.ts#L108)

Consequence rules declared at context creation.

***

### contextId

> **contextId**: `string`

Defined in: [src/trust.ts:100](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/trust.ts#L100)

The context to aggregate trust inputs for.

***

### events

> **events**: readonly `Record`\<`string`, `unknown`\>[]

Defined in: [src/trust.ts:104](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/trust.ts#L104)

Event log entries for the context (as plain objects).

***

### merkleRoot

> **merkleRoot**: readonly `number`[]

Defined in: [src/trust.ts:106](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/trust.ts#L106)

32-byte Merkle root as an array of numbers.

***

### subjectDid

> **subjectDid**: `string`

Defined in: [src/trust.ts:102](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/trust.ts#L102)

The DID of the subject to evaluate.

***

### thresholdRequirements?

> `optional` **thresholdRequirements**: `Readonly`\<`Record`\<`string`, `unknown`\>\>

Defined in: [src/trust.ts:110](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/trust.ts#L110)

Threshold requirements per attestation type.
