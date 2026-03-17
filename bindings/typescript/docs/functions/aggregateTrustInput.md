[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / aggregateTrustInput

# Function: aggregateTrustInput()

> **aggregateTrustInput**(`input`): `Promise`\<[`AggregatedTrustInput`](../interfaces/AggregatedTrustInput.md)\>

Defined in: [src/trust.ts:150](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/trust.ts#L150)

Aggregates all trust engine layers into a single TrustInput for
agent-level evaluation.

Combines participation records, attestation verification, challenge
results, consequence structure, and threshold counts. The returned
object contains verifiable facts -- agents apply their own criteria.

## Parameters

### input

[`AggregationInput`](../interfaces/AggregationInput.md)

The aggregation input parameters.

## Returns

`Promise`\<[`AggregatedTrustInput`](../interfaces/AggregatedTrustInput.md)\>

An `AggregatedTrustInput` with all trust layers.

## Throws

If inputs are malformed or aggregation fails.
