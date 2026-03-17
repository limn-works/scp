[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / evaluateTrust

# Function: evaluateTrust()

> **evaluateTrust**(`ctx`, `subjectDid`): `Promise`\<[`TrustEvaluation`](../interfaces/TrustEvaluation.md)\>

Defined in: [src/trust.ts:39](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/trust.ts#L39)

Evaluates trust for a participant in a context.

Computes a behavioral record from the context's event log and collects
attestation summaries. The returned `TrustEvaluation` contains verifiable
facts — the calling agent decides what trust level these facts warrant.

## Parameters

### ctx

[`Context`](../classes/Context.md)

The context to evaluate trust in.

### subjectDid

`string`

The DID of the participant to evaluate.

## Returns

`Promise`\<[`TrustEvaluation`](../interfaces/TrustEvaluation.md)\>

A `TrustEvaluation` with behavioral record and attestations.

## Throws

If the context is not active or evaluation fails.
