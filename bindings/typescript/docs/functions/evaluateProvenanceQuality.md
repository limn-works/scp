[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / evaluateProvenanceQuality

# Function: evaluateProvenanceQuality()

> **evaluateProvenanceQuality**(`options`): `Promise`\<`number`\>

Defined in: [src/provenance.ts:63](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/provenance.ts#L63)

Evaluates the provenance quality tier for a data provenance record.

## Parameters

### options

Evaluation parameters.

#### contextState?

`string`

#### counterparties?

`string`[]

#### sourceContext?

`string`

#### sourceType?

`string`

## Returns

`Promise`\<`number`\>

Quality tier as an integer (0-3).

## Throws

If sourceType or contextState is invalid.
