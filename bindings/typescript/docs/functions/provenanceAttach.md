[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / provenanceAttach

# Function: provenanceAttach()

> **provenanceAttach**(`sourceContextId`, `sourceType`, `memoryScope`, `members`, `targetContextId`, `actorDid`, `options?`): `Promise`\<[`ProvenanceRecord`](../interfaces/ProvenanceRecord.md)\>

Defined in: [src/provenance.ts:100](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/provenance.ts#L100)

Attaches provenance metadata when data crosses a context boundary.

## Parameters

### sourceContextId

`string`

ID of the source context.

### sourceType

`string`

`"persistent"`, `"ephemeral"`, or `"summary"`.

### memoryScope

`string`

`"full"`, `"summary"`, or `"ephemeral"`.

### members

`string`[]

Member DID strings from the source context.

### targetContextId

`string`

ID of the target context.

### actorDid

`string`

### options?

Optional additional provenance fields.

#### counterpartyPolicy?

`string`

`"full"`, `"pseudonymized"`, or `"redacted"`.

#### discoveryMethod?

`string`

How the source was discovered: `"OutOfBand"`,
  `"none"` (backward-compatible), `"shared_context:<context_id>"`, or
  `"registry:<context_id>"`.

#### existingChainDepth?

`number`

Chain depth of existing provenance (if any).

#### purpose?

`string`

Human-readable purpose of the cross-context data flow.

## Returns

`Promise`\<[`ProvenanceRecord`](../interfaces/ProvenanceRecord.md)\>

Parsed provenance record with all 12 spec fields (§24.2.1).

## Throws

If sourceType or memoryScope is invalid.
