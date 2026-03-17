[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / RequireParticipation

# Interface: RequireParticipation

Defined in: [src/types.ts:552](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L552)

A participation admission requirement declared by a context.

Contexts include one or more `RequireParticipation` entries in their
`ContextParams` admission requirements. Each entry specifies a
participation fact, a threshold, a freshness requirement, and a minimum
number of independent source contexts. See §7.3.2.1.

## Properties

### fact

> `readonly` **fact**: [`ParticipationFact`](../type-aliases/ParticipationFact.md)

Defined in: [src/types.ts:554](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L554)

Which participation category to evaluate.

***

### maxAgeSecs

> `readonly` **maxAgeSecs**: `number`

Defined in: [src/types.ts:558](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L558)

Maximum age in seconds for the profile's `updatedAt` timestamp.

***

### minContexts

> `readonly` **minContexts**: `number`

Defined in: [src/types.ts:560](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L560)

Minimum number of independent source contexts (distinct signer keys).

***

### threshold

> `readonly` **threshold**: [`ParticipationThreshold`](../type-aliases/ParticipationThreshold.md)

Defined in: [src/types.ts:556](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L556)

Comparison operator and value.
