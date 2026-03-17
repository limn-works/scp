[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / TrustEvaluation

# Interface: TrustEvaluation

Defined in: [src/types.ts:433](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L433)

Trust evaluation input for a participant.

## Properties

### attestations

> `readonly` **attestations**: readonly [`AttestationSummary`](AttestationSummary.md)[]

Defined in: [src/types.ts:441](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L441)

Attestations for the subject.

***

### behavioralRecord

> `readonly` **behavioralRecord**: [`BehavioralRecord`](BehavioralRecord.md)

Defined in: [src/types.ts:439](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L439)

Behavioral record computed from the event log.

***

### contextId

> `readonly` **contextId**: `string`

Defined in: [src/types.ts:437](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L437)

The context ID in which trust is being evaluated.

***

### subjectDid

> `readonly` **subjectDid**: `string`

Defined in: [src/types.ts:435](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L435)

The subject DID being evaluated.
