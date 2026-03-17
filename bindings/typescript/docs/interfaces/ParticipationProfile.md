[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / ParticipationProfile

# Interface: ParticipationProfile

Defined in: [src/types.ts:517](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L517)

A context-hosted participation profile attesting to a member's
verifiable participation facts.

Produced by contexts for opted-in members. The profile is signed by a
context-specific Ed25519 key (derived with domain separation) so that
verifiers cannot correlate which contexts share a signer.

See §7.3.2.1.

## Properties

### attestationCount

> `readonly` **attestationCount**: `number`

Defined in: [src/types.ts:533](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L533)

Number of attestation events.

***

### contextCreationCount

> `readonly` **contextCreationCount**: `number`

Defined in: [src/types.ts:529](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L529)

Number of contexts created.

***

### eventLogRoot

> `readonly` **eventLogRoot**: readonly `number`[]

Defined in: [src/types.ts:537](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L537)

Merkle root of the context's event log at profile computation time (32 bytes).

***

### governanceActionsAgainst

> `readonly` **governanceActionsAgainst**: `number`

Defined in: [src/types.ts:523](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L523)

Count of governance actions taken against this identity.

***

### governanceActionsBy

> `readonly` **governanceActionsBy**: `number`

Defined in: [src/types.ts:525](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L525)

Count of governance actions initiated by this identity.

***

### participationDurationSecs

> `readonly` **participationDurationSecs**: `number`

Defined in: [src/types.ts:521](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L521)

Total seconds of context participation.

***

### roleProgressionCount

> `readonly` **roleProgressionCount**: `number`

Defined in: [src/types.ts:531](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L531)

Number of role transitions.

***

### signature

> `readonly` **signature**: readonly `number`[]

Defined in: [src/types.ts:541](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L541)

Ed25519 signature over all fields except this one (64 bytes).

***

### signerPublicKey

> `readonly` **signerPublicKey**: readonly `number`[]

Defined in: [src/types.ts:539](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L539)

Context-specific Ed25519 public key used to sign this profile (32 bytes).

***

### subjectDid

> `readonly` **subjectDid**: `string`

Defined in: [src/types.ts:519](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L519)

DID of the member this profile is about.

***

### toolInvocationCount

> `readonly` **toolInvocationCount**: `number`

Defined in: [src/types.ts:527](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L527)

Total tool invocations across all tool types.

***

### updatedAt

> `readonly` **updatedAt**: `number`

Defined in: [src/types.ts:535](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L535)

Unix timestamp (seconds) of the last update to this profile.
