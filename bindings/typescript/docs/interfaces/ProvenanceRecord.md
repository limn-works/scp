[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / ProvenanceRecord

# Interface: ProvenanceRecord

Defined in: [src/provenance.ts:33](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/provenance.ts#L33)

Provenance record returned by [provenanceAttach](../functions/provenanceAttach.md).

## Properties

### ageSecs

> `readonly` **ageSecs**: `number`

Defined in: [src/provenance.ts:38](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/provenance.ts#L38)

***

### chainDepth

> `readonly` **chainDepth**: `number`

Defined in: [src/provenance.ts:36](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/provenance.ts#L36)

***

### chainPath

> `readonly` **chainPath**: readonly `string`[] \| `null`

Defined in: [src/provenance.ts:40](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/provenance.ts#L40)

***

### counterparties

> `readonly` **counterparties**: readonly `string`[]

Defined in: [src/provenance.ts:37](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/provenance.ts#L37)

***

### discoveryMethod

> `readonly` **discoveryMethod**: [`DiscoveryMethod`](../type-aliases/DiscoveryMethod.md)

Defined in: [src/provenance.ts:43](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/provenance.ts#L43)

How the data source was discovered (§24.2.3).

***

### memoryScope

> `readonly` **memoryScope**: `string`

Defined in: [src/provenance.ts:39](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/provenance.ts#L39)

***

### paymentAdapter

> `readonly` **paymentAdapter**: `string` \| `null`

Defined in: [src/provenance.ts:47](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/provenance.ts#L47)

Payment adapter used (e.g., `"lightning"`, `"stripe"`), if any.

***

### paymentAmount

> `readonly` **paymentAmount**: `number` \| `null`

Defined in: [src/provenance.ts:45](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/provenance.ts#L45)

Cost of producing this data in atomic units, if any (§24.3.4, §19.6).

***

### paymentReceiptId

> `readonly` **paymentReceiptId**: `string` \| `null`

Defined in: [src/provenance.ts:49](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/provenance.ts#L49)

Hex-encoded 32-byte receipt ID for payment verification, if any.

***

### purpose

> `readonly` **purpose**: `string` \| `null`

Defined in: [src/provenance.ts:41](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/provenance.ts#L41)

***

### sourceContext

> `readonly` **sourceContext**: `string`

Defined in: [src/provenance.ts:34](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/provenance.ts#L34)

***

### sourceType

> `readonly` **sourceType**: `string`

Defined in: [src/provenance.ts:35](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/provenance.ts#L35)
