[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / DiscoveryResult

# Interface: DiscoveryResult

Defined in: [src/discovery.ts:33](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/discovery.ts#L33)

A context discovery result.

Includes `trustLevel` and `resolutionPath` per §22.2.1 `AddressResolution`.

## Properties

### contextId

> `readonly` **contextId**: `string`

Defined in: [src/discovery.ts:34](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/discovery.ts#L34)

***

### discoverySource

> `readonly` **discoverySource**: `string`

Defined in: [src/discovery.ts:37](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/discovery.ts#L37)

***

### metadataSummary

> `readonly` **metadataSummary**: `string` \| `null`

Defined in: [src/discovery.ts:39](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/discovery.ts#L39)

***

### mode

> `readonly` **mode**: `string` \| `null`

Defined in: [src/discovery.ts:38](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/discovery.ts#L38)

***

### publisherDid

> `readonly` **publisherDid**: `string`

Defined in: [src/discovery.ts:36](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/discovery.ts#L36)

***

### relayUrls

> `readonly` **relayUrls**: readonly `string`[]

Defined in: [src/discovery.ts:35](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/discovery.ts#L35)

***

### resolutionPath

> `readonly` **resolutionPath**: [`ResolutionPath`](ResolutionPath.md)

Defined in: [src/discovery.ts:43](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/discovery.ts#L43)

Resolution path recording which layer produced this result (§22.7).

***

### trustLevel

> `readonly` **trustLevel**: [`TrustLevel`](../type-aliases/TrustLevel.md)

Defined in: [src/discovery.ts:41](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/discovery.ts#L41)

Trust level of this discovery result (§22.7).
