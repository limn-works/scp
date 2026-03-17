[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / AddressResolution

# Type Alias: AddressResolution

> **AddressResolution** = \{ `did`: `string`; `resolutionPath`: [`ResolutionPath`](../interfaces/ResolutionPath.md); `trustLevel`: [`TrustLevel`](TrustLevel.md); `type`: `"Identity"`; \} \| \{ `contextId`: `string`; `mode`: `string` \| `null`; `relayUrls`: readonly `string`[]; `resolutionPath`: [`ResolutionPath`](../interfaces/ResolutionPath.md); `trustLevel`: [`TrustLevel`](TrustLevel.md); `type`: `"Context"`; \}

Defined in: [src/types.ts:632](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L632)

A single resolution result from the addressing layer.

An address may resolve to an identity (DID) or a context (context ID +
relay URLs). Each result carries a trust level and the resolution path
that produced it.

See §22.2.1 Address Types.

## Type Declaration

\{ `did`: `string`; `resolutionPath`: [`ResolutionPath`](../interfaces/ResolutionPath.md); `trustLevel`: [`TrustLevel`](TrustLevel.md); `type`: `"Identity"`; \}

### did

> `readonly` **did**: `string`

The resolved DID.

### resolutionPath

> `readonly` **resolutionPath**: [`ResolutionPath`](../interfaces/ResolutionPath.md)

How this resolution was produced.

### trustLevel

> `readonly` **trustLevel**: [`TrustLevel`](TrustLevel.md)

Trust level of this resolution.

### type

> `readonly` **type**: `"Identity"`

Discriminant for identity resolution.

\{ `contextId`: `string`; `mode`: `string` \| `null`; `relayUrls`: readonly `string`[]; `resolutionPath`: [`ResolutionPath`](../interfaces/ResolutionPath.md); `trustLevel`: [`TrustLevel`](TrustLevel.md); `type`: `"Context"`; \}

### contextId

> `readonly` **contextId**: `string`

The context ID (hex-encoded).

### mode

> `readonly` **mode**: `string` \| `null`

The context mode, if known.

### relayUrls

> `readonly` **relayUrls**: readonly `string`[]

Relay URLs for reaching this context.

### resolutionPath

> `readonly` **resolutionPath**: [`ResolutionPath`](../interfaces/ResolutionPath.md)

How this resolution was produced.

### trustLevel

> `readonly` **trustLevel**: [`TrustLevel`](TrustLevel.md)

Trust level of this resolution.

### type

> `readonly` **type**: `"Context"`

Discriminant for context resolution.
