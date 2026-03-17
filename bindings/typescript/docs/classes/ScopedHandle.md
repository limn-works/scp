[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / ScopedHandle

# Class: ScopedHandle

Defined in: [src/context.ts:1333](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L1333)

Capability-restricted context handle (spec §8.4.2).

Wraps a `Context` with a whitelist of allowed capabilities. All protocol
operations must check the whitelist before proceeding. An app cannot access
protocol operations beyond its declared capabilities.

Once created, a `ScopedHandle` cannot gain additional capabilities
(no escalation guarantee, spec 8.4.2 rule 4).

## Constructors

### Constructor

> **new ScopedHandle**(`context`, `grantedCapabilities`, `appDid`): `ScopedHandle`

Defined in: [src/context.ts:1338](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L1338)

#### Parameters

##### context

[`Context`](Context.md)

##### grantedCapabilities

readonly `string`[]

##### appDid

`string`

#### Returns

`ScopedHandle`

## Properties

### appDid

> `readonly` **appDid**: `string`

Defined in: [src/context.ts:1336](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L1336)

***

### context

> `readonly` **context**: [`Context`](Context.md)

Defined in: [src/context.ts:1334](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L1334)

***

### grantedCapabilities

> `readonly` **grantedCapabilities**: readonly `string`[]

Defined in: [src/context.ts:1335](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L1335)

## Methods

### checkCapability()

> **checkCapability**(`capability`): `void`

Defined in: [src/context.ts:1352](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L1352)

Throws `ContextError` if the capability is not granted.

#### Parameters

##### capability

`string`

#### Returns

`void`

***

### hasCapability()

> **hasCapability**(`capability`): `boolean`

Defined in: [src/context.ts:1346](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L1346)

Check whether a given capability is allowed.

#### Parameters

##### capability

`string`

#### Returns

`boolean`
