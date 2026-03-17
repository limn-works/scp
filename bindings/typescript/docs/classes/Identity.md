[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / Identity

# Class: Identity

Defined in: [src/identity.ts:41](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/identity.ts#L41)

An SCP identity backed by a DID.

Identity objects are created via the static factory methods `create()` and
`load()`. They hold an opaque bridge handle that retains the key material
(for in-memory custody) or a reference to the platform key store.

# Usage

```typescript
const identity = await Identity.create({ custody: "in_memory" });
console.log(identity.did); // "did:dht:z6Mk..."
```

## Properties

### custodyType

> `readonly` **custodyType**: `string`

Defined in: [src/identity.ts:46](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/identity.ts#L46)

The custody type used at identity creation.

***

### did

> `readonly` **did**: `string`

Defined in: [src/identity.ts:43](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/identity.ts#L43)

The DID string for this identity (e.g., `"did:dht:z6Mk..."`).

## Methods

### addAgentKey()

> **addAgentKey**(): `Promise`\<`Identity`\>

Defined in: [src/identity.ts:167](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/identity.ts#L167)

Adds an agent signing key to this identity (ADR-039).

#### Returns

`Promise`\<`Identity`\>

A new `Identity` with the agent key added.

#### Throws

If this identity already has an agent key.

***

### attestDevice()

> **attestDevice**(): `Promise`\<`string`\>

Defined in: [src/identity.ts:234](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/identity.ts#L234)

Generates a device attestation token for this identity.

#### Returns

`Promise`\<`string`\>

The attestation token as a base64-encoded string.

#### Throws

If attestation generation fails.

***

### executeCustodyMigration()

> **executeCustodyMigration**(`target`, `contextIds?`): `Promise`\<`Record`\<`string`, `unknown`\>\>

Defined in: [src/identity.ts:292](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/identity.ts#L292)

Executes the custody migration protocol for this identity.

Runs the 5-step migration protocol from spec section 3.2.1.

#### Parameters

##### target

Target custody type: `"platform_managed"`, `"hardware"`, `"software"`, or `"in_memory"`.

`"in_memory"` | `"software"` | `"platform_managed"` | `"hardware"`

##### contextIds?

`string`[] = `[]`

Context IDs where this DID is a member.

#### Returns

`Promise`\<`Record`\<`string`, `unknown`\>\>

The migration result as a parsed object.

#### Throws

If migration fails.

***

### executeRecovery()

> **executeRecovery**(`tier`, `contextIds?`): `Promise`\<`Record`\<`string`, `unknown`\>\>

Defined in: [src/identity.ts:269](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/identity.ts#L269)

Executes the compromise recovery protocol for this identity.

Runs the 6-step recovery protocol from spec section 9.12.

#### Parameters

##### tier

Compromise tier: `"agent"`, `"active_signing"`, or `"identity_key"`.

`"agent"` | `"active_signing"` | `"identity_key"`

##### contextIds?

`string`[] = `[]`

Context IDs where this DID is a member.

#### Returns

`Promise`\<`Record`\<`string`, `unknown`\>\>

The recovery result as a parsed object.

#### Throws

If recovery fails.

***

### migrate()

> **migrate**(): `Promise`\<`Identity`\>

Defined in: [src/identity.ts:218](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/identity.ts#L218)

Migrates this identity to a new DID (Layer 2 rotation).

Creates a new DID using the pre-rotation key. The old DID document
is updated with an `alsoKnownAs` pointing to the new DID.

#### Returns

`Promise`\<`Identity`\>

A new `Identity` with the new DID.

#### Throws

If migration fails.

***

### removeAgentKey()

> **removeAgentKey**(): `Promise`\<`Identity`\>

Defined in: [src/identity.ts:199](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/identity.ts#L199)

Removes the agent signing key from this identity (ADR-039).

#### Returns

`Promise`\<`Identity`\>

A new `Identity` with the agent key removed.

#### Throws

If this identity has no agent key.

***

### rotateAgentKey()

> **rotateAgentKey**(): `Promise`\<`Identity`\>

Defined in: [src/identity.ts:183](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/identity.ts#L183)

Rotates the agent signing key for this identity (ADR-039).

#### Returns

`Promise`\<`Identity`\>

A new `Identity` with the rotated agent key.

#### Throws

If this identity has no agent key.

***

### rotateKey()

> **rotateKey**(): `Promise`\<`Identity`\>

Defined in: [src/identity.ts:129](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/identity.ts#L129)

Rotates the active signing key for this identity.

Generates a new Active Signing Key, updates the DID document, and
returns an updated identity with the same DID but a new key.

#### Returns

`Promise`\<`Identity`\>

A new `Identity` instance with the rotated key.

#### Throws

If key rotation fails.

***

### verifyDeviceAttestation()

> **verifyDeviceAttestation**(`tokenBase64`): `Promise`\<`boolean`\>

Defined in: [src/identity.ts:250](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/identity.ts#L250)

Verifies a device attestation token.

#### Parameters

##### tokenBase64

`string`

The base64-encoded attestation token.

#### Returns

`Promise`\<`boolean`\>

`true` if valid, `false` otherwise.

#### Throws

If verification fails.

***

### create()

> `static` **create**(`options?`): `Promise`\<`Identity`\>

Defined in: [src/identity.ts:70](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/identity.ts#L70)

Creates a new DID identity with the specified custody method.

For `"in_memory"` custody, key material is stored in heap memory. This is
suitable for testing and CLI usage but NOT for production on devices with
HSM capability. Use `"platform"` custody on iOS/Android.

#### Parameters

##### options?

Identity creation options.

###### custody?

[`CustodyType`](../type-aliases/CustodyType.md)

The custody method. Defaults to `"platform"`.

#### Returns

`Promise`\<`Identity`\>

A new `Identity` instance.

#### Throws

If identity creation fails.

#### Throws

If the custody type is not recognized.

***

### createWithAgentKey()

> `static` **createWithAgentKey**(`options?`): `Promise`\<`Identity`\>

Defined in: [src/identity.ts:150](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/identity.ts#L150)

Creates a new identity with an agent signing key (ADR-039).

Creates a DID identity with both the standard signing key and an
`#agent` verification method in the DID document.

#### Parameters

##### options?

Creation options.

###### custody?

[`CustodyType`](../type-aliases/CustodyType.md)

The custody method. Defaults to `"platform"`.

#### Returns

`Promise`\<`Identity`\>

A new `Identity` with an agent key.

#### Throws

If creation fails.

***

### load()

> `static` **load**(`did`): `Promise`\<`Identity`\>

Defined in: [src/identity.ts:92](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/identity.ts#L92)

Loads an existing identity from a DID string.

Validates the DID format and returns an identity handle. Key operations
require a wired `KeyCustodyProvider` callback for platform/software
custody types.

#### Parameters

##### did

`string`

The DID string to load (e.g., `"did:dht:z6Mk..."`).

#### Returns

`Promise`\<`Identity`\>

The loaded `Identity` instance.

#### Throws

If the DID format is invalid or loading fails.

***

### resolve()

> `static` **resolve**(`did`): `Promise`\<[`DIDDocument`](../interfaces/DIDDocument.md)\>

Defined in: [src/identity.ts:111](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/identity.ts#L111)

Resolves a DID to its DID Document.

Queries the DHT for the DID document. Requires network connectivity.

#### Parameters

##### did

`string`

The DID string to resolve.

#### Returns

`Promise`\<[`DIDDocument`](../interfaces/DIDDocument.md)\>

The resolved DID document.

#### Throws

If the DID cannot be resolved.
