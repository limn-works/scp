[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / validateCapabilityDeclaration

# Function: validateCapabilityDeclaration()

> **validateCapabilityDeclaration**(`declarationJson`, `ceilingCapabilities`, `roleCapabilities`): [`DeclarationValidationResult`](../interfaces/DeclarationValidationResult.md)

Defined in: [src/context.ts:1368](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L1368)

Validates a capability declaration against a context ceiling and role capabilities.

Returns a result object with validation outcome. See spec §8.4.1.
This is a synchronous operation -- no I/O is involved.

## Parameters

### declarationJson

`string`

### ceilingCapabilities

`string`[]

### roleCapabilities

`string`[]

## Returns

[`DeclarationValidationResult`](../interfaces/DeclarationValidationResult.md)
