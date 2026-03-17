[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / validateContextParams

# Function: validateContextParams()

> **validateContextParams**(`params`): `string` \| `null`

Defined in: [src/context.ts:1578](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L1578)

Validates cross-field invariants for ContextParams regardless of template.

Currently enforces: `projection_policy` must be `null` for `Encrypted` contexts.

## Parameters

### params

[`ContextParams`](../interfaces/ContextParams.md)

ContextParams to validate.

## Returns

`string` \| `null`

`null` on success, or a string error message on failure.
