[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / validateAgainstTemplate

# Function: validateAgainstTemplate()

> **validateAgainstTemplate**(`params`): `string` \| `null`

Defined in: [src/context.ts:1565](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L1565)

Validates that ContextParams match their template definition.

When `params` contains a `template_id`, every field is compared
against the canonical template definition.

## Parameters

### params

[`ContextParams`](../interfaces/ContextParams.md)

ContextParams to validate.

## Returns

`string` \| `null`

`null` on success, or a string error message on failure.
