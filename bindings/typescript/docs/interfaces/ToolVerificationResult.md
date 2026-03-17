[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / ToolVerificationResult

# Interface: ToolVerificationResult

Defined in: [src/types.ts:281](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L281)

Result of verifying a tool against its test vectors.

## Properties

### failures

> `readonly` **failures**: readonly `string`[]

Defined in: [src/types.ts:287](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L287)

Failure messages for vectors that did not pass. Empty on success.

***

### passed

> `readonly` **passed**: `boolean`

Defined in: [src/types.ts:285](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L285)

`true` if all test vectors passed.

***

### toolId

> `readonly` **toolId**: `string`

Defined in: [src/types.ts:283](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L283)

The verified tool's ID.
