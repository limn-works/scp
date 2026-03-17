[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / TestVector

# Interface: TestVector

Defined in: [src/types.ts:267](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L267)

A test vector for tool verification.

## Properties

### description

> `readonly` **description**: `string`

Defined in: [src/types.ts:273](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L273)

Human-readable description of what this test vector verifies.

***

### expectedOutput

> `readonly` **expectedOutput**: `Readonly`\<`Record`\<`string`, `unknown`\>\>

Defined in: [src/types.ts:271](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L271)

Expected output as a JSON object.

***

### input

> `readonly` **input**: `Readonly`\<`Record`\<`string`, `unknown`\>\>

Defined in: [src/types.ts:269](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L269)

Test input as a JSON object.
