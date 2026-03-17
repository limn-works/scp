[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / restoreAllContexts

# Function: restoreAllContexts()

> **restoreAllContexts**(): `Promise`\<`string`\>

Defined in: [src/context.ts:1302](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L1302)

Restores all persisted contexts from storage.

Only contexts in `Active` state are restored. Contexts in `Closing`,
`Closed`, or `Expired` states are skipped.

## Returns

`Promise`\<`string`\>

JSON array of restored context ID strings.

## Throws

If restoration fails (SCP-CTX-2065).
