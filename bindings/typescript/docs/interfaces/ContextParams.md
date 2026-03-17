[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / ContextParams

# Interface: ContextParams

Defined in: [src/types.ts:15](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L15)

Parameters for creating a new SCP context.

## Properties

### ceiling

> `readonly` **ceiling**: readonly `string`[]

Defined in: [src/types.ts:17](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L17)

Capability ceiling — maximum capabilities available in this context.

***

### ceilingPolicy?

> `readonly` `optional` **ceilingPolicy**: `"immutable"` \| `"governed"`

Defined in: [src/types.ts:31](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L31)

Ceiling policy: immutable or governed.

***

### economicPolicy?

> `readonly` `optional` **economicPolicy**: `string`

Defined in: [src/types.ts:35](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L35)

Economic policy for the context.

***

### governance?

> `readonly` `optional` **governance**: `"single_admin"` \| `"threshold"` \| `"majority"` \| `"unanimity"`

Defined in: [src/types.ts:27](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L27)

Governance model for the context.

***

### memoryScope?

> `readonly` `optional` **memoryScope**: `"ephemeral"` \| `"summary"` \| `"full"`

Defined in: [src/types.ts:25](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L25)

Memory scope for context data retention.

***

### minProtocolVersion?

> `readonly` `optional` **minProtocolVersion**: readonly \[`number`, `number`\]

Defined in: [src/types.ts:41](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L41)

Minimum protocol version required to join (spec §13.4).
Encoded as `[major, minor]`, e.g., `[1, 0]` for SCP/1.0.
Omit for default SCP/1.0 baseline.

***

### mode?

> `readonly` `optional` **mode**: `"Encrypted"` \| `"Broadcast"`

Defined in: [src/types.ts:29](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L29)

Context mode: encrypted MLS group or broadcast.

***

### promotionPolicy?

> `readonly` `optional` **promotionPolicy**: `"no_promotion"` \| `"promotable"`

Defined in: [src/types.ts:33](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L33)

Promotion policy for TTL-bound contexts.

***

### roles?

> `readonly` `optional` **roles**: `Readonly`\<`Record`\<`string`, readonly `string`[]\>\>

Defined in: [src/types.ts:21](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L21)

Role definitions: role name to capability list mapping.

***

### tools?

> `readonly` `optional` **tools**: readonly [`ToolDefinition`](ToolDefinition.md)[]

Defined in: [src/types.ts:19](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L19)

Tool definitions to register at context creation.

***

### ttl?

> `readonly` `optional` **ttl**: `number`

Defined in: [src/types.ts:23](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/types.ts#L23)

Time-to-live in seconds. Omit for persistent contexts.
