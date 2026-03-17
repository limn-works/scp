[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / ObservableMetrics

# Interface: ObservableMetrics

Defined in: [src/economy.ts:29](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/economy.ts#L29)

Observable metrics for cost estimation and formula evaluation.

## Properties

### contextMessageRate?

> `readonly` `optional` **contextMessageRate**: `number`

Defined in: [src/economy.ts:31](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/economy.ts#L31)

Messages per minute in this context.

***

### memberCount?

> `readonly` `optional` **memberCount**: `number`

Defined in: [src/economy.ts:33](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/economy.ts#L33)

Current member count.

***

### relayQueueDepth?

> `readonly` `optional` **relayQueueDepth**: `number`

Defined in: [src/economy.ts:35](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/economy.ts#L35)

Relay-level queue depth.

***

### senderVelocity?

> `readonly` `optional` **senderVelocity**: `number`

Defined in: [src/economy.ts:39](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/economy.ts#L39)

Sender's messages in sliding window.

***

### storageUsage?

> `readonly` `optional` **storageUsage**: `number`

Defined in: [src/economy.ts:41](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/economy.ts#L41)

Context storage usage in bytes.

***

### timeOfDay?

> `readonly` `optional` **timeOfDay**: `number`

Defined in: [src/economy.ts:37](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/economy.ts#L37)

UTC hour (0-23).
