[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / Transport

# Class: Transport

Defined in: [src/transport.ts:33](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/transport.ts#L33)

Transport connection manager for SCP relay communication.

Manages the WebSocket connection to an SCP relay. Implements
`AsyncDisposable` for automatic cleanup.

```typescript
await using transport = await Transport.connect({ relayUrl: "wss://relay.example.com" });
const status = await transport.status();
console.log(status.connected); // true
```

## Implements

- `AsyncDisposable`

## Methods

### \[asyncDispose\]()

> **\[asyncDispose\]**(): `Promise`\<`void`\>

Defined in: [src/transport.ts:114](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/transport.ts#L114)

Implements `AsyncDisposable` for automatic cleanup.

When used with `await using`, the transport is automatically
disconnected on scope exit.

#### Returns

`Promise`\<`void`\>

#### Implementation of

`AsyncDisposable.[asyncDispose]`

***

### disconnect()

> **disconnect**(): `Promise`\<`void`\>

Defined in: [src/transport.ts:95](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/transport.ts#L95)

Disconnects from the relay.

Closes the active transport connection. The `Transport` instance must
not be used for new operations after this call.

#### Returns

`Promise`\<`void`\>

#### Throws

If the transport is not connected.

***

### status()

> **status**(): `Promise`\<[`TransportStatus`](../interfaces/TransportStatus.md)\>

Defined in: [src/transport.ts:78](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/transport.ts#L78)

Returns the current transport connection status.

#### Returns

`Promise`\<[`TransportStatus`](../interfaces/TransportStatus.md)\>

The connection status including relay URL and latency.

***

### connect()

> `static` **connect**(`config`): `Promise`\<`Transport`\>

Defined in: [src/transport.ts:55](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/transport.ts#L55)

Connects to an SCP relay.

The relay URL must use the `wss://` scheme. Plaintext `ws://` connections
are rejected to prevent credential exposure.

#### Parameters

##### config

[`TransportConfig`](../interfaces/TransportConfig.md)

Transport configuration with the relay URL.

#### Returns

`Promise`\<`Transport`\>

A connected `Transport` instance.

#### Throws

If the relay URL does not use `wss://`.

#### Throws

If the connection fails.
