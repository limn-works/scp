[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / connectLocalTransport

# Function: connectLocalTransport()

> **connectLocalTransport**(`relayUrl`): `Promise`\<`void`\>

Defined in: [src/server.ts:276](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/server.ts#L276)

Connects the SDK transport layer to a local relay.

Unlike [Transport.connect](../classes/Transport.md#connect), this function accepts plaintext `ws://`
URLs because local relays (started via [Relay.startInMemory](../classes/Relay.md#startinmemory) or
[Node.startInMemory](../classes/Node.md#startinmemory)) bind to `127.0.0.1` without TLS.

## Parameters

### relayUrl

`string`

The WebSocket URL of the relay (e.g. `ws://127.0.0.1:PORT/scp/v1`).

## Returns

`Promise`\<`void`\>
