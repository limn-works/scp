[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / bridgeRegister

# Function: bridgeRegister()

> **bridgeRegister**(`contextId`, `operatorDid`, `governanceDid`, `platform`, `mode`): `Promise`\<[`BridgeRegistration`](../interfaces/BridgeRegistration.md)\>

Defined in: [src/bridge.ts:61](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/bridge.ts#L61)

Registers a bridge connector with a context.

## Parameters

### contextId

`string`

Context to register the bridge in.

### operatorDid

`string`

DID of the human operator.

### governanceDid

`string`

DID of the governance authority approving the
  registration.  Must differ from `operatorDid` (self-approval is
  forbidden per ADR-023).

### platform

`string`

External platform name (e.g., `"discord"`).

### mode

[`BridgeMode`](../type-aliases/BridgeMode.md)

Bridge mode: `"relay"`, `"puppet"`, `"api"`, or `"cooperative"`.

## Returns

`Promise`\<[`BridgeRegistration`](../interfaces/BridgeRegistration.md)\>

The bridge registration result.

## Throws

If mode is not recognized.

## Throws

If governance DID matches operator DID (self-approval).
