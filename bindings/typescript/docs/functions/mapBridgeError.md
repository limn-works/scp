[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / mapBridgeError

# Function: mapBridgeError()

> **mapBridgeError**(`error`): [`ScpError`](../classes/ScpError.md)

Defined in: [src/errors.ts:185](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/errors.ts#L185)

Parses a bridge error message and constructs the appropriate `ScpError`
subclass.

Bridge errors follow the format `"[SCP-CATEGORY-NUMBER] description"`.
If the error message does not match any known prefix, a generic `ScpError`
is returned.

## Parameters

### error

`unknown`

The raw error from the bridge layer (Error, string, or unknown).

## Returns

[`ScpError`](../classes/ScpError.md)

A typed `ScpError` subclass instance.
