[**@limn-works/scp-ts v0.1.0**](../README.md)

***

[@limn-works/scp-ts](../globals.md) / Context

# Class: Context

Defined in: [src/context.ts:118](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L118)

An SCP context — a bounded, encrypted interaction space.

Context objects are created via `Context.create()` and implement
`AsyncDisposable` for automatic cleanup:

```typescript
await using ctx = await Context.create(identity, {
  ceiling: ["messages:read", "messages:write"],
  memoryScope: "ephemeral",
});
await ctx.send("hello");
// ctx.leave() is called automatically on scope exit
```

Messages are received via the `receive()` generator, which returns an
`AsyncIterable<Message>`:

```typescript
for await (const msg of ctx.receive()) {
  console.log(msg.senderDid, msg.content);
}
```

## Implements

- `AsyncDisposable`

## Properties

### contextId

> `readonly` **contextId**: `string`

Defined in: [src/context.ts:120](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L120)

The unique identifier for this context.

## Methods

### \[asyncDispose\]()

> **\[asyncDispose\]**(): `Promise`\<`void`\>

Defined in: [src/context.ts:1255](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L1255)

Implements `AsyncDisposable` for automatic cleanup.

When used with `await using`, the context is automatically left on
scope exit (including exceptions).

#### Returns

`Promise`\<`void`\>

#### Implementation of

`AsyncDisposable.[asyncDispose]`

***

### acceptToolInterface()

> **acceptToolInterface**(`interfaceJson`): `Promise`\<`string`\>

Defined in: [src/context.ts:384](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L384)

Accepts a cross-context tool interface (step 4).

Sets `approved_by_target = true`. Both `approved_by_source` and
`approved_by_target` must be `true` before calls are permitted.

#### Parameters

##### interfaceJson

`string`

The ToolInterface JSON string to accept.

#### Returns

`Promise`\<`string`\>

The updated ToolInterface as a JSON string.

#### Throws

If the caller is not an admin or context mismatch.

***

### addCheckpointCosignature()

> **addCheckpointCosignature**(`checkpointJson`, `signerDid`, `signatureHex`): `Promise`\<`string`\>

Defined in: [src/context.ts:1007](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L1007)

Adds a cosignature to an existing governance checkpoint (ADR-031 section 9).

#### Parameters

##### checkpointJson

`string`

JSON-serialized checkpoint.

##### signerDid

`string`

DID of the cosigner.

##### signatureHex

`string`

Hex-encoded Ed25519 signature.

#### Returns

`Promise`\<`string`\>

JSON string with `attestation_status` and updated `checkpoint`.

#### Throws

If cosignature validation fails (SCP-CTX-2063).

***

### applyPendingCeilingModification()

> **applyPendingCeilingModification**(`currentTimestamp`): `Promise`\<`boolean`\>

Defined in: [src/context.ts:930](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L930)

Applies a pending ceiling modification if the notification period has elapsed.

#### Parameters

##### currentTimestamp

`number`

Current Unix timestamp in seconds.

#### Returns

`Promise`\<`boolean`\>

`true` if the modification was applied, `false` otherwise.

#### Throws

If the operation fails (SCP-CTX-2060).

***

### approveGovernanceProposal()

> **approveGovernanceProposal**(`proposalIdHex`, `voterDid?`): `Promise`\<`string`\>

Defined in: [src/context.ts:828](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L828)

Casts an approval vote on a pending governance proposal.

If the vote pushes the proposal past quorum, the action is auto-executed.

#### Parameters

##### proposalIdHex

`string`

Hex-encoded 32-byte proposal ID.

##### voterDid?

`string`

DID of the voter. Defaults to context identity.

#### Returns

`Promise`\<`string`\>

JSON string with `status`.

#### Throws

If the vote fails.

***

### broadcastAdmission()

> **broadcastAdmission**(): `Promise`\<[`BroadcastAdmissionPolicy`](../type-aliases/BroadcastAdmissionPolicy.md) \| `null`\>

Defined in: [src/context.ts:709](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L709)

Returns the broadcast admission policy for this context.

#### Returns

`Promise`\<[`BroadcastAdmissionPolicy`](../type-aliases/BroadcastAdmissionPolicy.md) \| `null`\>

The policy (`"Open"` or `"Gated"`), or `null` if not broadcast.

#### Throws

If the context has been disposed.

***

### broadcastBlockSubscriber()

> **broadcastBlockSubscriber**(`subscriberDid`, `blockerDid`): `Promise`\<`void`\>

Defined in: [src/context.ts:622](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L622)

Blocks a subscriber's read access in this broadcast context.

#### Parameters

##### subscriberDid

`string`

The DID of the subscriber to block.

##### blockerDid

`string`

The DID of the blocker.

#### Returns

`Promise`\<`void`\>

#### Throws

If the operation fails.

***

### broadcastHandleKeyRequest()

> **broadcastHandleKeyRequest**(`authorDid`, `requesterDid`): `Promise`\<`string`\>

Defined in: [src/context.ts:660](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L660)

Handles a broadcast key request from a subscriber.

#### Parameters

##### authorDid

`string`

The DID of the author handling the request.

##### requesterDid

`string`

The DID of the requester.

#### Returns

`Promise`\<`string`\>

A string describing the key request decision.

#### Throws

If the operation fails.

***

### broadcastIsSubscriber()

> **broadcastIsSubscriber**(`did`): `Promise`\<`boolean`\>

Defined in: [src/context.ts:693](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L693)

Checks whether a DID is a broadcast subscriber.

#### Parameters

##### did

`string`

The DID to check.

#### Returns

`Promise`\<`boolean`\>

`true` if the DID is a subscriber.

#### Throws

If the context has been disposed.

***

### broadcastPublish()

> **broadcastPublish**(`payload`, `authorDid?`): `Promise`\<`void`\>

Defined in: [src/context.ts:528](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L528)

Publishes a message to this broadcast context.

#### Parameters

##### payload

`Uint8Array`

The raw message payload.

##### authorDid?

`string`

The DID of the author publishing the message.
  Defaults to the identity that created/joined the context.

#### Returns

`Promise`\<`void`\>

#### Throws

If the context is not active or not broadcast.

***

### broadcastPublishAsset()

> **broadcastPublishAsset**(`asset`, `authorDid?`, `deployId?`): `Promise`\<[`PublishResult`](../interfaces/PublishResult.md)\>

Defined in: [src/context.ts:551](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L551)

Publishes a single asset to this broadcast context as structured content (SCP-290).

Constructs a BroadcastContent from the asset entry, computes an ETag,
and publishes via the structured content path.

#### Parameters

##### asset

[`AssetEntry`](../interfaces/AssetEntry.md)

The asset entry containing path, contentType, and body.

##### authorDid?

`string`

The DID of the author publishing the asset.
  Defaults to the identity that created/joined the context.

##### deployId?

`string`

Optional deploy ID to group assets into atomic deploys.

#### Returns

`Promise`\<[`PublishResult`](../interfaces/PublishResult.md)\>

A PublishResult with blobId and etag.

#### Throws

If the context is not active or not broadcast.

***

### broadcastPublishAssets()

> **broadcastPublishAssets**(`assets`, `authorDid?`, `deployId?`): `Promise`\<[`BatchPublishResult`](../interfaces/BatchPublishResult.md)\>

Defined in: [src/context.ts:583](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L583)

Publishes multiple assets to this broadcast context as structured content (SCP-290, SCP-292).

All assets are published with the same deployId (auto-generated if not provided).

#### Parameters

##### assets

[`AssetEntry`](../interfaces/AssetEntry.md)[]

The asset entries to publish.

##### authorDid?

`string`

The DID of the author publishing the assets.
  Defaults to the identity that created/joined the context.

##### deployId?

`string`

Optional deploy ID to group assets into atomic deploys.

#### Returns

`Promise`\<[`BatchPublishResult`](../interfaces/BatchPublishResult.md)\>

A BatchPublishResult with per-asset results and the shared deployId.

#### Throws

If any asset fails validation or publish.

***

### broadcastSubscribe()

> **broadcastSubscribe**(`subscriberDid`): `Promise`\<`void`\>

Defined in: [src/context.ts:493](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L493)

Subscribes a DID to this broadcast context.

#### Parameters

##### subscriberDid

`string`

The DID subscribing to broadcasts.

#### Returns

`Promise`\<`void`\>

#### Throws

If the context is not active or not broadcast.

***

### broadcastSubscriberCount()

> **broadcastSubscriberCount**(): `Promise`\<`number` \| `null`\>

Defined in: [src/context.ts:676](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L676)

Returns the number of broadcast subscribers for this context.

#### Returns

`Promise`\<`number` \| `null`\>

The subscriber count, or `null` if not a broadcast context.

#### Throws

If the context has been disposed.

***

### broadcastUnblockSubscriber()

> **broadcastUnblockSubscriber**(`subscriberDid`, `unblockerDid`): `Promise`\<`void`\>

Defined in: [src/context.ts:642](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L642)

Unblocks a previously blocked subscriber in this broadcast context.

Forward-only restoration (section 9.16.8): the unblocked subscriber can request
the current key on next pull but cannot decrypt content from the block period.

#### Parameters

##### subscriberDid

`string`

The DID of the subscriber to unblock.

##### unblockerDid

`string`

The DID of the author performing the unblock.

#### Returns

`Promise`\<`void`\>

#### Throws

If the operation fails.

***

### broadcastUnsubscribe()

> **broadcastUnsubscribe**(`subscriberDid`, `rotateKeys?`): `Promise`\<`void`\>

Defined in: [src/context.ts:510](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L510)

Unsubscribes a DID from this broadcast context.

#### Parameters

##### subscriberDid

`string`

The DID to unsubscribe.

##### rotateKeys?

`boolean` = `false`

When `true`, all authors rotate their broadcast keys.

#### Returns

`Promise`\<`void`\>

#### Throws

If the context is not active or not broadcast.

***

### close()

> **close**(): `Promise`\<`void`\>

Defined in: [src/context.ts:1236](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L1236)

Closes the context.

Terminates the context for all members. Subsequent operations throw
`ContextError`.

#### Returns

`Promise`\<`void`\>

#### Throws

If the context is not `"active"`.

***

### createGovernanceCheckpoint()

> **createGovernanceCheckpoint**(`params`): `Promise`\<`string`\>

Defined in: [src/context.ts:971](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L971)

Creates a governance checkpoint (ADR-031 section 9).

#### Parameters

##### params

Checkpoint parameters.

###### checkpointSeq

`number`

Sequence number in the event log.

###### creatorDid?

`string`

DID of the creator. Defaults to context identity.

###### creatorSignatureHex

`string`

Hex-encoded Ed25519 signature.

###### eventCount

`number`

Number of events included.

###### lastEventHashHex

`string`

Hex-encoded 32-byte hash.

###### merkleRootHex

`string`

Hex-encoded 32-byte Merkle root.

###### stateSnapshotHashHex

`string`

Hex-encoded 32-byte hash.

#### Returns

`Promise`\<`string`\>

JSON string with the `ContextCheckpoint` object.

#### Throws

If checkpoint creation fails (SCP-CTX-2062).

***

### drainEvents()

> **drainEvents**(): `Promise`\<readonly `string`[]\>

Defined in: [src/context.ts:1198](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L1198)

Drains all pending events from this context's receive buffer.

Returns events as an array of JSON strings. This is a non-blocking
alternative to the streaming `receive()` generator for batch processing.

#### Returns

`Promise`\<readonly `string`[]\>

An array of event JSON strings.

#### Throws

If the context has been disposed.

***

### executeGovernanceAction()

> **executeGovernanceAction**(`proposalJson`): `Promise`\<[`GovernanceActionResult`](../type-aliases/GovernanceActionResult.md)\>

Defined in: [src/context.ts:777](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L777)

Executes a governance action on this context.

#### Parameters

##### proposalJson

`string`

JSON-serialized `GovernanceProposal`.

#### Returns

`Promise`\<[`GovernanceActionResult`](../type-aliases/GovernanceActionResult.md)\>

A `GovernanceActionResult` string describing the outcome.

#### Throws

If the context is not active or governance fails.

***

### export()

> **export**(): `Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

Defined in: [src/context.ts:1156](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L1156)

Exports this context's full state as serialized bytes.

Returns serialized `StoredValue<ContextExport>` bytes (spec section 17.5)
suitable for backup, migration, or transfer to another node.

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

The serialized context export as a `Uint8Array`.

#### Throws

If the context has been disposed or export fails.

***

### exposeToolInterface()

> **exposeToolInterface**(`toolId`, `targetContextId`, `rateLimitJson?`): `Promise`\<`string`\>

Defined in: [src/context.ts:360](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L360)

Exposes a tool interface for cross-context sharing (step 1).

The caller (admin of the source context) proposes sharing a specific
tool with a target context. The returned JSON interface has
`approved_by_source = true` and `approved_by_target = false`.

#### Parameters

##### toolId

`string`

The ID of the tool to expose.

##### targetContextId

`string`

The target context to expose the tool to.

##### rateLimitJson?

`string`

Optional per-interface rate limit as a JSON string.

#### Returns

`Promise`\<`string`\>

The ToolInterface as a JSON string.

#### Throws

If the caller is not an admin or the tool is not found.

***

### extendTtl()

> **extendTtl**(`additionalSecs`): `Promise`\<`boolean`\>

Defined in: [src/context.ts:1059](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L1059)

Extends the TTL by the given number of seconds.

#### Parameters

##### additionalSecs

`number`

Number of seconds to add to the TTL. Must be a finite positive number.

#### Returns

`Promise`\<`boolean`\>

`true` if the extension was applied.

#### Throws

If the context has been disposed or extension fails.

#### Throws

If `additionalSecs` is not a finite positive number.

***

### finalizeClose()

> **finalizeClose**(): `Promise`\<`void`\>

Defined in: [src/context.ts:948](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L948)

Finalizes the cooperative close flow for a context in `Closing` state.

Transitions from `Closing` to `Closed`, destroys keys per memory scope,
and records a `ContextClosed` event.

#### Returns

`Promise`\<`void`\>

#### Throws

If the context is not in Closing state (SCP-CTX-2061).

***

### getEconomicPolicy()

> **getEconomicPolicy**(): `Promise`\<`string` \| `null`\>

Defined in: [src/context.ts:756](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L756)

Returns the economic policy for this context as a JSON string.

#### Returns

`Promise`\<`string` \| `null`\>

The economic policy JSON, or `null` if no policy is set.

#### Throws

If the context has been disposed.

***

### getGovernanceProposal()

> **getGovernanceProposal**(`proposalIdHex`): `Promise`\<`string`\>

Defined in: [src/context.ts:893](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L893)

Retrieves a single governance proposal by its hex-encoded ID.

#### Parameters

##### proposalIdHex

`string`

Hex-encoded 32-byte proposal ID.

#### Returns

`Promise`\<`string`\>

JSON string with proposal details.

#### Throws

If the proposal is not found (SCP-CTX-2045).

***

### handleTtlExpiry()

> **handleTtlExpiry**(): `Promise`\<`void`\>

Defined in: [src/context.ts:1081](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L1081)

Handles automatic TTL expiry for this context.

Triggers the TTL expiry lifecycle: transitions the context to expired
state and notifies members. Typically called by a timer or scheduler
when the context's TTL has elapsed.

#### Returns

`Promise`\<`void`\>

#### Throws

If the context is not active (SCP-CTX-2005).

***

### invokeTool()

> **invokeTool**(`toolId`, `input`, `identity`, `ucanToken`): `Promise`\<`unknown`\>

Defined in: [src/context.ts:304](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L304)

Invokes a tool within this context.

#### Parameters

##### toolId

`string`

The ID of the tool to invoke.

##### input

`Readonly`\<`Record`\<`string`, `unknown`\>\>

Tool input parameters.

##### identity

[`Identity`](Identity.md)

The invoking identity.

##### ucanToken

`string`

JWT-encoded UCAN token authorizing the invocation.
  Must contain `tool_invoke:{toolId}` or `tool_invoke:*` capability scoped
  to this context. Required per spec section 7.2: every capability-gated
  action requires a valid UCAN token. See also section 6.2, section 8,
  and ADR-016.

#### Returns

`Promise`\<`unknown`\>

The tool output as a parsed JSON object.

#### Throws

If invocation fails or the tool is not found.

#### Throws

If the UCAN token is invalid, expired,
  revoked, or lacks the required tool invocation capability.

***

### isMember()

> **isMember**(`did`): `Promise`\<`boolean`\>

Defined in: [src/context.ts:440](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L440)

Checks whether a DID is a member of this context.

#### Parameters

##### did

`string`

The DID to check.

#### Returns

`Promise`\<`boolean`\>

`true` if the DID is a member.

#### Throws

If the context has been disposed.

***

### join()

> **join**(`identity`): `Promise`\<`void`\>

Defined in: [src/context.ts:187](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L187)

Joins an existing context.

#### Parameters

##### identity

[`Identity`](Identity.md)

The identity joining the context.

#### Returns

`Promise`\<`void`\>

#### Throws

If the context is not in `"active"` state.

***

### leave()

> **leave**(): `Promise`\<`void`\>

Defined in: [src/context.ts:1215](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L1215)

Leaves the context.

Sends a `MemberLeft` event and releases local resources.

#### Returns

`Promise`\<`void`\>

#### Throws

If the context is not `"active"`.

***

### listGovernanceProposals()

> **listGovernanceProposals**(): `Promise`\<`string`\>

Defined in: [src/context.ts:909](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L909)

Lists all governance proposals for this context.

#### Returns

`Promise`\<`string`\>

JSON array of proposals.

#### Throws

If listing fails (SCP-CTX-2046).

***

### memberCount()

> **memberCount**(): `Promise`\<`number` \| `null`\>

Defined in: [src/context.ts:423](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L423)

Returns the number of members in this context.

#### Returns

`Promise`\<`number` \| `null`\>

The member count, or `null` if the context is not registered.

#### Throws

If the context has been disposed.

***

### memberDids()

> **memberDids**(): `Promise`\<readonly `string`[]\>

Defined in: [src/context.ts:456](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L456)

Returns all member DIDs in this context.

#### Returns

`Promise`\<readonly `string`[]\>

An array of DID strings.

#### Throws

If the context has been disposed.

***

### memberRole()

> **memberRole**(`did`): `Promise`\<[`MemberRole`](../type-aliases/MemberRole.md) \| `null`\>

Defined in: [src/context.ts:473](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L473)

Returns the role of a member in this context.

#### Parameters

##### did

`string`

The DID of the member.

#### Returns

`Promise`\<[`MemberRole`](../type-aliases/MemberRole.md) \| `null`\>

The role as a `MemberRole`, or `null` if the member is not found.

#### Throws

If the context has been disposed.

***

### proposeGovernanceAction()

> **proposeGovernanceAction**(`actionJson`, `proposerDid?`): `Promise`\<`string`\>

Defined in: [src/context.ts:804](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L804)

Proposes a governance action for voting.

For `SingleAdmin` contexts, the proposal is auto-approved and executed
immediately. For multi-admin models (Threshold, Majority, Unanimity),
the proposal enters `Pending` status and must accumulate votes.

#### Parameters

##### actionJson

`string`

JSON-serialized `GovernanceAction`.

##### proposerDid?

`string`

DID of the proposer. Defaults to context identity.

#### Returns

`Promise`\<`string`\>

JSON string with `proposal_id`, `status`, and `execution_result`.

#### Throws

If the context is not active or the proposal fails.

***

### proposeTtlExtension()

> **proposeTtlExtension**(`extensionSecs`, `proposerDid?`): `Promise`\<`boolean`\>

Defined in: [src/context.ts:1103](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L1103)

Proposes a TTL extension for this context.

Records consent from the given member for extending the context's TTL.
Returns `true` if the extension was unanimously approved by all members.

#### Parameters

##### extensionSecs

`number`

Number of seconds to extend the TTL by. Must be a finite positive number.

##### proposerDid?

`string`

DID of the proposer. Defaults to the context identity.

#### Returns

`Promise`\<`boolean`\>

`true` if the extension was unanimously approved.

#### Throws

If the context is not active or the proposal fails (SCP-CTX-2005).

#### Throws

If `extensionSecs` is not a finite positive number.

***

### receive()

> **receive**(): `AsyncIterable`\<[`Message`](../interfaces/Message.md)\>

Defined in: [src/context.ts:230](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L230)

Returns an `AsyncIterable<Message>` that yields incoming messages.

Messages are delivered in sequence order. Calling `break` on the
`for await...of` loop stops delivery and releases internal resources.

Each call to `receive()` returns an independent iterable (fan-out).

```typescript
for await (const msg of ctx.receive()) {
  console.log(msg.senderDid, msg.content);
}
```

#### Returns

`AsyncIterable`\<[`Message`](../interfaces/Message.md)\>

***

### registerTool()

> **registerTool**(`definition`): `Promise`\<`string`\>

Defined in: [src/context.ts:278](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L278)

Registers a tool in this context.

#### Parameters

##### definition

[`ToolDefinition`](../interfaces/ToolDefinition.md)

The tool definition.

#### Returns

`Promise`\<`string`\>

The assigned tool ID.

#### Throws

If registration fails.

***

### rejectGovernanceProposal()

> **rejectGovernanceProposal**(`proposalIdHex`, `voterDid?`): `Promise`\<`string`\>

Defined in: [src/context.ts:850](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L850)

Casts a rejection vote on a pending governance proposal.

#### Parameters

##### proposalIdHex

`string`

Hex-encoded 32-byte proposal ID.

##### voterDid?

`string`

DID of the voter. Defaults to context identity.

#### Returns

`Promise`\<`string`\>

JSON string with `status`.

#### Throws

If the vote fails.

***

### resetTtlTimer()

> **resetTtlTimer**(`newDurationSecs`): `Promise`\<`void`\>

Defined in: [src/context.ts:1130](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L1130)

Resets the TTL timer for this context to a new duration.

Replaces the current TTL countdown with a fresh timer of the specified
duration. Requires a core context handle.

#### Parameters

##### newDurationSecs

`number`

The new TTL duration in seconds. Must be a finite positive number.

#### Returns

`Promise`\<`void`\>

#### Throws

If the context does not have a core handle (SCP-CTX-2024).

#### Throws

If `newDurationSecs` is not a finite positive number.

***

### revokeToolInterface()

> **revokeToolInterface**(`interfaceIdHex`): `Promise`\<`string`\>

Defined in: [src/context.ts:403](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L403)

Revokes a cross-context tool interface (step 5).

Either context may revoke unilaterally.

#### Parameters

##### interfaceIdHex

`string`

The 32-byte interface/offer ID as a hex string.

#### Returns

`Promise`\<`string`\>

The InterfaceRevoked event as a JSON string.

#### Throws

If interfaceIdHex is invalid.

***

### send()

> **send**(`payload`): `Promise`\<`void`\>

Defined in: [src/context.ts:205](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L205)

Sends a message to the context.

Accepts either a string (encoded as UTF-8) or a `Uint8Array` payload.

#### Parameters

##### payload

The message content.

`string` | `Uint8Array`\<`ArrayBufferLike`\>

#### Returns

`Promise`\<`void`\>

#### Throws

If the context is not `"active"` or send fails.

***

### setEconomicPolicy()

> **setEconomicPolicy**(`policyJson`): `Promise`\<`void`\>

Defined in: [src/context.ts:739](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L739)

Sets the economic policy for this context.

Validates the JSON against the `EconomicPolicy` schema before storing.
The policy controls per-tool-invoke costs, per-period budgets, and other
economic governance parameters.

Schema validation is performed at the SDK layer as defense-in-depth:
the NAPI bridge validates via Rust deserialization, but the WASM bridge
can only check JSON syntax (ADR-034 prevents scp-core type imports).

#### Parameters

##### policyJson

`string`

The economic policy as a JSON string conforming to
  the `EconomicPolicy` schema (spec section 19).

#### Returns

`Promise`\<`void`\>

#### Throws

If the context has been disposed.

#### Throws

If the JSON is invalid or missing required fields.

***

### ttlRemaining()

> **ttlRemaining**(): `Promise`\<`number` \| `null`\>

Defined in: [src/context.ts:1041](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L1041)

Returns the configured TTL duration in seconds, or `null` if no TTL is set.

Note: In the WASM bridge, this returns the current TTL value stored on the
context (which increases when extended), not a real-time countdown. The
native (NAPI) bridge does not support this operation.

#### Returns

`Promise`\<`number` \| `null`\>

The configured TTL duration in seconds, or `null` for persistent contexts.

#### Throws

If the context has been disposed.

#### Throws

If using the native (NAPI) bridge, which does not support this operation.

***

### verifyTool()

> **verifyTool**(`toolId`): `Promise`\<[`ToolVerificationResult`](../interfaces/ToolVerificationResult.md)\>

Defined in: [src/context.ts:333](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L333)

Verifies a tool against its registered test vectors.

#### Parameters

##### toolId

`string`

The ID of the tool to verify.

#### Returns

`Promise`\<[`ToolVerificationResult`](../interfaces/ToolVerificationResult.md)\>

The verification result.

#### Throws

If verification fails.

***

### withdrawGovernanceVote()

> **withdrawGovernanceVote**(`proposalIdHex`, `voterDid?`): `Promise`\<`string`\>

Defined in: [src/context.ts:872](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L872)

Withdraws a previously cast vote on a pending governance proposal.

#### Parameters

##### proposalIdHex

`string`

Hex-encoded 32-byte proposal ID.

##### voterDid?

`string`

DID of the voter. Defaults to context identity.

#### Returns

`Promise`\<`string`\>

JSON string with `status`.

#### Throws

If the withdrawal fails.

***

### create()

> `static` **create**(`identity`, `params`): `Promise`\<`Context`\>

Defined in: [src/context.ts:158](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L158)

Creates a new SCP context.

The context is created in the `"active"` state. The creating identity
becomes the first member (and admin under `"single_admin"` governance).

#### Parameters

##### identity

[`Identity`](Identity.md)

The identity creating the context.

##### params

[`ContextParams`](../interfaces/ContextParams.md)

Context creation parameters.

#### Returns

`Promise`\<`Context`\>

A new `Context` instance in the `"active"` state.

#### Throws

If context creation fails.

#### Throws

If parameters are invalid.

***

### import()

> `static` **import**(`data`): `Promise`\<`string`\>

Defined in: [src/context.ts:1176](https://github.com/limn-works/scp/blob/7dbbc712ceb760d185db880a3249c4e0ce8b24ed/bindings/typescript/src/context.ts#L1176)

Imports a context from serialized bytes.

The bytes must be a `StoredValue<ContextExport>` envelope (spec section
17.5), as produced by [Context.prototype.export](#export).

#### Parameters

##### data

`Uint8Array`

The serialized context export bytes.

#### Returns

`Promise`\<`string`\>

The context ID of the imported context.

#### Throws

If deserialization, validation, or import fails.
