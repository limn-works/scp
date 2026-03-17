[**@limn-works/scp-ts v0.1.0**](README.md)

***

# @limn-works/scp-ts v0.1.0

@limn-works/scp-ts — Shared Context Protocol TypeScript SDK.

Dual-target architecture: browser (WASM) and Bun/Node (napi-rs native
addon). The correct backend is selected automatically at runtime.

## Quick start

```typescript
import { Identity, Context, Transport } from "@limn-works/scp-ts";

const identity = await Identity.create({ custody: "in_memory" });

await using ctx = await Context.create(identity, {
  ceiling: ["messages:read", "messages:write"],
  memoryScope: "ephemeral",
});

await ctx.send("hello world");

for await (const msg of ctx.receive()) {
  console.log(msg.senderDid, msg.content);
}
```

See ADR-022 in `.docs/adrs/phase-4.md` and `.docs/scaffold/typescript.md`.

## Classes

- [AttestationError](classes/AttestationError.md)
- [Context](classes/Context.md)
- [ContextError](classes/ContextError.md)
- [CryptoError](classes/CryptoError.md)
- [EventLog](classes/EventLog.md)
- [Identity](classes/Identity.md)
- [IdentityError](classes/IdentityError.md)
- [InMemorySqliteStorage](classes/InMemorySqliteStorage.md)
- [McpError](classes/McpError.md)
- [Node](classes/Node.md)
- [Relay](classes/Relay.md)
- [ScopedHandle](classes/ScopedHandle.md)
- [ScpError](classes/ScpError.md)
- [StorageError](classes/StorageError.md)
- [ToolError](classes/ToolError.md)
- [Transport](classes/Transport.md)
- [TransportError](classes/TransportError.md)
- [UcanPermissionError](classes/UcanPermissionError.md)
- [ValidationError](classes/ValidationError.md)
- [WasmSqliteStorage](classes/WasmSqliteStorage.md)

## Interfaces

- [AggregatedTrustInput](interfaces/AggregatedTrustInput.md)
- [AggregationInput](interfaces/AggregationInput.md)
- [AssetEntry](interfaces/AssetEntry.md)
- [AttestationSummary](interfaces/AttestationSummary.md)
- [BatchPublishResult](interfaces/BatchPublishResult.md)
- [BehavioralRecord](interfaces/BehavioralRecord.md)
- [BridgeRegistration](interfaces/BridgeRegistration.md)
- [Capability](interfaces/Capability.md)
- [Checkpoint](interfaces/Checkpoint.md)
- [ContextParams](interfaces/ContextParams.md)
- [CrossContextInvocationResult](interfaces/CrossContextInvocationResult.md)
- [DeclarationValidationResult](interfaces/DeclarationValidationResult.md)
- [DIDDocument](interfaces/DIDDocument.md)
- [DiscoveryResult](interfaces/DiscoveryResult.md)
- [EndSessionResult](interfaces/EndSessionResult.md)
- [Event](interfaces/Event.md)
- [EventClaim](interfaces/EventClaim.md)
- [EventFilter](interfaces/EventFilter.md)
- [HandleDeregisterResult](interfaces/HandleDeregisterResult.md)
- [HandleLookupResult](interfaces/HandleLookupResult.md)
- [HandleRegisterResult](interfaces/HandleRegisterResult.md)
- [InvitationEvaluationResult](interfaces/InvitationEvaluationResult.md)
- [McpClient](interfaces/McpClient.md)
- [McpClientConfig](interfaces/McpClientConfig.md)
- [McpServer](interfaces/McpServer.md)
- [McpServerConfig](interfaces/McpServerConfig.md)
- [MediaSession](interfaces/MediaSession.md)
- [Message](interfaces/Message.md)
- [MetadataRecord](interfaces/MetadataRecord.md)
- [ObservableMetrics](interfaces/ObservableMetrics.md)
- [OperationalMetadata](interfaces/OperationalMetadata.md)
- [ParsedAddress](interfaces/ParsedAddress.md)
- [ParticipationProfile](interfaces/ParticipationProfile.md)
- [Proof](interfaces/Proof.md)
- [Provenance](interfaces/Provenance.md)
- [ProvenanceRecord](interfaces/ProvenanceRecord.md)
- [PublishResult](interfaces/PublishResult.md)
- [RelayPriceAdjustment](interfaces/RelayPriceAdjustment.md)
- [RequireParticipation](interfaces/RequireParticipation.md)
- [ResolutionPath](interfaces/ResolutionPath.md)
- [ScpIdAuthentication](interfaces/ScpIdAuthentication.md)
- [ScpIdChallenge](interfaces/ScpIdChallenge.md)
- [ScpIdResponse](interfaces/ScpIdResponse.md)
- [SendSignalingResult](interfaces/SendSignalingResult.md)
- [SessionMetadata](interfaces/SessionMetadata.md)
- [ShadowIdentity](interfaces/ShadowIdentity.md)
- [SignalingResult](interfaces/SignalingResult.md)
- [StorageInterface](interfaces/StorageInterface.md)
- [StructuralMetadata](interfaces/StructuralMetadata.md)
- [SyncPolicy](interfaces/SyncPolicy.md)
- [TestVector](interfaces/TestVector.md)
- [ToolCost](interfaces/ToolCost.md)
- [ToolDefinition](interfaces/ToolDefinition.md)
- [ToolSessionInvokeResult](interfaces/ToolSessionInvokeResult.md)
- [ToolSessionResult](interfaces/ToolSessionResult.md)
- [ToolVerificationResult](interfaces/ToolVerificationResult.md)
- [TransportConfig](interfaces/TransportConfig.md)
- [TransportStatus](interfaces/TransportStatus.md)
- [TrustEvaluation](interfaces/TrustEvaluation.md)
- [UcanToken](interfaces/UcanToken.md)
- [VerificationMethod](interfaces/VerificationMethod.md)

## Type Aliases

- [AddressResolution](type-aliases/AddressResolution.md)
- [BridgeMode](type-aliases/BridgeMode.md)
- [BridgeTarget](type-aliases/BridgeTarget.md)
- [BroadcastAdmissionPolicy](type-aliases/BroadcastAdmissionPolicy.md)
- [CustodyType](type-aliases/CustodyType.md)
- [DiscoveryMethod](type-aliases/DiscoveryMethod.md)
- [GovernanceActionResult](type-aliases/GovernanceActionResult.md)
- [MemberRole](type-aliases/MemberRole.md)
- [PaidActionType](type-aliases/PaidActionType.md)
- [ParticipationFact](type-aliases/ParticipationFact.md)
- [ParticipationThreshold](type-aliases/ParticipationThreshold.md)
- [ResolutionLayer](type-aliases/ResolutionLayer.md)
- [ShadowStatus](type-aliases/ShadowStatus.md)
- [TrustLevel](type-aliases/TrustLevel.md)
- [VfsType](type-aliases/VfsType.md)

## Variables

- [BRIDGE\_TARGET](variables/BRIDGE_TARGET.md)
- [~~PermissionError~~](variables/PermissionError.md)

## Functions

- [addressResolve](functions/addressResolve.md)
- [adjustRelayPrice](functions/adjustRelayPrice.md)
- [aggregateTrustInput](functions/aggregateTrustInput.md)
- [antispamEscalatedCost](functions/antispamEscalatedCost.md)
- [antispamRecord](functions/antispamRecord.md)
- [antispamVelocity](functions/antispamVelocity.md)
- [autoAcceptBlocked](functions/autoAcceptBlocked.md)
- [bridgeCreateShadow](functions/bridgeCreateShadow.md)
- [bridgeEvaluateTrust](functions/bridgeEvaluateTrust.md)
- [bridgeRegister](functions/bridgeRegister.md)
- [budgetGrant](functions/budgetGrant.md)
- [budgetRecordSpend](functions/budgetRecordSpend.md)
- [budgetRemaining](functions/budgetRemaining.md)
- [checkPolicyLock](functions/checkPolicyLock.md)
- [classifyOffline](functions/classifyOffline.md)
- [classifyOfflineCustom](functions/classifyOfflineCustom.md)
- [connectLocalTransport](functions/connectLocalTransport.md)
- [connectMcp](functions/connectMcp.md)
- [connectMcpStdio](functions/connectMcpStdio.md)
- [createQuery](functions/createQuery.md)
- [defineToolDefinition](functions/defineToolDefinition.md)
- [delegateUcan](functions/delegateUcan.md)
- [discoverContexts](functions/discoverContexts.md)
- [estimateCost](functions/estimateCost.md)
- [evaluateFormula](functions/evaluateFormula.md)
- [evaluateInvitation](functions/evaluateInvitation.md)
- [evaluateProvenanceQuality](functions/evaluateProvenanceQuality.md)
- [evaluateTrust](functions/evaluateTrust.md)
- [getSyncPolicy](functions/getSyncPolicy.md)
- [handleDeregister](functions/handleDeregister.md)
- [handleLookup](functions/handleLookup.md)
- [handleRegister](functions/handleRegister.md)
- [mapBridgeError](functions/mapBridgeError.md)
- [mediaActivateSession](functions/mediaActivateSession.md)
- [mediaCheckCapability](functions/mediaCheckCapability.md)
- [mediaCreateAnswer](functions/mediaCreateAnswer.md)
- [mediaCreateIceCandidate](functions/mediaCreateIceCandidate.md)
- [mediaCreateOffer](functions/mediaCreateOffer.md)
- [mediaCreateSessionEnd](functions/mediaCreateSessionEnd.md)
- [mediaEndSession](functions/mediaEndSession.md)
- [mediaInitiateSession](functions/mediaInitiateSession.md)
- [mediaJoinSession](functions/mediaJoinSession.md)
- [mediaSendSignaling](functions/mediaSendSignaling.md)
- [mediaVerifySenderAttribution](functions/mediaVerifySenderAttribution.md)
- [metadataRecordFromJson](functions/metadataRecordFromJson.md)
- [metadataRecordToJson](functions/metadataRecordToJson.md)
- [mintUcan](functions/mintUcan.md)
- [normalizeAddress](functions/normalizeAddress.md)
- [parseAddress](functions/parseAddress.md)
- [petnameGetForContext](functions/petnameGetForContext.md)
- [petnameGetForDid](functions/petnameGetForDid.md)
- [petnameRemove](functions/petnameRemove.md)
- [petnameRemoveContext](functions/petnameRemoveContext.md)
- [petnameResolveContext](functions/petnameResolveContext.md)
- [petnameResolveDid](functions/petnameResolveDid.md)
- [petnameSet](functions/petnameSet.md)
- [petnameSetContext](functions/petnameSetContext.md)
- [policyRequiresPayment](functions/policyRequiresPayment.md)
- [prefixSuccessor](functions/prefixSuccessor.md)
- [provenanceAttach](functions/provenanceAttach.md)
- [provenanceCheckChainDepth](functions/provenanceCheckChainDepth.md)
- [resolveAddress](functions/resolveAddress.md)
- [restoreAllContexts](functions/restoreAllContexts.md)
- [restoreContext](functions/restoreContext.md)
- [revokeUcan](functions/revokeUcan.md)
- [scpidChallenge](functions/scpidChallenge.md)
- [scpidSign](functions/scpidSign.md)
- [scpidVerify](functions/scpidVerify.md)
- [serveMcp](functions/serveMcp.md)
- [templateGetParams](functions/templateGetParams.md)
- [toolInvokeCrossContext](functions/toolInvokeCrossContext.md)
- [toolSessionClose](functions/toolSessionClose.md)
- [toolSessionCreate](functions/toolSessionCreate.md)
- [toolSessionInvoke](functions/toolSessionInvoke.md)
- [validateAgainstTemplate](functions/validateAgainstTemplate.md)
- [validateCapabilityDeclaration](functions/validateCapabilityDeclaration.md)
- [validateContextParams](functions/validateContextParams.md)
- [validatePolicyChange](functions/validatePolicyChange.md)
- [validateUcan](functions/validateUcan.md)
- [verifyParticipationRequirements](functions/verifyParticipationRequirements.md)
