/**
 * wasm-bindgen WASM bridge adapter for browser environments.
 *
 * This module wraps the wasm-bindgen generated module (`@limn-works/scp-ts-wasm`)
 * into the unified `Bridge` interface consumed by the TypeScript SDK.
 *
 * WASM initialization is performed lazily via `initWasm()`, which must be
 * called once before any bridge functions are invoked. The `getBridge()`
 * function in `bridge.ts` handles this automatically.
 *
 * See ADR-022 in `.docs/adrs/phase-4.md`.
 */

import type { BridgeMode, ShadowStatus } from "../bridge";
import {
  EconomicPolicyUnsupportedOnWasm,
  IdentityError,
  ToolError,
  TransportError,
  WasmCannotValidateSpendingUcan,
} from "../errors";
import type {
  BroadcastAdmissionPolicy,
  Checkpoint,
  DIDDocument,
  Event,
  EventClaim,
  EventFilter,
  MemberRole,
  Proof,
  ToolDefinition,
  ToolVerificationResult,
  TransportStatus,
  UcanToken,
  VerificationMethod,
} from "../types";
import type {
  Bridge,
  BridgeContextHandle,
  BridgeIdentityHandle,
  BridgeTransportHandle,
  MessageCallback,
} from "./bridge";
import { safeJsonParse } from "./json-utils";

// ---------------------------------------------------------------------------
// WASM module types
// ---------------------------------------------------------------------------

/** The shape of the wasm-bindgen generated module. */
interface WasmModule {
  // Bundler target: `default` is an init function that loads the WASM binary.
  // Node.js target: `default` is a re-exported module object (not callable).
  // The initWasm() function handles both cases.
  default: (() => Promise<void>) | Record<string, unknown>;
  scp_init: () => void;
  scp_version: () => string;
  identity_create: (custody: string) => Promise<{ did: string; custodyType: string }>;
  identity_load: (did: string) => Promise<{ did: string; custodyType: string }>;
  identity_resolve: (did: string) => Promise<{
    id: string;
    verificationMethodsJson: string;
    servicesJson: string;
    alsoKnownAsJson: string;
    authenticationJson: string;
    assertionMethodsJson: string;
  }>;
  context_create: (
    identityDid: string,
    paramsJson: string,
  ) => Promise<{ contextId: string; state: string; creatorDid: string }>;
  context_join: (
    handle: BridgeContextHandle,
    identityDid: string,
    spendingUcanJwt?: string,
  ) => Promise<void>;
  context_leave: (handle: BridgeContextHandle, identityDid: string) => Promise<void>;
  context_close: (handle: BridgeContextHandle, identityDid: string) => Promise<void>;
  context_send: (
    handle: BridgeContextHandle,
    identityDid: string,
    payloadBase64: string,
    spendingUcanJwt?: string,
  ) => Promise<void>;
  context_subscribe: (
    handle: BridgeContextHandle,
    callback: {
      onMessage: (msg: {
        senderDid: string;
        payloadBase64: string;
        timestamp: number;
        contextId: string;
        sequence: number;
      }) => void;
      onComplete: () => void;
    },
  ) => void;
  tool_register: (handle: BridgeContextHandle, definitionJson: string) => Promise<string>;
  tool_invoke: (
    handle: BridgeContextHandle,
    toolId: string,
    inputJson: string,
    identityDid: string,
    ucanToken: string | undefined,
  ) => Promise<string>;
  tool_verify: (
    handle: BridgeContextHandle,
    toolId: string,
  ) => Promise<{ toolId: string; passed: boolean; failuresJson: string }>;
  // Cross-context tool interfaces (§6.2.0.1)
  tool_interface_expose: (
    handle: BridgeContextHandle,
    toolId: string,
    targetContextId: string,
    rateLimitJson: string | undefined,
  ) => Promise<string>;
  tool_interface_accept: (handle: BridgeContextHandle, interfaceJson: string) => Promise<string>;
  tool_interface_revoke: (handle: BridgeContextHandle, interfaceIdHex: string) => Promise<string>;
  transport_connect: (relayUrl: string) => Promise<{
    connected: boolean;
    relayUrl: string | null;
    latencyMs: number | null;
  }>;
  transport_disconnect: () => Promise<void>;
  event_log_query: (handle: BridgeContextHandle, filterJson: string | undefined) => Promise<string>;
  event_log_verify: (
    handle: BridgeContextHandle,
    claimJson: string,
  ) => Promise<{ verified: boolean; proofType: string; detailsJson: string }>;
  ucan_validate: (
    handle: BridgeContextHandle,
    token: string,
    capability: string,
    expectedAudDid: string,
    proofTokensJson: string | undefined,
  ) => Promise<void>;
  ucan_mint: (
    handle: BridgeContextHandle,
    memberDid: string,
    capabilitiesJson: string,
  ) => Promise<{
    tokenId: string;
    issuer: string;
    audience: string;
    capabilitiesJson: string;
    expiresAt: number | null;
    encoded: string;
  }>;
  ucan_revoke: (handle: BridgeContextHandle, token: string, revokerDid: string) => Promise<void>;
  // Bridge Connector
  bridge_register: (
    contextId: string,
    operatorDid: string,
    governanceDid: string,
    platform: string,
    mode: BridgeMode,
  ) => ReturnType<Bridge["bridgeRegister"]>;
  bridge_evaluate_trust: (
    isBridged: boolean,
    isNativeTransport: boolean,
    shadowStatus: ShadowStatus,
  ) => number;
  bridge_create_shadow: (
    bridgeId: string,
    platformHandle: string,
    bridgeMode: BridgeMode,
    contextId: string | undefined,
  ) => ReturnType<Bridge["bridgeCreateShadow"]>;
  // Discovery
  discovery_parse_address: (address: string) => string;
  discovery_create_query: (
    capabilitiesJson: string | undefined,
    keywordsJson: string | undefined,
    minHistorySecs: number | undefined,
  ) => string;
  discovery_normalize_address: (address: string) => string;
  context_discover: (query: string) => Promise<string>;
  // Petnames (§22.4)
  petname_set: (ownerDid: string, targetDid: string, name: string) => void;
  petname_remove: (ownerDid: string, targetDid: string) => void;
  petname_set_context: (ownerDid: string, contextId: string, name: string) => void;
  petname_remove_context: (ownerDid: string, contextId: string) => void;
  petname_resolve_did: (ownerDid: string, name: string) => string;
  petname_resolve_context: (ownerDid: string, name: string) => string;
  petname_get_for_did: (ownerDid: string, targetDid: string) => unknown;
  petname_get_for_context: (ownerDid: string, contextId: string) => unknown;
  petname_apply_event: (ownerDid: string, eventJson: string) => void;
  petname_did_count: (ownerDid: string) => number;
  petname_context_count: (ownerDid: string) => number;
  // Handle Registry (§22.3.1)
  handle_register: (
    discoveryContextId: string,
    handle: string,
    targetJson: string,
    registrantDid: string,
    description: string | undefined,
    tagsJson: string | undefined,
  ) => string;
  handle_lookup: (
    discoveryContextId: string,
    handle: string,
    typeFilter: string | undefined,
  ) => string;
  handle_deregister: (discoveryContextId: string, handle: string, did: string) => string;
  // Scope Registry (§22.3.5, ADR-043)
  scope_register: (
    scopeContextId: string,
    name: string,
    targetContextId: string,
    relayUrlsJson: string,
    registrantDid: string,
    description: string | undefined,
    tagsJson: string | undefined,
  ) => string;
  scope_lookup: (scopeContextId: string, name: string) => string;
  scope_deregister: (scopeContextId: string, name: string, did: string) => string;
  // Address Resolution (§22.8)
  address_resolve: (
    ownerDid: string,
    address: string,
    knownContextsJson: string | undefined,
  ) => string;
  // Provenance
  evaluate_provenance_quality: (
    sourceContext: string | undefined,
    sourceType: string,
    contextState: string,
    counterpartiesJson: string | undefined,
  ) => number;
  provenance_attach: (
    sourceContextId: string,
    sourceType: string,
    memoryScope: string,
    membersJson: string,
    targetContextId: string,
    actorDid: string,
    existingChainDepth: number | undefined,
    existingChainPathJson: string,
    discoveryMethod: string | undefined,
    purpose: string | undefined,
  ) => string;
  provenance_check_chain_depth: (chainDepth: number, maxDepth: number | undefined) => boolean;
  // Sync
  sync_classify_offline: (lastRelayContact: number, now: number) => string;
  sync_classify_offline_custom: (
    lastRelayContact: number,
    now: number,
    tier1ThresholdSecs: number,
    tier2ThresholdSecs: number,
  ) => string;
  sync_get_policy: () => ReturnType<Bridge["syncGetPolicy"]>;
  // Identity Advanced
  identity_create_with_agent_key: (
    custody: string,
  ) => Promise<{ did: string; custodyType: string }>;
  identity_add_agent_key: (identity: { did: string; custodyType: string }) => {
    did: string;
    custodyType: string;
  };
  identity_rotate_agent_key: (identity: { did: string; custodyType: string }) => {
    did: string;
    custodyType: string;
  };
  identity_remove_agent_key: (identity: { did: string; custodyType: string }) => {
    did: string;
    custodyType: string;
  };
  identity_migrate: (identity: { did: string; custodyType: string }) => Promise<{
    identity: { did: string; custodyType: string };
    rotationEventJson: string;
  }>;
  identity_attest_device: (did: string) => Promise<string>;
  identity_verify_device_attestation: (did: string, tokenBase64: string) => Promise<boolean>;
  // Identity link attestation (§3.5.1)
  identity_create_link_attestation: (
    did: string,
    platform: string,
    handle: string,
    proof: string,
    verificationMethod: string,
    platformId?: string,
  ) => Promise<string>;
  identity_link_attestations: (did: string) => string;
  identity_remove_link_attestation: (did: string, attestationId: string) => boolean;
  identity_remove: (did: string) => void;
  identity_remove_if_present: (did: string) => boolean;
  identity_verify_link_attestation: (
    attestationJson: string,
    issuerPublicKeyHex: string,
  ) => Promise<boolean>;
  // Recovery and custody migration (#632, spec §9.12, §3.2.1)
  identity_execute_recovery: (did: string, tier: string, contextIds: string[]) => string;
  identity_execute_custody_migration: (did: string, target: string, contextIds: string[]) => string;
  // Membership queries
  context_member_count: (handle: BridgeContextHandle) => number | null;
  context_is_member: (handle: BridgeContextHandle, did: string) => boolean;
  context_member_dids: (handle: BridgeContextHandle) => string;
  context_member_role: (handle: BridgeContextHandle, did: string) => string | null;
  // Broadcast operations
  broadcast_subscribe: (handle: BridgeContextHandle, subscriberDid: string) => Promise<void>;
  broadcast_unsubscribe: (handle: BridgeContextHandle, subscriberDid: string) => Promise<void>;
  broadcast_publish: (
    handle: BridgeContextHandle,
    authorDid: string,
    payloadBase64: string,
  ) => Promise<void>;
  broadcastPublishAsset: (
    handle: BridgeContextHandle,
    authorDid: string,
    assetJson: string,
    deployId?: string,
  ) => Promise<unknown>;
  broadcastPublishAssets: (
    handle: BridgeContextHandle,
    authorDid: string,
    assetsJson: string,
    deployId?: string,
  ) => Promise<unknown>;
  broadcast_block: (
    handle: BridgeContextHandle,
    subscriberDid: string,
    blockerDid: string,
  ) => Promise<void>;
  broadcast_unblock: (
    handle: BridgeContextHandle,
    subscriberDid: string,
    unblockerDid: string,
  ) => Promise<void>;
  broadcast_subscriber_count: (handle: BridgeContextHandle) => number | null;
  broadcast_is_subscriber: (handle: BridgeContextHandle, did: string) => boolean;
  broadcast_admission: (handle: BridgeContextHandle) => string | null;
  broadcast_handle_key_request: (
    handle: BridgeContextHandle,
    authorDid: string,
    requesterDid: string,
  ) => Promise<string>;
  // Identity key rotation
  identity_rotate_key: (identity: { did: string; custodyType: string }) => {
    did: string;
    custodyType: string;
  };
  // Governance lifecycle (#559)
  context_apply_pending_ceiling_modification: (
    handle: BridgeContextHandle,
    currentTimestamp: number,
  ) => Promise<boolean>;
  context_finalize_close: (handle: BridgeContextHandle) => Promise<void>;
  context_create_governance_checkpoint: (
    handle: BridgeContextHandle,
    checkpointSeq: number,
    merkleRootHex: string,
    eventCount: number,
    lastEventHashHex: string,
    stateSnapshotHashHex: string,
    creatorDid: string,
    creatorSignatureHex: string,
  ) => Promise<string>;
  context_add_checkpoint_cosignature: (
    handle: BridgeContextHandle,
    checkpointJson: string,
    signerDid: string,
    signatureHex: string,
  ) => Promise<string>;
  context_restore: (contextId: string) => Promise<void>;
  context_restore_all: () => Promise<string>;
  // Governance
  context_execute_governance: (
    handle: BridgeContextHandle,
    initiatorDid: string,
    proposalId: string,
    actionJson: string,
  ) => Promise<string>;
  // Governance proposal lifecycle (#621)
  context_governance_propose: (
    handle: BridgeContextHandle,
    proposerDid: string,
    proposalId: string,
    actionJson: string,
  ) => Promise<string>;
  context_governance_approve: (
    handle: BridgeContextHandle,
    proposalId: string,
    voterDid: string,
  ) => Promise<string>;
  context_governance_reject: (
    handle: BridgeContextHandle,
    proposalId: string,
    voterDid: string,
  ) => Promise<string>;
  context_governance_withdraw: (
    handle: BridgeContextHandle,
    proposalId: string,
    voterDid: string,
  ) => Promise<string>;
  context_governance_get_proposal: (
    handle: BridgeContextHandle,
    proposalId: string,
  ) => Promise<string>;
  context_governance_list_proposals: (handle: BridgeContextHandle) => Promise<string>;
  // Event log checkpoint
  event_log_checkpoint: (
    handle: BridgeContextHandle,
    identityDid: string,
    epoch: number,
  ) => Promise<{
    contextId: string;
    senderDid: string;
    eventCount: number;
    merkleRoot: string;
    epoch: number | null;
    timestamp: number;
    signingPayloadHash: string;
    signature: string;
  }>;
  // Context drain/export/import
  context_drain_events: (handle: BridgeContextHandle) => string;
  context_export: (handle: BridgeContextHandle) => Promise<Uint8Array>;
  context_import: (data: Uint8Array) => Promise<string>;
  // TTL
  context_ttl_remaining: (handle: BridgeContextHandle) => number | null;
  context_extend_ttl: (handle: BridgeContextHandle, additionalSecs: number) => Promise<boolean>;
  context_handle_ttl_expiry: (handle: BridgeContextHandle) => Promise<void>;
  context_propose_ttl_extension: (
    handle: BridgeContextHandle,
    proposerDid: string,
    extensionSecs: number,
  ) => Promise<boolean>;
  context_reset_ttl_timer: (handle: BridgeContextHandle, newDurationSecs: number) => Promise<void>;
  // UCAN delegate
  ucan_delegate: (
    handle: BridgeContextHandle,
    delegatorDid: string,
    delegateeDid: string,
    parentToken: string,
    capabilitiesJson: string,
  ) => Promise<{
    tokenId: string;
    issuer: string;
    audience: string;
    capabilitiesJson: string;
    expiresAt: number | null;
    encoded: string;
  }>;
  // Economic policy (§19.3)
  context_set_economic_policy: (handle: BridgeContextHandle, policyJson: string) => void;
  context_get_economic_policy: (handle: BridgeContextHandle) => string | undefined;
  // App Sandboxing (#595, spec §8.4.1, §8.4.2)
  sandbox_validate_declaration: (
    declarationJson: string,
    ceilingCapabilities: string[],
    roleCapabilities: string[],
  ) => string;
  sandbox_check_capability: (grantedCapabilities: string[], requiredCapability: string) => boolean;
  // Trust — participation verification (SCP-BA-004, §7.3.2.1)
  verify_participation_requirements: (profileJson: string, requirementsJson: string) => boolean;
  // Trust aggregation
  aggregate_trust_input: (
    contextId: string,
    subjectDid: string,
    eventsJson: string,
    merkleRootJson: string,
    consequenceRulesJson: string,
    thresholdRequirementsJson: string,
    attestorSetsJson: string,
    cachedAttestationsJson: string,
    challengeResultsJson: string,
  ) => string;
  // SCPID (§3.11) — challenge + sign only; verify requires DID resolution (not in WASM)
  scpid_challenge: (audience: string, ttlSeconds: number) => string;
  scpid_sign: (did: string, signingKeyId: string, challengeJson: string) => string;
  // Economy (§19)
  economy_estimate_cost: (policyJson: string, actionType: string, metricsJson: string) => number;
  economy_policy_requires_payment: (policyJson: string) => boolean;
  economy_auto_accept_blocked: (policyJson: string) => boolean;
  economy_check_policy_lock: (policyJson: string) => boolean;
  economy_validate_policy_change: (currentJson: string, proposedJson: string) => boolean;
  economy_evaluate_formula: (formulaJson: string, metricsJson: string) => number;
  economy_budget_remaining: (contextId: string, did: string) => number;
  economy_budget_grant: (contextId: string, did: string, amount: number) => void;
  economy_budget_record_spend: (contextId: string, did: string, amount: number) => void;
  economy_antispam_record: (contextId: string, senderDid: string, timestamp: number) => void;
  economy_antispam_velocity: (contextId: string, senderDid: string, now: number) => number;
  economy_antispam_escalated_cost: (
    contextId: string,
    senderDid: string,
    now: number,
    baseCost: number,
    thresholdsJson: string,
    floor: number | null,
    cap: number | null,
  ) => number;
  // Media (ADR-024)
  media_check_capability: (ceiling: string[], capability: string) => boolean;
  media_initiate_session: (
    contextId: string,
    ceiling: string[],
    capabilities: string[],
    participants: string[],
    timestamp: number,
  ) => string;
  media_activate_session: (sessionJson: string) => string;
  media_join_session: (sessionJson: string, participantDid: string) => string;
  media_end_session: (sessionJson: string, timestamp: number) => string;
  media_create_offer: (sessionId: string, sdp: string, senderDid: string) => string;
  media_create_answer: (sessionId: string, sdp: string, senderDid: string) => string;
  media_create_ice_candidate: (
    sessionId: string,
    candidate: string,
    senderDid: string,
    sdpMid: string | undefined,
    sdpMlineIndex: number | undefined,
  ) => string;
  media_create_session_end: (sessionId: string, senderDid: string) => string;
  media_send_signaling: (signalingJson: string) => string;
  media_verify_sender_attribution: (signalingJson: string, envelopeSenderDid: string) => boolean;
  // Invitation evaluation
  evaluate_invitation: (
    paramsJson: string,
    inviterDid: string,
    identityDid: string,
    policyJson: string | null,
    spendingJson: string | null,
    trustedDidsJson: string | null,
  ) => string;
  // MetadataRecord (§5.7.2)
  metadata_record_to_json: (
    contextId: string,
    sequence: number,
    signerDid: string,
    timestamp: number,
    structuralJson: string,
    operationalJson: string,
    signatureHex: string,
  ) => string;
  metadata_record_from_json: (jsonStr: string) => string;
  // Context template (§5.14)
  template_get_params: (templateId: string) => string;
  validate_against_template: (paramsJson: string) => string | null;
  validate_context_params: (paramsJson: string) => string | null;
}

// ---------------------------------------------------------------------------
// WASM initialization
// ---------------------------------------------------------------------------

let _wasmModule: WasmModule | null = null;
let _initPromise: Promise<void> | null = null;

/**
 * Initializes the WASM module.
 *
 * Loads and instantiates the wasm-bindgen generated module. This must be
 * called once before any bridge functions are invoked. The `getBridge()`
 * function handles this automatically.
 *
 * This function is idempotent -- calling it multiple times returns the same
 * initialization promise.
 */
export async function initWasm(): Promise<void> {
  if (_wasmModule !== null) {
    return;
  }

  if (_initPromise !== null) {
    return _initPromise;
  }

  _initPromise = (async () => {
    try {
      // Dynamic import of the wasm-bindgen generated package.
      // This package is produced by `wasm-pack build` with either
      // `--target bundler` (browser) or `--target nodejs` (Node.js/Bun).
      // It may not be installed in all environments.
      const mod = (await import(
        /* webpackIgnore: true */ "@limn-works/scp-ts-wasm"
      )) as unknown as WasmModule;
      // Bundler target exports `default` as an async init function.
      // Node.js target auto-initializes on import — `default` is the module object.
      if (typeof mod.default === "function") {
        await mod.default();
      }
      mod.scp_init();
      _wasmModule = mod;
    } catch (err) {
      _initPromise = null;
      throw new TransportError(
        `Failed to initialize WASM module: ${err instanceof Error ? err.message : String(err)}. ` +
          "Ensure @limn-works/scp-ts-wasm is installed and the WASM binary is accessible.",
        "SCP-TRANS-5002",
      );
    }
  })();

  return _initPromise;
}

/**
 * Returns the initialized WASM module, throwing if not yet initialized.
 */
function getWasm(): WasmModule {
  if (_wasmModule === null) {
    throw new TransportError(
      "WASM module not initialized -- call initWasm() first",
      "SCP-TRANS-5002",
    );
  }
  return _wasmModule;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Converts a Uint8Array to a base64 string for WASM boundary crossing. */
function uint8ToBase64(bytes: Uint8Array): string {
  // Use Buffer in Node.js/Bun, or manual conversion in browser.
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return globalThis.btoa(binary);
}

/** Converts a base64 string back to a Uint8Array. */
function base64ToUint8(base64: string): Uint8Array {
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(base64, "base64"));
  }
  const binary = globalThis.atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Generates a 64-character hex-encoded proposal ID (256-bit random).
 *
 * Native bridges receive hex-encoded SHA-256 hashes (64-char hex) from
 * scp-core's `compute_proposal_id()`. This function produces a 256-bit
 * random value in the same format for cross-bridge interop.
 */
function generateProposalIdHex(): string {
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(32));
  let hex = "";
  for (const b of bytes) {
    hex += b.toString(16).padStart(2, "0");
  }
  return hex;
}

/**
 * Re-throws a WASM bridge rejection as a typed error when it carries one of
 * the C2 fail-closed economy gate codes (`SCP-ECON-12095` /
 * `SCP-ECON-12096`).
 *
 * The Rust `WasmContextManager` rejects paid contexts at create / join /
 * send because the WASM bridge cannot run `scp-runtime`'s `enforce_economy`
 * pipeline (no payment adapter, no budget tracker, no velocity tracker, no
 * hard rate limit token bucket — see ADR-034). The rejection arrives here
 * as a generic `Error` whose `.message` carries the bracketed
 * `[SCP-ECON-12095]` / `[SCP-ECON-12096]` prefix.
 *
 * Most callers route through `mapBridgeError` upstream, which handles the
 * mapping uniformly. This helper exists so the WASM bridge layer ALSO emits
 * the typed subclass directly, even when callers do not pass through the
 * SDK error mapper. Returning the original error if no code matches keeps
 * the regular error flow intact.
 */
function rethrowEconomyFailClosed(error: unknown): unknown {
  if (!(error instanceof Error)) {
    return error;
  }
  const codeMatch = /\[(SCP-ECON-\d+)\]/.exec(error.message);
  if (codeMatch === null) {
    return error;
  }
  const code = codeMatch[1] ?? "SCP-ECON-0000";
  if (code === "SCP-ECON-12095") {
    return new EconomicPolicyUnsupportedOnWasm(error.message, code);
  }
  if (code === "SCP-ECON-12096") {
    return new WasmCannotValidateSpendingUcan(error.message, code);
  }
  return error;
}

// ---------------------------------------------------------------------------
// Bridge factory
// ---------------------------------------------------------------------------

/**
 * Creates a `Bridge` implementation backed by the wasm-bindgen WASM module.
 */
export function createWasmBridge(): Bridge {
  return {
    // Identity
    async identityCreate(custody: string): Promise<BridgeIdentityHandle> {
      const wasm = getWasm();
      const handle = await wasm.identity_create(custody);
      return { did: handle.did, custodyType: handle.custodyType };
    },

    async identityLoad(did: string): Promise<BridgeIdentityHandle> {
      const wasm = getWasm();
      const handle = await wasm.identity_load(did);
      return { did: handle.did, custodyType: handle.custodyType };
    },

    async identityResolve(did: string): Promise<DIDDocument> {
      const wasm = getWasm();
      const doc = await wasm.identity_resolve(did);
      // Derive agent key state from verificationMethodsJson — check for an
      // `#agent` verification method, consistent with the NAPI bridge which
      // uses `document.has_agent_key()` / `document.agent_verification_method()`.
      const verificationMethods: VerificationMethod[] = safeJsonParse(
        doc.verificationMethodsJson,
        "identity_resolve",
      ) as VerificationMethod[];
      const agentVm = verificationMethods.find((vm) => vm.id.endsWith("#agent"));
      return {
        id: doc.id,
        verificationMethods: verificationMethods as DIDDocument["verificationMethods"],
        authentication: safeJsonParse(
          doc.authenticationJson,
          "identity_resolve",
        ) as DIDDocument["authentication"],
        assertionMethods: safeJsonParse(
          doc.assertionMethodsJson,
          "identity_resolve",
        ) as DIDDocument["assertionMethods"],
        alsoKnownAs: safeJsonParse(
          doc.alsoKnownAsJson,
          "identity_resolve",
        ) as DIDDocument["alsoKnownAs"],
        serviceEndpoints: safeJsonParse(
          doc.servicesJson,
          "identity_resolve",
        ) as DIDDocument["serviceEndpoints"],
        hasAgentKey: agentVm !== undefined,
        ...(agentVm !== undefined && {
          agentPublicKey: agentVm.publicKeyMultibase,
        }),
      };
    },

    async identityRotateKey(handle: BridgeIdentityHandle): Promise<BridgeIdentityHandle> {
      const wasm = getWasm();
      const result = wasm.identity_rotate_key({
        did: handle.did,
        custodyType: handle.custodyType,
      });
      return { did: result.did, custodyType: result.custodyType };
    },

    // Context
    async contextCreate(
      identity: BridgeIdentityHandle,
      paramsJson: string,
    ): Promise<BridgeContextHandle> {
      const wasm = getWasm();
      // WASM bridge uses identity.did since wasm_bindgen context_create takes a DID string.
      //
      // C2 fail-closed: if `paramsJson` carries an `economicPolicy` that
      // requires payment for any action, the underlying Rust manager rejects
      // with `SCP-ECON-12095` (`EconomicPolicyUnsupportedOnWasm`). The
      // bracketed code in the rejection message is parsed by `mapBridgeError`
      // upstream into the typed subclass — it is intentionally NOT caught
      // here so the SDK layer can handle it via its own try/catch.
      try {
        const handle = await wasm.context_create(identity.did, paramsJson);
        return {
          contextId: handle.contextId,
          state: handle.state,
          creatorDid: handle.creatorDid,
        };
      } catch (e) {
        throw rethrowEconomyFailClosed(e);
      }
    },

    async contextJoin(
      handle: BridgeContextHandle,
      identityDid: string,
      spendingUcanJwt?: string | null,
    ): Promise<void> {
      const wasm = getWasm();
      // C2 fail-closed: if the target context's stored economic policy
      // requires payment, the underlying Rust manager rejects with
      // `SCP-ECON-12096` (`WasmCannotValidateSpendingUcan`) regardless of
      // whether `spendingUcanJwt` is supplied. See ADR-034 and
      // `crates/scp-ffi/wasm/src/manager.rs` for details.
      try {
        await wasm.context_join(handle, identityDid, spendingUcanJwt ?? undefined);
      } catch (e) {
        throw rethrowEconomyFailClosed(e);
      }
    },

    async contextLeave(handle: BridgeContextHandle, identityDid: string): Promise<void> {
      const wasm = getWasm();
      await wasm.context_leave(handle, identityDid);
    },

    async contextClose(handle: BridgeContextHandle, identityDid: string): Promise<void> {
      const wasm = getWasm();
      await wasm.context_close(handle, identityDid);
    },

    async contextSend(
      handle: BridgeContextHandle,
      identityDid: string,
      payload: Uint8Array,
      spendingUcanJwt?: string | null,
    ): Promise<void> {
      const wasm = getWasm();
      const payloadBase64 = uint8ToBase64(payload);
      // C2 fail-closed: if the target context's stored economic policy
      // requires payment, the underlying Rust manager rejects with
      // `SCP-ECON-12096` (`WasmCannotValidateSpendingUcan`) regardless of
      // whether `spendingUcanJwt` is supplied. See ADR-034 and
      // `crates/scp-ffi/wasm/src/manager.rs` for details.
      try {
        await wasm.context_send(handle, identityDid, payloadBase64, spendingUcanJwt ?? undefined);
      } catch (e) {
        throw rethrowEconomyFailClosed(e);
      }
    },

    // WASM `context_subscribe` is still synchronous — the WASM bridge
    // registers subscriptions inline rather than spawning runtime tasks
    // (ADR-034). The async signature mirrors NAPI for API parity; the
    // Promise resolves immediately once registration returns.
    async contextSubscribe(
      handle: BridgeContextHandle,
      _identityDid: string,
      callback: MessageCallback,
    ): Promise<void> {
      const wasm = getWasm();
      wasm.context_subscribe(handle, {
        onMessage: (msg) => {
          callback.onMessage({
            senderDid: msg.senderDid,
            content: base64ToUint8(msg.payloadBase64),
            timestamp: msg.timestamp,
            sequence: msg.sequence,
            contextId: msg.contextId,
          });
        },
        onComplete: () => {
          callback.onComplete();
        },
      });
    },

    contextCancelSubscription(_handle: BridgeContextHandle): void {
      // No-op in WASM — subscriptions are managed by the WASM runtime.
    },

    // Membership queries — delegate to WASM runtime
    async contextMemberCount(handle: BridgeContextHandle): Promise<number | null> {
      const wasm = getWasm();
      const count = wasm.context_member_count(handle);
      return count ?? null;
    },

    async contextIsMember(handle: BridgeContextHandle, did: string): Promise<boolean> {
      const wasm = getWasm();
      return wasm.context_is_member(handle, did);
    },

    async contextMemberDids(handle: BridgeContextHandle): Promise<readonly string[]> {
      const wasm = getWasm();
      const json = wasm.context_member_dids(handle);
      return safeJsonParse(json, "context_member_dids") as string[];
    },

    async contextMemberRole(handle: BridgeContextHandle, did: string): Promise<MemberRole | null> {
      const wasm = getWasm();
      const role = wasm.context_member_role(handle, did);
      return (role as MemberRole | null) ?? null;
    },

    // Broadcast operations — delegate to WASM runtime
    async broadcastSubscribe(handle: BridgeContextHandle, subscriberDid: string): Promise<void> {
      const wasm = getWasm();
      await wasm.broadcast_subscribe(handle, subscriberDid);
    },

    async broadcastUnsubscribe(
      handle: BridgeContextHandle,
      subscriberDid: string,
      rotateKeys?: boolean,
    ): Promise<void> {
      if (rotateKeys === true) {
        throw new TransportError(
          "WASM bridge does not support key rotation on broadcastUnsubscribe. " +
            "Use the native (napi-rs) bridge for rotateKeys support.",
          "SCP-TRANS-5003",
        );
      }
      const wasm = getWasm();
      await wasm.broadcast_unsubscribe(handle, subscriberDid);
    },

    async broadcastPublish(
      handle: BridgeContextHandle,
      authorDid: string,
      payload: Uint8Array,
    ): Promise<void> {
      const wasm = getWasm();
      const payloadBase64 = uint8ToBase64(payload);
      await wasm.broadcast_publish(handle, authorDid, payloadBase64);
    },

    async broadcastPublishAsset(
      handle: BridgeContextHandle,
      authorDid: string,
      asset: { path: string; contentType: string; body: number[] },
      deployId: string | null,
    ): Promise<{ blobId: string; etag: string; deployId: string }> {
      const wasm = getWasm();
      const bodyBase64 = uint8ToBase64(new Uint8Array(asset.body));
      const assetJson = JSON.stringify({
        path: asset.path.normalize("NFC"),
        contentType: asset.contentType,
        bodyBase64,
      });
      return (await wasm.broadcastPublishAsset(
        handle,
        authorDid,
        assetJson,
        deployId ?? undefined,
      )) as { blobId: string; etag: string; deployId: string };
    },

    async broadcastPublishAssets(
      handle: BridgeContextHandle,
      authorDid: string,
      assets: { path: string; contentType: string; body: number[] }[],
      deployId: string | null,
    ): Promise<{
      results: { blobId: string; etag: string; deployId: string }[];
      deployId: string;
    }> {
      const wasm = getWasm();
      const assetsJson = JSON.stringify(
        assets.map((a) => ({
          path: a.path.normalize("NFC"),
          contentType: a.contentType,
          bodyBase64: uint8ToBase64(new Uint8Array(a.body)),
        })),
      );
      return (await wasm.broadcastPublishAssets(
        handle,
        authorDid,
        assetsJson,
        deployId ?? undefined,
      )) as {
        results: { blobId: string; etag: string; deployId: string }[];
        deployId: string;
      };
    },

    async broadcastBlockSubscriber(
      handle: BridgeContextHandle,
      subscriberDid: string,
      blockerDid: string,
    ): Promise<void> {
      const wasm = getWasm();
      await wasm.broadcast_block(handle, subscriberDid, blockerDid);
    },

    async broadcastUnblockSubscriber(
      handle: BridgeContextHandle,
      subscriberDid: string,
      unblockerDid: string,
    ): Promise<void> {
      const wasm = getWasm();
      await wasm.broadcast_unblock(handle, subscriberDid, unblockerDid);
    },

    async broadcastHandleKeyRequest(
      handle: BridgeContextHandle,
      authorDid: string,
      requesterDid: string,
    ): Promise<string> {
      const wasm = getWasm();
      return await wasm.broadcast_handle_key_request(handle, authorDid, requesterDid);
    },

    async broadcastSubscriberCount(handle: BridgeContextHandle): Promise<number | null> {
      const wasm = getWasm();
      const count = wasm.broadcast_subscriber_count(handle);
      return count ?? null;
    },

    async broadcastIsSubscriber(handle: BridgeContextHandle, did: string): Promise<boolean> {
      const wasm = getWasm();
      return wasm.broadcast_is_subscriber(handle, did);
    },

    async broadcastAdmission(
      handle: BridgeContextHandle,
    ): Promise<BroadcastAdmissionPolicy | null> {
      const wasm = getWasm();
      const admission = wasm.broadcast_admission(handle);
      if (admission == null) return null;
      return admission as BroadcastAdmissionPolicy;
    },

    // Governance lifecycle (#559) — delegate to WASM runtime
    async contextApplyPendingCeilingModification(
      handle: BridgeContextHandle,
      currentTimestamp: number,
    ): Promise<boolean> {
      const wasm = getWasm();
      return await wasm.context_apply_pending_ceiling_modification(handle, currentTimestamp);
    },

    async contextFinalizeClose(handle: BridgeContextHandle): Promise<void> {
      const wasm = getWasm();
      await wasm.context_finalize_close(handle);
    },

    async contextCreateGovernanceCheckpoint(
      handle: BridgeContextHandle,
      checkpointSeq: number,
      merkleRootHex: string,
      eventCount: number,
      lastEventHashHex: string,
      stateSnapshotHashHex: string,
      creatorDid: string,
      creatorSignatureHex: string,
    ): Promise<string> {
      const wasm = getWasm();
      return await wasm.context_create_governance_checkpoint(
        handle,
        checkpointSeq,
        merkleRootHex,
        eventCount,
        lastEventHashHex,
        stateSnapshotHashHex,
        creatorDid,
        creatorSignatureHex,
      );
    },

    async contextAddCheckpointCosignature(
      handle: BridgeContextHandle,
      checkpointJson: string,
      signerDid: string,
      signatureHex: string,
    ): Promise<string> {
      const wasm = getWasm();
      return await wasm.context_add_checkpoint_cosignature(
        handle,
        checkpointJson,
        signerDid,
        signatureHex,
      );
    },

    async contextRestore(contextId: string): Promise<void> {
      const wasm = getWasm();
      await wasm.context_restore(contextId);
    },

    async contextRestoreAll(): Promise<string> {
      const wasm = getWasm();
      return await wasm.context_restore_all();
    },

    // Governance — delegate to WASM runtime
    async contextExecuteGovernanceAction(
      handle: BridgeContextHandle,
      actionJson: string,
      proposerDid: string,
    ): Promise<string> {
      const wasm = getWasm();
      // Generate a 64-char hex proposal ID (256-bit) matching native bridge
      // format (SHA-256 hex from scp-core's compute_proposal_id).
      const proposalId = generateProposalIdHex();
      return await wasm.context_execute_governance(handle, proposerDid, proposalId, actionJson);
    },

    // Governance proposal lifecycle (#621)
    async contextGovernancePropose(
      handle: BridgeContextHandle,
      actionJson: string,
      proposerDid: string,
    ): Promise<string> {
      const wasm = getWasm();
      const proposalId = generateProposalIdHex();
      return await wasm.context_governance_propose(handle, proposerDid, proposalId, actionJson);
    },
    async contextGovernanceApprove(
      handle: BridgeContextHandle,
      proposalIdHex: string,
      voterDid: string,
    ): Promise<string> {
      const wasm = getWasm();
      return await wasm.context_governance_approve(handle, proposalIdHex, voterDid);
    },
    async contextGovernanceReject(
      handle: BridgeContextHandle,
      proposalIdHex: string,
      voterDid: string,
    ): Promise<string> {
      const wasm = getWasm();
      return await wasm.context_governance_reject(handle, proposalIdHex, voterDid);
    },
    async contextGovernanceWithdraw(
      handle: BridgeContextHandle,
      proposalIdHex: string,
      voterDid: string,
    ): Promise<string> {
      const wasm = getWasm();
      return await wasm.context_governance_withdraw(handle, proposalIdHex, voterDid);
    },
    async contextGovernanceGetProposal(
      handle: BridgeContextHandle,
      proposalIdHex: string,
    ): Promise<string> {
      const wasm = getWasm();
      return await wasm.context_governance_get_proposal(handle, proposalIdHex);
    },
    async contextGovernanceListProposals(handle: BridgeContextHandle): Promise<string> {
      const wasm = getWasm();
      return await wasm.context_governance_list_proposals(handle);
    },

    // TTL operations
    async contextTtlRemaining(handle: BridgeContextHandle): Promise<number | null> {
      const wasm = getWasm();
      const remaining = wasm.context_ttl_remaining(handle);
      return remaining ?? null;
    },

    async contextExtendTtl(handle: BridgeContextHandle, additionalSecs: number): Promise<boolean> {
      const wasm = getWasm();
      return await wasm.context_extend_ttl(handle, additionalSecs);
    },

    async contextHandleTtlExpiry(handle: BridgeContextHandle): Promise<void> {
      const wasm = getWasm();
      await wasm.context_handle_ttl_expiry(handle);
    },

    async contextProposeTtlExtension(
      handle: BridgeContextHandle,
      proposerDid: string,
      extensionSecs: number,
    ): Promise<boolean> {
      const wasm = getWasm();
      return await wasm.context_propose_ttl_extension(handle, proposerDid, extensionSecs);
    },

    async contextResetTtlTimer(
      handle: BridgeContextHandle,
      newDurationSecs: number,
    ): Promise<void> {
      const wasm = getWasm();
      await wasm.context_reset_ttl_timer(handle, newDurationSecs);
    },

    // Economic policy (§19.3)
    async contextSetEconomicPolicy(handle: BridgeContextHandle, policyJson: string): Promise<void> {
      const wasm = getWasm();
      wasm.context_set_economic_policy(handle, policyJson);
    },

    async contextGetEconomicPolicy(handle: BridgeContextHandle): Promise<string | null> {
      const wasm = getWasm();
      return wasm.context_get_economic_policy(handle) ?? null;
    },

    // Context export/import
    async contextExport(handle: BridgeContextHandle): Promise<Uint8Array> {
      const wasm = getWasm();
      // WASM export returns Uint8Array directly — no base64 conversion needed.
      return await wasm.context_export(handle);
    },

    async contextImport(data: Uint8Array, _importerDid: string): Promise<string> {
      const wasm = getWasm();
      // WASM import takes Uint8Array directly — no base64 conversion needed.
      // §9.10.4 / ADR-034: the WASM bridge has no per-member pseudonym routing
      // (shared routing IDs only), so `importerDid` is intentionally ignored.
      return await wasm.context_import(data);
    },

    // §9.10.4 / ADR-034: the WASM bridge uses shared routing IDs and has no
    // per-member pseudonym registry, so there is nothing to seed. This test-only
    // helper is never used on the WASM path; reject loudly if it ever is.
    contextSeedPeerPseudonym(
      _handle: BridgeContextHandle,
      _peerDid: string,
      _pseudonym: Uint8Array,
    ): Promise<void> {
      return Promise.reject(
        new Error(
          "contextSeedPeerPseudonym is not supported on the WASM bridge " +
            "(ADR-034: shared routing IDs, no per-member pseudonym registry)",
        ),
      );
    },

    // Drain events
    async contextDrainEvents(handle: BridgeContextHandle): Promise<readonly string[]> {
      const wasm = getWasm();
      // context_drain_events is synchronous in the WASM export — no await needed.
      const json = wasm.context_drain_events(handle);
      return safeJsonParse(json, "context_drain_events") as string[];
    },

    // Tools -- delegates to WASM runtime registry
    async toolRegister(handle: BridgeContextHandle, definition: ToolDefinition): Promise<string> {
      const wasm = getWasm();
      const definitionJson = JSON.stringify({
        name: definition.name,
        description: definition.description,
        schema: {
          input: definition.inputSchema,
          output: definition.outputSchema,
        },
        operatorDid: definition.operator,
        testVectors: definition.testVectors?.map((tv) => ({
          input: tv.input,
          expectedOutput: tv.expectedOutput,
          description: tv.description,
        })),
        cost: definition.cost
          ? {
              amount: definition.cost.amount,
              currency: definition.cost.currency,
              payee: definition.cost.payee,
              costFormula: definition.cost.costFormula,
            }
          : undefined,
      });
      return await wasm.tool_register(handle, definitionJson);
    },

    async toolInvoke(
      handle: BridgeContextHandle,
      toolId: string,
      inputJson: string,
      identityDid: string,
      ucanToken: string,
      _proofTokens?: readonly string[],
      spendingUcan?: string,
    ): Promise<string> {
      // C4 (#1606): the WASM bridge has its own tool dispatch path
      // (ADR-034) and does NOT route through
      // ContextManager.invoke_tool_with_economy. Reject any
      // spendingUcan argument with a clear error rather than
      // silently dropping it — paid tool invocations require the
      // native (NAPI) bridge until the WASM economy path lands.
      if (spendingUcan !== undefined && spendingUcan !== null) {
        throw new ToolError(
          "spendingUcan is not supported by the WASM bridge — paid tool " +
            "invocations require the native (NAPI) bridge or the Python / " +
            "Swift / Kotlin SDKs (ADR-034). See issue #1606.",
          "SCP-TOOL-6041",
        );
      }
      const wasm = getWasm();
      return await wasm.tool_invoke(handle, toolId, inputJson, identityDid, ucanToken);
    },

    async toolVerify(handle: BridgeContextHandle, toolId: string): Promise<ToolVerificationResult> {
      const wasm = getWasm();
      const result = await wasm.tool_verify(handle, toolId);
      return {
        toolId: result.toolId,
        passed: result.passed,
        failures: safeJsonParse(
          result.failuresJson,
          "tool_verify",
        ) as ToolVerificationResult["failures"],
      };
    },

    // Bidirectional consent protocol (§6.2.0.1)
    async toolInterfaceExpose(
      handle: BridgeContextHandle,
      toolId: string,
      targetContextId: string,
      rateLimitJson?: string,
    ): Promise<string> {
      const wasm = getWasm();
      return await wasm.tool_interface_expose(handle, toolId, targetContextId, rateLimitJson);
    },

    async toolInterfaceAccept(handle: BridgeContextHandle, interfaceJson: string): Promise<string> {
      const wasm = getWasm();
      return await wasm.tool_interface_accept(handle, interfaceJson);
    },

    async toolInterfaceRevoke(
      handle: BridgeContextHandle,
      interfaceIdHex: string,
    ): Promise<string> {
      const wasm = getWasm();
      return await wasm.tool_interface_revoke(handle, interfaceIdHex);
    },

    // Cross-context tool invocation (spec section 6.2) — not available in WASM (ADR-034)
    async toolInvokeCrossContext(
      _sourceHandle: BridgeContextHandle,
      _targetHandle: BridgeContextHandle,
      _toolId: string,
      _inputJson: string,
      _invokerDid: string,
      _ucanToken: string,
      _chainDepth: number,
      _proofTokens?: readonly string[],
    ): Promise<string> {
      throw new ToolError(
        "toolInvokeCrossContext is not available in the WASM bridge (ADR-034). " +
          "Use the native (NAPI) bridge for cross-context tool invocation.",
        "SCP-TOOL-6040",
      );
    },

    // Stateful tool sessions (spec section 6.2.1) — not available in WASM (ADR-034)
    async toolSessionCreate(
      _handle: BridgeContextHandle,
      _toolId: string,
      _sourceContextId: string,
      _ttlSeconds?: number,
    ): Promise<string> {
      throw new ToolError(
        "toolSessionCreate is not available in the WASM bridge (ADR-034). " +
          "Use the native (NAPI) bridge for stateful tool sessions.",
        "SCP-TOOL-6040",
      );
    },

    async toolSessionInvoke(
      _handle: BridgeContextHandle,
      _sessionId: string,
      _inputJson: string,
      _invokerDid: string,
      _ucanToken: string,
      _proofTokens?: readonly string[],
    ): Promise<string> {
      throw new ToolError(
        "toolSessionInvoke is not available in the WASM bridge (ADR-034). " +
          "Use the native (NAPI) bridge for stateful tool sessions.",
        "SCP-TOOL-6040",
      );
    },

    async toolSessionClose(_handle: BridgeContextHandle, _sessionId: string): Promise<void> {
      throw new ToolError(
        "toolSessionClose is not available in the WASM bridge (ADR-034). " +
          "Use the native (NAPI) bridge for stateful tool sessions.",
        "SCP-TOOL-6040",
      );
    },

    // Transport
    async transportConnect(relayUrl: string): Promise<BridgeTransportHandle> {
      const wasm = getWasm();
      const status = await wasm.transport_connect(relayUrl);
      return { isConnected: status.connected, relayUrl: status.relayUrl };
    },

    async transportStatus(handle: BridgeTransportHandle): Promise<TransportStatus> {
      return { connected: handle.isConnected, relayUrl: handle.relayUrl, latencyMs: null };
    },

    async transportDisconnect(_handle: BridgeTransportHandle): Promise<void> {
      const wasm = getWasm();
      await wasm.transport_disconnect();
    },

    // UCAN -- delegates to WASM 11-step validation pipeline
    async ucanValidate(
      handle: BridgeContextHandle,
      token: string,
      capability: string,
    ): Promise<void> {
      const wasm = getWasm();
      // The WASM bridge expects an audience DID for step 5 validation.
      // Use the context creator DID as the expected audience.
      await wasm.ucan_validate(handle, token, capability, handle.creatorDid, undefined);
    },

    async ucanMint(
      handle: BridgeContextHandle,
      memberDid: string,
      capabilities: readonly string[],
      _proofs?: readonly string[],
    ): Promise<UcanToken> {
      const wasm = getWasm();
      const capabilitiesJson = JSON.stringify(capabilities);
      const result = await wasm.ucan_mint(handle, memberDid, capabilitiesJson);
      const token: UcanToken = {
        id: result.tokenId,
        encoded: result.encoded,
        issuer: result.issuer,
        audience: result.audience,
        capabilities: safeJsonParse(result.capabilitiesJson, "ucan_mint") as string[],
      };
      if (result.expiresAt != null) {
        return { ...token, expiresAt: result.expiresAt };
      }
      return token;
    },

    async ucanRevoke(
      handle: BridgeContextHandle,
      token: string,
      revokerDid: string,
    ): Promise<void> {
      const wasm = getWasm();
      await wasm.ucan_revoke(handle, token, revokerDid);
    },

    async ucanDelegate(
      handle: BridgeContextHandle,
      delegatorDid: string,
      delegateeDid: string,
      parentToken: string,
      capabilities: readonly string[],
    ): Promise<UcanToken> {
      const wasm = getWasm();
      const capabilitiesJson = JSON.stringify(capabilities);
      const result = await wasm.ucan_delegate(
        handle,
        delegatorDid,
        delegateeDid,
        parentToken,
        capabilitiesJson,
      );
      const token: UcanToken = {
        id: result.tokenId,
        encoded: result.encoded,
        issuer: result.issuer,
        audience: result.audience,
        capabilities: safeJsonParse(result.capabilitiesJson, "ucan_delegate") as string[],
      };
      if (result.expiresAt != null) {
        return { ...token, expiresAt: result.expiresAt };
      }
      return token;
    },

    // Trust Aggregation -- not available in WASM, delegates to WASM (throws)
    async aggregateTrustInput(
      contextId: string,
      subjectDid: string,
      eventsJson: string,
      merkleRootJson: string,
      consequenceRulesJson: string,
      thresholdRequirementsJson: string,
      attestorSetsJson: string,
      cachedAttestationsJson: string,
      challengeResultsJson: string,
    ): Promise<string> {
      const wasm = getWasm();
      return wasm.aggregate_trust_input(
        contextId,
        subjectDid,
        eventsJson,
        merkleRootJson,
        consequenceRulesJson,
        thresholdRequirementsJson,
        attestorSetsJson,
        cachedAttestationsJson,
        challengeResultsJson,
      ) as unknown as Promise<string>;
    },

    // Event Log -- delegates to WASM-local Merkle tree
    async eventLogQuery(
      handle: BridgeContextHandle,
      filter: EventFilter | undefined,
    ): Promise<readonly Event[]> {
      const wasm = getWasm();
      const filterJson = filter ? JSON.stringify(filter) : undefined;
      const resultJson = await wasm.event_log_query(handle, filterJson);
      const events = safeJsonParse(resultJson, "event_log_query") as Array<{
        eventType: string;
        actorDid: string;
        timestamp: number;
        payloadJson: string;
        sequence: number;
      }>;
      return events.map((e) => ({
        eventType: e.eventType,
        actorDid: e.actorDid,
        timestamp: e.timestamp,
        payload: safeJsonParse(e.payloadJson, "event_log_query") as Event["payload"],
        sequence: e.sequence,
      }));
    },

    async eventLogVerify(handle: BridgeContextHandle, claim: EventClaim): Promise<Proof> {
      const wasm = getWasm();
      const claimJson = JSON.stringify(claim);
      const result = await wasm.event_log_verify(handle, claimJson);
      return {
        verified: result.verified,
        proofType: result.proofType as "inclusion" | "absence",
        details: safeJsonParse(result.detailsJson, "event_log_verify") as Proof["details"],
      };
    },

    async eventLogCheckpoint(
      handle: BridgeContextHandle,
      identityDid: string,
      epoch: number,
    ): Promise<Checkpoint> {
      const wasm = getWasm();
      const result = await wasm.event_log_checkpoint(handle, identityDid, epoch);
      // WASM signs the checkpoint in-process with the identity's `#active`
      // Ed25519 key (WASM identities are Rust-custodied; the private key never
      // crosses FFI, ADR-006). Surface the flat signed checkpoint carrying the
      // signature, matching the NAPI bridge (see the `Checkpoint` type doc).
      return {
        contextId: result.contextId,
        senderDid: result.senderDid,
        merkleRoot: result.merkleRoot,
        eventCount: result.eventCount,
        // The WASM bridge surfaces `epoch` as `null` for Broadcast contexts;
        // normalize to `undefined` to match the `Checkpoint` optional field.
        epoch: result.epoch ?? undefined,
        timestamp: result.timestamp,
        signature: result.signature,
      };
    },

    // Bridge Connector
    bridgeRegister(
      contextId: string,
      operatorDid: string,
      governanceDid: string,
      platform: string,
      mode: BridgeMode,
    ) {
      const wasm = getWasm();
      return wasm.bridge_register(contextId, operatorDid, governanceDid, platform, mode);
    },

    bridgeEvaluateTrust(
      isBridged: boolean,
      isNativeTransport: boolean,
      shadowStatus: ShadowStatus,
    ) {
      const wasm = getWasm();
      return wasm.bridge_evaluate_trust(isBridged, isNativeTransport, shadowStatus);
    },

    bridgeCreateShadow(
      bridgeId: string,
      platformHandle: string,
      bridgeMode: BridgeMode,
      contextId: string | undefined,
    ) {
      const wasm = getWasm();
      return wasm.bridge_create_shadow(bridgeId, platformHandle, bridgeMode, contextId);
    },

    // Discovery
    discoveryParseAddress(address: string) {
      const wasm = getWasm();
      return wasm.discovery_parse_address(address);
    },

    discoveryCreateQuery(
      capabilities: string[] | undefined,
      keywords: string[] | undefined,
      minHistorySecs: number | undefined,
    ) {
      const wasm = getWasm();
      return wasm.discovery_create_query(
        capabilities ? JSON.stringify(capabilities) : undefined,
        keywords ? JSON.stringify(keywords) : undefined,
        minHistorySecs,
      );
    },

    discoveryNormalizeAddress(address: string) {
      const wasm = getWasm();
      return wasm.discovery_normalize_address(address);
    },

    async contextDiscover(query: string): Promise<string> {
      const wasm = getWasm();
      return await wasm.context_discover(query);
    },

    // Petnames (§22.4)
    petnameSet(ownerDid: string, targetDid: string, name: string): void {
      const wasm = getWasm();
      wasm.petname_set(ownerDid, targetDid, name);
    },

    petnameRemove(ownerDid: string, targetDid: string): void {
      const wasm = getWasm();
      wasm.petname_remove(ownerDid, targetDid);
    },

    petnameSetContext(ownerDid: string, contextId: string, name: string): void {
      const wasm = getWasm();
      wasm.petname_set_context(ownerDid, contextId, name);
    },

    petnameRemoveContext(ownerDid: string, contextId: string): void {
      const wasm = getWasm();
      wasm.petname_remove_context(ownerDid, contextId);
    },

    petnameResolveDid(ownerDid: string, name: string): string {
      const wasm = getWasm();
      return wasm.petname_resolve_did(ownerDid, name);
    },

    petnameResolveContext(ownerDid: string, name: string): string {
      const wasm = getWasm();
      return wasm.petname_resolve_context(ownerDid, name);
    },

    petnameGetForDid(ownerDid: string, targetDid: string): string | null {
      const wasm = getWasm();
      const result = wasm.petname_get_for_did(ownerDid, targetDid);
      if (result == null || result === undefined) return null;
      return result as string;
    },

    petnameGetForContext(ownerDid: string, contextId: string): string | null {
      const wasm = getWasm();
      const result = wasm.petname_get_for_context(ownerDid, contextId);
      if (result == null || result === undefined) return null;
      return result as string;
    },

    petnameApplyEvent(ownerDid: string, eventJson: string): void {
      const wasm = getWasm();
      wasm.petname_apply_event(ownerDid, eventJson);
    },

    petnameDidCount(ownerDid: string): number {
      const wasm = getWasm();
      return wasm.petname_did_count(ownerDid);
    },

    petnameContextCount(ownerDid: string): number {
      const wasm = getWasm();
      return wasm.petname_context_count(ownerDid);
    },

    // Handle Registry (§22.3.1)
    handleRegister(
      discoveryContextId: string,
      handle: string,
      targetJson: string,
      registrantDid: string,
      description: string | undefined,
      tags: string[] | undefined,
    ): string {
      const wasm = getWasm();
      return wasm.handle_register(
        discoveryContextId,
        handle,
        targetJson,
        registrantDid,
        description,
        tags ? JSON.stringify(tags) : undefined,
      );
    },

    handleLookup(
      discoveryContextId: string,
      handle: string,
      typeFilter: string | undefined,
    ): string {
      const wasm = getWasm();
      return wasm.handle_lookup(discoveryContextId, handle, typeFilter);
    },

    handleDeregister(discoveryContextId: string, handle: string, did: string): string {
      const wasm = getWasm();
      return wasm.handle_deregister(discoveryContextId, handle, did);
    },

    // Scope Registry (§22.3.5, ADR-043)
    scopeRegister(
      scopeContextId: string,
      name: string,
      targetContextId: string,
      relayUrls: string[],
      registrantDid: string,
      description: string | undefined,
      tags: string[] | undefined,
    ): string {
      const wasm = getWasm();
      return wasm.scope_register(
        scopeContextId,
        name,
        targetContextId,
        JSON.stringify(relayUrls),
        registrantDid,
        description,
        tags ? JSON.stringify(tags) : undefined,
      );
    },

    scopeLookup(scopeContextId: string, name: string): string {
      const wasm = getWasm();
      return wasm.scope_lookup(scopeContextId, name);
    },

    scopeDeregister(scopeContextId: string, name: string, did: string): string {
      const wasm = getWasm();
      return wasm.scope_deregister(scopeContextId, name, did);
    },

    // Address Resolution (§22.8)
    async addressResolve(
      ownerDid: string,
      address: string,
      knownContextsJson: string | undefined,
    ): Promise<string> {
      const wasm = getWasm();
      return await wasm.address_resolve(ownerDid, address, knownContextsJson);
    },

    // Provenance
    async evaluateProvenanceQuality(
      sourceContext: string | undefined,
      sourceType: string,
      contextState: string,
      counterparties: string[] | undefined,
    ): Promise<number> {
      const wasm = getWasm();
      return wasm.evaluate_provenance_quality(
        sourceContext,
        sourceType,
        contextState,
        counterparties ? JSON.stringify(counterparties) : undefined,
      );
    },

    provenanceAttach(
      sourceContextId: string,
      sourceType: string,
      memoryScope: string,
      members: string[],
      targetContextId: string,
      actorDid: string,
      existingChainDepth: number | undefined,
      discoveryMethod: string | undefined,
      purpose: string | undefined,
      _counterpartyPolicy: string | undefined,
    ) {
      const wasm = getWasm();
      // WASM bridge uses Option<u32> for existing_chain_depth: undefined/null
      // signals first hop (chain_depth 0), matching NAPI bridge semantics.
      // counterpartyPolicy is intentionally not forwarded to the WASM bridge.
      // The WASM bridge re-implements provenance locally (no scp-core dependency
      // per ADR-034) and its provenance_attach Rust export does not accept a
      // counterpartyPolicy parameter. The counterparty list is still included
      // in the record (via the members/counterparties_json param); only the
      // *policy* controlling how counterparties are represented (full /
      // pseudonymized / redacted) is unavailable in the WASM path. Callers
      // needing counterpartyPolicy support should use the native (napi-rs)
      // bridge.
      return wasm.provenance_attach(
        sourceContextId,
        sourceType,
        memoryScope,
        JSON.stringify(members),
        targetContextId,
        actorDid,
        existingChainDepth,
        "[]",
        discoveryMethod ?? undefined,
        purpose ?? undefined,
      );
    },

    provenanceCheckChainDepth(chainDepth: number, maxDepth: number | undefined) {
      const wasm = getWasm();
      return wasm.provenance_check_chain_depth(chainDepth, maxDepth);
    },

    // Sync
    syncClassifyOffline(lastRelayContact: number, now: number) {
      const wasm = getWasm();
      return wasm.sync_classify_offline(lastRelayContact, now);
    },

    syncClassifyOfflineCustom(
      lastRelayContact: number,
      now: number,
      tier1ThresholdSecs: number,
      tier2ThresholdSecs: number,
    ) {
      const wasm = getWasm();
      return wasm.sync_classify_offline_custom(
        lastRelayContact,
        now,
        tier1ThresholdSecs,
        tier2ThresholdSecs,
      );
    },

    syncGetPolicy() {
      const wasm = getWasm();
      return wasm.sync_get_policy();
    },

    // Identity Advanced
    async identityCreateWithAgentKey(custody: string): Promise<BridgeIdentityHandle> {
      const wasm = getWasm();
      const handle = await wasm.identity_create_with_agent_key(custody);
      return { did: handle.did, custodyType: handle.custodyType };
    },

    async identityAddAgentKey(handle: BridgeIdentityHandle): Promise<BridgeIdentityHandle> {
      const wasm = getWasm();
      const updated = wasm.identity_add_agent_key(handle);
      return { did: updated.did, custodyType: updated.custodyType };
    },

    async identityRotateAgentKey(handle: BridgeIdentityHandle): Promise<BridgeIdentityHandle> {
      const wasm = getWasm();
      const updated = wasm.identity_rotate_agent_key(handle);
      return { did: updated.did, custodyType: updated.custodyType };
    },

    async identityRemoveAgentKey(handle: BridgeIdentityHandle): Promise<BridgeIdentityHandle> {
      const wasm = getWasm();
      const updated = wasm.identity_remove_agent_key(handle);
      return { did: updated.did, custodyType: updated.custodyType };
    },

    async identityMigrate(handle: BridgeIdentityHandle): Promise<BridgeIdentityHandle> {
      const wasm = getWasm();
      const result = await wasm.identity_migrate(handle);
      // The WASM bridge returns the migrated identity AND a JSON-
      // serialized `DidRotationEvent` carrying the migration +
      // pre-rotation proofs. The SDK layer distributes the event to
      // active context members per spec §3.2.1 step 4b.
      return {
        did: result.identity.did,
        custodyType: result.identity.custodyType,
        rotationEventJson: result.rotationEventJson,
      };
    },

    async identityAttestDevice(did: string): Promise<string> {
      const wasm = getWasm();
      return await wasm.identity_attest_device(did);
    },

    async identityVerifyDeviceAttestation(did: string, tokenBase64: string): Promise<boolean> {
      const wasm = getWasm();
      return await wasm.identity_verify_device_attestation(did, tokenBase64);
    },

    // Identity link attestation (§3.5.1)
    async identityCreateLinkAttestation(
      did: string,
      platform: string,
      handle: string,
      proof: string,
      verificationMethod: string,
      platformId: string | null,
    ): Promise<string> {
      const wasm = getWasm();
      return await wasm.identity_create_link_attestation(
        did,
        platform,
        handle,
        proof,
        verificationMethod,
        platformId ?? undefined,
      );
    },

    identityLinkAttestations(did: string): string {
      const wasm = getWasm();
      return wasm.identity_link_attestations(did);
    },

    identityRemoveLinkAttestation(did: string, attestationId: string): boolean {
      const wasm = getWasm();
      return wasm.identity_remove_link_attestation(did, attestationId);
    },

    identityRemove(did: string): void {
      const wasm = getWasm();
      wasm.identity_remove(did);
    },

    identityRemoveIfPresent(did: string): boolean {
      const wasm = getWasm();
      return wasm.identity_remove_if_present(did);
    },

    async identityVerifyLinkAttestation(
      attestationJson: string,
      issuerPublicKeyHex: string,
    ): Promise<boolean> {
      const wasm = getWasm();
      return await wasm.identity_verify_link_attestation(attestationJson, issuerPublicKeyHex);
    },

    // Recovery and custody migration (#632, spec §9.12, §3.2.1)
    async identityExecuteRecovery(
      did: string,
      tier: string,
      contextIds: string[],
    ): Promise<string> {
      const wasm = getWasm();
      return wasm.identity_execute_recovery(did, tier, contextIds);
    },

    async identityExecuteCustodyMigration(
      did: string,
      target: string,
      contextIds: string[],
    ): Promise<string> {
      const wasm = getWasm();
      return wasm.identity_execute_custody_migration(did, target, contextIds);
    },

    // App Sandboxing (#595, spec §8.4.1, §8.4.2)
    validateCapabilityDeclaration(
      declarationJson: string,
      ceilingCapabilities: string[],
      roleCapabilities: string[],
    ): string {
      const wasm = getWasm();
      return wasm.sandbox_validate_declaration(
        declarationJson,
        ceilingCapabilities,
        roleCapabilities,
      );
    },

    checkScopedCapability(
      grantedCapabilities: readonly string[],
      requiredCapability: string,
    ): boolean {
      const wasm = getWasm();
      return wasm.sandbox_check_capability([...grantedCapabilities], requiredCapability);
    },

    // SCPID authentication (§3.11)
    scpidChallenge(audience: string, ttlSeconds: number): string {
      const wasm = getWasm();
      return wasm.scpid_challenge(audience, ttlSeconds);
    },

    scpidSign(did: string, signingKeyId: string, challengeJson: string): string {
      const wasm = getWasm();
      return wasm.scpid_sign(did, signingKeyId, challengeJson);
    },

    scpidVerify(_responseJson: string, _challengeJson: string): string {
      throw new IdentityError(
        "SCPID verification is not available in the WASM bridge — " +
          "it requires DID document resolution which depends on network access " +
          "and a full DID resolver. Use the native (napi-rs) bridge instead.",
        "SCP-IDENT-1033",
      );
    },

    // Trust — participation verification (SCP-BA-004, §7.3.2.1)
    verifyParticipationRequirements(profileJson: string, requirementsJson: string): boolean {
      const wasm = getWasm();
      // The WASM bridge function is synchronous (returns Result<bool, JsValue>).
      // Throws on validation/verification failure.
      return wasm.verify_participation_requirements(profileJson, requirementsJson) as boolean;
    },

    // Invitation evaluation
    evaluateInvitation(
      paramsJson: string,
      inviterDid: string,
      identityDid: string,
      policyJson: string | null,
      spendingJson: string | null,
      trustedDidsJson: string | null,
    ) {
      const wasm = getWasm();
      return wasm.evaluate_invitation(
        paramsJson,
        inviterDid,
        identityDid,
        policyJson,
        spendingJson,
        trustedDidsJson,
      );
    },

    // MetadataRecord inspection (§5.7.2, #615)
    metadataRecordToJson(
      contextId: string,
      sequence: number,
      signerDid: string,
      timestamp: number,
      structuralJson: string,
      operationalJson: string,
      signatureHex: string,
    ): string {
      const wasm = getWasm();
      return wasm.metadata_record_to_json(
        contextId,
        sequence,
        signerDid,
        timestamp,
        structuralJson,
        operationalJson,
        signatureHex,
      );
    },

    metadataRecordFromJson(jsonStr: string): string {
      const wasm = getWasm();
      return wasm.metadata_record_from_json(jsonStr);
    },

    // Context template inspection (§5.14, #615)
    templateGetParams(templateId: string): string {
      const wasm = getWasm();
      return wasm.template_get_params(templateId);
    },

    validateAgainstTemplate(paramsJson: string): string | null {
      const wasm = getWasm();
      return wasm.validate_against_template(paramsJson);
    },

    validateContextParams(paramsJson: string): string | null {
      const wasm = getWasm();
      return wasm.validate_context_params(paramsJson);
    },

    // Economy (§19, ADR-033)
    economyEstimateCost(policyJson: string, actionType: string, metricsJson: string): number {
      const wasm = getWasm();
      return wasm.economy_estimate_cost(policyJson, actionType, metricsJson);
    },

    economyPolicyRequiresPayment(policyJson: string): boolean {
      const wasm = getWasm();
      return wasm.economy_policy_requires_payment(policyJson);
    },

    economyAutoAcceptBlocked(policyJson: string): boolean {
      const wasm = getWasm();
      return wasm.economy_auto_accept_blocked(policyJson);
    },

    economyCheckPolicyLock(policyJson: string): boolean {
      const wasm = getWasm();
      return wasm.economy_check_policy_lock(policyJson);
    },

    economyValidatePolicyChange(currentJson: string, proposedJson: string): boolean {
      const wasm = getWasm();
      return wasm.economy_validate_policy_change(currentJson, proposedJson);
    },

    economyEvaluateFormula(formulaJson: string, metricsJson: string): number {
      const wasm = getWasm();
      return wasm.economy_evaluate_formula(formulaJson, metricsJson);
    },

    economyBudgetRemaining(contextId: string, did: string): number {
      const wasm = getWasm();
      return wasm.economy_budget_remaining(contextId, did);
    },

    economyBudgetGrant(contextId: string, did: string, amount: number): void {
      const wasm = getWasm();
      wasm.economy_budget_grant(contextId, did, amount);
    },

    economyBudgetRecordSpend(contextId: string, did: string, amount: number): void {
      const wasm = getWasm();
      wasm.economy_budget_record_spend(contextId, did, amount);
    },

    economyAntispamRecord(contextId: string, senderDid: string, timestamp: number): void {
      const wasm = getWasm();
      wasm.economy_antispam_record(contextId, senderDid, timestamp);
    },

    economyAntispamVelocity(contextId: string, senderDid: string, now: number): number {
      const wasm = getWasm();
      return wasm.economy_antispam_velocity(contextId, senderDid, now);
    },

    economyAntispamEscalatedCost(
      contextId: string,
      senderDid: string,
      now: number,
      baseCost: number,
      thresholdsJson: string,
      floor: number | null,
      cap: number | null,
    ): number {
      const wasm = getWasm();
      return wasm.economy_antispam_escalated_cost(
        contextId,
        senderDid,
        now,
        baseCost,
        thresholdsJson,
        floor,
        cap,
      );
    },

    economyVerifyPaymentReceipts(_receiptsJson: string): string {
      // The WASM bridge has no runtime payment adapter — `scp-runtime`'s
      // payment-receipt verification path does not compile to `wasm32`
      // per ADR-034. The method must exist (the shared `ScpBridge`
      // interface requires it) but is rejected fail-closed rather than
      // returning a fabricated result.
      throw new EconomicPolicyUnsupportedOnWasm(
        "economyVerifyPaymentReceipts is not supported by the WASM bridge — " +
          "payment-receipt verification requires a native client whose " +
          "bridge runs the payment adapter (the NAPI / Python / Swift / " +
          "Kotlin SDKs) per ADR-034.",
        "SCP-ECON-12095",
      );
    },

    // Media (ADR-024)
    mediaCheckCapability(ceiling: string[], capability: string): boolean {
      const wasm = getWasm();
      return wasm.media_check_capability(ceiling, capability);
    },

    mediaInitiateSession(
      contextId: string,
      ceiling: string[],
      capabilities: string[],
      participants: string[],
      timestamp: number,
    ): string {
      const wasm = getWasm();
      return wasm.media_initiate_session(contextId, ceiling, capabilities, participants, timestamp);
    },

    mediaActivateSession(sessionJson: string): string {
      const wasm = getWasm();
      return wasm.media_activate_session(sessionJson);
    },

    mediaJoinSession(sessionJson: string, participantDid: string): string {
      const wasm = getWasm();
      return wasm.media_join_session(sessionJson, participantDid);
    },

    mediaEndSession(sessionJson: string, timestamp: number): string {
      const wasm = getWasm();
      return wasm.media_end_session(sessionJson, timestamp);
    },

    mediaCreateOffer(sessionId: string, sdp: string, senderDid: string): string {
      const wasm = getWasm();
      return wasm.media_create_offer(sessionId, sdp, senderDid);
    },

    mediaCreateAnswer(sessionId: string, sdp: string, senderDid: string): string {
      const wasm = getWasm();
      return wasm.media_create_answer(sessionId, sdp, senderDid);
    },

    mediaCreateIceCandidate(
      sessionId: string,
      candidate: string,
      senderDid: string,
      sdpMid?: string,
      sdpMlineIndex?: number,
    ): string {
      const wasm = getWasm();
      return wasm.media_create_ice_candidate(
        sessionId,
        candidate,
        senderDid,
        sdpMid,
        sdpMlineIndex,
      );
    },

    mediaCreateSessionEnd(sessionId: string, senderDid: string): string {
      const wasm = getWasm();
      return wasm.media_create_session_end(sessionId, senderDid);
    },

    mediaSendSignaling(signalingJson: string): string {
      const wasm = getWasm();
      return wasm.media_send_signaling(signalingJson);
    },

    mediaVerifySenderAttribution(signalingJson: string, envelopeSenderDid: string): boolean {
      const wasm = getWasm();
      return wasm.media_verify_sender_attribution(signalingJson, envelopeSenderDid);
    },

    // Lifecycle
    version(): string {
      const wasm = getWasm();
      return wasm.scp_version();
    },

    // eslint-disable-next-line @typescript-eslint/require-await -- WASM has no bridge state to drain, but the signature must match the NAPI async shutdown for isomorphic callers.
    async shutdown(_timeoutMillis: number): Promise<void> {
      // No-op in the WASM bridge -- browser manages resource cleanup.
    },

    suspend(): void {
      // No-op in the WASM bridge -- there is no BridgeInstance in WASM
      // (ADR-034: WASM has no tokio runtime or relay connection to clear).
      // Provided for API parity with the NAPI bridge so isomorphic
      // callers can share code.
    },

    resume(): Promise<void> {
      // No-op in the WASM bridge -- see `suspend` for rationale. The
      // NAPI `resume` became async after #1678 so the Bridge
      // interface is now promise-returning; this WASM shim resolves
      // immediately to keep the await-chain uniform across targets.
      return Promise.resolve();
    },
  };
}
