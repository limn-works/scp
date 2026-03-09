/**
 * wasm-bindgen WASM bridge adapter for browser environments.
 *
 * This module wraps the wasm-bindgen generated module (`@scp/sdk-wasm`)
 * into the unified `Bridge` interface consumed by the TypeScript SDK.
 *
 * WASM initialization is performed lazily via `initWasm()`, which must be
 * called once before any bridge functions are invoked. The `getBridge()`
 * function in `bridge.ts` handles this automatically.
 *
 * See ADR-022 in `.docs/adrs/phase-4.md`.
 */

import { TransportError } from "../errors.js";
import type {
  Checkpoint,
  DIDDocument,
  Event,
  EventClaim,
  EventFilter,
  Proof,
  ToolDefinition,
  ToolVerificationResult,
  TransportStatus,
  UcanToken,
} from "../types.js";
import type {
  Bridge,
  BridgeContextHandle,
  BridgeIdentityHandle,
  BridgeTransportHandle,
  MessageCallback,
} from "./bridge.js";

// ---------------------------------------------------------------------------
// WASM module types
// ---------------------------------------------------------------------------

/** The shape of the wasm-bindgen generated module. */
interface WasmModule {
  default: () => Promise<void>;
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
  context_join: (handle: BridgeContextHandle, identityDid: string) => Promise<void>;
  context_leave: (handle: BridgeContextHandle, identityDid: string) => Promise<void>;
  context_close: (handle: BridgeContextHandle, identityDid: string) => Promise<void>;
  context_send: (
    handle: BridgeContextHandle,
    identityDid: string,
    payloadBase64: string,
  ) => Promise<void>;
  context_subscribe: (
    handle: BridgeContextHandle,
    callback: {
      onMessage: (msg: {
        senderDid: string;
        payloadBase64: string;
        timestamp: number;
        contextId: string;
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
  ) => Promise<string>;
  tool_verify: (
    handle: BridgeContextHandle,
    toolId: string,
  ) => Promise<{ toolId: string; passed: boolean; failuresJson: string }>;
  transport_connect: (relayUrl: string) => Promise<{
    connected: boolean;
    relayUrl: string | null;
    latencyMs: number | null;
  }>;
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
  ucan_revoke: (handle: BridgeContextHandle, token: string) => Promise<void>;
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
      // This package is produced by `wasm-pack build --target bundler`
      // and may not be installed in all environments.
      const mod = (await import(
        /* webpackIgnore: true */ "@scp/sdk-wasm"
      )) as unknown as WasmModule;
      await mod.default();
      mod.scp_init();
      _wasmModule = mod;
    } catch (err) {
      _initPromise = null;
      throw new TransportError(
        `Failed to initialize WASM module: ${err instanceof Error ? err.message : String(err)}. ` +
          "Ensure @scp/sdk-wasm is installed and the WASM binary is accessible.",
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
      return {
        id: doc.id,
        verificationMethods: JSON.parse(doc.verificationMethodsJson),
        authentication: JSON.parse(doc.authenticationJson),
        assertionMethods: JSON.parse(doc.assertionMethodsJson),
        alsoKnownAs: JSON.parse(doc.alsoKnownAsJson),
        serviceEndpoints: JSON.parse(doc.servicesJson),
      };
    },

    async identityRotateKey(_handle: BridgeIdentityHandle): Promise<BridgeIdentityHandle> {
      throw new TransportError(
        "Key rotation in the browser requires WebCrypto orchestration -- " +
          "this operation is not yet supported in the WASM bridge",
        "SCP-TRANS-5004",
      );
    },

    // Context
    async contextCreate(
      identity: BridgeIdentityHandle,
      paramsJson: string,
    ): Promise<BridgeContextHandle> {
      const wasm = getWasm();
      // WASM bridge uses identity.did since wasm_bindgen context_create takes a DID string.
      const handle = await wasm.context_create(identity.did, paramsJson);
      return {
        contextId: handle.contextId,
        state: handle.state,
        creatorDid: handle.creatorDid,
      };
    },

    async contextJoin(handle: BridgeContextHandle, identityDid: string): Promise<void> {
      const wasm = getWasm();
      await wasm.context_join(handle, identityDid);
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
    ): Promise<void> {
      const wasm = getWasm();
      const payloadBase64 = uint8ToBase64(payload);
      await wasm.context_send(handle, identityDid, payloadBase64);
    },

    contextSubscribe(
      handle: BridgeContextHandle,
      _identityDid: string,
      callback: MessageCallback,
    ): void {
      const wasm = getWasm();
      wasm.context_subscribe(handle, {
        onMessage: (msg) => {
          callback.onMessage({
            senderDid: msg.senderDid,
            content: base64ToUint8(msg.payloadBase64),
            timestamp: msg.timestamp,
            sequence: 0,
            contextId: msg.contextId,
          });
        },
        onComplete: () => {
          callback.onComplete();
        },
      });
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
        })),
      });
      return await wasm.tool_register(handle, definitionJson);
    },

    async toolInvoke(
      handle: BridgeContextHandle,
      toolId: string,
      inputJson: string,
      identityDid: string,
    ): Promise<string> {
      const wasm = getWasm();
      return await wasm.tool_invoke(handle, toolId, inputJson, identityDid);
    },

    async toolVerify(handle: BridgeContextHandle, toolId: string): Promise<ToolVerificationResult> {
      const wasm = getWasm();
      const result = await wasm.tool_verify(handle, toolId);
      return {
        toolId: result.toolId,
        passed: result.passed,
        failures: JSON.parse(result.failuresJson),
      };
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
      // WebSocket disconnect -- handled by the browser runtime.
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
    ): Promise<UcanToken> {
      const wasm = getWasm();
      const capabilitiesJson = JSON.stringify(capabilities);
      const result = await wasm.ucan_mint(handle, memberDid, capabilitiesJson);
      const token: UcanToken = {
        id: result.tokenId,
        encoded: result.encoded,
        issuer: result.issuer,
        audience: result.audience,
        capabilities: JSON.parse(result.capabilitiesJson) as string[],
      };
      if (result.expiresAt != null) {
        return { ...token, expiresAt: result.expiresAt };
      }
      return token;
    },

    async ucanRevoke(handle: BridgeContextHandle, token: string): Promise<void> {
      const wasm = getWasm();
      await wasm.ucan_revoke(handle, token);
    },

    // Event Log -- delegates to WASM-local Merkle tree
    async eventLogQuery(
      handle: BridgeContextHandle,
      filter: EventFilter | undefined,
    ): Promise<readonly Event[]> {
      const wasm = getWasm();
      const filterJson = filter ? JSON.stringify(filter) : undefined;
      const resultJson = await wasm.event_log_query(handle, filterJson);
      const events: Array<{
        eventType: string;
        actorDid: string;
        timestamp: number;
        payloadJson: string;
        sequence: number;
      }> = JSON.parse(resultJson);
      return events.map((e) => ({
        eventType: e.eventType,
        actorDid: e.actorDid,
        timestamp: e.timestamp,
        payload: JSON.parse(e.payloadJson),
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
        details: JSON.parse(result.detailsJson),
      };
    },

    async eventLogCheckpoint(_handle: BridgeContextHandle): Promise<Checkpoint> {
      // Checkpoint requires access to the Merkle root — this is not directly
      // exposed via a dedicated WASM export yet. Return a minimal checkpoint
      // from available data. The WASM bridge stores the Merkle tree internally;
      // the root is accessible via event_log_verify with a known leaf.
      throw new TransportError(
        "Event log checkpoint in the WASM bridge requires a dedicated export",
        "SCP-CTX-2027",
      );
    },

    // Lifecycle
    version(): string {
      const wasm = getWasm();
      return wasm.scp_version();
    },

    shutdown(_timeoutSecs: number): void {
      // No-op in the WASM bridge -- browser manages resource cleanup.
    },
  };
}
