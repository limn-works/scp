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
  identity_load: (did: string) => Promise<{ did: string; custodyType: string }>;
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
      if (custody === "in_memory" || custody === "js_custody") {
        const handle = await wasm.identity_load("did:dht:placeholder");
        return { did: handle.did, custodyType: custody };
      }
      throw new TransportError(
        `Custody type "${custody}" is not supported in the browser WASM bridge. ` +
          'Use "js_custody" or "in_memory" for browser environments.',
        "SCP-TRANS-5003",
      );
    },

    async identityLoad(did: string): Promise<BridgeIdentityHandle> {
      const wasm = getWasm();
      const handle = await wasm.identity_load(did);
      return { did: handle.did, custodyType: handle.custodyType };
    },

    async identityResolve(did: string): Promise<DIDDocument> {
      return {
        id: did,
        verificationMethods: [],
        authentication: [],
        assertionMethods: [],
        alsoKnownAs: [],
        serviceEndpoints: [],
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

    // Tools -- WASM bridge stubs (require JS-side implementation)
    async toolRegister(_handle: BridgeContextHandle, _definition: ToolDefinition): Promise<string> {
      throw new TransportError(
        "Tool registration in the WASM bridge requires runtime wiring",
        "SCP-TOOL-6001",
      );
    },

    async toolInvoke(
      _handle: BridgeContextHandle,
      _toolId: string,
      _inputJson: string,
      _identityDid: string,
    ): Promise<string> {
      throw new TransportError(
        "Tool invocation in the WASM bridge requires runtime wiring",
        "SCP-TOOL-6001",
      );
    },

    async toolVerify(
      _handle: BridgeContextHandle,
      _toolId: string,
    ): Promise<ToolVerificationResult> {
      throw new TransportError(
        "Tool verification in the WASM bridge requires runtime wiring",
        "SCP-TOOL-6001",
      );
    },

    // Transport
    async transportConnect(relayUrl: string): Promise<BridgeTransportHandle> {
      return { isConnected: true, relayUrl };
    },

    async transportStatus(handle: BridgeTransportHandle): Promise<TransportStatus> {
      return { connected: handle.isConnected, relayUrl: handle.relayUrl, latencyMs: null };
    },

    async transportDisconnect(_handle: BridgeTransportHandle): Promise<void> {
      // WebSocket disconnect -- handled by the browser runtime.
    },

    // UCAN -- WASM bridge stubs
    async ucanValidate(
      _handle: BridgeContextHandle,
      _token: string,
      _capability: string,
    ): Promise<void> {
      throw new TransportError(
        "UCAN validation in the WASM bridge requires runtime wiring",
        "SCP-PERM-3001",
      );
    },

    async ucanMint(
      _handle: BridgeContextHandle,
      _memberDid: string,
      _capabilities: readonly string[],
    ): Promise<UcanToken> {
      throw new TransportError(
        "UCAN minting in the WASM bridge requires runtime wiring",
        "SCP-PERM-3002",
      );
    },

    async ucanRevoke(_handle: BridgeContextHandle, _token: string): Promise<void> {
      throw new TransportError(
        "UCAN revocation in the WASM bridge requires runtime wiring",
        "SCP-PERM-3003",
      );
    },

    // Event Log -- WASM bridge stubs
    async eventLogQuery(
      _handle: BridgeContextHandle,
      _filter: EventFilter | undefined,
    ): Promise<readonly Event[]> {
      throw new TransportError(
        "Event log query in the WASM bridge requires runtime wiring",
        "SCP-CTX-2023",
      );
    },

    async eventLogVerify(_handle: BridgeContextHandle, _claim: EventClaim): Promise<Proof> {
      throw new TransportError(
        "Event log verification in the WASM bridge requires runtime wiring",
        "SCP-CTX-2025",
      );
    },

    async eventLogCheckpoint(_handle: BridgeContextHandle): Promise<Checkpoint> {
      throw new TransportError(
        "Event log checkpoint in the WASM bridge requires runtime wiring",
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
