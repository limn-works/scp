/**
 * Cross-bridge E2E tests: NAPI Node (server with TLS) + WASM (browser client).
 *
 * These tests verify that both the NAPI and WASM bridges can operate in the
 * same process, exercising the cross-bridge interop surface:
 *
 * - NAPI `nodeStartInMemory()` starts a Node with self-signed TLS, exposing
 *   a `wss://` relay URL.
 * - WASM `transport_connect` validates the `wss://` URL (browser WebSocket
 *   lifecycle is managed by the TypeScript wrapper, not the Rust bridge).
 * - Both bridges can independently create `did:dht` identities.
 * - WASM can create contexts and send MLS-encrypted messages.
 *
 * Prerequisites:
 * - NAPI bridge compiled with `allow_in_memory_custody` feature.
 * - WASM bridge compiled with `wasm-pack build crates/scp-ffi/wasm --target bundler`.
 * - Web-target build available at `crates/scp-ffi/wasm/pkg-web/`
 *   (symlinked to `node_modules/@limn-works/scp-ts-wasm`).
 *
 * If either bridge is unavailable, all tests are skipped gracefully.
 */

import { afterAll, beforeAll, describe, expect, test } from "bun:test";

// ---------------------------------------------------------------------------
// Guard: load both NAPI and WASM bridges, skip if either is unavailable
// ---------------------------------------------------------------------------

type NativeBridge = Awaited<ReturnType<typeof import("../src/internal/bridge").getBridge>>;

interface ServerAddon {
  nodeStartInMemory(): Promise<{
    readonly relayUrl: string;
    readonly relayPort: number;
    readonly did: string;
    readonly isShutdown: boolean;
    shutdown(): void;
  }>;
  transportConnect(relayUrl: string): Promise<unknown>;
}

// biome-ignore lint/suspicious/noExplicitAny: raw WASM module has dynamic shape
let wasmModule: any = null;
let napiBridge: NativeBridge | null = null;
let serverAddon: ServerAddon | null = null;
let skipReason = "";

try {
  // Load NAPI bridge
  const { createNativeBridge } = await import("../src/internal/native.js");
  napiBridge = createNativeBridge();

  // Load NAPI server addon
  const { createRequire } = await import("node:module");
  const req = createRequire(import.meta.url);
  const platform = process.platform;
  const arch = process.arch;
  const platformMap: Record<string, string> = {
    "linux-x64": "@limn-works/scp-ts-napi-linux-x64-gnu",
    "linux-arm64": "@limn-works/scp-ts-napi-linux-arm64-gnu",
    "darwin-x64": "@limn-works/scp-ts-napi-darwin-x64",
    "darwin-arm64": "@limn-works/scp-ts-napi-darwin-arm64",
    "win32-x64": "@limn-works/scp-ts-napi-win32-x64-msvc",
  };
  const pkg = platformMap[`${platform}-${arch}`];
  if (pkg) {
    serverAddon = req(pkg) as ServerAddon;
  } else {
    throw new Error(`No native addon for ${platform}-${arch}`);
  }

  // Load WASM bridge
  const { initWasm } = await import("../src/internal/wasm");
  await initWasm();
  wasmModule = await import("@limn-works/scp-ts-wasm");
} catch (e: unknown) {
  const msg = e instanceof Error ? e.message : String(e);
  skipReason = `Bridge(s) not available: ${msg}`;
}

if (napiBridge === null || serverAddon === null || wasmModule === null) {
  describe("Cross-bridge E2E: NAPI Node + WASM (SKIPPED)", () => {
    test.skip(`all tests skipped: ${skipReason}`, () => {});
  });
} else {
  // Capture for type narrowing.
  const napi = napiBridge;
  const addon = serverAddon;
  const wasm = wasmModule;

  // -------------------------------------------------------------------------
  // Node lifecycle state
  // -------------------------------------------------------------------------

  let nodeHandle: Awaited<ReturnType<typeof addon.nodeStartInMemory>> | null = null;

  beforeAll(async () => {
    nodeHandle = await addon.nodeStartInMemory();
  });

  afterAll(async () => {
    if (nodeHandle && !nodeHandle.isShutdown) {
      nodeHandle.shutdown();
    }
  });

  // -------------------------------------------------------------------------
  // 1. WASM connects to NAPI Node via wss://
  // -------------------------------------------------------------------------

  describe("WASM transport_connect to NAPI Node relay", () => {
    test("Node starts and reports a relay URL", () => {
      expect(nodeHandle).not.toBeNull();
      // Node relay URL is either ws:// (NAT fallback) or wss:// (domain mode).
      const url = nodeHandle?.relayUrl ?? "";
      expect(url).toMatch(/^wss?:\/\//);
      expect(url).toContain("/scp/v1");
    });

    test("Node reports a valid DID", () => {
      expect(nodeHandle?.did).toMatch(/^did:dht:/);
    });

    test("WASM transport_connect validates wss:// URL format", async () => {
      // The Node's relay URL may be wss://localhost/scp/v1 (domain mode with
      // self-signed TLS) or ws://... (NAT fallback). WASM transport_connect
      // requires wss://, so we construct a wss:// URL from the relay port.
      const wssUrl = `wss://localhost:${nodeHandle?.relayPort}/scp/v1`;

      // In bun (non-browser), WebSocket to self-signed TLS may throw a DOM
      // exception. Accept either success or a WebSocket-level error.
      try {
        const status = await wasm.transport_connect(wssUrl);
        expect(status).toBeDefined();
        expect(status.relayUrl).toBe(wssUrl);
      } catch (e: unknown) {
        // WebSocket errors in non-browser runtime are expected.
        // Verify it's NOT a URL validation rejection (SCP-VALID-7000).
        const msg = e instanceof Error ? e.message : String(e);
        expect(msg).not.toContain("SCP-VALID-7000");
      }
    });

    test("WASM transport_connect rejects ws:// (requires TLS)", async () => {
      const wsUrl = `ws://127.0.0.1:${nodeHandle?.relayPort}/scp/v1`;
      await expect(wasm.transport_connect(wsUrl)).rejects.toThrow(/wss:\/\//);
    });
  });

  // -------------------------------------------------------------------------
  // 2. WASM creates identity
  // -------------------------------------------------------------------------

  describe("WASM identity creation alongside NAPI Node", () => {
    test("WASM creates an in-memory identity with a valid did:dht DID", async () => {
      const identity = await wasm.identity_create("in_memory");
      expect(identity.did).toMatch(/^did:dht:/);
    });

    test("WASM creates two identities with distinct DIDs", async () => {
      const a = await wasm.identity_create("in_memory");
      const b = await wasm.identity_create("in_memory");
      expect(a.did).not.toBe(b.did);
    });
  });

  // -------------------------------------------------------------------------
  // 3. WASM creates context + sends encrypted message
  // -------------------------------------------------------------------------

  describe("WASM MLS-encrypted context with real relay available", () => {
    test("WASM creates context with MLS encryption", async () => {
      const creator = await wasm.identity_create("in_memory");
      const ctx = await wasm.context_create(
        creator.did,
        JSON.stringify({
          ceiling: ["messages:read", "messages:write"],
          memoryScope: "ephemeral",
        }),
      );
      expect(ctx.contextId).toBeTruthy();
      expect(typeof ctx.contextId).toBe("string");
      expect(ctx.creatorDid).toBe(creator.did);
      // Context creation with MLS group succeeded — real OpenMLS in WASM.
    });

    test("second member joins WASM context", async () => {
      const creator = await wasm.identity_create("in_memory");
      const joiner = await wasm.identity_create("in_memory");
      const ctx = await wasm.context_create(
        creator.did,
        JSON.stringify({ ceiling: ["messages:read", "messages:write"] }),
      );

      // Join should not throw.
      await wasm.context_join(ctx, joiner.did);
    });

    test("WASM context lifecycle: create -> join -> send -> leave", async () => {
      const alice = await wasm.identity_create("in_memory");
      const bob = await wasm.identity_create("in_memory");
      const ctx = await wasm.context_create(
        alice.did,
        JSON.stringify({
          ceiling: ["messages:read", "messages:write"],
          memoryScope: "ephemeral",
        }),
      );

      await wasm.context_join(ctx, bob.did);

      const payloadBase64 = btoa("test message from Alice");
      await wasm.context_send(ctx, alice.did, payloadBase64);

      await wasm.context_leave(ctx, bob.did);
    });
  });

  // -------------------------------------------------------------------------
  // 4. Cross-bridge identity — both NAPI and WASM create valid identities
  // -------------------------------------------------------------------------

  describe("Cross-bridge identity creation", () => {
    test("NAPI and WASM both create valid did:dht identities", async () => {
      const napiIdentity = await napi.identityCreate("in_memory");
      const wasmIdentity = await wasm.identity_create("in_memory");

      // Both must produce valid did:dht identities.
      expect(napiIdentity.did).toMatch(/^did:dht:/);
      expect(wasmIdentity.did).toMatch(/^did:dht:/);

      // They must be distinct (different key material).
      expect(napiIdentity.did).not.toBe(wasmIdentity.did);
    });

    test("Node DID, NAPI-created DID, and WASM-created DID are all distinct", async () => {
      const nodeDid = nodeHandle?.did ?? "";
      const napiDid = (await napi.identityCreate("in_memory")).did;
      const wasmDid = (await wasm.identity_create("in_memory")).did;

      // All three must be valid and distinct.
      expect(nodeDid).toMatch(/^did:dht:/);
      expect(napiDid).toMatch(/^did:dht:/);
      expect(wasmDid).toMatch(/^did:dht:/);

      const dids = new Set([nodeDid, napiDid, wasmDid]);
      expect(dids.size).toBe(3);
    });
  });
}
