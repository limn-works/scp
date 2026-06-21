/**
 * Real NAPI bridge E2E tests for the SCP TypeScript SDK (Phase D5).
 *
 * These tests exercise the actual napi-rs native addon compiled from
 * `crates/scp-ffi/napi/`. They verify that the TypeScript SDK classes
 * correctly delegate through the real FFI bridge to scp-core Rust code.
 *
 * A-grade: All tests run through a real in-process relay (RelayTransportProvider),
 * not LocalTransportProvider. The full encrypt -> sign -> relay publish pipeline
 * executes for every contextSend / broadcastPublish call.
 *
 * Prerequisites:
 * - The NAPI bridge must be compiled with `allow_in_memory_custody` feature.
 * - The platform-specific `@limn-works/scp-ts-napi-*` package must be loadable.
 *
 * If the native addon is not available, all tests are skipped gracefully.
 */

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { generateKeyPairSync } from "node:crypto";
import { createRequire } from "node:module";
import type { BridgeMode } from "../src/bridge";
import { SCP } from "../src/scp";
import type { Relay } from "../src/server";

/**
 * Generates a raw X25519 keypair (32-byte secret + 32-byte public key) for
 * broadcast key-distribution tests. Uses Node/Bun's WebCrypto-backed
 * `generateKeyPairSync('x25519')` and extracts the raw scalars from the JWK
 * `d` (private) and `x` (public) base64url fields — no third-party dependency.
 */
function generateX25519KeyPair(): { secret: Uint8Array; publicKey: Uint8Array } {
  const { publicKey: pub, privateKey: priv } = generateKeyPairSync("x25519");
  const pubJwk = pub.export({ format: "jwk" }) as { x: string };
  const privJwk = priv.export({ format: "jwk" }) as { d: string };
  return {
    publicKey: new Uint8Array(Buffer.from(pubJwk.x, "base64url")),
    secret: new Uint8Array(Buffer.from(privJwk.d, "base64url")),
  };
}

// ---------------------------------------------------------------------------
// Guard: skip all tests if the native NAPI binding is unavailable.
// ---------------------------------------------------------------------------

type NativeBridge = Awaited<ReturnType<typeof import("../src/internal/bridge").getBridge>>;

// Post-ADR-048 (#1549 Phase 4 PR 4): every stateful operation dispatches
// through the caller-owned `SCP` instance. Relay startup, relay-transport
// configuration, and context subscriptions are all first-class `SCP.*`
// methods — no private-handle indirection needed.
//
// A small set of stateless helpers deliberately remain as module-level
// free functions on the raw addon — `discovery_*`, `context_discover`,
// `bridge_evaluate_trust`, `bridge_register`, `scp_version`. They touch
// no bridge state, so they never needed instance-scoping (see the
// "sub-slice B" comment in `crates/scp-ffi/napi/src/scp.rs`). These calls
// dispatch through `rawAddon` below rather than through the `SCP` wrapper.
// biome-ignore lint/suspicious/noExplicitAny: the native addon module is untyped
type NativeAddon = any;

// `createNativeBridge` is resolved once at module load so `beforeEach` can
// mint a fresh bridge/SCP pair per test without the async-import penalty.
let createNativeBridge:
  | ((scp: SCP) => ReturnType<typeof import("../src/internal/native").createNativeBridge>)
  | null = null;
let rawAddon: NativeAddon = null;
let skipReason = "";
let napiAvailable = false;

try {
  // Resolve the SDK bridge factory and probe the SCP class for the
  // Phase 4 surface. The probe SCP is discarded immediately — each test
  // will mint its own.
  ({ createNativeBridge } = await import("../src/internal/native.js"));
  const probe = new SCP({ storage: { type: "in_memory" } });
  if (typeof (probe as unknown as Record<string, unknown>).relayStartInMemory !== "function") {
    skipReason = "SCP missing relayStartInMemory — rebuild with the Phase 4 changes";
    createNativeBridge = null;
  } else {
    napiAvailable = true;
  }
  // Dispose of the probe so it never leaks state into the per-test
  // instances bootstrapped in `beforeEach` below.
  probe.shutdown(1).catch(() => {});

  // Also load the raw addon — it still exports the stateless module-level
  // helpers (discovery, bridge_evaluate_trust, bridge_register).
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
  if (pkg !== undefined) {
    rawAddon = req(pkg) as NativeAddon;
  }
} catch (e: unknown) {
  const msg = e instanceof Error ? e.message : String(e);
  skipReason = `Native NAPI bridge not available: ${msg}`;
}

// When the bridge is unavailable, define a single test that reports the skip.
if (!napiAvailable || createNativeBridge === null || rawAddon === null) {
  describe("Real NAPI bridge E2E (SKIPPED)", () => {
    test.skip(`all tests skipped: ${skipReason}`, () => {});
  });
} else {
  // Capture the add-on and the bridge factory in consts for type narrowing.
  const addon = rawAddon;
  const makeBridge = createNativeBridge;

  // ---------------------------------------------------------------------------
  // Per-test isolation state (security-reviewer round-1 LOW #3 / #1549)
  // ---------------------------------------------------------------------------
  //
  // Every test gets its own fresh `SCP` + bridge + in-memory relay so no
  // per-test state (UCAN nonces, blocked subscribers, registered tools,
  // relay messages, event-log entries) leaks into any subsequent test. The
  // per-test bootstrap measured at ~1 ms/cycle on the target hardware —
  // negligible next to the suite's overall runtime.
  //
  // `scp`, `napi`, and `relayHandle` are reassigned in `beforeEach`; every
  // nested `test` captures the current values through the closure `let`
  // bindings, so there is no stale reference even though the block
  // structure still looks shared.
  let scpInstance: SCP = null as unknown as SCP;
  let napi: NativeBridge = null as unknown as NativeBridge;
  let relayHandle: Relay | null = null;

  beforeEach(async () => {
    // Construct a fresh SCP + bridge per test. The bridge handle
    // affinity guard (#1549 Phase 4) ensures the new bridge only
    // accepts handles minted by this SCP — cross-instance reuse
    // from an earlier test would be rejected with SCP-PERM-3030.
    scpInstance = new SCP({ storage: { type: "in_memory" } });
    napi = makeBridge(scpInstance);

    // Start an in-memory relay on an ephemeral port. Post-ADR-048 this
    // is a first-class method on the SDK's `SCP` class that returns a
    // `Relay` wrapper around the raw native handle.
    const handle = await scpInstance.relayStartInMemory();
    relayHandle = handle;

    // Bootstrap identity first to get a DID for MLS credential identity.
    // This must happen BEFORE configureRelayTransport because the
    // ContextManager is initialized lazily by whichever per-instance call
    // wins the race.
    const bootstrap = await napi.identityCreate("in_memory");

    // Configure the ContextManager with a relay-backed transport provider.
    // configureRelayTransport creates a relay connection and wraps it in
    // RelayTransportProvider, so contextSend publishes encrypted payloads
    // through the relay. Must be called BEFORE any contextCreate.
    //
    // Post-ADR-048 this is a first-class method on the SDK's `SCP` class.
    await scpInstance.configureRelayTransport(handle.relayUrl, bootstrap.did);

    // Establish a SECOND WebSocket connection for contextSubscribe.
    // contextSubscribe uses the bridge's transport manager for its
    // subscription stream, separate from the ContextManager's transport
    // provider. `napi.transportConnect` dispatches through the same SCP
    // instance (the `Bridge` wrapper routes every call through
    // `scpInstance`).
    await napi.transportConnect(handle.relayUrl);
  });

  afterEach(async () => {
    // Shutdown timeout is in milliseconds after #1549 Phase 4 unit
    // unification — 1000 ms (1 second) gives pending tasks time to
    // drain without stalling the suite. `napi.shutdown` is the `Bridge`
    // wrapper, which keeps a `number`-valued signature and coerces to
    // `bigint` internally before crossing the FFI boundary (#1692 NAPI
    // `u64` widening).
    //
    // The shutdown call goes through the single `SCP` instance that
    // owns every handle minted above, so the suite never risks
    // cross-instance affinity rejections (`SCP-PERM-3030`).
    try {
      await napi.shutdown(1000);
    } catch {
      // best effort — tests may have already invoked shutdown
    }
    if (relayHandle && !relayHandle.isShutdown) {
      try {
        await relayHandle.shutdown();
      } catch {
        // best effort
      }
    }
    relayHandle = null;
  });

  // ---------------------------------------------------------------------------
  // 1. Identity creation and lifecycle
  // ---------------------------------------------------------------------------

  describe("Identity (real NAPI)", () => {
    test("creates an in-memory identity with a valid did:dht DID", async () => {
      const handle = await napi.identityCreate("in_memory");
      expect(handle.did).toMatch(/^did:dht:/);
      expect(handle.custodyType).toBe("in_memory");
    });

    test("creates two identities with distinct DIDs", async () => {
      const a = await napi.identityCreate("in_memory");
      const b = await napi.identityCreate("in_memory");
      expect(a.did).not.toBe(b.did);
    });

    // identityLoad and identityResolve now use the local identity registry
    // as a fallback when DHT is unavailable. See #1144 (C6).
    test("loads an identity by DID (local registry fallback)", async () => {
      const created = await napi.identityCreate("in_memory");
      const loaded = await napi.identityLoad(created.did);
      expect(loaded.did).toBe(created.did);
    });

    test("resolves a DID to a DID document (no agent key)", async () => {
      const handle = await napi.identityCreate("in_memory");
      const doc = await napi.identityResolve(handle.did);
      expect(doc.id).toBe(handle.did);
      // The document should have at least one authentication method.
      expect(doc.authentication.length).toBeGreaterThanOrEqual(1);
      // Verification methods must have non-empty publicKeyMultibase (issue #547).
      expect(doc.verificationMethods.length).toBeGreaterThanOrEqual(1);
      expect(doc.verificationMethods[0]?.publicKeyMultibase).toBeTruthy();
      expect(doc.verificationMethods[0]?.publicKeyMultibase.startsWith("z")).toBe(true);
      // Identity created without agent key: hasAgentKey must be false.
      expect(doc.hasAgentKey).toBe(false);
      expect(doc.agentPublicKey).toBeUndefined();
    });

    test("resolves a DID to a DID document (with agent key, ADR-039)", async () => {
      const handle = await napi.identityCreateWithAgentKey("in_memory");
      const doc = await napi.identityResolve(handle.did);
      expect(doc.id).toBe(handle.did);
      // Identity created with agent key: hasAgentKey must be true.
      expect(doc.hasAgentKey).toBe(true);
      expect(doc.agentPublicKey).toBeDefined();
      expect(typeof doc.agentPublicKey).toBe("string");
      // Agent public key should be multibase-encoded (starts with 'z' for base58btc).
      expect(doc.agentPublicKey?.startsWith("z")).toBe(true);
    });

    test("rotates an identity key and preserves the DID", async () => {
      const handle = await napi.identityCreate("in_memory");
      const rotated = await napi.identityRotateKey(handle);
      expect(rotated.did).toBe(handle.did);
    });

    test("creates an identity with an agent key (ADR-039)", async () => {
      const handle = await napi.identityCreateWithAgentKey("in_memory");
      expect(handle.did).toMatch(/^did:dht:/);
    });

    test("adds an agent key to an existing identity", async () => {
      const handle = await napi.identityCreate("in_memory");
      const withAgent = await napi.identityAddAgentKey(handle);
      expect(withAgent.did).toBe(handle.did);
    });

    test("rotates an agent key", async () => {
      const handle = await napi.identityCreateWithAgentKey("in_memory");
      const rotated = await napi.identityRotateAgentKey(handle);
      expect(rotated.did).toBe(handle.did);
    });

    test("removes an agent key", async () => {
      const handle = await napi.identityCreateWithAgentKey("in_memory");
      const removed = await napi.identityRemoveAgentKey(handle);
      expect(removed.did).toBe(handle.did);
    });

    test("migrates an identity to a new DID", async () => {
      const handle = await napi.identityCreate("in_memory");
      const migrated = await napi.identityMigrate(handle);
      // Migration creates a new DID.
      expect(migrated.did).toMatch(/^did:dht:/);
      expect(migrated.did).not.toBe(handle.did);
    });

    test("removes an existing identity from the registry", async () => {
      const handle = await napi.identityCreate("in_memory");
      // `identityRemove` is void and idempotent; after it runs the DID is
      // no longer present, so `identityRemoveIfPresent` reports false.
      napi.identityRemove(handle.did);
      expect(napi.identityRemoveIfPresent(handle.did)).toBe(false);
    });

    test("identityRemoveIfPresent reports true then false", async () => {
      const handle = await napi.identityCreate("in_memory");
      // First call finds the identity and removes it.
      expect(napi.identityRemoveIfPresent(handle.did)).toBe(true);
      // Second call finds nothing.
      expect(napi.identityRemoveIfPresent(handle.did)).toBe(false);
    });

    test("removing a non-existent identity is silent", () => {
      const missing = "did:dht:z6MkNeverRegisteredIdentityForRemoveTest";
      // No throw; idempotent no-op matching the cross-bridge contract.
      expect(() => napi.identityRemove(missing)).not.toThrow();
      expect(napi.identityRemoveIfPresent(missing)).toBe(false);
    });

    test("removing a malformed DID is rejected", () => {
      // Both removal ops gate on the shared `validate_did` validator before
      // touching the registry, matching the PyO3 reference bridge. A
      // syntactically invalid DID throws rather than silently no-op'ing.
      const bad = "not-a-did";
      expect(() => napi.identityRemove(bad)).toThrow();
      expect(() => napi.identityRemoveIfPresent(bad)).toThrow();
    });

    test("generates and verifies a device attestation", async () => {
      const handle = await napi.identityCreate("in_memory");
      const token = await napi.identityAttestDevice(handle.did);
      expect(typeof token).toBe("string");
      expect(token.length).toBeGreaterThan(0);

      const valid = await napi.identityVerifyDeviceAttestation(handle.did, token);
      expect(valid).toBe(true);
    });
  });

  // ---------------------------------------------------------------------------
  // 2. Context lifecycle
  // ---------------------------------------------------------------------------

  describe("Context lifecycle (real NAPI)", () => {
    test("creates a context and returns a context ID", async () => {
      const identity = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({
          ceiling: ["messages:read", "messages:write"],
          memoryScope: "ephemeral",
        }),
      );
      expect(ctx.contextId).toBeTruthy();
      expect(typeof ctx.contextId).toBe("string");
    });

    test("a second identity can join the context", async () => {
      const creator = await napi.identityCreate("in_memory");
      const joiner = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        creator,
        JSON.stringify({ ceiling: ["messages:read", "role:assign"] }),
      );
      // Should not throw.
      await napi.contextJoin(ctx, joiner.did);
    });

    test("sends a message without error (relay transport)", async () => {
      const identity = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({ ceiling: ["messages:read", "messages:write"] }),
      );
      const payload = new TextEncoder().encode("hello from NAPI");
      // Should not throw — RelayTransportProvider publishes through the relay.
      await napi.contextSend(ctx, identity.did, payload);
    });

    test("leaves a context without error", async () => {
      const identity = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({ ceiling: ["messages:read"] }),
      );
      await napi.contextLeave(ctx, identity.did);
    });

    test("closes a context without error", async () => {
      const identity = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({ ceiling: ["messages:read", "context:close"] }),
      );
      await napi.contextClose(ctx, identity.did);
    });

    test("creates a context with broadcast mode", async () => {
      const identity = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({
          ceiling: ["messages:read"],
          mode: "Broadcast",
          memoryScope: "full",
        }),
      );
      expect(ctx.contextId).toBeTruthy();
    });

    test("rejects unsupported governance model", async () => {
      const identity = await napi.identityCreate("in_memory");
      await expect(
        napi.contextCreate(
          identity,
          JSON.stringify({
            ceiling: ["messages:read"],
            governance: "invalid_model",
            ttlSeconds: 3600,
            memoryScope: "full",
            ceilingPolicy: "governed",
          }),
        ),
      ).rejects.toThrow(/unsupported governance model/);
    });

    test("creates a context with single_admin governance and TTL", async () => {
      const identity = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({
          ceiling: ["messages:read"],
          governance: "single_admin",
          ttlSeconds: 3600,
          memoryScope: "full",
        }),
      );
      expect(ctx.contextId).toBeTruthy();
    });
  });

  // ---------------------------------------------------------------------------
  // 3. Membership queries
  // ---------------------------------------------------------------------------

  describe("Membership (real NAPI)", () => {
    test("member count after creation is 1", async () => {
      const identity = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({ ceiling: ["messages:read"] }),
      );
      const count = await napi.contextMemberCount(ctx);
      expect(count).toBe(1);
    });

    test("creator is a member", async () => {
      const identity = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({ ceiling: ["messages:read"] }),
      );
      const isMember = await napi.contextIsMember(ctx, identity.did);
      expect(isMember).toBe(true);
    });

    test("non-member is not a member", async () => {
      const identity = await napi.identityCreate("in_memory");
      const other = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({ ceiling: ["messages:read"] }),
      );
      const isMember = await napi.contextIsMember(ctx, other.did);
      expect(isMember).toBe(false);
    });

    test("member DIDs includes the creator", async () => {
      const identity = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({ ceiling: ["messages:read"] }),
      );
      const dids = await napi.contextMemberDids(ctx);
      expect(dids).toContain(identity.did);
    });

    test("member count increases after join", async () => {
      const creator = await napi.identityCreate("in_memory");
      const joiner = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        creator,
        JSON.stringify({ ceiling: ["messages:read", "role:assign"] }),
      );
      await napi.contextJoin(ctx, joiner.did);
      const count = await napi.contextMemberCount(ctx);
      expect(count).toBe(2);
    });

    test("creator role is Admin", async () => {
      const identity = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({ ceiling: ["messages:read"] }),
      );
      const role = await napi.contextMemberRole(ctx, identity.did);
      // Case normalization applied in native.ts — closes #1236
      expect(role).toBe("Admin");
    });
  });

  // ---------------------------------------------------------------------------
  // 4. Tools
  // ---------------------------------------------------------------------------

  describe("Tools (real NAPI)", () => {
    test("registers a tool and returns a tool ID", async () => {
      const identity = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({ ceiling: ["tool:register"] }),
      );
      const toolId = await napi.toolRegister(ctx, {
        name: "echo",
        description: "Echoes input",
        inputSchema: {
          type: "object",
          properties: { input: { type: "string" }, mode: { type: "string" } },
          required: ["input", "mode"],
        },
        outputSchema: {
          type: "object",
          properties: { result: { type: "string" }, status: { type: "string" } },
          required: ["result", "status"],
        },
        operator: identity.did,
      });
      expect(typeof toolId).toBe("string");
      expect(toolId.length).toBeGreaterThan(0);
    });

    test("invokes a registered tool", async () => {
      const admin = await napi.identityCreate("in_memory");
      const member = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        admin,
        JSON.stringify({ ceiling: ["tool:register", "tool:invoke:*"] }),
      );
      // Join member to context so they have role-based capabilities.
      await napi.contextJoin(ctx, member.did);
      const toolId = await napi.toolRegister(ctx, {
        name: "test-tool",
        description: "A test tool",
        inputSchema: {
          type: "object",
          properties: { x: { type: "number" }, y: { type: "number" } },
        },
        outputSchema: { type: "object" },
        operator: admin.did,
      });
      // Mint UCAN for the member (cross-delegation, not self).
      const ucan = await napi.ucanMint(ctx, member.did, ["tool:invoke:*"]);
      const resultJson = await napi.toolInvoke(
        ctx,
        toolId,
        JSON.stringify({ x: 42, y: 7 }),
        member.did,
        ucan.encoded,
      );
      expect(typeof resultJson).toBe("string");
      const parsed = JSON.parse(resultJson);
      expect(parsed).toBeTruthy();
    });

    test("verifies a tool and returns a verification result", async () => {
      const identity = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({ ceiling: ["tool:register"] }),
      );
      const toolId = await napi.toolRegister(ctx, {
        name: "verify-me",
        description: "Tool for verification",
        inputSchema: {
          type: "object",
          properties: { query: { type: "string" }, limit: { type: "number" } },
          required: ["query", "limit"],
        },
        outputSchema: {
          type: "object",
          properties: { data: { type: "string" }, count: { type: "number" } },
          required: ["data", "count"],
        },
        operator: identity.did,
      });
      const result = await napi.toolVerify(ctx, toolId);
      expect(typeof result.passed).toBe("boolean");
      expect(Array.isArray(result.failures)).toBe(true);
    });
  });

  // ---------------------------------------------------------------------------
  // 5. UCAN lifecycle
  // ---------------------------------------------------------------------------

  describe("UCAN (real NAPI)", () => {
    test("mints a UCAN token with capabilities", async () => {
      const admin = await napi.identityCreate("in_memory");
      const member = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        admin,
        JSON.stringify({ ceiling: ["messages:read", "messages:write"] }),
      );

      const token = await napi.ucanMint(ctx, member.did, ["messages:read"]);
      expect(token.id).toBeTruthy();
      expect(token.encoded).toBeTruthy();
      expect(token.issuer).toBeTruthy();
      expect(token.audience).toBe(member.did);
      // NAPI capabilities are full URIs: "scp:ctx:{id}/messages:read".
      expect(token.capabilities.some((c: string) => c.endsWith("/messages:read"))).toBe(true);
    });

    // identity_create now publishes to the shared InMemoryDhtClient so that
    // the DualLayerResolver can find the issuer's DID document (#1144).
    test("validates a minted token for a granted capability", async () => {
      const admin = await napi.identityCreate("in_memory");
      const member = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(admin, JSON.stringify({ ceiling: ["messages:read"] }));

      const token = await napi.ucanMint(ctx, member.did, ["messages:read"]);
      // NAPI bridge requires full capability URI with scp:ctx:{contextId}/ prefix.
      const fullUri = token.capabilities[0];
      expect(fullUri).toBeDefined();
      await napi.ucanValidate(ctx, token.encoded, fullUri as string);
    });

    test("rejects validation for an ungranted capability", async () => {
      const admin = await napi.identityCreate("in_memory");
      const member = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(admin, JSON.stringify({ ceiling: ["messages:read"] }));

      const token = await napi.ucanMint(ctx, member.did, ["messages:read"]);
      await expect(napi.ucanValidate(ctx, token.encoded, "messages:write")).rejects.toThrow();
    });

    test("revokes a token", async () => {
      const admin = await napi.identityCreate("in_memory");
      const member = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(admin, JSON.stringify({ ceiling: ["messages:read"] }));

      const token = await napi.ucanMint(ctx, member.did, ["messages:read"]);
      // Revocation by the context creator should not throw.
      await napi.ucanRevoke(ctx, token.encoded, admin.did);
    });
  });

  // ---------------------------------------------------------------------------
  // 6. Event log
  // ---------------------------------------------------------------------------

  describe("Event log (real NAPI)", () => {
    test("queries events after context creation (ContextManager Merkle entries)", async () => {
      const identity = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({ ceiling: ["messages:read"] }),
      );
      const events = await napi.eventLogQuery(ctx, undefined);
      expect(events.length).toBeGreaterThanOrEqual(1);
      expect(events[0]?.eventType).toBe("ContextCreated");
      expect(typeof events[0]?.actorDid).toBe("string");
      expect(typeof events[0]?.sequence).toBe("number");
    });

    test("a send surfaces MessageSent on the ContextEvent buffer, not the durable log", async () => {
      const identity = await napi.identityCreate("in_memory");
      const bob = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({
          ceiling: ["messages:read", "messages:write", "member:invite", "role:assign"],
        }),
      );
      // §9.10.4: a lone-member encrypted send is a no-op that records no
      // MessageSent event. Add a peer and seed its per-member pseudonym so the
      // send actually fans out and the MessageSent event is emitted.
      await napi.contextJoin(ctx, bob.did);
      await napi.contextSeedPeerPseudonym(ctx, bob.did, new Uint8Array(32).fill(0x42));
      // Clear the join/create ContextEvents so the only event we observe below is
      // the one produced by the send.
      await napi.contextDrainEvents(ctx);

      await napi.contextSend(ctx, identity.did, new TextEncoder().encode("msg"));

      // ADR-011 amendment (phase-2.md:907-934): MessageSent is per-author,
      // non-convergent application activity. It is NOT a durable Merkle leaf —
      // it is surfaced only as a local `ContextEvent::MessageSent` on the
      // in-process buffer (drained here as a Debug-formatted string).
      const drained = await napi.contextDrainEvents(ctx);
      expect(drained.some((e) => e.includes("MessageSent"))).toBe(true);

      // The durable event log (read by eventLogQuery) deliberately excludes
      // MessageSent so two honest members derive the same merkle_root (§9.9.3),
      // so a MessageSent filter against the durable log returns nothing.
      const durable = await napi.eventLogQuery(ctx, { eventType: "MessageSent" });
      expect(Array.isArray(durable)).toBe(true);
      expect(durable.length).toBe(0);
    });

    // event_log_verify now syncs ContextManager Merkle entries into the
    // UCAN-state EventLog via push_leaf_raw before calling prove_inclusion.
    test("verifies an inclusion proof against ContextManager event log", async () => {
      const identity = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({ ceiling: ["messages:read"] }),
      );

      const proof = await napi.eventLogVerify(ctx, { type: "inclusion", leafIndex: 0 });
      expect(proof.verified).toBe(true);
      expect(proof.proofType).toBe("inclusion");
    });

    test("creates a checkpoint (via DID registry lookup)", async () => {
      const identity = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({ ceiling: ["messages:read"] }),
      );

      const checkpoint = await napi.eventLogCheckpoint(ctx, identity.did, 0);
      expect(checkpoint.merkleRoot).toBeTruthy();
      expect(typeof checkpoint.eventCount).toBe("number");
      expect(typeof checkpoint.timestamp).toBe("number");
      // The flat checkpoint mirrors the Python/Swift/Kotlin field set: it
      // carries the context id, the signing member's DID, and the MLS epoch
      // alongside the Merkle root.
      expect(checkpoint.contextId).toBe(ctx.contextId);
      expect(checkpoint.senderDid).toBe(identity.did);
      expect(checkpoint.epoch).toBe(0);
      // The NAPI bridge signs the checkpoint in-process, so the SDK returns a
      // flat checkpoint carrying the Ed25519 signature (hex, 128 chars).
      expect(typeof checkpoint.signature).toBe("string");
      expect(checkpoint.signature).toMatch(/^[0-9a-f]{128}$/);
    });
  });

  // ---------------------------------------------------------------------------
  // 7. Discovery
  // ---------------------------------------------------------------------------

  describe("Discovery (real NAPI)", () => {
    test("parses a discovery handle address", () => {
      // `discoveryParseAddress` is a stateless module-level helper — not
      // on the `Scp` class. Dispatch through the raw addon post-ADR-048.
      const result = addon.discoveryParseAddress("alice@cooking-community");
      const parsed = JSON.parse(result);
      expect(parsed.type).toBe("DiscoveryHandle");
      expect(parsed.local_part).toBe("alice");
    });

    test("parses a domain handle address", () => {
      const result = addon.discoveryParseAddress("alice@example.com");
      const parsed = JSON.parse(result);
      expect(parsed.type).toBe("DomainHandle");
      expect(parsed.local_part).toBe("alice");
      expect(parsed.domain).toBe("example.com");
    });

    test("creates a discovery query with capabilities", () => {
      const result = addon.discoveryCreateQuery(["code_review"], undefined, undefined);
      expect(typeof result).toBe("string");
      const parsed = JSON.parse(result);
      expect(parsed.capability_filter).toContain("code_review");
    });

    test("creates a discovery query with keywords", () => {
      const result = addon.discoveryCreateQuery(undefined, ["rust", "security"], undefined);
      const parsed = JSON.parse(result);
      expect(parsed.keywords).toContain("rust");
      expect(parsed.keywords).toContain("security");
    });

    test("creates an empty discovery query", () => {
      const result = addon.discoveryCreateQuery(undefined, undefined, undefined);
      expect(typeof result).toBe("string");
      // Should be valid JSON.
      JSON.parse(result);
    });

    test("normalizes an address (lowercases and trims)", () => {
      const result = addon.discoveryNormalizeAddress("  ALICE@Cooking  ");
      expect(result).toBe("alice@cooking");
    });

    test("discovers contexts from an scp:// URI", async () => {
      const uri =
        "scp://context/deadbeef?relay=wss%3A%2F%2Frelay.example.com%2Fscp%2Fv1&mode=broadcast";
      const raw = await addon.contextDiscover(uri);
      const results = JSON.parse(raw);
      expect(Array.isArray(results)).toBe(true);
      expect(results.length).toBe(1);
      expect(results[0].context_id).toBe("deadbeef");
      expect(results[0].discovery_source).toBe("context_uri");
    });

    test("rejects discovery with an invalid query", async () => {
      await expect(addon.contextDiscover("not-a-did-or-uri")).rejects.toThrow();
    });
  });

  // ---------------------------------------------------------------------------
  // 8. Provenance
  // ---------------------------------------------------------------------------

  describe("Provenance (real NAPI)", () => {
    test("evaluates provenance quality for an active persistent context", async () => {
      const quality = await napi.evaluateProvenanceQuality(
        "ctx-source-123",
        "persistent",
        "active",
        ["did:dht:z6MkTestCounterparty"],
      );
      expect(typeof quality).toBe("number");
      expect(quality).toBeGreaterThanOrEqual(0);
      expect(quality).toBeLessThanOrEqual(3);
    });

    test("evaluates provenance quality without a source context", async () => {
      const quality = await napi.evaluateProvenanceQuality(
        undefined,
        "ephemeral",
        "unknown",
        undefined,
      );
      expect(typeof quality).toBe("number");
    });

    test("attaches provenance metadata at a cross-context boundary", () => {
      const raw = napi.provenanceAttach(
        "ctx-source",
        "persistent",
        "full",
        ["did:dht:z6MkMember1"],
        "ctx-target",
        "did:dht:z6MkActor",
        undefined,
        undefined,
        undefined,
        undefined,
      );
      const record = JSON.parse(raw);
      expect(record.source_context).toBe("ctx-source");
      // Without existing provenance, chain_depth starts at 0.
      expect(record.chain_depth).toBe(0);
      expect(Array.isArray(record.counterparties)).toBe(true);
      // New fields present with default values.
      expect(record.discovery_method).toBe("OutOfBand");
      expect(record.purpose).toBeNull();
      expect(record.payment_amount).toBeNull();
      expect(record.payment_adapter).toBeNull();
      expect(record.payment_receipt_id).toBeNull();
    });

    test("attaches provenance with existing chain depth", () => {
      const raw = napi.provenanceAttach(
        "ctx-source",
        "persistent",
        "full",
        ["did:dht:z6MkMember1"],
        "ctx-target",
        "did:dht:z6MkActor",
        2,
        undefined,
        undefined,
        undefined,
      );
      const record = JSON.parse(raw);
      // Chain depth should be existing + 1 = 3.
      expect(record.chain_depth).toBe(3);
    });

    test("attaches provenance with discovery_method SharedContext", () => {
      const raw = napi.provenanceAttach(
        "ctx-source",
        "persistent",
        "full",
        ["did:dht:z6MkMember1"],
        "ctx-target",
        "did:dht:z6MkActor",
        undefined,
        "shared_context:ctx-shared-abc",
        "data sharing purpose",
        undefined,
      );
      const record = JSON.parse(raw);
      expect(record.discovery_method).toEqual({ SharedContext: "ctx-shared-abc" });
      expect(record.purpose).toBe("data sharing purpose");
    });

    test("attaches provenance with discovery_method Registry", () => {
      const raw = napi.provenanceAttach(
        "ctx-source",
        "persistent",
        "full",
        [],
        "ctx-target",
        "did:dht:z6MkActor",
        undefined,
        "registry:ctx-registry-abc",
        undefined,
        undefined,
      );
      const record = JSON.parse(raw);
      expect(record.discovery_method).toEqual({ Registry: "ctx-registry-abc" });
    });

    test("attaches provenance with counterparty_policy", () => {
      const raw = napi.provenanceAttach(
        "ctx-source",
        "persistent",
        "full",
        ["did:dht:z6MkMember1"],
        "ctx-target",
        "did:dht:z6MkActor",
        undefined,
        undefined,
        undefined,
        "redacted",
      );
      const record = JSON.parse(raw);
      // Redacted policy results in empty counterparties.
      expect(record.counterparties).toEqual([]);
    });

    test("checks chain depth within default limit (8)", () => {
      expect(napi.provenanceCheckChainDepth(0, undefined)).toBe(true);
      expect(napi.provenanceCheckChainDepth(8, undefined)).toBe(true);
      expect(napi.provenanceCheckChainDepth(9, undefined)).toBe(false);
    });

    test("checks chain depth with custom limit", () => {
      expect(napi.provenanceCheckChainDepth(1, 1)).toBe(true);
      expect(napi.provenanceCheckChainDepth(2, 1)).toBe(false);
    });
  });

  // ---------------------------------------------------------------------------
  // 9. Bridge trust evaluation
  // ---------------------------------------------------------------------------

  describe("Bridge trust (real NAPI)", () => {
    // `bridgeEvaluateTrust` and `bridgeRegister` are stateless module-level
    // helpers on the raw addon — not on the `Scp` class. Post-ADR-048 the
    // test calls dispatch through `addon` directly. The raw addon returns
    // camelCase keys (napi-rs `#[napi(object)]` default); the Bridge
    // wrapper's snake_case normalization no longer applies here so the
    // assertions below read the camelCase shape.
    test("evaluates trust for native non-bridged action (highest tier)", () => {
      const tier = addon.bridgeEvaluateTrust(false, true, "shadow");
      expect(typeof tier).toBe("number");
      // Native + non-bridged should be highest trust.
      expect(tier).toBe(3);
    });

    test("evaluates trust for shadow bridged action (lowest tier)", () => {
      const tier = addon.bridgeEvaluateTrust(true, false, "shadow");
      expect(typeof tier).toBe("number");
      expect(tier).toBeLessThan(3);
    });

    test("evaluates trust for claimed bridged action", () => {
      const tier = addon.bridgeEvaluateTrust(true, false, "claimed");
      expect(typeof tier).toBe("number");
      // Claimed should be higher trust than shadow when bridged.
      const shadowTier = addon.bridgeEvaluateTrust(true, false, "shadow");
      expect(tier).toBeGreaterThanOrEqual(shadowTier);
    });

    test("registers a bridge connector", () => {
      const reg = addon.bridgeRegister(
        "ctx-bridge-test",
        "did:key:operator",
        "did:key:governance",
        "discord",
        "relay",
      );
      // Raw addon returns camelCase keys.
      expect(reg.bridgeId).toBeTruthy();
      expect(reg.operatorDid).toBe("did:key:operator");
      expect(reg.platform).toBe("discord");
      expect(reg.mode).toBe("relay");
      expect(reg.status).toBe("active");
      expect(reg.contextId).toBe("ctx-bridge-test");
    });

    test("rejects self-approval (operator === governance)", () => {
      expect(() =>
        addon.bridgeRegister(
          "ctx-self",
          "did:key:operator",
          "did:key:operator",
          "discord",
          "relay",
        ),
      ).toThrow(/approver cannot be the same/);
    });

    test("creates a shadow identity", () => {
      const shadow = napi.bridgeCreateShadow("bridge-1", "@discorduser", "relay", "ctx-shadow");
      expect(shadow.shadow_id).toBeTruthy();
      expect(shadow.platform_handle).toBe("@discorduser");
      expect(shadow.bridge_id).toBe("bridge-1");
      expect(shadow.attributed_role).toBe("observer");
      // Provenance status should be "Shadow" (Debug format from Rust).
      expect(shadow.provenance_status).toBeTruthy();
    });

    test("registers bridges with all four modes", () => {
      for (const mode of [
        "relay",
        "puppet",
        "api",
        "cooperative",
      ] as const satisfies readonly BridgeMode[]) {
        const reg = addon.bridgeRegister(`ctx-${mode}`, "did:key:op", "did:key:gov", "slack", mode);
        expect(reg.status).toBe("active");
      }
    });
  });

  // ---------------------------------------------------------------------------
  // 9b. Bridge credential store (spec §12.11) — per-instance SCP methods
  // ---------------------------------------------------------------------------

  describe("Bridge credentials (real NAPI)", () => {
    const key = new Uint8Array(32).fill(7);

    test("provision -> retrieve -> rotate -> revoke lifecycle", () => {
      const bridgeId = "bridge-cred-ts-001";

      const provisioned = scpInstance.bridgeCredentialProvision(
        bridgeId,
        "ApiKey",
        new TextEncoder().encode("first-secret"),
        key,
      );
      expect(provisioned.bridgeId).toBe(bridgeId);
      expect(provisioned.credentialType).toBe("ApiKey");
      expect(typeof provisioned.createdAt).toBe("number");

      const retrieved = scpInstance.bridgeCredentialRetrieve(bridgeId, "ApiKey", key);
      expect(new TextDecoder().decode(retrieved)).toBe("first-secret");

      scpInstance.bridgeCredentialRotate(
        bridgeId,
        "ApiKey",
        new TextEncoder().encode("second-secret"),
        key,
      );
      const rotated = scpInstance.bridgeCredentialRetrieve(bridgeId, "ApiKey", key);
      expect(new TextDecoder().decode(rotated)).toBe("second-secret");

      expect(scpInstance.bridgeCredentialList(bridgeId)).toEqual(["ApiKey"]);

      scpInstance.bridgeCredentialRevoke(bridgeId);
      expect(() => scpInstance.bridgeCredentialRetrieve(bridgeId, "ApiKey", key)).toThrow();
    });

    test("credential key store -> get -> delete lifecycle", () => {
      const bridgeId = "bridge-cred-ts-002";

      scpInstance.bridgeCredentialStoreKey(bridgeId, key);
      const got = scpInstance.bridgeCredentialGetKey(bridgeId);
      expect(Array.from(got)).toEqual(Array.from(key));

      scpInstance.bridgeCredentialDeleteKey(bridgeId);
      expect(() => scpInstance.bridgeCredentialGetKey(bridgeId)).toThrow();
    });

    test("rejects a non-32-byte credential key", () => {
      expect(() =>
        scpInstance.bridgeCredentialProvision(
          "bridge-cred-ts-003",
          "ApiKey",
          new TextEncoder().encode("secret"),
          new Uint8Array(16),
        ),
      ).toThrow();
    });
  });

  // ---------------------------------------------------------------------------
  // 10. Sync / offline classification
  // ---------------------------------------------------------------------------

  describe("Sync classification (real NAPI)", () => {
    test("classifies a short offline duration", () => {
      const now = 1_000_000;
      const lastContact = now - 3600; // 1 hour ago
      const result = napi.syncClassifyOffline(lastContact, now);
      expect(result).toBe("short");
    });

    test("classifies an extended offline duration", () => {
      const now = 1_000_000;
      const lastContact = now - 100_000; // ~27 hours ago
      const result = napi.syncClassifyOffline(lastContact, now);
      expect(result).toBe("extended");
    });

    test("classifies a long offline duration", () => {
      const now = 2_000_000;
      const lastContact = 1_000_000; // 1,000,000 seconds ago (~11 days)
      const result = napi.syncClassifyOffline(lastContact, now);
      expect(result).toBe("long");
    });

    test("returns default sync policy with expected fields", () => {
      const policy = napi.syncGetPolicy();
      expect(policy.tier_1_threshold_secs).toBe(14_400); // 4 hours
      expect(policy.tier_2_threshold_secs).toBe(604_800); // 7 days
      expect(policy.gap_timeout_secs).toBeGreaterThan(0);
      expect(policy.reorder_buffer_capacity).toBeGreaterThan(0);
      expect(policy.max_sequential_commits).toBeGreaterThan(0);
      expect(policy.commit_process_timeout_secs).toBeGreaterThan(0);
      expect(policy.sender_key_timeout_secs).toBeGreaterThan(0);
      expect(policy.reconnection_dedup_window_secs).toBeGreaterThan(0);
    });

    test("classifies offline duration with custom thresholds", () => {
      const now = 1_000_000;
      // Custom: 1 hour short, 3 days extended
      const t1 = 3600;
      const t2 = 259_200;

      // 30 min ago -> short (within custom 1h threshold)
      expect(napi.syncClassifyOfflineCustom(now - 1800, now, t1, t2)).toBe("short");
      // 2 hours ago -> extended (over 1h, within 3 days)
      expect(napi.syncClassifyOfflineCustom(now - 7200, now, t1, t2)).toBe("extended");
      // 4 days ago -> long (over 3 days)
      expect(napi.syncClassifyOfflineCustom(now - 345_600, now, t1, t2)).toBe("long");
    });
  });

  // ---------------------------------------------------------------------------
  // 11. Version and lifecycle
  // ---------------------------------------------------------------------------

  describe("Lifecycle (real NAPI)", () => {
    test("version returns a non-empty string", () => {
      const v = napi.version();
      expect(typeof v).toBe("string");
      expect(v.length).toBeGreaterThan(0);
    });

    // NOTE: There is no `shutdown(0)` test here because the bridge is
    // process-global and once shut down it cannot be revived for
    // subsequent tests. A shutdown test belongs in a dedicated test
    // file that runs in a process of its own (see `lifecycle.test.ts`
    // for suspend/resume coverage). `shutdown(timeoutMillis)` is
    // exercised end-to-end via the `afterAll` hook above.
  });

  // ---------------------------------------------------------------------------
  // 12. End-to-end scenario: full context lifecycle
  // ---------------------------------------------------------------------------

  describe("E2E context lifecycle (real NAPI)", () => {
    test("create -> join -> send -> membership check -> leave -> close (relay transport)", async () => {
      const alice = await napi.identityCreate("in_memory");
      const bob = await napi.identityCreate("in_memory");

      const ctx = await napi.contextCreate(
        alice,
        JSON.stringify({
          ceiling: ["messages:read", "messages:write", "role:assign", "context:close"],
          memoryScope: "ephemeral",
          governance: "single_admin",
        }),
      );

      expect(await napi.contextMemberCount(ctx)).toBe(1);
      expect(await napi.contextIsMember(ctx, alice.did)).toBe(true);
      expect(await napi.contextIsMember(ctx, bob.did)).toBe(false);

      await napi.contextJoin(ctx, bob.did);
      expect(await napi.contextMemberCount(ctx)).toBe(2);
      expect(await napi.contextIsMember(ctx, bob.did)).toBe(true);

      // Seed Bob's per-member pseudonym so the multi-member fan-out is
      // registered; otherwise the send fails closed with SCP-CTX-2095
      // ("pseudonym registry empty") per §9.10.4.
      await napi.contextSeedPeerPseudonym(ctx, bob.did, new Uint8Array(32).fill(0x42));

      await napi.contextSend(ctx, alice.did, new TextEncoder().encode("hello bob"));

      const events = await napi.eventLogQuery(ctx, undefined);
      expect(events.length).toBeGreaterThanOrEqual(1);

      // Checkpoint reads from the UCAN-state EventLog (separate from the
      // ContextManager's MerkleEventLogProvider that eventLogQuery uses).
      // The checkpoint still functions correctly (generates a valid Merkle
      // root of whatever's in the UCAN-state log).
      const checkpoint = await napi.eventLogCheckpoint(ctx, alice.did, 0);
      expect(typeof checkpoint.eventCount).toBe("number");

      await napi.contextLeave(ctx, bob.did);
      await napi.contextClose(ctx, alice.did);
    });
  });

  // ---------------------------------------------------------------------------
  // 13. E2E: UCAN mint -> validate -> revoke
  // ---------------------------------------------------------------------------

  describe("E2E UCAN lifecycle (real NAPI)", () => {
    // identity_create now publishes to the shared InMemoryDhtClient (#1144).
    test("mint -> validate -> revoke lifecycle", async () => {
      const admin = await napi.identityCreate("in_memory");
      const member = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        admin,
        JSON.stringify({ ceiling: ["messages:read", "messages:write"] }),
      );

      // Mint separate tokens for each capability. UCAN nonce replay
      // prevention (ADR-016 step 9) rejects the same token presented
      // twice, so each validation needs its own token.
      const readToken = await napi.ucanMint(ctx, member.did, ["messages:read"]);
      expect(readToken.capabilities.length).toBe(1);
      const readCap = readToken.capabilities[0] as string;
      expect(readCap).toBeDefined();

      const writeToken = await napi.ucanMint(ctx, member.did, ["messages:write"]);
      expect(writeToken.capabilities.length).toBe(1);
      const writeCap = writeToken.capabilities[0] as string;
      expect(writeCap).toBeDefined();

      // Validate both capabilities (separate tokens, separate nonces).
      await napi.ucanValidate(ctx, readToken.encoded, readCap);
      await napi.ucanValidate(ctx, writeToken.encoded, writeCap);

      // Revoke the read token (revoker is the admin/context creator).
      await napi.ucanRevoke(ctx, readToken.encoded, admin.did);

      // Verify the revoked token is rejected.
      await expect(napi.ucanValidate(ctx, readToken.encoded, readCap)).rejects.toThrow();

      // Mint a fresh write token to verify non-revoked capabilities still work.
      // The original writeToken's nonce was already consumed at line 927, so
      // re-validating it would fail on nonce replay (ADR-016 step 9) before
      // the revocation check is reached.
      const freshWriteToken = await napi.ucanMint(ctx, member.did, ["messages:write"]);
      const freshWriteCap = freshWriteToken.capabilities[0] as string;
      await napi.ucanValidate(ctx, freshWriteToken.encoded, freshWriteCap);
    });
  });

  // ---------------------------------------------------------------------------
  // 14. E2E: Tools register + invoke + verify
  // ---------------------------------------------------------------------------

  describe("E2E tool lifecycle (real NAPI)", () => {
    test("register -> invoke -> verify", async () => {
      const admin = await napi.identityCreate("in_memory");
      const member = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        admin,
        JSON.stringify({
          ceiling: ["tool:register", "tool:invoke:*"],
        }),
      );
      // Join member so they have role-based capabilities.
      await napi.contextJoin(ctx, member.did);

      // Register.
      const toolId = await napi.toolRegister(ctx, {
        name: "e2e-tool",
        description: "End-to-end test tool",
        inputSchema: {
          type: "object",
          properties: { value: { type: "number" }, mode: { type: "string" } },
        },
        outputSchema: {
          type: "object",
          properties: { doubled: { type: "number" }, ok: { type: "boolean" } },
        },
        operator: admin.did,
      });
      expect(toolId).toBeTruthy();

      // Invoke (mint for member, cross-delegation).
      const ucan = await napi.ucanMint(ctx, member.did, ["tool:invoke:*"]);
      const resultJson = await napi.toolInvoke(
        ctx,
        toolId,
        JSON.stringify({ value: 21 }),
        member.did,
        ucan.encoded,
      );
      expect(typeof resultJson).toBe("string");
      const result = JSON.parse(resultJson);
      expect(result).toBeTruthy();

      // Verify.
      const verification = await napi.toolVerify(ctx, toolId);
      expect(typeof verification.passed).toBe("boolean");
      expect(Array.isArray(verification.failures)).toBe(true);
    });
  });

  // ---------------------------------------------------------------------------
  // 15. Cross-cutting: provenance + discovery in sequence
  // ---------------------------------------------------------------------------

  describe("Cross-cutting provenance and discovery (real NAPI)", () => {
    test("provenance attach -> chain depth check -> discovery query", () => {
      // Attach provenance.
      const provRaw = napi.provenanceAttach(
        "ctx-origin",
        "persistent",
        "full",
        ["did:dht:z6MkA", "did:dht:z6MkB"],
        "ctx-destination",
        "did:dht:z6MkActor",
        undefined,
        undefined,
        undefined,
        undefined,
      );
      const prov = JSON.parse(provRaw);
      // Without existing provenance, chain_depth starts at 0.
      expect(prov.chain_depth).toBe(0);

      // Check the chain depth is within limit.
      expect(napi.provenanceCheckChainDepth(prov.chain_depth, undefined)).toBe(true);

      // Create a discovery query for the destination context.
      const queryJson = addon.discoveryCreateQuery(["messages:read"], ["collaboration"], 3600);
      const query = JSON.parse(queryJson);
      expect(query.capability_filter).toContain("messages:read");
      expect(query.keywords).toContain("collaboration");
    });
  });

  // ---------------------------------------------------------------------------
  // 16. Broadcast operations
  // ---------------------------------------------------------------------------

  describe("Broadcast operations (real NAPI)", () => {
    test("subscriber count is 0 on a fresh broadcast context", async () => {
      const identity = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({
          ceiling: ["messages:read"],
          mode: "Broadcast",
          memoryScope: "full",
        }),
      );
      const count = await napi.broadcastSubscriberCount(ctx);
      // Broadcast context starts with 0 subscribers (creator is an author, not subscriber).
      expect(count).toBe(0);
    });

    test("subscribe adds a subscriber", async () => {
      const identity = await napi.identityCreate("in_memory");
      const subscriber = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({
          ceiling: ["messages:read"],
          mode: "Broadcast",
          memoryScope: "full",
        }),
      );

      // Subscribe.
      await napi.broadcastSubscribe(ctx, subscriber.did);

      // Verify subscriber is recognized.
      const isSub = await napi.broadcastIsSubscriber(ctx, subscriber.did);
      expect(isSub).toBe(true);

      // Verify count.
      const count = await napi.broadcastSubscriberCount(ctx);
      expect(count).toBe(1);
    });

    test("non-subscriber is not a subscriber", async () => {
      const identity = await napi.identityCreate("in_memory");
      const other = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({
          ceiling: ["messages:read"],
          mode: "Broadcast",
          memoryScope: "full",
        }),
      );
      const isSub = await napi.broadcastIsSubscriber(ctx, other.did);
      expect(isSub).toBe(false);
    });

    test("unsubscribe removes a subscriber", async () => {
      const identity = await napi.identityCreate("in_memory");
      const subscriber = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({
          ceiling: ["messages:read"],
          mode: "Broadcast",
          memoryScope: "full",
        }),
      );

      await napi.broadcastSubscribe(ctx, subscriber.did);
      expect(await napi.broadcastIsSubscriber(ctx, subscriber.did)).toBe(true);

      await napi.broadcastUnsubscribe(ctx, subscriber.did);
      expect(await napi.broadcastIsSubscriber(ctx, subscriber.did)).toBe(false);
    });

    test("broadcast admission returns a policy", async () => {
      const identity = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({
          ceiling: ["messages:read"],
          mode: "Broadcast",
          memoryScope: "full",
        }),
      );
      const admission = await napi.broadcastAdmission(ctx);
      // Should return a string representation of the admission policy.
      expect(typeof admission).toBe("string");
    });

    test("publish sends a broadcast message (relay transport)", async () => {
      const identity = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({
          ceiling: ["messages:read", "messages:write"],
          mode: "Broadcast",
          memoryScope: "full",
        }),
      );
      const payload = new TextEncoder().encode("broadcast hello");
      // Should not throw — RelayTransportProvider publishes through the relay.
      await napi.broadcastPublish(ctx, identity.did, payload);
    });

    // Per §5.14.8: per-author blocking does NOT remove from the context-wide
    // subscriber roster. The subscriber loses access to the blocking author's
    // content only, not to other authors'. Only governance_ban_subscriber
    // removes from the roster.
    test("block subscriber adds to block list without removing from roster", async () => {
      const identity = await napi.identityCreate("in_memory");
      const subscriber = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({
          ceiling: ["messages:read"],
          mode: "Broadcast",
          memoryScope: "full",
        }),
      );

      await napi.broadcastSubscribe(ctx, subscriber.did);
      expect(await napi.broadcastIsSubscriber(ctx, subscriber.did)).toBe(true);

      // Block does not throw.
      await napi.broadcastBlockSubscriber(ctx, subscriber.did, identity.did);
      // Per §5.14.8: subscriber stays in the roster after per-author block.
      expect(await napi.broadcastIsSubscriber(ctx, subscriber.did)).toBe(true);
      // Subscriber count unchanged (still in roster).
      expect(await napi.broadcastSubscriberCount(ctx)).toBe(1);
    });

    test("unblock after block does not throw and subscriber remains in roster", async () => {
      const identity = await napi.identityCreate("in_memory");
      const subscriber = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({
          ceiling: ["messages:read"],
          mode: "Broadcast",
          memoryScope: "full",
        }),
      );

      await napi.broadcastSubscribe(ctx, subscriber.did);
      expect(await napi.broadcastIsSubscriber(ctx, subscriber.did)).toBe(true);

      await napi.broadcastBlockSubscriber(ctx, subscriber.did, identity.did);
      // Subscriber stays in roster after block (§5.14.8).
      expect(await napi.broadcastIsSubscriber(ctx, subscriber.did)).toBe(true);

      // Unblock does not throw.
      await napi.broadcastUnblockSubscriber(ctx, subscriber.did, identity.did);
      // Subscriber still in roster after unblock.
      expect(await napi.broadcastIsSubscriber(ctx, subscriber.did)).toBe(true);
    });

    test("unblock non-blocked subscriber throws", async () => {
      const identity = await napi.identityCreate("in_memory");
      const subscriber = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({
          ceiling: ["messages:read"],
          mode: "Broadcast",
          memoryScope: "full",
        }),
      );

      await napi.broadcastSubscribe(ctx, subscriber.did);

      await expect(
        napi.broadcastUnblockSubscriber(ctx, subscriber.did, identity.did),
      ).rejects.toThrow();
    });

    test("handle key request grants and the subscriber opens the key", async () => {
      const identity = await napi.identityCreate("in_memory");
      const subscriber = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({
          ceiling: ["messages:read"],
          mode: "Broadcast",
          memoryScope: "full",
        }),
      );

      await napi.broadcastSubscribe(ctx, subscriber.did);

      // Real X25519 wrapping keypair for the subscriber (HPKE recipient).
      const { secret, publicKey } = generateX25519KeyPair();
      const sealedJson = await napi.broadcastHandleKeyRequest(
        ctx,
        identity.did,
        subscriber.did,
        publicKey,
      );
      expect(sealedJson).not.toBeNull();
      expect(typeof sealedJson).toBe("string");
      expect((sealedJson as string).length).toBeGreaterThan(0);

      // The subscriber opens the sealed key with its matching secret and gets
      // the raw 32-byte AES-256 broadcast key.
      const key = await napi.broadcastOpenKey(sealedJson as string, secret);
      expect(key.length).toBe(32);
    });

    test("handle key request denies a non-subscriber with no key material", async () => {
      const identity = await napi.identityCreate("in_memory");
      const stranger = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({
          ceiling: ["messages:read"],
          mode: "Broadcast",
          memoryScope: "full",
        }),
      );

      // `stranger` never subscribed — the author returns no key material.
      const { publicKey } = generateX25519KeyPair();
      const decision = await napi.broadcastHandleKeyRequest(
        ctx,
        identity.did,
        stranger.did,
        publicKey,
      );
      expect(decision).toBeNull();
    });
  });

  // ---------------------------------------------------------------------------
  // 17. Governance operations
  // ---------------------------------------------------------------------------

  describe("Governance (real NAPI)", () => {
    test("executes a ChangeRole governance action", async () => {
      const admin = await napi.identityCreate("in_memory");
      const member = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        admin,
        JSON.stringify({
          ceiling: ["messages:read", "messages:write", "role:assign"],
          governance: "single_admin",
        }),
      );

      // Add the member first.
      await napi.contextJoin(ctx, member.did);

      // Execute a ChangeRole governance action using a role that exists
      // in single_admin governance. "admin" and "member" are the only
      // predefined roles — promote member to admin.
      const actionJson = JSON.stringify({
        ChangeRole: {
          did: member.did,
          new_role: "admin",
        },
      });
      const result = await napi.contextExecuteGovernanceAction(ctx, actionJson, admin.did);
      expect(typeof result).toBe("string");
    });

    test("rejects invalid governance action JSON", async () => {
      const admin = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        admin,
        JSON.stringify({
          ceiling: ["messages:read"],
          governance: "single_admin",
        }),
      );

      await expect(
        napi.contextExecuteGovernanceAction(ctx, "not-valid-json", admin.did),
      ).rejects.toThrow();
    });
  });

  // ---------------------------------------------------------------------------
  // 18. TTL operations
  // ---------------------------------------------------------------------------

  describe("TTL operations (real NAPI)", () => {
    test("handle TTL expiry on a context with TTL", async () => {
      const identity = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({
          ceiling: ["messages:read"],
          ttlSeconds: 3600,
        }),
      );
      // Should not throw (handles TTL expiry check).
      await napi.contextHandleTtlExpiry(ctx);
    });

    test("propose TTL extension returns a boolean", async () => {
      const identity = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({
          ceiling: ["messages:read"],
          ttlSeconds: 3600,
        }),
      );
      const unanimous = await napi.contextProposeTtlExtension(ctx, identity.did, 7200);
      // With a single member, the extension should be unanimously approved.
      expect(typeof unanimous).toBe("boolean");
    });

    test("reset TTL timer does not throw", async () => {
      const identity = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({
          ceiling: ["messages:read"],
          ttlSeconds: 3600,
        }),
      );
      // Should not throw.
      await napi.contextResetTtlTimer(ctx, 7200);
    });
  });

  // ---------------------------------------------------------------------------
  // 19. Context export/import
  // ---------------------------------------------------------------------------

  describe("Context export/import (real NAPI)", () => {
    test("exports a context to bytes", async () => {
      const identity = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({
          ceiling: ["messages:read"],
          memoryScope: "ephemeral",
        }),
      );

      const data = await napi.contextExport(ctx);
      expect(data).toBeInstanceOf(Uint8Array);
      expect(data.length).toBeGreaterThan(0);
    });

    // import_context now allows reimport when the existing context is in a
    // terminal state (Closed/Expired/Tombstoned). Test the create → export →
    // close → import round-trip.
    test("exports and imports a context round-trip (close before reimport)", async () => {
      const identity = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({
          ceiling: ["messages:read", "context:close"],
          memoryScope: "ephemeral",
        }),
      );

      const data = await napi.contextExport(ctx);
      expect(data.length).toBeGreaterThan(0);

      // Close the context so import_context sees a terminal state and
      // allows reimport.
      await napi.contextClose(ctx, identity.did);

      const importedContextId = await napi.contextImport(data, identity.did);
      expect(typeof importedContextId).toBe("string");
      expect(importedContextId.length).toBeGreaterThan(0);
    });

    test("import rejects invalid data", async () => {
      const identity = await napi.identityCreate("in_memory");
      const invalidData = new Uint8Array([0, 1, 2, 3]);
      await expect(napi.contextImport(invalidData, identity.did)).rejects.toThrow();
    });

    // Spec §23.16.8: the verifying key is resolved from the snapshot's
    // creator_did via local custody first (then DID resolver). A self-export of
    // an in-memory (unpublished) identity must round-trip on import — the
    // creator's verifying key is derived from its own #active custody key, so
    // no published DID document is required. This is the regression guard for
    // the prior bug where import went straight to the DID resolver and failed
    // for unpublished self-exports.
    test("self-export round-trips via local-custody key resolution (§23.16.8)", async () => {
      const identity = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({
          ceiling: ["messages:read", "context:close"],
          memoryScope: "ephemeral",
        }),
      );

      const data = await napi.contextExport(ctx);
      expect(data.length).toBeGreaterThan(0);

      // Close so import_context sees a terminal state and allows reimport.
      await napi.contextClose(ctx, identity.did);

      // Untampered self-export must verify and import: the snapshot signature
      // checks against the creator's local-custody #active key.
      const importedContextId = await napi.contextImport(data, identity.did);
      expect(typeof importedContextId).toBe("string");
      expect(importedContextId.length).toBeGreaterThan(0);
    });

    // Spec §23.16.8 / ADR-050: the exported snapshot is Ed25519-signed over the
    // full canonical snapshot. Tampering with the exported bytes after signing
    // must cause import to be rejected with SCP-CTX-2093 (the dedicated
    // signed-export verification code), not a generic context error.
    test("import rejects a tampered export with SCP-CTX-2093 (§23.16.8)", async () => {
      const identity = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({
          ceiling: ["messages:read", "context:close"],
          memoryScope: "ephemeral",
        }),
      );

      const data = await napi.contextExport(ctx);
      expect(data.length).toBeGreaterThan(0);
      await napi.contextClose(ctx, identity.did);

      // Flip bytes across the embedded snapshot region (back half of the
      // MessagePack envelope) without re-signing. At least one flip lands in a
      // signed/trusted snapshot field, so the recomputed digest no longer
      // matches the Ed25519 signature.
      const tampered = new Uint8Array(data);
      const start = Math.floor(tampered.length / 2);
      for (let i = start; i < tampered.length; i += 17) {
        tampered[i] = (tampered[i] ?? 0) ^ 0xff;
      }
      // The tamper MUST be rejected. A flip that lands in a signed snapshot
      // field surfaces the dedicated "[SCP-CTX-2093]" signature-failure code;
      // a flip that corrupts the MessagePack framing surfaces a deserialize
      // error instead. Both are valid rejections — what must NEVER happen is a
      // silent accept, nor a mapping to the catch-all "SCP-CTX-2001" generic
      // context error. So assert the import rejects and that the rejection is
      // not the catch-all (matching the Python reference test).
      // `expect(...).rejects` takes a promise, so invoke the async wrapper to
      // hand `expect` the promise it returns (matching the promise-first
      // `rejects.toThrow()` idiom used elsewhere in this file).
      await expect(
        (async () => {
          try {
            await napi.contextImport(tampered, identity.did);
          } catch (err) {
            const message = err instanceof Error ? err.message : String(err);
            if (message.includes("SCP-CTX-2001")) {
              throw new Error(
                `tampered snapshot must not map to the catch-all CTX-2001: ${message}`,
              );
            }
            throw err;
          }
        })(),
      ).rejects.toThrow();
    });
  });

  // ---------------------------------------------------------------------------
  // 20. Drain events
  // ---------------------------------------------------------------------------

  describe("Drain events (real NAPI)", () => {
    test("drain events returns an array after context creation", async () => {
      const identity = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({
          ceiling: ["messages:read"],
        }),
      );

      const events = await napi.contextDrainEvents(ctx);
      expect(Array.isArray(events)).toBe(true);
    });

    test("drain events is idempotent (second drain returns empty)", async () => {
      const identity = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({
          ceiling: ["messages:read"],
        }),
      );

      // First drain consumes any pending events.
      await napi.contextDrainEvents(ctx);

      // Second drain should return empty (events already consumed).
      const events = await napi.contextDrainEvents(ctx);
      expect(events.length).toBe(0);
    });

    test("drain events captures events from join", async () => {
      const creator = await napi.identityCreate("in_memory");
      const joiner = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        creator,
        JSON.stringify({ ceiling: ["messages:read", "role:assign"] }),
      );

      // Drain creation events.
      await napi.contextDrainEvents(ctx);

      // Join triggers an event.
      await napi.contextJoin(ctx, joiner.did);
      const events = await napi.contextDrainEvents(ctx);
      expect(events.length).toBeGreaterThanOrEqual(1);
    });
  });

  // ---------------------------------------------------------------------------
  // 21. UCAN delegation
  // ---------------------------------------------------------------------------

  describe("UCAN delegation (real NAPI)", () => {
    test("delegates a minted token to a third party", async () => {
      const admin = await napi.identityCreate("in_memory");
      const member = await napi.identityCreate("in_memory");
      const delegate = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        admin,
        JSON.stringify({ ceiling: ["messages:read", "messages:write"] }),
      );

      // Mint a token for the member.
      const parentToken = await napi.ucanMint(ctx, member.did, ["messages:read", "messages:write"]);
      expect(parentToken.encoded).toBeTruthy();

      // Delegate a subset of capabilities from member to delegate.
      const delegated = await napi.ucanDelegate(
        ctx,
        member.did,
        delegate.did,
        parentToken.encoded,
        ["messages:read"],
      );
      expect(delegated.audience).toBe(delegate.did);
      expect(delegated.capabilities.length).toBe(1);
    });

    test("delegation rejects invalid delegator DID", async () => {
      const admin = await napi.identityCreate("in_memory");
      const member = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(admin, JSON.stringify({ ceiling: ["messages:read"] }));

      const token = await napi.ucanMint(ctx, member.did, ["messages:read"]);

      // Use an invalid DID as delegator.
      await expect(
        napi.ucanDelegate(ctx, "not-a-did", member.did, token.encoded, ["messages:read"]),
      ).rejects.toThrow();
    });

    test("delegation rejects mismatched delegator (not token audience)", async () => {
      const admin = await napi.identityCreate("in_memory");
      const member = await napi.identityCreate("in_memory");
      const other = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(admin, JSON.stringify({ ceiling: ["messages:read"] }));

      // Mint token for member (audience = member.did).
      const token = await napi.ucanMint(ctx, member.did, ["messages:read"]);

      // Try to delegate as "other" who is NOT the token audience.
      await expect(
        napi.ucanDelegate(ctx, other.did, admin.did, token.encoded, ["messages:read"]),
      ).rejects.toThrow();
    });
  });

  // ---------------------------------------------------------------------------
  // 22. E2E: Broadcast full lifecycle
  // ---------------------------------------------------------------------------

  describe("E2E broadcast lifecycle (real NAPI)", () => {
    test("create -> subscribe -> publish -> check subscriber -> unsubscribe (relay transport)", async () => {
      const author = await napi.identityCreate("in_memory");
      const subscriber = await napi.identityCreate("in_memory");

      const ctx = await napi.contextCreate(
        author,
        JSON.stringify({
          ceiling: ["messages:read", "messages:write"],
          mode: "Broadcast",
          memoryScope: "full",
        }),
      );

      expect(await napi.broadcastSubscriberCount(ctx)).toBe(0);

      await napi.broadcastSubscribe(ctx, subscriber.did);
      expect(await napi.broadcastIsSubscriber(ctx, subscriber.did)).toBe(true);
      expect(await napi.broadcastSubscriberCount(ctx)).toBe(1);

      const payload = new TextEncoder().encode("broadcast message");
      await napi.broadcastPublish(ctx, author.did, payload);

      await napi.broadcastUnsubscribe(ctx, subscriber.did);
      expect(await napi.broadcastIsSubscriber(ctx, subscriber.did)).toBe(false);
      expect(await napi.broadcastSubscriberCount(ctx)).toBe(0);
    });
  });

  // ---------------------------------------------------------------------------
  // 23. Broadcast Content Delivery — asset publishing (SCP-290)
  // ---------------------------------------------------------------------------

  describe("Broadcast content delivery (real NAPI)", () => {
    test("broadcastPublishAsset returns blobId and etag", async () => {
      const identity = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({
          ceiling: ["messages:read", "messages:write"],
          mode: "Broadcast",
          memoryScope: "full",
        }),
      );

      const body = Array.from(new TextEncoder().encode("<h1>Hello</h1>"));
      const result = await napi.broadcastPublishAsset(
        ctx,
        identity.did,
        { path: "/index.html", contentType: "text/html", body },
        "deploy-napi-1",
      );
      // Relay transport is configured — publish succeeds.
      expect(result).toHaveProperty("blobId");
      expect(result).toHaveProperty("etag");
      expect(result).toHaveProperty("deployId");
      expect(typeof result.blobId).toBe("string");
      expect(result.blobId.length).toBe(64);
      expect(result.deployId).toBe("deploy-napi-1");
    });

    test("broadcastPublishAssets batch returns correct count", async () => {
      const identity = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({
          ceiling: ["messages:read", "messages:write"],
          mode: "Broadcast",
          memoryScope: "full",
        }),
      );

      const assets = [
        {
          path: "/index.html",
          contentType: "text/html",
          body: Array.from(new TextEncoder().encode("<h1>Home</h1>")),
        },
        {
          path: "/style.css",
          contentType: "text/css",
          body: Array.from(new TextEncoder().encode("body { margin: 0 }")),
        },
      ];

      const batch = await napi.broadcastPublishAssets(
        ctx,
        identity.did,
        assets,
        "deploy-napi-batch",
      );
      // Relay transport is configured — batch publish succeeds.
      expect(batch.results.length).toBe(2);
      expect(batch.deployId).toBe("deploy-napi-batch");
      for (const r of batch.results) {
        expect(r).toHaveProperty("blobId");
        expect(r).toHaveProperty("etag");
        expect(r).toHaveProperty("deployId");
      }
    });
  });
}
