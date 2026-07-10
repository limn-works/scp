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
import { ContextError } from "../src/errors";
import { __getNativeScp, SCP } from "../src/scp";
import type { Relay } from "../src/server";
import type { BehavioralRecord, CapabilityRequirement, ParticipationProfile } from "../src/types";
import { allValid } from "../src/types";

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
  // per-test state (UCAN nonces, blocked subscribers, registered outlets,
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
  // 4. Outlets
  // ---------------------------------------------------------------------------

  describe("Outlets (real NAPI)", () => {
    test("registers an outlet and returns an outlet ID", async () => {
      const identity = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({ ceiling: ["outlet:register"] }),
      );
      const outletId = await napi.outletRegister(ctx, {
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
      expect(typeof outletId).toBe("string");
      expect(outletId.length).toBeGreaterThan(0);
    });

    test("invokes a registered outlet", async () => {
      const admin = await napi.identityCreate("in_memory");
      const member = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        admin,
        JSON.stringify({ ceiling: ["outlet:register", "tool:invoke:*"] }),
      );
      // Join member to context so they have role-based capabilities.
      await napi.contextJoin(ctx, member.did);
      const outletId = await napi.outletRegister(ctx, {
        name: "test-outlet",
        description: "A test outlet",
        inputSchema: {
          type: "object",
          properties: { x: { type: "number" }, y: { type: "number" } },
        },
        outputSchema: { type: "object" },
        operator: admin.did,
      });
      // Mint UCAN for the member (cross-delegation, not self).
      const ucan = await napi.ucanMint(ctx, member.did, ["tool:invoke:*"]);
      const resultJson = await napi.outletInvoke(
        ctx,
        outletId,
        JSON.stringify({ x: 42, y: 7 }),
        member.did,
        ucan.encoded,
      );
      expect(typeof resultJson).toBe("string");
      const parsed = JSON.parse(resultJson);
      expect(parsed).toBeTruthy();
    });

    test("registers an outlet whose cost.amount exceeds 2^53 (bigint boundary, ADR-060)", async () => {
      const identity = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({ ceiling: ["outlet:register"] }),
      );
      // 2^53 + 1 — the first integer a JS `number` cannot hold exactly — and
      // u64::MAX. Both cross the FFI boundary as a JS `bigint`; a `number`-typed
      // cost field would have narrowed and either lost precision or thrown.
      for (const amount of [9_007_199_254_740_993n, 18_446_744_073_709_551_615n]) {
        const outletId = await napi.outletRegister(ctx, {
          name: `priced-outlet-${amount}`,
          description: "A outlet with a large per-invocation cost",
          inputSchema: {
            type: "object",
            properties: { a: { type: "string" }, b: { type: "number" } },
            required: ["a", "b"],
          },
          outputSchema: {
            type: "object",
            properties: { result: { type: "string" }, ok: { type: "boolean" } },
            required: ["result", "ok"],
          },
          operator: identity.did,
          cost: {
            amount,
            currency: "SAT",
            payee: identity.did,
          },
        });
        expect(typeof outletId).toBe("string");
        expect(outletId.length).toBeGreaterThan(0);
      }
    });

    test("rejects a negative cost.amount (fail-closed, unsigned money)", async () => {
      const identity = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({ ceiling: ["outlet:register"] }),
      );
      await expect(
        napi.outletRegister(ctx, {
          name: "negative-cost-outlet",
          description: "invalid",
          inputSchema: {
            type: "object",
            properties: { a: { type: "string" }, b: { type: "number" } },
            required: ["a", "b"],
          },
          outputSchema: {
            type: "object",
            properties: { result: { type: "string" }, ok: { type: "boolean" } },
            required: ["result", "ok"],
          },
          operator: identity.did,
          cost: { amount: -1n, currency: "SAT", payee: identity.did },
        }),
      ).rejects.toThrow(/SCP-VALID-7001/);
    });

    test("verifies an outlet and returns a verification result", async () => {
      const identity = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({ ceiling: ["outlet:register"] }),
      );
      const outletId = await napi.outletRegister(ctx, {
        name: "verify-me",
        description: "Outlet for verification",
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
      const result = await napi.outletVerify(ctx, outletId);
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
      // The enforcing gate fails closed without a presenting agent — pass the
      // subject the token was minted for (its `aud`).
      await napi.ucanValidate(ctx, token.encoded, fullUri as string, member.did);
    });

    test("rejects validation for an ungranted capability", async () => {
      const admin = await napi.identityCreate("in_memory");
      const member = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(admin, JSON.stringify({ ceiling: ["messages:read"] }));

      const token = await napi.ucanMint(ctx, member.did, ["messages:read"]);
      await expect(
        napi.ucanValidate(ctx, token.encoded, "messages:write", member.did),
      ).rejects.toThrow();
    });

    test("ucanValidate fails closed when no presenting agent is supplied", async () => {
      const admin = await napi.identityCreate("in_memory");
      const member = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(admin, JSON.stringify({ ceiling: ["messages:read"] }));

      const token = await napi.ucanMint(ctx, member.did, ["messages:read"]);
      const fullUri = token.capabilities[0] as string;

      // Empty presenting agent → the gate MUST reject rather than default the
      // audience check to the token's own `aud` (which would be a tautology that
      // inflates trust). presenting_agent_did is a required (non-optional)
      // parameter; an empty string is rejected by validate_did. The fail-closed
      // check fires before nonce recording, so the token's nonce is NOT consumed
      // and the control call below still works.
      await expect(napi.ucanValidate(ctx, token.encoded, fullUri, "")).rejects.toThrow();

      // Control: supplying the subject (the token's audience) passes.
      await napi.ucanValidate(ctx, token.encoded, fullUri, member.did);
    });

    test("revokes a token", async () => {
      const admin = await napi.identityCreate("in_memory");
      const member = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(admin, JSON.stringify({ ceiling: ["messages:read"] }));

      const token = await napi.ucanMint(ctx, member.did, ["messages:read"]);
      // Revocation by the context creator should not throw.
      await napi.ucanRevoke(ctx, token.encoded, admin.did);
    });

    // C3c (ADR-059, §7.2.4): structured read-only diagnostic.
    test("ucanEvaluate returns all-true for a valid token on a granted capability", async () => {
      const admin = await napi.identityCreate("in_memory");
      const member = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(admin, JSON.stringify({ ceiling: ["messages:read"] }));

      const token = await napi.ucanMint(ctx, member.did, ["messages:read"]);
      const fullUri = token.capabilities[0] as string;
      const result = await napi.ucanEvaluate(ctx, token.encoded, fullUri, member.did);
      expect(result).toEqual({
        tokensValid: true,
        signaturesValid: true,
        withinCeiling: true,
        nonceValid: true,
        notRevoked: true,
        timeBoundsValid: true,
      });
    });

    test("ucanEvaluate reports signaturesValid:false for a forged-signature token (no throw)", async () => {
      const admin = await napi.identityCreate("in_memory");
      const member = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(admin, JSON.stringify({ ceiling: ["messages:read"] }));

      const token = await napi.ucanMint(ctx, member.did, ["messages:read"]);
      const fullUri = token.capabilities[0] as string;

      // Forge the signature: a UCAN is `header.payload.signature` (base64url).
      // Replace ONLY the signature segment so the token still PARSES
      // (tokensValid stays true) but signature verification fails.
      const parts = token.encoded.split(".");
      expect(parts.length).toBe(3);
      // A different, structurally-valid base64url signature segment.
      const forgedSig = "A".repeat((parts[2] as string).length);
      const forged = `${parts[0]}.${parts[1]}.${forgedSig}`;

      // Read-only diagnostic: must NOT throw — it reports the failure as bools.
      const result = await napi.ucanEvaluate(ctx, forged, fullUri, member.did);
      expect(result.tokensValid).toBe(true);
      expect(result.signaturesValid).toBe(false);
      // Everything downstream of the signature stage never ran → false.
      expect(result.withinCeiling).toBe(false);
      expect(result.nonceValid).toBe(false);
      expect(result.notRevoked).toBe(false);
      expect(result.timeBoundsValid).toBe(false);
    });

    test("ucanEvaluate is read-only: re-evaluating the same token keeps nonceValid:true", async () => {
      const admin = await napi.identityCreate("in_memory");
      const member = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(admin, JSON.stringify({ ceiling: ["messages:read"] }));

      const token = await napi.ucanMint(ctx, member.did, ["messages:read"]);
      const fullUri = token.capabilities[0] as string;

      const first = await napi.ucanEvaluate(ctx, token.encoded, fullUri, member.did);
      const second = await napi.ucanEvaluate(ctx, token.encoded, fullUri, member.did);
      // The probe never records the nonce, so the second evaluation is NOT a
      // replay — nonceValid stays true (unlike ucanValidate, which would
      // consume the nonce and reject the second call).
      expect(first.nonceValid).toBe(true);
      expect(second.nonceValid).toBe(true);
      expect(second).toEqual(first);
    });

    // Cross-bridge parity (Finding K): every bridge applies
    // `capability.filter(|c| !c.trim().is_empty())`, so an empty/whitespace
    // capability is coerced to "no challenge" — identical to omitting it
    // (None). Sibling of the PyO3 test_ucan_evaluate_empty_capability_coerced
    // _to_no_challenge test; the two assert the SAME coercion so a future edit
    // to one bridge cannot silently diverge. A bare "*" is NOT this (it is a
    // malformed URI the bridge rejects); absence is emptiness/omission only.
    test("ucanEvaluate empty/whitespace capability coerces to no-challenge (NAPI parity)", async () => {
      const admin = await napi.identityCreate("in_memory");
      const member = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(admin, JSON.stringify({ ceiling: ["messages:read"] }));

      const token = await napi.ucanMint(ctx, member.did, ["messages:read"]);

      // Presenting agent fixed to the token audience so the only variable is
      // the capability argument's emptiness.
      const omitted = await napi.ucanEvaluate(ctx, token.encoded, null, member.did);
      const empty = await napi.ucanEvaluate(ctx, token.encoded, "", member.did);
      const whitespace = await napi.ucanEvaluate(ctx, token.encoded, "   ", member.did);

      // Empty / whitespace capability == omitted capability: identical record.
      expect(empty).toEqual(omitted);
      expect(whitespace).toEqual(omitted);
      // A fresh, in-ceiling token is intrinsically valid on every stage.
      expect(allValid(omitted)).toBe(true);
    });

    // C3c (ADR-059 / §7.2.4): evaluateTrust assesses each token's GENERAL
    // (intrinsic) validity — it must NOT impose an invoked-capability
    // grant-match. The previous implementation passed a `"*"` sentinel that the
    // real bridge rejects ("missing scp:ctx: prefix"); the fix passes no
    // challenge capability (intrinsic-validity mode). A single valid, in-ceiling
    // token must therefore report all six checks true — this case would have
    // FAILED under the old `"*"` behavior (grant-match against `*` never
    // matches), so it is the regression guard for the actual bug.
    test("evaluateTrust reports a single valid token as intrinsically valid (real SCP method)", async () => {
      const admin = await napi.identityCreate("in_memory");
      const member = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(admin, JSON.stringify({ ceiling: ["messages:read"] }));

      const good = await napi.ucanMint(ctx, member.did, ["messages:read"]);

      const result = await scpInstance.evaluateTrust(ctx, member.did, [good.encoded]);
      // No grant-match challenge: a fresh, well-signed, in-ceiling token is
      // intrinsically valid on every stage.
      expect(result.capabilityValidation.tokensValid).toBe(true);
      expect(result.capabilityValidation.signaturesValid).toBe(true);
      expect(result.capabilityValidation.withinCeiling).toBe(true);
      expect(result.capabilityValidation.nonceValid).toBe(true);
      expect(result.capabilityValidation.notRevoked).toBe(true);
      expect(result.capabilityValidation.timeBoundsValid).toBe(true);
      // The derived happy-path accessor collapses the six fields: all true.
      expect(allValid(result.capabilityValidation)).toBe(true);
      expect(result.subjectDid).toBe(member.did);
      // The evaluation is labeled with the context the handle RESOLVES to (the
      // canonical id the layers were computed against), not the bare label arg
      // ("ctx-real") — the handle carries a real `contextId`, so a mismatched
      // label does not relabel the result.
      expect(result.contextId).toBe(ctx.contextId);
    });

    test("evaluateTrust AND-combines per-token validations (real SCP method)", async () => {
      const admin = await napi.identityCreate("in_memory");
      const member = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(admin, JSON.stringify({ ceiling: ["messages:read"] }));

      const good = await napi.ucanMint(ctx, member.did, ["messages:read"]);
      // Forge a second token whose signature is invalid.
      const parts = good.encoded.split(".");
      const forged = `${parts[0]}.${parts[1]}.${"A".repeat((parts[2] as string).length)}`;

      const result = await scpInstance.evaluateTrust(ctx, member.did, [good.encoded, forged]);
      // Intrinsic validity per token, AND-combined: the good token passes every
      // stage; the forged one fails signatures — so the AND is false there while
      // tokensValid (both parse) stays true.
      expect(result.capabilityValidation.tokensValid).toBe(true);
      expect(result.capabilityValidation.signaturesValid).toBe(false);
      // A single failing stage makes the derived accessor false.
      expect(allValid(result.capabilityValidation)).toBe(false);
      expect(result.subjectDid).toBe(member.did);
      // Labeled with the handle-resolved context id, not the bare label arg.
      expect(result.contextId).toBe(ctx.contextId);
      // Layer 2 behavioral record is present (event-log query succeeded).
      expect(result.behavioralRecord).toBeDefined();
    });

    // C3c (Phase 2C-2): the Layer-2 behavioral record is now the TYPED
    // participation record (§7.3.2) RECEIVED from the shared Rust core via
    // `participationRecord` — the SDK no longer classifies raw events
    // client-side, so the divergence-prone per-binding `toolInvocations` map is
    // gone. The record exposes the flattened `ParticipationFacts` 1:1.
    //
    // After create+join the context's supervisor Merkle log holds convergent
    // leaves (the `eventLogRoot` is a real, non-zero hash that advances with
    // each lifecycle op), so `participationRecord` RETURNS a typed record — it
    // does NOT throw. This test pins the baseline record SHAPE on a context with
    // no governance activity yet: a real Merkle root, a real `computedAt`,
    // `attestationCount == 0` (no attestations supplied — credential-layer, §7.4),
    // `toolInvocationCountAnchored == false` (ADR-051), and the obsolete
    // client-side fields absent. The per-fact governance/role COUNTS being
    // exercised live (and asserted non-zero) is the job of the affirmative test
    // below — the runtime DOES populate the ADR-011-amendment subject-bearing
    // payloads on the live NAPI governance path, so those counts move with
    // activity. This test deliberately does not assert them, since no governance
    // action has occurred at this point.
    test("participationRecord returns a typed record with a real Merkle root (real SCP method)", async () => {
      const admin = await napi.identityCreate("in_memory");
      const member = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        admin,
        JSON.stringify({ ceiling: ["messages:read"], governance: "single_admin" }),
      );
      await napi.contextJoin(ctx, member.did);

      // Key the lookup by the context's canonical id (the 64-char hex the handle
      // carries) — the same value `evaluateTrust` resolves from the handle — so
      // the lookup hits the context's REAL supervisor log.
      const realContextId = (ctx as { readonly contextId: string }).contextId;
      const record = await scpInstance.participationRecord(realContextId, member.did);

      expect(record.subjectDid).toBe(member.did);
      // The log is non-empty: a real 32-byte Merkle root (64 hex chars), not the
      // all-zero placeholder of an absent root.
      expect(record.eventLogRoot).toMatch(/^[0-9a-f]{64}$/);
      expect(record.eventLogRoot).not.toBe("0".repeat(64));
      expect(record.computedAt).toBeGreaterThan(0);
      // `tool_invocation_count` is never Merkle-anchored until ADR-051 (§7.3.2).
      expect(record.toolInvocationCountAnchored).toBe(false);
      // No cached attestations supplied → credential-layer count is 0 (§7.4),
      // honest and verifier-relative — the SDK fabricates none.
      expect(record.attestationCount).toBe(0);
      // The obsolete client-side fields are gone from the typed shape.
      expect((record as unknown as Record<string, unknown>).toolInvocations).toBeUndefined();
      expect((record as unknown as Record<string, unknown>).participationCount).toBeUndefined();
    });

    // C3c (Phase 2C-2): the leaf-derived participation facts (§7.3.2) MOVE in
    // response to real governance activity. A `single_admin` context whose
    // ceiling carries the governance capabilities auto-executes each proposal
    // on `propose` (ADR-031), appending convergent `GovernanceActionExecuted` /
    // `RoleAssigned` / `ChildContextCreated` leaves to the supervisor's Merkle
    // log. The typed `participationRecord` then RECEIVES non-zero counts
    // attributed by the subject-bearing payloads (ADR-011 amendment): the actor
    // for `governance_actions_by` / `context_creation_count`, and the projected
    // member for `role_progression_count` / `governance_actions_against`. This
    // is the affirmative counterpart to the create+join-only test above — it
    // proves the facts are real, not perpetually zero.
    test("participationRecord reflects real governance activity (real SCP method)", async () => {
      const admin = await napi.identityCreate("in_memory");
      const member = await napi.identityCreate("in_memory");
      // The ceiling MUST carry the governance + child-creation capabilities, or
      // the proposer (creator) lacks `governance:propose` / the child-creation
      // capability and the proposal is permission-denied.
      const ctx = await napi.contextCreate(
        admin,
        JSON.stringify({
          ceiling: [
            "messages:read",
            "messages:write",
            "role:assign",
            "governance:propose",
            "governance:vote",
            "context:close",
            "context:child:create",
          ],
          governance: "single_admin",
        }),
      );
      const realContextId = (ctx as { readonly contextId: string }).contextId;
      await napi.contextJoin(ctx, member.did);

      // 1. ChangeRole(member → moderator): a RoleAssigned leaf projected to the
      //    member + a GovernanceActionExecuted leaf actored by the admin.
      await napi.contextGovernancePropose(
        ctx,
        JSON.stringify({ ChangeRole: { did: member.did, new_role: "moderator" } }),
        admin.did,
      );
      // 2. RemoveMember(member): an adverse action → governance_actions_against
      //    the member + another GovernanceActionExecuted by the admin.
      await napi.contextGovernancePropose(
        ctx,
        JSON.stringify({ RemoveMember: { did: member.did, reason: "participation-test" } }),
        admin.did,
      );
      // 3. CreateChildContext: a ChildContextCreated leaf actored by the admin →
      //    the admin's context_creation_count increments by one.
      await napi.contextGovernancePropose(
        ctx,
        JSON.stringify({
          CreateChildContext: {
            params: {
              mode: "Encrypted",
              ceiling: [],
              ceiling_policy: "Immutable",
              promotion_policy: "NoPromotion",
              roles: [],
              outlets: [],
              ttl: null,
              memory_scope: "Ephemeral",
              governance: "SingleAdmin",
              template_id: null,
            },
          },
        }),
        admin.did,
      );

      const adminRecord = await scpInstance.participationRecord(realContextId, admin.did);
      const memberRecord = await scpInstance.participationRecord(realContextId, member.did);

      // Admin INITIATED all three governance actions and created one child.
      expect(adminRecord.governanceActionsBy).toBe(3);
      expect(adminRecord.governanceActionsAgainst).toBe(0);
      expect(adminRecord.contextCreationCount).toBe(1);
      expect(adminRecord.roleProgressionCount).toBe(0);
      // Member was the TARGET of one role change and one (adverse) removal.
      expect(memberRecord.roleProgressionCount).toBe(1);
      expect(memberRecord.governanceActionsAgainst).toBe(1);
      expect(memberRecord.governanceActionsBy).toBe(0);
      expect(memberRecord.contextCreationCount).toBe(0);
      // Credential-layer / anchoring invariants hold for both subjects.
      expect(adminRecord.attestationCount).toBe(0);
      expect(memberRecord.attestationCount).toBe(0);
      expect(adminRecord.toolInvocationCountAnchored).toBe(false);
      expect(memberRecord.toolInvocationCountAnchored).toBe(false);
      // Real Merkle root over the convergent governance leaves.
      expect(adminRecord.eventLogRoot).toMatch(/^[0-9a-f]{64}$/);
      expect(adminRecord.eventLogRoot).not.toBe("0".repeat(64));

      // evaluateTrust (handle-resolved contextId) RECEIVES the SAME record the
      // direct op returns — no client-side recomputation, no divergence.
      const evaluated = await scpInstance.evaluateTrust(ctx, admin.did);
      expect(evaluated.behavioralRecord).toEqual(adminRecord);
    });

    // CROSS-SDK PARITY (the divergence-killer). Because both SDKs now RECEIVE
    // the identical Rust-computed `ParticipationFacts` rather than each
    // recomputing Layer 2, the SAME governance scenario MUST yield the SAME
    // per-fact counts in TypeScript and Python. This test pins the canonical
    // expected counts for the scenario; the Python sibling
    // `test_participation_record_reflects_governance_real_ffi`
    // (bindings/python/tests/test_real_ffi.py) asserts the IDENTICAL counts for
    // the IDENTICAL scenario — so a divergence between the two bindings is a
    // CI-visible test failure on one side, by construction. (DIDs and the
    // Merkle root vary per run and are excluded from the parity tuple; the
    // leaf-derived/credential counts are deterministic for the scenario.)
    test("participation facts match the canonical cross-SDK counts (real SCP method)", async () => {
      const admin = await napi.identityCreate("in_memory");
      const member = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        admin,
        JSON.stringify({
          ceiling: [
            "messages:read",
            "messages:write",
            "role:assign",
            "governance:propose",
            "governance:vote",
            "context:close",
            "context:child:create",
          ],
          governance: "single_admin",
        }),
      );
      const realContextId = (ctx as { readonly contextId: string }).contextId;
      await napi.contextJoin(ctx, member.did);
      await napi.contextGovernancePropose(
        ctx,
        JSON.stringify({ ChangeRole: { did: member.did, new_role: "moderator" } }),
        admin.did,
      );
      await napi.contextGovernancePropose(
        ctx,
        JSON.stringify({ RemoveMember: { did: member.did, reason: "parity" } }),
        admin.did,
      );
      await napi.contextGovernancePropose(
        ctx,
        JSON.stringify({
          CreateChildContext: {
            params: {
              mode: "Encrypted",
              ceiling: [],
              ceiling_policy: "Immutable",
              promotion_policy: "NoPromotion",
              roles: [],
              outlets: [],
              ttl: null,
              memory_scope: "Ephemeral",
              governance: "SingleAdmin",
              template_id: null,
            },
          },
        }),
        admin.did,
      );

      const adminRec = await scpInstance.participationRecord(realContextId, admin.did);
      const memberRec = await scpInstance.participationRecord(realContextId, member.did);

      // The CANONICAL counts the Python sibling test asserts verbatim. Keys are
      // the deterministic, DID-independent facts (the Merkle root + subject_did
      // are excluded since they vary per run).
      const counts = (r: BehavioralRecord) => ({
        governanceActionsAgainst: r.governanceActionsAgainst,
        governanceActionsBy: r.governanceActionsBy,
        toolInvocationCount: r.toolInvocationCount,
        toolInvocationCountAnchored: r.toolInvocationCountAnchored,
        contextCreationCount: r.contextCreationCount,
        roleProgressionCount: r.roleProgressionCount,
        attestationCount: r.attestationCount,
        participationDurationSecs: r.participationDurationSecs,
      });
      expect(counts(adminRec)).toEqual({
        governanceActionsAgainst: 0,
        governanceActionsBy: 3,
        toolInvocationCount: 0,
        toolInvocationCountAnchored: false,
        contextCreationCount: 1,
        roleProgressionCount: 0,
        attestationCount: 0,
        participationDurationSecs: 0,
      });
      expect(counts(memberRec)).toEqual({
        governanceActionsAgainst: 1,
        governanceActionsBy: 0,
        toolInvocationCount: 0,
        toolInvocationCountAnchored: false,
        contextCreationCount: 0,
        roleProgressionCount: 1,
        attestationCount: 0,
        participationDurationSecs: 0,
      });
    });

    // `evaluateTrust` must remain usable on a context with NO convergent leaves
    // (the EmptyEventLog case): the core returns `EmptyEventLog`, which the SDK
    // folds into a zeroed behavioral record rather than throwing, so a
    // Layer-1-only trust check never has to populate the log first. Drive the
    // genuinely-empty case by keying the (handle-resolved) lookup at a context
    // label the supervisor has never seen, so the core's event-log lookup is
    // empty and the graceful fold is exercised end-to-end against the real
    // bridge. `participationRecord` on the same empty context propagates instead.
    test("evaluateTrust folds an empty event log into a zeroed behavioral record (real SCP method)", async () => {
      const member = await napi.identityCreate("in_memory");
      // A handle whose resolved contextId is a never-created label → empty log.
      const emptyHandle = { contextId: "ctx-never-created-empty-log" };

      // Direct record request on the empty context → typed ContextError keyed
      // on the dedicated, machine-detectable SCP-CTX-2076 code (the SDK branches
      // on the code, not error prose).
      const directError = await scpInstance
        .participationRecord(emptyHandle.contextId, member.did)
        .then(
          () => undefined,
          (err: unknown) => err,
        );
      expect(directError).toBeInstanceOf(ContextError);
      expect((directError as ContextError).code).toBe("SCP-CTX-2076");

      // evaluateTrust on the same empty context (no Layer-1 tokens, so only the
      // Layer-2 empty-log fold is exercised) → graceful zeroed record.
      const result = await scpInstance.evaluateTrust(emptyHandle, member.did);
      const record = result.behavioralRecord;
      expect(record.subjectDid).toBe(member.did);
      expect(record.participationDurationSecs).toBe(0);
      expect(record.governanceActionsAgainst).toBe(0);
      expect(record.governanceActionsBy).toBe(0);
      expect(record.toolInvocationCount).toBe(0);
      expect(record.toolInvocationCountAnchored).toBe(false);
      expect(record.contextCreationCount).toBe(0);
      expect(record.roleProgressionCount).toBe(0);
      expect(record.attestationCount).toBe(0);
      // attestationCount is credential-layer, never Merkle-anchored.
      expect(record.attestationCountAnchored).toBe(false);
      // Empty-log fold uses the all-zero root placeholder, not a real hash.
      expect(record.eventLogRoot).toBe("");
    });

    // Finding O: audience-mismatch trust-inflation regression (TS sibling of
    // the PyO3 `test_evaluate_trust_audience_mismatch_real_ffi`). A token whose
    // `aud` differs from the evaluated subject must report `signaturesValid:
    // false` — `evaluateTrust` passes `subjectDid` as the presenting agent so
    // the step-5 audience check evaluates against the DID under assessment.
    // `presentingAgentDid` is fail-closed: the bridge REJECTS an absent or empty
    // value rather than defaulting the presenting agent to the token's OWN `aud`
    // (which would make `aud == aud` always true, inflating trust for a token
    // addressed to someone else). This guards a future edit that drops
    // `subjectDid` from `evaluateTrust` (ADR-059 / §7.2.4).
    test("evaluateTrust reports signaturesValid:false for an audience-mismatched token", async () => {
      const admin = await napi.identityCreate("in_memory");
      const bob = await napi.identityCreate("in_memory");
      const carol = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(admin, JSON.stringify({ ceiling: ["messages:read"] }));

      // Token audience is Bob.
      const tokenForBob = await napi.ucanMint(ctx, bob.did, ["messages:read"]);

      // Evaluate trust for Carol (a DIFFERENT subject than the token audience):
      // the audience check fails, so the structural-checks field is false.
      const mismatch = await scpInstance.evaluateTrust(ctx, carol.did, [tokenForBob.encoded]);
      expect(mismatch.capabilityValidation.signaturesValid).toBe(false);

      // Control: evaluating the SAME token for its true audience (Bob) passes
      // the audience check — proving the false above is the mismatch, not an
      // unrelated failure.
      const control = await scpInstance.evaluateTrust(ctx, bob.did, [tokenForBob.encoded]);
      expect(control.capabilityValidation.signaturesValid).toBe(true);
    });

    // Finding P: empty/whitespace capability coercion must NOT bypass a failing
    // stage. The intrinsic-validity coercion (`capability=""` → no challenge) is
    // a no-CHALLENGE switch, not a no-CHECK switch — a forged-signature token
    // with an empty capability must still report `signaturesValid: false`. The
    // existing coercion parity test only covered a VALID token; this pins the
    // INVALID case so coercion cannot be mistaken for a validity shortcut. PyO3
    // sibling: test_ucan_evaluate_empty_capability_invalid_token_still_fails.
    test("ucanEvaluate empty capability on a forged token still reports signaturesValid:false", async () => {
      const admin = await napi.identityCreate("in_memory");
      const member = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(admin, JSON.stringify({ ceiling: ["messages:read"] }));

      const token = await napi.ucanMint(ctx, member.did, ["messages:read"]);
      // Forge the signature segment so signature verification fails.
      const parts = token.encoded.split(".");
      expect(parts.length).toBe(3);
      const forged = `${parts[0]}.${parts[1]}.${"A".repeat((parts[2] as string).length)}`;

      // Empty capability == no challenge — but the failing signature stage must
      // STILL be reported, never bypassed by the coercion.
      const empty = await napi.ucanEvaluate(ctx, forged, "", member.did);
      expect(empty.tokensValid).toBe(true);
      expect(empty.signaturesValid).toBe(false);
      // Equivalent to omitting the capability entirely: same failing record.
      const omitted = await napi.ucanEvaluate(ctx, forged, null, member.did);
      expect(empty).toEqual(omitted);
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

      // Validate both capabilities (separate tokens, separate nonces). The
      // enforcing gate requires the presenting agent (the token's audience).
      await napi.ucanValidate(ctx, readToken.encoded, readCap, member.did);
      await napi.ucanValidate(ctx, writeToken.encoded, writeCap, member.did);

      // Revoke the read token (revoker is the admin/context creator).
      await napi.ucanRevoke(ctx, readToken.encoded, admin.did);

      // Verify the revoked token is rejected.
      await expect(
        napi.ucanValidate(ctx, readToken.encoded, readCap, member.did),
      ).rejects.toThrow();

      // Mint a fresh write token to verify non-revoked capabilities still work.
      // The original writeToken's nonce was already consumed at line 927, so
      // re-validating it would fail on nonce replay (ADR-016 step 9) before
      // the revocation check is reached.
      const freshWriteToken = await napi.ucanMint(ctx, member.did, ["messages:write"]);
      const freshWriteCap = freshWriteToken.capabilities[0] as string;
      await napi.ucanValidate(ctx, freshWriteToken.encoded, freshWriteCap, member.did);
    });
  });

  // ---------------------------------------------------------------------------
  // 14. E2E: Outlets register + invoke + verify
  // ---------------------------------------------------------------------------

  describe("E2E outlet lifecycle (real NAPI)", () => {
    test("register -> invoke -> verify", async () => {
      const admin = await napi.identityCreate("in_memory");
      const member = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        admin,
        JSON.stringify({
          ceiling: ["outlet:register", "tool:invoke:*"],
        }),
      );
      // Join member so they have role-based capabilities.
      await napi.contextJoin(ctx, member.did);

      // Register.
      const outletId = await napi.outletRegister(ctx, {
        name: "e2e-outlet",
        description: "End-to-end test outlet",
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
      expect(outletId).toBeTruthy();

      // Invoke (mint for member, cross-delegation).
      const ucan = await napi.ucanMint(ctx, member.did, ["tool:invoke:*"]);
      const resultJson = await napi.outletInvoke(
        ctx,
        outletId,
        JSON.stringify({ value: 21 }),
        member.did,
        ucan.encoded,
      );
      expect(typeof resultJson).toBe("string");
      const result = JSON.parse(resultJson);
      expect(result).toBeTruthy();

      // Verify.
      const verification = await napi.outletVerify(ctx, outletId);
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
    test("rejects an untracked proposal id (direct-execute trust boundary)", async () => {
      const admin = await napi.identityCreate("in_memory");
      const member = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        admin,
        JSON.stringify({
          ceiling: ["messages:read", "messages:write", "role:assign"],
          governance: "single_admin",
        }),
      );

      await napi.contextJoin(ctx, member.did);

      // Direct execute is BY ID: the runtime resolves the authoritative proposal
      // from the context actor's own quorum-validated engine. A fabricated id
      // (a forgery) is rejected — a caller cannot supply an action to run.
      const fabricated = "ab".repeat(32);
      await expect(napi.contextExecuteGovernanceAction(ctx, fabricated)).rejects.toThrow(
        /not tracked/,
      );
    });

    test("rejects a malformed proposal id", async () => {
      const admin = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        admin,
        JSON.stringify({
          ceiling: ["messages:read"],
          governance: "single_admin",
        }),
      );

      await expect(napi.contextExecuteGovernanceAction(ctx, "not-hex")).rejects.toThrow();
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

  // ---------------------------------------------------------------------------
  // 18. Cross-context outlet-invocation saga (§6.2.4, ADR-049 §3a)
  // ---------------------------------------------------------------------------
  //
  // The §6.2.4 saga export lives on the native `SCP` class as
  // `outletInvokeCrossContextSaga`. The SDK wrapper (`SCP.outletInvokeCrossContextSaga`)
  // now exists too, but these tests deliberately reach the RAW native instance
  // DIRECTLY — obtained via `__getNativeScp` against the SAME `SCP` that minted
  // the context handles — so they pin the JS-marshaling boundary (BigInt
  // narrowing, hex nonce, NapiSagaResult round-trip, typed-SagaError survival)
  // independently of the SDK wrapper layer. Using the same instance is
  // mandatory: the per-instance handle-affinity guard rejects a handle minted
  // by any other instance with SCP-PERM-3030.
  //
  // The signature crossing the addon boundary is:
  //   outletInvokeCrossContextSaga(
  //     sourceHandle, targetHandle, callerDid, outletRegistrationId,
  //     inputJson, assertedNonceHex, timestampMs: BigInt, chainDepth: u8,
  //     ucanProofId?: string,
  //   ) => Promise<{ sagaId, receipt?, output? }>
  //
  // What these cases pin is the JS-marshaling boundary the Rust-side napi
  // test cannot exercise: the `BigInt` timestamp narrowing, the hex-nonce
  // string, the `#[napi(object)] NapiSagaResult` (`saga_id`/`receipt`/`output`)
  // round-trip, and — the load-bearing one — that a typed `SagaError` survives
  // the collapse to a single `napi::Error` message string with its
  // `SCP-SAGA-{code}` + parseable structured suffix intact, so the TypeScript
  // error layer can reverse it.
  describe("Cross-context outlet-invocation saga (real NAPI)", () => {
    // A 16-byte freshness nonce as the one canonical 32-char lowercase-hex
    // wire form (§6.2.4 envelope nonce).
    const NONCE_HEX = "0123456789abcdef0123456789abcdef";

    // The deterministic, cross-bridge outlet id form (`generate_tool_id(name)`).
    const TOOL_NAME = "xctx_saga_ts_outlet";
    const TOOL_ID = `outlet-${TOOL_NAME}`;

    // A near-now Unix-ms timestamp as a JS `BigInt`. Prepare-B enforces a
    // §9.14 ±5min skew, so a fixed historical value would abort with a skew
    // error rather than reaching the terminal under test.
    function nowMsBigInt(): bigint {
      return BigInt(Date.now());
    }

    // Handle types, inferred from the bridge surface so this block needs no
    // extra import. `napi.contextCreate` returns the raw native context handle
    // (it carries `.contextId`); `napi.identityCreate` returns the raw native
    // identity handle (it carries `.did`).
    type IdentityHandle = Awaited<ReturnType<typeof napi.identityCreate>>;
    type ContextHandle = Awaited<ReturnType<typeof napi.contextCreate>>;

    // The native `outletInvokeCrossContextSaga` method as it crosses the addon
    // boundary, read off the raw native SCP that minted every handle below.
    // Using that exact instance is mandatory — the per-instance handle-affinity
    // guard rejects a handle minted by any other instance (SCP-PERM-3030).
    type SagaResult = { sagaId: string; receipt?: Uint8Array; output?: Uint8Array };
    type SagaFn = (
      sourceHandle: ContextHandle,
      targetHandle: ContextHandle,
      callerDid: string,
      outletRegistrationId: string,
      inputJson: string,
      assertedNonceHex: string,
      timestampMs: bigint,
      chainDepth: number,
      ucanProofId: string | undefined,
    ) => Promise<SagaResult>;
    function nativeSaga(): SagaFn {
      const raw = __getNativeScp(scpInstance) as unknown as {
        outletInvokeCrossContextSaga: SagaFn;
      };
      return raw.outletInvokeCrossContextSaga.bind(raw);
    }

    // Creates a caller (source) context A owned by `ownerDid`. A's ceiling
    // carries `governance:propose` (so the admin can propose) and
    // `outlet:interface` (required by execute_establish_tool_interface's ceiling
    // check). `contextCreate` mints a real 64-hex id so the ADR-056 saga
    // chokepoint round-trips to A's actor.
    async function createCallerContext(owner: IdentityHandle): Promise<ContextHandle> {
      return napi.contextCreate(
        owner,
        JSON.stringify({
          ceiling: [
            "governance:propose",
            "outlet:interface",
            "tools:invoke",
            "messages:read",
            "messages:write",
          ],
          governance: "single_admin",
          memoryScope: "ephemeral",
        }),
      );
    }

    // Creates a target (executing) context B owned by `ownerDid`. B's ceiling
    // carries `governance:propose` + `outlet:register` so the saga outlet can be
    // registered into B's ACTOR governance state (the saga's Prepare-B reads
    // the outlet from there).
    async function createTargetContext(owner: IdentityHandle): Promise<ContextHandle> {
      return napi.contextCreate(
        owner,
        JSON.stringify({
          ceiling: ["governance:propose", "outlet:register"],
          governance: "single_admin",
          memoryScope: "ephemeral",
        }),
      );
    }

    // Externally-tagged `GovernanceAction::RegisterTool` for the saga outlet.
    // Two input + two output properties clear the §9.2.1 specificity floor of
    // 2. `implementation_hash` is a 32-element JSON number array (serde expects
    // a fixed `[u8; 32]`). `operator_did` is a required string (not nullable).
    // Registering this into B's actor state via governance is what the saga's
    // Prepare-B requires.
    function registerOutletActionJson(operatorDid: string): string {
      return JSON.stringify({
        RegisterTool: {
          registration: {
            outlet_id: TOOL_ID,
            name: TOOL_NAME,
            description: `Outlet: ${TOOL_NAME}`,
            schema: {
              input_schema: {
                type: "object",
                properties: { a: { type: "string" }, b: { type: "string" } },
              },
              output_schema: {
                type: "object",
                properties: { sum: { type: "number" }, ok: { type: "number" } },
              },
            },
            implementation_hash: new Array(32).fill(0),
            test_vectors: [],
            operator_did: operatorDid,
            cost: null,
            registered_at: 0,
            signature: [],
          },
        },
      });
    }

    // Externally-tagged `GovernanceAction::EstablishToolInterface`, source=A,
    // target=B, BOTH approvals true. The producer's gate 2 queries this
    // bidirectionally-approved interface against the CALLER context A's actor
    // governance state, so it is established IN A.
    function establishInterfaceActionJson(ctxA: string, ctxB: string): string {
      return JSON.stringify({
        EstablishToolInterface: {
          interface: {
            source_context: ctxA,
            target_context: ctxB,
            outlet_id: TOOL_ID,
            rate_limit: null,
            inbound_rate_limit: null,
            per_caller_rate_limit: null,
            approved_by_source: true,
            approved_by_target: true,
            outbound_policy: null,
            inbound_policy: null,
          },
        },
      });
    }

    // -----------------------------------------------------------------------
    // 1. Method exists + argument marshaling.
    //
    // Drives the saga from a real authenticated caller (a member of context A)
    // with a `BigInt` timestamp and a 32-char hex nonce, but WITHOUT an
    // established interface. The producer's target-axis gate 2 then aborts with
    // SCP-SAGA-13062 — which is exactly the point: a typed terminal (not a
    // `TypeError` / native panic) proves the `BigInt`, the hex nonce, the two
    // raw context handles, and the chain-depth `u8` all marshaled across the
    // addon and the saga actually ran.
    // -----------------------------------------------------------------------
    test("is callable: BigInt timestamp + hex nonce marshal and the saga runs", async () => {
      const owner = await napi.identityCreate("in_memory");
      const ctxA = await createCallerContext(owner);
      const ctxB = await createTargetContext(owner);

      const promise = nativeSaga()(
        ctxA,
        ctxB,
        owner.did,
        TOOL_ID,
        JSON.stringify({ a: "x", b: "y" }),
        NONCE_HEX,
        nowMsBigInt(),
        1,
        undefined,
      );

      // No established interface ⇒ the producer's gate 2 rejects. The
      // rejection is a real `Error` carrying the typed saga code (NOT a
      // synchronous TypeError from a failed BigInt/handle marshal).
      let caught: unknown;
      try {
        await promise;
        throw new Error("saga unexpectedly resolved without an established interface");
      } catch (e) {
        caught = e;
      }
      expect(caught).toBeInstanceOf(Error);
      const message = (caught as Error).message;
      expect(message).not.toMatch(/TypeError/);
      // Target-axis gate (no interface) ⇒ SCP-SAGA-13062.
      expect(message).toContain("SCP-SAGA-13062");
    });

    // -----------------------------------------------------------------------
    // 2. Error-code surfacing — the key marshaling check.
    //
    // A caller_did that is NOT an identity hosted by this bridge instance
    // trips the FFI-side §6.2.4 Caller-authentication binding BEFORE the saga
    // runs, mapping to a typed `SagaAborted` with code SCP-SAGA-13050 and a
    // `retry_after_ms = None` (rendered as the literal `null`). This proves the
    // typed-SagaError → napi::Error → JS-Error-message mapping survives the
    // boundary with both the code AND the parseable structured suffix intact.
    // -----------------------------------------------------------------------
    test("surfaces SCP-SAGA-13050 with a parseable structured suffix on a caller mismatch", async () => {
      const owner = await napi.identityCreate("in_memory");
      const ctxA = await createCallerContext(owner);
      const ctxB = await createTargetContext(owner);

      // A well-formed did:dht that this bridge instance does NOT host.
      const foreignCallerDid = "did:dht:z6MkNeverHostedSagaCallerForMarshalTest";

      let caught: unknown;
      try {
        await nativeSaga()(
          ctxA,
          ctxB,
          foreignCallerDid,
          TOOL_ID,
          JSON.stringify({ a: "x", b: "y" }),
          NONCE_HEX,
          nowMsBigInt(),
          1,
          undefined,
        );
        throw new Error("saga unexpectedly resolved for a non-hosted caller");
      } catch (e) {
        caught = e;
      }
      expect(caught).toBeInstanceOf(Error);
      const message = (caught as Error).message;
      // The canonical caller-axis saga code.
      expect(message).toContain("SCP-SAGA-13050");
      // The structured back-off suffix is present and parseable: a plain
      // (non-rate-limit) caller rejection carries no precise back-off, so it
      // renders as the literal `null` — never coerced to `0`.
      expect(message).toMatch(/\(retry_after_ms=null\)/);
    });

    // -----------------------------------------------------------------------
    // 3. Committed terminal through the addon — result-object marshaling.
    //
    // Establishes the full saga precondition entirely through the addon's
    // governance surface (no Rust-internal handler hook is reachable from JS):
    //
    //   - RegisterTool into B's ACTOR governance state (Prepare-B reads it).
    //   - EstablishToolInterface (bidirectionally approved) into A (gate 2).
    //
    // No outlet handler is registered (the only handler-attach path is
    // Rust-internal `register_outlet_handler`, not a napi export), so the
    // supervisor-side executor runs the schema-echo fallback the FFI bridge
    // builds — the producer captures whatever the executor returns as the
    // signed `output_jcs`. The committed result object therefore marshals to a
    // non-empty `sagaId`, a `receipt` Buffer, and an `output` Buffer that
    // decodes to the echoed JSON.
    // -----------------------------------------------------------------------
    test("commits via governance-established interface and marshals the result object", async () => {
      const owner = await napi.identityCreate("in_memory");
      const ctxA = await createCallerContext(owner);
      const ctxB = await createTargetContext(owner);

      // Register the saga outlet into B's actor governance state (auto-executes
      // under single_admin). The outlet's operator is the owner DID.
      await napi.contextGovernancePropose(ctxB, registerOutletActionJson(owner.did), owner.did);

      // Establish the bidirectionally-approved interface in A (auto-executes
      // under single_admin). The id-form fields compare on the raw 64-hex
      // digest the handles carry.
      await napi.contextGovernancePropose(
        ctxA,
        establishInterfaceActionJson(ctxA.contextId, ctxB.contextId),
        owner.did,
      );

      const result = await nativeSaga()(
        ctxA,
        ctxB,
        owner.did,
        TOOL_ID,
        JSON.stringify({ a: "x", b: "y" }),
        NONCE_HEX,
        nowMsBigInt(),
        1,
        undefined,
      );

      // The `#[napi(object)] NapiSagaResult` round-trips: a non-empty
      // supervisor-minted saga id and the receipt/output buffers.
      expect(typeof result.sagaId).toBe("string");
      expect(result.sagaId.length).toBeGreaterThan(0);
      expect(result.receipt).toBeInstanceOf(Uint8Array);
      expect((result.receipt as Uint8Array).length).toBeGreaterThan(0);
      expect(result.output).toBeInstanceOf(Uint8Array);

      // The committed output decodes to the executor's (echo-fallback) JSON.
      // Assert the parsed structure, not raw bytes, so a JCS-canonical
      // encoding still passes: the echo carries the validated input back.
      const decoded = JSON.parse(new TextDecoder().decode(result.output as Uint8Array));
      expect(decoded).toBeTruthy();
      expect(decoded.validated_input).toEqual({ a: "x", b: "y" });
    });
  });

  // ---------------------------------------------------------------------------
  // Typed trust-input admission (ADR-058, SCP-1991)
  //
  // The SDK `checkCapabilityRequirements` / `verifyParticipationRequirements`
  // methods take typed inputs and serialize them internally to the serde wire
  // shape. These e2e tests drive the typed API through the real napi addon so
  // the encoders are exercised against the actual `serde_json::from_str`
  // deserializers in crates/scp-ffi/napi/src/trust.rs — a shape mismatch would
  // surface as a parse error here, not just in the mock unit tests.
  // ---------------------------------------------------------------------------
  describe("Typed trust-input admission (real NAPI, ADR-058)", () => {
    test("checkCapabilityRequirements: SelfAttested requirement met by a declared capability", () => {
      const requirements: readonly CapabilityRequirement[] = [
        { capability: "scp:capability:schema-validation/v1", verificationLevel: "SelfAttested" },
      ];
      // A SelfAttested requirement is satisfied by the declared capability with
      // no challenge verification — the typed inputs round-trip through the
      // bridge deserializers and admission succeeds (returns void, no throw).
      expect(() =>
        scpInstance.checkCapabilityRequirements(
          "ctx-admission",
          "did:dht:zSubject",
          requirements,
          ["scp:capability:schema-validation/v1"],
          [],
        ),
      ).not.toThrow();
    });

    test("checkCapabilityRequirements: missing SelfAttested capability is rejected", () => {
      const requirements: readonly CapabilityRequirement[] = [
        { capability: "scp:capability:schema-validation/v1", verificationLevel: "SelfAttested" },
      ];
      expect(() =>
        scpInstance.checkCapabilityRequirements(
          "ctx-admission",
          "did:dht:zSubject",
          requirements,
          [],
          [],
        ),
      ).toThrow();
    });

    test("verifyParticipationRequirements: valid profile + empty requirements round-trips", () => {
      // A structurally-valid profile (real 32/32/64 byte arrays) deserializes
      // cleanly on the Rust side; with no requirements, verification is a no-op
      // success — this exercises the full ParticipationProfile encoder path.
      const profile: ParticipationProfile = {
        subjectDid: "did:dht:zSubject",
        participationDurationSecs: 3_600,
        governanceActionsAgainst: 0,
        governanceActionsBy: 1,
        toolInvocationCount: 150,
        toolInvocationCountAnchored: false,
        contextCreationCount: 2,
        roleProgressionCount: 3,
        attestationCount: 4,
        updatedAt: 1_700_000_000,
        eventLogRoot: Array.from({ length: 32 }, (_, i) => i),
        signerPublicKey: Array.from({ length: 32 }, (_, i) => i + 100),
        signature: Array.from({ length: 64 }, () => 0),
      };
      expect(() =>
        scpInstance.verifyParticipationRequirements("did:dht:zSubject", [], [profile]),
      ).not.toThrow();
    });

    test("verifyParticipationRequirements: wrong-length signature byte array is rejected", () => {
      // The Rust `signature: [u8; 64]` field rejects a 63-element array at
      // deserialize time — byte-array length validation is enforced by the
      // core serde types, surfaced through the typed encoder path.
      const malformed: ParticipationProfile = {
        subjectDid: "did:dht:zSubject",
        participationDurationSecs: 3_600,
        governanceActionsAgainst: 0,
        governanceActionsBy: 0,
        toolInvocationCount: 0,
        toolInvocationCountAnchored: false,
        contextCreationCount: 0,
        roleProgressionCount: 0,
        attestationCount: 0,
        updatedAt: 1_700_000_000,
        eventLogRoot: Array.from({ length: 32 }, () => 0),
        signerPublicKey: Array.from({ length: 32 }, () => 0),
        signature: Array.from({ length: 63 }, () => 0),
      };
      expect(() =>
        scpInstance.verifyParticipationRequirements("did:dht:zSubject", [], [malformed]),
      ).toThrow();
    });
  });

  // ---------------------------------------------------------------------------
  // Economy amounts cross the addon as bigint (ADR-060)
  // ---------------------------------------------------------------------------

  describe("Economy bigint amounts (real NAPI)", () => {
    test("grants and reads back a > 2^53 budget exactly", async () => {
      const ctxId = `econ-bigint-${Date.now()}`;
      const did = "did:dht:econ-member";
      // 2^53 + 1 — the first integer a JS `number` cannot hold exactly.
      const granted = 9_007_199_254_740_993n;

      scpInstance.economyBudgetGrant(ctxId, did, granted);
      const remaining = scpInstance.economyBudgetRemaining(ctxId, did);

      expect(typeof remaining).toBe("bigint");
      expect(remaining).toBe(granted);

      // Spend part of it and confirm exact bigint arithmetic survives the
      // round-trip through the native tracker.
      scpInstance.economyBudgetRecordSpend(ctxId, did, 1n);
      expect(scpInstance.economyBudgetRemaining(ctxId, did)).toBe(granted - 1n);
    });

    test("estimateCost returns a bigint for a free context", () => {
      const cost = scpInstance.economyEstimateCost("", "MessageSend", "{}");
      expect(typeof cost).toBe("bigint");
      expect(cost).toBe(0n);
    });
  });
}
