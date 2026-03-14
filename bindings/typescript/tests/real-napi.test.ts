/**
 * Real NAPI bridge E2E tests for the SCP TypeScript SDK (Phase D5).
 *
 * These tests exercise the actual napi-rs native addon compiled from
 * `crates/scp-ffi/napi/`. They verify that the TypeScript SDK classes
 * correctly delegate through the real FFI bridge to scp-core Rust code.
 *
 * Prerequisites:
 * - The NAPI bridge must be compiled with `allow_in_memory_custody` feature.
 * - The platform-specific `@limn-works/scp-ts-napi-*` package must be loadable.
 *
 * If the native addon is not available, all tests are skipped gracefully.
 */

import { afterAll, describe, expect, test } from "bun:test";

// ---------------------------------------------------------------------------
// Guard: skip all tests if the native NAPI binding is unavailable.
// ---------------------------------------------------------------------------

let bridge: Awaited<ReturnType<typeof import("../src/internal/bridge").getBridge>> | null = null;
let skipReason = "";

try {
  // Attempt to load the native bridge synchronously to detect availability.
  const { createNativeBridge } = await import("../src/internal/native.js");
  bridge = createNativeBridge();
} catch (e: unknown) {
  const msg = e instanceof Error ? e.message : String(e);
  skipReason = `Native NAPI bridge not available: ${msg}`;
}

// When the bridge is unavailable, define a single test that reports the skip.
if (bridge === null) {
  describe("Real NAPI bridge E2E (SKIPPED)", () => {
    test.skip(`all tests skipped: ${skipReason}`, () => {});
  });
} else {
  // Capture the bridge in a const for type narrowing.
  const napi = bridge;

  // ---------------------------------------------------------------------------
  // Lifecycle hooks
  // ---------------------------------------------------------------------------

  afterAll(() => {
    napi.shutdown(1);
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

    // identityLoad and identityResolve require DHT network resolution which is
    // not available for in-memory identities in CI. Skip until a local identity
    // registry fallback is implemented. See #1144.
    test.skip("loads an identity by DID (requires DHT — #1144)", async () => {
      const created = await napi.identityCreate("in_memory");
      const loaded = await napi.identityLoad(created.did);
      expect(loaded.did).toBe(created.did);
    });

    test.skip("resolves a DID to a DID document (no agent key) (requires DHT — #1144)", async () => {
      const handle = await napi.identityCreate("in_memory");
      const doc = await napi.identityResolve(handle.did);
      expect(doc.id).toBe(handle.did);
      // The document should have at least one authentication method.
      expect(doc.authentication.length).toBeGreaterThanOrEqual(1);
      // Verification methods must have non-empty publicKeyMultibase (issue #547).
      expect(doc.verificationMethods.length).toBeGreaterThanOrEqual(1);
      expect(doc.verificationMethods[0].publicKeyMultibase).toBeTruthy();
      expect(doc.verificationMethods[0].publicKeyMultibase.startsWith("z")).toBe(true);
      // Identity created without agent key: hasAgentKey must be false.
      expect(doc.hasAgentKey).toBe(false);
      expect(doc.agentPublicKey).toBeUndefined();
    });

    test.skip("resolves a DID to a DID document (with agent key, ADR-039) (requires DHT — #1144)", async () => {
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

    test("sends a message without error", async () => {
      const identity = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({ ceiling: ["messages:read", "messages:write"] }),
      );
      const payload = new TextEncoder().encode("hello from NAPI");
      // Should not throw.
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

    test("creates a context with governance and TTL", async () => {
      const identity = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({
          ceiling: ["messages:read"],
          governance: "threshold",
          ttlSeconds: 3600,
          memoryScope: "full",
          ceilingPolicy: "governed",
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
        inputSchema: { type: "object" },
        outputSchema: { type: "object" },
        operator: identity.did,
      });
      expect(typeof toolId).toBe("string");
      expect(toolId.length).toBeGreaterThan(0);
    });

    // toolInvoke requires UCAN authorization but the NAPI bridge's
    // validate_tool_invocation_ucan uses a different capability URI format
    // (tool_invoke:{id}) than what ucanMint produces (tool:invoke:*).
    // Skip until the Rust UCAN capability URI format is unified. See #1144.
    test.skip("invokes a registered tool (UCAN format mismatch — #1144)", async () => {
      const identity = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({ ceiling: ["tool:register", "tool:invoke:*"] }),
      );
      const toolId = await napi.toolRegister(ctx, {
        name: "test-tool",
        description: "A test tool",
        inputSchema: { type: "object" },
        outputSchema: { type: "object" },
        operator: identity.did,
      });
      const ucan = await napi.ucanMint(ctx, identity.did, ["tool:invoke:*"]);
      const resultJson = await napi.toolInvoke(
        ctx,
        toolId,
        JSON.stringify({ x: 42 }),
        identity.did,
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
        inputSchema: { type: "object" },
        outputSchema: { type: "object" },
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

    test("validates a minted token for a granted capability", async () => {
      const admin = await napi.identityCreate("in_memory");
      const member = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(admin, JSON.stringify({ ceiling: ["messages:read"] }));

      const token = await napi.ucanMint(ctx, member.did, ["messages:read"]);
      // Should not throw.
      await napi.ucanValidate(ctx, token.encoded, "messages:read");
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
      // Revocation should not throw.
      await napi.ucanRevoke(ctx, token.encoded);
    });
  });

  // ---------------------------------------------------------------------------
  // 6. Event log
  // ---------------------------------------------------------------------------

  describe("Event log (real NAPI)", () => {
    test("queries events after context creation", async () => {
      const identity = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({ ceiling: ["messages:read"] }),
      );
      const events = await napi.eventLogQuery(ctx, undefined);
      // At minimum, a ContextCreated event should exist.
      expect(events.length).toBeGreaterThanOrEqual(1);
      expect(events[0].eventType).toBeTruthy();
      expect(events[0].actorDid).toBeTruthy();
      expect(typeof events[0].sequence).toBe("number");
    });

    test("queries events with a filter", async () => {
      const identity = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({ ceiling: ["messages:read", "messages:write"] }),
      );
      await napi.contextSend(ctx, identity.did, new TextEncoder().encode("msg"));

      const events = await napi.eventLogQuery(ctx, { eventType: "MessageSent" });
      expect(Array.isArray(events)).toBe(true);
    });

    test("verifies an inclusion proof", async () => {
      const identity = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({ ceiling: ["messages:read"] }),
      );

      const proof = await napi.eventLogVerify(ctx, { type: "inclusion", leafIndex: 0 });
      expect(typeof proof.verified).toBe("boolean");
      expect(typeof proof.proofType).toBe("string");
    });

    test("creates a checkpoint", async () => {
      const identity = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({ ceiling: ["messages:read"] }),
      );

      const checkpoint = await napi.eventLogCheckpoint(ctx, identity.did, 0);
      expect(checkpoint.root).toBeTruthy();
      expect(typeof checkpoint.eventCount).toBe("number");
      expect(typeof checkpoint.timestamp).toBe("number");
    });
  });

  // ---------------------------------------------------------------------------
  // 7. Discovery
  // ---------------------------------------------------------------------------

  describe("Discovery (real NAPI)", () => {
    test("parses a discovery handle address", () => {
      const result = napi.discoveryParseAddress("alice@cooking-community");
      const parsed = JSON.parse(result);
      expect(parsed.type).toBe("DiscoveryHandle");
      expect(parsed.local_part).toBe("alice");
    });

    test("parses a domain handle address", () => {
      const result = napi.discoveryParseAddress("alice@example.com");
      const parsed = JSON.parse(result);
      expect(parsed.type).toBe("DomainHandle");
      expect(parsed.local_part).toBe("alice");
      expect(parsed.domain).toBe("example.com");
    });

    test("creates a discovery query with capabilities", () => {
      const result = napi.discoveryCreateQuery(["code_review"], undefined, undefined);
      expect(typeof result).toBe("string");
      const parsed = JSON.parse(result);
      expect(parsed.capability_filter).toContain("code_review");
    });

    test("creates a discovery query with keywords", () => {
      const result = napi.discoveryCreateQuery(undefined, ["rust", "security"], undefined);
      const parsed = JSON.parse(result);
      expect(parsed.keywords).toContain("rust");
      expect(parsed.keywords).toContain("security");
    });

    test("creates an empty discovery query", () => {
      const result = napi.discoveryCreateQuery(undefined, undefined, undefined);
      expect(typeof result).toBe("string");
      // Should be valid JSON.
      JSON.parse(result);
    });

    test("normalizes an address (lowercases and trims)", () => {
      const result = napi.discoveryNormalizeAddress("  ALICE@Cooking  ");
      expect(result).toBe("alice@cooking");
    });

    test("discovers contexts from an scp:// URI", async () => {
      const uri =
        "scp://context/deadbeef?relay=wss%3A%2F%2Frelay.example.com%2Fscp%2Fv1&mode=broadcast";
      const raw = await napi.contextDiscover(uri);
      const results = JSON.parse(raw);
      expect(Array.isArray(results)).toBe(true);
      expect(results.length).toBe(1);
      expect(results[0].context_id).toBe("deadbeef");
      expect(results[0].discovery_source).toBe("context_uri");
    });

    test("rejects discovery with an invalid query", async () => {
      await expect(napi.contextDiscover("not-a-did-or-uri")).rejects.toThrow();
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
        undefined,
        undefined,
        undefined,
        undefined,
      );
      const record = JSON.parse(raw);
      expect(record.source_context).toBe("ctx-source");
      expect(record.chain_depth).toBe(1);
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
        undefined,
        undefined,
        undefined,
        "redacted",
      );
      const record = JSON.parse(raw);
      // Redacted policy results in empty counterparties.
      expect(record.counterparties).toEqual([]);
    });

    test("checks chain depth within default limit (3)", () => {
      expect(napi.provenanceCheckChainDepth(0, undefined)).toBe(true);
      expect(napi.provenanceCheckChainDepth(3, undefined)).toBe(true);
      expect(napi.provenanceCheckChainDepth(4, undefined)).toBe(false);
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
    test("evaluates trust for native non-bridged action (highest tier)", () => {
      const tier = napi.bridgeEvaluateTrust(false, true, "shadow");
      expect(typeof tier).toBe("number");
      // Native + non-bridged should be highest trust.
      expect(tier).toBe(3);
    });

    test("evaluates trust for shadow bridged action (lowest tier)", () => {
      const tier = napi.bridgeEvaluateTrust(true, false, "shadow");
      expect(typeof tier).toBe("number");
      expect(tier).toBeLessThan(3);
    });

    test("evaluates trust for claimed bridged action", () => {
      const tier = napi.bridgeEvaluateTrust(true, false, "claimed");
      expect(typeof tier).toBe("number");
      // Claimed should be higher trust than shadow when bridged.
      const shadowTier = napi.bridgeEvaluateTrust(true, false, "shadow");
      expect(tier).toBeGreaterThanOrEqual(shadowTier);
    });

    test("registers a bridge connector", () => {
      const reg = napi.bridgeRegister(
        "ctx-bridge-test",
        "did:key:operator",
        "did:key:governance",
        "discord",
        "relay",
      );
      expect(reg.bridge_id).toBeTruthy();
      expect(reg.operator_did).toBe("did:key:operator");
      expect(reg.platform).toBe("discord");
      expect(reg.mode).toBe("relay");
      expect(reg.status).toBe("active");
      expect(reg.context_id).toBe("ctx-bridge-test");
    });

    test("rejects self-approval (operator === governance)", () => {
      expect(() =>
        napi.bridgeRegister("ctx-self", "did:key:operator", "did:key:operator", "discord", "relay"),
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
      for (const mode of ["relay", "puppet", "api", "cooperative"]) {
        const reg = napi.bridgeRegister(`ctx-${mode}`, "did:key:op", "did:key:gov", "slack", mode);
        expect(reg.status).toBe("active");
      }
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

    test("shutdown with 0 timeout returns immediately", () => {
      // Should not hang.
      napi.shutdown(0);
    });
  });

  // ---------------------------------------------------------------------------
  // 12. End-to-end scenario: full context lifecycle
  // ---------------------------------------------------------------------------

  describe("E2E context lifecycle (real NAPI)", () => {
    test("create -> join -> send -> membership check -> leave -> close", async () => {
      // Create identities.
      const alice = await napi.identityCreate("in_memory");
      const bob = await napi.identityCreate("in_memory");

      // Create context.
      const ctx = await napi.contextCreate(
        alice,
        JSON.stringify({
          ceiling: ["messages:read", "messages:write", "role:assign", "context:close"],
          memoryScope: "ephemeral",
          governance: "single_admin",
        }),
      );

      // Verify initial state.
      expect(await napi.contextMemberCount(ctx)).toBe(1);
      expect(await napi.contextIsMember(ctx, alice.did)).toBe(true);
      expect(await napi.contextIsMember(ctx, bob.did)).toBe(false);

      // Bob joins.
      await napi.contextJoin(ctx, bob.did);
      expect(await napi.contextMemberCount(ctx)).toBe(2);
      expect(await napi.contextIsMember(ctx, bob.did)).toBe(true);

      // Alice sends a message.
      await napi.contextSend(ctx, alice.did, new TextEncoder().encode("hello bob"));

      // Verify event log has entries.
      const events = await napi.eventLogQuery(ctx, undefined);
      expect(events.length).toBeGreaterThanOrEqual(1);

      // Checkpoint the event log.
      const checkpoint = await napi.eventLogCheckpoint(ctx, alice.did, 0);
      expect(checkpoint.eventCount).toBeGreaterThanOrEqual(1);

      // Bob leaves.
      await napi.contextLeave(ctx, bob.did);

      // Alice closes.
      await napi.contextClose(ctx, alice.did);
    });
  });

  // ---------------------------------------------------------------------------
  // 13. E2E: UCAN mint -> validate -> revoke
  // ---------------------------------------------------------------------------

  describe("E2E UCAN lifecycle (real NAPI)", () => {
    test("mint -> validate -> revoke -> validation fails", async () => {
      const admin = await napi.identityCreate("in_memory");
      const member = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        admin,
        JSON.stringify({ ceiling: ["messages:read", "messages:write"] }),
      );

      // Mint.
      const token = await napi.ucanMint(ctx, member.did, ["messages:read", "messages:write"]);
      expect(token.capabilities.length).toBe(2);

      // Validate both capabilities.
      await napi.ucanValidate(ctx, token.encoded, "messages:read");
      await napi.ucanValidate(ctx, token.encoded, "messages:write");

      // Revoke.
      await napi.ucanRevoke(ctx, token.encoded);

      // Validation should now fail.
      await expect(napi.ucanValidate(ctx, token.encoded, "messages:read")).rejects.toThrow();
    });
  });

  // ---------------------------------------------------------------------------
  // 14. E2E: Tools register + invoke + verify
  // ---------------------------------------------------------------------------

  describe("E2E tool lifecycle (real NAPI)", () => {
    // toolInvoke UCAN validation uses a different capability URI format
    // (tool_invoke:{id}) than what ucanMint produces (tool:invoke:*).
    // Skip until the Rust UCAN capability URI format is unified. See #1144.
    test.skip("register -> invoke -> verify (UCAN format mismatch — #1144)", async () => {
      const identity = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({
          ceiling: ["tool:register", "tool:invoke:*"],
        }),
      );

      // Register.
      const toolId = await napi.toolRegister(ctx, {
        name: "e2e-tool",
        description: "End-to-end test tool",
        inputSchema: {
          type: "object",
          properties: { value: { type: "number" } },
        },
        outputSchema: {
          type: "object",
          properties: { doubled: { type: "number" } },
        },
        operator: identity.did,
      });
      expect(toolId).toBeTruthy();

      // Invoke.
      const ucan = await napi.ucanMint(ctx, identity.did, ["tool:invoke:*"]);
      const resultJson = await napi.toolInvoke(
        ctx,
        toolId,
        JSON.stringify({ value: 21 }),
        identity.did,
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
        undefined,
        undefined,
        undefined,
        undefined,
      );
      const prov = JSON.parse(provRaw);
      expect(prov.chain_depth).toBe(1);

      // Check the chain depth is within limit.
      expect(napi.provenanceCheckChainDepth(prov.chain_depth, undefined)).toBe(true);

      // Create a discovery query for the destination context.
      const queryJson = napi.discoveryCreateQuery(["messages:read"], ["collaboration"], 3600);
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

    test("publish sends a broadcast message", async () => {
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
      // Should not throw.
      await napi.broadcastPublish(ctx, identity.did, payload);
    });

    test("block subscriber removes and blocks a subscriber", async () => {
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

      // Block the subscriber.
      await napi.broadcastBlockSubscriber(ctx, subscriber.did, identity.did);
      expect(await napi.broadcastIsSubscriber(ctx, subscriber.did)).toBe(false);
    });

    test("unblock restores subscriber after block", async () => {
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

      // Block then unblock.
      await napi.broadcastBlockSubscriber(ctx, subscriber.did, identity.did);
      expect(await napi.broadcastIsSubscriber(ctx, subscriber.did)).toBe(false);

      await napi.broadcastUnblockSubscriber(ctx, subscriber.did, identity.did);
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

    test("handle key request returns a decision", async () => {
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

      const decision = await napi.broadcastHandleKeyRequest(ctx, identity.did, subscriber.did);
      expect(typeof decision).toBe("string");
      expect(decision.length).toBeGreaterThan(0);
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

      // Execute a ChangeRole governance action.
      const actionJson = JSON.stringify({
        ChangeRole: {
          target_did: member.did,
          new_role: "Moderator",
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

    test("exports and imports a context round-trip", async () => {
      const identity = await napi.identityCreate("in_memory");
      const ctx = await napi.contextCreate(
        identity,
        JSON.stringify({
          ceiling: ["messages:read"],
          memoryScope: "ephemeral",
        }),
      );

      // Export.
      const data = await napi.contextExport(ctx);
      expect(data.length).toBeGreaterThan(0);

      // Import.
      const importedContextId = await napi.contextImport(data);
      expect(typeof importedContextId).toBe("string");
      expect(importedContextId.length).toBeGreaterThan(0);
    });

    test("import rejects invalid data", async () => {
      const invalidData = new Uint8Array([0, 1, 2, 3]);
      await expect(napi.contextImport(invalidData)).rejects.toThrow();
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
    test("create -> subscribe -> publish -> check subscriber -> unsubscribe", async () => {
      const author = await napi.identityCreate("in_memory");
      const subscriber = await napi.identityCreate("in_memory");

      // Create broadcast context.
      const ctx = await napi.contextCreate(
        author,
        JSON.stringify({
          ceiling: ["messages:read", "messages:write"],
          mode: "Broadcast",
          memoryScope: "full",
        }),
      );

      // Initial state.
      expect(await napi.broadcastSubscriberCount(ctx)).toBe(0);

      // Subscribe.
      await napi.broadcastSubscribe(ctx, subscriber.did);
      expect(await napi.broadcastIsSubscriber(ctx, subscriber.did)).toBe(true);
      expect(await napi.broadcastSubscriberCount(ctx)).toBe(1);

      // Publish.
      const payload = new TextEncoder().encode("broadcast message");
      await napi.broadcastPublish(ctx, author.did, payload);

      // Unsubscribe.
      await napi.broadcastUnsubscribe(ctx, subscriber.did);
      expect(await napi.broadcastIsSubscriber(ctx, subscriber.did)).toBe(false);
      expect(await napi.broadcastSubscriberCount(ctx)).toBe(0);
    });
  });
}
