/**
 * Real WASM bridge integration tests for the SCP TypeScript SDK.
 *
 * These tests exercise the actual wasm-bindgen compiled module from
 * `crates/scp-ffi/wasm/`. They verify that the WASM bridge functions
 * correctly implement the protocol operations.
 *
 * Prerequisites:
 * - The WASM bridge must be compiled with `wasm-pack build crates/scp-ffi/wasm --target bundler`.
 * - A web-target build must also be available at `crates/scp-ffi/wasm/pkg-web/`
 *   (symlinked to `node_modules/@limn-works/scp-ts-wasm`) for bun/Node.js loading.
 *
 * If the WASM module is not available, all tests are skipped gracefully.
 */

import { describe, expect, test } from "bun:test";

// ---------------------------------------------------------------------------
// Guard: skip all tests if the WASM module is unavailable.
// ---------------------------------------------------------------------------

type WasmBridge = Awaited<ReturnType<typeof import("../src/internal/wasm").createWasmBridge>>;

let bridge: WasmBridge | null = null;
// biome-ignore lint/suspicious/noExplicitAny: raw WASM module has dynamic shape
let wasmModule: any = null;
let skipReason = "";

try {
  const { initWasm, createWasmBridge } = await import("../src/internal/wasm");
  await initWasm();
  bridge = createWasmBridge();
  // Also import the raw WASM module for operations that need the native
  // WasmContextHandle (the adapter converts it to a plain object, which
  // breaks _assertClass checks on subsequent calls).
  wasmModule = await import("@limn-works/scp-ts-wasm");
} catch (e: unknown) {
  const msg = e instanceof Error ? e.message : String(e);
  skipReason = `WASM bridge not available: ${msg}`;
}

// When the bridge is unavailable, define a single test that reports the skip.
if (bridge === null || wasmModule === null) {
  describe("Real WASM bridge E2E (SKIPPED)", () => {
    test.skip(`all tests skipped: ${skipReason}`, () => {});
  });
} else {
  // Capture for type narrowing.
  const wasm = bridge;
  const raw = wasmModule;

  // ---------------------------------------------------------------------------
  // 1. Provenance quality evaluation
  // ---------------------------------------------------------------------------

  describe("Provenance quality (real WASM)", () => {
    test("evaluates quality for an active persistent context", async () => {
      const quality = await wasm.evaluateProvenanceQuality(
        "ctx-source-123",
        "persistent",
        "active",
        ["did:dht:z6MkTestCounterparty"],
      );
      expect(typeof quality).toBe("number");
      expect(quality).toBeGreaterThanOrEqual(0);
      expect(quality).toBeLessThanOrEqual(3);
    });

    test("evaluates quality without a source context", async () => {
      const quality = await wasm.evaluateProvenanceQuality(
        undefined,
        "ephemeral",
        "unknown",
        undefined,
      );
      expect(typeof quality).toBe("number");
      // No source context + unknown state should be lowest quality.
      expect(quality).toBe(0);
    });

    test("evaluates quality for an ephemeral active context", async () => {
      const quality = await wasm.evaluateProvenanceQuality("ctx-eph", "ephemeral", "active", []);
      expect(typeof quality).toBe("number");
      expect(quality).toBeGreaterThanOrEqual(0);
    });
  });

  // ---------------------------------------------------------------------------
  // 2. Provenance attach
  // ---------------------------------------------------------------------------

  describe("Provenance attach (real WASM)", () => {
    test("attaches provenance metadata at a cross-context boundary", () => {
      const rawJson = wasm.provenanceAttach(
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
      const record = JSON.parse(rawJson);
      expect(record.source_context).toBe("ctx-source");
      expect(record.chain_depth).toBe(0);
      expect(Array.isArray(record.counterparties)).toBe(true);
      expect(record.counterparties).toContain("did:dht:z6MkMember1");
      expect(record.discovery_method).toBe("OutOfBand");
      expect(record.purpose).toBeNull();
      expect(record.payment_amount).toBeNull();
      expect(record.payment_adapter).toBeNull();
      expect(record.payment_receipt_id).toBeNull();
    });

    test("attaches provenance with existing chain depth", () => {
      const rawJson = wasm.provenanceAttach(
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
      const record = JSON.parse(rawJson);
      // Chain depth should be existing + 1 = 3.
      expect(record.chain_depth).toBe(3);
    });

    test("attaches provenance with discovery_method SharedContext", () => {
      const rawJson = wasm.provenanceAttach(
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
      const record = JSON.parse(rawJson);
      expect(record.discovery_method).toEqual({ SharedContext: "ctx-shared-abc" });
      expect(record.purpose).toBe("data sharing purpose");
    });

    test("attaches provenance with discovery_method Registry", () => {
      const rawJson = wasm.provenanceAttach(
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
      const record = JSON.parse(rawJson);
      expect(record.discovery_method).toEqual({ Registry: "ctx-registry-abc" });
    });

    test("checks chain depth within default limit (8)", () => {
      expect(wasm.provenanceCheckChainDepth(0, undefined)).toBe(true);
      expect(wasm.provenanceCheckChainDepth(8, undefined)).toBe(true);
      expect(wasm.provenanceCheckChainDepth(9, undefined)).toBe(false);
    });

    test("checks chain depth with custom limit", () => {
      expect(wasm.provenanceCheckChainDepth(1, 1)).toBe(true);
      expect(wasm.provenanceCheckChainDepth(2, 1)).toBe(false);
    });
  });

  // ---------------------------------------------------------------------------
  // 3. Event log query
  // ---------------------------------------------------------------------------

  describe("Event log (real WASM)", () => {
    test("queries events after context creation", async () => {
      const identity = await raw.identity_create("in_memory");
      const ctx = await raw.context_create(
        identity.did,
        JSON.stringify({ ceiling: ["messages:read"] }),
      );

      const eventsJson = await raw.event_log_query(ctx, undefined);
      const events = JSON.parse(eventsJson);

      // At minimum, a LogSummary event should exist after context creation.
      expect(events.length).toBeGreaterThanOrEqual(1);
      expect(events[0].eventType).toBeTruthy();
      expect(typeof events[0].sequence).toBe("number");
      expect(typeof events[0].timestamp).toBe("number");
    });

    test("queries events with a filter", async () => {
      const identity = await raw.identity_create("in_memory");
      const ctx = await raw.context_create(
        identity.did,
        JSON.stringify({ ceiling: ["messages:read", "messages:write"] }),
      );

      const eventsJson = await raw.event_log_query(
        ctx,
        JSON.stringify({ eventType: "ContextCreated" }),
      );
      const events = JSON.parse(eventsJson);
      expect(Array.isArray(events)).toBe(true);
    });

    test("verifies an inclusion proof", async () => {
      const identity = await raw.identity_create("in_memory");
      const ctx = await raw.context_create(
        identity.did,
        JSON.stringify({ ceiling: ["messages:read"] }),
      );

      const proof = await raw.event_log_verify(
        ctx,
        JSON.stringify({ type: "inclusion", leafIndex: 0 }),
      );
      expect(typeof proof.verified).toBe("boolean");
      expect(typeof proof.proofType).toBe("string");
    });
  });

  // ---------------------------------------------------------------------------
  // 4. UCAN validation
  // ---------------------------------------------------------------------------

  describe("UCAN validation (real WASM)", () => {
    test("rejects a malformed JWT token", async () => {
      const identity = await raw.identity_create("in_memory");
      const ctx = await raw.context_create(
        identity.did,
        JSON.stringify({ ceiling: ["messages:read"] }),
      );

      await expect(
        raw.ucan_validate(
          ctx,
          "not-a-jwt",
          `scp:ctx:${ctx.contextId}/messages:read`,
          identity.did,
          undefined,
        ),
      ).rejects.toThrow();
    });

    test("rejects a token with invalid base64 segments", async () => {
      const identity = await raw.identity_create("in_memory");
      const ctx = await raw.context_create(
        identity.did,
        JSON.stringify({ ceiling: ["messages:read"] }),
      );

      // Three segments but invalid base64 content.
      await expect(
        raw.ucan_validate(
          ctx,
          "aaa.bbb.ccc",
          `scp:ctx:${ctx.contextId}/messages:read`,
          identity.did,
          undefined,
        ),
      ).rejects.toThrow();
    });

    test("rejects validation with an empty token", async () => {
      const identity = await raw.identity_create("in_memory");
      const ctx = await raw.context_create(
        identity.did,
        JSON.stringify({ ceiling: ["messages:read"] }),
      );

      await expect(
        raw.ucan_validate(
          ctx,
          "",
          `scp:ctx:${ctx.contextId}/messages:read`,
          identity.did,
          undefined,
        ),
      ).rejects.toThrow();
    });

    test("ucan_revoke succeeds for authorized revoker", async () => {
      const identity = await raw.identity_create("in_memory");
      const ctx = await raw.context_create(
        identity.did,
        JSON.stringify({ ceiling: ["messages:read"] }),
      );

      // Construct a valid UCAN JWT for revocation (issuer = creator DID).
      const header = btoa(JSON.stringify({ alg: "EdDSA", typ: "JWT", ucv: "0.10.0" }))
        .replace(/=/g, "")
        .replace(/\+/g, "-")
        .replace(/\//g, "_");
      const payload = btoa(
        JSON.stringify({
          iss: identity.did,
          aud: "did:dht:zMember",
          exp: 9999999999,
          nnc: "1699999000000-aabbccdd11223344",
          att: [],
          prf: [],
        }),
      )
        .replace(/=/g, "")
        .replace(/\+/g, "-")
        .replace(/\//g, "_");
      const sig = btoa("test-signature-bytes-000000000000")
        .replace(/=/g, "")
        .replace(/\+/g, "-")
        .replace(/\//g, "_");
      const testJwt = `${header}.${payload}.${sig}`;

      // Revocation by the context creator (authorized) should succeed.
      await raw.ucan_revoke(ctx, testJwt, identity.did);
    });
  });

  // ---------------------------------------------------------------------------
  // 5. Identity lifecycle (via adapter)
  // ---------------------------------------------------------------------------

  describe("Identity (real WASM)", () => {
    test("creates an in-memory identity with a valid did:dht DID", async () => {
      const handle = await wasm.identityCreate("in_memory");
      expect(handle.did).toMatch(/^did:dht:/);
      expect(handle.custodyType).toBe("in_memory");
    });

    test("creates two identities with distinct DIDs", async () => {
      const a = await wasm.identityCreate("in_memory");
      const b = await wasm.identityCreate("in_memory");
      expect(a.did).not.toBe(b.did);
    });
  });

  // ---------------------------------------------------------------------------
  // 6. Context lifecycle (via raw WASM)
  // ---------------------------------------------------------------------------

  describe("Context lifecycle (real WASM)", () => {
    test("creates a context and returns a context ID", async () => {
      const identity = await raw.identity_create("in_memory");
      const ctx = await raw.context_create(
        identity.did,
        JSON.stringify({
          ceiling: ["messages:read", "messages:write"],
          memoryScope: "ephemeral",
        }),
      );
      expect(ctx.contextId).toBeTruthy();
      expect(typeof ctx.contextId).toBe("string");
    });

    test("a second identity can join the context", async () => {
      const creator = await raw.identity_create("in_memory");
      const joiner = await raw.identity_create("in_memory");
      const ctx = await raw.context_create(
        creator.did,
        JSON.stringify({ ceiling: ["messages:read"] }),
      );
      // Should not throw.
      await raw.context_join(ctx, joiner.did);
    });

    test("leaves a context without error", async () => {
      const identity = await raw.identity_create("in_memory");
      const ctx = await raw.context_create(
        identity.did,
        JSON.stringify({ ceiling: ["messages:read"] }),
      );
      await raw.context_leave(ctx, identity.did);
    });
  });

  // ---------------------------------------------------------------------------
  // 7. Sync classification
  // ---------------------------------------------------------------------------

  describe("Sync classification (real WASM)", () => {
    test("classifies a short offline duration", () => {
      const now = 1_000_000;
      const lastContact = now - 3600; // 1 hour ago
      const result = wasm.syncClassifyOffline(lastContact, now);
      expect(result).toBe("short");
    });

    test("classifies an extended offline duration", () => {
      const now = 1_000_000;
      const lastContact = now - 100_000; // ~27 hours ago
      const result = wasm.syncClassifyOffline(lastContact, now);
      expect(result).toBe("extended");
    });

    test("classifies a long offline duration", () => {
      const now = 2_000_000;
      const lastContact = 1_000_000; // ~11 days
      const result = wasm.syncClassifyOffline(lastContact, now);
      expect(result).toBe("long");
    });
  });

  // ---------------------------------------------------------------------------
  // 8. Bridge trust evaluation
  // ---------------------------------------------------------------------------

  describe("Bridge trust (real WASM)", () => {
    test("evaluates trust for native non-bridged action (highest tier)", () => {
      const tier = wasm.bridgeEvaluateTrust(false, true, "shadow");
      expect(typeof tier).toBe("number");
      expect(tier).toBe(3);
    });

    test("evaluates trust for bridged action (lower tier)", () => {
      const tier = wasm.bridgeEvaluateTrust(true, false, "shadow");
      expect(typeof tier).toBe("number");
      expect(tier).toBeLessThan(3);
    });
  });

  // ---------------------------------------------------------------------------
  // 9. E2E: Provenance + event log + UCAN validation
  // ---------------------------------------------------------------------------

  describe("E2E cross-cutting (real WASM)", () => {
    test("provenance attach -> chain depth check -> event log query -> UCAN reject", async () => {
      // Provenance attach.
      const provRaw = wasm.provenanceAttach(
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
      expect(prov.chain_depth).toBe(0);
      expect(prov.counterparties).toContain("did:dht:z6MkA");

      // Chain depth check.
      expect(wasm.provenanceCheckChainDepth(prov.chain_depth, undefined)).toBe(true);

      // Create context and query event log.
      const identity = await raw.identity_create("in_memory");
      const ctx = await raw.context_create(
        identity.did,
        JSON.stringify({ ceiling: ["messages:read", "messages:write"] }),
      );

      const eventsJson = await raw.event_log_query(ctx, undefined);
      const events = JSON.parse(eventsJson);
      expect(events.length).toBeGreaterThanOrEqual(1);

      // UCAN validation should reject an invalid token.
      await expect(
        raw.ucan_validate(
          ctx,
          "invalid.token.here",
          `scp:ctx:${ctx.contextId}/messages:read`,
          identity.did,
          undefined,
        ),
      ).rejects.toThrow();
    });
  });

  // ---------------------------------------------------------------------------
  // 10. Version
  // ---------------------------------------------------------------------------

  describe("Version (real WASM)", () => {
    test("version returns a non-empty string", () => {
      const v = wasm.version();
      expect(typeof v).toBe("string");
      expect(v.length).toBeGreaterThan(0);
    });
  });
}
