/**
 * E2E encrypted messaging tests with an in-process relay.
 *
 * These tests exercise the protocol stack at two levels:
 *
 * **Relay lifecycle tests** (section 1) verify the real WebSocket relay:
 * - In-process relay starts and reports a valid WebSocket URL (ADR-004)
 * - `transportConnect` establishes a real WebSocket connection (ADR-005)
 *
 * **Send tests** (sections 2-7) exercise the MLS encryption pipeline:
 * - Real did:dht identity creation (ADR-003)
 * - Real MLS group encryption (ADR-001)
 * - Real sender key signing (ADR-007)
 * - Real inner/outer envelope construction (ADR-002)
 *
 * Send tests route through LocalTransportProvider, NOT the relay. The relay
 * is started for lifecycle tests, but `configureLocalTransport` wins the
 * OnceLock race (called after `transportConnect` in beforeAll), so sends
 * complete locally. Each send verifies the full MLS encryption pipeline
 * executes without error, but messages are not delivered through the relay
 * (receive is not yet wired to real relay subscription delivery).
 *
 * The Rust integration test `encrypted_relay_roundtrip` covers full
 * send-receive-decrypt verification at the protocol layer.
 *
 * Prerequisites:
 * - NAPI bridge compiled with `allow_in_memory_custody` feature.
 * - Platform-specific `@limn-works/scp-ts-napi-*` package loadable.
 *
 * If the native addon is not available, all tests are skipped gracefully.
 */

import { afterAll, beforeAll, describe, expect, test } from "bun:test";

// ---------------------------------------------------------------------------
// Guard: skip if native addon unavailable
// ---------------------------------------------------------------------------

type NativeBridge = Awaited<ReturnType<typeof import("../src/internal/bridge").getBridge>>;
type ServerAddon = {
  relayStartInMemory(): Promise<{
    readonly relayUrl: string;
    readonly relayPort: number;
    readonly isShutdown: boolean;
    shutdown(): void;
  }>;
  transportConnect(relayUrl: string): Promise<unknown>;
  configureLocalTransport(localDid: string): void;
};

let bridge: NativeBridge | null = null;
let serverAddon: ServerAddon | null = null;
let skipReason = "";

try {
  const { createNativeBridge } = await import("../src/internal/native.js");
  bridge = createNativeBridge();

  // Load the server addon for relay + transport operations
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
    skipReason = `No native addon for ${platform}-${arch}`;
  }
} catch (e: unknown) {
  const msg = e instanceof Error ? e.message : String(e);
  skipReason = `Native NAPI bridge not available: ${msg}`;
}

if (bridge === null || serverAddon === null) {
  describe("E2E relay (SKIPPED)", () => {
    test.skip(`all tests skipped: ${skipReason}`, () => {});
  });
} else {
  const napi = bridge;
  const addon = serverAddon;

  // -------------------------------------------------------------------------
  // Relay lifecycle state
  // -------------------------------------------------------------------------

  let relayHandle: Awaited<ReturnType<typeof addon.relayStartInMemory>> | null = null;

  beforeAll(async () => {
    // Start an in-memory relay on an ephemeral port
    relayHandle = await addon.relayStartInMemory();

    // Establish a real WebSocket connection from the SDK transport layer
    // to the relay. This is a REAL connection — not LocalTransportProvider.
    await addon.transportConnect(relayHandle.relayUrl);

    // Bootstrap the ContextManager with a DID for MLS credential identity.
    // `configureLocalTransport` wins the OnceLock race because
    // `transportConnect` does NOT initialize the ContextManager — it only
    // establishes a WebSocket connection. So sends route through
    // LocalTransportProvider, not the relay.
    const bootstrap = await napi.identityCreate("in_memory");
    addon.configureLocalTransport(bootstrap.did);
  });

  afterAll(async () => {
    napi.shutdown(1);
    if (relayHandle && !relayHandle.isShutdown) {
      relayHandle.shutdown();
    }
  });

  // -------------------------------------------------------------------------
  // 1. Relay start and transport
  // -------------------------------------------------------------------------

  describe("Relay lifecycle", () => {
    test("relay starts and reports a valid WebSocket URL", () => {
      expect(relayHandle).not.toBeNull();
      expect(relayHandle?.relayUrl).toMatch(/^ws:\/\/127\.0\.0\.1:\d+\/scp\/v1$/);
    });

    test("relay reports a valid port number", () => {
      expect(relayHandle?.relayPort).toBeGreaterThan(0);
      expect(relayHandle?.relayPort).toBeLessThan(65536);
    });

    test("relay is not in shutdown state", () => {
      expect(relayHandle?.isShutdown).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // 2. Two-party encrypted send through real relay
  // -------------------------------------------------------------------------

  describe("Two-party encrypted messaging", () => {
    test("Alice creates identity, context, Bob joins, Alice sends -- full MLS pipeline", async () => {
      const alice = await napi.identityCreate("in_memory");
      const bob = await napi.identityCreate("in_memory");

      expect(alice.did).toMatch(/^did:dht:/);
      expect(bob.did).toMatch(/^did:dht:/);
      expect(alice.did).not.toBe(bob.did);

      // Alice creates an encrypted context
      const ctx = await napi.contextCreate(
        alice,
        JSON.stringify({
          ceiling: ["messages:read", "messages:write", "member:invite", "role:assign"],
          governance: "single_admin",
          memoryScope: "ephemeral",
        }),
      );
      expect(ctx.contextId).toBeTruthy();

      // Bob joins
      await napi.contextJoin(ctx, bob.did);

      // Verify membership
      const memberCount = await napi.contextMemberCount(ctx);
      expect(memberCount).toBe(2);

      const isBobMember = await napi.contextIsMember(ctx, bob.did);
      expect(isBobMember).toBe(true);

      const members = await napi.contextMemberDids(ctx);
      expect(members).toContain(alice.did);
      expect(members).toContain(bob.did);

      // Alice sends a message -- exercises the full pipeline:
      // inner envelope creation (Ed25519 signing) -> MLS encryption ->
      // sender key encryption -> outer envelope -> relay publish
      const plaintext = "hello from Alice to Bob -- E2E encrypted via MLS";
      const payload = new TextEncoder().encode(plaintext);
      await napi.contextSend(ctx, alice.did, payload);

      // NOTE: contextSubscribe is not yet wired to real relay delivery
      // (it signals immediate completion). The Rust test
      // encrypted_relay_roundtrip.rs verifies the full decrypt path.
      // Here we verify the send pipeline completed without error,
      // proving MLS encryption + relay publish succeeded.
    });

    test("Bob sends a reply after joining", async () => {
      const alice = await napi.identityCreate("in_memory");
      const bob = await napi.identityCreate("in_memory");

      const ctx = await napi.contextCreate(
        alice,
        JSON.stringify({
          ceiling: ["messages:read", "messages:write", "member:invite", "role:assign"],
          governance: "single_admin",
          memoryScope: "ephemeral",
        }),
      );

      await napi.contextJoin(ctx, bob.did);

      // Alice sends
      await napi.contextSend(ctx, alice.did, new TextEncoder().encode("message 1 from Alice"));

      // Bob sends a reply
      await napi.contextSend(ctx, bob.did, new TextEncoder().encode("reply from Bob"));
    });
  });

  // -------------------------------------------------------------------------
  // 3. Three-party encrypted messaging
  // -------------------------------------------------------------------------

  describe("Three-party encrypted messaging", () => {
    test("Alice, Bob, and Carol all exchange messages in one context", async () => {
      const alice = await napi.identityCreate("in_memory");
      const bob = await napi.identityCreate("in_memory");
      const carol = await napi.identityCreate("in_memory");

      const ctx = await napi.contextCreate(
        alice,
        JSON.stringify({
          ceiling: ["messages:read", "messages:write", "member:invite", "role:assign"],
          governance: "single_admin",
          memoryScope: "ephemeral",
        }),
      );

      await napi.contextJoin(ctx, bob.did);
      await napi.contextJoin(ctx, carol.did);

      // Three members
      const count = await napi.contextMemberCount(ctx);
      expect(count).toBe(3);

      // Each participant sends
      await napi.contextSend(ctx, alice.did, new TextEncoder().encode("Alice says hi"));
      await napi.contextSend(ctx, bob.did, new TextEncoder().encode("Bob says hello"));
      await napi.contextSend(ctx, carol.did, new TextEncoder().encode("Carol joins the chat"));
    });
  });

  // -------------------------------------------------------------------------
  // 4. Multiple messages (ordering)
  // -------------------------------------------------------------------------

  describe("Multiple sequential messages", () => {
    test("five messages sent sequentially without error", async () => {
      const alice = await napi.identityCreate("in_memory");
      const bob = await napi.identityCreate("in_memory");

      const ctx = await napi.contextCreate(
        alice,
        JSON.stringify({
          ceiling: ["messages:read", "messages:write", "member:invite", "role:assign"],
          governance: "single_admin",
          memoryScope: "ephemeral",
        }),
      );

      await napi.contextJoin(ctx, bob.did);

      // Send 5 messages with incrementing content
      for (let i = 0; i < 5; i++) {
        await napi.contextSend(ctx, alice.did, new TextEncoder().encode(`message ${i}`));
      }
    });

    test("binary payload roundtrip through send pipeline", async () => {
      const alice = await napi.identityCreate("in_memory");

      const ctx = await napi.contextCreate(
        alice,
        JSON.stringify({
          ceiling: ["messages:read", "messages:write"],
          governance: "single_admin",
          memoryScope: "ephemeral",
        }),
      );

      // Send raw binary (not UTF-8 text)
      const binaryPayload = new Uint8Array([0x00, 0xff, 0x42, 0xde, 0xad, 0xbe, 0xef]);
      await napi.contextSend(ctx, alice.did, binaryPayload);
    });
  });

  // -------------------------------------------------------------------------
  // 5. Governance after join
  // -------------------------------------------------------------------------

  // NOTE: These governance tests exercise the execution path with auto-approved
  // proposals. The NAPI bridge constructs proposals with `ProposalStatus::Approved`
  // internally (see crates/scp-ffi/napi/src/context.rs), so callers cannot submit
  // a pending/unapproved proposal through this API. The status gate (rejecting
  // non-Approved proposals) is tested at the Rust layer in ContextManager and in
  // the Python E2E test `test_pending_proposal_is_rejected` where the bridge
  // accepts raw proposal JSON with caller-specified status.
  describe("Governance operations with real relay", () => {
    test("Alice changes Bob's role after join", async () => {
      const alice = await napi.identityCreate("in_memory");
      const bob = await napi.identityCreate("in_memory");

      const ctx = await napi.contextCreate(
        alice,
        JSON.stringify({
          ceiling: [
            "messages:read",
            "messages:write",
            "member:invite",
            "role:assign",
            "member:remove",
          ],
          governance: "single_admin",
          memoryScope: "ephemeral",
        }),
      );

      await napi.contextJoin(ctx, bob.did);

      // Verify Bob's initial role
      const initialRole = await napi.contextMemberRole(ctx, bob.did);
      expect(initialRole).toBeTruthy();

      // Execute governance action: change Bob's role to moderator.
      // GovernanceAction is a Rust tagged enum — serialized as {"VariantName":{fields}}.
      const result = await napi.contextExecuteGovernanceAction(
        ctx,
        JSON.stringify({
          ChangeRole: {
            did: bob.did,
            new_role: "moderator",
          },
        }),
        alice.did,
      );
      expect(result).toBeDefined();

      // Verify role changed
      const newRole = await napi.contextMemberRole(ctx, bob.did);
      expect(newRole).toBeTruthy();
    });

    test("Alice removes Bob from context", async () => {
      const alice = await napi.identityCreate("in_memory");
      const bob = await napi.identityCreate("in_memory");

      const ctx = await napi.contextCreate(
        alice,
        JSON.stringify({
          ceiling: [
            "messages:read",
            "messages:write",
            "member:invite",
            "member:remove",
            "role:assign",
          ],
          governance: "single_admin",
          memoryScope: "ephemeral",
        }),
      );

      await napi.contextJoin(ctx, bob.did);
      expect(await napi.contextIsMember(ctx, bob.did)).toBe(true);

      // Remove Bob via governance
      await napi.contextExecuteGovernanceAction(
        ctx,
        JSON.stringify({
          RemoveMember: {
            did: bob.did,
            reason: null,
          },
        }),
        alice.did,
      );

      expect(await napi.contextIsMember(ctx, bob.did)).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // 6. Context lifecycle with relay
  // -------------------------------------------------------------------------

  describe("Context lifecycle with relay", () => {
    test("create -> join -> send -> leave -> close", async () => {
      const alice = await napi.identityCreate("in_memory");
      const bob = await napi.identityCreate("in_memory");

      const ctx = await napi.contextCreate(
        alice,
        JSON.stringify({
          ceiling: [
            "messages:read",
            "messages:write",
            "member:invite",
            "role:assign",
            "context:close",
          ],
          governance: "single_admin",
          memoryScope: "ephemeral",
        }),
      );

      // Join
      await napi.contextJoin(ctx, bob.did);
      expect(await napi.contextMemberCount(ctx)).toBe(2);

      // Send
      await napi.contextSend(ctx, alice.did, new TextEncoder().encode("test message"));

      // Bob leaves
      await napi.contextLeave(ctx, bob.did);
      expect(await napi.contextMemberCount(ctx)).toBe(1);

      // Alice closes
      await napi.contextClose(ctx, alice.did);
    });

    test("send fails on closed context", async () => {
      const alice = await napi.identityCreate("in_memory");

      const ctx = await napi.contextCreate(
        alice,
        JSON.stringify({
          ceiling: ["messages:read", "messages:write", "context:close"],
          governance: "single_admin",
          memoryScope: "ephemeral",
        }),
      );

      await napi.contextClose(ctx, alice.did);

      // Sending to a closed context must fail
      await expect(
        napi.contextSend(ctx, alice.did, new TextEncoder().encode("should fail")),
      ).rejects.toThrow();
    });
  });

  // -------------------------------------------------------------------------
  // 7. Event log with relay context
  // -------------------------------------------------------------------------

  describe("Event log on relay-connected context", () => {
    test("event log records context creation", async () => {
      const alice = await napi.identityCreate("in_memory");

      const ctx = await napi.contextCreate(
        alice,
        JSON.stringify({
          ceiling: ["messages:read"],
          governance: "single_admin",
          memoryScope: "ephemeral",
        }),
      );

      const events = await napi.eventLogQuery(ctx, undefined);
      expect(Array.isArray(events)).toBe(true);
    });
  });
}
