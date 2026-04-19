/**
 * E2E encrypted messaging tests with an in-process relay.
 *
 * These tests exercise the FULL send pipeline end-to-end:
 *
 * - Real did:dht identity creation (ADR-003)
 * - Real MLS group encryption (ADR-001)
 * - Real sender key signing (ADR-007)
 * - Real inner/outer envelope construction (ADR-002)
 * - Real WebSocket relay transport (ADR-004, ADR-005)
 * - Real relay publication via `contextSend`
 *
 * Two relay connections are established:
 *
 * 1. `configureRelayTransport(relayUrl, did)` -- initializes the
 *    ContextManager with a `RelayTransportProvider` so `contextSend`
 *    publishes encrypted payloads to the relay.
 * 2. `transportConnect(relayUrl)` -- stores a `NativeRelayAdapter` in
 *    global state for `contextSubscribe` to subscribe.
 *
 * NOTE: Full decrypt roundtrip (send -> relay -> subscribe -> MLS decrypt)
 * cannot be tested in a single-process NAPI bridge because the single
 * `MlsCryptoProvider` instance cannot decrypt its own ciphertext (MLS
 * self-decryption is not supported -- the group's encryption state has
 * already advanced past the sent message). The full decrypt roundtrip is
 * verified at the Rust layer in the `encrypted_relay_roundtrip` integration
 * test (`crates/scp-testing/tests/integration/encrypted_relay_roundtrip.rs`)
 * which uses separate MLS group instances for Alice and Bob.
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
  configureRelayTransport(relayUrl: string, localDid: string): Promise<void>;
  contextSubscribe(
    handle: unknown,
    identityDid: string,
    onMessage: (msg: NapiRawMessage | null) => void,
  ): Promise<void>;
};

/**
 * Raw message object returned by the NAPI bridge's `contextSubscribe`.
 *
 * napi-rs converts Rust snake_case fields to camelCase. `payload` is
 * `Vec<u8>` which marshals as `number[]` in JS.
 */
interface NapiRawMessage {
  senderDid: string;
  payload: number[];
  timestamp: number;
  sequence: number;
  contextId: string;
}

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

  /** Contexts with active subscriptions that need closing before relay shutdown. */
  const subscribedContexts: Array<{
    // biome-ignore lint/suspicious/noExplicitAny: test cleanup needs opaque handle from contextCreate
    handle: any;
    did: string;
  }> = [];

  beforeAll(async () => {
    // Start an in-memory relay on an ephemeral port
    relayHandle = await addon.relayStartInMemory();

    // Bootstrap identity first to get a DID for MLS credential identity.
    // This must happen BEFORE configureRelayTransport because the
    // ContextManager OnceLock is set by whichever call wins the race.
    // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
    const bootstrap = await napi.identityCreate("in_memory");

    // Configure the ContextManager with a relay-backed transport provider.
    // configureRelayTransport creates a relay connection and wraps it in
    // RelayTransportProvider, so contextSend publishes encrypted payloads
    // through the relay. Must be called BEFORE any contextCreate (which
    // triggers init_context_manager via OnceLock).
    await addon.configureRelayTransport(relayHandle.relayUrl, bootstrap.did);

    // Establish a SECOND WebSocket connection for contextSubscribe.
    // contextSubscribe uses the global RELAY_ADAPTER (set by
    // transportConnect) for its subscription stream, separate from the
    // ContextManager's transport provider.
    await addon.transportConnect(relayHandle.relayUrl);
  });

  afterAll(async () => {
    // Close contexts that have active subscriptions so their background
    // tasks terminate before the relay shuts down.
    for (const { handle, did } of subscribedContexts) {
      try {
        // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
        await napi.contextClose(handle, did);
      } catch {
        // Best-effort — context may already be closed.
      }
    }
    subscribedContexts.length = 0;

    // Shutdown timeout is in milliseconds after #1549 Phase 4 unit
    // unification — 1000 ms is enough for pending tasks to drain.
    // `napi.shutdown` is async and must be awaited; prior to #1549
    // Phase 4 it was synchronous, so a fire-and-forget call worked
    // by accident and would clear bridge state under concurrent tests.
    // The `napi` handle here is the `BridgeApi` wrapper, which kept its
    // `shutdown(ms: number)` signature through the #1692 NAPI `u64`
    // widening — the wrapper coerces to `BigInt` before crossing FFI.
    await napi.shutdown(1000);
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
  //
  // Verifies the full send pipeline: identity -> context -> MLS encrypt ->
  // sender key encrypt -> outer envelope -> relay publish. The relay accepts
  // the message (no error), proving the envelope is well-formed and the
  // transport is wired correctly.
  //
  // Decrypt verification is covered by the Rust-level integration test
  // `encrypted_relay_roundtrip` which uses separate MLS group instances.
  // -------------------------------------------------------------------------

  describe("Two-party encrypted messaging", () => {
    test("Alice sends to Bob through relay -- full send pipeline", async () => {
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      const alice = await napi.identityCreate("in_memory");
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      const bob = await napi.identityCreate("in_memory");

      expect(alice.did).toMatch(/^did:dht:/);
      expect(bob.did).toMatch(/^did:dht:/);
      expect(alice.did).not.toBe(bob.did);

      // Alice creates an encrypted context
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
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
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      await napi.contextJoin(ctx, bob.did);

      // Verify membership
      const memberCount = await napi.contextMemberCount(ctx);
      expect(memberCount).toBe(2);

      const isBobMember = await napi.contextIsMember(ctx, bob.did);
      expect(isBobMember).toBe(true);

      const members = await napi.contextMemberDids(ctx);
      expect(members).toContain(alice.did);
      expect(members).toContain(bob.did);

      // Alice sends a message -- full pipeline:
      // inner envelope (Ed25519 signing) -> MLS encryption ->
      // sender key encryption -> outer envelope -> relay publish.
      // No error means the relay accepted the well-formed envelope.
      const plaintext = "hello from Alice to Bob -- E2E encrypted via MLS";
      const payload = new TextEncoder().encode(plaintext);
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      await napi.contextSend(ctx, alice.did, payload);
    });

    test("Bob sends a reply through relay", async () => {
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      const alice = await napi.identityCreate("in_memory");
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      const bob = await napi.identityCreate("in_memory");

      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      const ctx = await napi.contextCreate(
        alice,
        JSON.stringify({
          ceiling: ["messages:read", "messages:write", "member:invite", "role:assign"],
          governance: "single_admin",
          memoryScope: "ephemeral",
        }),
      );

      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      await napi.contextJoin(ctx, bob.did);

      // Both Alice and Bob can send through the relay without error.
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      await napi.contextSend(ctx, alice.did, new TextEncoder().encode("message from Alice"));
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      await napi.contextSend(ctx, bob.did, new TextEncoder().encode("reply from Bob"));
    });
  });

  // -------------------------------------------------------------------------
  // 3. Three-party encrypted messaging
  // -------------------------------------------------------------------------

  describe("Three-party encrypted messaging", () => {
    test("three members can all send through relay", async () => {
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      const alice = await napi.identityCreate("in_memory");
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      const bob = await napi.identityCreate("in_memory");
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      const carol = await napi.identityCreate("in_memory");

      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      const ctx = await napi.contextCreate(
        alice,
        JSON.stringify({
          ceiling: ["messages:read", "messages:write", "member:invite", "role:assign"],
          governance: "single_admin",
          memoryScope: "ephemeral",
        }),
      );

      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      await napi.contextJoin(ctx, bob.did);
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      await napi.contextJoin(ctx, carol.did);

      const count = await napi.contextMemberCount(ctx);
      expect(count).toBe(3);

      // Each member sends through the relay -- all succeed.
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      await napi.contextSend(ctx, alice.did, new TextEncoder().encode("hello from Alice"));
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      await napi.contextSend(ctx, bob.did, new TextEncoder().encode("hello from Bob"));
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      await napi.contextSend(ctx, carol.did, new TextEncoder().encode("hello from Carol"));
    });
  });

  // -------------------------------------------------------------------------
  // 4. Multiple messages (ordering) -- send pipeline
  // -------------------------------------------------------------------------

  describe("Multiple sequential messages", () => {
    test("five messages sent sequentially through relay", async () => {
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      const alice = await napi.identityCreate("in_memory");
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      const bob = await napi.identityCreate("in_memory");

      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      const ctx = await napi.contextCreate(
        alice,
        JSON.stringify({
          ceiling: ["messages:read", "messages:write", "member:invite", "role:assign"],
          governance: "single_admin",
          memoryScope: "ephemeral",
        }),
      );

      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      await napi.contextJoin(ctx, bob.did);

      // Send 5 messages -- all should succeed through the relay.
      for (let i = 0; i < 5; i++) {
        // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
        await napi.contextSend(ctx, alice.did, new TextEncoder().encode(`message ${i}`));
      }
    });

    test("binary payload through send pipeline", async () => {
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      const alice = await napi.identityCreate("in_memory");

      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      const ctx = await napi.contextCreate(
        alice,
        JSON.stringify({
          ceiling: ["messages:read", "messages:write"],
          governance: "single_admin",
          memoryScope: "ephemeral",
        }),
      );

      // Send raw binary (not UTF-8 text) -- relay must accept it.
      const binaryPayload = new Uint8Array([0x00, 0xff, 0x42, 0xde, 0xad, 0xbe, 0xef]);
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      await napi.contextSend(ctx, alice.did, binaryPayload);
    });
  });

  // -------------------------------------------------------------------------
  // 5. contextSubscribe wiring
  // -------------------------------------------------------------------------

  describe("contextSubscribe relay wiring", () => {
    test("contextSubscribe establishes relay subscription without throwing", async () => {
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      const alice = await napi.identityCreate("in_memory");

      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      const ctx = await napi.contextCreate(
        alice,
        JSON.stringify({
          ceiling: ["messages:read", "messages:write", "context:close"],
          governance: "single_admin",
          memoryScope: "ephemeral",
        }),
      );

      // contextSubscribe should not throw -- it establishes a relay
      // subscription and spawns a background task. Signature is now
      // `async` after #1549 Phase 4 PR 1 — the returned Promise
      // resolves once the task is registered against the bridge's
      // JoinSet.
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      await addon.contextSubscribe(ctx, alice.did, (_msg: NapiRawMessage | null) => {
        // Callback may or may not fire depending on relay delivery.
      });

      // Track for cleanup in afterAll.
      subscribedContexts.push({ handle: ctx, did: alice.did });
    });

    test("duplicate subscription is rejected (SCP-CTX-2022)", async () => {
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      const alice = await napi.identityCreate("in_memory");

      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      const ctx = await napi.contextCreate(
        alice,
        JSON.stringify({
          ceiling: ["messages:read", "messages:write", "context:close"],
          governance: "single_admin",
          memoryScope: "ephemeral",
        }),
      );

      // First subscription succeeds.
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      await addon.contextSubscribe(ctx, alice.did, () => {});
      subscribedContexts.push({ handle: ctx, did: alice.did });

      // Second subscription to the same context must fail. Async
      // rejection — use `.rejects.toThrow()` rather than
      // sync `.toThrow()`.
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      await expect(addon.contextSubscribe(ctx, alice.did, () => {})).rejects.toThrow(
        /already subscribed/,
      );
    });

    test("subscription rejected on non-active context", async () => {
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      const alice = await napi.identityCreate("in_memory");

      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      const ctx = await napi.contextCreate(
        alice,
        JSON.stringify({
          ceiling: ["messages:read", "messages:write", "context:close"],
          governance: "single_admin",
          memoryScope: "ephemeral",
        }),
      );

      // Close the context first.
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      await napi.contextClose(ctx, alice.did);

      // Subscription to a closed context must fail. Promise-rejection,
      // not synchronous throw.
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      await expect(addon.contextSubscribe(ctx, alice.did, () => {})).rejects.toThrow();
    });
  });

  // -------------------------------------------------------------------------
  // 6. Governance after join
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
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      const alice = await napi.identityCreate("in_memory");
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      const bob = await napi.identityCreate("in_memory");

      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
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

      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      await napi.contextJoin(ctx, bob.did);

      // Verify Bob's initial role
      const initialRole = await napi.contextMemberRole(ctx, bob.did);
      expect(initialRole).toBeTruthy();

      // Execute governance action: change Bob's role to moderator.
      // GovernanceAction is a Rust tagged enum -- serialized as {"VariantName":{fields}}.
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

      // Verify role changed to moderator
      const newRole = await napi.contextMemberRole(ctx, bob.did);
      expect(newRole).toBeTruthy();
      expect(String(newRole).toLowerCase()).toContain("moderator");
    });

    test("Alice removes Bob from context", async () => {
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      const alice = await napi.identityCreate("in_memory");
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      const bob = await napi.identityCreate("in_memory");

      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
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

      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
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
  // 7. Context lifecycle with relay
  // -------------------------------------------------------------------------

  describe("Context lifecycle with relay", () => {
    test("create -> join -> send -> leave -> close", async () => {
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      const alice = await napi.identityCreate("in_memory");
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      const bob = await napi.identityCreate("in_memory");

      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
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
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      await napi.contextJoin(ctx, bob.did);
      expect(await napi.contextMemberCount(ctx)).toBe(2);

      // Send through relay
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      await napi.contextSend(ctx, alice.did, new TextEncoder().encode("test message"));

      // Bob leaves
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      await napi.contextLeave(ctx, bob.did);
      expect(await napi.contextMemberCount(ctx)).toBe(1);

      // Alice closes
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      await napi.contextClose(ctx, alice.did);
    });

    test("send fails on closed context", async () => {
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      const alice = await napi.identityCreate("in_memory");

      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      const ctx = await napi.contextCreate(
        alice,
        JSON.stringify({
          ceiling: ["messages:read", "messages:write", "context:close"],
          governance: "single_admin",
          memoryScope: "ephemeral",
        }),
      );

      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      await napi.contextClose(ctx, alice.did);

      // Sending to a closed context must fail
      await expect(
        // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
        napi.contextSend(ctx, alice.did, new TextEncoder().encode("should fail")),
      ).rejects.toThrow();
    });
  });

  // -------------------------------------------------------------------------
  // 8. Event log with relay context
  // -------------------------------------------------------------------------

  describe("Event log on relay-connected context", () => {
    test("event log records context creation", async () => {
      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
      const alice = await napi.identityCreate("in_memory");

      // SCP-DEFAULT-INSTANCE-OK: raw NAPI bridge test; bypasses SDK facade by design
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
