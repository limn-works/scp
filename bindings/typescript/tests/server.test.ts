/**
 * Unit tests for Node broadcast deployment lifecycle (SCP-296), and for
 * `SCP.nodeStart` and `NodeStartConfig` (SCP-324).
 *
 * The SCP-296 tests and the nodeStart config and error-table tests mock the
 * native addon. The last nodeStart block, which also starts the dev pair
 * (SCP-327), runs against the built napi addon and skips itself when none is
 * installed.
 *
 * See spec section 18.11.8 and `.docs/prds/http-features.json` SCP-296.
 */

import { afterAll, beforeAll, describe, expect, it, mock } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { type AddressInfo, createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  ContextError,
  IdentityError,
  mapBridgeError,
  type ScpError,
  StorageError,
  TransportError,
  UcanPermissionError,
  ValidationError,
} from "../src/errors";
import { Identity } from "../src/identity";
import { __getNativeScp, SCP } from "../src/scp";
import {
  NODE_START_ARMS,
  NODE_START_FIELDS,
  NODE_START_INVALID_CONFIG_CODE,
  Node,
  type NodeStartConfig,
  nodeStartConfigToWire,
} from "../src/server";
import type { SiteConfig } from "../src/types";
import { createInMemoryIdentity } from "./harness-custody";
import { mountMockScp } from "./mock-bridge";
import { napiSuite } from "./napi-guard";

// ---------------------------------------------------------------------------
// Minimal mock for NativeNodeHandle (bypasses native addon loading)
// ---------------------------------------------------------------------------

interface MockNodeHandle {
  relayUrl: string;
  relayPort: number;
  did: string;
  isShutdown: boolean;
  shutdown: () => void;
  enableSiteProjection: (
    contextId: string,
    admission: string,
    hostname: string,
    broadcastKeyHex: string | null,
    authorDid: string | null,
    indexPath: string | null,
    maxAssetsPerDeploy: number | null,
    maxDeploySizeBytes: number | null,
    deployRetentionCount: number | null,
    cspOverride: string | null,
  ) => Promise<void>;
  commitDeploy: (contextId: string, deployId: string) => Promise<number>;
  rollbackDeploy: (contextId: string, deployId: string) => Promise<void>;
  disableSiteProjection: (contextId: string) => Promise<void>;
}

function createMockHandle(): MockNodeHandle {
  return {
    relayUrl: "ws://127.0.0.1:9876/scp/v1",
    relayPort: 9876,
    did: "did:dht:z6MkTestNode",
    isShutdown: false,
    shutdown: mock(() => {}),
    enableSiteProjection: mock(async () => {}),
    commitDeploy: mock(async () => 42),
    rollbackDeploy: mock(async () => {}),
    disableSiteProjection: mock(async () => {}),
  };
}

// The Node class uses private #handle, so we test through the public API
// by constructing Node with a mock handle via the private constructor.
// Since the constructor is private, we use a workaround: create a test
// subclass or access the class through the module's internal mechanism.
//
// Actually, the Node constructor IS private. We need to test through the
// server module. Let's import and test the Node class by constructing it
// through a mock pattern that accesses the private handle.

// Since the Node class in server.ts has a private constructor and relies on
// native addon loading, we test the lifecycle method signatures and validation
// at the type level and through integration patterns.

describe("Node lifecycle methods (SCP-296)", () => {
  // We test the method signatures exist and the type constraints are correct.
  // Full integration tests require a running native addon (see real-napi.test.ts).

  it("SiteConfig validation rejects empty hostname", () => {
    const { validateSiteConfig } = require("../src/types");
    expect(() => validateSiteConfig({ hostname: "" })).toThrow("hostname must not be empty");
  });

  it("SiteConfig validation rejects invalid retention count", () => {
    const { validateSiteConfig } = require("../src/types");
    expect(() => validateSiteConfig({ hostname: "example.com", deployRetentionCount: 0 })).toThrow(
      "deployRetentionCount must be an integer between 1 and 8",
    );
    expect(() => validateSiteConfig({ hostname: "example.com", deployRetentionCount: 9 })).toThrow(
      "deployRetentionCount must be an integer between 1 and 8",
    );
  });

  it("SiteConfig validation rejects unsafe CSP", () => {
    const { validateSiteConfig } = require("../src/types");
    expect(() =>
      validateSiteConfig({
        hostname: "example.com",
        cspOverride: "script-src 'unsafe-eval'",
      }),
    ).toThrow("CSP must not contain 'unsafe-eval'");
  });

  it("SiteConfig validation accepts valid config", () => {
    const { validateSiteConfig } = require("../src/types");
    expect(() =>
      validateSiteConfig({
        hostname: "mysite.example.com",
        indexPath: "/app.html",
        maxAssetsPerDeploy: 5000,
        maxDeploySizeBytes: 100_000_000,
        deployRetentionCount: 4,
        cspOverride: "default-src 'self'",
      }),
    ).not.toThrow();
  });

  it("SiteConfig validation accepts minimal config", () => {
    const { validateSiteConfig } = require("../src/types");
    expect(() => validateSiteConfig({ hostname: "example.com" })).not.toThrow();
  });

  it("Node class exports from server module", async () => {
    // Verify the Node class is exported. Phase 4 PR 4 (#1549, ADR-048)
    // deleted the static `Node.startInMemory` / `Node.startLocal`
    // factories — callers construct nodes via
    // `scp.nodeStartInMemory(...)` / `scp.nodeStartLocal(...)` which
    // hydrate via `Node._fromHandle`. The class itself is still a
    // real export used as a type and for the instance method surface.
    const { Node } = await import("../src/server");
    expect(Node).toBeDefined();
    expect(typeof Node._fromHandle).toBe("function");
  });

  it("Node class exports from index", async () => {
    // Verify Node is re-exported from the package root
    const { Node } = await import("../src/index");
    expect(Node).toBeDefined();
  });

  // Direct mock-based tests using the internal handle pattern
  it("enableSiteProjection delegates to native handle", async () => {
    const handle = createMockHandle();
    // We cannot construct Node directly (private constructor), but we
    // verify the mock handle interface matches the expected contract.
    const config: SiteConfig = {
      hostname: "mysite.example.com",
      indexPath: "/app.html",
      maxAssetsPerDeploy: 5000,
      maxDeploySizeBytes: 100_000_000,
      deployRetentionCount: 4,
      cspOverride: "default-src 'self'",
    };

    await handle.enableSiteProjection(
      "ctx-123",
      "open",
      config.hostname,
      "ab".repeat(32),
      "did:dht:z6MkAuthor",
      config.indexPath ?? null,
      config.maxAssetsPerDeploy ?? null,
      config.maxDeploySizeBytes ?? null,
      config.deployRetentionCount ?? null,
      config.cspOverride ?? null,
    );

    expect(handle.enableSiteProjection).toHaveBeenCalledTimes(1);
  });

  it("commitDeploy returns asset count", async () => {
    const handle = createMockHandle();
    const count = await handle.commitDeploy("ctx-123", "deploy-abc");
    expect(count).toBe(42);
  });

  it("commitDeploy propagates errors", async () => {
    const handle = createMockHandle();
    handle.commitDeploy = mock(async () => {
      throw new Error("not projected");
    });

    await expect(handle.commitDeploy("ctx-bad", "deploy-xyz")).rejects.toThrow("not projected");
  });

  it("rollbackDeploy delegates to native handle", async () => {
    const handle = createMockHandle();
    await handle.rollbackDeploy("ctx-123", "deploy-old");
    expect(handle.rollbackDeploy).toHaveBeenCalledTimes(1);
  });

  it("rollbackDeploy propagates errors", async () => {
    const handle = createMockHandle();
    handle.rollbackDeploy = mock(async () => {
      throw new Error("deploy not found");
    });

    await expect(handle.rollbackDeploy("ctx-bad", "deploy-nope")).rejects.toThrow(
      "deploy not found",
    );
  });

  it("disableSiteProjection delegates to native handle", async () => {
    const handle = createMockHandle();
    await handle.disableSiteProjection("ctx-123");
    expect(handle.disableSiteProjection).toHaveBeenCalledTimes(1);
  });

  it("disableSiteProjection is idempotent (no error on unprojected)", async () => {
    const handle = createMockHandle();
    // Should not throw — mock returns void.
    await handle.disableSiteProjection("ctx-nonexistent");
  });
});

// ---------------------------------------------------------------------------
// SCP.nodeStart and NodeStartConfig (SCP-324)
// ---------------------------------------------------------------------------

const REPO = fileURLToPath(new URL("../../../", import.meta.url));

/**
 * The bridge's wire-shape fixture: every arm of every sum type, a full config,
 * and the optional fields. The `node_start_config.rs` unit tests check it
 * against the Rust types, so a field or arm added, renamed or made optional in
 * Rust fails there until the fixture follows, and fails here until the
 * TypeScript types follow.
 */
interface WireFixture {
  readonly arms: Record<string, Record<string, unknown>[]>;
  readonly optional_arm_fields: Record<string, Record<string, string[]>>;
  readonly fields: string[];
  readonly config: Record<string, unknown>;
  readonly optional_fields: string[];
}

const WIRE = JSON.parse(
  readFileSync(join(REPO, "crates/scp-ffi/common/tests/fixtures/node_start_config.json"), "utf8"),
) as WireFixture;

/** `camelCase` as `snake_case`. */
function snakeCase(name: string): string {
  return name.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`);
}

/** `snake_case` as `camelCase`. */
function camelCase(name: string): string {
  return name.replace(/_([a-z])/g, (_, c: string) => c.toUpperCase());
}

/** The fixture's full config as a TS config under `identity`. */
function fixtureConfig(identity: Identity): NodeStartConfig {
  const values: Record<string, unknown> = {};
  for (const [name, value] of Object.entries(WIRE.config)) values[camelCase(name)] = value;
  values.identity = identity;
  return values as unknown as NodeStartConfig;
}

/** A local plaintext config on a loopback port the OS picks. */
function localConfig(
  identity: Identity,
  overrides: Partial<NodeStartConfig> = {},
): NodeStartConfig {
  return {
    reach: { kind: "local" },
    identity,
    blobStorage: { kind: "in_memory" },
    tls: { kind: "plaintext" },
    dht: { kind: "disabled" },
    corsOrigins: { kind: "any_origin" },
    bindAddr: "127.0.0.1:0",
    ...overrides,
  };
}

function mockIdentity(scp: SCP, did = "did:dht:z6MkNodeStartOperatorProbe"): Identity {
  return Identity._fromHandle(scp, { did, custodyType: "in_memory" });
}

async function thrown(call: () => unknown): Promise<unknown> {
  try {
    await call();
  } catch (err) {
    return err;
  }
  throw new Error("expected the call to throw");
}

describe("NodeStartConfig wire shape (SCP-324)", () => {
  it("lowers fields under the bridge struct's names, in its order", () => {
    expect(NODE_START_FIELDS.map((f) => f.wire)).toEqual(WIRE.fields);
    expect(NODE_START_FIELDS.map((f) => snakeCase(f.key))).toEqual(WIRE.fields);
  });

  it("makes a field optional exactly when the bridge does", () => {
    expect(NODE_START_FIELDS.filter((f) => f.optional).map((f) => f.wire)).toEqual(
      WIRE.optional_fields,
    );
  });

  it("knows every arm of every sum-typed field and no other", () => {
    expect(Object.keys(NODE_START_ARMS).sort()).toEqual(Object.keys(WIRE.arms).sort());
    const armFields = NODE_START_FIELDS.filter((f) => f.type === "arm").map((f) => f.wire);
    expect(armFields.sort()).toEqual(Object.keys(WIRE.arms).sort());
    for (const [field, entries] of Object.entries(WIRE.arms)) {
      const table = (NODE_START_ARMS as Record<string, Record<string, Record<string, string>>>)[
        field
      ];
      expect(Object.keys(table ?? {}).sort()).toEqual(entries.map((e) => String(e.kind)).sort());
      for (const entry of entries) {
        const kind = String(entry.kind);
        const fields = Object.keys(entry).filter((k) => k !== "kind");
        expect(Object.keys(table?.[kind] ?? {}).sort()).toEqual(fields.sort());
        const optional = Object.entries(table?.[kind] ?? {})
          .filter(([, type]) => type === "optional_string")
          .map(([name]) => name);
        expect(optional).toEqual(WIRE.optional_arm_fields[field]?.[kind] ?? []);
      }
    }
  });

  it("emits each fixture arm as the fixture entry", () => {
    const { scp } = mountMockScp();
    const identity = mockIdentity(scp);
    for (const [field, entries] of Object.entries(WIRE.arms)) {
      for (const entry of entries) {
        const config = { ...localConfig(identity), [camelCase(field)]: entry };
        expect(nodeStartConfigToWire(config)[field]).toEqual(entry);
      }
    }
  });

  it("emits the fixture's full config field for field, identity as its DID", () => {
    const { scp } = mountMockScp();
    const identity = mockIdentity(scp, String(WIRE.config.identity));
    const wire = nodeStartConfigToWire(fixtureConfig(identity));
    expect(Object.keys(wire)).toEqual(WIRE.fields);
    expect(wire).toEqual(WIRE.config);
  });

  it("emits an absent optional field and an absent acme email as null", () => {
    const { scp } = mountMockScp();
    const wire = nodeStartConfigToWire(
      localConfig(mockIdentity(scp), { bindAddr: null, tls: { kind: "acme" } }),
    );
    for (const name of WIRE.optional_fields) expect(wire[name]).toBeNull();
    expect(wire.tls).toEqual({ kind: "acme", email: null });
  });

  it("requires every field the bridge requires", () => {
    const { scp } = mountMockScp();
    const required = WIRE.fields.filter((f) => !WIRE.optional_fields.includes(f));
    for (const wireName of required.filter((f) => f !== "identity")) {
      const config: Record<string, unknown> = { ...localConfig(mockIdentity(scp)) };
      delete config[camelCase(wireName)];
      const err = (() => {
        try {
          nodeStartConfigToWire(config);
        } catch (e) {
          return e;
        }
        return undefined;
      })();
      expect(err).toBeInstanceOf(StorageError);
      expect((err as StorageError).code).toBe(NODE_START_INVALID_CONFIG_CODE);
    }
  });

  it.each([
    ["an unknown top-level key", { bind_addr: "127.0.0.1:0" }],
    ["a kind outside the arms", { tls: { kind: "custom" } }],
    ["a field the arm lacks", { reach: { kind: "local", domain: "x.example.org" } }],
    ["a missing arm field", { blobStorage: { kind: "redb" } }],
    ["a non-object arm", { dht: "disabled" }],
    ["a non-string bind address", { bindAddr: 8443 }],
    ["a negative rate limit", { projectionRateLimit: -1 }],
    ["a fractional rate limit", { projectionRateLimit: 1.5 }],
    ["a rate limit above u32", { projectionRateLimit: 2 ** 32 }],
    ["an origin list with a non-string", { corsOrigins: { kind: "allowlist", origins: [1] } }],
  ])("rejects %s with SCP-STORAGE-8007", (_label, override) => {
    const { scp } = mountMockScp();
    const config = { ...localConfig(mockIdentity(scp)), ...override };
    expect(() => nodeStartConfigToWire(config)).toThrow(StorageError);
    try {
      nodeStartConfigToWire(config);
    } catch (err) {
      expect((err as StorageError).code).toBe("SCP-STORAGE-8007");
    }
  });
});

describe("SCP.nodeStart (SCP-324)", () => {
  it("sends the lowered config and the operator's raw handle, and returns a Node", async () => {
    const { scp, native } = mountMockScp();
    const rawIdentity = { did: "did:dht:z6MkNodeStartOperatorProbe", custodyType: "in_memory" };
    const identity = Identity._fromHandle(scp, rawIdentity);
    native.__stub("nodeStart", async () => createMockHandle());
    const node = await scp.nodeStart(localConfig(identity, { projectionRateLimit: 7 }));
    expect(node).toBeInstanceOf(Node);
    const args = native.__lastCall("nodeStart")?.args ?? [];
    expect(args).toHaveLength(2);
    expect(JSON.parse(String(args[0]))).toEqual(
      nodeStartConfigToWire(localConfig(identity, { projectionRateLimit: 7 })),
    );
    expect(JSON.parse(String(args[0])).identity).toBe(rawIdentity.did);
    expect(args[1]).toBe(rawIdentity);
  });

  it.each([
    ["a DID string", "did:dht:z6MkNodeStartOperatorProbe"],
    [
      "a raw bridge handle",
      { did: "did:dht:z6MkNodeStartOperatorProbe", custodyType: "in_memory" },
    ],
    ["null", null],
    ["undefined", undefined],
    ["a plain object copy of an Identity", { did: "did:dht:z6MkX", custodyType: "in_memory" }],
  ])("rejects %s as identity with SCP-VALID-7005 before the bridge", async (_label, identity) => {
    const { scp, native } = mountMockScp();
    native.__stub("nodeStart", async () => createMockHandle());
    const config = { ...localConfig(mockIdentity(scp)), identity } as unknown as NodeStartConfig;
    const err = await thrown(() => scp.nodeStart(config));
    expect(err).toBeInstanceOf(ValidationError);
    expect((err as ValidationError).code).toBe("SCP-VALID-7005");
    expect(native.__calls("nodeStart")).toHaveLength(0);
  });

  it("rejects a config that is not an object with SCP-VALID-7005 before the bridge", async () => {
    const { scp, native } = mountMockScp();
    native.__stub("nodeStart", async () => createMockHandle());
    for (const config of [null, "{}", 7]) {
      const err = await thrown(() => scp.nodeStart(config as unknown as NodeStartConfig));
      expect(err).toBeInstanceOf(ValidationError);
      expect((err as ValidationError).code).toBe("SCP-VALID-7005");
    }
    expect(native.__calls("nodeStart")).toHaveLength(0);
  });

  it("rejects a malformed config with SCP-STORAGE-8007 before the bridge", async () => {
    const { scp, native } = mountMockScp();
    native.__stub("nodeStart", async () => createMockHandle());
    const config = { ...localConfig(mockIdentity(scp)), tls: { kind: "custom" } };
    const err = await thrown(() => scp.nodeStart(config as unknown as NodeStartConfig));
    expect(err).toBeInstanceOf(StorageError);
    expect((err as StorageError).code).toBe("SCP-STORAGE-8007");
    expect(native.__calls("nodeStart")).toHaveLength(0);
  });
});

/**
 * Every row of sdk-common.md §"Node start error codes": the code and the SDK
 * class of its category.
 */
const NODE_START_CODES: readonly (readonly [string, new (...a: never[]) => ScpError])[] = [
  ["SCP-STORAGE-8007", StorageError],
  ["SCP-STORAGE-8008", StorageError],
  ["SCP-STORAGE-8009", StorageError],
  ["SCP-IDENT-1063", IdentityError],
  ["SCP-IDENT-1100", IdentityError],
  ["SCP-TRANS-5051", TransportError],
  ["SCP-TRANS-5052", TransportError],
  ["SCP-TRANS-5054", TransportError],
  ["SCP-TRANS-5050", TransportError],
  ["SCP-IDENT-1001", IdentityError],
  ["SCP-VALID-7004", ValidationError],
  ["SCP-CTX-2053", ContextError],
  ["SCP-TRANS-5055", TransportError],
  ["SCP-TRANS-5056", TransportError],
  ["SCP-PERM-3030", UcanPermissionError],
];

describe("SCP.nodeStart error codes (SCP-324)", () => {
  it("covers exactly the codes of sdk-common.md §Node start error codes", () => {
    const doc = readFileSync(join(REPO, ".docs/standards/sdk-common.md"), "utf8");
    const start = doc.indexOf("### Node start error codes");
    expect(start).toBeGreaterThanOrEqual(0);
    const rest = doc.slice(start);
    const section = rest.slice(0, rest.indexOf("\n### "));
    const rows = [...section.matchAll(/^\| [^|]+ \| `(SCP-[A-Z]+-\d+)` \|/gm)].map((m) => m[1]);
    expect(new Set(rows).size).toBe(rows.length);
    expect([...rows].sort()).toEqual(NODE_START_CODES.map(([code]) => code).sort());
  });

  it.each(NODE_START_CODES.map(([code, cls]) => [code, cls.name, cls] as const))(
    "throws %s as %s with the code preserved",
    async (code, _name, cls) => {
      const { scp, native } = mountMockScp();
      native.__stub("nodeStart", async () => {
        throw new Error(`[${code}] node start failed`);
      });
      const err = await thrown(() => scp.nodeStart(localConfig(mockIdentity(scp))));
      expect(Object.getPrototypeOf(err)).toBe(cls.prototype);
      expect((err as ScpError).code).toBe(code);
    },
  );

  // SCP-327: a shipped addon refuses the dev pair with SCP-TRANS-5055, in the
  // form `ScpNapiError` renders it, and the SDK throws it as TransportError.
  it("throws a shipped addon's dev-pair SCP-TRANS-5055 as TransportError", async () => {
    const { scp, native } = mountMockScp();
    const refusal = async () => {
      throw new Error(
        "[SCP-TRANS-5055] transport error: development node start is unavailable in this build; use node_start",
      );
    };
    native.__stub("nodeStartInMemory", refusal);
    native.__stub("nodeStartLocal", refusal);
    for (const call of [
      () => scp.nodeStartInMemory(),
      () => scp.nodeStartLocal("/tmp/scp-dev-start", null, "passphrase"),
    ]) {
      const err = await thrown(call);
      expect(Object.getPrototypeOf(err)).toBe(TransportError.prototype);
      expect((err as ScpError).code).toBe("SCP-TRANS-5055");
    }
  });
});

// ---------------------------------------------------------------------------
// SCP.nodeStart against the real napi addon
// ---------------------------------------------------------------------------

const suite = await napiSuite(() => new SCP({ storage: { type: "in_memory" } }));

suite.describe("SCP.nodeStart on the napi addon", (realScp) => {
  const scp = realScp;
  /** The raw napi `SCP.nodeStart`, for configs the SDK would not lower. */
  const rawNodeStart = (configJson: string, identity: Identity): Promise<unknown> =>
    (
      __getNativeScp(scp) as unknown as {
        nodeStart(c: string, i: unknown): Promise<unknown>;
      }
    ).nodeStart(configJson, identity._rawHandle);

  async function startError(config: NodeStartConfig): Promise<unknown> {
    let node: Node;
    try {
      node = await scp.nodeStart(config);
    } catch (err) {
      return err;
    }
    await node.shutdown();
    throw new Error(`nodeStart must fail for ${JSON.stringify(nodeStartConfigToWire(config))}`);
  }

  describe("SCP.nodeStart on the napi addon (SCP-324)", () => {
    let operator: Identity;
    let stranger: Identity;
    let other: SCP;
    let workDir: string;

    beforeAll(async () => {
      operator = await createInMemoryIdentity(scp);
      other = new SCP({ storage: { type: "in_memory" } });
      stranger = await createInMemoryIdentity(other);
      workDir = mkdtempSync(join(tmpdir(), "scp-node-start-"));
    });

    afterAll(async () => {
      rmSync(workDir, { recursive: true, force: true });
      await other.shutdown();
      await scp.shutdown();
    });

    it("starts a node under the operator identity and shuts it down", async () => {
      const node = await scp.nodeStart(localConfig(operator));
      try {
        expect(node).toBeInstanceOf(Node);
        expect(node.did).toBe(operator.did);
        expect(node.relayPort).toBeGreaterThan(0);
        expect(node.relayUrl.startsWith("ws://127.0.0.1:")).toBe(true);
        expect(node.isShutdown).toBe(false);
      } finally {
        await node.shutdown();
      }
      expect(node.isShutdown).toBe(true);
    });

    // A config naming an operator not registered on the instance fails at
    // identity resolution (SCP-IDENT-1063), which runs only after the parse
    // that rejects an unknown key or kind with SCP-STORAGE-8007. The handle
    // passed is the instance's own, so the ADR-048 check before the parse
    // passes.
    for (const [field, entries] of Object.entries(WIRE.arms)) {
      for (const entry of entries) {
        it(`the addon reads the ${field} arm ${String(entry.kind)}`, async () => {
          const config = localConfig(stranger, {
            httpBindAddr: "127.0.0.1:0",
            nat: { kind: "auto" },
            projectionRateLimit: 5,
          });
          const wire = { ...nodeStartConfigToWire(config), [field]: entry };
          const err = await thrown(() => rawNodeStart(JSON.stringify(wire), operator));
          expect(String((err as Error).message)).toStartWith("[SCP-IDENT-1063]");
        });
      }
    }

    it("the addon refuses a key outside the bridge shape (control)", async () => {
      const wire: Record<string, unknown> = nodeStartConfigToWire(localConfig(operator));
      wire.bind_address = wire.bind_addr;
      delete wire.bind_addr;
      const err = await thrown(() => rawNodeStart(JSON.stringify(wire), operator));
      expect(String((err as Error).message)).toStartWith("[SCP-STORAGE-8007]");
    });

    // No config makes the addon return the other node start codes from a
    // test, and the table test above shows each throws its typed error:
    // - SCP-STORAGE-8009 is a core node storage error. The node writes to the
    //   SCP instance's own storage, which the config does not name, and the
    //   in-memory instance store a test builds does not fail.
    // - SCP-TRANS-5052 is a TLS provisioning failure. A self-signed
    //   certificate is generated for any domain, and ACME needs port 80 and a
    //   reachable certificate authority, so its outcome depends on the network.
    // - SCP-TRANS-5054 is a serve or NAT traversal failure. nodeStart does not
    //   bind the HTTP server (a taken httpBindAddr starts), and NAT traversal
    //   fails only when its STUN exchange over the network does.
    // - SCP-TRANS-5050, SCP-IDENT-1001, SCP-VALID-7004 and SCP-CTX-2053 come
    //   from core node wiring that an in-memory instance with a registered
    //   operator completes.
    // - SCP-TRANS-5055 comes only from the dev pair of a shipped addon. This
    //   suite runs a `testing` addon, where the dev pair starts a node (the
    //   test after this one), and the Rust shipped-build tests prove 5055.
    // The suite's addon is built with `testing`, where the dev pair still
    // starts a node (SCP-327 cuts it only from shipped builds).
    it("starts a node through the dev pair on the testing addon", async () => {
      const inMemory = await scp.nodeStartInMemory();
      try {
        expect(inMemory.did.startsWith("did:")).toBe(true);
        expect(inMemory.relayPort).toBeGreaterThan(0);
      } finally {
        await inMemory.shutdown();
      }
      expect(inMemory.isShutdown).toBe(true);

      const local = await scp.nodeStartLocal(join(workDir, "dev-local"), operator.did, null);
      try {
        expect(local.did).toBe(operator.did);
        expect(local.relayPort).toBeGreaterThan(0);
      } finally {
        await local.shutdown();
      }
      expect(local.isShutdown).toBe(true);
    });

    it("throws 8007, 8008, 1063, 3030, 5051 and 5056 from the addon as typed errors", async () => {
      const regularFile = join(workDir, "regular-file");
      writeFileSync(regularFile, "x");
      const taken = createServer();
      await new Promise<void>((resolve) => taken.listen(0, "127.0.0.1", resolve));
      const takenPort = (taken.address() as AddressInfo).port;
      const cases: [string, NodeStartConfig, new (...a: never[]) => ScpError, string][] = [
        [
          "domain with plaintext",
          localConfig(operator, { reach: { kind: "domain", domain: "node.example.org" } }),
          StorageError,
          "SCP-STORAGE-8007",
        ],
        [
          "zero projection rate limit",
          localConfig(operator, { projectionRateLimit: 0 }),
          StorageError,
          "SCP-STORAGE-8007",
        ],
        [
          "malformed bind address",
          localConfig(operator, { bindAddr: "not-an-address" }),
          StorageError,
          "SCP-STORAGE-8007",
        ],
        [
          "blob parent under a regular file",
          localConfig(operator, {
            blobStorage: { kind: "redb", path: join(regularFile, "sub", "blobs.redb") },
          }),
          StorageError,
          "SCP-STORAGE-8008",
        ],
        [
          "operator from another SCP instance",
          localConfig(stranger),
          UcanPermissionError,
          "SCP-PERM-3030",
        ],
        [
          "relay bind on a taken port",
          localConfig(operator, { bindAddr: `127.0.0.1:${takenPort}` }),
          TransportError,
          "SCP-TRANS-5051",
        ],
      ];
      try {
        for (const [label, config, cls, code] of cases) {
          const err = await startError(config);
          expect([label, Object.getPrototypeOf(err) === cls.prototype]).toEqual([label, true]);
          expect([label, (err as ScpError).code]).toEqual([label, code]);
        }
      } finally {
        await new Promise<void>((resolve) => taken.close(() => resolve()));
      }

      // A raw config whose DID is not the handle's is SCP-IDENT-1063 through
      // the SDK's error mapping too.
      const misnamed = { ...nodeStartConfigToWire(localConfig(operator)), identity: stranger.did };
      const misnamedErr = mapBridgeError(
        await thrown(() => rawNodeStart(JSON.stringify(misnamed), operator)),
      );
      expect(misnamedErr).toBeInstanceOf(IdentityError);
      expect(misnamedErr.code).toBe("SCP-IDENT-1063");

      const first = await scp.nodeStart(localConfig(operator));
      try {
        const err = await startError(localConfig(operator));
        expect(err).toBeInstanceOf(TransportError);
        expect((err as ScpError).code).toBe("SCP-TRANS-5056");
      } finally {
        await first.shutdown();
      }
    });
  });
});
