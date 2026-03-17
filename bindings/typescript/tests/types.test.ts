/**
 * Type-level tests for shared type definitions.
 *
 * These tests verify that the type definitions compile correctly and
 * can be instantiated with valid data. They serve as compile-time
 * verification rather than runtime tests.
 */

import { describe, expect, it } from "bun:test";
import type {
  AddressResolution,
  ContextParams,
  DIDDocument,
  Event,
  Message,
  ParticipationFact,
  ParticipationProfile,
  ParticipationThreshold,
  Proof,
  RequireParticipation,
  ResolutionPath,
  SiteConfig,
  ToolDefinition,
  TransportStatus,
  TrustLevel,
  UcanToken,
} from "../src/types";
import { validateSiteConfig } from "../src/types";

describe("type definitions", () => {
  it("ContextParams has required ceiling field", () => {
    const params: ContextParams = {
      ceiling: ["messages:read", "messages:write"],
    };
    expect(params.ceiling).toHaveLength(2);
  });

  it("ContextParams accepts all optional fields", () => {
    const params: ContextParams = {
      ceiling: ["messages:read"],
      ttl: 300,
      memoryScope: "ephemeral",
      governance: "single_admin",
      mode: "Encrypted",
      ceilingPolicy: "immutable",
    };
    expect(params.ttl).toBe(300);
    expect(params.memoryScope).toBe("ephemeral");
  });

  it("Message has all required fields", () => {
    const msg: Message = {
      senderDid: "did:dht:z6MkTest",
      content: "hello",
      timestamp: Date.now() / 1000,
      sequence: 1,
      contextId: "ctx-test",
    };
    expect(msg.senderDid).toBe("did:dht:z6MkTest");
  });

  it("DIDDocument has all required fields", () => {
    const doc: DIDDocument = {
      id: "did:dht:z6MkTest",
      verificationMethods: [
        {
          id: "did:dht:z6MkTest#key-0",
          type: "Ed25519VerificationKey2020",
          controller: "did:dht:z6MkTest",
          publicKeyMultibase: "z6Mk...",
        },
      ],
      authentication: ["did:dht:z6MkTest#key-0"],
      assertionMethods: [],
      alsoKnownAs: [],
      serviceEndpoints: [],
      hasAgentKey: false,
    };
    expect(doc.verificationMethods).toHaveLength(1);
  });

  it("ToolDefinition has all required fields", () => {
    const def: ToolDefinition = {
      name: "calculator",
      description: "Simple calculator",
      inputSchema: { type: "object" },
      outputSchema: { type: "object" },
      operator: "did:dht:z6MkTest",
    };
    expect(def.name).toBe("calculator");
  });

  it("UcanToken has all required fields", () => {
    const token: UcanToken = {
      id: "ucan-123",
      encoded: "eyJ...",
      issuer: "did:dht:z6MkIssuer",
      audience: "did:dht:z6MkAudience",
      capabilities: ["messages:read"],
    };
    expect(token.capabilities).toHaveLength(1);
  });

  it("TransportStatus represents connected state", () => {
    const status: TransportStatus = {
      connected: true,
      relayUrl: "wss://relay.example.com",
      latencyMs: 42,
    };
    expect(status.connected).toBe(true);
  });

  it("TransportStatus represents disconnected state", () => {
    const status: TransportStatus = {
      connected: false,
      relayUrl: null,
      latencyMs: null,
    };
    expect(status.connected).toBe(false);
  });

  it("Event has all required fields", () => {
    const event: Event = {
      eventType: "MessageSent",
      actorDid: "did:dht:z6MkTest",
      timestamp: Date.now() / 1000,
      payload: { content: "hello" },
      sequence: 1,
    };
    expect(event.eventType).toBe("MessageSent");
  });

  it("Proof has all required fields", () => {
    const proof: Proof = {
      verified: true,
      proofType: "inclusion",
      details: { path: [] },
    };
    expect(proof.verified).toBe(true);
  });

  // -- Address Resolution types (§22.2.1, §22.7) ---------------------------

  it("TrustLevel accepts all simple variants", () => {
    const levels: TrustLevel[] = [
      { kind: "DirectExchange" },
      { kind: "LocalPetname" },
      { kind: "DomainVerified" },
      { kind: "AttestationVerified" },
      { kind: "DiscoveryContextVerified" },
    ];
    expect(levels).toHaveLength(5);
  });

  it("TrustLevel MultiLayerCorroborated carries sources", () => {
    const level: TrustLevel = {
      kind: "MultiLayerCorroborated",
      sources: [
        { layer: "Petname", source: "local", sourceId: null, resolvedAt: 1700000000 },
        { layer: "Domain", source: "example.com", sourceId: null, resolvedAt: 1700000000 },
      ],
    };
    expect(level.kind).toBe("MultiLayerCorroborated");
    if (level.kind === "MultiLayerCorroborated") {
      expect(level.sources).toHaveLength(2);
    }
  });

  it("ResolutionPath has all required fields", () => {
    const path: ResolutionPath = {
      layer: "DiscoveryContext",
      source: "cooking-community",
      sourceId: "ctx-disc-1",
      resolvedAt: 1700000000,
    };
    expect(path.layer).toBe("DiscoveryContext");
    expect(path.source).toBe("cooking-community");
    expect(path.sourceId).toBe("ctx-disc-1");
    expect(path.resolvedAt).toBe(1700000000);
  });

  it("ResolutionPath allows null sourceId", () => {
    const path: ResolutionPath = {
      layer: "Domain",
      source: "dht",
      sourceId: null,
      resolvedAt: 1700000000,
    };
    expect(path.sourceId).toBeNull();
  });

  it("AddressResolution Identity variant has all fields", () => {
    const resolution: AddressResolution = {
      type: "Identity",
      did: "did:dht:z6MkAlice",
      trustLevel: { kind: "DiscoveryContextVerified" },
      resolutionPath: {
        layer: "DiscoveryContext",
        source: "cooking-community",
        sourceId: "ctx-disc-1",
        resolvedAt: 1700000000,
      },
    };
    expect(resolution.type).toBe("Identity");
    if (resolution.type === "Identity") {
      expect(resolution.did).toBe("did:dht:z6MkAlice");
      expect(resolution.trustLevel.kind).toBe("DiscoveryContextVerified");
      expect(resolution.resolutionPath.layer).toBe("DiscoveryContext");
    }
  });

  it("AddressResolution Context variant has all fields", () => {
    const resolution: AddressResolution = {
      type: "Context",
      contextId: "a1b2c3d4e5f6",
      relayUrls: ["wss://relay.example.com/scp/v1"],
      mode: "broadcast",
      trustLevel: { kind: "DomainVerified" },
      resolutionPath: {
        layer: "Domain",
        source: "dht",
        sourceId: null,
        resolvedAt: 1700000000,
      },
    };
    expect(resolution.type).toBe("Context");
    if (resolution.type === "Context") {
      expect(resolution.contextId).toBe("a1b2c3d4e5f6");
      expect(resolution.relayUrls).toEqual(["wss://relay.example.com/scp/v1"]);
      expect(resolution.mode).toBe("broadcast");
      expect(resolution.trustLevel.kind).toBe("DomainVerified");
      expect(resolution.resolutionPath.layer).toBe("Domain");
    }
  });

  it("AddressResolution Context variant allows null mode", () => {
    const resolution: AddressResolution = {
      type: "Context",
      contextId: "deadbeef",
      relayUrls: [],
      mode: null,
      trustLevel: { kind: "DiscoveryContextVerified" },
      resolutionPath: {
        layer: "DiscoveryContext",
        source: "discovery_context",
        sourceId: "disc-ctx-1",
        resolvedAt: 1700000000,
      },
    };
    if (resolution.type === "Context") {
      expect(resolution.mode).toBeNull();
    }
  });

  // -- Participation types (§7.3.2.1, SCP-BA-004) ----------------------------

  it("ParticipationFact accepts all 7 variants", () => {
    const facts: ParticipationFact[] = [
      "ParticipationDuration",
      "GovernanceActionsAgainst",
      "GovernanceActionsBy",
      "ToolInvocationCount",
      "ContextCreationCount",
      "RoleProgressionCount",
      "AttestationCount",
    ];
    expect(facts).toHaveLength(7);
  });

  it("ParticipationThreshold accepts all 5 operator variants", () => {
    const thresholds: ParticipationThreshold[] = [
      { GreaterThan: 10 },
      { LessThan: 5 },
      { AtLeast: 100 },
      { AtMost: 50 },
      { Equals: 42 },
    ];
    expect(thresholds).toHaveLength(5);
  });

  it("ParticipationProfile has all required fields", () => {
    const profile: ParticipationProfile = {
      subjectDid: "did:dht:z6MkAlice",
      participationDurationSecs: 3600,
      governanceActionsAgainst: 2,
      governanceActionsBy: 5,
      toolInvocationCount: 10,
      contextCreationCount: 3,
      roleProgressionCount: 1,
      attestationCount: 7,
      updatedAt: 1700000000,
      eventLogRoot: new Array(32).fill(0),
      signerPublicKey: new Array(32).fill(1),
      signature: new Array(64).fill(2),
    };
    expect(profile.subjectDid).toBe("did:dht:z6MkAlice");
    expect(profile.participationDurationSecs).toBe(3600);
    expect(profile.governanceActionsAgainst).toBe(2);
    expect(profile.governanceActionsBy).toBe(5);
    expect(profile.toolInvocationCount).toBe(10);
    expect(profile.contextCreationCount).toBe(3);
    expect(profile.roleProgressionCount).toBe(1);
    expect(profile.attestationCount).toBe(7);
    expect(profile.updatedAt).toBe(1700000000);
    expect(profile.eventLogRoot).toHaveLength(32);
    expect(profile.signerPublicKey).toHaveLength(32);
    expect(profile.signature).toHaveLength(64);
  });

  it("RequireParticipation has all required fields", () => {
    const requirement: RequireParticipation = {
      fact: "ParticipationDuration",
      threshold: { AtLeast: 100 },
      maxAgeSecs: 3600,
      minContexts: 1,
    };
    expect(requirement.fact).toBe("ParticipationDuration");
    expect(requirement.maxAgeSecs).toBe(3600);
    expect(requirement.minContexts).toBe(1);
  });

  it("RequireParticipation with GreaterThan threshold", () => {
    const requirement: RequireParticipation = {
      fact: "ToolInvocationCount",
      threshold: { GreaterThan: 50 },
      maxAgeSecs: 7200,
      minContexts: 3,
    };
    expect(requirement.fact).toBe("ToolInvocationCount");
    expect(requirement.maxAgeSecs).toBe(7200);
    expect(requirement.minContexts).toBe(3);
  });

  // -- SiteConfig types (SCP-293, §18.11.12) --------------------------------

  it("SiteConfig with only hostname (defaults)", () => {
    const config: SiteConfig = {
      hostname: "mysite.example.com",
    };
    expect(config.hostname).toBe("mysite.example.com");
    expect(config.indexPath).toBeUndefined();
    expect(config.maxAssetsPerDeploy).toBeUndefined();
    expect(config.maxDeploySizeBytes).toBeUndefined();
    expect(config.deployRetentionCount).toBeUndefined();
    expect(config.cspOverride).toBeUndefined();
  });

  it("SiteConfig with all fields", () => {
    const config: SiteConfig = {
      hostname: "cdn.example.com",
      indexPath: "/home.html",
      maxAssetsPerDeploy: 5000,
      maxDeploySizeBytes: 268435456,
      deployRetentionCount: 4,
      cspOverride: "default-src 'self'",
    };
    expect(config.hostname).toBe("cdn.example.com");
    expect(config.indexPath).toBe("/home.html");
    expect(config.maxAssetsPerDeploy).toBe(5000);
    expect(config.maxDeploySizeBytes).toBe(268435456);
    expect(config.deployRetentionCount).toBe(4);
    expect(config.cspOverride).toBe("default-src 'self'");
  });
});

// ---------------------------------------------------------------------------
// SiteConfig validation (SCP-293)
// ---------------------------------------------------------------------------

describe("validateSiteConfig", () => {
  it("accepts valid config with hostname only", () => {
    expect(() => validateSiteConfig({ hostname: "example.com" })).not.toThrow();
  });

  it("accepts valid config with all fields", () => {
    expect(() =>
      validateSiteConfig({
        hostname: "cdn.example.com",
        indexPath: "/home.html",
        maxAssetsPerDeploy: 5000,
        maxDeploySizeBytes: 268435456,
        deployRetentionCount: 4,
        cspOverride: "default-src 'self'",
      }),
    ).not.toThrow();
  });

  it("rejects empty hostname", () => {
    expect(() => validateSiteConfig({ hostname: "" })).toThrow("hostname must not be empty");
  });

  it("rejects hostname exceeding 253 characters", () => {
    const longHostname = `${"a".repeat(63)}.${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(63)}.e`;
    expect(() => validateSiteConfig({ hostname: longHostname })).toThrow(
      "hostname exceeds 253 characters",
    );
  });

  it("rejects hostname label with invalid characters", () => {
    expect(() => validateSiteConfig({ hostname: "bad_host.com" })).toThrow(
      "hostname label contains invalid characters",
    );
  });

  it("rejects hostname label starting with hyphen", () => {
    expect(() => validateSiteConfig({ hostname: "-bad.com" })).toThrow(
      "hostname label starts or ends with '-'",
    );
  });

  it("rejects hostname label ending with hyphen", () => {
    expect(() => validateSiteConfig({ hostname: "bad-.com" })).toThrow(
      "hostname label starts or ends with '-'",
    );
  });

  it("accepts hostname with hyphens in middle", () => {
    expect(() => validateSiteConfig({ hostname: "my-site.example.com" })).not.toThrow();
  });

  it("accepts single-label hostname", () => {
    expect(() => validateSiteConfig({ hostname: "localhost" })).not.toThrow();
  });

  it("rejects deployRetentionCount of 0", () => {
    expect(() => validateSiteConfig({ hostname: "example.com", deployRetentionCount: 0 })).toThrow(
      "deployRetentionCount must be an integer between 1 and 8",
    );
  });

  it("rejects deployRetentionCount of 9", () => {
    expect(() => validateSiteConfig({ hostname: "example.com", deployRetentionCount: 9 })).toThrow(
      "deployRetentionCount must be an integer between 1 and 8",
    );
  });

  it("accepts deployRetentionCount of 1", () => {
    expect(() =>
      validateSiteConfig({ hostname: "example.com", deployRetentionCount: 1 }),
    ).not.toThrow();
  });

  it("accepts deployRetentionCount of 8", () => {
    expect(() =>
      validateSiteConfig({ hostname: "example.com", deployRetentionCount: 8 }),
    ).not.toThrow();
  });

  it("rejects CSP with unsafe-eval", () => {
    expect(() =>
      validateSiteConfig({ hostname: "example.com", cspOverride: "script-src 'unsafe-eval'" }),
    ).toThrow("CSP must not contain 'unsafe-eval'");
  });

  it("rejects CSP with unsafe-inline", () => {
    expect(() =>
      validateSiteConfig({ hostname: "example.com", cspOverride: "style-src 'unsafe-inline'" }),
    ).toThrow("CSP must not contain 'unsafe-inline'");
  });

  it("rejects CSP with unsafe-hashes", () => {
    expect(() =>
      validateSiteConfig({ hostname: "example.com", cspOverride: "script-src 'unsafe-hashes'" }),
    ).toThrow("CSP must not contain 'unsafe-hashes'");
  });

  it("rejects CSP with bare wildcard", () => {
    expect(() =>
      validateSiteConfig({ hostname: "example.com", cspOverride: "default-src *" }),
    ).toThrow("CSP must not contain bare wildcard '*'");
  });

  it("allows CSP with subdomain wildcard", () => {
    expect(() =>
      validateSiteConfig({ hostname: "example.com", cspOverride: "default-src *.example.com" }),
    ).not.toThrow();
  });

  it("rejects CSP with data: source", () => {
    expect(() =>
      validateSiteConfig({ hostname: "example.com", cspOverride: "img-src data:" }),
    ).toThrow("CSP must not contain 'data:' source");
  });

  it("rejects CSP with blob: source", () => {
    expect(() =>
      validateSiteConfig({ hostname: "example.com", cspOverride: "worker-src blob:" }),
    ).toThrow("CSP must not contain 'blob:' source");
  });

  it("accepts valid CSP", () => {
    expect(() =>
      validateSiteConfig({
        hostname: "example.com",
        cspOverride: "default-src 'self'; script-src 'nonce-abc123'",
      }),
    ).not.toThrow();
  });

  it("rejects CSP with case-variant unsafe-eval", () => {
    expect(() =>
      validateSiteConfig({ hostname: "example.com", cspOverride: "script-src 'Unsafe-Eval'" }),
    ).toThrow("CSP must not contain 'unsafe-eval'");
  });

  it("rejects maxAssetsPerDeploy of 0", () => {
    expect(() => validateSiteConfig({ hostname: "example.com", maxAssetsPerDeploy: 0 })).toThrow(
      "maxAssetsPerDeploy must be >= 1",
    );
  });

  it("rejects maxDeploySizeBytes of -1", () => {
    expect(() => validateSiteConfig({ hostname: "example.com", maxDeploySizeBytes: -1 })).toThrow(
      "maxDeploySizeBytes must be >= 1",
    );
  });

  it("accepts maxAssetsPerDeploy of 1", () => {
    expect(() =>
      validateSiteConfig({ hostname: "example.com", maxAssetsPerDeploy: 1 }),
    ).not.toThrow();
  });

  it("accepts maxDeploySizeBytes of 1", () => {
    expect(() =>
      validateSiteConfig({ hostname: "example.com", maxDeploySizeBytes: 1 }),
    ).not.toThrow();
  });
});
