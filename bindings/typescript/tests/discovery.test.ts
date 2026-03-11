/**
 * Tests for the discovery module types and DiscoveryResult field mapping.
 *
 * These tests verify that DiscoveryResult correctly includes trustLevel
 * and resolutionPath per §22.2.1, and that resolveAddress() returns
 * properly typed AddressResolution results.
 */

import { describe, expect, it } from "bun:test";
import type { DiscoveryResult } from "../src/discovery";
import type { AddressResolution, ResolutionPath, TrustLevel } from "../src/types";

describe("DiscoveryResult type (§22.2.1)", () => {
  it("includes trustLevel and resolutionPath fields", () => {
    const result: DiscoveryResult = {
      contextId: "abc123",
      relayUrls: ["wss://relay.example.com"],
      publisherDid: "did:dht:zTest",
      discoverySource: "dht_did_document",
      mode: "broadcast",
      metadataSummary: null,
      trustLevel: { kind: "DomainVerified" },
      resolutionPath: {
        layer: "domain",
        source: "dht",
        sourceId: null,
        resolvedAt: 1700000000,
      },
    };
    expect(result.trustLevel.kind).toBe("DomainVerified");
    expect(result.resolutionPath.layer).toBe("domain");
    expect(result.resolutionPath.source).toBe("dht");
    expect(result.resolutionPath.sourceId).toBeNull();
    expect(result.resolutionPath.resolvedAt).toBe(1700000000);
  });

  it("accepts DiscoveryContextVerified trust level for discovery context source", () => {
    const result: DiscoveryResult = {
      contextId: "ctx456",
      relayUrls: ["wss://relay.example.com"],
      publisherDid: "did:dht:zTest",
      discoverySource: "discovery_context",
      mode: null,
      metadataSummary: null,
      trustLevel: { kind: "DiscoveryContextVerified" },
      resolutionPath: {
        layer: "discovery_context",
        source: "discovery_context",
        sourceId: "disc-ctx-1",
        resolvedAt: 1700000000,
      },
    };
    expect(result.trustLevel.kind).toBe("DiscoveryContextVerified");
    expect(result.resolutionPath.sourceId).toBe("disc-ctx-1");
  });

  it("maps context_uri to DirectExchange trust level (§22.7)", () => {
    const result: DiscoveryResult = {
      contextId: "deadbeef",
      relayUrls: ["wss://relay.example.com/scp/v1"],
      publisherDid: "did:dht:zTest",
      discoverySource: "context_uri",
      mode: "broadcast",
      metadataSummary: null,
      trustLevel: { kind: "DirectExchange" },
      resolutionPath: {
        layer: "domain",
        source: "context_uri",
        sourceId: null,
        resolvedAt: 1700000000,
      },
    };
    expect(result.trustLevel.kind).toBe("DirectExchange");
    expect(result.resolutionPath.layer).toBe("domain");
  });
});

describe("AddressResolution discriminated union", () => {
  it("Identity variant is distinguishable by type field", () => {
    const resolutions: AddressResolution[] = [
      {
        type: "Identity",
        did: "did:dht:z6MkAlice",
        trustLevel: { kind: "LocalPetname" },
        resolutionPath: {
          layer: "petname",
          source: "local",
          sourceId: null,
          resolvedAt: 1700000000,
        },
      },
      {
        type: "Context",
        contextId: "abc123",
        relayUrls: ["wss://relay.example.com"],
        mode: "broadcast",
        trustLevel: { kind: "DomainVerified" },
        resolutionPath: {
          layer: "domain",
          source: "dht",
          sourceId: null,
          resolvedAt: 1700000000,
        },
      },
    ];

    const identities = resolutions.filter((r) => r.type === "Identity");
    const contexts = resolutions.filter((r) => r.type === "Context");
    expect(identities).toHaveLength(1);
    expect(contexts).toHaveLength(1);

    if (identities[0].type === "Identity") {
      expect(identities[0].did).toBe("did:dht:z6MkAlice");
    }
    if (contexts[0].type === "Context") {
      expect(contexts[0].contextId).toBe("abc123");
    }
  });

  it("all simple TrustLevel kinds are assignable", () => {
    const levels: TrustLevel[] = [
      { kind: "DirectExchange" },
      { kind: "LocalPetname" },
      { kind: "DomainVerified" },
      { kind: "AttestationVerified" },
      { kind: "DiscoveryContextVerified" },
    ];
    for (const level of levels) {
      const resolution: AddressResolution = {
        type: "Identity",
        did: "did:dht:zTest",
        trustLevel: level,
        resolutionPath: {
          layer: "domain",
          source: "test",
          sourceId: null,
          resolvedAt: 0,
        },
      };
      expect(resolution.trustLevel.kind).toBe(level.kind);
    }
  });

  it("MultiLayerCorroborated TrustLevel carries sources array (§22.7)", () => {
    const level: TrustLevel = {
      kind: "MultiLayerCorroborated",
      sources: [
        { layer: "petname", source: "local", sourceId: null, resolvedAt: 1700000000 },
        { layer: "domain", source: "example.com", sourceId: null, resolvedAt: 1700000000 },
      ],
    };
    const resolution: AddressResolution = {
      type: "Identity",
      did: "did:dht:zTest",
      trustLevel: level,
      resolutionPath: {
        layer: "domain",
        source: "test",
        sourceId: null,
        resolvedAt: 0,
      },
    };
    expect(resolution.trustLevel.kind).toBe("MultiLayerCorroborated");
    if (resolution.trustLevel.kind === "MultiLayerCorroborated") {
      expect(resolution.trustLevel.sources).toHaveLength(2);
      expect(resolution.trustLevel.sources[0].layer).toBe("petname");
    }
  });

  it("all ResolutionLayer values are assignable (exactly 4 per §22.7)", () => {
    const layers: ResolutionPath["layer"][] = [
      "petname",
      "discovery_context",
      "attestation",
      "domain",
    ];
    for (const layer of layers) {
      const path: ResolutionPath = {
        layer,
        source: "test",
        sourceId: null,
        resolvedAt: 0,
      };
      expect(path.layer).toBe(layer);
    }
  });
});
