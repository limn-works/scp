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
      trustLevel: "DomainVerified",
      resolutionPath: {
        layer: "Domain",
        source: "dht",
        sourceId: null,
        resolvedAt: 1700000000,
      },
    };
    expect(result.trustLevel).toBe("DomainVerified");
    expect(result.resolutionPath.layer).toBe("Domain");
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
      trustLevel: "DiscoveryContextVerified",
      resolutionPath: {
        layer: "DiscoveryContext",
        source: "discovery_context",
        sourceId: "disc-ctx-1",
        resolvedAt: 1700000000,
      },
    };
    expect(result.trustLevel).toBe("DiscoveryContextVerified");
    expect(result.resolutionPath.sourceId).toBe("disc-ctx-1");
  });
});

describe("AddressResolution discriminated union", () => {
  it("Identity variant is distinguishable by type field", () => {
    const resolutions: AddressResolution[] = [
      {
        type: "Identity",
        did: "did:dht:z6MkAlice",
        trustLevel: "LocalPetname",
        resolutionPath: {
          layer: "Petname",
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
        trustLevel: "DomainVerified",
        resolutionPath: {
          layer: "Domain",
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

  it("all TrustLevel values are assignable", () => {
    const levels: TrustLevel[] = [
      "DirectExchange",
      "LocalPetname",
      "MultiLayerCorroborated",
      "DomainVerified",
      "AttestationVerified",
      "DiscoveryContextVerified",
    ];
    // Verify each can be used in an AddressResolution
    for (const level of levels) {
      const resolution: AddressResolution = {
        type: "Identity",
        did: "did:dht:zTest",
        trustLevel: level,
        resolutionPath: {
          layer: "Domain",
          source: "test",
          sourceId: null,
          resolvedAt: 0,
        },
      };
      expect(resolution.trustLevel).toBe(level);
    }
  });

  it("all ResolutionLayer values are assignable", () => {
    const layers: ResolutionPath["layer"][] = [
      "Petname",
      "DiscoveryContext",
      "Attestation",
      "Domain",
      "MultiLayerCorroborated",
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
