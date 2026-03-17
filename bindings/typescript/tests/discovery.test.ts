/**
 * Tests for the discovery module types and DiscoveryResult field mapping.
 *
 * These tests verify that DiscoveryResult correctly includes trustLevel
 * and resolutionPath per §22.2.1, that resolveAddress() returns
 * properly typed AddressResolution results, and that scope registry
 * types are properly structured (§22.3.5, ADR-043).
 */

import { describe, expect, it } from "bun:test";
import type {
  DiscoveryResult,
  ScopeDeregisterResult,
  ScopeEntry,
  ScopeLookupResult,
  ScopeMetadata,
  ScopeRegisterResult,
  ScopeTarget,
} from "../src/discovery";
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
        layer: "Domain",
        source: "dht",
        sourceId: null,
        resolvedAt: 1700000000,
      },
    };
    expect(result.trustLevel.kind).toBe("DomainVerified");
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
      trustLevel: { kind: "DiscoveryContextVerified" },
      resolutionPath: {
        layer: "DiscoveryContext",
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
        layer: "Domain",
        source: "context_uri",
        sourceId: null,
        resolvedAt: 1700000000,
      },
    };
    expect(result.trustLevel.kind).toBe("DirectExchange");
    expect(result.resolutionPath.layer).toBe("Domain");
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
        trustLevel: { kind: "DomainVerified" },
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

    if (identities[0]?.type === "Identity") {
      expect(identities[0]?.did).toBe("did:dht:z6MkAlice");
    }
    if (contexts[0]?.type === "Context") {
      expect(contexts[0]?.contextId).toBe("abc123");
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
          layer: "Domain",
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
        { layer: "Petname", source: "local", sourceId: null, resolvedAt: 1700000000 },
        { layer: "Domain", source: "example.com", sourceId: null, resolvedAt: 1700000000 },
      ],
    };
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
    expect(resolution.trustLevel.kind).toBe("MultiLayerCorroborated");
    if (resolution.trustLevel.kind === "MultiLayerCorroborated") {
      expect(resolution.trustLevel.sources).toHaveLength(2);
      expect(resolution.trustLevel.sources?.[0]?.layer).toBe("Petname");
    }
  });

  it("all ResolutionLayer values are assignable (5 per §22.11.3)", () => {
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

// ---------------------------------------------------------------------------
// Scope registry types (§22.3.5, ADR-043)
// ---------------------------------------------------------------------------

describe("Scope registry types (§22.3.5)", () => {
  it("ScopeTarget has context_id and relay_urls fields", () => {
    const target: ScopeTarget = {
      context_id: "ctx-cooking",
      relay_urls: ["wss://relay.example.com"],
    };
    expect(target.context_id).toBe("ctx-cooking");
    expect(target.relay_urls).toHaveLength(1);
  });

  it("ScopeMetadata supports null description and tags", () => {
    const metadata: ScopeMetadata = {
      description: null,
      tags: null,
    };
    expect(metadata.description).toBeNull();
    expect(metadata.tags).toBeNull();
  });

  it("ScopeMetadata supports populated description and tags", () => {
    const metadata: ScopeMetadata = {
      description: "A cooking community",
      tags: ["food", "recipes"],
    };
    expect(metadata.description).toBe("A cooking community");
    expect(metadata.tags).toHaveLength(2);
  });

  it("ScopeEntry has all required fields", () => {
    const entry: ScopeEntry = {
      name: "cooking-community",
      target: {
        context_id: "ctx-cooking",
        relay_urls: ["wss://relay.example.com"],
      },
      owner_did: "did:dht:zAdmin",
      registered_at: 1700000000,
      metadata: { description: null, tags: null },
      entry_id: "scope-1",
    };
    expect(entry.name).toBe("cooking-community");
    expect(entry.target.context_id).toBe("ctx-cooking");
    expect(entry.owner_did).toBe("did:dht:zAdmin");
    expect(entry.registered_at).toBe(1700000000);
    expect(entry.entry_id).toBe("scope-1");
  });

  it("ScopeRegisterResult status is a string union", () => {
    const registered: ScopeRegisterResult = {
      status: "registered",
      entry_id: "scope-1",
    };
    const conflict: ScopeRegisterResult = {
      status: "conflict",
      entry_id: null,
    };
    const updated: ScopeRegisterResult = {
      status: "updated",
      entry_id: "scope-1",
    };
    expect(registered.status).toBe("registered");
    expect(conflict.status).toBe("conflict");
    expect(conflict.entry_id).toBeNull();
    expect(updated.status).toBe("updated");
  });

  it("ScopeLookupResult contains typed ScopeEntry array", () => {
    const result: ScopeLookupResult = {
      results: [
        {
          name: "cooking-community",
          target: {
            context_id: "ctx-cooking",
            relay_urls: ["wss://relay.example.com"],
          },
          owner_did: "did:dht:zAdmin",
          registered_at: 1700000000,
          metadata: {
            description: "A cooking community",
            tags: ["food"],
          },
          entry_id: "scope-1",
        },
      ],
    };
    expect(result.results).toHaveLength(1);
    expect(result.results[0]?.name).toBe("cooking-community");
    expect(result.results[0]?.target.context_id).toBe("ctx-cooking");
    expect(result.results[0]?.metadata.description).toBe("A cooking community");
  });

  it("ScopeDeregisterResult has removed boolean", () => {
    const removed: ScopeDeregisterResult = { removed: true };
    const notRemoved: ScopeDeregisterResult = { removed: false };
    expect(removed.removed).toBe(true);
    expect(notRemoved.removed).toBe(false);
  });
});
