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
  Proof,
  ResolutionPath,
  ToolDefinition,
  TransportStatus,
  TrustLevel,
  UcanToken,
} from "../src/types";

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

  it("TrustLevel accepts all valid variants", () => {
    const levels: TrustLevel[] = [
      "DirectExchange",
      "LocalPetname",
      "MultiLayerCorroborated",
      "DomainVerified",
      "AttestationVerified",
      "DiscoveryContextVerified",
    ];
    expect(levels).toHaveLength(6);
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
      trustLevel: "DiscoveryContextVerified",
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
      expect(resolution.trustLevel).toBe("DiscoveryContextVerified");
      expect(resolution.resolutionPath.layer).toBe("DiscoveryContext");
    }
  });

  it("AddressResolution Context variant has all fields", () => {
    const resolution: AddressResolution = {
      type: "Context",
      contextId: "a1b2c3d4e5f6",
      relayUrls: ["wss://relay.example.com/scp/v1"],
      mode: "broadcast",
      trustLevel: "DomainVerified",
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
      expect(resolution.trustLevel).toBe("DomainVerified");
      expect(resolution.resolutionPath.layer).toBe("Domain");
    }
  });

  it("AddressResolution Context variant allows null mode", () => {
    const resolution: AddressResolution = {
      type: "Context",
      contextId: "deadbeef",
      relayUrls: [],
      mode: null,
      trustLevel: "DiscoveryContextVerified",
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
});
