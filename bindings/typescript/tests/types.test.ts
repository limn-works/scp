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

  it("TrustLevel accepts all simple variants", () => {
    const levels: TrustLevel[] = [
      { kind: "unverified" },
      { kind: "petname_only" },
      { kind: "discovery_context_verified" },
      { kind: "domain_verified" },
      { kind: "attestation_verified" },
      { kind: "direct_exchange" },
    ];
    expect(levels).toHaveLength(6);
  });

  it("TrustLevel multi_layer_corroborated carries sources", () => {
    const level: TrustLevel = {
      kind: "multi_layer_corroborated",
      sources: [
        { layer: "petname", source: "local", sourceId: null, resolvedAt: 1700000000 },
        { layer: "domain", source: "example.com", sourceId: null, resolvedAt: 1700000000 },
      ],
    };
    expect(level.kind).toBe("multi_layer_corroborated");
    if (level.kind === "multi_layer_corroborated") {
      expect(level.sources).toHaveLength(2);
    }
  });

  it("ResolutionPath has all required fields", () => {
    const path: ResolutionPath = {
      layer: "discovery_context",
      source: "cooking-community",
      sourceId: "ctx-disc-1",
      resolvedAt: 1700000000,
    };
    expect(path.layer).toBe("discovery_context");
    expect(path.source).toBe("cooking-community");
    expect(path.sourceId).toBe("ctx-disc-1");
    expect(path.resolvedAt).toBe(1700000000);
  });

  it("ResolutionPath allows null sourceId", () => {
    const path: ResolutionPath = {
      layer: "domain",
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
      trustLevel: { kind: "discovery_context_verified" },
      resolutionPath: {
        layer: "discovery_context",
        source: "cooking-community",
        sourceId: "ctx-disc-1",
        resolvedAt: 1700000000,
      },
    };
    expect(resolution.type).toBe("Identity");
    if (resolution.type === "Identity") {
      expect(resolution.did).toBe("did:dht:z6MkAlice");
      expect(resolution.trustLevel.kind).toBe("discovery_context_verified");
      expect(resolution.resolutionPath.layer).toBe("discovery_context");
    }
  });

  it("AddressResolution Context variant has all fields", () => {
    const resolution: AddressResolution = {
      type: "Context",
      contextId: "a1b2c3d4e5f6",
      relayUrls: ["wss://relay.example.com/scp/v1"],
      mode: "broadcast",
      trustLevel: { kind: "domain_verified" },
      resolutionPath: {
        layer: "domain",
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
      expect(resolution.trustLevel.kind).toBe("domain_verified");
      expect(resolution.resolutionPath.layer).toBe("domain");
    }
  });

  it("AddressResolution Context variant allows null mode", () => {
    const resolution: AddressResolution = {
      type: "Context",
      contextId: "deadbeef",
      relayUrls: [],
      mode: null,
      trustLevel: { kind: "discovery_context_verified" },
      resolutionPath: {
        layer: "discovery_context",
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
