/**
 * Discovery module for the SCP TypeScript SDK.
 *
 * Provides functions for parsing SCP addresses, creating discovery queries,
 * normalizing addresses, and discovering contexts from DIDs or `scp://` URIs.
 *
 * See ADR-020 in `.docs/adrs/phase-4.md` and spec section 22 (Addressing).
 */

import { mapBridgeError } from "./errors.js";
import { getBridge } from "./internal/bridge.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** A parsed SCP address. */
export interface ParsedAddress {
  /** Address type: `"discovery_handle"`, `"domain_handle"`, `"attestation_handle"`, or `"unscoped"`. */
  readonly type: string;
  /** Additional fields depend on the address type. */
  readonly [key: string]: unknown;
}

/** A context discovery result. */
export interface DiscoveryResult {
  readonly contextId: string;
  readonly relayUrls: readonly string[];
  readonly publisherDid: string;
  readonly discoverySource: string;
  readonly mode: string | null;
  readonly metadataSummary: string | null;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Parses an SCP address string into its components.
 *
 * @param address - The address string to parse (e.g., `"alice@cooking-community"`).
 * @returns The parsed address object.
 * @throws {ValidationError} If the address is malformed.
 */
export async function parseAddress(address: string): Promise<ParsedAddress> {
  try {
    const bridge = await getBridge();
    const result = await bridge.discoveryParseAddress(address);
    return JSON.parse(result) as ParsedAddress;
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Creates a discovery query as a JSON string.
 *
 * @param options - Query parameters.
 * @returns A JSON string representing the discovery query.
 */
export async function createQuery(options?: {
  capabilities?: string[];
  keywords?: string[];
  minHistorySecs?: number;
}): Promise<string> {
  try {
    const bridge = await getBridge();
    return bridge.discoveryCreateQuery(
      options?.capabilities,
      options?.keywords,
      options?.minHistorySecs,
    );
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Normalizes an address string per SCP addressing rules.
 *
 * @param address - The address to normalize.
 * @returns The normalized address string.
 */
export async function normalizeAddress(address: string): Promise<string> {
  try {
    const bridge = await getBridge();
    return bridge.discoveryNormalizeAddress(address);
  } catch (error) {
    throw mapBridgeError(error);
  }
}

/**
 * Discovers contexts from a DID string or `scp://` URI.
 *
 * @param query - A DID string or `scp://` URI.
 * @returns Parsed discovery results.
 * @throws {ContextError} If discovery fails.
 * @throws {ValidationError} If the query is neither a DID nor an `scp://` URI.
 */
export async function discoverContexts(query: string): Promise<DiscoveryResult[]> {
  try {
    const bridge = await getBridge();
    const raw = await bridge.contextDiscover(query);
    const results: DiscoveryResult[] = JSON.parse(raw);
    return results;
  } catch (error) {
    throw mapBridgeError(error);
  }
}
