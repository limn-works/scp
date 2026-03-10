/**
 * Transport module for the SCP TypeScript SDK.
 *
 * Provides the `Transport` class for relay connection management.
 * Transport is fully abstracted behind the bridge interface — the native
 * bridge uses OS-level networking (tokio), while the WASM bridge uses
 * browser WebSocket.
 *
 * See ADR-005 (Transport Abstraction) and ADR-022 in `.docs/adrs/phase-4.md`.
 */

import { mapBridgeError, ValidationError } from "./errors";
import type { BridgeTransportHandle } from "./internal/bridge";
import { getBridge } from "./internal/bridge";
import type { TransportConfig, TransportStatus } from "./types";

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/**
 * Transport connection manager for SCP relay communication.
 *
 * Manages the WebSocket connection to an SCP relay. Implements
 * `AsyncDisposable` for automatic cleanup.
 *
 * ```typescript
 * await using transport = await Transport.connect({ relayUrl: "wss://relay.example.com" });
 * const status = await transport.status();
 * console.log(status.connected); // true
 * ```
 */
export class Transport implements AsyncDisposable {
  /** @internal Opaque bridge handle. */
  private readonly _handle: BridgeTransportHandle;

  /** Whether the transport has been disconnected. */
  private _disposed = false;

  private constructor(handle: BridgeTransportHandle) {
    this._handle = handle;
  }

  /**
   * Connects to an SCP relay.
   *
   * The relay URL must use the `wss://` scheme. Plaintext `ws://` connections
   * are rejected to prevent credential exposure.
   *
   * @param config - Transport configuration with the relay URL.
   * @returns A connected `Transport` instance.
   * @throws {ValidationError} If the relay URL does not use `wss://`.
   * @throws {TransportError} If the connection fails.
   */
  static async connect(config: TransportConfig): Promise<Transport> {
    if (!config.relayUrl.startsWith("wss://")) {
      throw new ValidationError(
        `Relay URL must use wss:// scheme (got "${config.relayUrl}") — ` +
          "plaintext ws:// connections are not permitted",
        "SCP-VALID-7000",
      );
    }

    try {
      const bridge = await getBridge();
      const handle = await bridge.transportConnect(config.relayUrl);
      return new Transport(handle);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Returns the current transport connection status.
   *
   * @returns The connection status including relay URL and latency.
   */
  async status(): Promise<TransportStatus> {
    try {
      const bridge = await getBridge();
      return await bridge.transportStatus(this._handle);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Disconnects from the relay.
   *
   * Closes the active transport connection. The `Transport` instance must
   * not be used for new operations after this call.
   *
   * @throws {TransportError} If the transport is not connected.
   */
  async disconnect(): Promise<void> {
    if (this._disposed) {
      return;
    }
    this._disposed = true;
    try {
      const bridge = await getBridge();
      await bridge.transportDisconnect(this._handle);
    } catch (error) {
      throw mapBridgeError(error);
    }
  }

  /**
   * Implements `AsyncDisposable` for automatic cleanup.
   *
   * When used with `await using`, the transport is automatically
   * disconnected on scope exit.
   */
  async [Symbol.asyncDispose](): Promise<void> {
    await this.disconnect();
  }
}
