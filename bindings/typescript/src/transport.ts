/**
 * Transport handle type for the SCP TypeScript SDK.
 *
 * {@link TransportManager} is a pure handle type that wraps the raw NAPI
 * transport manager. {@link SCP.transportConnect} returns it, and
 * {@link SCP.transportStatus} and {@link SCP.transportDisconnect} take it
 * back, matching the Swift SDK's `TransportManager`.
 */

/**
 * Pure handle to one relay connection, returned by
 * {@link SCP.transportConnect}.
 */
export class TransportManager {
  /** The raw napi-rs transport handle; private, so it also brands real instances. */
  readonly #rawHandle: unknown;

  private constructor(rawHandle: unknown) {
    this.#rawHandle = rawHandle;
  }

  /** @internal Raw napi-rs transport handle — not part of the public API. */
  get _rawHandle(): unknown {
    return this.#rawHandle;
  }

  /** @internal Wraps the raw handle `scp.transportConnect` receives from the bridge. */
  static _fromHandle(raw: unknown): TransportManager {
    return new TransportManager(raw);
  }

  /**
   * Reports whether `value` is a `TransportManager` this SDK constructed.
   *
   * @internal Used by the `SCP` methods to reject a wrong argument with
   *   `SCP-VALID-7005` before any bridge call.
   */
  static _isTransportManager(value: unknown): value is TransportManager {
    return typeof value === "object" && value !== null && #rawHandle in value;
  }
}
