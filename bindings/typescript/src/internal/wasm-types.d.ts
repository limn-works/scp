/**
 * Type declarations for the `@limn-works/scp-ts-wasm` package.
 *
 * This module is produced by `wasm-pack build --target bundler` from
 * `crates/scp-ffi/wasm/` and does not ship its own TypeScript declarations.
 * This ambient module declaration provides the expected type surface.
 */
declare module "@limn-works/scp-ts-wasm" {
  function init(): Promise<void>;
  export default init;
  export function scp_init(): void;
  export function scp_version(): string;
  export function identity_load(did: string): Promise<{
    did: string;
    custodyType: string;
  }>;
  export function context_create(
    identityDid: string,
    paramsJson: string,
  ): Promise<{
    contextId: string;
    state: string;
    creatorDid: string;
  }>;
  export function context_join(
    handle: { contextId: string; state: string; creatorDid: string },
    identityDid: string,
  ): Promise<void>;
  export function context_leave(
    handle: { contextId: string; state: string; creatorDid: string },
    identityDid: string,
  ): Promise<void>;
  export function context_close(
    handle: { contextId: string; state: string; creatorDid: string },
    identityDid: string,
  ): Promise<void>;
  export function context_send(
    handle: { contextId: string; state: string; creatorDid: string },
    identityDid: string,
    payloadBase64: string,
  ): Promise<void>;
  export function context_subscribe(
    handle: { contextId: string; state: string; creatorDid: string },
    callback: {
      onMessage: (msg: {
        senderDid: string;
        payloadBase64: string;
        timestamp: number;
        contextId: string;
      }) => void;
      onComplete: () => void;
    },
  ): void;
}
