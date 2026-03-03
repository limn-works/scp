/** Type declarations for wa-sqlite VFS modules (no upstream .d.ts). */

declare module "wa-sqlite/src/examples/OriginPrivateFileSystemVFS.js" {
  export class OriginPrivateFileSystemVFS {
    isReady: Promise<void>;
  }
}

declare module "wa-sqlite/src/examples/IDBBatchAtomicVFS.js" {
  export class IDBBatchAtomicVFS {
    isReady: Promise<void>;
  }
}
