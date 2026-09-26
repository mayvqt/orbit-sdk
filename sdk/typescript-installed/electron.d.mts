import type { Client, ClientOptions } from "./index.mjs";

export interface ElectronAppLike { isReady(): boolean }
export interface ElectronSafeStorageLike {
  isEncryptionAvailable?(): boolean;
  isAsyncEncryptionAvailable(): Promise<boolean>;
  getSelectedStorageBackend?(): string;
  encryptStringAsync(value: string): Promise<Uint8Array>;
  decryptStringAsync(value: Uint8Array): Promise<{
    result: string;
    shouldReEncrypt: boolean;
    isTemporarilyUnavailable?: boolean;
  }>;
}
export interface ElectronClientOptions extends ClientOptions {
  readonly app: ElectronAppLike;
  readonly safeStorage: ElectronSafeStorageLike;
}
export declare function openElectronClient(appKey: string, options: ElectronClientOptions): Promise<Client>;
