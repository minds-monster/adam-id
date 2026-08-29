import type { EnvelopeHeader } from "../crypto/envelope.js";

/**
 * A place sealed objects live.
 *
 * Only ciphertext and headers cross this boundary — an implementation never sees
 * a plaintext byte or the KEK. That is what makes it safe to point at a third
 * party like MCSP: a storage provider holding these blobs cannot read them.
 */
export interface StorageAdapter {
  readonly name: string;
  /** Human-readable description of where data goes, for `vault doctor`. */
  describe(): string;
  put(key: string, ciphertext: Buffer, header: EnvelopeHeader): Promise<PutResult>;
  get(key: string): Promise<{ ciphertext: Buffer; header: EnvelopeHeader }>;
  has(key: string): Promise<boolean>;
  list(prefix?: string): Promise<StoredObject[]>;
}

export interface PutResult {
  key: string;
  /** Backend-specific address (a path, CID, or content id). */
  locator: string;
  cipherSha256: string;
  bytes: number;
}

export interface StoredObject {
  key: string;
  locator: string;
  cipherSha256: string;
  bytes: number;
  header: EnvelopeHeader;
}

/** Thrown when a backend exists in code but isn't provisioned yet. */
export class NotProvisionedError extends Error {
  constructor(backend: string, missing: string[]) {
    super(
      `Storage backend "${backend}" is not provisioned yet.\n\nStill needed:\n` +
        missing.map((m) => `  - ${m}`).join("\n"),
    );
    this.name = "NotProvisionedError";
  }
}
