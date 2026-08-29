import type { EnvelopeHeader } from "../crypto/envelope.js";
import { NotProvisionedError, type PutResult, type StorageAdapter, type StoredObject } from "./adapter.js";

/**
 * Moca Chain Storage Provider backend — interface only, deliberately not guessed.
 *
 * `@mocanetwork/airkit@1.10.0` contains no storage surface whatsoever: a grep of
 * its `dist` for mcsp / dstorage / storageProvider / uploadBlob / putObject
 * returns nothing. AIR Kit does identity, wallet, agent keys and credentials.
 * There is therefore no client to call and no documented request shape to code
 * against, so this adapter fails loudly with what's missing rather than shipping
 * a fabricated REST contract that would silently not work.
 *
 * What unblocks it:
 *   - MCSP_ENDPOINT — the upload/retrieve base URL
 *   - the auth shape (bearer token from AIR Kit's getAccessToken(), a separate
 *     API key, or a signed request) and which of those MCSP expects
 *   - the response shape for an upload, specifically the content id / locator to
 *     persist in the manifest so `get` can address the blob later
 *
 * Once those are known, only the four methods below need bodies. Nothing else in
 * the vault changes: `seal` already writes through StorageAdapter, and the
 * envelope format is backend-agnostic.
 */
export class McspStorageAdapter implements StorageAdapter {
  readonly name = "mcsp";
  #endpoint: string | undefined;

  constructor(endpoint = process.env.MCSP_ENDPOINT) {
    this.#endpoint = endpoint;
  }

  describe(): string {
    return this.#endpoint
      ? `MCSP at ${this.#endpoint} (client not implemented — see src/storage/mcsp.ts)`
      : "MCSP (not configured: MCSP_ENDPOINT unset)";
  }

  #missing(): never {
    throw new NotProvisionedError("mcsp", [
      this.#endpoint ? `endpoint configured: ${this.#endpoint}` : "MCSP_ENDPOINT is not set",
      "Moca Credential Services activation (issueCredential returns the cakPublicKey used as KEK)",
      "the MCSP upload/retrieve API contract — @mocanetwork/airkit@1.10.0 exposes no storage client",
      "the auth mechanism MCSP expects (AIR Kit access token vs. separate API key)",
    ]);
  }

  async put(_key: string, _ciphertext: Buffer, _header: EnvelopeHeader): Promise<PutResult> {
    this.#missing();
  }

  async get(_key: string): Promise<{ ciphertext: Buffer; header: EnvelopeHeader }> {
    this.#missing();
  }

  async has(_key: string): Promise<boolean> {
    this.#missing();
  }

  async list(_prefix?: string): Promise<StoredObject[]> {
    this.#missing();
  }
}
