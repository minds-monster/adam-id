/**
 * Publishing the store's Merkle root somewhere tamper-evident.
 *
 * Anchoring a single root covers every object at once, so re-sealing costs one
 * transaction rather than thousands.
 */
export interface AnchorAdapter {
  readonly name: string;
  describe(): string;
  /** Publish a root; returns a reference (tx hash) and where it landed. */
  anchor(root: string): Promise<AnchorReceipt>;
  /** Read back the most recently anchored root, if the backend can. */
  latest(): Promise<AnchorReceipt | null>;
}

export interface AnchorReceipt {
  root: string;
  /** Transaction hash, or a local marker for the noop backend. */
  reference: string;
  chainId: number | null;
  anchoredAt: string;
  explorerUrl?: string;
}

/**
 * Records roots locally without touching a chain. This is the default so that
 * `seal` and `verify` are useful before any wallet is funded — verification of
 * store integrity does not require the chain, only the recorded root.
 */
export class LocalAnchorAdapter implements AnchorAdapter {
  readonly name = "local";
  #path: string;

  constructor(path: string) {
    this.#path = path;
  }

  describe(): string {
    return `local anchor file at ${this.#path} (no on-chain proof)`;
  }

  async anchor(root: string): Promise<AnchorReceipt> {
    const { writeFileSync } = await import("node:fs");
    const receipt: AnchorReceipt = {
      root,
      reference: "local",
      chainId: null,
      anchoredAt: new Date().toISOString(),
    };
    writeFileSync(this.#path, `${JSON.stringify(receipt, null, 2)}\n`, "utf8");
    return receipt;
  }

  async latest(): Promise<AnchorReceipt | null> {
    const { existsSync, readFileSync } = await import("node:fs");
    if (!existsSync(this.#path)) return null;
    return JSON.parse(readFileSync(this.#path, "utf8")) as AnchorReceipt;
  }
}
