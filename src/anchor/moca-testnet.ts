import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { createPublicClient, createWalletClient, defineChain, http, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import type { AnchorAdapter, AnchorReceipt } from "./adapter.js";

export const MOCA_TESTNET_RPC = "https://rpc.testnet.mocachain.dev";

/**
 * Moca Chain testnet. chainId 223400 (0x366a8), confirmed live against the RPC.
 */
export const mocaTestnet = defineChain({
  id: 223400,
  name: "Moca Chain Testnet",
  nativeCurrency: { name: "MOCA", symbol: "MOCA", decimals: 18 },
  rpcUrls: { default: { http: [MOCA_TESTNET_RPC] } },
  testnet: true,
});

const ANCHOR_MAGIC = "MOCAVAULT1";

/**
 * Anchor the store's Merkle root on Moca Chain testnet.
 *
 * The root is written as calldata on a zero-value self-transaction. No contract
 * is deployed because none is needed: the value of the anchor is that a root
 * existed at a block height, which plain calldata already proves, and a contract
 * would add a deployment to maintain for no extra guarantee.
 *
 * Signing uses a local key via viem rather than AIR Kit's EIP-1193 provider,
 * because AirService only exists inside a browser iframe and cannot be used from
 * this Node process. Identity operations that genuinely need AIR Kit live in the
 * browser companion page instead.
 */
export class MocaTestnetAnchorAdapter implements AnchorAdapter {
  readonly name = "moca-testnet";
  #receiptPath: string;
  #privateKey: Hex | undefined;

  constructor(receiptPath: string, privateKey = process.env.MOCA_ANCHOR_PRIVATE_KEY) {
    this.#receiptPath = receiptPath;
    this.#privateKey = privateKey as Hex | undefined;
  }

  describe(): string {
    return this.#privateKey
      ? `Moca Chain testnet (chainId ${mocaTestnet.id}) via ${MOCA_TESTNET_RPC}`
      : `Moca Chain testnet — no signer (set MOCA_ANCHOR_PRIVATE_KEY to enable anchoring)`;
  }

  async anchor(root: string): Promise<AnchorReceipt> {
    if (!this.#privateKey) {
      throw new Error(
        "Anchoring to Moca testnet needs a funded signer. Set MOCA_ANCHOR_PRIVATE_KEY " +
          "(testnet key only), or use `--anchor local` to record the root without a chain.",
      );
    }
    const account = privateKeyToAccount(this.#privateKey);
    const wallet = createWalletClient({ account, chain: mocaTestnet, transport: http() });
    const pub = createPublicClient({ chain: mocaTestnet, transport: http() });

    // `MOCAVAULT1` prefix makes the anchor identifiable when scanning calldata.
    const data = `0x${Buffer.from(`${ANCHOR_MAGIC}${root}`, "utf8").toString("hex")}` as Hex;

    const balance = await pub.getBalance({ address: account.address });
    if (balance === 0n) {
      throw new Error(
        `Signer ${account.address} has zero balance on Moca testnet — fund it before anchoring.`,
      );
    }

    const hash = await wallet.sendTransaction({ to: account.address, value: 0n, data });
    await pub.waitForTransactionReceipt({ hash });

    const receipt: AnchorReceipt = {
      root,
      reference: hash,
      chainId: mocaTestnet.id,
      anchoredAt: new Date().toISOString(),
    };
    writeFileSync(this.#receiptPath, `${JSON.stringify(receipt, null, 2)}\n`, "utf8");
    return receipt;
  }

  /**
   * Read back the last anchor. The root comes from the cached receipt and is then
   * confirmed against the chain by re-reading the transaction's calldata — so a
   * tampered local receipt is caught, without needing an indexer to scan history.
   */
  async latest(): Promise<AnchorReceipt | null> {
    if (!existsSync(this.#receiptPath)) return null;
    const cached = JSON.parse(readFileSync(this.#receiptPath, "utf8")) as AnchorReceipt;
    if (cached.reference === "local" || cached.chainId !== mocaTestnet.id) return cached;

    const pub = createPublicClient({ chain: mocaTestnet, transport: http() });
    const tx = await pub.getTransaction({ hash: cached.reference as Hex });
    const decoded = Buffer.from(tx.input.slice(2), "hex").toString("utf8");
    if (!decoded.startsWith(ANCHOR_MAGIC)) {
      throw new Error(`Transaction ${cached.reference} is not a vault anchor.`);
    }
    const onChainRoot = decoded.slice(ANCHOR_MAGIC.length);
    if (onChainRoot !== cached.root) {
      throw new Error(
        `Local anchor receipt claims root ${cached.root} but the on-chain transaction ` +
          `records ${onChainRoot}. The receipt file has been altered.`,
      );
    }
    return cached;
  }
}
