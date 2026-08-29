import { execFileSync } from "node:child_process";
import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";

const SERVICE = "adam-id-vault";
const ACCOUNT = "agent-key";

/**
 * The AI agent's own identity.
 *
 * AIR Kit models agents as non-human identities: `AirService.registerAgentKey(publicKey)`
 * associates a public key with your Moca account, `getAgentKeys()` lists what's
 * registered, and `removeAgentKey(id)` revokes it. The private half is generated
 * here and never leaves this machine, so revocation is a property of your Moca
 * account rather than something the agent can undo.
 *
 * P-256 is used because it's one of the two curves AIR Kit's `issueCredential`
 * accepts (`secp256r1` | `secp256k1`), making it the safer default of the two for
 * interop. Confirm the expected encoding with Moca before registering in
 * production — `registerAgentKey` takes an opaque string and the docs do not
 * pin down the format, so this exports SPKI/base64 and records that choice.
 */
export const AGENT_KEY_CURVE = "prime256v1"; // secp256r1 / P-256
export const AGENT_KEY_ENCODING = "spki-base64";

export interface AgentKeyInfo {
  publicKeySpkiBase64: string;
  curve: string;
  encoding: string;
  createdLocally: boolean;
}

function keychainGet(): string | null {
  try {
    return (
      execFileSync("security", ["find-generic-password", "-s", SERVICE, "-a", ACCOUNT, "-w"], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      }).trim() || null
    );
  } catch {
    return null;
  }
}

function keychainSet(pkcs8Base64: string): void {
  execFileSync(
    "security",
    ["add-generic-password", "-s", SERVICE, "-a", ACCOUNT, "-w", pkcs8Base64, "-U"],
    { stdio: ["ignore", "ignore", "ignore"] },
  );
}

/** Load the agent keypair, generating and storing it on first use. */
export function loadOrCreateAgentKey(): AgentKeyInfo {
  const existing = keychainGet();
  if (existing) {
    const priv = createPrivateKey({
      key: Buffer.from(existing, "base64"),
      format: "der",
      type: "pkcs8",
    });
    return {
      publicKeySpkiBase64: createPublicKey(priv)
        .export({ format: "der", type: "spki" })
        .toString("base64"),
      curve: AGENT_KEY_CURVE,
      encoding: AGENT_KEY_ENCODING,
      createdLocally: false,
    };
  }

  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: AGENT_KEY_CURVE });
  keychainSet(privateKey.export({ format: "der", type: "pkcs8" }).toString("base64"));
  return {
    publicKeySpkiBase64: publicKey.export({ format: "der", type: "spki" }).toString("base64"),
    curve: AGENT_KEY_CURVE,
    encoding: AGENT_KEY_ENCODING,
    createdLocally: true,
  };
}

/**
 * Sign a challenge with the agent key. Used by the future HTTP transport to prove
 * the caller holds the key registered under your Moca account.
 */
export function signChallenge(challenge: Buffer): Buffer {
  const stored = keychainGet();
  if (!stored) throw new Error("No agent key — run `vault agent-key` first.");
  const priv = createPrivateKey({
    key: Buffer.from(stored, "base64"),
    format: "der",
    type: "pkcs8",
  });
  return sign("sha256", challenge, priv);
}

export function verifyChallenge(
  challenge: Buffer,
  signature: Buffer,
  publicKeySpkiBase64: string,
): boolean {
  const pub = createPublicKey({
    key: Buffer.from(publicKeySpkiBase64, "base64"),
    format: "der",
    type: "spki",
  });
  return verify("sha256", challenge, pub, signature);
}
