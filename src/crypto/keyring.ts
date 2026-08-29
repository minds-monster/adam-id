import { execFileSync } from "node:child_process";
import { randomBytes, scryptSync } from "node:crypto";

const SERVICE = "adam-id-vault";
const ACCOUNT = "master-kek";

/**
 * The key-encryption key (KEK) that wraps every object's data key.
 *
 * Today this is a locally generated 32-byte secret held in the macOS Keychain.
 * It is deliberately the *only* thing that needs to change when Moca Credential
 * Services activate: because the KEK only ever wraps per-object DEKs, migrating
 * to a CAK-derived key re-wraps a few hundred small keys rather than
 * re-encrypting gigabytes of ciphertext. See `rewrapAll` in seal.ts.
 */
export interface Keyring {
  kek: Buffer;
  source: "keychain" | "passphrase" | "env";
}

function keychainGet(): Buffer | null {
  try {
    const out = execFileSync(
      "security",
      ["find-generic-password", "-s", SERVICE, "-a", ACCOUNT, "-w"],
      { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] },
    ).trim();
    return out ? Buffer.from(out, "base64") : null;
  } catch {
    // Not found, or not macOS.
    return null;
  }
}

function keychainSet(key: Buffer): boolean {
  try {
    execFileSync(
      "security",
      [
        "add-generic-password",
        "-s", SERVICE,
        "-a", ACCOUNT,
        "-w", key.toString("base64"),
        "-U", // update if it already exists
      ],
      { stdio: ["ignore", "ignore", "ignore"] },
    );
    return true;
  } catch {
    return false;
  }
}

/**
 * Load the KEK, creating it on first use.
 *
 * Resolution order:
 *   1. VAULT_PASSPHRASE — scrypt-derived, for headless/CI use
 *   2. VAULT_KEK_BASE64 — raw key, for tests
 *   3. macOS Keychain    — the normal path
 *
 * A passphrase-derived key uses a fixed salt so the same passphrase always
 * yields the same KEK; that is a deliberate trade (reproducibility over
 * per-install salting) and is why the passphrase must be high-entropy.
 */
export function loadKeyring(opts: { create?: boolean } = {}): Keyring {
  const passphrase = process.env.VAULT_PASSPHRASE;
  if (passphrase) {
    if (passphrase.length < 12) {
      throw new Error("VAULT_PASSPHRASE must be at least 12 characters.");
    }
    const kek = scryptSync(passphrase, `${SERVICE}:${ACCOUNT}`, 32, {
      N: 2 ** 15,
      r: 8,
      p: 1,
      maxmem: 128 * 1024 * 1024,
    });
    return { kek, source: "passphrase" };
  }

  const raw = process.env.VAULT_KEK_BASE64;
  if (raw) {
    const kek = Buffer.from(raw, "base64");
    if (kek.length !== 32) throw new Error("VAULT_KEK_BASE64 must decode to exactly 32 bytes.");
    return { kek, source: "env" };
  }

  const existing = keychainGet();
  if (existing) {
    if (existing.length !== 32) {
      throw new Error(
        `Keychain item ${SERVICE}/${ACCOUNT} is ${existing.length} bytes, expected 32. ` +
          `Delete it with: security delete-generic-password -s ${SERVICE} -a ${ACCOUNT}`,
      );
    }
    return { kek: existing, source: "keychain" };
  }

  if (!opts.create) {
    throw new Error(
      `No vault key found. Run \`vault seal\` to create one, or set VAULT_PASSPHRASE.`,
    );
  }

  const kek = randomBytes(32);
  if (!keychainSet(kek)) {
    throw new Error(
      "Could not store the vault key in the macOS Keychain. Set VAULT_PASSPHRASE instead " +
        "so the key can be re-derived rather than lost.",
    );
  }
  return { kek, source: "keychain" };
}

export function keyStatus(): { present: boolean; source: string } {
  if (process.env.VAULT_PASSPHRASE) return { present: true, source: "passphrase (env)" };
  if (process.env.VAULT_KEK_BASE64) return { present: true, source: "raw key (env)" };
  const k = keychainGet();
  return k ? { present: true, source: "macOS Keychain" } : { present: false, source: "none" };
}
