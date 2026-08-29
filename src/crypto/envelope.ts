import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";

export const ENVELOPE_VERSION = 1;
const ALG = "aes-256-gcm";
const IV_LEN = 12; // 96-bit nonce, the GCM standard
const TAG_LEN = 16;
const KEY_LEN = 32;

/**
 * Envelope encryption.
 *
 * Each object gets a fresh random data key (DEK) which encrypts the payload; the
 * DEK is then wrapped under the vault KEK. Two reasons this indirection is worth
 * it here:
 *
 *  1. Key rotation — and specifically migrating to a Moca CAK-derived key once
 *     Credential Services activate — only rewraps the small DEK blobs. The 2 GB
 *     of media ciphertext is never touched.
 *  2. A per-object DEK means one random 96-bit IV per key, so there is no risk of
 *     the catastrophic GCM nonce reuse that a single shared key invites.
 */
export interface EnvelopeHeader {
  v: number;
  alg: typeof ALG;
  /** Wrapped DEK: iv ‖ ciphertext ‖ tag, base64. */
  wrappedDek: string;
  /** IV for the payload, base64. */
  iv: string;
  /** GCM tag for the payload, base64. */
  tag: string;
  /** SHA-256 of the plaintext, hex — lets `verify` prove a round trip. */
  plaintextSha256: string;
  plaintextBytes: number;
}

export interface SealedObject {
  header: EnvelopeHeader;
  ciphertext: Buffer;
}

function wrapDek(dek: Buffer, kek: Buffer): string {
  const iv = randomBytes(IV_LEN);
  const c = createCipheriv(ALG, kek, iv);
  const body = Buffer.concat([c.update(dek), c.final()]);
  return Buffer.concat([iv, body, c.getAuthTag()]).toString("base64");
}

function unwrapDek(wrapped: string, kek: Buffer): Buffer {
  const raw = Buffer.from(wrapped, "base64");
  if (raw.length !== IV_LEN + KEY_LEN + TAG_LEN) {
    throw new Error("Malformed wrapped data key.");
  }
  const iv = raw.subarray(0, IV_LEN);
  const body = raw.subarray(IV_LEN, IV_LEN + KEY_LEN);
  const tag = raw.subarray(IV_LEN + KEY_LEN);
  const d = createDecipheriv(ALG, kek, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(body), d.final()]);
}

export function sha256(buf: Buffer): string {
  return createHash("sha256").update(buf).digest("hex");
}

export function seal(plaintext: Buffer, kek: Buffer): SealedObject {
  const dek = randomBytes(KEY_LEN);
  const iv = randomBytes(IV_LEN);
  const c = createCipheriv(ALG, dek, iv);
  const ciphertext = Buffer.concat([c.update(plaintext), c.final()]);
  return {
    header: {
      v: ENVELOPE_VERSION,
      alg: ALG,
      wrappedDek: wrapDek(dek, kek),
      iv: iv.toString("base64"),
      tag: c.getAuthTag().toString("base64"),
      plaintextSha256: sha256(plaintext),
      plaintextBytes: plaintext.length,
    },
    ciphertext,
  };
}

export function open(obj: SealedObject, kek: Buffer): Buffer {
  const { header, ciphertext } = obj;
  if (header.v !== ENVELOPE_VERSION) {
    throw new Error(`Unsupported envelope version ${header.v}.`);
  }
  const dek = unwrapDek(header.wrappedDek, kek);
  const d = createDecipheriv(ALG, dek, Buffer.from(header.iv, "base64"));
  d.setAuthTag(Buffer.from(header.tag, "base64"));
  // GCM's own tag check throws here on tampering; the digest check below is a
  // second, independent guard that also catches a corrupted header.
  const plaintext = Buffer.concat([d.update(ciphertext), d.final()]);
  const got = Buffer.from(sha256(plaintext), "hex");
  const want = Buffer.from(header.plaintextSha256, "hex");
  if (got.length !== want.length || !timingSafeEqual(got, want)) {
    throw new Error("Decrypted payload does not match its recorded digest.");
  }
  return plaintext;
}

/**
 * Re-wrap an object's DEK under a new KEK without touching its ciphertext.
 * This is the migration path to a Moca CAK-derived key.
 */
export function rewrap(header: EnvelopeHeader, oldKek: Buffer, newKek: Buffer): EnvelopeHeader {
  const dek = unwrapDek(header.wrappedDek, oldKek);
  return { ...header, wrappedDek: wrapDek(dek, newKek) };
}
