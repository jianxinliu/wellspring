/// Derived operations: the agent asks for a RESULT, never for the key.
///
/// This is the purest form of the Wellspring promise. A signature, a TOTP code
/// or a ciphertext is safe to hand back because the key that produced it never
/// leaves this process. Every derivation is rate limited and audited like a draw:
/// the difference is only that what crosses the socket is a derived artefact.
import { createHmac, createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export type TotpResult = { code: string; period: number; remaining: number; expiresAt: number };

export function base32Decode(input: string): Uint8Array {
  const cleaned = input.replace(/[\s=]/g, "").toUpperCase();
  if (!cleaned) throw new Error("empty base32 seed");
  const out: number[] = [];
  let bits = 0;
  let value = 0;
  for (const ch of cleaned) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx < 0) throw new Error("invalid base32 seed: only A-Z and 2-7 are allowed");
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
      value &= (1 << bits) - 1;
    }
  }
  return new Uint8Array(out);
}

/** RFC 6238. The code is short-lived by construction, which is the point. */
export function totp(seedBase32: string, opts: { digits?: number; period?: number; at?: number } = {}): TotpResult {
  const digits = opts.digits ?? 6;
  const period = opts.period ?? 30;
  if (!Number.isInteger(digits) || digits < 6 || digits > 8) throw new Error("digits must be 6..8");
  if (!Number.isInteger(period) || period < 1 || period > 300) throw new Error("period must be 1..300 seconds");
  const now = opts.at ?? Date.now();
  const key = base32Decode(seedBase32);
  if (key.length === 0) throw new Error("empty TOTP seed");
  const counter = Math.floor(now / 1000 / period);
  const buf = Buffer.alloc(8);
  buf.writeUInt32BE(Math.floor(counter / 0x1_0000_0000), 0);
  buf.writeUInt32BE(counter >>> 0, 4);
  const mac = createHmac("sha1", key).update(buf).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  const binary =
    ((mac[offset] & 0x7f) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  const modulus = 10 ** digits;
  return {
    code: String(binary % modulus).padStart(digits, "0"),
    period,
    remaining: period - (Math.floor(now / 1000) % period),
    expiresAt: (counter + 1) * period * 1000,
  };
}

export type HmacAlg = "sha256" | "sha512";

export function hmac(key: string, data: string, alg: HmacAlg = "sha256"): string {
  if (data.length > 1024 * 1024) throw new Error("data too long: at most 1 MiB");
  // The key is used as UTF-8 bytes: API secrets are strings, not raw binary.
  return createHmac(alg, Buffer.from(key, "utf8")).update(Buffer.from(data, "utf8")).digest("hex");
}

function aesKey(materialBase64: string): Buffer {
  const key = Buffer.from(materialBase64, "base64");
  if (![16, 24, 32].includes(key.length)) {
    throw new Error("AES key must decode from base64 to 16, 24 or 32 bytes");
  }
  return key;
}

/** nonce(12) | ciphertext | tag(16), base64. A fresh nonce per call, always. */
export function encryptAesGcm(materialBase64: string, plaintext: string): string {
  const key = aesKey(materialBase64);
  if (key.length !== 32) throw new Error("encrypt requires a 32-byte (AES-256) key");
  if (plaintext.length > 1024 * 1024) throw new Error("plaintext too long: at most 1 MiB");
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return Buffer.concat([nonce, ct, cipher.getAuthTag()]).toString("base64");
}

export function decryptAesGcm(materialBase64: string, blobBase64: string): string {
  // Keys shorter than 32 bytes are not used here: a 128/192-bit key would need
  // a different cipher name, and guessing at the algorithm is worse than refusing.
  // Check it before the blob, so a wrong key never reports a malformed ciphertext.
  const key = aesKey(materialBase64);
  if (key.length !== 32) throw new Error("decrypt requires a 32-byte (AES-256) key");
  const blob = Buffer.from(blobBase64, "base64");
  if (blob.length < 29) throw new Error("ciphertext too short");
  const nonce = blob.subarray(0, 12);
  const tag = blob.subarray(blob.length - 16);
  const ct = blob.subarray(12, blob.length - 16);
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString("utf8");
}
