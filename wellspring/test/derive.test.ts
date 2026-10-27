import { describe, expect, test } from "bun:test";
import { totp, hmac, encryptAesGcm, decryptAesGcm, base32Decode } from "../src/core/derive.ts";

// RFC 6238 published test vectors, SHA-1, 8 digits, 30s period.
// Seed is the ASCII string "12345678901234567890" in base32.
const VECTOR_SEED = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const VECTORS: [number, string][] = [
  [59, "94287082"],
  [1111111109, "07081804"],
  [1111111111, "14050471"],
  [1234567890, "89005924"],
  [2000000000, "69279037"],
];

test("TOTP matches the RFC 6238 test vectors", () => {
  for (const [seconds, expected] of VECTORS) {
    expect(totp(VECTOR_SEED, { digits: 8, at: seconds * 1000 }).code).toBe(expected);
  }
});

test("TOTP codes are single-use: the value rotates with the window", () => {
  const a = totp(VECTOR_SEED, { at: 1_700_000_000_000 });
  const b = totp(VECTOR_SEED, { at: 1_700_000_000_000 + 30_000 });
  expect(a.code).not.toBe(b.code);
  expect(a.expiresAt).toBe(b.expiresAt - 30_000);
  expect(a.remaining).toBeGreaterThan(0);
  expect(a.remaining).toBeLessThanOrEqual(30);
});

test("TOTP rejects out-of-range digits and periods", () => {
  expect(() => totp(VECTOR_SEED, { digits: 5, at: 0 })).toThrow("digits must be 6..8");
  expect(() => totp(VECTOR_SEED, { digits: 9, at: 0 })).toThrow("digits must be 6..8");
  expect(() => totp(VECTOR_SEED, { period: 0, at: 0 })).toThrow("period must be 1..300 seconds");
  expect(() => totp(VECTOR_SEED, { period: 301, at: 0 })).toThrow("period must be 1..300 seconds");
});

test("base32 accepts the standard alphabet and rejects everything else", () => {
  expect(Buffer.from(base32Decode(VECTOR_SEED)).toString("ascii")).toBe("12345678901234567890");
  // Lowercase and padding are tolerated; unknown characters are not.
  expect(Buffer.from(base32Decode("gezdgnbvgy3tqojqgezdgnbvgy3tqojq")).toString("ascii")).toBe("12345678901234567890");
  expect(() => base32Decode("")).toThrow("empty base32 seed");
  expect(() => base32Decode("AB1")).toThrow("invalid base32 seed");
  expect(() => base32Decode("AB!")).toThrow("invalid base32 seed");
});

test("HMAC matches the RFC 4231 SHA-256 vectors", () => {
  // RFC 4231 test case 2: 20-byte key 0x0b repeated, data "Hi There".
  const key = Buffer.alloc(20, 0x0b).toString("hex");
  const got = hmac(Buffer.from(key, "hex").toString("latin1"), "Hi There");
  // The key is fed as UTF-8 bytes, and every 0x0b byte is a valid ASCII character,
  // so the latin1 round-trip reproduces the exact RFC key material.
  expect(got).toBe("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
  expect(hmac("key", "The quick brown fox jumps over the lazy dog"))
    .toBe("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");
});

test("HMAC-SHA512 differs from HMAC-SHA256 for the same input", () => {
  expect(hmac("k", "data")).toHaveLength(64);
  expect(hmac("k", "data", "sha512")).toHaveLength(128);
  expect(hmac("k", "data")).not.toBe(hmac("k", "data", "sha512"));
});

test("AES-256-GCM round-trips and refuses a tampered blob", () => {
  const key = Buffer.alloc(32, 0x42).toString("base64");
  const plaintext = "card 4111111111111111, cvv 123";
  const blob = encryptAesGcm(key, plaintext);
  expect(blob).not.toContain("4111");
  expect(decryptAesGcm(key, blob)).toBe(plaintext);

  // Flip one byte of the ciphertext: GCM must refuse instead of returning garbage.
  const raw = Buffer.from(blob, "base64");
  raw[13] ^= 0x01;
  expect(() => decryptAesGcm(key, raw.toString("base64"))).toThrow();
});

test("AES-256-GCM uses a fresh nonce on every call", () => {
  const key = Buffer.alloc(32, 0x07).toString("base64");
  const a = encryptAesGcm(key, "same plaintext");
  const b = encryptAesGcm(key, "same plaintext");
  expect(a).not.toBe(b);
  expect(decryptAesGcm(key, a)).toBe(decryptAesGcm(key, b));
});

test("AES rejects keys that are not 32 bytes, and bad input", () => {
  const short16 = Buffer.alloc(16, 1).toString("base64");
  const key32 = Buffer.alloc(32, 1).toString("base64");
  expect(() => encryptAesGcm(short16, "x")).toThrow("encrypt requires a 32-byte (AES-256) key");
  expect(() => decryptAesGcm(short16, "x")).toThrow("decrypt requires a 32-byte (AES-256) key");
  expect(() => encryptAesGcm("not base64 at all!!!", "x")).toThrow();
  expect(() => decryptAesGcm(key32, "AAAA")).toThrow("ciphertext too short");
  expect(() => encryptAesGcm("!!", "x")).toThrow("AES key must decode from base64 to 16, 24 or 32 bytes");
});
