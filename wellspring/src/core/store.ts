/**
 * Wellspring core: crypto + storage.
 * Store: JSON file, values encrypted with AES-256-GCM.
 * Master key: from env WELLSPRING_KEY (base64) or keyfile ~/.wellspring/master.key
 */
import { gcm } from "@noble/ciphers/aes";
import { randomBytes, scryptSync } from "node:crypto";
import { obtainPassphrase, SEALED_KEY_ERROR } from "./custody.ts";
import { mkdirSync, readFileSync, writeFileSync, existsSync, renameSync, chmodSync } from "node:fs";
import { join, dirname } from "node:path";
import { homedir } from "node:os";

export const WS_HOME = process.env.WELLSPRING_HOME ?? join(homedir(), ".wellspring");
export const STORE_PATH = join(WS_HOME, "store.json");
const MASTER_KEY_PATH = join(WS_HOME, "master.key");

// ---------- master key ----------
export const SCRYPT_PARAMS = Object.freeze({ N: 2 ** 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
export type ScryptParams = typeof SCRYPT_PARAMS;
const KEYFILE_V2_LENGTH = 1 + 16 + 12 + 32 + 16;

/** Parameters can be supplied by isolated tests; files do not encode a KDF profile. */
export function unwrapMasterKey(blob: Uint8Array, passphrase: string, params: ScryptParams = SCRYPT_PARAMS): Uint8Array {
  if (blob.length !== KEYFILE_V2_LENGTH || blob[0] !== 2) throw new Error("corrupt master key (expected raw v1 or sealed v2 keyfile)");
  try {
    const wrappingKey = scryptSync(passphrase, blob.subarray(1, 17), 32, params);
    try { return gcm(wrappingKey, blob.subarray(17, 29)).decrypt(blob.subarray(29)); }
    finally { wrappingKey.fill(0); }
  } catch { throw new Error(SEALED_KEY_ERROR); }
}

export function wrapMasterKey(key: Uint8Array, passphrase: string, params: ScryptParams = SCRYPT_PARAMS): Uint8Array {
  if (key.length !== 32 || !passphrase) throw new Error("a 32-byte master key and nonempty passphrase are required");
  const salt = randomBytes(16);
  const nonce = randomBytes(12);
  const wrappingKey = scryptSync(passphrase, salt, 32, params);
  try { return Buffer.concat([Buffer.from([2]), salt, nonce, gcm(wrappingKey, nonce).encrypt(key)]); }
  finally { wrappingKey.fill(0); }
}

export function getMasterKey(): Uint8Array {
  if (process.env.WELLSPRING_KEY) {
    return Buffer.from(process.env.WELLSPRING_KEY, "base64");
  }
  if (existsSync(MASTER_KEY_PATH)) {
    const k = readFileSync(MASTER_KEY_PATH);
    if (k.length === 32) return new Uint8Array(k); // v1 is always exactly 32 raw bytes.
    if (k.length !== KEYFILE_V2_LENGTH || k[0] !== 2) throw new Error("corrupt master key (expected raw v1 or sealed v2 keyfile)");
    return unwrapMasterKey(k, obtainPassphrase());
  }
  return initMasterKey();
}

function replaceMasterKey(blob: Uint8Array): void {
  const tmp = MASTER_KEY_PATH + ".tmp";
  writeFileSync(tmp, blob, { mode: 0o600 });
  chmodSync(tmp, 0o600);
  renameSync(tmp, MASTER_KEY_PATH);
  chmodSync(MASTER_KEY_PATH, 0o600);
}

export function sealMasterKey(): void {
  if (process.env.WELLSPRING_KEY !== undefined) throw new Error("seal refuses WELLSPRING_KEY: unset it to use file custody");
  if (!existsSync(MASTER_KEY_PATH)) throw new Error("no master keyfile to seal; initialize the store first");
  const key = getMasterKey(); // A sealed key must be unlocked before re-wrapping.
  try { replaceMasterKey(wrapMasterKey(key, obtainPassphrase(true))); }
  finally { key.fill(0); }
}

export function unsealMasterKey(): void {
  if (process.env.WELLSPRING_KEY !== undefined) throw new Error("unseal refuses WELLSPRING_KEY: unset it to use file custody");
  if (!existsSync(MASTER_KEY_PATH)) throw new Error("no master keyfile to unseal");
  const key = getMasterKey();
  try { replaceMasterKey(key); }
  finally { key.fill(0); }
}

function initMasterKey(): Uint8Array {
  mkdirSync(WS_HOME, { recursive: true });
  const key = randomBytes(32);
  writeFileSync(MASTER_KEY_PATH, key, { mode: 0o600 });
  chmodSync(MASTER_KEY_PATH, 0o600);
  return new Uint8Array(key);
}

// ---------- aead ----------
function encrypt(key: Uint8Array, plaintext: Uint8Array): string {
  const nonce = randomBytes(12);
  const ct = gcm(key, nonce).encrypt(plaintext);
  // nonce(12) | ct | tag(16)
  const blob = Buffer.concat([nonce, ct]);
  return blob.toString("base64");
}

function decrypt(key: Uint8Array, b64: string): Uint8Array {
  const blob = Buffer.from(b64, "base64");
  const nonce = blob.subarray(0, 12);
  const ct = blob.subarray(12);
  return gcm(key, nonce).decrypt(ct);
}

// ---------- store ----------
export type Class = "credential" | "pii" | "pii_high";
export type Recipe = { id: string; channel: string; template: unknown };

export type Field = {
  value: string; // encrypted b64 (or plaintext if store not sealed yet — never, we seal on write)
  class: Class;
  mask?: string; // for pii: keep1 | phone | region | none
  expiresAt?: number; // epoch ms; after this instant the daemon refuses to draw the value
};

export type Entry = {
  id: string; // e.g. cred:db_prod / person:zhang_san
  type: "credential" | "person" | "record";
  fields: Record<string, Field>;
  recipes?: Recipe[];
  tags?: string[];
};

type Store = { version: 1; entries: Record<string, Entry> };

function loadStore(): Store {
  if (!existsSync(STORE_PATH)) return { version: 1, entries: {} };
  return JSON.parse(readFileSync(STORE_PATH, "utf8"));
}

function saveStore(s: Store) {
  mkdirSync(dirname(STORE_PATH), { recursive: true });
  const tmp = STORE_PATH + ".tmp";
  writeFileSync(tmp, JSON.stringify(s, null, 2), { mode: 0o600 });
  renameSync(tmp, STORE_PATH);
  chmodSync(STORE_PATH, 0o600);
}

// ---------- fingerprint ----------
import { createHash } from "node:crypto";
export function fingerprint(plaintext: string): string {
  return "sha256:" + createHash("sha256").update(plaintext).digest("hex").slice(0, 16);
}

// ---------- public API ----------
// Reject prototype keys even when input arrives from untyped JSON-RPC callers.
const RESERVED_KEYS = new Set([...Object.getOwnPropertyNames(Object.prototype), "prototype"]);
const hasOwn = (object: object, key: string): boolean => Object.prototype.hasOwnProperty.call(object, key);

function validateKey(value: unknown, name: "id" | "field"): asserts value is string {
  const max = name === "id" ? 256 : 128;
  if (typeof value !== "string" || !value.length || value.length > max || /[\s\u0000-\u001f\u007f/]/u.test(value) || RESERVED_KEYS.has(value)) {
    throw new Error(`invalid ${name}`);
  }
}

export const MIN_TTL_MS = 1000;                 // 1 second
export const MAX_TTL_MS = 31_536_000_000;       // 1 year (365 days)
/** True when the field carries an expiry that has already elapsed. Never reads plaintext. */
export function isExpired(f: Field): boolean {
  return f.expiresAt !== undefined && Date.now() >= f.expiresAt;
}
/** True when a draw failure was caused by expiry rather than a missing secret. */
export function isExpiryError(error: unknown): boolean {
  return error instanceof Error && error.message.startsWith("secret expired: ");
}

function resolveExpiry(opts?: { ttlMs?: number; expiresAt?: number }): number | undefined {
  const ttlMs = opts?.ttlMs;
  const expiresAt = opts?.expiresAt;
  if (ttlMs !== undefined && expiresAt !== undefined) throw new Error("specify either ttlMs or expiresAt, not both");
  if (ttlMs !== undefined) {
    if (!Number.isInteger(ttlMs) || ttlMs < MIN_TTL_MS || ttlMs > MAX_TTL_MS) {
      throw new Error(`invalid ttlMs: expected an integer from ${MIN_TTL_MS} to ${MAX_TTL_MS} (1 second .. 1 year)`);
    }
    return Date.now() + ttlMs;
  }
  if (expiresAt !== undefined) {
    if (!Number.isInteger(expiresAt)) throw new Error("invalid expiresAt: expected an integer epoch timestamp in milliseconds");
    const now = Date.now();
    if (expiresAt <= now) throw new Error("invalid expiresAt: must be in the future");
    if (expiresAt - now > MAX_TTL_MS) throw new Error(`invalid expiresAt: at most 1 year (${MAX_TTL_MS} ms) from now`);
    return expiresAt;
  }
  return undefined; // no expiry supplied: the credential becomes permanent again
}

export function putSecret(id: string, field: string, plaintext: string, opts?: { cls?: Class; mask?: string; tags?: string[]; ttlMs?: number; expiresAt?: number }) {
  validateKey(id, "id");
  validateKey(field, "field");
  if (typeof plaintext !== "string" || !plaintext.length || Buffer.byteLength(plaintext, "utf8") > 1024 * 1024) {
    throw new Error("invalid value: expected a nonempty string of at most 1 MiB");
  }
  if (opts !== undefined && (opts === null || typeof opts !== "object" || Array.isArray(opts))) throw new Error("invalid options");
  if (opts?.cls !== undefined && !["credential", "pii", "pii_high"].includes(opts.cls)) throw new Error("invalid class");
  if (opts?.mask !== undefined && !["keep1", "phone", "region", "none"].includes(opts.mask)) throw new Error("invalid mask");
  if (opts?.tags !== undefined && (!Array.isArray(opts.tags) || opts.tags.length > 100 ||
    Array.from(opts.tags).some((tag) => typeof tag !== "string" || !tag.trim() || tag.length > 128 || /[\u0000-\u001f\u007f]/u.test(tag)))) {
    throw new Error("invalid tags: expected at most 100 nonempty strings of at most 128 characters");
  }
  const expiresAt = resolveExpiry(opts);
  const key = getMasterKey();
  const s = loadStore();
  if (!hasOwn(s.entries, id)) s.entries[id] = { id, type: id.startsWith("person:") ? "person" : "credential", fields: Object.create(null) };
  const cls = opts?.cls ?? (id.startsWith("person:") ? "pii" : "credential");
  const stored: Field = {
    value: encrypt(key, Buffer.from(plaintext, "utf8")),
    class: cls,
    mask: opts?.mask,
  };
  // An omitted expiry explicitly makes the replacement permanent.
  if (expiresAt !== undefined) stored.expiresAt = expiresAt;
  s.entries[id].fields[field] = stored;
  if (opts?.tags) s.entries[id].tags = opts.tags;
  saveStore(s);
}

export function deleteSecret(id: string, field?: string): void {
  validateKey(id, "id");
  if (field !== undefined) validateKey(field, "field");
  const s = loadStore();
  if (!hasOwn(s.entries, id)) throw new Error(`no such entry: ${id}`);
  if (field === undefined) {
    delete s.entries[id];
  } else {
    const entry = s.entries[id];
    if (!hasOwn(entry.fields, field)) throw new Error(`no such secret: ${id}/${field}`);
    delete entry.fields[field];
    if (Object.keys(entry.fields).length === 0) delete s.entries[id];
  }
  saveStore(s);
}

export function getSecret(id: string, field: string): string {
  validateKey(id, "id");
  validateKey(field, "field");
  const key = getMasterKey();
  const s = loadStore();
  const entry = hasOwn(s.entries, id) ? s.entries[id] : undefined;
  const f = entry && hasOwn(entry.fields, field) ? entry.fields[field] : undefined;
  if (!f) throw new Error(`no such secret: ${id}/${field}`);
  return Buffer.from(decrypt(key, f.value)).toString("utf8");
}

/**
 * Draw-path read: identical to getSecret except that an expired field is refused
 * BEFORE any ciphertext touches the caller. Errors mention "expired".
 */
export function getSecretFresh(id: string, field: string): string {
  validateKey(id, "id");
  validateKey(field, "field");
  const key = getMasterKey();
  const s = loadStore();
  const entry = hasOwn(s.entries, id) ? s.entries[id] : undefined;
  const f = entry && hasOwn(entry.fields, field) ? entry.fields[field] : undefined;
  if (!f) throw new Error(`no such secret: ${id}/${field}`);
  if (f.expiresAt !== undefined && Date.now() >= f.expiresAt) throw new Error(`secret expired: ${id}/${field}`);
  return Buffer.from(decrypt(key, f.value)).toString("utf8");
}

export function mask(plaintext: string, mode?: string): string {
  switch (mode) {
    case "phone":
      return plaintext.length >= 7
        ? plaintext.slice(0, 3) + "****" + plaintext.slice(-4)
        : "****";
    case "region": {
      // keep first 6 chars (city/district) then mask
      return plaintext.length <= 6 ? "*".repeat(plaintext.length) : plaintext.slice(0, 6) + "***";
    }
    case "none":
      return "****";
    case "keep1":
    default:
      return plaintext.length <= 1 ? "*" : plaintext[0] + "*".repeat(Math.max(plaintext.length - 1, 1));
  }
}

/** Descriptor: everything an agent is allowed to see. Never contains plaintext. */
export type Descriptor = {
  ref: string;
  fields: { name: string; class: Class; mask?: string; fingerprint: string; expiresAt?: number; expired?: boolean }[];
  recipes: { id: string; channel: string }[];
  tags: string[];
};

/**
 * Expiry projection for the agent-visible surfaces: a future expiry, or the flag
 * that it elapsed. Both keys are omitted for permanent credentials. No plaintext.
 */
function expiryProjection(f: Field): { expiresAt?: number; expired?: boolean } {
  return f.expiresAt === undefined ? {} : { expiresAt: f.expiresAt, expired: Date.now() >= f.expiresAt };
}

const BUILTIN_RECIPES = [
  {id:'env',channel:'A1/exec'}, {id:'fd',channel:'A2/fd'},
  {id:'file',channel:'C1/file'}, {id:'template',channel:'C1/template'},
  {id:'askpass',channel:'git/askpass'},
];
function availableRecipes(entry: Entry): Descriptor['recipes'] {
  return [...BUILTIN_RECIPES,...(entry.recipes ?? []).map(({id,channel})=>({id,channel}))];
}
export function listDescriptors(filter?: { tag?: string }): Descriptor[] {
  const s = loadStore();
  const key = getMasterKey();
  return Object.values(s.entries)
    .filter((e) => !filter?.tag || (e.tags ?? []).includes(filter.tag))
    .map((e) => ({
      ref: `secret://${e.id}`,
      fields: Object.entries(e.fields).map(([name, f]) => ({
        name,
        class: f.class,
        mask: f.mask,
        fingerprint: fingerprint(Buffer.from(decrypt(key, f.value)).toString("utf8")),
        ...expiryProjection(f),
      })),
      recipes: availableRecipes(e),
      tags: e.tags ?? [],
    }));
}

export function describe(id: string): Descriptor & { maskedPreview: Record<string, string> } {
  validateKey(id, "id");
  const s = loadStore();
  const key = getMasterKey();
  const e = hasOwn(s.entries, id) ? s.entries[id] : undefined;
  if (!e) throw new Error(`no such entry: ${id}`);
  const masked: Record<string, string> = Object.create(null);
  const fields: Descriptor["fields"] = [];
  for (const [name, f] of Object.entries(e.fields)) {
    const pt = Buffer.from(decrypt(key, f.value)).toString("utf8");
    masked[name] = f.class === "credential" ? "****" : mask(pt, f.mask);
    fields.push({ name, class: f.class, mask: f.mask, fingerprint: fingerprint(pt), ...expiryProjection(f) });
  }
  return {
    ref: `secret://${e.id}`,
    fields,
    recipes: availableRecipes(e),
    tags: e.tags ?? [],
    maskedPreview: masked,
  };
}
