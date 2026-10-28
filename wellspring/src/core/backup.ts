/** Human/offline portable backup. Source definitions are copied; host source data is never read. */
import { gcm } from "@noble/ciphers/aes";
import { randomBytes, scryptSync } from "node:crypto";
import { closeSync, constants, existsSync, fchmodSync, fstatSync, fsyncSync, mkdirSync, openSync, readSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { STORE_PATH, getMasterKey, type Entry, type Field } from "./store.ts";
import { parseSource } from "./source.ts";
import { validateUsePolicy } from "../policy/access.ts";

export const MAX_BACKUP_BYTES = 16 * 1024 * 1024;
const MAX_STORE_BYTES = 32 * 1024 * 1024;
const MAX_VALUE_BYTES = 1024 * 1024;
const RESERVED = new Set([...Object.getOwnPropertyNames(Object.prototype), "prototype"]);
const KDF = Object.freeze({ name: "scrypt", N: 32768, r: 8, p: 1 });
/** getKey returns an owned 32-byte copy, wiped after use. Import requires exclusive/offline custody. */
export type BackupStore = { path: string; getKey: () => Uint8Array };
const DEFAULT_STORE: BackupStore = { path: STORE_PATH, getKey: getMasterKey };
type PortableField = Omit<Field, "value"> & { value?: string };
type PortableEntry = Omit<Entry, "fields"> & { fields: Record<string, PortableField> };
type Portable = { version: 1; entries: PortableEntry[] };
type Store = { version: 1; entries: Record<string, Entry> };

function fail(): never { throw new Error("invalid backup archive or store"); }
function object(value: unknown): Record<string, any> {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail();
  return value as Record<string, any>;
}
function keys(value: Record<string, any>, allowed: string[]) {
  if (Object.keys(value).some(k => !allowed.includes(k))) fail();
}
function identifier(value: unknown, max: number): asserts value is string {
  if (typeof value !== "string" || !value.length || value.length > max || /[\s\u0000-\u001f\u007f/]/u.test(value) || RESERVED.has(value)) fail();
}
function rejectPrototypeKeys(value: unknown, depth = 0): void {
  if (depth > 32) fail();
  if (!value || typeof value !== "object") return;
  for (const key of Object.keys(value)) {
    if (RESERVED.has(key)) fail();
    rejectPrototypeKeys((value as Record<string, unknown>)[key], depth + 1);
  }
}
function parse(data: Uint8Array): any {
  let value: unknown;
  try { value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(data)); } catch { fail(); }
  rejectPrototypeKeys(value);
  return value;
}
function b64(value: unknown, min: number, max = min): Buffer {
  if (typeof value !== "string" || value.length > Math.ceil(max / 3) * 4 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) fail();
  const bytes = Buffer.from(value, "base64");
  if (bytes.length < min || bytes.length > max || bytes.toString("base64") !== value) fail();
  return bytes;
}
/** Bounded regular-file read, including growth after fstat; no FIFO/device allocation surprises. */
function readBounded(path: string, max: number): Buffer {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NONBLOCK);
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size > max) throw new Error("backup input exceeds size limit or is not a regular file");
    const data = Buffer.alloc(stat.size + 1);
    let used = 0;
    while (used < data.length) {
      const n = readSync(fd, data, used, data.length - used, null);
      if (!n) break;
      used += n;
    }
    if (used > stat.size) throw new Error("backup input changed while reading");
    return data.subarray(0, used);
  } finally { closeSync(fd); }
}
function validateEntries(input: unknown, encrypted: boolean): PortableEntry[] {
  if (!Array.isArray(input) || input.length > 10000) fail();
  const ids = new Set<string>();
  return input.map(raw => {
    const e = object(raw); keys(e, ["id", "type", "fields", "recipes", "tags"]);
    identifier(e.id, 256);
    if (ids.has(e.id) || !["credential", "person", "record"].includes(e.type)) fail();
    ids.add(e.id);
    const fields = object(e.fields);
    if (!Object.keys(fields).length || Object.keys(fields).length > 1000) fail();
    const out: PortableEntry = { id: e.id, type: e.type, fields: Object.create(null) };
    for (const [name, rawField] of Object.entries(fields)) {
      identifier(name, 128);
      const f = object(rawField); keys(f, ["value", "source", "class", "mask", "expiresAt", "usePolicy"]);
      if (!Object.hasOwn(f, "value") === !Object.hasOwn(f, "source")) fail();
      if (!["credential", "pii", "pii_high"].includes(f.class)) fail();
      const field: PortableField = { class: f.class };
      if (f.source !== undefined) {
        const source = object(f.source); keys(source, ["kind", "ref", "field"]);
        if (typeof source.ref !== "string" || (source.field !== undefined && typeof source.field !== "string")) fail();
        field.source = parseSource(source); // Validation only: never readSource/getSecret.
      } else {
        if (typeof f.value !== "string" || !f.value.length) fail();
        if (encrypted) b64(f.value, 29, MAX_VALUE_BYTES + 28);
        else if (Buffer.byteLength(f.value, "utf8") > MAX_VALUE_BYTES) fail();
        field.value = f.value;
      }
      if (f.mask !== undefined) {
        if (!["keep1", "phone", "region", "none"].includes(f.mask)) fail();
        field.mask = f.mask;
      }
      if (f.expiresAt !== undefined) {
        if (!Number.isSafeInteger(f.expiresAt) || f.expiresAt < 0) fail();
        field.expiresAt = f.expiresAt; // Preserve expired entries without extending their lifetime.
      }
      if (f.usePolicy !== undefined) field.usePolicy = validateUsePolicy(f.usePolicy);
      out.fields[name] = field;
    }
    if (e.tags !== undefined) {
      if (!Array.isArray(e.tags) || e.tags.length > 100 || e.tags.some((t: unknown) => typeof t !== "string" || !t.trim() || t.length > 128 || /[\u0000-\u001f\u007f]/u.test(t))) fail();
      out.tags = [...e.tags];
    }
    if (e.recipes !== undefined) {
      if (!Array.isArray(e.recipes) || e.recipes.length > 100) fail();
      out.recipes = e.recipes.map((raw: unknown) => {
        const r = object(raw); keys(r, ["id", "channel", "template"]);
        identifier(r.id, 128);
        if (typeof r.channel !== "string" || !r.channel.length || r.channel.length > 128 || !Object.hasOwn(r, "template")) fail();
        return { id: r.id, channel: r.channel, template: r.template };
      });
    }
    return out;
  });
}
function load(store: BackupStore): Store {
  if (!existsSync(store.path)) return { version: 1, entries: Object.create(null) };
  const raw = object(parse(readBounded(store.path, MAX_STORE_BYTES)));
  keys(raw, ["version", "entries"]);
  if (raw.version !== 1) fail();
  const entries = object(raw.entries);
  for (const [id, entry] of Object.entries(entries)) if (id !== object(entry).id) fail();
  const validated = validateEntries(Object.values(entries), true);
  return { version: 1, entries: Object.fromEntries(validated.map(e => [e.id, e as Entry])) };
}
function passphraseCheck(passphrase: string) {
  if (typeof passphrase !== "string" || !passphrase.length || Buffer.byteLength(passphrase) > 4096) throw new Error("backup passphrase must contain 1..4096 UTF-8 bytes");
}
function master(store: BackupStore): Uint8Array {
  const key = store.getKey();
  if (key.length !== 32) { key.fill(0); throw new Error("backup requires a 32-byte destination/source master key"); }
  return key;
}
function header(salt: string, nonce: string) { return { format: "wellspring-backup", version: 1, cipher: "aes-256-gcm", kdf: { ...KDF, salt }, nonce }; }
function derive(passphrase: string, salt: Uint8Array) {
  return scryptSync(passphrase, salt, 32, { N: KDF.N, r: KDF.r, p: KDF.p, maxmem: 64 * 1024 * 1024 });
}
/** Exclusive 0600 write; only encrypted data is ever written to disk. */
function writeExclusive(path: string, data: Uint8Array): void {
  const fd = openSync(path, "wx", 0o600);
  let complete = false;
  try { fchmodSync(fd, 0o600); writeFileSync(fd, data); fsyncSync(fd); complete = true; }
  finally { closeSync(fd); if (!complete) unlinkSync(path); }
}
export function exportBackup(path: string, passphrase: string, store: BackupStore = DEFAULT_STORE): { entries: number } {
  passphraseCheck(passphrase);
  const snapshot = load(store);
  const entries = Object.values(snapshot.entries) as PortableEntry[];
  const key = entries.some(e => Object.values(e.fields).some(f => f.source === undefined)) ? master(store) : undefined;
  let plaintext: Buffer | undefined;
  let wrappingKey: Buffer | undefined;
  try {
    for (const e of entries) for (const f of Object.values(e.fields)) {
      if (f.source !== undefined) continue;
      const blob = b64(f.value, 29, MAX_VALUE_BYTES + 28);
      const bytes = gcm(key!, blob.subarray(0, 12)).decrypt(blob.subarray(12));
      try { f.value = new TextDecoder("utf-8", { fatal: true }).decode(bytes); } finally { bytes.fill(0); }
    }
    plaintext = Buffer.from(JSON.stringify({ version: 1, entries } satisfies Portable));
    if (plaintext.length > MAX_BACKUP_BYTES / 2) throw new Error("backup plaintext exceeds size limit");
    const salt = randomBytes(16), nonce = randomBytes(12);
    const h = header(salt.toString("base64"), nonce.toString("base64"));
    wrappingKey = derive(passphrase, salt);
    const ciphertext = gcm(wrappingKey, nonce, Buffer.from(JSON.stringify(h))).encrypt(plaintext);
    const archive = Buffer.from(JSON.stringify({ ...h, ciphertext: Buffer.from(ciphertext).toString("base64") }));
    if (archive.length > MAX_BACKUP_BYTES) throw new Error("backup archive exceeds size limit");
    writeExclusive(path, archive);
    return { entries: entries.length };
  } finally { key?.fill(0); wrappingKey?.fill(0); plaintext?.fill(0); }
}
export function importBackup(path: string, passphrase: string, store: BackupStore = DEFAULT_STORE): { entries: number } {
  passphraseCheck(passphrase);
  const archive = object(parse(readBounded(path, MAX_BACKUP_BYTES)));
  keys(archive, ["format", "version", "cipher", "kdf", "nonce", "ciphertext"]);
  if (archive.format !== "wellspring-backup" || archive.version !== 1 || archive.cipher !== "aes-256-gcm") fail();
  const kdf = object(archive.kdf); keys(kdf, ["name", "N", "r", "p", "salt"]);
  // A single supported bounded profile: validate BEFORE running attacker-selected KDF work.
  if (kdf.name !== KDF.name || kdf.N !== KDF.N || kdf.r !== KDF.r || kdf.p !== KDF.p) fail();
  const salt = b64(kdf.salt, 16), nonce = b64(archive.nonce, 12);
  const ciphertext = b64(archive.ciphertext, 16, MAX_BACKUP_BYTES / 2 + 16);
  const h = header(kdf.salt, archive.nonce);
  const wrappingKey = derive(passphrase, salt);
  let plaintext: Uint8Array;
  try { plaintext = gcm(wrappingKey, nonce, Buffer.from(JSON.stringify(h))).decrypt(ciphertext); }
  catch { throw new Error("backup authentication failed (wrong passphrase or damaged archive)"); }
  finally { wrappingKey.fill(0); }
  let entries: PortableEntry[];
  try {
    const payload = object(parse(plaintext)); keys(payload, ["version", "entries"]);
    if (payload.version !== 1) fail();
    entries = validateEntries(payload.entries, false);
  } finally { plaintext.fill(0); }
  // All input validation and conflict checks precede key initialization or store mutation.
  const destination = load(store);
  for (const entry of entries) if (Object.hasOwn(destination.entries, entry.id)) throw new Error(`backup conflict: ${entry.id}`);
  if (!entries.length) return { entries: 0 };
  const key = entries.some(e => Object.values(e.fields).some(f => f.source === undefined)) ? master(store) : undefined;
  try {
    for (const e of entries) {
      for (const f of Object.values(e.fields)) {
        if (f.source !== undefined) continue;
        const bytes = Buffer.from(f.value!, "utf8"), iv = randomBytes(12);
        try { f.value = Buffer.concat([iv, gcm(key!, iv).encrypt(bytes)]).toString("base64"); }
        finally { bytes.fill(0); }
      }
      destination.entries[e.id] = e as Entry;
    }
    const encoded = Buffer.from(JSON.stringify(destination, null, 2));
    if (encoded.length > MAX_STORE_BYTES) throw new Error("restored store exceeds size limit");
    mkdirSync(dirname(store.path), { recursive: true });
    const tmp = `${store.path}.backup-${randomBytes(12).toString("hex")}.tmp`;
    writeExclusive(tmp, encoded);
    try { renameSync(tmp, store.path); } catch (error) { unlinkSync(tmp); throw error; }
    return { entries: entries.length };
  } finally { key?.fill(0); }
}

/** Dedicated backup input, never the master-passphrase/keychain channel or argv/chat. */
export function obtainBackupPassphrase(confirm = false): string {
  let value: string | undefined;
  if (process.env.WELLSPRING_BACKUP_PASSPHRASE !== undefined) value = process.env.WELLSPRING_BACKUP_PASSPHRASE;
  else if (process.env.WELLSPRING_BACKUP_PASSPHRASE_FILE !== undefined) {
    const bytes = readBounded(process.env.WELLSPRING_BACKUP_PASSPHRASE_FILE, 4098);
    try { value = new TextDecoder("utf-8", { fatal: true }).decode(bytes).replace(/\r?\n$/, ""); }
    finally { bytes.fill(0); }
  } else {
    value = promptBackup("Backup passphrase: ");
    if (confirm && promptBackup("Confirm backup passphrase: ") !== value) throw new Error("backup passphrase confirmation does not match");
  }
  passphraseCheck(value);
  return value;
}
function promptBackup(label: string): string {
  if (!process.stdin.isTTY || !process.stdin.setRawMode) throw new Error("backup requires hidden TTY input or WELLSPRING_BACKUP_PASSPHRASE[_FILE]");
  const wasRaw = process.stdin.isRaw;
  const fd = openSync("/dev/tty", "r");
  const bytes: number[] = [];
  process.stderr.write(label);
  try {
    process.stdin.setRawMode(true);
    const byte = Buffer.alloc(1);
    for (;;) {
      if (readSync(fd, byte, 0, 1, null) !== 1 || byte[0] === 3 || byte[0] === 4) throw new Error("backup passphrase entry cancelled");
      if (byte[0] === 10 || byte[0] === 13) break;
      if (byte[0] === 127 || byte[0] === 8) {
        while (bytes.length && (bytes[bytes.length - 1] & 0xc0) === 0x80) bytes.pop();
        bytes.pop();
      } else { bytes.push(byte[0]); if (bytes.length > 4096) throw new Error("backup passphrase too long"); }
    }
    return new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.from(bytes));
  } finally { process.stdin.setRawMode(wasRaw); closeSync(fd); bytes.fill(0); process.stderr.write("\n"); }
}
