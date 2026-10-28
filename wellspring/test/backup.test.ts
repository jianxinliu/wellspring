import { test, expect } from "bun:test";
import { gcm } from "@noble/ciphers/aes";
import { randomBytes, scryptSync } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, truncateSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { exportBackup, importBackup, MAX_BACKUP_BYTES, type BackupStore } from "../src/core/backup.ts";

const PASSWORD = "synthetic backup passphrase";
function fixture(run: (ctx: { dir: string; source: BackupStore; target: BackupStore; archive: string; keyA: Buffer; keyB: Buffer }) => void) {
  const dir = mkdtempSync(join(tmpdir(), "wellspring-backup-"));
  const keyA = Buffer.alloc(32, 31), keyB = Buffer.alloc(32, 73);
  try { run({ dir, keyA, keyB, archive: join(dir, "archive.ws"), source: { path: join(dir, "source.json"), getKey: () => Buffer.from(keyA) }, target: { path: join(dir, "target.json"), getKey: () => Buffer.from(keyB) } }); }
  finally { rmSync(dir, { recursive: true, force: true }); }
}
function encrypt(value: string, key: Uint8Array) {
  const nonce = randomBytes(12);
  return Buffer.concat([nonce, gcm(key, nonce).encrypt(Buffer.from(value))]).toString("base64");
}
function decrypt(value: string, key: Uint8Array) {
  const blob = Buffer.from(value, "base64");
  return Buffer.from(gcm(key, blob.subarray(0, 12)).decrypt(blob.subarray(12))).toString();
}
function seed(path: string, key: Uint8Array) {
  writeFileSync(path, JSON.stringify({ version: 1, entries: {
    "cred:alpha": { id: "cred:alpha", type: "credential", fields: { password: { value: encrypt("synthetic-secret-alpha", key), class: "credential", expiresAt: 1, mask: "none", usePolicy: { callers: ["alice"], purposes: ["test"], channels: ["A2/fd"], targets: ["synthetic"] } } }, tags: ["synthetic"], recipes: [{ id: "custom", channel: "test/channel", template: { text: "{{password}}" } }] },
    "person:beta": { id: "person:beta", type: "person", fields: { name: { value: encrypt("Synthetic Name", key), class: "pii_high", mask: "keep1" }, external: { class: "credential", source: { kind: "file", ref: "/synthetic/absent/path" }, expiresAt: 10 }, command: { class: "credential", source: { kind: "command", ref: "exit 99" } }, env: { class: "credential", source: { kind: "env", ref: "WELLSPRING_SYNTHETIC_ABSENT" } } } }
  } }));
}
/** A valid authenticated envelope around deliberately malformed synthetic payloads. */
function forge(path: string, payload: unknown) {
  const salt = randomBytes(16), nonce = randomBytes(12);
  const header = { format: "wellspring-backup", version: 1, cipher: "aes-256-gcm", kdf: { name: "scrypt", N: 32768, r: 8, p: 1, salt: salt.toString("base64") }, nonce: nonce.toString("base64") };
  const key = scryptSync(PASSWORD, salt, 32, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
  try { writeFileSync(path, JSON.stringify({ ...header, ciphertext: Buffer.from(gcm(key, nonce, Buffer.from(JSON.stringify(header))).encrypt(Buffer.from(JSON.stringify(payload)))).toString("base64") })); }
  finally { key.fill(0); }
}
const entry = (id: string, value = "synthetic") => ({ id, type: "credential", fields: { value: { class: "credential", value } } });

test("portable multi-entry backup reencrypts destination, preserves metadata and never reads sources", () => fixture(c => {
  seed(c.source.path, c.keyA);
  expect(exportBackup(c.archive, PASSWORD, c.source)).toEqual({ entries: 2 });
  expect(statSync(c.archive).mode & 0o777).toBe(0o600);
  const archive = readFileSync(c.archive, "utf8");
  for (const absent of ["synthetic-secret-alpha", "Synthetic Name", "password", "admin.token", "/synthetic/absent/path", c.keyA.toString("base64")]) expect(archive).not.toContain(absent);
  expect(importBackup(c.archive, PASSWORD, c.target)).toEqual({ entries: 2 });
  const before = JSON.parse(readFileSync(c.source.path, "utf8")), after = JSON.parse(readFileSync(c.target.path, "utf8"));
  const original = before.entries["cred:alpha"], restored = after.entries["cred:alpha"];
  expect(decrypt(restored.fields.password.value, c.keyB)).toBe("synthetic-secret-alpha");
  expect(() => decrypt(restored.fields.password.value, c.keyA)).toThrow();
  expect(restored.fields.password.value).not.toBe(original.fields.password.value);
  delete restored.fields.password.value; delete original.fields.password.value;
  expect(restored).toEqual(original);
  expect(after.entries["person:beta"].fields.external).toEqual(before.entries["person:beta"].fields.external);
  expect(after.entries["person:beta"].fields.command).toEqual(before.entries["person:beta"].fields.command);
  expect(decrypt(after.entries["person:beta"].fields.name.value, c.keyB)).toBe("Synthetic Name");
  expect(statSync(c.target.path).mode & 0o777).toBe(0o600);
  expect(readdirSync(c.dir).some(p => p.endsWith(".tmp"))).toBe(false);
}));

test("fresh salt/nonce per export and exclusive existing-file protection", () => fixture(c => {
  seed(c.source.path, c.keyA);
  exportBackup(c.archive, PASSWORD, c.source);
  const second = join(c.dir, "second.ws"); exportBackup(second, PASSWORD, c.source);
  const a = JSON.parse(readFileSync(c.archive, "utf8")), b = JSON.parse(readFileSync(second, "utf8"));
  expect(a.kdf.salt).not.toBe(b.kdf.salt); expect(a.nonce).not.toBe(b.nonce);
  const bytes = readFileSync(c.archive);
  expect(() => exportBackup(c.archive, PASSWORD, c.source)).toThrow();
  expect(readFileSync(c.archive)).toEqual(bytes);
}));

test("wrong password and ciphertext/header tampering never create store or obtain destination key", () => fixture(c => {
  seed(c.source.path, c.keyA); exportBackup(c.archive, PASSWORD, c.source);
  let calls = 0; const target = { path: c.target.path, getKey: () => { calls++; return Buffer.from(c.keyB); } };
  expect(() => importBackup(c.archive, "wrong", target)).toThrow("authentication failed");
  const original = JSON.parse(readFileSync(c.archive, "utf8"));
  for (const part of ["ciphertext", "nonce"]) {
    const altered = structuredClone(original); const bytes = Buffer.from(altered[part], "base64"); bytes[0] ^= 1; altered[part] = bytes.toString("base64");
    writeFileSync(c.archive, JSON.stringify(altered));
    expect(() => importBackup(c.archive, PASSWORD, target)).toThrow("authentication failed");
  }
  expect(calls).toBe(0); expect(existsSync(c.target.path)).toBe(false);
}));

test("bounded KDF rejects hostile parameters and malformed envelope without key/store effects", () => fixture(c => {
  forge(c.archive, { version: 1, entries: [] });
  const original = JSON.parse(readFileSync(c.archive, "utf8"));
  for (const changed of [{ ...original, kdf: { ...original.kdf, N: 2 ** 30 } }, { ...original, kdf: { ...original.kdf, p: 100000 } }, { ...original, nonce: "x" }, { ...original, version: 2 }, { ...original, extra: "x" }]) {
    writeFileSync(c.archive, JSON.stringify(changed));
    expect(() => importBackup(c.archive, PASSWORD, c.target)).toThrow();
  }
  writeFileSync(c.archive, "{bad json"); expect(() => importBackup(c.archive, PASSWORD, c.target)).toThrow();
  truncateSync(c.archive, MAX_BACKUP_BYTES + 1); expect(() => importBackup(c.archive, PASSWORD, c.target)).toThrow("size limit");
  expect(existsSync(c.target.path)).toBe(false);
}));

test("late invalid entry and duplicate IDs validate whole archive before key initialization or mutation", () => fixture(c => {
  let calls = 0; const target = { path: c.target.path, getKey: () => { calls++; return Buffer.from(c.keyB); } };
  const badEntries = [
    [entry("cred:ok"), entry("cred:bad", "")],
    [entry("cred:ok"), entry("cred:ok")],
    [entry("cred:ok"), { ...entry("cred:bad"), fields: { value: { value: "x", source: { kind: "env", ref: "X" }, class: "credential" } } }],
    [entry("cred:ok"), { ...entry("cred:bad"), fields: JSON.parse('{"__proto__":{"value":"x","class":"credential"}}') }],
    [entry("cred:ok"), { ...entry("cred:bad"), recipes: [{ id: "r", channel: "x", template: JSON.parse('{"constructor":"x"}') }] }],
    [entry("cred:ok"), { ...entry("cred:bad"), tags: [1] }],
    [entry("cred:ok"), { ...entry("cred:bad"), fields: { value: { value: "x", class: "credential", expiresAt: 1.5 } } }],
  ];
  for (const entries of badEntries) {
    forge(c.archive, { version: 1, entries });
    expect(() => importBackup(c.archive, PASSWORD, target)).toThrow();
    expect(existsSync(c.target.path)).toBe(false);
  }
  expect(calls).toBe(0);
}));

test("late conflict fails entire import and leaves existing destination byte-identical", () => fixture(c => {
  seed(c.target.path, c.keyB); const original = readFileSync(c.target.path);
  forge(c.archive, { version: 1, entries: [entry("cred:new"), entry("cred:alpha")] });
  let calls = 0;
  expect(() => importBackup(c.archive, PASSWORD, { path: c.target.path, getKey: () => { calls++; return Buffer.from(c.keyB); } })).toThrow("backup conflict");
  expect(readFileSync(c.target.path)).toEqual(original); expect(calls).toBe(0);
}));

test("destination encryption failure commits no partial entry", () => fixture(c => {
  seed(c.target.path, c.keyB); const original = readFileSync(c.target.path);
  forge(c.archive, { version: 1, entries: [entry("cred:new1"), entry("cred:new2")] });
  expect(() => importBackup(c.archive, PASSWORD, { path: c.target.path, getKey: () => Buffer.alloc(31) })).toThrow("32-byte");
  expect(readFileSync(c.target.path)).toEqual(original);
}));

test("restore merges unrelated entries and final rename failure cleans only encrypted temp", () => fixture(c => {
  seed(c.target.path, c.keyB);
  const before = JSON.parse(readFileSync(c.target.path, "utf8"));
  forge(c.archive, { version: 1, entries: [entry("cred:new")] });
  importBackup(c.archive, PASSWORD, c.target);
  const after = JSON.parse(readFileSync(c.target.path, "utf8"));
  expect(after.entries["cred:alpha"]).toEqual(before.entries["cred:alpha"]);
  expect(after.entries["person:beta"]).toEqual(before.entries["person:beta"]);
  expect(decrypt(after.entries["cred:new"].fields.value.value, c.keyB)).toBe("synthetic");
  const blocked = join(c.dir, "blocked.json");
  // The injected key callback simulates a concurrent filesystem change after load.
  const target = { path: blocked, getKey: () => { mkdirSync(blocked); writeFileSync(join(blocked, "sentinel"), "unchanged"); return Buffer.from(c.keyB); } };
  expect(() => importBackup(c.archive, PASSWORD, target)).toThrow();
  expect(readFileSync(join(blocked, "sentinel"), "utf8")).toBe("unchanged");
  expect(readdirSync(c.dir).some(name => name.includes(".backup-"))).toBe(false);
}));

test("archive rejects excluded data and source-only archive needs no master key", () => fixture(c => {
  forge(c.archive, { version: 1, entries: [], adminToken: "synthetic" });
  expect(() => importBackup(c.archive, PASSWORD, c.target)).toThrow();
  forge(c.archive, { version: 1, entries: [{ id: "cred:source", type: "record", fields: { value: { class: "credential", source: { kind: "file", ref: "/synthetic/missing" } } } }] });
  const sourceOnly = { path: c.target.path, getKey: () => { throw new Error("must not obtain key"); } };
  expect(importBackup(c.archive, PASSWORD, sourceOnly)).toEqual({ entries: 1 });
  expect(exportBackup(join(c.dir, "sources.ws"), PASSWORD, sourceOnly)).toEqual({ entries: 1 });
}));

test("human CLI uses dedicated backup passphrase file, restores offline, rejects scoped agent and argv passwords", () => fixture(c => {
  const cli = join(import.meta.dir, "../src/cli/main.ts");
  const sourceHome = join(c.dir, "source-home"), targetHome = join(c.dir, "target-home");
  const passfile = join(c.dir, "passphrase"); writeFileSync(passfile, PASSWORD + "\n", { mode: 0o600 });
  const run = (args: string[], home: string, extra = {}) => Bun.spawnSync({ cmd: [process.execPath, cli, ...args], env: { ...process.env, WELLSPRING_HOME: home, WELLSPRING_SOCK: join(home, "daemon.sock"), WELLSPRING_KEY: c.keyA.toString("base64"), WELLSPRING_BACKUP_PASSPHRASE: undefined, WELLSPRING_BACKUP_PASSPHRASE_FILE: passfile, WELLSPRING_CLIENT_TOKEN: undefined, WELLSPRING_ONESHOT: undefined, ...extra } });
  mkdirSync(sourceHome); seed(join(sourceHome, "store.json"), c.keyA);
  const exported = run(["export", c.archive], sourceHome);
  expect(exported.exitCode).toBe(0); expect(exported.stdout.toString()).toContain("source definitions only");
  expect(run(["import", c.archive], targetHome, { WELLSPRING_KEY: c.keyB.toString("base64") }).exitCode).toBe(0);
  const restored = JSON.parse(readFileSync(join(targetHome, "store.json"), "utf8"));
  expect(decrypt(restored.entries["cred:alpha"].fields.password.value, c.keyB)).toBe("synthetic-secret-alpha");
  writeFileSync(join(targetHome, "daemon.sock"), "synthetic socket sentinel");
  expect(run(["import", c.archive], targetHome).stderr.toString()).toContain("stop wellspringd");
  expect(run(["export", join(c.dir, "blocked")], sourceHome, { WELLSPRING_CLIENT_TOKEN: "synthetic-scoped" }).exitCode).toBe(1);
  expect(run(["export", join(c.dir, "blocked"), "--passphrase", "never-in-argv"], sourceHome).exitCode).toBe(1);
  expect(run(["export", join(c.dir, "blocked")], sourceHome, { WELLSPRING_BACKUP_PASSPHRASE_FILE: undefined, WELLSPRING_PASSPHRASE: PASSWORD }).exitCode).toBe(1);
  expect(existsSync(join(c.dir, "blocked"))).toBe(false);
}));
