/// Wellspring daemon (wellspringd): unix-socket JSON-RPC, sole owner of the store.
/// Protocol: newline-delimited JSON {op, ...} -> {ok, ...} | {ok:false, error}
/// AUTH: sensitive ops (draw_env, draw_fd, resolve) require a draw token.
///   MCP server gets an admin token via WELLSPRING_ADMIN_TOKEN at spawn time
///   (trusted host = whoever spawned us). One-shot exec tokens are issued by
///   `wellspring exec` via the CLI's admin token, and burn on first use.
import { createServer, connect, Socket } from "node:net";
import { join } from "node:path";
import { homedir } from "node:os";
import { appendFileSync, readFileSync, existsSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { listDescriptors, describe, getSecret, getSecretFresh, putSecret, deleteSecret, mask, fingerprint, isExpiryError } from "../core/store.ts";

export const WS_HOME = process.env.WELLSPRING_HOME ?? join(homedir(), ".wellspring");
export const SOCK_PATH = process.env.WELLSPRING_SOCK ?? join(WS_HOME, "wellspringd.sock");
export const POLICY_PATH = join(WS_HOME, "policy.json");
const AUDIT_PATH = join(WS_HOME, "draw-events.jsonl");

// ---------- policy (configurable reason allowlist) ----------
type Policy = { resolveReasons: string[]; resolveRatePerMin: number };
function validatePolicy(input: unknown): Policy {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("invalid policy");
  const { resolveReasons, resolveRatePerMin } = input as Policy;
  if (!Array.isArray(resolveReasons) || resolveReasons.length === 0 || resolveReasons.length > 100 ||
    Array.from(resolveReasons).some((reason) => typeof reason !== "string" || !reason.trim() || reason.length > 256 || /[\u0000-\u001f\u007f]/u.test(reason))) {
    throw new Error("invalid resolveReasons: expected 1..100 nonempty strings of at most 256 characters");
  }
  if (!Number.isInteger(resolveRatePerMin) || resolveRatePerMin < 1 || resolveRatePerMin > 10000) {
    throw new Error("invalid resolveRatePerMin: expected an integer from 1 to 10000");
  }
  return { resolveReasons: [...resolveReasons], resolveRatePerMin };
}
function loadPolicy(): Policy {
  if (existsSync(POLICY_PATH)) {
    try { return { resolveReasons: [], resolveRatePerMin: 10, ...JSON.parse(readFileSync(POLICY_PATH, "utf8")) }; } catch {}
  }
  return { resolveReasons: ["shipping_label", "shipping", "demo", "test", "contact_customer"], resolveRatePerMin: 10 };
}

// ---------- auth tokens ----------
// Admin token: created by daemon if absent, readable only by same user (0600).
// The MCP server / CLI read it at spawn time from the host user's keyfile.
const ADMIN_TOKEN_PATH = join(WS_HOME, "admin.token");
function ensureAdminToken(): string {
  if (process.env.WELLSPRING_ADMIN_TOKEN) return process.env.WELLSPRING_ADMIN_TOKEN;
  if (existsSync(ADMIN_TOKEN_PATH)) return readFileSync(ADMIN_TOKEN_PATH, "utf8").trim();
  const tok = randomBytes(32).toString("base64url");
  mkdirSync(WS_HOME, { recursive: true });
  writeFileSync(ADMIN_TOKEN_PATH, tok, { mode: 0o600 });
  return tok;
}
const ADMIN_TOKEN = ensureAdminToken();

// One-shot tokens: issued for exec, burned after a single use, expire in 60s.
type Grant = { expires: number; ref: string; channel: string };
const oneShot = new Map<string, Grant>();
function issueOneShot(ref: unknown, channel: unknown): string {
  if (typeof ref !== 'string' || !/^(?:secret:\/\/)?[^/\s]+(?:\/[^/\s]+)?$/.test(ref)) throw new Error('one-shot requires a single secret ref');
  if (typeof channel !== 'string' || !['git/askpass','ssh/askpass','A2/fd'].includes(channel)) throw new Error('invalid one-shot channel');
  const [id, field] = parseRef(ref);
  getSecret(id, field); // Validate existence before granting.
  const now = Date.now();
  for (const [token, grant] of oneShot) if (grant.expires <= now) oneShot.delete(token);
  if (oneShot.size >= 10000) throw new Error('too many active grants');
  const tok = 'os_' + randomBytes(24).toString('base64url');
  oneShot.set(tok, {expires: now + 60_000, ref: `${id}/${field}`, channel});
  return tok;
}
function burnToken(msg: any): "admin" | "oneshot" | null {
  const t = String(msg.token ?? "");
  const eq = (a: string, b: string) => { const aa=Buffer.from(a), bb=Buffer.from(b); return aa.length === bb.length && timingSafeEqual(aa,bb); };
  if (eq(t, ADMIN_TOKEN)) return "admin";
  const grant = oneShot.get(t);
  if (grant) {
    oneShot.delete(t); // Every attempted use consumes the capability, including scope violations.
    const [id, field] = parseRef(msg.ref ?? '');
    if (grant.expires > Date.now() && msg.op === 'draw' && `${id}/${field}` === grant.ref && msg.channel === grant.channel) return 'oneshot';
  }
  return null;
}

// simple in-memory rate limit for resolve
const resolveHits = new Map<string, number[]>();
function rateLimited(id: string): boolean {
  const now = Date.now();
  const arr = (resolveHits.get(id) ?? []).filter((t) => now - t < 60_000);
  arr.push(now);
  resolveHits.set(id, arr);
  return arr.length > loadPolicy().resolveRatePerMin;
}

type DrawEvent = {
  ts: number;
  op: string;
  entry: string;
  field: string;
  channel: string;
  reason?: string;
  verdict: "ok" | "denied_rate" | "denied_reason" | "denied_auth" | "expired" | "error";
};

function logDraw(e: DrawEvent) {
  mkdirSync(WS_HOME, { recursive: true });
  appendFileSync(AUDIT_PATH, JSON.stringify(e) + "\n");
}

/**
 * Shared read for every draw path. A refused draw yields NO plaintext to the
 * caller: the expiry check runs before decryption and we return {error} only.
 * Other failures (unknown ref) propagate for the existing error handling.
 */
function drawFresh(base: Omit<DrawEvent, "verdict" | "ts">): { value: string } | { error: string } {
  try {
    return { value: getSecretFresh(base.entry, base.field) };
  } catch (error) {
    if (!isExpiryError(error)) throw error;
    logDraw({ ...base, ts: Date.now(), verdict: "expired" });
    return { error: `secret expired: ${base.entry}/${base.field}` };
  }
}

function parseRef(ref: string): [string, string] {
  const [id, field = "value"] = String(ref).replace(/^secret:\/\//, "").split("/");
  return [id, field];
}

export function handle(msg: any): any {
  switch (msg.op) {
    case "ping":
      return { pong: true, version: "0.1.0" };
    case "auth_check":
      return burnToken(msg) === "admin" ? { ok: true } : { error: "unauthorized" };
    case "auth_issue_oneshot": {
      // admin-only: used by CLI/MCP before spawning a child that needs draw access
      if (burnToken(msg) !== "admin") return { error: "unauthorized" };
      return { token: issueOneShot(msg.ref, msg.channel) };
    }
    case "list":
      return { descriptors: listDescriptors({ tag: msg.tag }) };
    case "describe":
      return describe(msg.id);
    case "policy_get":
      return { policy: loadPolicy() };
    case "policy_put": {
      if (burnToken(msg) !== "admin") return { error: "unauthorized" };
      const policy = validatePolicy(msg.policy);
      mkdirSync(WS_HOME, { recursive: true });
      writeFileSync(POLICY_PATH, JSON.stringify(policy, null, 2), { mode: 0o600 });
      return { ok: true };
    }
    case "put": {
      if (burnToken(msg) !== "admin") return { error: "unauthorized" };
      // Rotation replaces the value without reading it, including when it has expired.
      putSecret(msg.id, msg.field, msg.value, { cls: msg.cls, mask: msg.mask, tags: msg.tags, ttlMs: msg.ttlMs, expiresAt: msg.expiresAt });
      logDraw({ ts: Date.now(), op: "put", entry: msg.id, field: msg.field, channel: "admin", verdict: "ok" });
      return { ok: true };
    }
    case "delete": {
      // Do not copy arbitrary input objects or secret values into the audit log.
      const event = { ts: Date.now(), op: "delete", entry: typeof msg.id === "string" ? msg.id : "<invalid>",
        field: msg.field === undefined ? "*" : typeof msg.field === "string" ? msg.field : "<invalid>", channel: "admin" };
      if (burnToken(msg) !== "admin") {
        logDraw({ ...event, verdict: "denied_auth" });
        return { error: "unauthorized" };
      }
      try {
        deleteSecret(msg.id, msg.field);
      } catch (error) {
        logDraw({ ...event, verdict: "error" });
        throw error;
      }
      logDraw({ ...event, verdict: "ok" });
      return { ok: true };
    }
    case "view": {
      const d = describe(msg.id);
      return { maskedPreview: d.maskedPreview };
    }
    case "resolve": {
      const policy = loadPolicy();
      if (burnToken(msg) !== "admin") {
        logDraw({ ts: Date.now(), op: "resolve", entry: msg.id, field: msg.field, channel: "resolve", reason: msg.reason, verdict: "denied_auth" });
        return { error: "unauthorized" };
      }
      if (!msg.reason || !policy.resolveReasons.includes(msg.reason)) {
        logDraw({ ts: Date.now(), op: "resolve", entry: msg.id, field: msg.field, channel: "resolve", reason: msg.reason, verdict: "denied_reason" });
        return { error: "reason not allowlisted" };
      }
      if (rateLimited(`${msg.id}/${msg.field}`)) {
        logDraw({ ts: Date.now(), op: "resolve", entry: msg.id, field: msg.field, channel: "resolve", reason: msg.reason, verdict: "denied_rate" });
        return { error: "rate limited" };
      }
      // Expiry is checked last so an unauthenticated caller learns nothing new.
      const drawn = drawFresh({ op: "resolve", entry: msg.id, field: msg.field, channel: "resolve", reason: msg.reason });
      if ("error" in drawn) return drawn;
      logDraw({ ts: Date.now(), op: "resolve", entry: msg.id, field: msg.field, channel: "resolve", reason: msg.reason, verdict: "ok" });
      return { value: drawn.value };
    }
    case "draw_env": {
      // A1 channel: requires admin OR one-shot token.
      const role = burnToken(msg);
      if (!role) {
        logDraw({ ts: Date.now(), op: "draw_env", entry: "*", field: "*", channel: "A1/exec", verdict: "denied_auth" });
        return { error: "unauthorized" };
      }
      // Fail closed: draw every ref first, so an expiry never ships a partial env.
      const env: Record<string, string> = {};
      const failures: string[] = [];
      for (const [varName, ref] of Object.entries(msg.env ?? {})) {
        const [id, field] = parseRef(ref as string);
        const drawn = drawFresh({ op: "draw_env", entry: id, field, channel: "A1/exec" });
        if ("error" in drawn) { failures.push(drawn.error); continue; }
        env[varName] = drawn.value;
        logDraw({ ts: Date.now(), op: "draw_env", entry: id, field, channel: "A1/exec", verdict: "ok" });
      }
      if (failures.length) return { error: failures[0] };
      return { env };
    }
    case "draw": {
      // A2 channel: single value by ref; used by fd pipe / GIT_ASKPASS helper.
      const role = burnToken(msg);
      if (!role) {
        logDraw({ ts: Date.now(), op: "draw", entry: msg.ref, field: "*", channel: msg.channel ?? "A2/fd", verdict: "denied_auth" });
        return { error: "unauthorized" };
      }
      const [id, field] = parseRef(msg.ref);
      const drawn = drawFresh({ op: "draw", entry: id, field, channel: msg.channel ?? "A2/fd" });
      if ("error" in drawn) return drawn;
      logDraw({ ts: Date.now(), op: "draw", entry: id, field, channel: msg.channel ?? "A2/fd", verdict: "ok" });
      return { value: drawn.value };
    }
    case "audit":
      return { events: existsSync(AUDIT_PATH) ? readFileSync(AUDIT_PATH, "utf8").trim().split("\n") : [] };
    default:
      return { error: `unknown op: ${msg.op}` };
  }
}

// A killed or crashed daemon leaves its socket file behind. The file still looks
// present but every connect fails with ENOENT, so the MCP server reports a
// confusing "ENOENT" instead of "the daemon is not running". Probe first.
function probeLive(path: string): Promise<boolean> {
  return new Promise((resolve) => {
    const sock = connect(path);
    const done = (live: boolean) => { sock.destroy(); resolve(live); };
    sock.once("connect", () => done(true));
    sock.once("error", () => done(false));
  });
}

async function ensureSocketFree(path: string) {
  if (!(await probeLive(path))) {
    try { rmSync(path); } catch (e: any) { if (e?.code !== "ENOENT") throw e; }
    return;
  }
  throw new Error(`another wellspringd is already listening on ${path} — stop it first, or start this one with a different WELLSPRING_SOCK`);
}

if (import.meta.main) {
  const server = createServer((sock: Socket) => {
    let buf = "";
    sock.on("data", (chunk) => {
      buf += chunk.toString("utf8");
      let idx: number;
      while ((idx = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, idx).trim();
        buf = buf.slice(idx + 1);
        if (!line) continue;
        let reply: any;
        try {
          reply = handle(JSON.parse(line));
        } catch (e: any) {
          reply = { error: String(e?.message ?? e) };
        }
        sock.write(JSON.stringify(reply) + "\n");
      }
    });
  });
  server.on("error", (error: NodeJS.ErrnoException) => {
    if (error.code === "EADDRINUSE") return;
    console.error(`wellspringd failed to listen on ${SOCK_PATH}: ${error.message}`);
  });
  // The Web UI is a convenience; the credential socket is the product.
  ensureSocketFree(SOCK_PATH).then(() => { server.listen(SOCK_PATH, () => console.log(`wellspringd listening on ${SOCK_PATH}`)); })
    .catch((error) => { console.error(String(error?.message ?? error)); process.exit(1); });
  // Web UI + HTTP API on loopback (human-facing admin console)
  import("./web.ts").then((m) => m.startHttp()).catch((e) => console.error("web ui failed:", e?.message));
}
