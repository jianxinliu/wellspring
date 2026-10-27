#!/usr/bin/env bun
/// Wellspring CLI: put / delete / list / describe / view / resolve / policy / audit / exec / derive / askpass
/// exec = A1 (env) + A2 (fd) channels. Plaintext lives only in this process + child fds.
import { connect } from "node:net";
import { spawn, type ChildProcess } from "node:child_process";
import { join } from "node:path";
import { constants, tmpdir } from "node:os";
import { readFileSync, existsSync, mkdtempSync, writeFileSync, rmSync, statSync } from "node:fs";
import type { Writable } from "node:stream";
import { parseTemplate, renderTemplate, type TemplatePart } from "../core/template.ts";
import { parseExecGuard, checkExecAllowed } from "../policy/exec.ts";
import { sealMasterKey, unsealMasterKey } from "../core/store.ts";
import { obtainPassphrase, readKeychainPassphrase, storeKeychainPassphrase, removeKeychainPassphrase } from "../core/custody.ts";

const WS_HOME = process.env.WELLSPRING_HOME ?? join(process.env.HOME ?? "", ".wellspring");
export const SOCK_PATH = process.env.WELLSPRING_SOCK ?? join(WS_HOME, "wellspringd.sock");
const ADMIN_TOKEN_PATH = join(WS_HOME, "admin.token");

function adminToken(): string | undefined {
  if (process.env.WELLSPRING_ADMIN_TOKEN) return process.env.WELLSPRING_ADMIN_TOKEN;
  if (existsSync(ADMIN_TOKEN_PATH)) return readFileSync(ADMIN_TOKEN_PATH, "utf8").trim();
  return undefined;
}

function rpc(msg: object, signal?: AbortSignal): Promise<any> {
  return new Promise((resolve, reject) => {
    const sock = connect(SOCK_PATH);
    let buf = "";
    let settled = false;
    const finish = (error?: Error, reply?: any) => {
      if (settled) return;
      settled = true;
      signal?.removeEventListener("abort", abort);
      sock.destroy();
      error ? reject(error) : resolve(reply);
    };
    const abort = () => finish(new Error("RPC interrupted"));
    signal?.addEventListener("abort", abort, { once: true });
    if (signal?.aborted) abort();
    sock.on("connect", () => sock.write(JSON.stringify(msg) + "\n"));
    sock.on("data", (c) => {
      buf += c.toString();
      const i = buf.indexOf("\n");
      if (i >= 0) {
        try {
          const reply = JSON.parse(buf.slice(0, i));
          finish(reply.error ? new Error(reply.error) : undefined, reply);
        } catch (error) { finish(error as Error); }
      }
    });
    sock.on("error", (error) => finish(error));
    sock.on("close", () => { if (!settled) finish(new Error("RPC closed without a reply")); });
  });
}

function shellQuote(value: string): string {
  return "'" + value.replaceAll("'", "'\\''") + "'";
}

// Duration -> ms. Accepts a bare number of seconds, or a number with a unit suffix:
// s (秒), m (分钟), h (小时), d (天). Empty/invalid input throws with a usage hint.
export function parseTtlMs(input: string): number {
  const m = /^(\d+)(s|m|h|d)?$/.exec(input.trim());
  if (!m) throw new Error(`invalid --ttl: ${input} (use e.g. 30s, 15m, 12h, 7d, or a bare second count)`);
  const n = Number(m[1]);
  const scale = { s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 }[m[2] ?? "s"] as number;
  return n * scale;
}

async function exec(rest: string[]): Promise<number> {
  const dash = rest.indexOf("--");
  if (dash < 0) throw new Error("usage: exec [--secret NAME=ref] [--secret-fd NAME=ref] [--secret-file NAME=ref] [--template-file NAME=path] [--git-cred ref] -- <cmd...>");
  const childArgs = rest.slice(dash + 1);
  if (!childArgs[0]) throw new Error("no command after --");
  let policyReply;
  try { policyReply = await rpc({ op: "policy_get" }); }
  catch (error) {
    // Older live daemons may not implement policy_get; all other failures refuse exec.
    if (!(error instanceof Error) || error.message !== "unknown op: policy_get") throw new Error("unable to fetch exec policy");
    policyReply = { policy: {} };
  }
  if (!policyReply?.policy || typeof policyReply.policy !== "object" || Array.isArray(policyReply.policy)) throw new Error("invalid exec policy response");
  const decision = checkExecAllowed(parseExecGuard(policyReply.policy.exec), childArgs);
  if (!decision.allowed) throw new Error(decision.reason);

  // Parse the entire plan before drawing secrets or creating files.
  const envRefs: Record<string, string> = Object.create(null);
  const fdRefs: Array<{ name: string; ref: string }> = [];
  const fileRefs: Array<{ name: string; ref: string }> = [];
  const templateFiles: Array<{ name: string; path: string }> = [];
  const names = new Set<string>();
  const envNames = new Set<string>();
  let gitCredRef: string | undefined;
  for (let i = 0; i < dash; i += 2) {
    const flag = rest[i];
    if (!["--secret", "-s", "--secret-fd", "--secret-file", "--template-file", "--git-cred"].includes(flag)) {
      throw new Error(`unknown exec flag: ${flag}`);
    }
    const value = rest[i + 1];
    if (i + 1 >= dash || !value || value.startsWith("-")) throw new Error(`missing value for ${flag}`);
    if (flag === "--git-cred") {
      if (gitCredRef !== undefined) throw new Error("duplicate --git-cred");
      gitCredRef = value;
      continue;
    }
    const equals = value.indexOf("=");
    const name = value.slice(0, equals);
    const ref = value.slice(equals + 1);
    if (equals < 1 || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(name) || !ref || ref.trim() !== ref) {
      throw new Error(`invalid mapping for ${flag}: expected NAME=ref with an identifier name`);
    }
    // Every delivery mapping lands in the child environment; WELLSPRING_ is reserved for our own plumbing.
    if (name.startsWith("WELLSPRING_")) throw new Error(`reserved name for ${flag}: ${name}`);
    const envName = flag === "--secret-fd" ? `WELLSPRING_FD_${name}` : name;
    if (names.has(name) || envNames.has(envName)) throw new Error(`duplicate mapping: ${name}`);
    names.add(name);
    envNames.add(envName);
    if (flag === "--secret-fd") fdRefs.push({ name, ref });
    else if (flag === "--secret-file") fileRefs.push({ name, ref });
    else if (flag === "--template-file") templateFiles.push({ name, path: ref });
    else envRefs[name] = ref;
  }
  if (gitCredRef && ["WELLSPRING_REF", "WELLSPRING_ONESHOT", "GIT_ASKPASS", "SSH_ASKPASS", "SSH_ASKPASS_REQUIRE", "DISPLAY"].some((name) => envNames.has(name))) {
    throw new Error("secret mapping conflicts with askpass environment");
  }

  // Read and validate every template before drawing secrets or creating files:
  // a rejected template must not be able to leave a rendered secret behind.
  const templatePlans: Array<{ name: string; parts: TemplatePart[] }> = [];
  for (const { name, path } of templateFiles) {
    let template: string;
    try {
      const stat = statSync(path);
      if (!stat.isFile()) throw new Error("not a regular file");
      template = readFileSync(path, "utf8");
    } catch (error) {
      throw new Error(`unreadable template file for ${name}: ${error instanceof Error ? error.message : String(error)}`);
    }
    try {
      templatePlans.push({ name, parts: parseTemplate(template) });
    } catch (error) {
      throw new Error(`invalid template file ${path}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  const tempDirs: string[] = [];
  const controller = new AbortController();
  const request = (msg: object) => rpc(msg, controller.signal);
  let child: ChildProcess | undefined;
  let interrupted: NodeJS.Signals | undefined;
  const signalCode = (signal: NodeJS.Signals) => 128 + (constants.signals[signal] ?? 1);
  const forward = (signal: NodeJS.Signals) => {
    interrupted ??= signal;
    controller.abort();
    child?.kill(signal);
  };
  const onInt = () => forward("SIGINT");
  const onTerm = () => forward("SIGTERM");
  const checkInterrupted = () => { if (interrupted) throw new Error(`interrupted by ${interrupted}`); };
  process.on("SIGINT", onInt);
  process.on("SIGTERM", onTerm);
  try {
    const fileEnv: Record<string, string> = Object.create(null);
    for (const { name, ref } of fileRefs) {
      const { value } = await request({ op: "draw", ref, channel: "C1/file", token: adminToken() });
      checkInterrupted();
      const dir = mkdtempSync(join(tmpdir(), "ws-file-"));
      tempDirs.push(dir); // Register before any subsequent operation can throw.
      const path = join(dir, name); // Identifier-only names cannot traverse the directory.
      writeFileSync(path, value, { mode: 0o600 });
      fileEnv[name] = path;
    }
    for (const { name, parts } of templatePlans) {
      const rendered = await renderTemplate(parts, async (ref) => {
        const draw = await request({ op: "draw", ref, channel: "C1/template", token: adminToken() });
        if (typeof draw?.value !== "string") throw new Error(`no value returned for template reference ${ref}`);
        return draw.value;
      });
      checkInterrupted();
      const dir = mkdtempSync(join(tmpdir(), "ws-file-"));
      tempDirs.push(dir); // Register before any subsequent operation can throw.
      const path = join(dir, name); // Identifier-only names cannot traverse the directory.
      writeFileSync(path, rendered.text, { mode: 0o600 });
      fileEnv[name] = path;
    }
    const { env: secretEnv } = Object.keys(envRefs).length
      ? await request({ op: "draw_env", env: envRefs, token: adminToken() })
      : { env: {} };
    checkInterrupted();

    const childEnvExtra: Record<string, string> = {};
    if (gitCredRef) {
      const { token } = await request({ op: "auth_issue_oneshot", ref: gitCredRef, channel: 'git/askpass', token: adminToken() });
      checkInterrupted();
      const dir = mkdtempSync(join(tmpdir(), "ws-askpass-"));
      tempDirs.push(dir);
      const script = join(dir, "askpass.sh");
      // Compiled Bun executables have an embedded argv[1], not an on-disk script.
      const embedded = import.meta.path.startsWith("/$bunfs/") || import.meta.path.includes("/~BUN/");
      const launcher = [process.execPath, ...(embedded ? [] : [process.argv[1]]), "askpass"];
      writeFileSync(script, `#!/bin/sh\nexec ${launcher.map(shellQuote).join(" ")} "$@"\n`, { mode: 0o700 });
      Object.assign(childEnvExtra, {
        WELLSPRING_REF: gitCredRef, WELLSPRING_ONESHOT: token,
        GIT_ASKPASS: script, SSH_ASKPASS: script, SSH_ASKPASS_REQUIRE: "force", DISPLAY: ":0",
      });
    }

    const stdio: Array<"inherit" | "pipe"> = ["inherit", "inherit", "inherit"];
    const fdValues: string[] = [];
    for (const { ref } of fdRefs) {
      const { value } = await request({ op: "draw", ref, channel: "A2/fd", token: adminToken() });
      checkInterrupted();
      fdValues.push(value);
      stdio.push("pipe");
    }
    const inherited = { ...process.env };
    delete inherited.WELLSPRING_ADMIN_TOKEN;
    delete inherited.WELLSPRING_KEY;
    delete inherited.WELLSPRING_PASSPHRASE;
    delete inherited.WELLSPRING_PASSPHRASE_FILE;
    delete inherited.WELLSPRING_ONESHOT;
    const childEnv = { ...inherited, ...secretEnv, ...fileEnv, ...childEnvExtra };
    fdRefs.forEach(({ name }, i) => { childEnv[`WELLSPRING_FD_${name}`] = String(3 + i); });
    checkInterrupted();
    child = spawn(childArgs[0], childArgs.slice(1), { stdio, env: childEnv });
    const runningChild = child;
    return await new Promise<number>((resolve, reject) => {
      let spawnError: Error | undefined;
      runningChild.once("error", (error) => { spawnError = error; });
      // close also follows spawn failure and waits for inherited secret pipes to close.
      runningChild.once("close", (code, signal) => {
        if (interrupted) resolve(signalCode(interrupted));
        else if (spawnError) reject(spawnError);
        else resolve(signal ? signalCode(signal) : (code ?? 1));
      });
      fdValues.forEach((value, i) => {
        const pipe = runningChild.stdio[3 + i] as Writable | null;
        // Children may close an unused secret fd early (EPIPE).
        pipe?.on("error", () => {});
        pipe?.end(value);
      });
    });
  } catch (error) {
    if (interrupted) return signalCode(interrupted);
    throw error;
  } finally {
    process.removeListener("SIGINT", onInt);
    process.removeListener("SIGTERM", onTerm);
    for (const dir of tempDirs) {
      try { rmSync(dir, { recursive: true, force: true }); }
      catch { console.error("failed to remove temporary secret directory"); process.exitCode = 1; }
    }
  }
}

async function main() {
  const [cmd, ...rest] = process.argv.slice(2);
  const flag = (name: string): string | undefined => {
    const i = rest.indexOf(`--${name}`);
    return i >= 0 ? rest[i + 1] : undefined;
  };
  switch (cmd) {
    case "seal":
      if (rest.length) throw new Error("usage: wellspring seal");
      sealMasterKey();
      console.log("Master key sealed (v2).");
      break;
    case "unseal":
      if (rest.length) throw new Error("usage: wellspring unseal");
      unsealMasterKey();
      console.log("Master key unsealed (v1): the raw key is now readable by same-UID processes.");
      break;
    case "keychain": {
      if (rest.length !== 1) throw new Error("usage: wellspring keychain store|remove|status");
      switch (rest[0]) {
        case "store":
          storeKeychainPassphrase(obtainPassphrase(true));
          console.log("Master passphrase stored in macOS keychain.");
          break;
        case "remove":
          removeKeychainPassphrase();
          console.log("Master passphrase removed from macOS keychain.");
          break;
        case "status": {
          const { available, present } = readKeychainPassphrase();
          console.log(!available ? "keychain unavailable (requires macOS security)" : present ? "keychain passphrase present and usable" : "keychain passphrase absent or not usable; unlock the login keychain or run wellspring keychain store");
          break;
        }
        default: throw new Error("usage: wellspring keychain store|remove|status");
      }
      break;
    }
    case "--help":
    case "help":
      console.log("usage: wellspring <put|adopt|delete|list|describe|view|resolve|policy|audit|exec|derive|askpass|seal|unseal|keychain> ...\n  put ... --from <src>  Reference an external source instead of storing a copy\n  adopt      Copy an external source value into the vault\n  seal       Wrap the file master key with a passphrase (v2)\n  unseal     Restore same-UID-readable raw master key (v1)\n  keychain store|remove|status  Manage the macOS master passphrase");
      break;
    case "put": {
      const ttlRaw = flag("ttl");
      if (rest.includes("--ttl") && (!ttlRaw || ttlRaw.startsWith("--"))) throw new Error("--ttl requires a duration (e.g. 30s, 15m, 12h, 7d)");
      const from = flag("from");
      if (from !== undefined) {
        // Reference mode: the value stays where it already lives. `put id field
        // --from env:NAME` needs no third argument, so the secret is never typed
        // into a shell (where it would land in history).
        // `rest` still carries the flag pair, so count only positional words.
        const positional = rest.filter((w, i) => !w.startsWith("--") && !(i > 0 && rest[i - 1].startsWith("--")));
        const [refId, refField] = positional;
        if (!refId || !refField || positional.length > 2) {
          throw new Error("usage: put <id> <field> --from env:NAME | dotenv:/abs/path#KEY | file:/abs/path | keychain:SERVICE | command:...");
        }
        const r = await rpc({ op: "put_source", id: refId, field: refField, source: from, cls: flag("cls"), mask: flag("mask"), tags: flag("tag") ? [flag("tag")!] : undefined, ttlMs: ttlRaw ? parseTtlMs(ttlRaw) : undefined, token: adminToken() });
        console.log(JSON.stringify(r));
        break;
      }
      const [id, field, value] = rest;
      if (!id || !field || value === undefined) throw new Error("usage: put <id> <field> <value> [--cls] [--mask] [--tag] [--ttl 30s|15m|12h|7d]\n       put <id> <field> --from env:NAME|dotenv:/abs/path#KEY|file:/abs/path|keychain:SERVICE|command:...");
      const r = await rpc({ op: "put", id, field, value, cls: flag("cls"), mask: flag("mask"), tags: flag("tag") ? [flag("tag")!] : undefined, ttlMs: ttlRaw ? parseTtlMs(ttlRaw) : undefined, token: adminToken() });
      console.log(JSON.stringify(r));
      break;
    }
    // Copy an external source's current value into the encrypted store, so the
    // reference stops following the host (useful when the host will lose it).
    case "adopt": {
      const [id, field] = rest;
      if (!id || !field || rest.length > 2) throw new Error("usage: adopt <id> <field>");
      const r = await rpc({ op: "adopt", id, field, token: adminToken() });
      console.log(JSON.stringify(r));
      break;
    }
    case "delete": {
      const [id, field] = rest;
      if (!id || rest.length > 2 || rest.some((value) => value.startsWith("-"))) {
        throw new Error("usage: delete <id> [field]");
      }
      const token = adminToken();
      if (!token) throw new Error("delete requires admin authentication");
      const r = await rpc({ op: "delete", id, field, token });
      console.log(JSON.stringify(r));
      break;
    }
    case "list": {
      const r = await rpc({ op: "list" });
      console.log(JSON.stringify(r.descriptors, null, 2));
      break;
    }
    case "describe": {
      const r = await rpc({ op: "describe", id: rest[0] });
      console.log(JSON.stringify(r, null, 2));
      break;
    }
    case "view": {
      const r = await rpc({ op: "view", id: rest[0] });
      console.log(JSON.stringify(r.maskedPreview, null, 2));
      break;
    }
    case "resolve": {
      const [id, field] = rest[0]?.split("/") ?? [];
      const r = await rpc({ op: "resolve", id, field: field ?? "value", reason: flag("reason"), token: adminToken() });
      console.log(JSON.stringify(r));
      break;
    }
    case "policy": {
      if (flag("set")) {
        const r = await rpc({ op: "policy_put", policy: JSON.parse(flag("set")!), token: adminToken() });
        console.log(JSON.stringify(r));
      } else {
        const r = await rpc({ op: "policy_get" });
        console.log(JSON.stringify(r.policy, null, 2));
      }
      break;
    }
    case "audit": {
      const r = await rpc({ op: "audit" });
      for (const line of r.events) console.log(line);
      break;
    }
    case "exec": {
      const code = await exec(rest);
      process.exitCode = process.exitCode || code;
      break;
    }
    case "derive": {
      // Human-facing counterpart of the MCP derive tool: the key stays in the daemon.
      const [op, refOrId, field] = rest;
      if (!op || !refOrId) throw new Error("usage: derive <totp|hmac|encrypt|decrypt> <ref|id> [field]");
      if (!["totp", "hmac", "encrypt", "decrypt"].includes(op)) throw new Error(`unknown derive op: ${op}`);
      // A bare id defaults to the "value" field, matching every other CLI subcommand.
      const ref = refOrId.includes("/") ? refOrId : `${refOrId}/${field ?? "value"}`;
      const msg: Record<string, unknown> = { op: `derive_${op}`, ref, token: adminToken() };
      if (op === "hmac") {
        msg.data = (await new Promise<string>((resolve, reject) => {
          // HMAC needs the exact bytes to sign; a shell-mangled newline changes the MAC.
          let text = "";
          process.stdin.setEncoding("utf8");
          process.stdin.on("data", (c) => { text += c; });
          process.stdin.on("end", () => resolve(text.replace(/\r?\n$/, "")));
          process.stdin.on("error", reject);
        }));
        msg.alg = flag("alg");
      } else if (op === "encrypt" || op === "decrypt") {
        const key = op === "encrypt" ? "plaintext" : "blob";
        if (flag(key) !== undefined) {
          msg[key] = flag(key);
        } else {
          msg[key] = (await new Promise<string>((resolve, reject) => {
            let text = "";
            process.stdin.setEncoding("utf8");
            process.stdin.on("data", (c) => { text += c; });
            process.stdin.on("end", () => resolve(text.replace(/\r?\n$/, "")));
            process.stdin.on("error", reject);
          }));
        }
      }
      const r = await rpc(msg);
      console.log(op === "encrypt" || op === "decrypt" ? String(r.blob ?? r.plaintext) : JSON.stringify(r));
      break;
    }
    case "askpass": {
      // Called by git/ssh via GIT_ASKPASS/SSH_ASKPASS script. Env: WELLSPRING_REF, WELLSPRING_ONESHOT.
      const ref = process.env.WELLSPRING_REF;
      const token = process.env.WELLSPRING_ONESHOT;
      if (!ref || !token) process.exit(1);
      const channel = 'git/askpass'; // The shared git/ssh helper uses the capability's fixed channel.
      const { value } = await rpc({ op: "draw", ref, channel, token });
      process.stdout.write(value);
      process.exit(0);
    }
    default:
      console.error("usage: wellspring <put|adopt|delete|list|describe|view|resolve|policy|audit|exec|derive|askpass|seal|unseal|keychain> ... (see --help)");
      process.exit(2);
  }
}

main().catch((e) => {
  console.error(String(e?.message ?? e));
  process.exit(1);
});
