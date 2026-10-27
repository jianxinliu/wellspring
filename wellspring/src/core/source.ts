/**
 * External credential sources.
 *
 * A field may point at a value that lives outside the store: an environment
 * variable, a plain file, a `.env` key, or the output of a command. Nothing is
 * copied into the encrypted store; the daemon reads the source at draw time, so
 * rotating the underlying secret needs no Wellspring action at all.
 *
 * Threat model is unchanged: the agent still never sees the value, and it never
 * learns the source path unless the descriptor exposes it (only the *kind* is
 * exposed). Read failures are loud: an unresolvable source makes the draw fail
 * rather than silently deliver an empty string.
 */
import { readFileSync, statSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { isAbsolute, resolve as resolvePath } from "node:path";
import { homedir } from "node:os";

export type SourceKind = "env" | "file" | "dotenv" | "command" | "keychain";
export type Source = { kind: SourceKind; ref: string; field?: string };

/** Same ceiling as a stored value: a source may not deliver an unbounded blob. */
const MAX_VALUE_BYTES = 1024 * 1024;
const MAX_SOURCE_REF = 4096;
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
const KEYCHAIN_SERVICE = /^[^\u0000-\u001f\u007f]{1,512}$/;
const DOTENV_KEY = /^[A-Za-z_][A-Za-z0-9_.-]*$/;

/**
 * Validate a source spec. Accepts the compact string form:
 *   env:NAME  file:/abs/path  dotenv:/abs/path#KEY  command:<shell text>  keychain:<service>
 * and the explicit object form { kind, ref, field }.
 */
export function parseSource(spec: unknown): Source {
  if (typeof spec === "string") {
    const colon = spec.indexOf(":");
    if (colon < 1) throw new Error(`invalid source: expected "<kind>:<target>", got ${preview(spec)}`);
    const kind = spec.slice(0, colon);
    const rest = spec.slice(colon + 1);
    if (kind === "dotenv") {
      const hash = rest.lastIndexOf("#");
      if (hash < 1 || hash === rest.length - 1) throw new Error("invalid source: dotenv needs <path>#<KEY>");
      return validate({ kind: "dotenv", ref: rest.slice(0, hash), field: rest.slice(hash + 1) });
    }
    return validate({ kind: kind as SourceKind, ref: rest });
  }
  if (spec && typeof spec === "object" && !Array.isArray(spec)) {
    const o = spec as Record<string, unknown>;
    const out: Source = { kind: o.kind as SourceKind, ref: String(o.ref ?? "") };
    if (o.field !== undefined) out.field = String(o.field);
    return validate(out);
  }
  throw new Error("invalid source: expected a string or { kind, ref }");
}

function preview(value: string): string {
  // Never echo a whole spec back: it may hold a path or command with secrets in it.
  return JSON.stringify(value.length > 40 ? value.slice(0, 40) + "…" : value);
}

/** Expand a leading ~ so `file:~/x` works without shell help. */
function expandHome(path: string): string {
  if (path === "~") return homedir();
  if (path.startsWith("~/")) return resolvePath(homedir(), path.slice(2));
  return path;
}

function validate(s: Source): Source {
  if (!["env", "file", "dotenv", "command", "keychain"].includes(s.kind)) {
    throw new Error(`invalid source kind: ${JSON.stringify(s.kind)} (expected env, file, dotenv, command or keychain)`);
  }
  if (typeof s.ref !== "string" || !s.ref.length || s.ref.length > MAX_SOURCE_REF || /[\u0000-\u001f\u007f]/u.test(s.ref)) {
    throw new Error("invalid source: target must be a nonempty string without control characters");
  }
  if (s.kind === "env" && !ENV_NAME.test(s.ref)) throw new Error(`invalid source: ${s.ref} is not an environment variable name`);
  if (s.kind === "keychain" && !KEYCHAIN_SERVICE.test(s.ref)) throw new Error("invalid source: keychain needs a service name");
  if (s.kind === "dotenv") {
    if (!s.field || !DOTENV_KEY.test(s.field)) throw new Error("invalid source: dotenv needs a variable name after #");
  }
  if (s.kind === "file" || s.kind === "dotenv") {
    // Relative paths would make the daemon's cwd part of the secret's identity.
    if (!isAbsolute(expandHome(s.ref))) throw new Error("invalid source: file paths must be absolute (a leading ~ is allowed)");
    return { ...s, ref: expandHome(s.ref) };
  }
  return s;
}

/** A human-readable label that is safe to show an agent: never the full path. */
export function sourceLabel(s: Source): string {
  switch (s.kind) {
    case "env": return `env:${s.ref}`;
    case "dotenv": return `dotenv:…${basenameOf(s.ref)}#${s.field}`;
    case "file": return `file:…${basenameOf(s.ref)}`;
    case "keychain": return `keychain:${s.ref}`;
    case "command": return "command";
  }
}

function basenameOf(path: string): string {
  const i = path.lastIndexOf("/");
  return i === -1 ? path : path.slice(i + 1);
}

/**
 * Read the current value behind a source. Called on every draw on purpose:
 * external sources are expected to rotate without Wellspring involvement.
 */
export function readSource(s: Source): string {
  let raw: string;
  switch (s.kind) {
    case "env": {
      const v = process.env[s.ref];
      if (v === undefined) throw new Error(`source empty: environment variable ${s.ref} is not set`);
      raw = v;
      break;
    }
    case "file": {
      // Refuse symlinks that point outside the requested path is overkill for a
      // local-first tool; refusing *dangling* links and directories is not.
      let stat;
      try { stat = statSync(s.ref); }
      catch (e: any) { throw new Error(`source unreadable: ${s.ref} (${e?.code ?? e?.message})`); }
      if (stat.isDirectory()) throw new Error(`source unreadable: ${s.ref} is a directory`);
      raw = readFileSync(s.ref, "utf8");
      // A trailing newline is an editor's habit, not part of the secret.
      raw = trimTrailingNewline(raw);
      break;
    }
    case "dotenv": {
      let text: string;
      try { text = readFileSync(s.ref, "utf8"); }
      catch (e: any) { throw new Error(`source unreadable: ${s.ref} (${e?.code ?? e?.message})`); }
      const found = parseDotenv(text, s.field!);
      if (found === undefined) throw new Error(`source empty: ${s.field} is not set in ${basenameOf(s.ref)}`);
      raw = found;
      break;
    }
    case "keychain": {
      try {
        raw = execFileSync("security", ["find-generic-password", "-s", s.ref, "-w"],
          { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], timeout: 10_000, maxBuffer: MAX_VALUE_BYTES });
      } catch {
        throw new Error(`source unreadable: no keychain item for service ${s.ref}`);
      }
      raw = trimTrailingNewline(raw);
      break;
    }
    case "command": {
      // Runs only after the caller proved it may draw: the policy gate is the
      // authorization for executing a command, not the source kind itself.
      try {
        raw = execFileSync("/bin/sh", ["-c", s.ref],
          { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 30_000, maxBuffer: MAX_VALUE_BYTES });
      } catch (e: any) {
        const why = e?.status !== undefined ? `exit ${e.status}` : (e?.code ?? "failed");
        throw new Error(`source failed: command ${why}`);
      }
      raw = trimTrailingNewline(raw);
      break;
    }
  }
  if (!raw.length) throw new Error(`source empty: ${sourceLabel(s)} produced an empty value`);
  if (Buffer.byteLength(raw, "utf8") > MAX_VALUE_BYTES) throw new Error(`source too large: ${sourceLabel(s)} exceeds 1 MiB`);
  return raw;
}

/**
 * Minimal dotenv reader: KEY=value per line, # comments, optional `export`,
 * single/double quotes, and \n escapes inside double quotes. Deliberately not a
 * general shell parser — a .env file that needs one is a config bug.
 */
export function parseDotenv(text: string, key: string): string | undefined {
  let found: string | undefined;
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq < 1) continue;
    let name = trimmed.slice(0, eq).trim();
    if (name.startsWith("export ")) name = name.slice(7).trim();
    if (name !== key) continue;
    found = unquote(trimmed.slice(eq + 1).trim());
  }
  return found;
}

function trimTrailingNewline(text: string): string {
  return text.replace(/\r?\n$/, "");
}

function unquote(value: string): string {
  if (value.length >= 2 && (value[0] === '"' || value[0] === "'") && value[value.length - 1] === value[0]) {
    const body = value.slice(1, -1);
    return value[0] === '"' ? body.replace(/\\n/g, "\n").replace(/\\t/g, "\t").replace(/\\"/g, '"').replace(/\\\\/g, "\\") : body;
  }
  // Unquoted values end at an inline comment only when preceded by whitespace.
  const m = /^(.*?)\s+#/.exec(value);
  return (m ? m[1] : value).trim();
}

/** True when the target is a readable regular file; used for UI hints only. */
export function looksReadable(path: string): boolean {
  try { return statSync(expandHome(path)).isFile(); } catch { return false; }
}
