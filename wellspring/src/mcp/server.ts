#!/usr/bin/env bun
/// Wellspring MCP server (stdio). Descriptors, credential delivery and derived results.
/// Tools: wellspring_list, wellspring_describe, wellspring_exec, wellspring_derive.
/// Uses minimal MCP stdio JSON-RPC (initialize / tools/list / tools/call) — Phase 0
/// avoids the SDK dependency to keep the compiled binary dependency-free.
import { spawn } from "node:child_process";
import { StringDecoder } from "node:string_decoder";
import { connect } from "node:net";
import { join } from "node:path";
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from 'node:os';
import type { Writable } from 'node:stream';
import { parseTemplate, renderTemplate } from '../core/template.ts';
import { parseExecGuard, checkExecAllowed } from '../policy/exec.ts';

const WS_HOME = process.env.WELLSPRING_HOME ?? join(process.env.HOME ?? "", ".wellspring");
const SOCK_PATH = process.env.WELLSPRING_SOCK ?? join(WS_HOME, "wellspringd.sock");
const ADMIN_TOKEN_PATH = join(WS_HOME, "admin.token");

function adminToken(): string | undefined {
  if (process.env.WELLSPRING_ADMIN_TOKEN) return process.env.WELLSPRING_ADMIN_TOKEN;
  try { return readFileSync(ADMIN_TOKEN_PATH, "utf8").trim(); } catch { return undefined; }
}

function clientToken(): string | undefined {
  return process.env.WELLSPRING_CLIENT_TOKEN || adminToken();
}

function rpc(msg: object, signal?: AbortSignal, timeoutMs = 10000): Promise<any> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(new Error('request cancelled'));
    const sock = connect(SOCK_PATH);
    let buf = "";
    let settled = false;
    const finish = (error?: unknown, reply?: any) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      sock.destroy();
      error ? reject(error) : resolve(reply);
    };
    const abort = () => finish(new Error('request cancelled'));
    const timer = setTimeout(() => finish(new Error('daemon request timed out')), timeoutMs);
    signal?.addEventListener('abort', abort, { once: true });
    sock.once('close', () => finish(new Error('daemon connection closed')));
    sock.on("connect", () => sock.write(JSON.stringify(msg) + "\n"));
    sock.on("data", (c) => {
      buf += c.toString();
      const i = buf.indexOf("\n");
      if (i >= 0) {
        let reply: any;
        try { reply = JSON.parse(buf.slice(0, i)); } catch (e) { return finish(e); }
        if (!reply || typeof reply !== 'object' || Array.isArray(reply)) return finish(new Error('invalid daemon response'));
        finish(reply.error ? new Error(reply.error) : undefined, reply);
      }
    });
    sock.on("error", error => finish(error));
  });
}

function pause(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(new Error('request cancelled'));
    const finish = () => { signal?.removeEventListener('abort', abort); resolve(); };
    const timer = setTimeout(finish, ms);
    const abort = () => { clearTimeout(timer); signal?.removeEventListener('abort', abort); reject(new Error('request cancelled')); };
    signal?.addEventListener('abort', abort, { once: true });
  });
}

const TOOLS = [
  {
    name: "wellspring_request",
    description: "Request a credential from the user through Wellspring's separate Web form. Returns a request ID and expiry; use wellspring_request_status to obtain its ref after the user fills it. Never put a secret value in this tool.",
    inputSchema: { type: "object", additionalProperties: false, properties: {
      label: { type: "string", maxLength: 256, description: "What credential is needed, e.g. GitHub release token" },
      purpose: { type: "string", maxLength: 512, description: "Task purpose; reuse this exact value when delivering the fulfilled ref" },
      target: { type: "string", maxLength: 512, description: "Intended destination; an intent claim, not verified network isolation" },
      channel: { type: "string", enum: ["A1/exec", "A2/fd", "C1/file", "C1/template", "git/askpass", "ssh/askpass", "derive_totp", "derive_hmac", "derive_encrypt", "derive_decrypt"] },
      ttlMs: { type: "integer", minimum: 1000, maximum: 86400000, description: "Request expiry, default 15 minutes; temporary credentials expire with the request" },
    }, required: ["label", "purpose", "channel"] },
  },
  {
    name: "wellspring_request_status",
    description: "Check, wait for, or cancel your credential request. Fulfilled returns a ref, never its value. A bounded wait keeps this call pending; timeout returns pending with waitTimedOut, without resuming finished calls or host turns.",
    inputSchema: { type: "object", additionalProperties: false, properties: {
      requestId: { type: "string" },
      cancel: { type: "boolean", description: "Default false; true cancels the credential request immediately, ignoring waitMs" },
      waitMs: { type: "integer", minimum: 0, maximum: 55000, description: "Maximum wait in milliseconds, default 0; use a positive bound while the user fills the form" },
    }, required: ["requestId"] },
  },
  {
    name: "wellspring_list",
    description: "List all sensitive-info descriptors this agent may use. Returns refs (secret://...), field fingerprints, where a field is backed by an external source (source, e.g. env:NAME — a label only, never a value), expiry (expiresAt/expired) and available recipes. NEVER returns plaintext.",
    inputSchema: { type: "object", properties: { tag: { type: "string" } } },
  },
  {
    name: "wellspring_describe",
    description: "Describe one entry: fields with sha256 fingerprints (first 16 hex), masked previews for PII, external source labels, expiry (expiresAt/expired), recipes. No plaintext. Fields backed by an external source show a placeholder preview because reading one would be a draw.",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string", description: "e.g. cred:db_prod or person:zhang_san" } },
      required: ["id"],
    },
  },
  {
    name: "wellspring_exec",
    description:
      "Run a trusted program with referenced secrets through environment variables, read-once file descriptors or temporary files. Returns exit status; output is suppressed by default. Optional redacted output masks exact injected values, not transformed data. Programs can read their injected secrets; use only trusted programs.",
    inputSchema: {
      type: "object",
      properties: {
        purpose: { type: "string", description: "Declared task purpose; must match the credential's use policy when restricted" },
        target: { type: "string", description: "Declared intended destination; must match policy, does not enforce network routing" },
        env: { type: "object", additionalProperties: { type: "string" }, description: "ENV_VAR -> secret://id/field mapping" },
        fd: { type: 'object', additionalProperties: {type:'string'}, description: 'NAME -> ref; child reads descriptor number from WELLSPRING_FD_NAME' },
        files: { type: 'object', additionalProperties: {type:'string'}, description: 'ENV_VAR -> ref; child receives a temporary 0600 file path, removed after exit' },
        templates: { type: 'object', additionalProperties: {type:'string'}, description: 'ENV_VAR -> template text, delivered as temporary file path. Placeholders: {{secret://id/field | raw}}, json (quoted JSON string), or uri (URL component). Default raw; no code evaluation.' },
        command: { type: "array", minItems: 1, items: { type: "string" }, description: "Program and arguments; no shell expansion" },
        output: { type: "string", enum: ["none", "redacted"], description: "Default none; redacted returns bounded stdout/stderr with exact injected values masked" },
        timeoutMs: { type: "integer", minimum: 100, maximum: 300000, description: "Execution timeout, default 30000 milliseconds" },
      },
      required: ["command"],
    },
  },
  {
    name: "wellspring_derive",
    description:
      "Compute a TOTP code, HMAC signature, or AES-256-GCM encryption/decryption without exporting the key. Results enter agent context and may be sensitive; decrypt returns plaintext. Use only when disclosure of that result is authorized.",
    inputSchema: {
      type: "object",
      properties: {
        op: {
          type: "string",
          enum: ["totp", "hmac", "encrypt", "decrypt"],
          description: "totp = 2FA code; hmac = sign a string; encrypt/decrypt = AES-256-GCM ",
        },
        purpose: { type: "string", description: "Declared task purpose required by the credential's use policy" },
        target: { type: "string", description: "Declared intended destination required by the use policy" },
        ref: { type: "string", description: "secret://id/field holding the key. totp wants a base32 seed; hmac wants the raw secret; aes wants a base64 32-byte key" },
        data: { type: "string", description: "hmac only: the exact string to sign, at most 1 MiB" },
        plaintext: { type: "string", description: "encrypt only: the text to encrypt, at most 1 MiB" },
        blob: { type: "string", description: "decrypt only: base64 nonce|ciphertext|tag as produced by encrypt" },
        alg: { type: "string", enum: ["sha256", "sha512"], description: "hmac only, default sha256" },
        digits: { type: "integer", minimum: 6, maximum: 8, description: "totp only, default 6" },
        period: { type: "integer", minimum: 1, maximum: 300, description: "totp only, default 30 seconds" },
      },
      required: ["op", "ref"],
    },
  },
];

async function callTool(name: string, args: any, signal?: AbortSignal): Promise<string> {
  switch (name) {
    case "wellspring_request": {
      if (!args || typeof args !== 'object' || Array.isArray(args) || Object.keys(args).some(k => !['label','purpose','target','channel','ttlMs'].includes(k))) throw new Error('invalid request arguments; enter values only in the separate Web form');
      return JSON.stringify(await rpc({ ...args, op: 'request_create', token: clientToken() }));
    }
    case "wellspring_request_status": {
      if (!args || Array.isArray(args) || typeof args.requestId !== 'string' || Object.keys(args).some(k => !['requestId','cancel','waitMs'].includes(k)) || (args.cancel !== undefined && typeof args.cancel !== 'boolean')) throw new Error('invalid request status arguments');
      const waitMs = args.waitMs === undefined ? 0 : args.waitMs;
      if (!Number.isInteger(waitMs) || waitMs < 0 || waitMs > 55000) throw new Error('waitMs must be 0..55000');
      const message = { op: args.cancel ? 'request_cancel' : 'request_status', requestId: args.requestId, token: clientToken() };
      if (args.cancel || waitMs === 0) return JSON.stringify(await rpc(message, signal));
      const deadline = performance.now() + waitMs;
      let status: any;
      while (true) {
        const remaining = deadline - performance.now();
        if (remaining <= 0 && status) return JSON.stringify({ ...status, waitTimedOut: true });
        try { status = await rpc(message, signal, Math.max(1, Math.min(10000, remaining))); }
        catch (error) {
          if (status && !signal?.aborted && error instanceof Error && error.message === 'daemon request timed out' && performance.now() >= deadline) return JSON.stringify({ ...status, waitTimedOut: true });
          throw error;
        }
        if (status.status !== 'pending') return JSON.stringify(status);
        const delay = Math.min(300, deadline - performance.now());
        if (delay <= 0) return JSON.stringify({ ...status, waitTimedOut: true });
        await pause(delay, signal);
      }
    }
    case "wellspring_list": {
      const r = await rpc({ op: "list", tag: args?.tag, token: clientToken() });
      return JSON.stringify(r.descriptors, null, 2);
    }
    case "wellspring_describe": {
      const r = await rpc({ op: "describe", id: args.id, token: clientToken() });
      return JSON.stringify(r, null, 2);
    }
    case "wellspring_exec": {
      const { env = {}, fd = {}, files = {}, templates = {}, command, output = 'none', timeoutMs = 30000 } = args;
      const names = new Set<string>();
      for (const mapping of [env,fd,files,templates]) {
        if (!mapping || typeof mapping !== 'object' || Array.isArray(mapping)) throw new Error('delivery mappings must be objects');
        for (const [name,ref] of Object.entries(mapping)) {
          if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name) || name.startsWith('WELLSPRING_') || typeof ref !== 'string' || !ref || names.has(name)) throw new Error('invalid, reserved or duplicate delivery name');
          names.add(name);
        }
      }
      if (!Array.isArray(command) || !command.length || command.some(v => typeof v !== 'string' || v.includes('\0')) || !command[0]) throw new Error('command must be non-empty string argv array');
      if (!env || typeof env !== 'object' || Array.isArray(env) || Object.entries(env).some(([k,v]) => !/^[A-Za-z_][A-Za-z0-9_]*$/.test(k) || k.startsWith('WELLSPRING_') || typeof v !== 'string' || !v)) throw new Error('env must map variable names to secret refs; WELLSPRING_ names are reserved');
      if (!['none','redacted'].includes(output)) throw new Error('invalid output mode');
      if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 300000) throw new Error('timeoutMs must be 100..300000');
      let policyReply;
      try { policyReply = await rpc({ op: 'policy_get' }); }
      catch (error) {
        // Older live daemons may not implement policy_get; all other failures refuse exec.
        if (!(error instanceof Error) || error.message !== 'unknown op: policy_get') throw new Error('unable to fetch exec policy');
        policyReply = { policy: {} };
      }
      if (!policyReply?.policy || typeof policyReply.policy !== 'object' || Array.isArray(policyReply.policy)) throw new Error('invalid exec policy response');
      const decision = checkExecAllowed(parseExecGuard(policyReply.policy.exec), command);
      if (!decision.allowed) throw new Error(decision.reason);
      const context = { purpose: args.purpose, target: args.target };
      for (const value of Object.values(context)) if (value !== undefined && (typeof value !== 'string' || !value.trim() || value.length > 512)) throw new Error('purpose and target must be nonempty strings of at most 512 characters');
      const templatePlans = Object.entries(templates).map(([name,text])=>({name,parts:parseTemplate(text as string)}));
      const tempDirs: string[] = [];
      try {
      const { env: secretEnv } = await rpc({ op: 'draw_env', env, token: clientToken(), ...context });
      const values = Object.values(secretEnv) as string[];
      const fdValues: string[] = [];
      const childEnv = { ...process.env, ...secretEnv };
      for (const [name,ref] of Object.entries(fd)) {
        const {value} = await rpc({op:'draw',ref,channel:'A2/fd',token:clientToken(),...context});
        values.push(value); fdValues.push(value);
        childEnv[`WELLSPRING_FD_${name}`] = String(2+fdValues.length);
      }
      for (const [name,ref] of Object.entries(files)) {
        const {value} = await rpc({op:'draw',ref,channel:'C1/file',token:clientToken(),...context});
        values.push(value);
        const dir=mkdtempSync(join(tmpdir(),'ws-mcp-file-')); tempDirs.push(dir);
        const path=join(dir,name); writeFileSync(path,value,{mode:0o600}); childEnv[name]=path;
      }
      for (const {name,parts} of templatePlans) {
        const rendered = await renderTemplate(parts,async ref => (await rpc({op:'draw',ref,channel:'C1/template',token:clientToken(),...context})).value);
        values.push(...rendered.sensitive);
        const dir=mkdtempSync(join(tmpdir(),'ws-mcp-file-'));tempDirs.push(dir);
        const path=join(dir,name);writeFileSync(path,rendered.text,{mode:0o600});childEnv[name]=path;
      }
      for (const key of ['WELLSPRING_ADMIN_TOKEN','WELLSPRING_CLIENT_TOKEN','WELLSPRING_KEY','WELLSPRING_ONESHOT','WELLSPRING_PASSPHRASE','WELLSPRING_PASSPHRASE_FILE']) delete childEnv[key];
      const redact = (text: string) => values.filter(Boolean).sort((a,b)=>b.length-a.length).reduce((s,v)=>s.split(v).join('[REDACTED]'), text);
      // Retain only bounded decoded prefixes. Redact BEFORE truncating the returned string.
      const captures = [{ text:'', decoder:new StringDecoder('utf8'), truncated:false }, { text:'', decoder:new StringDecoder('utf8'), truncated:false }];
      const limit = 65536;
      const child = spawn(command[0], command.slice(1), { stdio:['ignore','pipe','pipe',...fdValues.map(()=>'pipe' as const)], env:childEnv });
      fdValues.forEach((value,i)=>{ const pipe=child.stdio[3+i] as Writable; pipe.on('error',()=>{}); pipe.end(value); });
      [child.stdout, child.stderr].forEach((stream, i) => stream!.on('data', c => {
        if (output === 'none') return;
        const capture = captures[i];
        const text = capture.decoder.write(c);
        if (capture.text.length + text.length > limit) capture.truncated = true;
        capture.text += text.slice(0, Math.max(0, limit-capture.text.length));
      }));
      let timedOut = false;
      const timer = setTimeout(() => { timedOut=true; child.kill('SIGKILL'); }, timeoutMs);
      try {
        const result = await new Promise<{exitCode:number|null; signal:string|null}>((resolve,reject) => {
          child.once('error', () => reject(new Error('failed to start program')));
          child.once('close', (exitCode,signal) => resolve({exitCode,signal}));
        });
        const streams = captures.map(c => {
          if (output === 'none') return '';
          // On capture overflow suppress the entire stream: a cut secret suffix must not leak.
          return c.truncated ? '[output suppressed: capture limit exceeded]' : redact(c.text + c.decoder.end()).slice(0,4000);
        });
        return JSON.stringify({...result,timedOut,outputMode:output,stdout:streams[0],stderr:streams[1],truncated:captures.some(c=>c.truncated)});
      } finally { clearTimeout(timer); }
      } finally { for (const dir of tempDirs) rmSync(dir,{recursive:true,force:true}); }
    }
    case "wellspring_derive": {
      const { op, ref, data, plaintext, blob, alg, digits, period } = args;
      if (!["totp","hmac","encrypt","decrypt"].includes(op)) throw new Error("invalid derive op");
      if (typeof ref !== "string" || !ref) throw new Error("ref must be a secret://id/field reference");
      if (op === "totp") {
        if (digits !== undefined && (!Number.isInteger(digits) || digits < 6 || digits > 8)) throw new Error("digits must be 6..8");
        if (period !== undefined && (!Number.isInteger(period) || period < 1 || period > 300)) throw new Error("period must be 1..300 seconds");
      }
      if (op === "hmac") {
        if (typeof data !== "string") throw new Error("hmac requires a data string");
        if (alg !== undefined && !["sha256","sha512"].includes(alg)) throw new Error("alg must be sha256 or sha512");
      }
      if (op === "encrypt" && typeof plaintext !== "string") throw new Error("encrypt requires a plaintext string");
      if (op === "decrypt" && typeof blob !== "string") throw new Error("decrypt requires a base64 blob string");
      // The daemon decides: it holds the key, so the key never crosses the socket.
      const r = await rpc({ op: `derive_${op}`, ref, data, plaintext, blob, alg, digits, period, purpose: args.purpose, target: args.target, token: clientToken() });
      // A derived artefact is safe to return by design, but the key is not.
      const text = JSON.stringify(r);
      return text;
    }
    default:
      throw new Error(`unknown tool: ${name}`);
  }
}

// ---- minimal MCP stdio loop ----
async function handle(msg: any, signal?: AbortSignal): Promise<any> {
  if (msg.method === "initialize") {
    return {
      protocolVersion: "2024-11-05",
      capabilities: { tools: {} },
      serverInfo: { name: "wellspring-mcp", version: "0.1.0" },
    };
  }
  if (msg.method === 'ping') return {};
  if (msg.method === "tools/list") return { tools: TOOLS };
  if (msg.method === "tools/call") {
    try {
      const text = await callTool(msg.params.name, msg.params.arguments ?? {}, signal);
      return { content: [{ type: "text", text }] };
    } catch (e: any) {
      return { content: [{ type: "text", text: `error: ${e.message}` }], isError: true };
    }
  }
  return null;
}

let buf = "";
process.stdin.setEncoding("utf8");
const pending = new Map<string | number, AbortController>();
const waitingRequests = new Set<string | number>();
let disconnected = false;
function disconnect() {
  disconnected = true;
  for (const controller of pending.values()) controller.abort();
}
function respond(response: object) {
  if (!disconnected) process.stdout.write(JSON.stringify(response) + '\n');
}
async function dispatch(msg: any) {
  if (msg?.method === 'notifications/cancelled') {
    pending.get(msg.params?.requestId)?.abort();
    return;
  }
  const hasId = msg?.id !== undefined;
  const controller = new AbortController();
  if (hasId) {
    if (pending.has(msg.id)) {
      respond({jsonrpc:'2.0',id:msg.id,error:{code:-32600,message:'Request ID already pending'}});
      return;
    }
    pending.set(msg.id, controller);
    if (msg.method === 'tools/call' && msg.params?.name === 'wellspring_request_status' && !msg.params?.arguments?.cancel && msg.params?.arguments?.waitMs > 0) waitingRequests.add(msg.id);
  }
  try {
    const result = await handle(msg, controller.signal);
    if (hasId) {
      const response = controller.signal.aborted
        ? {jsonrpc:'2.0',id:msg.id,error:{code:-32800,message:'Request cancelled'}}
        : result === null
          ? {jsonrpc:'2.0',id:msg.id,error:{code:-32601,message:'Method not found'}}
          : {jsonrpc:'2.0',id:msg.id,result};
      respond(response);
    }
  } finally {
    if (hasId) { pending.delete(msg.id); waitingRequests.delete(msg.id); }
  }
}
process.stdin.on("data", (chunk) => {
  buf += chunk;
  let i: number;
  while ((i = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, i).trim();
    buf = buf.slice(i + 1);
    if (!line) continue;
    let msg: any;
    try { msg = JSON.parse(line); }
    catch { respond({jsonrpc:'2.0',id:null,error:{code:-32700,message:'Parse error'}}); continue; }
    // Each request progresses independently, including cancellation notifications.
    void dispatch(msg).catch(() => respond({jsonrpc:'2.0',id:msg?.id ?? null,error:{code:-32600,message:'Invalid request'}}));
  }
});
// EOF is a half-close: one-shot CLI clients still read outstanding responses.
// Abort bounded waits, but let ordinary in-flight tools finish and flush stdout.
process.stdin.on('end', () => { for (const id of waitingRequests) pending.get(id)?.abort(); });
process.stdin.on('close', () => { for (const id of waitingRequests) pending.get(id)?.abort(); });
process.stdin.on('error', disconnect);
process.stdout.on('close', disconnect);
process.stdout.on('error', disconnect);
