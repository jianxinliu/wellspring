/** Persistent request metadata. Secret values live only in the encrypted store. */
import { existsSync, mkdirSync, readFileSync, writeFileSync, renameSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { WS_HOME, putSecret, deleteSecret, hasEntry } from "./store.ts";
import { boundedText, validateChannel, type UsePolicy } from "../policy/access.ts";
export const REQUESTS_PATH = join(WS_HOME, "requests.json");
export const REQUEST_RETENTION_MS = 7 * 24 * 60 * 60 * 1000;
export type RequestStatus = "pending" | "fulfilled" | "cancelled" | "expired";
export type SecretRequest = { requestId: string; caller: string; label: string; purpose: string; target?: string; channel: string; status: RequestStatus; createdAt: number; expiresAt: number; updatedAt: number; ref?: string; temporary?: boolean };
type Requests = { version: 1; requests: SecretRequest[] };
function load(): Requests {
  if (!existsSync(REQUESTS_PATH)) return { version: 1, requests: [] };
  const data = JSON.parse(readFileSync(REQUESTS_PATH, "utf8"));
  if (data.version !== 1 || !Array.isArray(data.requests) || data.requests.some((r: any) => !["pending", "fulfilled", "cancelled", "expired"].includes(r.status))) throw new Error("corrupt request metadata");
  return data;
}
function persist(data: Requests) {
  mkdirSync(WS_HOME, { recursive: true });
  const tmp = REQUESTS_PATH + ".tmp";
  writeFileSync(tmp, JSON.stringify(data, null, 2), { mode: 0o600 }); chmodSync(tmp, 0o600);
  renameSync(tmp, REQUESTS_PATH); chmodSync(REQUESTS_PATH, 0o600);
}
function publicRequest(r: SecretRequest): Omit<SecretRequest, "temporary"> {
  const { temporary, ref, ...metadata } = r;
  return { ...metadata, ...(r.status === "fulfilled" && ref ? { ref } : {}) };
}
function purgeValue(r: SecretRequest) {
  if (!r.temporary || !r.ref) return;
  const [id, field] = r.ref.replace(/^secret:\/\//, "").split("/");
  if (hasEntry(id!)) deleteSecret(id!, field);
}
export function cleanupRequests(): void {
  const data = load(); const now = Date.now(); let changed = false;
  for (const r of data.requests) {
    if (now >= r.expiresAt && (r.status === "pending" || (r.status === "fulfilled" && r.temporary))) {
      purgeValue(r); r.status = "expired"; r.updatedAt = r.expiresAt; delete r.ref; changed = true;
    }
  }
  const kept = data.requests.filter(r => r.status === "pending" || (r.status === "fulfilled" && r.temporary) || now - r.updatedAt < REQUEST_RETENTION_MS);
  if (kept.length !== data.requests.length) changed = true;
  if (changed) persist({ version: 1, requests: kept });
}
export function createRequest(caller: string, input: any) {
  // Exact allowlist: values, refs, sources and other secret arguments are never accepted.
  if (!input || typeof input !== "object" || Object.keys(input).some(k => !["label", "purpose", "target", "channel", "ttlMs"].includes(k))) throw new Error("invalid request arguments");
  const label = boundedText(input.label, "label", 256);
  const purpose = boundedText(input.purpose, "purpose");
  const target = input.target === undefined ? undefined : boundedText(input.target, "target");
  const channel = validateChannel(input.channel);
  const ttlMs = input.ttlMs ?? 15 * 60 * 1000;
  if (!Number.isInteger(ttlMs) || ttlMs < 1000 || ttlMs > 24 * 60 * 60 * 1000) throw new Error("invalid request ttlMs: expected 1000..86400000");
  cleanupRequests(); const data = load();
  if (data.requests.length >= 10000) throw new Error("too many retained requests");
  const now = Date.now(); const requestId = "req_" + randomBytes(18).toString("base64url");
  const r: SecretRequest = { requestId, caller, label, purpose, ...(target === undefined ? {} : { target }), channel, status: "pending", createdAt: now, expiresAt: now + ttlMs, updatedAt: now };
  data.requests.push(r); persist(data);
  return { requestId, status: r.status, expiresAt: r.expiresAt };
}
function owned(data: Requests, requestId: unknown, caller: string, admin: boolean): SecretRequest {
  const r = data.requests.find(r => r.requestId === requestId);
  if (!r || (!admin && r.caller !== caller)) throw new Error("no such request");
  return r;
}
export function requestStatus(requestId: unknown, caller: string, admin: boolean) {
  cleanupRequests(); return publicRequest(owned(load(), requestId, caller, admin));
}
export function listRequests() {
  cleanupRequests(); return load().requests.slice(-200).reverse().map(publicRequest);
}
export function fulfillRequest(requestId: unknown, input: any) {
  cleanupRequests(); const data = load(); const r = owned(data, requestId, "admin", true);
  if (r.status !== "pending" || Date.now() >= r.expiresAt) throw new Error("request is not pending");
  if (typeof input.save !== "boolean") throw new Error("save must be a boolean");
  if (!input.save && (input.id !== undefined || input.field !== undefined)) throw new Error("temporary request does not accept id or field");
  const id = input.save ? boundedText(input.id, "id", 256) : `cred:request_${r.requestId}`;
  const field = input.save ? (input.field ?? "value") : "value";
  if (hasEntry(id)) throw new Error("request destination already exists");
  const usePolicy: UsePolicy = { callers: [r.caller], channels: [r.channel], purposes: [r.purpose], ...(r.target === undefined ? {} : { targets: [r.target] }) };
  // Synchronous daemon dispatch serializes check + write: only the first pending fulfillment wins.
  putSecret(id, field, input.value, { usePolicy, ...(input.save ? {} : { expiresAt: r.expiresAt }) });
  r.status = "fulfilled"; r.updatedAt = Date.now(); r.ref = `secret://${id}/${field}`; r.temporary = !input.save;
  persist(data); return publicRequest(r);
}
export function cancelRequest(requestId: unknown, caller: string, admin: boolean) {
  cleanupRequests(); const data = load(); const r = owned(data, requestId, caller, admin);
  if (r.status !== "pending") throw new Error("request is not pending");
  r.status = "cancelled"; r.updatedAt = Date.now(); persist(data); return publicRequest(r);
}
