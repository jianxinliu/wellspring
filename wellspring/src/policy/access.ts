/** Exact-match use constraints. Purpose/target are caller intent claims, not endpoint verification. */
export type UsePolicy = { callers?: string[]; channels?: string[]; purposes?: string[]; targets?: string[] };
export type UseContext = { caller: string; channel?: string; purpose?: string; target?: string };
export const DELIVERY_CHANNELS = ["A1/exec", "A2/fd", "C1/file", "C1/template", "git/askpass", "ssh/askpass", "derive_totp", "derive_hmac", "derive_encrypt", "derive_decrypt", "resolve"] as const;
export function boundedText(value: unknown, name: string, max = 512): string {
  if (typeof value !== "string" || !value.trim() || value.length > max || /[\u0000-\u001f\u007f]/u.test(value)) throw new Error(`invalid ${name}`);
  return value;
}
export function validateChannel(value: unknown): string {
  if (typeof value !== "string" || !(DELIVERY_CHANNELS as readonly string[]).includes(value)) throw new Error("invalid delivery channel");
  return value;
}
export function validateUsePolicy(input: unknown): UsePolicy {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("invalid usePolicy");
  const out: UsePolicy = {};
  for (const key of Object.keys(input)) {
    if (!["callers", "channels", "purposes", "targets"].includes(key)) throw new Error("unknown usePolicy key");
    const items = (input as any)[key];
    if (!Array.isArray(items) || items.length < 1 || items.length > 100) throw new Error(`invalid usePolicy.${key}: expected 1..100 strings`);
    (out as any)[key] = Array.from(items, item => boundedText(item, `usePolicy.${key}`));
  }
  return out;
}
export function useAllowed(policy: UsePolicy | undefined, context: UseContext): boolean {
  if (!policy) return true;
  return (!policy.callers || policy.callers.includes(context.caller)) &&
    (!policy.channels || (context.channel !== undefined && policy.channels.includes(context.channel))) &&
    (!policy.purposes || (context.purpose !== undefined && policy.purposes.includes(context.purpose))) &&
    (!policy.targets || (context.target !== undefined && policy.targets.includes(context.target)));
}
/** Discovery checks caller only: remaining constraints are exposed as metadata for planning a use. */
export function discoverAllowed(policy: UsePolicy | undefined, caller?: string): boolean {
  if (!policy || Object.keys(policy).length === 0) return true;
  return caller !== undefined && (!policy.callers || policy.callers.includes(caller));
}
