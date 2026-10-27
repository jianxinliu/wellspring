export type ExecRule = { argv0: string; args: string[] };
export type ExecGuard = { enabled: boolean; allow: ExecRule[]; deny: ExecRule[] };

function parseRule(entry: unknown): ExecRule {
  if (typeof entry !== "string" || !entry.trim()) throw new Error("invalid exec rule: empty or non-string entry");
  if (/[\0\r\n]/u.test(entry)) throw new Error("invalid exec rule: NUL and newline are forbidden");
  const tokens: string[] = [];
  let token = "";
  let started = false;
  let quote: "'" | '"' | undefined;
  for (let i = 0; i < entry.length; i++) {
    const char = entry[i];
    if (char === "\\" && quote !== "'") {
      if (i + 1 >= entry.length) throw new Error("invalid exec rule: trailing escape");
      token += entry[++i];
      started = true;
    } else if (quote) {
      if (char === quote) quote = undefined;
      else token += char;
    } else if (char === "'" || char === '"') {
      quote = char;
      started = true;
    } else if (/\s/u.test(char)) {
      if (started) { tokens.push(token); token = ""; started = false; }
    } else {
      token += char;
      started = true;
    }
  }
  if (quote) throw new Error("invalid exec rule: unbalanced quotes");
  if (started) tokens.push(token);
  const [argv0, ...args] = tokens;
  if (!argv0 || argv0 === "*" || argv0 === "**") throw new Error("invalid exec rule: argv0 must be a nonempty literal");
  if (args.some((arg, index) => arg === "**" && index !== args.length - 1)) {
    throw new Error("invalid exec rule: ** is allowed only once, in the final position");
  }
  return { argv0, args };
}

export function parseExecGuard(input: unknown): ExecGuard {
  if (input === undefined) return { enabled: false, allow: [], deny: [] };
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("invalid exec policy: expected an object");
  const { enabled = true, allow = [], deny = [] } = input as { enabled?: unknown; allow?: unknown; deny?: unknown };
  if (typeof enabled !== "boolean") throw new Error("invalid exec policy: enabled must be boolean");
  if (!Array.isArray(allow) || !Array.isArray(deny)) throw new Error("invalid exec policy: allow and deny must be string arrays");
  if (allow.length + deny.length > 200) throw new Error("invalid exec policy: at most 200 rules are allowed");
  return { enabled, allow: Array.from(allow, parseRule), deny: Array.from(deny, parseRule) };
}

export function matchExecRule(rule: ExecRule, argv: string[]): boolean {
  if (argv[0] !== rule.argv0) return false;
  let index = 1;
  for (const arg of rule.args) {
    if (arg === "**") return true;
    if (index >= argv.length || (arg !== "*" && arg !== argv[index])) return false;
    index++;
  }
  return index === argv.length;
}

export function checkExecAllowed(guard: ExecGuard, argv: string[]): { allowed: boolean; reason?: string } {
  if (!guard.enabled) return { allowed: true };
  if (!argv.length || !argv[0]) return { allowed: false, reason: "empty command" };
  if (guard.deny.some(rule => matchExecRule(rule, argv))) return { allowed: false, reason: `command denied by policy: ${argv[0]}` };
  if (!guard.allow.length) return { allowed: false, reason: "no exec rule allows this command" };
  if (!guard.allow.some(rule => matchExecRule(rule, argv))) return { allowed: false, reason: `command not in exec allowlist: ${argv[0]}` };
  return { allowed: true };
}
