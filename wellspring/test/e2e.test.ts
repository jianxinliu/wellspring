import { describe, expect, test, beforeAll, afterAll } from "bun:test";
import { spawn, ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const DIR = mkdtempSync(join(tmpdir(), "wellspring-test-"));
process.env.WELLSPRING_HOME = join(DIR, "home");
process.env.WELLSPRING_SOCK = join(DIR, "wellspringd.sock");
const ADMIN_TOKEN = "test-admin-token-xyz";
process.env.WELLSPRING_ADMIN_TOKEN = ADMIN_TOKEN;

let daemon: ChildProcess;
// The suite daemon also serves the Web UI on an announced ephemeral port.
// Reuse it to reduce process churn and keep HTTP and socket checks on one instance.
let httpPort = 0;
// The daemon's pipes must be drained: a full stderr pipe blocks the writer, and a
// blocked daemon looks exactly like a dead one. Cap it so a log storm cannot eat RAM.
let daemonLog = "";
let daemonExited: string | undefined;

beforeAll(async () => {
  daemon = spawn("bun", ["run", join(import.meta.dir, "../src/daemon/main.ts")], {
    env: { ...process.env, WELLSPRING_HTTP_PORT: "0" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  const collect = (kind: string) => (c: Buffer) => {
    daemonLog += `[${kind}] ${c.toString()}`;
    if (daemonLog.length > 65536) daemonLog = daemonLog.slice(-16384);
  };
  daemon.stdout!.on("data", collect("out"));
  daemon.stderr!.on("data", collect("err"));
  daemon.once("exit", (code, signal) => { daemonExited = `exit code=${code} signal=${signal}`; });
  // Wait for the socket to actually answer. A fixed sleep races a loaded machine:
  // when it loses, every later test fails with ENOENT instead of a real signal.
  const deadline = Date.now() + 20000;
  let socketReady = false;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 100));
    if (daemonExited) throw new Error(`daemon died during startup (${daemonExited}); log: ${daemonLog}`);
    try {
      if ((await rpc({ op: "ping" })).pong) { socketReady = true; break; }
    } catch { /* not up yet */ }
    if (httpPort === 0) {
      const m = /wellspring web UI: http:\/\/127\.0\.0\.1:(\d+)/.exec(daemonLog);
      if (m) httpPort = Number(m[1]);
    }
  }
  if (!socketReady) throw new Error(`daemon socket did not become ready; log: ${daemonLog}`);
  // The UI binds after the socket; wait for its line rather than assuming.
  const uiDeadline = Date.now() + 10000;
  while (httpPort === 0 && Date.now() < uiDeadline) {
    await new Promise((r) => setTimeout(r, 100));
    const m = /wellspring web UI: http:\/\/127\.0\.0\.1:(\d+)/.exec(daemonLog);
    if (m) httpPort = Number(m[1]);
  }
  if (!httpPort) throw new Error(`suite daemon never announced a web port; log: ${daemonLog}`);
  try {
    const res = await fetch(`http://127.0.0.1:${httpPort}/api/ping`, { method: "POST", body: "{}" });
    if (!(await res.json()).pong) throw new Error("web ui answered but not with pong");
  } catch (e) {
    throw new Error(`web ui on ${httpPort} not reachable: ${String(e?.message ?? e)}`);
  }
});

afterAll(() => {
  // Report a mid-suite death instead of letting 40 ENOENT failures hide the cause.
  if (daemonExited) console.error(`\nwellspringd exited during the suite (${daemonExited}); tail of its log:\n${daemonLog.slice(-4000)}\n`);
  daemon?.kill();
  rmSync(DIR, { recursive: true, force: true });
});

function rpc(msg: object): Promise<any> {
  const { connect } = require("node:net");
  return new Promise((resolve, reject) => {
    const sock = connect(process.env.WELLSPRING_SOCK!);
    let buf = "";
    sock.on("connect", () => sock.write(JSON.stringify(msg) + "\n"));
    sock.on("data", (c: Buffer) => {
      buf += c.toString();
      const i = buf.indexOf("\n");
      if (i >= 0) {
        const reply = JSON.parse(buf.slice(0, i));
        sock.end();
        resolve(reply);
      }
    });
    sock.on("error", reject);
  });
}

const AUTH = { token: ADMIN_TOKEN };

test("put requires admin token", async () => {
  const noTok = await rpc({ op: "put", id: "x", field: "value", value: "v" });
  expect(noTok.error).toBe("unauthorized");
  const ok = await rpc({ op: "put", id: "cred:db_prod", field: "password", value: "hunter2-super-secret", ...AUTH });
  expect(ok.ok).toBe(true);
});

test("describe never leaks plaintext, fingerprint stable", async () => {
  const d = await rpc({ op: "describe", id: "cred:db_prod" });
  const json = JSON.stringify(d);
  expect(json.includes("hunter2")).toBe(false);
  expect(d.maskedPreview.password).toBe("****");
  expect(d.fields[0].fingerprint).toMatch(/^sha256:[0-9a-f]{16}$/);
});

test("PII view masks phone", async () => {
  await rpc({ op: "put", id: "person:zhang_san", field: "phone", value: "13800005678", cls: "pii", mask: "phone", ...AUTH });
  const v = await rpc({ op: "view", id: "person:zhang_san" });
  expect(v.maskedPreview.phone).toBe("138****5678");
});

test("draw_env without token denied (same-UID attacker)", async () => {
  const r = await rpc({ op: "draw_env", env: { DB_PASSWORD: "cred:db_prod/password" } });
  expect(r.error).toBe("unauthorized");
});

test("draw_env with admin token ok", async () => {
  const r = await rpc({ op: "draw_env", env: { DB_PASSWORD: "cred:db_prod/password" }, ...AUTH });
  expect(r.env.DB_PASSWORD).toBe("hunter2-super-secret");
});

test("one-shot token: issued, works once, then burned", async () => {
  const { token } = await rpc({ op: "auth_issue_oneshot", ref: 'cred:db_prod/password', channel: 'git/askpass', ...AUTH });
  expect(typeof token).toBe("string");
  const first = await rpc({ op: "draw", ref: "cred:db_prod/password", channel: "git/askpass", token });
  expect(first.value).toBe("hunter2-super-secret");
  const second = await rpc({ op: "draw", ref: "cred:db_prod/password", channel: "git/askpass", token });
  expect(second.error).toBe("unauthorized"); // burned
});

test("one-shot token cannot issue more tokens (privilege boundary)", async () => {
  const { token } = await rpc({ op: "auth_issue_oneshot", ref: 'cred:db_prod/password', channel: 'git/askpass', ...AUTH });
  const r = await rpc({ op: "auth_issue_oneshot", token });
  expect(r.error).toBe("unauthorized");
});

test('one-shot capability restricts secret, operation and channel', async () => {
  const issue=async()=> (await rpc({op:'auth_issue_oneshot',ref:'cred:db_prod/password',channel:'git/askpass',...AUTH})).token;
  expect((await rpc({op:'auth_issue_oneshot',...AUTH})).error).toBeDefined();
  for (const request of [
    {op:'draw',ref:'person:zhang_san/phone',channel:'git/askpass'},
    {op:'draw',ref:'cred:db_prod/password',channel:'A2/fd'},
    {op:'draw_env',env:{PASSWORD:'cred:db_prod/password'}},
    {op:'delete',id:'cred:db_prod'},
  ]) {
    const token=await issue();
    expect((await rpc({...request,token})).error).toBe('unauthorized');
    expect((await rpc({op:'draw',ref:'cred:db_prod/password',channel:'git/askpass',token})).error).toBe('unauthorized');
  }
  expect((await rpc({op:'draw',ref:'secret://cred:db_prod/password',channel:'git/askpass',token:await issue()})).value).toBe('hunter2-super-secret');
});

test("resolve requires allowlisted reason", async () => {
  const bad = await rpc({ op: "resolve", id: "person:zhang_san", field: "phone", reason: "bulk_export", ...AUTH });
  expect(bad.error).toBe("reason not allowlisted");
  const good = await rpc({ op: "resolve", id: "person:zhang_san", field: "phone", reason: "shipping_label", ...AUTH });
  expect(good.value).toBe("13800005678");
});

test("policy is configurable", async () => {
  const get1 = await rpc({ op: "policy_get" });
  expect(get1.policy.resolveReasons).toContain("shipping_label");
  await rpc({ op: "policy_put", policy: { resolveReasons: ["my_reason"], resolveRatePerMin: 5 }, ...AUTH });
  const get2 = await rpc({ op: "policy_get" });
  expect(get2.policy.resolveReasons).toEqual(["my_reason"]);
});

test("exec A1: child gets env, tool output has no plaintext", async () => {
  const out = Bun.spawnSync({
    cmd: ["bun", "run", join(import.meta.dir, "..", "src/cli/main.ts"),
      "exec", "--secret", "DB_PASSWORD=cred:db_prod/password", "--",
      "node", "-e", "console.log('child sees:', process.env.DB_PASSWORD === 'hunter2-super-secret')"],
    env: { ...process.env },
  });
  const text = out.stdout.toString();
  expect(text.trim()).toBe("child sees: true");
});

test("exec A2: child reads secret from fd, env/argv clean", async () => {
  const out = Bun.spawnSync({
    cmd: ["bun", "run", join(import.meta.dir, "..", "src/cli/main.ts"),
      "exec", "--secret-fd", "CERT=cred:db_prod/password", "--",
      "node", "-e", "const s=require('fs').readFileSync(Number(process.env.WELLSPRING_FD_CERT),'utf8');console.log('fd sees:', s==='hunter2-super-secret', 'env clean:', !process.env.DB_PASSWORD)"],
    env: { ...process.env },
  });
  const text = out.stdout.toString().trim();
  expect(text).toBe("fd sees: true env clean: true");
  expect(out.stdout.toString().includes("hunter2")).toBe(false); // never in wrapper stdout
});

test("audit log records draws + denials", async () => {
  const r = await rpc({ op: "audit" });
  const events = r.events.map((l: string) => JSON.parse(l));
  expect(events.some((e: any) => e.op === "put" && e.entry === "cred:db_prod" && e.verdict === "ok")).toBe(true);
  expect(events.some((e: any) => e.op === "draw_env" && e.verdict === "denied_auth")).toBe(true);
  expect(events.some((e: any) => e.op === "draw" && e.channel === "git/askpass" && e.verdict === "ok")).toBe(true);
  expect(events.some((e: any) => e.op === "resolve" && e.verdict === "denied_reason")).toBe(true);
});

test("MCP server: exec via stdio, no plaintext in tool output", async () => {
  const { spawn: sp } = await import("node:child_process");
  const reqs = [
    { jsonrpc: "2.0", id: 1, method: "initialize", params: {} },
    { jsonrpc: "2.0", id: 2, method: "tools/list" },
    { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "wellspring_exec", arguments: { output: 'redacted', env: { DB_PASSWORD: "cred:db_prod/password" }, command: ["node", "-e", "console.log('child sees:', process.env.DB_PASSWORD === 'hunter2-super-secret')"] } } },
    { jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "wellspring_describe", arguments: { id: "cred:db_prod" } } },
  ];
  const p = sp("bun", ["run", join(import.meta.dir, "../src/mcp/server.ts")], { stdio: ["pipe", "pipe", "pipe"], env: { ...process.env } });
  let out = ""; let err = "";
  p.stdout.on("data", (c: Buffer) => (out += c.toString()));
  p.stderr.on("data", (c: Buffer) => (err += c.toString()));
  // Send all requests together then close stdin: pending async responses must still finish.
  p.stdin.end(reqs.map(r => JSON.stringify(r)).join("\n") + "\n");
  // poll for responses instead of fixed sleep (CI machines are slow)
  const byId: Record<number, any> = {};
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 200));
    for (const l of out.trim().split("\n").filter((l: string) => l.startsWith("{"))) {
      const d = JSON.parse(l);
      if (d.id !== undefined) byId[d.id] = d;
    }
    if (byId[3] && byId[4]) break;
  }
  p.kill();
  expect(byId[1]?.result?.serverInfo?.name).toBe("wellspring-mcp");
  expect(byId[2]?.result?.tools.map((t: any) => t.name)).toContain("wellspring_exec");
  const execText = byId[3]?.result?.content?.[0]?.text ?? "";
  expect(execText).toContain("child sees: true");
  expect(execText.includes("hunter2")).toBe(false); // MCP tool output never has plaintext
  const descText = byId[4]?.result?.content?.[0]?.text ?? "";
  expect(descText.includes("hunter2")).toBe(false);
  expect(descText).toContain("fingerprint");
});

test('CLI validates before drawing and cleans temporary files after failed spawn', async () => {
  const {readdirSync,existsSync}=await import('node:fs');
  const cli=join(import.meta.dir,'../src/cli/main.ts');
  const execute=async (args:string[])=>{
    const p=spawn('bun',[cli,...args],{env:{...process.env},stdio:['ignore','pipe','pipe']});
    let err=''; p.stderr!.on('data',c=>err+=c);
    const code=await new Promise(resolve=>p.once('close',resolve)); return {code,err};
  };
  const invalid=await execute(['exec','--secret-file','../escape=cred:db_prod/password','--','node','-e','']);
  expect(invalid.code).not.toBe(0);
  const before=new Set(readdirSync(tmpdir()).filter(n=>n.startsWith('ws-file-')||n.startsWith('ws-askpass-')));
  const failure=await execute(['exec','--secret-file','PASSFILE=cred:db_prod/password','--git-cred','cred:db_prod/password','--','/no-such-wellspring-command']);
  expect(failure.code).not.toBe(0);
  expect(readdirSync(tmpdir()).filter(n=>(n.startsWith('ws-file-')||n.startsWith('ws-askpass-'))&&!before.has(n))).toEqual([]);
  const p=spawn('bun',[cli,'exec','--secret-file','PASSFILE=cred:db_prod/password','--','node','-e',`console.log(process.env.PASSFILE);setInterval(()=>{},1000)`],{env:{...process.env},stdio:['ignore','pipe','pipe']});
  const exit=new Promise(resolve=>p.once('close',resolve));
  const path=await new Promise<string>(resolve=>p.stdout!.once('data',c=>resolve(c.toString().trim())));
  expect(existsSync(path)).toBe(true); p.kill('SIGTERM'); expect(await exit).toBe(143);
  expect(existsSync(path)).toBe(false);
});

test('MCP suppresses output by default, redacts chunks, bounds capture and handles failures', async () => {
  const invoke = async (args: object) => {
    const p=spawn('bun',['run',join(import.meta.dir,'../src/mcp/server.ts')],{env:{...process.env},stdio:['pipe','pipe','pipe']});
    let text=''; p.stdout!.on('data',c=>text+=c);
    const done=new Promise<void>((resolve,reject)=>{p.once('close',()=>resolve());p.once('error',reject);});
    p.stdin!.end(JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/call',params:{name:'wellspring_exec',arguments:args}})+'\n');
    await done; return JSON.parse(text).result;
  };
  const env={PASSWORD:'cred:db_prod/password'};
  const silent=await invoke({env,command:['node','-e','console.log(process.env.PASSWORD)']});
  expect(JSON.parse(silent.content[0].text).stdout).toBe('');
  const printed=await invoke({env,output:'redacted',command:['node','-e',`process.stdout.write(process.env.PASSWORD.slice(0,5));setTimeout(()=>{console.log(process.env.PASSWORD.slice(5));console.error(process.env.PASSWORD);console.log('internal:',!!process.env.WELLSPRING_ADMIN_TOKEN)},10)`]});
  const result=JSON.parse(printed.content[0].text);
  expect(result.stdout).toContain('[REDACTED]'); expect(result.stderr).toContain('[REDACTED]');
  expect(result.stdout).toContain('internal: false'); expect(printed.content[0].text).not.toContain('hunter2');
  const overflow=await invoke({env,output:'redacted',command:['node','-e',`process.stdout.write('x'.repeat(70000)+process.env.PASSWORD)`]});
  expect(JSON.parse(overflow.content[0].text).stdout).toContain('suppressed');
  const fdResult=await invoke({fd:{PASS:'cred:db_prod/password'},output:'redacted',command:['node','-e',`const fs=require('fs');console.log(fs.readFileSync(Number(process.env.WELLSPRING_FD_PASS),'utf8'));console.log('env clean:',!process.env.PASSWORD)`]});
  expect(JSON.parse(fdResult.content[0].text).stdout).toContain('[REDACTED]');
  expect(JSON.parse(fdResult.content[0].text).stdout).toContain('env clean: true');
  const fileResult=await invoke({files:{PASSFILE:'cred:db_prod/password'},output:'redacted',command:['node','-e',`const fs=require('fs');console.log(process.env.PASSFILE);console.log(fs.statSync(process.env.PASSFILE).mode&511);console.log(fs.readFileSync(process.env.PASSFILE,'utf8'))`]});
  const fileOutput=JSON.parse(fileResult.content[0].text).stdout;
  expect(fileOutput).toContain('[REDACTED]');expect(fileOutput).toContain('384');
  expect((await import('node:fs')).existsSync(fileOutput.split('\n')[0])).toBe(false);
  const templateResult=await invoke({templates:{CONFIG:'{"password":{{secret://cred:db_prod/password | json}}}'},output:'redacted',command:['node','-e',`const fs=require('fs');const config=JSON.parse(fs.readFileSync(process.env.CONFIG,'utf8'));console.log('valid:',config.password=== 'hunter2-super-secret');console.log(process.env.CONFIG);console.log(config.password)`]});
  const templateOutput=JSON.parse(templateResult.content[0].text).stdout;
  expect(templateOutput).toContain('valid: true');expect(templateOutput).toContain('[REDACTED]');
  expect((await import('node:fs')).existsSync(templateOutput.split('\n')[1])).toBe(false);
  expect((await invoke({templates:{CONFIG:'{{bad}}'},command:['node','-e','']})).isError).toBe(true);
  const duplicate=await invoke({env,fd:{PASSWORD:'cred:db_prod/password'},command:['node','-e','']});expect(duplicate.isError).toBe(true);
  const timeout=await invoke({env,timeoutMs:100,command:['node','-e','setInterval(()=>{},1000)']});
  expect(JSON.parse(timeout.content[0].text).timedOut).toBe(true);
  const failure=await invoke({env,command:['/nonexistent-wellspring-program']});
  expect(failure.isError).toBe(true);
  const invalid=await invoke({env:{WELLSPRING_ADMIN_TOKEN:'cred:db_prod/password'},command:['node','-e','']});
  expect(invalid.isError).toBe(true);
});

test("git askpass recipe: local git push with one-shot token", async () => {
  // Create bare repo + clone, push via --git-cred; the credential never touches argv/agent context.
  const { execSync } = await import("node:child_process");
  const tmp = mkdtempSync(join(tmpdir(), "ws-git-"));
  const bare = join(tmp, "remote.git");
  const work = join(tmp, "work");
  execSync(`git init --bare -q ${bare} && git init -q ${work}`, { shell: "/bin/bash" });
  execSync(`git -C ${work} commit -q --allow-empty -m init`);
  // askpass returns the PAT; git over local protocol doesn't use askpass, so we verify the helper path directly:
  const out = Bun.spawnSync({
    cmd: ["bun", "run", join(import.meta.dir, "..", "src/cli/main.ts"),
      "exec", "--git-cred", "cred:db_prod/password", "--",
      "node", "-e", `
        const {execFileSync} = require('child_process');
        const out = execFileSync(process.env.GIT_ASKPASS, ['Password for git'], {env: process.env, encoding: 'utf8'});
        console.log('askpass got secret:', out === 'hunter2-super-secret');
        console.log('env clean:', !JSON.stringify(process.env).includes('hunter2'));
      `],
    env: { ...process.env, GIT_DIR: undefined as any },
    cwd: work,
  });
  const text = out.stdout.toString().trim();
  expect(out.stdout.toString().includes("hunter2")).toBe(false); // child stdout echoed by tool must not contain plaintext
  // run with output not containing plaintext: our node -e prints booleans only
  expect(text).toContain("askpass got secret: true");
  expect(text).toContain("env clean: true");
  rmSync(tmp, { recursive: true, force: true });
});

// A busy default port must move the UI aside, never take the credential socket down.
test("Web UI falls back to an ephemeral port when 7777 is busy", async () => {
  const { createServer } = await import("node:http");
  const { HTTP_PORT, startHttp } = await import("../src/daemon/web.ts");
  const blocker = createServer((_q, r) => r.end("blocker"));
  const occupied = await new Promise<boolean>((res) => {
    blocker.once("error", () => res(true)); // Busy is the precondition we want.
    blocker.listen(HTTP_PORT, "127.0.0.1", () => res(true));
  });
  if (!occupied) throw new Error("precondition failed: could not occupy the default port");
  const server = startHttp();
  const port = await new Promise<number>((res) => server.once("listening", () => res((server.address() as { port?: number })?.port ?? 0)));
  expect(port).not.toBe(HTTP_PORT);
  const response = await fetch(`http://127.0.0.1:${port}/api/ping`, { method: "POST", body: "{}" });
  expect((await response.json()).pong).toBe(true);
  server.close(); blocker.close();
});

test("Web UI HTTP API: auth, vault ops, audit", async () => {
  // Exercise HTTP against the same isolated daemon used by the socket tests.
  const port = httpPort;
  const post = async (op: string, body: object, tok?: string) => {
    const res = await fetch(`http://127.0.0.1:${port}/api/${op}`, {
      method: "POST",
      headers: { "content-type": "application/json", ...(tok ? { authorization: `Bearer ${tok}` } : {}) },
      body: JSON.stringify(body),
    });
    return res.json();
  };
  // ping works without token
  expect((await post("ping", {})).pong).toBe(true);
  // put without token denied
  expect((await post("put", { id: "x", field: "v", value: "y" })).error).toBe("unauthorized");
  // put with token ok
  expect((await post("put", { id: "cred:web_test", field: "password", value: "websecret" }, ADMIN_TOKEN)).ok).toBe(true);
  // list shows descriptor, no plaintext
  expect((await post("auth_check", {}, "wrong")).error).toBe("unauthorized");
  expect((await post("auth_check", {}, ADMIN_TOKEN)).ok).toBe(true);
  expect((await post("list", {})).error).toBe("unauthorized");
  const list = await post("list", {}, ADMIN_TOKEN);
  expect(JSON.stringify(list).includes("websecret")).toBe(false);
  // draw_env via HTTP
  const draw = await post("draw_env", { env: { X: "cred:web_test/password" } }, ADMIN_TOKEN);
  expect(draw.env.X).toBe("websecret");
  const base=`http://127.0.0.1:${port}`;
  const headers={authorization:`Bearer ${ADMIN_TOKEN}`};
  expect((await fetch(base+'/api/delete?id=cred:web_test',{headers})).status).toBe(405);
  expect((await fetch(base+'/api/no_such_operation',{headers})).status).toBe(404);
  expect((await fetch(base+'/api/list',{headers})).status).toBe(200);
  expect((await fetch(base+'/api/put',{method:'POST',headers:{...headers,'content-type':'application/json'},body:JSON.stringify({value:'x'.repeat(1024*1024)})})).status).toBe(413);
  // HTML served
  const html = await (await fetch(`http://127.0.0.1:${port}/`)).text();
  expect(html).toContain("Wellspring");
  expect(html).toContain("凭据库");
  // audit via HTTP
  const audit = await post("audit", {}, ADMIN_TOKEN);
  const evs = audit.events.map((l: string) => JSON.parse(l));
  expect(evs.some((e: any) => e.op === "put" && e.entry === "cred:web_test")).toBe(true);
  expect(evs.some((e: any) => e.op === "draw_env" && e.verdict === "ok")).toBe(true);
  // HTTP not reachable from non-loopback? (bind check)
  expect(evs.length).toBeGreaterThan(0);
});

test("vault management validates writes, rotates and deletes with audit", async () => {
  const put = (id: string, field: string, value: string) => rpc({op:'put',id,field,value,token:ADMIN_TOKEN});
  expect((await put('__proto__','value','bad')).error).toBeDefined();
  expect((await put('cred:manage','constructor','bad')).error).toBeDefined();
  expect((await put('cred:manage','value','')).error).toBeDefined();
  expect((await put('cred:manage','value','first')).ok).toBe(true);
  const before = await rpc({op:'describe',id:'cred:manage'});
  expect((await put('cred:manage','value','rotated')).ok).toBe(true);
  const after = await rpc({op:'describe',id:'cred:manage'});
  expect(after.fields[0].fingerprint).not.toBe(before.fields[0].fingerprint);
  expect(JSON.stringify(after)).not.toContain('rotated');
  expect((await rpc({op:'delete',id:'cred:manage'})).error).toBe('unauthorized');
  expect((await rpc({op:'delete',id:'cred:manage',field:'value',token:ADMIN_TOKEN})).ok).toBe(true);
  expect((await rpc({op:'describe',id:'cred:manage'})).error).toBeDefined();
  expect((await rpc({op:'policy_put',policy:{resolveReasons:['test'],resolveRatePerMin:0},token:ADMIN_TOKEN})).error).toBeDefined();
  expect((await rpc({op:'audit'})).events.some((line: string) => JSON.parse(line).op === 'delete')).toBe(true);
});

test('CLI template config is valid, private and removed after exit',async()=>{
  const {writeFileSync,existsSync}=await import('node:fs');
  const template=join(DIR,'db.template');
  writeFileSync(template,'{"password":{{secret://cred:db_prod/password | json}}}');
  const p=spawn('bun',[join(import.meta.dir,'../src/cli/main.ts'),'exec','--template-file',`CONFIG=${template}`,'--','node','-e',`const fs=require('fs');const p=process.env.CONFIG;console.log(p);console.log((fs.statSync(p).mode&511)===384);console.log(JSON.parse(fs.readFileSync(p,'utf8')).password==='hunter2-super-secret')`],{env:{...process.env},stdio:['ignore','pipe','pipe']});
  let out='';p.stdout!.on('data',c=>out+=c);let err='';p.stderr!.on('data',c=>err+=c);
  const code=await new Promise(resolve=>p.once('close',resolve));
  expect(err).toBe('');expect(code).toBe(0);expect(out).toContain('true\ntrue');
  expect(existsSync(out.split('\n')[0])).toBe(false);expect(out).not.toContain('hunter2');
});

// A crashed daemon leaves a socket file that answers nothing; a restart must reclaim it.
// The daemon runs forever, so each launch is spawned, observed and then killed.
async function startDaemonObserved(env: Record<string, string | undefined>, stopAfter: RegExp) {
  const child = spawn("bun", ["run", join(import.meta.dir, "..", "src/daemon/main.ts")], { env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"] });
  let log = "";
  const collect = (c: Buffer) => { log += c.toString(); };
  child.stdout!.on("data", collect);
  child.stderr!.on("data", collect);
  const deadline = Date.now() + 25000;
  while (!stopAfter.test(log) && Date.now() < deadline) await new Promise((r) => setTimeout(r, 200));
  child.kill("SIGKILL");
  return log;
}

test("daemon reclaims a stale socket file and refuses a live one", async () => {
  const { createServer } = await import("node:net");
  const staleDir = mkdtempSync(join(tmpdir(), "ws-stale-"));
  const sock = join(staleDir, "wellspringd.sock");
  // Emulate a crashed daemon: the socket file remains, but no process owns it.
  await new Promise<void>((res) => { const s = createServer(() => {}); s.listen(sock, () => { s.close(); res(); }); });
  const env = { WELLSPRING_HOME: staleDir, WELLSPRING_SOCK: sock, WELLSPRING_ADMIN_TOKEN: "stale-probe" };
  expect(await startDaemonObserved(env, /listening/)).toContain("listening");
  // With a live daemon holding the socket, a second one must refuse instead of stealing it.
  const live = spawn("bun", ["run", join(import.meta.dir, "..", "src/daemon/main.ts")], { env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"] });
  let liveLog = "";
  live.stdout!.on("data", (c: Buffer) => { liveLog += c.toString(); });
  const deadline = Date.now() + 25000;
  while (!liveLog.includes("listening") && Date.now() < deadline) await new Promise((r) => setTimeout(r, 200));
  const collision = await startDaemonObserved(env, /already listening|listening/);
  expect(collision).toContain("already listening");
  expect(collision).not.toContain("wellspringd listening");
  live.kill("SIGKILL");
  rmSync(staleDir, { recursive: true, force: true });
}, 60000);

test("exec C1: secret-file rendered 0600, removed after exit", async () => {
  const { rmSync, existsSync, statSync } = await import("node:fs");
  const tmp = mkdtempSync(join(tmpdir(), "ws-c1-"));
  const out = Bun.spawnSync({
    cmd: ["bun", "run", join(import.meta.dir, "..", "src/cli/main.ts"),
      "exec", "--secret-file", "KEY=cred:db_prod/password", "--",
      "node", "-e", "const fs=require('fs');const p=process.env.KEY;const st=fs.statSync(p);console.log('exists:',fs.existsSync(p));console.log('mode0600:',(st.mode&0o777)===0o600);console.log('content ok:',fs.readFileSync(p,'utf8')==='hunter2-super-secret')"],
    env: { ...process.env },
    cwd: tmp,
  });
  const text = out.stdout.toString();
  expect(text).toContain("exists: true");
  expect(text).toContain("mode0600: true");
  expect(text).toContain("content ok: true");
  expect(text.includes("hunter2")).toBe(false); // tool stdout clean
  rmSync(tmp, { recursive: true, force: true });
});

test("exec ssh recipe: SSH_ASKPASS helper answers with secret", async () => {
  const out = Bun.spawnSync({
    cmd: ["bun", "run", join(import.meta.dir, "..", "src/cli/main.ts"),
      "exec", "--git-cred", "cred:db_prod/password", "--",
      "node", "-e", `
        const {execFileSync} = require('child_process');
        const out = execFileSync(process.env.SSH_ASKPASS, ['Password for ssh'], {env: process.env, encoding: 'utf8'});
        console.log('ssh askpass got secret:', out === 'hunter2-super-secret');
        console.log('SSH_ASKPASS_REQUIRE:', process.env.SSH_ASKPASS_REQUIRE);
        console.log('env clean:', !JSON.stringify(process.env).includes('hunter2'));
      `],
    env: { ...process.env },
  });
  const text = out.stdout.toString();
  expect(text).toContain("ssh askpass got secret: true");
  expect(text).toContain("SSH_ASKPASS_REQUIRE: force");
  expect(text).toContain("env clean: true");
  expect(text.includes("hunter2")).toBe(false);
});

// ---- A3: short-lived credentials (TTL / expiry) ----

async function freshSecret(id: string, field: string, value: string, opts: Record<string, unknown> = {}) {
  const r = await rpc({ op: "put", id, field, value, ...opts, ...AUTH });
  expect(r.ok).toBe(true);
  return r;
}

test("TTL: expired secret yields no plaintext and is audited as expired", async () => {
  // 1s is the shortest TTL web.ts exposes; wait past it to cross the boundary.
  await freshSecret("cred:short", "value", "ephemeral-plaintext-AAA", { ttlMs: 1000 });
  expect((await rpc({ op: "resolve", id: "cred:short", field: "value", reason: "my_reason", ...AUTH })).value).toBe("ephemeral-plaintext-AAA");
  await Bun.sleep(1100);
  const after = await rpc({ op: "resolve", id: "cred:short", field: "value", reason: "my_reason", ...AUTH });
  expect(after.error).toContain("expired");
  expect(JSON.stringify(after)).not.toContain("ephemeral-plaintext-AAA");
  const draw = await rpc({ op: "draw", ref: "secret://cred:short/value", ...AUTH });
  expect(draw.error).toContain("expired");
  expect(draw.value).toBeUndefined();
  expect((await rpc({ op: "draw", ref: "secret://cred:short/value", token: "bad" })).error).toBe("unauthorized");
  const evs = (await rpc({ op: "audit", ...AUTH })).events.map((l: string) => JSON.parse(l));
  expect(evs.some((e: any) => e.op === "resolve" && e.entry === "cred:short" && e.verdict === "expired")).toBe(true);
});

test("TTL: list and describe expose expiry metadata but never plaintext", async () => {
  await freshSecret("cred:dated", "value", "dated-plaintext-BBB", { ttlMs: 60_000 });
  const list = await rpc({ op: "list", ...AUTH });
  const entry = list.descriptors.find((d: any) => d.ref === "secret://cred:dated");
  expect(typeof entry.fields[0].expiresAt).toBe("number");
  expect(entry.fields[0].expired).toBe(false);
  expect(JSON.stringify(list)).not.toContain("dated-plaintext-BBB");
  const d = await rpc({ op: "describe", id: "cred:dated", ...AUTH });
  expect(typeof d.fields[0].expiresAt).toBe("number");
  expect(d.fields[0].expired).toBe(false);
});

test("TTL: validation rejects conflicting, out-of-range and past expiry inputs", async () => {
  expect((await rpc({ op: "put", id: "cred:bad_ttl", field: "value", value: "x", ttlMs: 1000, expiresAt: Date.now() + 5000, ...AUTH })).error).toContain("not both");
  expect((await rpc({ op: "put", id: "cred:bad_ttl", field: "value", value: "x", ttlMs: 500, ...AUTH })).error).toBeDefined();
  expect((await rpc({ op: "put", id: "cred:bad_ttl", field: "value", value: "x", ttlMs: Date.now() + 31_536_000_001, ...AUTH })).error).toBeDefined();
  expect((await rpc({ op: "put", id: "cred:bad_ttl", field: "value", value: "x", expiresAt: Date.now() - 1000, ...AUTH })).error).toBeDefined();
  expect((await rpc({ op: "describe", id: "cred:bad_ttl", ...AUTH })).error).toBeDefined();
});

test("TTL: rotation refreshes plaintext and clears a stale expiry", async () => {
  await freshSecret("cred:rotate_ttl", "value", "rotate-plaintext-CCC", { ttlMs: 1000 });
  await Bun.sleep(1100);
  expect((await rpc({ op: "resolve", id: "cred:rotate_ttl", field: "value", reason: "my_reason", ...AUTH })).error).toContain("expired");
  // Rotation on an expired credential must still succeed: the operator is replacing it, not reading it.
  await freshSecret("cred:rotate_ttl", "value", "rotate-plaintext-DDD");
  expect((await rpc({ op: "resolve", id: "cred:rotate_ttl", field: "value", reason: "my_reason", ...AUTH })).value).toBe("rotate-plaintext-DDD");
  const d = await rpc({ op: "describe", id: "cred:rotate_ttl", ...AUTH });
  expect(d.fields[0].expiresAt).toBeUndefined();
});

test("TTL: unauthenticated draw learns nothing about expiry", async () => {
  await freshSecret("cred:auth_first", "value", "auth-plaintext-EEE", { ttlMs: 1000 });
  await Bun.sleep(1100);
  // Bad token against an expired secret must fail as "unauthorized", never "expired":
  // otherwise expiry itself leaks to an unauthenticated caller.
  const r = await rpc({ op: "resolve", id: "cred:auth_first", field: "value", reason: "my_reason", token: "wrong-token" });
  expect(r.error).toBe("unauthorized");
  expect(JSON.stringify(r)).not.toContain("expired");
  expect(JSON.stringify(r)).not.toContain("auth-plaintext-EEE");
});

test("TTL: draw_env never hands out a partial environment", async () => {
  await freshSecret("cred:env_ok", "value", "env-plaintext-FFF", { ttlMs: 60_000 });
  await freshSecret("cred:env_bad", "value", "env-plaintext-GGG", { ttlMs: 1000 });
  await Bun.sleep(1100);
  const r = await rpc({ op: "draw_env", env: { A: "secret://cred:env_ok/value", B: "secret://cred:env_bad/value" }, ...AUTH });
  expect(r.error).toContain("expired");
  expect(r.env).toBeUndefined();
  expect(JSON.stringify(r)).not.toContain("env-plaintext-FFF");
  expect(JSON.stringify(r)).not.toContain("env-plaintext-GGG");
});

test("CLI: --ttl accepts durations and enforces expiry", async () => {
  const cli = (args: string[]) => Bun.spawnSync({
    cmd: ["bun", "run", join(import.meta.dir, "..", "src/cli/main.ts"), ...args],
    env: { ...process.env },
  });
  expect(cli(["put", "cred:cli_ttl", "value", "cli-plaintext-HHH", "--ttl", "1s"]).stdout.toString()).toContain('"ok":true');
  const view = JSON.parse(cli(["resolve", "cred:cli_ttl/value", "--reason", "my_reason"]).stdout.toString());
  expect(view.value).toBe("cli-plaintext-HHH");
  await Bun.sleep(1100);
  const expired = cli(["resolve", "cred:cli_ttl/value", "--reason", "my_reason"]);
  expect(expired.exitCode).not.toBe(0);
  expect(expired.stderr.toString()).toContain("expired");
  expect(expired.stdout.toString() + expired.stderr.toString()).not.toContain("cli-plaintext-HHH");
  expect(cli(["put", "cred:cli_bad", "value", "x", "--ttl", "soon"]).exitCode).not.toBe(0);
});

// ---- Master key custody: separate homes never disturb the shared daemon. ----
const custodyStore = join(import.meta.dir, "../src/core/store.ts");
const custodyCli = join(import.meta.dir, "../src/cli/main.ts");
function custodyEnv(home: string, extra: Record<string, string | undefined> = {}) {
  return { ...process.env, WELLSPRING_HOME: home, WELLSPRING_KEY: undefined,
    WELLSPRING_PASSPHRASE: undefined, WELLSPRING_PASSPHRASE_FILE: undefined, ...extra };
}
function custodyScript(home: string, script: string, extra: Record<string, string | undefined> = {}) {
  return Bun.spawnSync({ cmd: [process.execPath, "-e", `import * as store from ${JSON.stringify(custodyStore)}; ${script}`],
    env: custodyEnv(home, extra), stdin: "ignore", timeout: 15000 });
}
function custodyCommand(home: string, args: string[], extra: Record<string, string | undefined> = {}) {
  return Bun.spawnSync({ cmd: [process.execPath, custodyCli, ...args], env: custodyEnv(home, extra), stdin: "ignore", timeout: 15000 });
}

test("custody: seal, rewrap and unseal preserve stored secret and master key", async () => {
  const { readFileSync, statSync } = await import("node:fs");
  const home = join(DIR, "custody-roundtrip");
  const password = "synthetic-custody-test-password";
  const env = { WELLSPRING_PASSPHRASE: password };
  expect(custodyScript(home, 'store.putSecret("cred:custody", "value", "custody-test-secret");').exitCode).toBe(0);
  const path = join(home, "master.key");
  const original = readFileSync(path);
  expect(original.length).toBe(32);
  expect(custodyCommand(home, ["seal"], env).exitCode).toBe(0);
  const sealed = readFileSync(path);
  expect(sealed.length).toBe(77);
  expect(sealed[0]).toBe(2);
  expect(statSync(path).mode & 0o777).toBe(0o600);
  const read = custodyScript(home, 'console.log(store.getSecret("cred:custody", "value") === "custody-test-secret");', env);
  expect(read.exitCode).toBe(0);
  expect(read.stdout.toString().trim()).toBe("true");
  expect(custodyCommand(home, ["seal"], env).exitCode).toBe(0);
  expect(readFileSync(path).equals(sealed)).toBe(false);
  const unseal = custodyCommand(home, ["unseal"], env);
  expect(unseal.exitCode).toBe(0);
  expect(unseal.stdout.toString()).toContain("same-UID");
  expect(readFileSync(path).equals(original)).toBe(true);
}, 60000);

test("custody: wrong or unavailable passphrase fails without returning a secret", () => {
  const home = join(DIR, "custody-wrong");
  expect(custodyScript(home, 'store.putSecret("cred:custody", "value", "never-return-this-secret");').exitCode).toBe(0);
  expect(custodyCommand(home, ["seal"], { WELLSPRING_PASSPHRASE: "correct-test-password" }).exitCode).toBe(0);
  for (const extra of [{ WELLSPRING_PASSPHRASE: "wrong-test-password" }, { PATH: "/no-such-wellspring-path" }]) {
    const read = custodyScript(home, 'console.log(store.getSecret("cred:custody", "value"));', extra);
    expect(read.exitCode).not.toBe(0);
    expect(read.stdout.toString()).toBe("");
    expect(read.stderr.toString()).toContain("WELLSPRING_PASSPHRASE");
    expect(read.stderr.toString()).toContain("keychain");
    expect(read.stderr.toString()).not.toContain("never-return-this-secret");
  }
}, 60000);

test("custody: v1 key remains untouched and passphrase file follows environment", async () => {
  const { readFileSync, writeFileSync } = await import("node:fs");
  const home = join(DIR, "custody-v1");
  expect(custodyScript(home, 'store.putSecret("cred:custody", "value", "v1-secret");').exitCode).toBe(0);
  const path = join(home, "master.key");
  const original = readFileSync(path);
  expect(custodyScript(home, 'console.log(store.getSecret("cred:custody", "value") === "v1-secret");', { PATH: "/no-such-wellspring-path" }).stdout.toString().trim()).toBe("true");
  expect(readFileSync(path).equals(original)).toBe(true);
  const passfile = join(home, "passphrase");
  writeFileSync(passfile, "file-test-password\n", { mode: 0o600 });
  const env = { WELLSPRING_PASSPHRASE_FILE: passfile };
  expect(custodyCommand(home, ["seal"], env).exitCode).toBe(0);
  expect(custodyScript(home, 'console.log(store.getSecret("cred:custody", "value") === "v1-secret");', env).stdout.toString().trim()).toBe("true");
  expect(custodyScript(home, 'store.getMasterKey();', { ...env, WELLSPRING_PASSPHRASE: "wrong-override" }).exitCode).not.toBe(0);
  expect(custodyCommand(home, ["seal"], { WELLSPRING_KEY: Buffer.alloc(32).toString("base64") }).stderr.toString()).toContain("refuses WELLSPRING_KEY");
}, 60000);

test("custody: keychain status gracefully handles missing security binary", () => {
  const result = custodyCommand(join(DIR, "custody-no-keychain"), ["keychain", "status"], { PATH: "/no-such-wellspring-path" });
  expect(result.exitCode).toBe(0);
  expect(result.stdout.toString()).toContain("keychain unavailable");
  expect(result.stderr.toString()).toBe("");
}, 60000);

test("custody: wrapping helpers support a fast explicit test scrypt profile", async () => {
  const { wrapMasterKey, unwrapMasterKey, SCRYPT_PARAMS } = await import("../src/core/store.ts");
  const params = { ...SCRYPT_PARAMS, N: 16 };
  const key = new Uint8Array(32).fill(7);
  const wrapped = wrapMasterKey(key, "synthetic-fast-password", params);
  expect(unwrapMasterKey(wrapped, "synthetic-fast-password", params)).toEqual(key);
  expect(() => unwrapMasterKey(wrapped, "incorrect", params)).toThrow("passphrase is incorrect or unavailable");
});

// ---- Target-command allowlist: all policy changes are scoped and restored. ----
test('exec guard matches exact argv, single/rest wildcards and deny precedence', async () => {
  const { parseExecGuard, matchExecRule, checkExecAllowed } = await import('../src/policy/exec.ts');
  const guard = parseExecGuard({ allow: ['node *', 'psql **', '"/usr/bin/node app.js" "quoted arg"'], deny: ['node blocked.js'] });
  expect(guard.enabled).toBe(true);
  expect(matchExecRule(guard.allow[0], ['node', 'a.js'])).toBe(true);
  expect(matchExecRule(guard.allow[0], ['node'])).toBe(false);
  expect(matchExecRule(guard.allow[0], ['node', 'a.js', 'extra'])).toBe(false);
  expect(matchExecRule(guard.allow[1], ['psql'])).toBe(true);
  expect(matchExecRule(guard.allow[1], ['psql', '-c', 'select 1'])).toBe(true);
  expect(matchExecRule(guard.allow[2], ['/usr/bin/node app.js', 'quoted arg'])).toBe(true);
  expect(checkExecAllowed(guard, ['node', 'blocked.js', 'private-arg']).allowed).toBe(false);
  expect(checkExecAllowed(guard, ['node', 'blocked.js'])).toEqual({ allowed: false, reason: 'command denied by policy: node' });
  expect(checkExecAllowed(guard, ['sh', 'private-arg'])).toEqual({ allowed: false, reason: 'command not in exec allowlist: sh' });
  expect(checkExecAllowed(guard, [])).toEqual({ allowed: false, reason: 'empty command' });
  expect(checkExecAllowed(parseExecGuard({}), ['node'])).toEqual({ allowed: false, reason: 'no exec rule allows this command' });
  expect(checkExecAllowed(parseExecGuard(undefined), [])).toEqual({ allowed: true });
});

test('exec guard rejects malformed policy without mutating input', async () => {
  const { parseExecGuard } = await import('../src/policy/exec.ts');
  expect(parseExecGuard(undefined)).toEqual({ enabled: false, allow: [], deny: [] });
  for (const input of [null, [], true, { enabled: 'yes' }, { allow: 'node' }, { deny: [1] },
    { allow: ['node "unfinished'] }, { allow: ['node ** middle'] }, { deny: ['node ** *'] },
    { allow: ['node ** **'] }, { allow: [''] }, { allow: ['   '] }, { allow: ['"" arg'] },
    { allow: ['* arg'] }, { allow: ['**'] }, { allow: ['node\0arg'] }, { allow: ['node\narg'] },
    { allow: Array(101).fill('node'), deny: Array(100).fill('psql') }]) {
    expect(() => parseExecGuard(input)).toThrow();
  }
  expect(() => parseExecGuard({ allow: ['node "unfinished'] })).toThrow('unbalanced quotes');
  expect(() => parseExecGuard({ allow: ['node ** middle'] })).toThrow('final position');
  const input = Object.freeze({ allow: Object.freeze(['node *']), deny: Object.freeze([]) });
  expect(parseExecGuard(input).allow).toEqual([{ argv0: 'node', args: ['*'] }]);
  expect(input.allow).toEqual(['node *']);
  expect(parseExecGuard({ allow: Array(200).fill('node') }).allow.length).toBe(200);
});

async function withExecPolicy(exec: object, run: () => Promise<void>) {
  const original = (await rpc({ op: 'policy_get' })).policy;
  try {
    expect((await rpc({ op: 'policy_put', policy: { ...original, exec }, ...AUTH })).ok).toBe(true);
    expect((await rpc({ op: 'policy_get' })).policy.exec).toEqual(exec);
    await run();
  } finally {
    expect((await rpc({ op: 'policy_put', policy: original, ...AUTH })).ok).toBe(true);
  }
}

function execPolicyCli(args: string[]) {
  return Bun.spawnSync({ cmd: ['bun', join(import.meta.dir, '../src/cli/main.ts'), 'exec', ...args], env: { ...process.env } });
}

test('CLI exec allowlist refuses before any draw or temporary secret directory', async () => {
  const { readFileSync, readdirSync, existsSync } = await import('node:fs');
  await withExecPolicy({ enabled: true, allow: ['psql **'], deny: [] }, async () => {
    const auditPath = join(process.env.WELLSPRING_HOME!, 'draw-events.jsonl');
    const audit = () => existsSync(auditPath) ? readFileSync(auditPath, 'utf8') : '';
    const beforeAudit = audit();
    const dirs = () => readdirSync(tmpdir()).filter(n => n.startsWith('ws-file-') || n.startsWith('ws-mcp-file-'));
    const beforeDirs = new Set(dirs());
    const result = execPolicyCli(['--secret', 'PASSWORD=cred:db_prod/password', '--secret-file', 'PASSFILE=cred:db_prod/password', '--', 'node', '-e', 'throw Error("must not run")']);
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr.toString()).toContain('command not in exec allowlist: node');
    expect(audit()).toBe(beforeAudit);
    expect(dirs().filter(n => !beforeDirs.has(n))).toEqual([]);
  });
});

test('CLI exec matching fixed arguments delivers secrets end to end', async () => {
  const script = 'console.log(process.env.PASSWORD === "hunter2-super-secret")';
  await withExecPolicy({ enabled: true, allow: [`node -e '${script}'`], deny: [] }, async () => {
    const result = execPolicyCli(['--secret', 'PASSWORD=cred:db_prod/password', '--', 'node', '-e', script]);
    expect(result.exitCode).toBe(0);
    expect(result.stderr.toString()).toBe('');
    expect(result.stdout.toString().trim()).toBe('true');
  });
});

test('MCP exec uses deny-first allowlist before templates or draws', async () => {
  const { readFileSync, readdirSync } = await import('node:fs');
  await withExecPolicy({ enabled: true, allow: ['node **'], deny: ['node **'] }, async () => {
    const auditPath = join(process.env.WELLSPRING_HOME!, 'draw-events.jsonl');
    const beforeAudit = readFileSync(auditPath, 'utf8');
    const beforeDirs = new Set(readdirSync(tmpdir()));
    const p = spawn('bun', [join(import.meta.dir, '../src/mcp/server.ts')], { env: { ...process.env }, stdio: ['pipe', 'pipe', 'pipe'] });
    let text = '';
    p.stdout!.on('data', c => text += c);
    const done = new Promise<void>((resolve, reject) => { p.once('close', () => resolve()); p.once('error', reject); });
    p.stdin!.end(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'wellspring_exec', arguments: {
      env: { PASSWORD: 'cred:db_prod/password' }, files: { PASSFILE: 'cred:db_prod/password' },
      templates: { CONFIG: '{{bad}}' }, command: ['node', '-e', 'private-command-arg'],
    } } }) + '\n');
    await done;
    const result = JSON.parse(text).result;
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toBe('error: command denied by policy: node');
    expect(readFileSync(auditPath, 'utf8')).toBe(beforeAudit);
    expect(readdirSync(tmpdir()).filter(n => (n.startsWith('ws-file-') || n.startsWith('ws-mcp-file-')) && !beforeDirs.has(n))).toEqual([]);
  });
});

test('CLI and MCP exec fail closed on policy errors and support legacy policy_get', async () => {
  const { createServer } = await import('node:net');
  const socket = join(DIR, 'exec-policy-probe.sock');
  let reply: unknown;
  const ops: string[] = [];
  const server = createServer(sock => {
    let buf = '';
    sock.on('data', chunk => {
      buf += chunk.toString();
      if (!buf.includes('\n')) return;
      const request = JSON.parse(buf.slice(0, buf.indexOf('\n')));
      ops.push(request.op);
      sock.end(JSON.stringify(request.op === 'policy_get' ? reply : { env: {} }) + '\n');
    });
  });
  await new Promise<void>(resolve => server.listen(socket, resolve));
  try {
    for (const mcp of [false, true]) {
      for (const response of [{ error: 'policy backend unavailable' }, null, {}, { policy: { exec: { allow: ['node ** middle'] } } }, { error: 'unknown op: policy_get' }]) {
        reply = response;
        ops.length = 0;
        const legacy = (response as any)?.error === 'unknown op: policy_get';
        const argv = mcp ? [join(import.meta.dir, '../src/mcp/server.ts')] : [join(import.meta.dir, '../src/cli/main.ts'), 'exec', '--', 'node', '-e', ''];
        const p = spawn('bun', argv, { env: { ...process.env, WELLSPRING_SOCK: socket }, stdio: ['pipe', 'pipe', 'pipe'] });
        let text = '';
        p.stdout!.on('data', c => text += c);
        const done = new Promise<number | null>((resolve, reject) => { p.once('close', resolve); p.once('error', reject); });
        p.stdin!.end(mcp ? JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'wellspring_exec', arguments: { command: ['node', '-e', ''] } } }) + '\n' : '');
        const code = await done;
        if (mcp) expect(JSON.parse(text).result.isError === true).toBe(!legacy);
        else expect(code === 0).toBe(legacy);
        expect(ops).toEqual(legacy && mcp ? ['policy_get', 'draw_env'] : ['policy_get']);
      }
    }
  } finally {
    await new Promise<void>(resolve => server.close(() => resolve()));
  }
});

// ---- derived artefacts: the key stays in the daemon, only the result crosses ----
test("derive returns artefacts over the socket and never the key material", async () => {
  await rpc({ op: "put", id: "cred:mfa", field: "value", value: "JBSWY3DPEHPK3PXP", token: ADMIN_TOKEN });
  await rpc({ op: "put", id: "cred:sig", field: "key", value: "wellspring-hmac-key", token: ADMIN_TOKEN });
  const totp = await rpc({ op: "derive_totp", ref: "cred:mfa/value", token: ADMIN_TOKEN });
  expect(totp.code).toMatch(/^\d{6}$/);
  expect(typeof totp.remaining).toBe("number");
  const mac = await rpc({ op: "derive_hmac", ref: "cred:sig/key", data: "GET /v1/orders", alg: "sha256", token: ADMIN_TOKEN });
  expect(mac.mac).toMatch(/^[0-9a-f]{64}$/);
  // The whole point: the key itself must not be echoed back in any field.
  const blob = JSON.stringify(totp) + JSON.stringify(mac);
  expect(blob).not.toContain("JBSWY3DPEHPK3PXP");
  expect(blob).not.toContain("wellspring-hmac-key");
  // And an expired credential must not be used as signing material either.
  await rpc({ op: "put", id: "cred:short", field: "key", value: "k", ttlMs: 1000, token: ADMIN_TOKEN });
  await new Promise((r) => setTimeout(r, 1200));
  const expired = await rpc({ op: "derive_hmac", ref: "cred:short/key", data: "x", token: ADMIN_TOKEN });
  expect(expired.error).toContain("expired");
  const events = (await rpc({ op: "audit" })).events.map((l: string) => JSON.parse(l));
  expect(events.some((e: any) => e.op === "derive_hmac" && e.verdict === "expired")).toBe(true);
});

test("derive refuses callers without the admin token, even for a reveal-only op", async () => {
  await rpc({ op: "put", id: "cred:mfa2", field: "value", value: "JBSWY3DPEHPK3PXP", token: ADMIN_TOKEN });
  const denied = await rpc({ op: "derive_totp", ref: "cred:mfa2/value" });
  expect(denied.error).toBe("unauthorized");
  // An unauthenticated caller must learn nothing: not the code, not even whether it is expired.
  expect(JSON.stringify(denied)).not.toContain("expired");
});
