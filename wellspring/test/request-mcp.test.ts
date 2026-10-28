import { test, expect } from 'bun:test';
import { spawn } from 'node:child_process';
import { connect } from 'node:net';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

test('MCP request → private HTTP form → scoped exec returns only ref and redacted output', async () => {
  const home = mkdtempSync(join(tmpdir(), 'ws-request-mcp-'));
  const socket = join(home, 'daemon.sock');
  const env = { ...process.env, WELLSPRING_HOME: home, WELLSPRING_SOCK: socket, WELLSPRING_HTTP_PORT: '0', WELLSPRING_ADMIN_TOKEN: 'request-test-admin' };
  delete env.WELLSPRING_CLIENT_TOKEN;
  const daemon = spawn('bun', ['run', join(import.meta.dir, '../src/daemon/main.ts')], { env, stdio: ['ignore','pipe','pipe'] });
  let log = ''; daemon.stdout!.on('data', c => log += c); daemon.stderr!.on('data', c => log += c);
  const rpc = (msg: object): Promise<any> => new Promise((resolve, reject) => {
    const s = connect(socket); let text = '';
    const timer = setTimeout(() => { s.destroy(); reject(new Error('socket timeout')); }, 5000);
    s.on('connect', () => s.write(JSON.stringify(msg)+'\n'));
    s.on('error', e => { clearTimeout(timer); reject(e); });
    s.on('data', c => { text += c; if (text.includes('\n')) { clearTimeout(timer); s.end(); resolve(JSON.parse(text.split('\n')[0]!)); } });
  });
  let mcp: ReturnType<typeof spawn> | undefined;
  try {
    const deadline = Date.now()+15000; let port = 0;
    while (Date.now()<deadline) {
      const match = /web UI: http:\/\/127\.0\.0\.1:(\d+)/.exec(log);
      if (match) { port = Number(match[1]); break; }
      await new Promise(r => setTimeout(r, 50));
    }
    expect(port, log).toBeGreaterThan(0);
    const html = await (await fetch(`http://127.0.0.1:${port}/?request=example`)).text();
    for (const script of html.matchAll(/<script>([\s\S]*?)<\/script>/g)) expect(() => new Function(script[1]!)).not.toThrow();
    expect(html).toContain('request_fulfill');
    const issued = await rpc({op:'client_issue', caller:'release-agent',token:env.WELLSPRING_ADMIN_TOKEN});
    expect(typeof issued.token).toBe('string');
    mcp = spawn('bun', ['run',join(import.meta.dir,'../src/mcp/server.ts')], {env:{...env,WELLSPRING_CLIENT_TOKEN:issued.token},stdio:['pipe','pipe','pipe']});
    let output = ''; let seq = 0;
    mcp.stdout!.on('data', c => output += c);
    mcp.stderr!.on('data', () => {});
    async function call(name: string, args: object): Promise<any> {
      const id = ++seq;
      mcp!.stdin!.write(JSON.stringify({jsonrpc:'2.0',id,method:'tools/call',params:{name,arguments:args}})+'\n');
      const end = Date.now()+10000;
      while (Date.now()<end) {
        for (const line of output.split('\n').filter(Boolean)) {
          const r = JSON.parse(line); if(r.id===id) return r.result;
        }
        await new Promise(r => setTimeout(r, 20));
      }
      throw new Error('MCP timed out');
    }
    const created = await call('wellspring_request',{label:'Release token',purpose:'publish',target:'github.com',channel:'A1/exec'});
    expect(created.isError).not.toBe(true);
    const request = JSON.parse(created.content[0].text);
    const pending = await call('wellspring_request_status',{requestId:request.requestId});
    expect(JSON.parse(pending.content[0].text).status).toBe('pending');
    const post = (op:string,body:object,auth=true) => fetch(`http://127.0.0.1:${port}/api/${op}`, {method:'POST',headers:{'content-type':'application/json',...(auth?{authorization:`Bearer ${env.WELLSPRING_ADMIN_TOKEN}`}:{})},body:JSON.stringify(body)});
    expect((await post('request_list',{},false)).status).toBe(401);
    const secret = 'synthetic-request-sensitive-79231';
    const response = await post('request_fulfill',{requestId:request.requestId,value:secret,save:false});
    const fulfilled = await response.json();
    expect(fulfilled.status).toBe('fulfilled');
    const ready = await call('wellspring_request_status',{requestId:request.requestId});
    expect(ready.content[0].text).not.toContain(secret);
    const ref = JSON.parse(ready.content[0].text).ref;
    const ran = await call('wellspring_exec',{env:{APP_SECRET:ref},purpose:'publish',target:'github.com',command:['bun','-e',"console.log(process.env.APP_SECRET);console.log('client-token-in-child:'+Boolean(process.env.WELLSPRING_CLIENT_TOKEN))"],output:'redacted'});
    expect(ran.isError, JSON.stringify(ran)).not.toBe(true);
    const result = JSON.parse(ran.content[0].text);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain('[REDACTED]');
    expect(result.stdout).toContain('client-token-in-child:false');
    const denied = await call('wellspring_exec',{env:{APP_SECRET:ref},purpose:'other',target:'github.com',command:['bun','-e','process.exit(0)']});
    expect(denied.isError).toBe(true);
    expect(output).not.toContain(secret);
    expect(readFileSync(join(home,'requests.json'),'utf8')).not.toContain(secret);
    expect(readFileSync(join(home,'draw-events.jsonl'),'utf8')).not.toContain(secret);
  } finally {
    mcp?.kill(); daemon.kill();
    await new Promise(r => daemon.once('close',r));
    rmSync(home,{recursive:true,force:true});
  }
}, 30000);
