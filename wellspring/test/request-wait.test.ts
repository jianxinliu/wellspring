import { test, expect } from 'bun:test';
import { spawn, type ChildProcess } from 'node:child_process';
import { connect } from 'node:net';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

function transport(env: NodeJS.ProcessEnv) {
  const child = spawn(process.execPath, ['run', join(import.meta.dir, '../src/mcp/server.ts')], { env, stdio: ['pipe', 'pipe', 'pipe'] });
  let output = '', errors = '', buffer = '', seq = 0;
  const pending = new Map<number, { resolve: (value: any) => void; reject: (error: Error) => void; timer: ReturnType<typeof setTimeout> }>();
  child.stderr!.on('data', c => errors += c);
  child.stdout!.on('data', c => {
    output += c; buffer += c;
    let i: number;
    while ((i = buffer.indexOf('\n')) >= 0) {
      const message = JSON.parse(buffer.slice(0, i)); buffer = buffer.slice(i + 1);
      const waiter = pending.get(message.id);
      if (waiter) { clearTimeout(waiter.timer); pending.delete(message.id); waiter.resolve(message); }
    }
  });
  child.on('exit', () => {
    for (const waiter of pending.values()) { clearTimeout(waiter.timer); waiter.reject(new Error('MCP exited')); }
    pending.clear();
  });
  function request(method: string, params?: object) {
    const id = ++seq;
    const result = new Promise<any>((resolve, reject) => {
      const timer = setTimeout(() => { pending.delete(id); reject(new Error('MCP timeout')); }, 8000);
      pending.set(id, { resolve, reject, timer });
    });
    child.stdin!.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
    return { id, result };
  }
  const call = (name: string, args: object) => request('tools/call', { name, arguments: args });
  return { child, request, call, output: () => output + errors, cancel: (requestId: number) => child.stdin!.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId } }) + '\n') };
}

function data(message: any) {
  expect(message.error).toBeUndefined();
  expect(message.result.isError, JSON.stringify(message)).not.toBe(true);
  return JSON.parse(message.result.content[0].text);
}

async function stop(child: ChildProcess) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const closed = new Promise(resolve => child.once('close', resolve));
  child.kill(); await closed;
}

test('bounded MCP request wait: fulfill, cancel, expiry, concurrent tools, identity and disconnect', async () => {
  const home = mkdtempSync(join(tmpdir(), 'ws-request-wait-'));
  const socket = join(home, 'daemon.sock');
  const env = { ...process.env, WELLSPRING_HOME: home, WELLSPRING_SOCK: socket, WELLSPRING_HTTP_PORT: '0', WELLSPRING_ADMIN_TOKEN: 'wait-test-admin' };
  delete env.WELLSPRING_CLIENT_TOKEN;
  delete env.WELLSPRING_KEY;
  delete env.WELLSPRING_PASSPHRASE;
  const daemon = spawn(process.execPath, ['run', join(import.meta.dir, '../src/daemon/main.ts')], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  let log = '';
  daemon.stdout!.on('data', c => log += c); daemon.stderr!.on('data', c => log += c);
  const clients: ReturnType<typeof transport>[] = [];
  const rpc = (msg: object): Promise<any> => new Promise((resolve, reject) => {
    const sock = connect(socket); let text = '';
    const timer = setTimeout(() => { sock.destroy(); reject(new Error('daemon timeout')); }, 5000);
    sock.on('connect', () => sock.write(JSON.stringify(msg) + '\n'));
    sock.on('error', e => { clearTimeout(timer); reject(e); });
    sock.on('data', c => { text += c; if (text.includes('\n')) { clearTimeout(timer); sock.end(); resolve(JSON.parse(text.split('\n')[0]!)); } });
  });
  try {
    const deadline = Date.now() + 15000;
    while (!/web UI: http:\/\/127\.0\.0\.1:(\d+)/.test(log) && Date.now() < deadline) await sleep(30);
    const port = /web UI: http:\/\/127\.0\.0\.1:(\d+)/.exec(log)?.[1];
    expect(port, log).toBeDefined();
    const alice = await rpc({ op: 'client_issue', caller: 'alice', token: env.WELLSPRING_ADMIN_TOKEN });
    const bob = await rpc({ op: 'client_issue', caller: 'bob', token: env.WELLSPRING_ADMIN_TOKEN });
    const mcp = transport({ ...env, WELLSPRING_CLIENT_TOKEN: alice.token }); clients.push(mcp);
    const other = transport({ ...env, WELLSPRING_CLIENT_TOKEN: bob.token }); clients.push(other);
    const create = async (ttlMs = 15000) => data(await mcp.call('wellspring_request', { label: 'Test token', purpose: 'wait test', channel: 'A2/fd', ttlMs }).result);
    const post = (op: string, body: object) => fetch(`http://127.0.0.1:${port}/api/${op}`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${env.WELLSPRING_ADMIN_TOKEN}` }, body: JSON.stringify(body) });

    const request = await create();
    const start = performance.now();
    let completed = false;
    const wait = mcp.call('wellspring_request_status', { requestId: request.requestId, waitMs: 5000 });
    void wait.result.then(() => completed = true);
    await sleep(100);
    expect(completed).toBe(false);
    const quick = performance.now();
    const unrelated = await mcp.call('wellspring_list', {}).result;
    expect(unrelated.result.isError).not.toBe(true);
    expect(performance.now() - quick).toBeLessThan(1000);
    const secret = 'private-form-only-982731';
    const filledAt = performance.now();
    expect((await (await post('request_fulfill', { requestId: request.requestId, value: secret, save: false })).json() as any).status).toBe('fulfilled');
    const fulfilled = data(await wait.result);
    expect(fulfilled.status).toBe('fulfilled');
    expect(fulfilled.ref).toMatch(/^secret:\/\//);
    expect(fulfilled.waitTimedOut).toBeUndefined();
    expect(performance.now() - filledAt).toBeLessThan(1000);
    expect(performance.now() - start).toBeLessThan(3000);
    const alreadyAt = performance.now();
    expect(data(await mcp.call('wellspring_request_status', { requestId: request.requestId, waitMs: 55000 }).result).ref).toBe(fulfilled.ref);
    expect(performance.now() - alreadyAt).toBeLessThan(500);

    const defaultRequest = await create();
    const now = performance.now();
    expect(data(await mcp.call('wellspring_request_status', { requestId: defaultRequest.requestId }).result).status).toBe('pending');
    expect(performance.now() - now).toBeLessThan(500);
    const timeoutStart = performance.now();
    const timed = data(await mcp.call('wellspring_request_status', { requestId: defaultRequest.requestId, waitMs: 420 }).result);
    expect(timed.status).toBe('pending'); expect(timed.waitTimedOut).toBe(true);
    expect(performance.now() - timeoutStart).toBeGreaterThanOrEqual(400);
    expect(performance.now() - timeoutStart).toBeLessThan(1000);
    for (const waitMs of [-1, 55001, 0.5, '300', null]) {
      // null is not an integer even though the default applies only to omitted values.
      const invalid = await mcp.call('wellspring_request_status', { requestId: defaultRequest.requestId, waitMs }).result;
      expect(invalid.result.isError).toBe(true);
    }

    const forgedAt = performance.now();
    const forged = await other.call('wellspring_request_status', { requestId: request.requestId, waitMs: 5000, caller: 'alice' }).result;
    expect(forged.result.isError).toBe(true);
    const denied = await other.call('wellspring_request_status', { requestId: request.requestId, waitMs: 5000 }).result;
    expect(denied.result.isError).toBe(true); expect(denied.result.content[0].text).toContain('no such request');
    expect(performance.now() - forgedAt).toBeLessThan(1000);

    const cancelled = await create();
    const cancelWait = mcp.call('wellspring_request_status', { requestId: cancelled.requestId, waitMs: 5000 });
    await sleep(50);
    const cancelAt = performance.now();
    expect(data(await mcp.call('wellspring_request_status', { requestId: cancelled.requestId, cancel: true, waitMs: 55000 }).result).status).toBe('cancelled');
    expect(data(await cancelWait.result).status).toBe('cancelled');
    expect(performance.now() - cancelAt).toBeLessThan(1000);

    const expiry = await create(1000);
    const expiryAt = performance.now();
    expect(data(await mcp.call('wellspring_request_status', { requestId: expiry.requestId, waitMs: 5000 }).result).status).toBe('expired');
    expect(performance.now() - expiryAt).toBeLessThan(2000);

    const aborted = await create();
    const abortWait = mcp.call('wellspring_request_status', { requestId: aborted.requestId, waitMs: 55000 });
    await sleep(50);
    const abortedAt = performance.now();
    mcp.cancel(abortWait.id);
    expect((await abortWait.result).error.code).toBe(-32800);
    expect(performance.now() - abortedAt).toBeLessThan(500);
    // Transport cancellation does not cancel the underlying credential request.
    expect(data(await mcp.call('wellspring_request_status', { requestId: aborted.requestId }).result).status).toBe('pending');

    // Stdio disconnect (stdin EOF) releases a 55-second wait immediately.
    {
      const disconnected = transport({ ...env, WELLSPRING_CLIENT_TOKEN: alice.token }); clients.push(disconnected);
      const hanging = disconnected.call('wellspring_request_status', { requestId: aborted.requestId, waitMs: 55000 });
      void hanging.result.catch(() => {});
      await sleep(100);
      const closed = new Promise(resolve => disconnected.child.once('close', resolve));
      disconnected.child.stdin!.end();
      const bound = setTimeout(() => disconnected.child.kill(), 1200);
      const endedAt = performance.now();
      await closed; clearTimeout(bound);
      expect(disconnected.child.signalCode).toBeNull();
      expect(performance.now() - endedAt).toBeLessThan(1000);
    }
    for (const client of clients) expect(client.output()).not.toContain(secret);
    expect(log).not.toContain(secret);
    for (const name of ['requests.json', 'store.json', 'draw-events.jsonl']) expect(readFileSync(join(home, name), 'utf8')).not.toContain(secret);
  } finally {
    await Promise.all(clients.map(client => stop(client.child)));
    await stop(daemon);
    rmSync(home, { recursive: true, force: true });
  }
}, 30000);
