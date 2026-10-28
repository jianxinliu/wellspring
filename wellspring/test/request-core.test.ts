import { test, expect } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Each scenario runs in a separate process: HOME is set before dynamic imports,
// and this suite never mutates the e2e suite's shared environment/module cache.
function scenario(script: string) {
  const home = mkdtempSync(join(tmpdir(), "wellspring-request-core-"));
  try {
    const out = Bun.spawnSync({ cmd: [process.execPath, "-e", `
      const { handle } = await import(${JSON.stringify(join(import.meta.dir, "../src/daemon/main.ts"))});
      const store = await import(${JSON.stringify(join(import.meta.dir, "../src/core/store.ts"))});
      const fs = await import('node:fs');
      const { join } = await import('node:path');
      const { strict: assert } = await import('node:assert');
      const admin = msg => handle({...msg, token:'request-test-admin'});
      const alice = admin({op:'client_issue',caller:'alice'}).token;
      const bob = admin({op:'client_issue',caller:'bob'}).token;
      const call = msg => handle({...msg,token:alice});
      ${script}
    `], env: { ...process.env, HOME: home, WELLSPRING_HOME: home, WELLSPRING_ADMIN_TOKEN: "request-test-admin", WELLSPRING_KEY: undefined, WELLSPRING_PASSPHRASE: undefined }, timeout: 15000 });
    expect(out.stderr.toString()).toBe("");
    expect(out.exitCode).toBe(0);
  } finally { rmSync(home, { recursive: true, force: true }); }
}

test("scoped bearer identity cannot be forged and discovery filters before decryption", () => scenario(`
  admin({op:'put',id:'cred:hidden',field:'value',value:'private',usePolicy:{callers:['bob']}});
  admin({op:'put',id:'cred:public',field:'value',value:'public'});
  assert.equal(call({op:'draw',ref:'cred:hidden/value',caller:'bob'}).error,'access denied');
  assert.equal(call({op:'describe',id:'cred:hidden',caller:'bob'}).error,'no such entry: cred:hidden');
  assert.equal(call({op:'list'}).descriptors.some(d=>d.ref==='secret://cred:hidden'),false);
  assert.equal(handle({op:'list'}).descriptors.some(d=>d.ref==='secret://cred:public'),true);
  assert.equal(handle({op:'list'}).descriptors.some(d=>d.ref==='secret://cred:hidden'),false);
  for(const op of ['put','access_put','policy_put','resolve','client_issue','request_list']) assert.equal(call({op,caller:'admin'}).error,'unauthorized');
  assert.equal(fs.statSync(join(store.WS_HOME,'client-tokens.json')).mode & 511,384);
`));

test("policy validation, replacement preservation and admin identity", () => scenario(`
  const usePolicy={callers:['alice'],channels:['A2/fd'],purposes:['checkout'],targets:['shop']};
  assert.equal(admin({op:'put',id:'cred:gate',field:'value',value:'first',usePolicy}).ok,true);
  admin({op:'put',id:'cred:gate',field:'value',value:'second'});
  assert.deepEqual(store.describe('cred:gate').fields[0].usePolicy,usePolicy);
  assert.equal(admin({op:'draw',ref:'cred:gate/value',caller:'alice',purpose:'checkout',target:'shop'}).error,'access denied');
  assert.equal(call({op:'draw',ref:'cred:gate/value',purpose:'checkout',target:'shop'}).value,'second');
  assert.equal(call({op:'draw',ref:'cred:gate/value',channel:'invalid',purpose:'checkout',target:'shop'}).error,'invalid delivery channel');
  for (const channel of ['derive_hmac','resolve']) assert.equal(call({op:'draw',ref:'cred:gate/value',channel,purpose:'checkout',target:'shop'}).error,'invalid draw channel');
  assert.equal(call({op:'draw',ref:'cred:gate/value',purpose:'Checkout',target:'shop'}).error,'access denied');
  for(const policy of [null,{callers:[]},{channels:['']},{purposes:[1]},{targets:Array(101).fill('x')},{other:['x']}]) assert.ok(admin({op:'access_put',id:'cred:gate',field:'value',usePolicy:policy}).error);
  assert.equal(admin({op:'access_put',id:'cred:gate',field:'value',usePolicy:{}}).ok,true);
  assert.equal(admin({op:'draw',ref:'cred:gate/value'}).value,'second');
`));

test("denied source gates and env preflight execute no command; one-shot binds intent", () => scenario(`
  const marker=join(store.WS_HOME,'source-read');
  const source={kind:'command',ref:'printf x >> '+marker+'; printf secret'};
  admin({op:'put_source',id:'cred:source',field:'value',source,usePolicy:{callers:['admin'],channels:['A1/exec','derive_hmac','git/askpass'],purposes:['deploy'],targets:['prod']}});
  fs.unlinkSync(marker); // registration probes source once, draws must preflight.
  const ref='cred:source/value';
  assert.equal(call({op:'draw',ref,channel:'git/askpass',purpose:'deploy',target:'prod'}).error,'access denied');
  assert.equal(admin({op:'derive_hmac',ref,data:'data',purpose:'wrong',target:'prod'}).error,'access denied');
  assert.equal(admin({op:'auth_issue_oneshot',ref,channel:'git/askpass',purpose:'wrong',target:'prod'}).error,'access denied');
  admin({op:'put',id:'cred:denied',field:'value',value:'x',usePolicy:{callers:['other']}});
  assert.equal(admin({op:'draw_env',env:{FIRST:ref,SECOND:'cred:denied/value'},purpose:'deploy',target:'prod'}).error,'access denied');
  assert.equal(fs.existsSync(marker),false);
  const token=admin({op:'auth_issue_oneshot',ref,channel:'git/askpass',purpose:'deploy',target:'prod'}).token;
  assert.ok(token); assert.equal(fs.existsSync(marker),false);
  assert.equal(handle({op:'draw',ref,channel:'git/askpass',token,purpose:'forged',target:'different'}).value,'secret');
  assert.equal(handle({op:'draw',ref,channel:'git/askpass',token}).error,'unauthorized');
  assert.ok(fs.readFileSync(join(store.WS_HOME,'draw-events.jsonl'),'utf8').includes('denied_access'));
  admin({op:'put',id:'cred:clientgit',field:'value',value:'client-git',usePolicy:{callers:['alice'],channels:['git/askpass'],purposes:['push']}});
  assert.ok(call({op:'policy_get'}).policy);
  assert.equal(call({op:'auth_issue_oneshot',ref:'cred:clientgit/value',channel:'git/askpass',purpose:'wrong'}).error,'access denied');
  const clientGrant=call({op:'auth_issue_oneshot',ref:'cred:clientgit/value',channel:'git/askpass',purpose:'push'}).token;
  assert.ok(clientGrant);
  assert.equal(handle({op:'draw',ref:'cred:clientgit/value',channel:'git/askpass',token:clientGrant,purpose:'forged'}).value,'client-git');
`));

test("requests owner/admin, first fulfill wins, policy binding and encrypted persistence", () => scenario(`
  const request=call({op:'request_create',label:'Database',purpose:'deploy',target:'prod',channel:'A2/fd'});
  assert.equal(request.status,'pending'); assert.equal(request.ref,undefined);
  assert.equal(call({op:'request_create',label:'x',purpose:'x',channel:'A2/fd',value:'forbidden'}).error,'invalid request arguments');
  assert.equal(call({op:'request_fulfill',requestId:request.requestId,value:'secret-plaintext-777',save:false}).error,'unauthorized');
  assert.equal(handle({op:'request_status',requestId:request.requestId,token:bob,caller:'alice'}).error,'no such request');
  const done=admin({op:'request_fulfill',requestId:request.requestId,value:'secret-plaintext-777',save:false});
  assert.equal(done.status,'fulfilled'); assert.ok(done.ref);
  assert.equal(admin({op:'request_fulfill',requestId:request.requestId,value:'second',save:false}).error,'request is not pending');
  assert.equal(call({op:'request_status',requestId:request.requestId}).ref,done.ref);
  assert.equal(call({op:'draw',ref:done.ref,purpose:'deploy',target:'prod'}).value,'secret-plaintext-777');
  assert.equal(call({op:'draw',ref:done.ref,purpose:'wrong',target:'prod'}).error,'access denied');
  for(const path of ['requests.json','store.json','draw-events.jsonl']) assert.equal(fs.readFileSync(join(store.WS_HOME,path),'utf8').includes('secret-plaintext-777'),false);
  assert.equal(fs.statSync(join(store.WS_HOME,'requests.json')).mode & 511,384);
  const child=Bun.spawnSync({cmd:[process.execPath,'-e', 'const {handle}=await import('+JSON.stringify(${JSON.stringify(join(import.meta.dir, "../src/daemon/main.ts"))})+'); console.log(JSON.stringify(handle({op:"request_status",requestId:'+JSON.stringify(request.requestId)+',token:'+JSON.stringify(alice)+'})))'],env:{...process.env}});
  assert.equal(child.exitCode,0); assert.equal(JSON.parse(child.stdout.toString()).ref,done.ref);
`));

test("requests expiry cleans temporary values and cancellation and collision are final", () => scenario(`
  const create=()=>call({op:'request_create',label:'one',purpose:'test',channel:'A2/fd',ttlMs:1000});
  const expired=create(); const temporary=create();
  const done=admin({op:'request_fulfill',requestId:temporary.requestId,value:'temp',save:false});
  const cancelled=create(); assert.equal(call({op:'request_cancel',requestId:cancelled.requestId}).status,'cancelled');
  assert.equal(admin({op:'request_fulfill',requestId:cancelled.requestId,value:'x',save:false}).error,'request is not pending');
  admin({op:'put',id:'cred:collision',field:'value',value:'original'});
  const collision=create();
  assert.equal(admin({op:'request_fulfill',requestId:collision.requestId,value:'replacement',save:true,id:'cred:collision'}).error,'request destination already exists');
  assert.equal(store.getSecret('cred:collision','value'),'original');
  const realNow=Date.now; Date.now=()=>realNow()+2000;
  assert.equal(call({op:'request_status',requestId:expired.requestId}).status,'expired');
  assert.equal(admin({op:'request_fulfill',requestId:expired.requestId,value:'late',save:false}).error,'request is not pending');
  assert.equal(call({op:'request_status',requestId:temporary.requestId}).status,'expired');
  assert.equal(store.hasEntry(done.ref.replace('secret://','').split('/')[0]),false);
  assert.equal(call({op:'request_cancel',requestId:expired.requestId}).error,'request is not pending');
  Date.now=realNow;
`));
