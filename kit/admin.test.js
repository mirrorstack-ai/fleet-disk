// The admin routes (/_k/*): kit-admin-v1 Ed25519 signatures, role separation,
// write-once uploads through R2, the gateway pair, invites and the floor.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { sha256Hex } from './worker-util.js';
import {
  makeHarness, ready, get, read, bytesOf, admin, addInvite, uploadBundle, uploadGateway, jsonOf, CODE, day,
} from './worker-harness.test-util.js';

const NF = 'not found\n';
const dec = (b) => new TextDecoder().decode(b);
async function is404(res) {
  const r = await read(res);
  assert.equal(r.status, 404);
  assert.equal(dec(r.body), NF);
  assert.deepEqual(Object.fromEntries(r.headers), { 'content-type': 'text/plain', 'cache-control': 'no-store, no-transform' });
}
const failures = (h) => h.q('SELECT COALESCE(SUM(n), 0) AS n FROM allfails')[0].n;
const state = async (h) => jsonOf(await admin(h, 'gateway', 'GET', '/_k/state'));

test('state: the gateway role reads health, counts only', async () => {
  const h = await ready({}, bytesOf(1000));
  const res = await admin(h, 'gateway', 'GET', '/_k/state');
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('cache-control'), 'no-store, no-transform');
  const s = await jsonOf(res);
  assert.equal(s.ok, true);
  assert.equal(s.openInvites, 1);
  assert.equal(s.bundles, 1);
  assert.equal(s.floorError, false);
  assert.ok(!JSON.stringify(s).includes('ref-0000'));
});

test('a bad or unsigned call is the one 404, spends no budget and reaches no admin op', async () => {
  const h = await ready({}, bytesOf(1000));
  const base = h.calls.admin;
  const ok = JSON.stringify({ floor: 1 });
  const stale = Date.now() - 6 * 60 * 1000;
  const calls = [
    admin(h, 'upload', 'PUT', '/_k/floor', ok, { noAuth: true }),
    admin(h, 'upload', 'PUT', '/_k/floor', ok, { auth: 'KitAdmin upload 1 x' }),
    admin(h, 'upload', 'PUT', '/_k/floor', ok, { auth: 'Bearer abc' }),
    admin(h, 'upload', 'PUT', '/_k/floor', ok, { keyRole: 'gateway' }), // signed with the other role's key
    admin(h, 'gateway', 'POST', '/_k/invite', '{}', { keyRole: 'upload' }),
    admin(h, 'upload', 'PUT', '/_k/floor', ok, { signedRole: 'gateway' }),
    admin(h, 'upload', 'PUT', '/_k/floor', ok, { digest: '0'.repeat(64) }), // signature over another body
    admin(h, 'upload', 'PUT', '/_k/floor', ok, { signedPath: '/_k/state' }),
    admin(h, 'upload', 'PUT', '/_k/floor', ok, { signedMethod: 'POST' }),
    admin(h, 'upload', 'PUT', '/_k/floor', ok, { ts: stale }),
    admin(h, 'upload', 'PUT', '/_k/floor', ok, { ts: Date.now() + 6 * 60 * 1000 }),
    admin(h, 'upload', 'PUT', '/_k/floor?x=1', ok),
    admin(h, 'upload', 'PUT', '/_k/nothing', ok),
    admin(h, 'upload', 'GET', '/_k/floor'),
    admin(h, 'upload', 'PUT', '/_k/floor', 'x'.repeat(2000)), // over the body cap
    admin(h, 'upload', 'PUT', '/_k/file/5/bundle.tar', bytesOf(10), { stream: true, digest: 'nothex' }),
  ];
  for (const c of calls) await is404(await c);
  assert.equal(h.calls.admin, base);
  assert.equal(failures(h), 0);
  // a key that is not configured switches that role off
  const keyless = await makeHarness({ KIT_UP_PUB: '' });
  await is404(await admin(keyless, 'upload', 'PUT', '/_k/floor', ok));
  const badKey = await makeHarness({ KIT_GW_PUB: 'zz' });
  await is404(await admin(badKey, 'gateway', 'GET', '/_k/state'));
});

test('replay: a timestamp must be strictly greater than the role\'s last one', async () => {
  const h = await ready({}, bytesOf(1000));
  const ts = Date.now() + 60000;
  const body = JSON.stringify({ floor: 1 });
  assert.equal((await admin(h, 'upload', 'PUT', '/_k/floor', body, { ts })).status, 200);
  const again = await admin(h, 'upload', 'PUT', '/_k/floor', body, { ts });
  assert.equal(again.status, 409);
  assert.equal((await jsonOf(again)).error, 'replay');
  assert.equal((await admin(h, 'upload', 'PUT', '/_k/floor', body, { ts: ts - 1 })).status, 409);
  assert.equal((await admin(h, 'upload', 'PUT', '/_k/floor', body, { ts: ts + 1 })).status, 200);
  // roles keep separate clocks
  assert.equal((await admin(h, 'gateway', 'GET', '/_k/state', null, { ts: ts - 5 })).status, 200);
});

test('each role calls only its own routes', async () => {
  const h = await ready({}, bytesOf(1000));
  const forbidden = async (res) => {
    assert.equal(res.status, 403);
    assert.equal((await jsonOf(res)).error, 'forbidden');
  };
  await forbidden(await admin(h, 'upload', 'POST', '/_k/invite', '{}'));
  await forbidden(await admin(h, 'upload', 'GET', '/_k/state'));
  await forbidden(await admin(h, 'upload', 'DELETE', '/_k/invite/ref-00000001'));
  await forbidden(await admin(h, 'gateway', 'PUT', '/_k/floor', '{"floor":1}'));
  await forbidden(await admin(h, 'gateway', 'PUT', '/_k/gateway/1', '{}'));
  await forbidden(await admin(h, 'gateway', 'PUT', '/_k/file/6/bundle.tar', bytesOf(10), { stream: true }));
  assert.equal(h.env.KIT.objs.size, 1); // the gateway role wrote nothing
  assert.equal((await state(h)).openInvites, 1); // nothing moved
});

test('bundle upload: R2 writes it once, identical bytes get 200, other bytes 409', async () => {
  const h = await makeHarness();
  const a = bytesOf(5000, 1);
  const first = await uploadBundle(h, 7, a);
  assert.equal(first.status, 200);
  assert.deepEqual(await jsonOf(first), { ok: true, created: true, key: 'kit/7/bundle.tar' });
  assert.deepEqual(h.env.KIT.objs.get('kit/7/bundle.tar').bytes, a);
  const rerun = await uploadBundle(h, 7, a);
  assert.equal(rerun.status, 200);
  assert.equal((await jsonOf(rerun)).created, false);
  const other = await uploadBundle(h, 7, bytesOf(5000, 2));
  assert.equal(other.status, 409);
  assert.deepEqual(h.env.KIT.objs.get('kit/7/bundle.tar').bytes, a); // untouched
  assert.deepEqual(h.q('SELECT serial, size FROM files'), [{ serial: 7, size: 5000 }]);
});

test('bundle upload: bytes that are not the signed digest are refused by R2 and nothing is stored or recorded', async () => {
  const h = await makeHarness();
  const res = await uploadBundle(h, 7, bytesOf(100), { digest: await sha256Hex(bytesOf(100, 9)) });
  assert.equal(res.status, 422);
  assert.equal(h.env.KIT.objs.size, 0);
  assert.equal(h.q('SELECT * FROM files').length, 0);
});

test('bundle upload: length is required and capped', async () => {
  const h = await makeHarness();
  assert.equal((await uploadBundle(h, 7, bytesOf(10), { contentLength: null })).status, 411);
  assert.equal((await uploadBundle(h, 7, bytesOf(10), { contentLength: 100 * 1024 * 1024 + 1 })).status, 413);
  await is404(await uploadBundle(h, 0, bytesOf(10))); // serials start at 1: no route, nothing written
  assert.equal(h.env.KIT.objs.size, 0);
});

test('gateway pair: written to R2 first, then one atomic pointer flip; no rollback, no rewrite', async () => {
  const h = await makeHarness();
  const j1 = new TextEncoder().encode('{"v":1}');
  const s1 = new TextEncoder().encode('sig-1');
  const first = await uploadGateway(h, 3, j1, s1);
  assert.equal(first.status, 200);
  assert.deepEqual([...h.env.KIT.objs.keys()].sort(), ['kit/gateway/3/gateway.json', 'kit/gateway/3/gateway.json.sig']);
  assert.equal((await state(h)).gateway, 3);
  const same = await uploadGateway(h, 3, j1, s1);
  assert.equal(same.status, 200);
  assert.equal((await jsonOf(same)).created, false);
  assert.equal((await uploadGateway(h, 3, new TextEncoder().encode('{"v":2}'), s1)).status, 409); // same serial, other bytes
  const old = await uploadGateway(h, 2, j1, s1);
  assert.equal(old.status, 409); // a lower serial: replay of an old file
  assert.equal((await jsonOf(old)).error, 'rollback');
  assert.equal((await state(h)).gateway, 3);
  assert.equal((await uploadGateway(h, 4, new TextEncoder().encode('{"v":4}'), new TextEncoder().encode('sig-4'))).status, 200);
  assert.equal((await state(h)).gateway, 4);
});

test('gateway pair: refuses malformed or oversize bodies', async () => {
  const h = await makeHarness();
  const ok = new TextEncoder().encode('x');
  for (const body of ['not json', '[]', '{"json":"!!!!","sig":"eA=="}', '{"json":"eA==","sig":""}', '{"json":"eA=="}', '{"json":"eB==","sig":"eA=="}']) {
    const res = await admin(h, 'upload', 'PUT', '/_k/gateway/1', body);
    assert.equal(res.status, 400, body);
  }
  assert.equal((await uploadGateway(h, 1, new Uint8Array(65537).fill(97), ok)).status, 400);
  assert.equal((await uploadGateway(h, 1, ok, new Uint8Array(4097).fill(97))).status, 400);
  assert.equal(h.env.KIT.objs.size, 0);
});

test('invites: the Worker keeps only the tag; ceilings and tombstones come from the Gate', async () => {
  const h = await makeHarness();
  const exp = Date.now() + day;
  const add = await addInvite(h, { exp });
  assert.equal(add.status, 200);
  assert.deepEqual(await jsonOf(add), { ok: true, created: true });
  const row = h.q('SELECT * FROM invites')[0];
  assert.ok(!JSON.stringify(row).includes(CODE));
  assert.equal(h.q('SELECT * FROM invites').length, 1);
  assert.equal((await addInvite(h, { code: 'bad' })).status, 400);
  assert.equal((await addInvite(h, { code: undefined })).status, 400);
  assert.equal((await addInvite(h, { ref: 'ref-00000002', code: 'MMMM3333RR', cap: 11 })).status, 422);
  assert.equal((await addInvite(h, { ref: 'ref-00000002', code: 'MMMM3333RR', exp: Date.now() + 4 * day })).status, 422);
  assert.equal((await addInvite(h, { exp })).status, 200); // the same record again is a no-op
  const rev = await admin(h, 'gateway', 'DELETE', '/_k/invite/ref-00000001');
  assert.deepEqual(await jsonOf(rev), { ok: true, existed: true });
  const back = await addInvite(h, { exp });
  assert.equal(back.status, 409);
  assert.equal((await jsonOf(back)).error, 'revoked');
  await admin(h, 'gateway', 'DELETE', '/_k/invite/ref-0000zzzz'); // unknown: a tombstone
  assert.equal((await addInvite(h, { ref: 'ref-0000zzzz', code: 'RRRR6666WW' })).status, 409);
  const A = '23456789CFGHJMPQRVWX';
  for (let i = 0; i < 16; i++) {
    const r = await addInvite(h, { ref: `open-ref-${i}`, code: `GGGGGGGG${A[i]}${A[(i + 1) % 20]}` });
    assert.equal(r.status, 200, `invite ${i}`);
  }
  const over = await addInvite(h, { ref: 'open-ref-16', code: `GGGGGGGG${A[16]}${A[17]}` });
  assert.equal(over.status, 422);
  assert.equal((await jsonOf(over)).error, 'ceiling-open');
});

test('floor: the upload role sets it and a lower serial stops being served', async () => {
  const h = await ready({}, bytesOf(2000));
  assert.equal((await get(h, '/v1/kit/5/bundle.tar')).status, 200);
  const res = await admin(h, 'upload', 'PUT', '/_k/floor', '{"floor":6}');
  assert.equal(res.status, 200);
  await is404(await get(h, '/v1/kit/5/bundle.tar'));
  assert.equal((await admin(h, 'upload', 'PUT', '/_k/floor', '{"floor":"x"}')).status, 400);
  assert.equal((await state(h)).effectiveFloor, 6);
});

test('a Gate that fails answers admin calls 503', async () => {
  const h = await ready({}, bytesOf(1000));
  h.broken = true;
  const res = await admin(h, 'gateway', 'GET', '/_k/state');
  assert.equal(res.status, 503);
  assert.equal((await jsonOf(res)).error, 'unavailable');
});

test('wrangler.jsonc: the deploy settings the K6 gate reads back, and no break-glass variable', () => {
  const text = readFileSync(new URL('./wrangler.jsonc', import.meta.url), 'utf8');
  const cfg = JSON.parse(text.split('\n').filter((l) => !l.trim().startsWith('//')).join('\n'));
  assert.ok(!/KIT_DISABLED|KIT_FLOOR|INVITE_PEPPER/.test(text.split('\n').filter((l) => !l.trim().startsWith('//')).join('\n')));
  const envs = { production: cfg, staging: cfg.env.staging };
  assert.deepEqual(Object.keys(cfg.env), ['staging']);
  assert.equal(cfg.name, 'fleet-kit');
  assert.equal(cfg.env.staging.name, 'fleet-kit-staging');
  assert.match(cfg.compatibility_date, /^\d{4}-\d{2}-\d{2}$/);
  assert.ok(cfg.compatibility_date >= '2024-04-03'); // Durable Object RPC
  assert.equal(cfg.main, 'worker.js');
  for (const [name, c] of Object.entries(envs)) {
    assert.equal(c.workers_dev, true, name);
    assert.equal(c.preview_urls, false, name);
    assert.deepEqual(c.observability, { enabled: false }, name);
    assert.equal(c.logpush, false, name);
    assert.equal(c.keep_vars, true, name);
    assert.equal(c.tail_consumers, undefined, name);
    assert.equal(c.routes, undefined, name);
    assert.equal(c.route, undefined, name);
    assert.deepEqual(c.durable_objects.bindings, [{ name: 'GATE', class_name: 'Gate' }], name);
    assert.deepEqual(c.migrations, [{ tag: 'v1', new_sqlite_classes: ['Gate'] }], name);
    assert.deepEqual(Object.keys(c.vars).sort(), ['KIT_GW_PUB', 'KIT_UP_PUB'], name);
    assert.deepEqual(Object.values(c.vars), ['', ''], name); // placeholders until go-live (K11)
    assert.equal(c.r2_buckets.length, 1, name);
    assert.equal(c.r2_buckets[0].binding, 'KIT', name);
  }
  assert.equal(cfg.r2_buckets[0].bucket_name, 'fleet-kit');
  assert.equal(cfg.env.staging.r2_buckets[0].bucket_name, 'fleet-kit-staging');
});
