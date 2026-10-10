// The public route of the Worker front: the front shape check, the fixed
// answers, one Gate call, what happens after the gate, streaming and release.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { sha256Hex } from './worker-util.js';
import {
  ready, get, read, bytesOf, admin, addInvite, uploadGateway, jsonOf, CODE, fixedLengths, streamOf,
} from './worker-harness.test-util.js';

const BUNDLE = '/v1/kit/5/bundle.tar';

async function assert404(res) {
  const r = await read(res);
  assert.equal(r.status, 404);
  assert.equal(new TextDecoder().decode(r.body), 'not found\n');
  const h = Object.fromEntries(r.headers);
  assert.equal(h['content-type'], 'text/plain');
  assert.equal(h['cache-control'], 'no-store, no-transform');
  assert.deepEqual(Object.keys(h).sort(), ['cache-control', 'content-type']);
}

const failures = (h) => h.q('SELECT COALESCE(SUM(n), 0) AS n FROM allfails')[0].n;
const used = (h) => h.q('SELECT used, refunds FROM invites')[0];

test('a good request gets the exact bytes, the headers, and one reserved download', async () => {
  const h = await ready();
  const res = await get(h, BUNDLE, { headers: { range: 'bytes=10-20', 'accept-encoding': 'gzip' } });
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('content-type'), 'application/octet-stream');
  assert.equal(res.headers.get('cache-control'), 'no-store, no-transform');
  assert.equal(res.headers.get('content-encoding'), null);
  assert.equal(res.headers.get('content-range'), null); // Range is ignored: the whole object, status 200
  const body = new Uint8Array(await res.arrayBuffer());
  assert.deepEqual(body, h.bytes);
  await h.settle();
  assert.deepEqual(used(h), { used: 1, refunds: 0 });
  assert.equal(failures(h), 0);
  assert.deepEqual(h.calls.hints[h.calls.hints.length - 1], ['id:gate', { locationHint: 'apac' }]);
});

test('the front check: every malformed request is the one 404, with no Gate call and no budget', async () => {
  const h = await ready();
  const before = h.calls.namespace; // setup used the admin path
  const cases = [
    ['POST', BUNDLE, {}],
    ['HEAD', BUNDLE, {}],
    ['PUT', BUNDLE, {}],
    ['GET', `${BUNDLE}?`, {}],
    ['GET', `${BUNDLE}?x=1`, {}],
    ['GET', '/v1/kit/5/bundle.tar/', {}],
    ['GET', '/V1/kit/5/bundle.tar', {}],
    ['GET', '/v1/kit/5/%62undle.tar', {}],
    ['GET', '/v1/kit/5/bundle.TAR', {}],
    ['GET', '/v1/kit/1234567890/bundle.tar', {}],
    ['GET', '/v1/kit//bundle.tar', {}],
    ['GET', '/v1/kit/a/bundle.tar', {}],
    ['GET', '/v1/kit/-1/bundle.tar', {}],
    ['GET', '/v1/kit/5/gateway.json.sig2', {}],
    ['GET', '/v1/kit/5/other', {}],
    ['GET', '/v1/kit/5', {}],
    ['GET', '/', {}],
    ['GET', '/_k', {}],
    ['GET', BUNDLE, { code: null }],
    ['GET', BUNDLE, { auth: 'Bearer CCCC2222VV' }],
    ['GET', BUNDLE, { auth: 'fleetinvite CCCC2222VV' }],
    ['GET', BUNDLE, { auth: 'FleetInvite  CCCC2222VV' }],
    ['GET', BUNDLE, { auth: 'FleetInvite CCCC2222V' }],
    ['GET', BUNDLE, { auth: 'FleetInvite CCCC2222VVV' }],
    ['GET', BUNDLE, { auth: 'FleetInvite cccc2222vv' }],
    ['GET', BUNDLE, { auth: 'FleetInvite CCCC2222V0' }], // 0 is not in the alphabet
    ['GET', BUNDLE, { auth: 'FleetInvite CCCC2222VI' }],
    ['GET', BUNDLE, { auth: 'FleetInvite CCCC2222VV, FleetInvite CCCC2222VV' }],
    ['GET', BUNDLE, { code: null, headers: { 'x-fleet-invite': CODE } }], // the old header name
  ];
  for (const [method, path, o] of cases) {
    await assert404(await get(h, path, { method, ...o }));
  }
  assert.equal(h.calls.namespace, before);
  assert.equal(h.calls.decide, 0);
  assert.equal(failures(h), 0);
  // ... and they stay 404 (never 429) with the source's well-formed budget spent
  for (let i = 0; i < 30; i++) await get(h, BUNDLE, { code: 'WWWW2222HH' });
  assert.equal((await get(h, BUNDLE)).status, 429);
  await assert404(await get(h, `${BUNDLE}?`));
  await assert404(await get(h, BUNDLE, { auth: 'nope' }));
});

test('every failed decision is the same 404 and exactly one budget write', async () => {
  const h = await ready();
  await addInvite(h, { ref: 'ref-00000002', code: 'MMMM3333RR', lo: 6, hi: 9 }).then(jsonOf);
  await addInvite(h, { ref: 'ref-00000003', code: 'PPPP4444QQ', exp: Date.now() + 1000 });
  await admin(h, 'gateway', 'DELETE', '/_k/invite/ref-00000003');
  const bad = [
    [BUNDLE, 'WWWW2222HH'], // unknown code
    [BUNDLE, 'PPPP4444QQ'], // revoked
    [BUNDLE, 'MMMM3333RR'], // serial out of the invite's range
    ['/v1/kit/6/bundle.tar', CODE], // no such bundle
    ['/v1/kit/5/gateway.json', CODE], // no gateway pair yet
  ];
  let n = 0;
  for (const [path, code] of bad) {
    await assert404(await get(h, path, { code }));
    n++;
    assert.equal(failures(h), n);
  }
  assert.deepEqual(used(h), { used: 0, refunds: 0 });
  assert.equal((await get(h, BUNDLE)).status, 200); // a good one still works
});

test('30 failures from one source is a 429 that writes nothing, other sources still served', async () => {
  const h = await ready();
  for (let i = 0; i < 30; i++) await assert404(await get(h, BUNDLE, { code: 'WWWW2222HH' }));
  const spent = failures(h);
  const res = await read(await get(h, BUNDLE)); // a VALID invite from the spent source
  assert.equal(res.status, 429);
  assert.equal(new TextDecoder().decode(res.body), 'try later\n');
  assert.deepEqual(Object.fromEntries(res.headers), { 'content-type': 'text/plain', 'cache-control': 'no-store, no-transform' });
  assert.equal(failures(h), spent); // nothing written
  assert.equal((await get(h, BUNDLE, { ip: '198.51.100.7' })).status, 200);
});

test('the source key is an HMAC: no raw address in the Gate, IPv6 per /64, mapped IPv4 as IPv4', async () => {
  const h = await ready();
  const miss = (ip) => get(h, BUNDLE, { code: 'WWWW2222HH', ip });
  await miss('203.0.113.9');
  await miss('2001:db8:1:2:aaaa:bbbb:cccc:dddd');
  await miss('2001:DB8:1:2::1'); // same /64
  await miss('2001:db8:1:3::1'); // another /64
  await miss('::ffff:203.0.113.9'); // the first IPv4 again
  const rows = h.q('SELECT src, SUM(n) AS n FROM fails GROUP BY src');
  assert.deepEqual(rows.map((r) => r.n).sort(), [1, 2, 2]);
  for (const r of rows) {
    assert.match(r.src, /^[0-9a-f]{16}$/);
  }
  const dump = JSON.stringify([h.q('SELECT * FROM fails'), h.q('SELECT * FROM invites'), h.q('SELECT * FROM meta')]);
  for (const s of ['203.0.113', '2001', 'db8', CODE, 'CCCC2222VV']) assert.ok(!dump.includes(s), s);
});

test('a stored invite is an HMAC tag under the pepper, never the code or its plain sha256', async () => {
  const h = await ready();
  const tag = h.q('SELECT tag FROM invites')[0].tag;
  assert.match(tag, /^[0-9a-f]{64}$/);
  assert.notEqual(tag, await sha256Hex(new TextEncoder().encode(CODE)));
  const other = await ready({ INVITE_PEPPER: 'another-pepper-0123456789abc' });
  assert.notEqual(other.q('SELECT tag FROM invites')[0].tag, tag);
});

test('KIT_DISABLED (any non-empty value) makes every request the 404 and touches nothing', async () => {
  const h = await ready();
  h.env.KIT_DISABLED = '1';
  const ns = h.calls.namespace;
  await assert404(await get(h, BUNDLE));
  await assert404(await addInvite(h, { ref: 'ref-00000009', code: 'GGGG5555JJ' }));
  assert.equal(h.calls.namespace, ns);
  h.env.KIT_DISABLED = '';
  assert.equal((await get(h, BUNDLE)).status, 200);
  delete h.env.KIT_DISABLED;
  assert.equal((await get(h, BUNDLE)).status, 200);
});

test('the cap of 10 holds, and the 11th is a 404', async () => {
  const h = await ready({}, bytesOf(5000));
  for (let i = 0; i < 10; i++) assert.equal((await get(h, BUNDLE)).status, 200);
  await assert404(await get(h, BUNDLE));
  assert.deepEqual(used(h), { used: 10, refunds: 0 });
});

test('the gateway pair is served behind a live invite and never counts against the cap', async () => {
  const h = await ready({}, bytesOf(5000));
  const gj = new TextEncoder().encode('{"gateway":1}');
  const gs = new TextEncoder().encode('SIGNATURE-BYTES');
  assert.equal((await uploadGateway(h, 1, gj, gs)).status, 200);
  for (let i = 0; i < 12; i++) {
    const a = await get(h, '/v1/kit/5/gateway.json');
    assert.equal(a.status, 200);
    assert.deepEqual(new Uint8Array(await a.arrayBuffer()), gj);
  }
  const b = await get(h, '/v1/kit/5/gateway.json.sig');
  assert.deepEqual(new Uint8Array(await b.arrayBuffer()), gs);
  assert.deepEqual(used(h), { used: 0, refunds: 0 });
});

test('after a yes, an R2 miss, wrong size, wrong sha256 or error is the same 404, one budget write, count released', async () => {
  const faults = {
    missing: (h) => h.env.KIT.objs.delete('kit/5/bundle.tar'),
    'wrong size': (h) => { const o = h.env.KIT.objs.get('kit/5/bundle.tar'); o.bytes = o.bytes.slice(1); },
    'wrong sha256': (h) => { h.env.KIT.objs.get('kit/5/bundle.tar').sha = 'f'.repeat(64); },
    'r2 error': (h) => { h.env.KIT.failGet = true; },
  };
  for (const [name, inject] of Object.entries(faults)) {
    const h = await ready({}, bytesOf(3000));
    inject(h);
    await assert404(await get(h, BUNDLE));
    assert.equal(failures(h), 1, name);
    assert.deepEqual(used(h), { used: 0, refunds: 0 }, name); // released, and not a refund
    assert.equal(h.calls.reject, 1, name);
  }
});

test('a client that cuts the stream gets the count back, at most 3 times per invite', async () => {
  const h = await ready({}, bytesOf(1 << 20));
  for (let i = 1; i <= 4; i++) {
    const res = await get(h, BUNDLE);
    assert.equal(res.status, 200);
    const reader = res.body.getReader();
    await reader.read();
    await reader.cancel();
    await h.settle();
    // 3 refunds are given; the 4th cut stays spent
    assert.deepEqual(used(h), i <= 3 ? { used: 0, refunds: i } : { used: 1, refunds: 3 });
  }
  assert.equal(h.calls.release, 4);
});

test('a download that completes is not released', async () => {
  const h = await ready({}, bytesOf(100000));
  await (await get(h, BUNDLE)).arrayBuffer();
  await h.settle();
  assert.equal(h.calls.release, 0);
  assert.deepEqual(used(h), { used: 1, refunds: 0 });
});

test('503 only when the Gate call itself fails, the same for every well-formed request', async () => {
  const h = await ready();
  h.broken = true;
  for (const [path, code] of [[BUNDLE, CODE], [BUNDLE, 'WWWW2222HH'], ['/v1/kit/7/gateway.json', CODE]]) {
    const r = await read(await get(h, path, { code }));
    assert.equal(r.status, 503);
    assert.equal(new TextDecoder().decode(r.body), 'unavailable\n');
    assert.deepEqual(Object.fromEntries(r.headers), { 'content-type': 'text/plain', 'cache-control': 'no-store, no-transform' });
  }
  await assert404(await get(h, `${BUNDLE}?`)); // malformed is still the 404 and never reached the Gate
  h.broken = false;
  const noPepper = await ready();
  delete noPepper.env.INVITE_PEPPER;
  assert.equal((await get(noPepper, BUNDLE)).status, 503);
});

test('when the budget write after a fault cannot be made the answer is still the 404', async () => {
  const h = await ready({}, bytesOf(3000));
  h.env.KIT.objs.delete('kit/5/bundle.tar');
  h.gate.reject = async () => { throw new Error('storage'); };
  await assert404(await get(h, BUNDLE));
});

test('KIT_FLOOR: a serial below it is a 404, an unreadable value fails closed', async () => {
  const h = await ready({}, bytesOf(3000));
  h.env.KIT_FLOOR = '6';
  await assert404(await get(h, BUNDLE));
  h.env.KIT_FLOOR = '5';
  assert.equal((await get(h, BUNDLE, { ip: '198.51.100.1' })).status, 200);
  h.env.KIT_FLOOR = 'abc';
  await assert404(await get(h, BUNDLE, { ip: '198.51.100.2' }));
});

test('worker.js exports exactly the fetch handler and the Gate class, and never logs', async () => {
  const mod = await import('./worker.js');
  assert.deepEqual(Object.keys(mod).sort(), ['Gate', 'default']);
  assert.deepEqual(Object.keys(mod.default), ['fetch']);
  const files = readdirSync(new URL('.', import.meta.url)).filter((f) => f.endsWith('.js') && !f.includes('test'));
  assert.ok(files.includes('worker.js') && files.includes('worker-util.js'));
  for (const f of files) {
    const src = readFileSync(new URL(f, import.meta.url), 'utf8');
    assert.ok(!/\bconsole\s*\./.test(src), f);
    assert.ok(!/caches\s*\.|\bcaches\b|Response\.redirect|\bRange\b|\brange\b/.test(src.replace(/\/\/.*$/gm, '')), `${f}: no cache, redirect or range`);
  }
});

test('a 200 streams through a FixedLengthStream of exactly the stored size (exact Content-Length)', async () => {
  const h = await ready({}, bytesOf(5000));
  const gj = new TextEncoder().encode('{"gateway":1}');
  const gs = new TextEncoder().encode('SIGNATURE-BYTES');
  assert.equal((await uploadGateway(h, 1, gj, gs)).status, 200);
  const cases = [
    ['/v1/kit/5/bundle.tar', 5000],
    ['/v1/kit/5/gateway.json', gj.byteLength],
    ['/v1/kit/5/gateway.json.sig', gs.byteLength],
  ];
  for (const [path, size] of cases) {
    const before = fixedLengths.length;
    const res = await get(h, path);
    assert.equal(res.status, 200, path);
    await res.arrayBuffer();
    assert.deepEqual(fixedLengths.slice(before), [size], path);
  }
});

test('an R2 body that is longer or shorter than the recorded size errors the response body', async () => {
  for (const delta of [1, -1]) {
    const h = await ready({}, bytesOf(3000));
    const get0 = h.env.KIT.get;
    h.env.KIT.get = async (key) => {
      const o = await get0(key);
      const bytes = new Uint8Array(o.size + delta).fill(7);
      return { ...o, body: streamOf(bytes) }; // size and checksum still say 3000
    };
    const res = await get(h, BUNDLE);
    assert.equal(res.status, 200);
    await assert.rejects(() => res.arrayBuffer(), `delta ${delta}`);
    await h.settle();
  }
});

test('a pepper under 16 characters is a 503 for a well-formed request and for an invite; a malformed request stays the 404', async () => {
  for (const pepper of ['short', 'a'.repeat(15)]) {
    const h = await ready();
    h.env.INVITE_PEPPER = pepper;
    const r = await read(await get(h, BUNDLE));
    assert.equal(r.status, 503, pepper);
    assert.equal(new TextDecoder().decode(r.body), 'unavailable\n');
    await assert404(await get(h, `${BUNDLE}?x=1`));
    const inv = await addInvite(h, { ref: 'ref-00000002', code: 'MMMM3333RR' });
    assert.equal(inv.status, 503, pepper);
    assert.equal((await jsonOf(inv)).error, 'unavailable');
    assert.equal(h.q('SELECT * FROM invites').length, 1); // nothing was recorded
  }
  const h = await ready({ INVITE_PEPPER: 'a'.repeat(16) }); // exactly 16 is enough
  assert.equal((await get(h, BUNDLE)).status, 200);
});
