import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sourceOf, sourceKey, rawPathAndQuery, fromBase64, parseJson, TARGET, INVITE_AUTH, readCapped } from './worker-util.js';

test('sourceOf: IPv4 whole, IPv6 per /64, mapped IPv4 as IPv4, junk as one shared unknown', () => {
  assert.equal(sourceOf('203.0.113.9'), '4:203.0.113.9');
  assert.equal(sourceOf(' 203.0.113.9 '), '4:203.0.113.9');
  assert.equal(sourceOf('2001:db8:1:2:aaaa:bbbb:cccc:dddd'), '6:2001:0db8:0001:0002');
  assert.equal(sourceOf('2001:DB8:1:2::1'), '6:2001:0db8:0001:0002');
  assert.equal(sourceOf('2001:db8:1:2:ffff:ffff:ffff:ffff'), sourceOf('2001:db8:1:2::'));
  assert.notEqual(sourceOf('2001:db8:1:3::1'), sourceOf('2001:db8:1:2::1'));
  assert.equal(sourceOf('::1'), '6:0000:0000:0000:0000');
  assert.equal(sourceOf('::'), '6:0000:0000:0000:0000');
  assert.equal(sourceOf('fe80::1%en0'), '6:fe80:0000:0000:0000');
  assert.equal(sourceOf('::ffff:203.0.113.9'), '4:203.0.113.9');
  assert.equal(sourceOf('::ffff:cb00:7109'), '4:203.0.113.9');
  assert.equal(sourceOf('2001:db8::1.2.3.4'), '6:2001:0db8:0000:0000');
  for (const bad of [undefined, null, '', 'x', '1.2.3', '1.2.3.256', '1:2:3:4:5:6:7', '1:2:3:4:5:6:7:8:9', '1::2::3', ':::', '12345::1', '1.2.3.4:80', '::1.2.3.4.5']) {
    assert.equal(sourceOf(bad), 'unknown', String(bad));
  }
});

test('sourceKey is 16 hex, depends on the pepper, and never carries the address', async () => {
  const a = await sourceKey('pepper-one-0123456789', '203.0.113.9');
  assert.match(a, /^[0-9a-f]{16}$/);
  assert.equal(a, await sourceKey('pepper-one-0123456789', '::ffff:203.0.113.9'));
  assert.notEqual(a, await sourceKey('pepper-two-0123456789', '203.0.113.9'));
});

test('rawPathAndQuery slices the URL string and decodes nothing', () => {
  assert.equal(rawPathAndQuery('https://h.example/v1/kit/5/bundle.tar'), '/v1/kit/5/bundle.tar');
  assert.equal(rawPathAndQuery('https://h.example/v1/kit/5/%62undle.tar?x=1'), '/v1/kit/5/%62undle.tar?x=1');
  assert.equal(rawPathAndQuery('https://h.example/a//b/'), '/a//b/');
  assert.equal(rawPathAndQuery('https://h.example'), '/');
});

test('the public shapes', () => {
  assert.ok(TARGET.test('/v1/kit/123456789/gateway.json.sig'));
  assert.ok(!TARGET.test('/v1/kit/1234567890/bundle.tar'));
  assert.ok(!TARGET.test('/v1/kit/5/bundle.tar\n'));
  assert.ok(!INVITE_AUTH.test('FleetInvite CCCC2222VV\n'));
  assert.equal(INVITE_AUTH.exec('FleetInvite CCCC2222VV')[1], 'CCCC2222VV');
});

test('fromBase64 is strict and parseJson takes objects only', () => {
  assert.deepEqual(fromBase64('eA=='), Uint8Array.of(120));
  for (const bad of ['', 'eA', 'eA=', 'eB==', 'e A==', 'eA==\n', '====', 5, null, 'eA-_']) assert.equal(fromBase64(bad), null, String(bad));
  assert.deepEqual(parseJson(new TextEncoder().encode('{"a":1}')), { a: 1 });
  for (const bad of ['[]', '1', 'null', '{', '\xff']) assert.equal(parseJson(new TextEncoder().encode(bad)), null);
  assert.equal(parseJson(Uint8Array.of(0xff, 0xfe)), null);
});

test('readCapped stops at the cap, by declared length and by the stream', async () => {
  const mk = (body, headers = {}) => new Request('https://h.example/', { method: 'PUT', body, headers, duplex: 'half' });
  assert.deepEqual(await readCapped(mk('abc'), 3), new TextEncoder().encode('abc'));
  assert.equal(await readCapped(mk('abcd'), 3), null);
  assert.equal(await readCapped(mk('ab', { 'content-length': '99' }), 3), null);
  assert.equal(await readCapped(mk('ab', { 'content-length': 'x' }), 3), null);
  assert.deepEqual(await readCapped(new Request('https://h.example/'), 0), new Uint8Array(0));
  const stream = new ReadableStream({ pull(c) { c.enqueue(new Uint8Array(10)); } });
  assert.equal(await readCapped(mk(stream), 25), null);
});
