import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { inviteTag, sourceKey, canonicalSource, parseGuess } from './keys.js';

const PEPPER = 'test-pepper-not-secret';

test('inviteTag is HMAC-SHA256(pepper, code) in hex (D2)', async () => {
  const want = createHmac('sha256', PEPPER).update('CFGHJMPQRV').digest('hex');
  assert.equal(await inviteTag(PEPPER, 'CFGHJMPQRV'), want);
  assert.notEqual(await inviteTag('other-pepper', 'CFGHJMPQRV'), want);
});

test('sourceKey is 16 hex of HMAC(pepper, source)', async () => {
  const k = await sourceKey(PEPPER, '203.0.113.7');
  assert.match(k, /^[0-9a-f]{16}$/);
  assert.equal(k, createHmac('sha256', PEPPER).update('4:203.0.113.7').digest('hex').slice(0, 16));
  assert.notEqual(k, await sourceKey(PEPPER, '203.0.113.8'), 'IPv4 is a /32');
});

test('D3: IPv6 is budgeted per /64', async () => {
  const a = await sourceKey(PEPPER, '2001:db8:1:2:aaaa:bbbb:cccc:dddd');
  assert.equal(a, await sourceKey(PEPPER, '2001:db8:1:2::1'));
  assert.equal(a, await sourceKey(PEPPER, '2001:0DB8:0001:0002:0:0:0:0'));
  assert.equal(a, await sourceKey(PEPPER, '[2001:db8:1:2::9]'));
  assert.equal(a, await sourceKey(PEPPER, '2001:db8:1:2::9%eth0'));
  assert.notEqual(a, await sourceKey(PEPPER, '2001:db8:1:3::1'));
  assert.notEqual(a, await sourceKey(PEPPER, '2001:db8:2:2::1'));
});

test('canonical forms: mapped IPv4 is the IPv4 host, junk is "?"', () => {
  assert.equal(canonicalSource('::ffff:203.0.113.7'), '4:203.0.113.7');
  assert.equal(canonicalSource('::ffff:cb00:7107'), '4:203.0.113.7');
  assert.equal(canonicalSource('::1'), '6:0000:0000:0000:0000');
  assert.equal(canonicalSource('::'), '6:0000:0000:0000:0000');
  assert.equal(canonicalSource('2001:db8::'), '6:2001:0db8:0000:0000');
  assert.equal(canonicalSource('64:ff9b::1.2.3.4'), '6:0064:ff9b:0000:0000');
  for (const junk of [undefined, null, '', 'unknown', '1.2.3', '256.1.1.1', '1.2.3.4.5', '1::2::3', '12345::1', 'g::1', '1:2:3:4:5:6:7', '1:2:3:4:5:6:7:8:9', '::1.2.3.256']) {
    assert.equal(canonicalSource(junk), '?', String(junk));
  }
});

test('D1: only the exact shape is a guess', () => {
  const ok = 'FleetInvite CFGHJMPQRV';
  assert.deepEqual(parseGuess('GET', '/v1/kit/5/bundle.tar', ok), { serial: 5, name: 'bundle.tar', code: 'CFGHJMPQRV' });
  assert.deepEqual(parseGuess('GET', 'https://kit.example.workers.dev/v1/kit/123456789/gateway.json', ok), { serial: 123456789, name: 'gateway.json', code: 'CFGHJMPQRV' });
  assert.equal(parseGuess('GET', '/v1/kit/5/gateway.json.sig', ok).name, 'gateway.json.sig');
  const no = [
    ['POST', '/v1/kit/5/bundle.tar', ok], ['HEAD', '/v1/kit/5/bundle.tar', ok], ['get', '/v1/kit/5/bundle.tar', ok],
    ['GET', '/v1/kit/5/bundle.tar?x=1', ok], ['GET', '/v1/kit/5/bundle.tar?', ok], ['GET', '/v1/kit/5/bundle.tar/', ok],
    ['GET', '/v1/kit/1234567890/bundle.tar', ok], ['GET', '/v1/kit//bundle.tar', ok], ['GET', '/v1/kit/a/bundle.tar', ok],
    ['GET', '/v1/kit/5/other.tar', ok], ['GET', '//v1/kit/5/bundle.tar', ok], ['GET', '/v1/kit/5/%62undle.tar', ok],
    ['GET', '/v1/kit/5/bundle.tar', null], ['GET', '/v1/kit/5/bundle.tar', ''],
    ['GET', '/v1/kit/5/bundle.tar', 'FleetInvite CFGHJMPQR'], ['GET', '/v1/kit/5/bundle.tar', 'FleetInvite CFGHJMPQRVW'],
    ['GET', '/v1/kit/5/bundle.tar', 'FleetInvite cfghjmpqrv'], ['GET', '/v1/kit/5/bundle.tar', 'FleetInvite 0123456789'],
    ['GET', '/v1/kit/5/bundle.tar', 'Bearer CFGHJMPQRV'], ['GET', '/v1/kit/5/bundle.tar', 'fleetinvite CFGHJMPQRV'],
    ['GET', '/v1/kit/5/bundle.tar', `${ok}, ${ok}`], ['GET', '/v1/kit/5/bundle.tar', `${ok} `], ['GET', '/v1/kit/5/bundle.tar', `${ok}\n`],
    ['GET', '/v1/kit/5/bundle.tar\n', ok], ['GET', undefined, ok],
  ];
  for (const [m, u, a] of no) assert.equal(parseGuess(m, u, a), null, `${m} ${u} ${a}`);
});
