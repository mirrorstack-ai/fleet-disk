// The Gate class itself: loaded the way Workers loads it, with
// `cloudflare:workers` stood in by a one-class module, over the fake storage.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { registerHooks } from 'node:module';
import { fakeStorage } from './fake-storage.js';
import { TAG, SRC, SHA } from './helpers.test-util.js';

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === 'cloudflare:workers') {
      return {
        url: 'data:text/javascript,export class DurableObject { constructor(ctx, env) { this.ctx = ctx; this.env = env; } }',
        shortCircuit: true,
      };
    }
    return nextResolve(specifier, context);
  },
});
const { Gate } = await import('./gate.js');

const ctxOf = (storage) => ({ storage, blockConcurrencyWhile: (f) => f() });

test('Gate extends DurableObject and exposes only the four RPC methods', () => {
  const g = new Gate(ctxOf(fakeStorage()), {});
  const methods = Object.getOwnPropertyNames(Gate.prototype).filter((n) => n !== 'constructor').sort();
  assert.deepEqual(methods, ['admin', 'decide', 'reject', 'release']);
  assert.equal(Object.getPrototypeOf(Gate).name, 'DurableObject');
  assert.equal(g.ctx.storage.sql !== undefined, true);
});

test('Gate end to end over the fake storage, KIT_FLOOR read from env at each call', async () => {
  const env = {};
  const g = new Gate(ctxOf(fakeStorage()), env);
  const t = Date.now();
  const inv = { ref: 'ref-00000001', tag: TAG, tier: 'install', lo: 1, hi: 100, exp: t + 3600000, cap: 2 };
  assert.equal((await g.admin('gateway', t, 'addInvite', inv)).ok, true);
  assert.equal((await g.admin('upload', t, 'putBundle', { serial: 5, sha256: SHA, size: 10 })).ok, true);
  const a = await g.decide({ src: SRC, tag: TAG, serial: 5, name: 'bundle.tar' });
  assert.equal(a.status, 200);
  assert.deepEqual(await g.release({ rid: a.rid }), { released: true });
  env.KIT_FLOOR = '6';
  assert.deepEqual(await g.decide({ src: SRC, tag: TAG, serial: 5, name: 'bundle.tar' }), { status: 404 });
  delete env.KIT_FLOOR;
  const b = await g.decide({ src: SRC, tag: TAG, serial: 5, name: 'bundle.tar' });
  assert.deepEqual(await g.reject({ src: SRC, rid: b.rid }), { status: 404 });
});

test('no console.* anywhere in the shipped kit source (the deploy gate greps for it)', () => {
  const files = readdirSync(new URL('.', import.meta.url)).filter((f) => f.endsWith('.js') && !f.includes('test'));
  assert.ok(files.includes('gate.js') && files.includes('gate-core.js'));
  for (const f of files) {
    assert.ok(!/\bconsole\s*\./.test(readFileSync(new URL(f, import.meta.url), 'utf8')), f);
  }
});
