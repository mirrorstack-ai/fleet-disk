import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fakeStorage } from './fake-storage.js';
import { GateCore, LIMITS } from './gate-core.js';
import {
  H, T0, TAG, TAG2, SRC, SHA, hex64, make, invite, adm, addInvite, putBundle, setGateway, dec, count, used, writes,
} from './helpers.test-util.js';

async function ready(o) {
  const ctx = make(o);
  assert.equal((await addInvite(ctx)).ok, true);
  assert.equal((await putBundle(ctx)).ok, true);
  assert.equal((await setGateway(ctx)).ok, true);
  return ctx;
}

// ---- the happy path and the reservation ------------------------------------

test('a valid bundle download reserves used+1 and syncs before it resolves', async () => {
  const ctx = await ready();
  let release;
  ctx.storage.syncImpl = () => new Promise((r) => { release = r; });
  const before = ctx.storage.stats.syncs;
  let done = false;
  const p = dec(ctx).then((r) => { done = true; return r; });
  await new Promise((r) => setImmediate(r));
  assert.equal(done, false, 'must not resolve before sync()');
  assert.equal(ctx.storage.stats.syncs, before + 1);
  assert.equal(used(ctx.storage), 1, 'the count is already written');
  release();
  const r = await p;
  assert.deepEqual(r, { status: 200, serial: 5, name: 'bundle.tar', key: 'kit/5/bundle.tar', size: 1000, sha256: SHA, rid: 1 });
});

test('a failing sync() rejects the call, so no byte is ever sent for it', async () => {
  const ctx = await ready();
  ctx.storage.syncImpl = async () => { throw new Error('storage'); };
  await assert.rejects(dec(ctx), /storage/);
  assert.equal(used(ctx.storage), 1, 'the count stays spent: the safe direction');
});

test('gateway files pass, never count against the cap, never reserve', async () => {
  const ctx = await ready();
  for (let i = 0; i < 25; i++) {
    const a = await dec(ctx, { name: 'gateway.json', serial: 7 });
    assert.equal(a.status, 200);
    assert.equal(a.rid, null);
    assert.equal(a.key, 'kit/gateway/1/gateway.json');
  }
  assert.equal((await dec(ctx, { name: 'gateway.json.sig' })).size, 200);
  assert.equal(used(ctx.storage), 0);
  assert.equal(count(ctx.storage, 'reservations'), 0);
  assert.equal(count(ctx.storage, 'allfails'), 0);
});

test('the cap: cap downloads, then the same 404 as any failure', async () => {
  const ctx = make();
  await addInvite(ctx, { cap: 2 });
  await putBundle(ctx);
  assert.equal((await dec(ctx)).status, 200);
  assert.equal((await dec(ctx)).status, 200);
  assert.deepEqual(await dec(ctx), { status: 404 });
});

test('20 concurrent downloads of a cap-10 invite: exactly 10 get a 200', async () => {
  const ctx = await ready();
  const rs = await Promise.all(Array.from({ length: 20 }, () => dec(ctx)));
  assert.equal(rs.filter((r) => r.status === 200).length, 10);
  assert.equal(used(ctx.storage), 10);
  assert.equal(new Set(rs.filter((r) => r.status === 200).map((r) => r.rid)).size, 10);
});

// ---- every failure is the same answer and the same single budget write -------

const causes = {
  'unknown tag': (ctx) => dec(ctx, { tag: TAG2 }),
  'revoked': async (ctx) => { await adm(ctx, 'gateway', 'revokeInvite', { ref: 'ref-00000001' }); return dec(ctx); },
  'serial below range': (ctx) => dec(ctx, { serial: 0 }),
  'serial above range': (ctx) => dec(ctx, { serial: 101 }),
  'below the stored floor': async (ctx) => { await adm(ctx, 'upload', 'setFloor', { floor: 6 }); return dec(ctx); },
  'below KIT_FLOOR': (ctx) => { ctx.env.KIT_FLOOR = '6'; return dec(ctx); },
  'expired': (ctx) => { ctx.clk.add(25 * H); return dec(ctx); },
  'spent': async (ctx) => { for (let i = 0; i < 10; i++) await dec(ctx); return dec(ctx); },
  'bundle not uploaded': (ctx) => dec(ctx, { serial: 6 }),
};

test('every failure cause: identical 404, exactly one budget write, identical statements', async () => {
  const seen = [];
  for (const [label, run] of Object.entries(causes)) {
    const ctx = await ready();
    // measure only the last decide() of the scenario
    const orig = ctx.core.decide.bind(ctx.core);
    let from = 0;
    ctx.core.decide = (req) => { from = ctx.storage.stats.execs.length; return orig(req); };
    const r = await run(ctx);
    assert.deepEqual(r, { status: 404 }, label);
    assert.equal(count(ctx.storage, 'allfails'), 1, label);
    assert.equal(ctx.storage.db.prepare('SELECT n FROM fails').get().n, 1, label);
    seen.push([label, ctx.storage.stats.execs.slice(from)]);
  }
  // All failure paths run the same statements in the same order.
  const [first, ...rest] = seen;
  assert.ok(first[1].length > 5);
  for (const [label, execs] of rest) assert.deepEqual(execs, first[1], `${label} differs from ${first[0]}`);
});

test('gateway file missing is the same 404 and write', async () => {
  const ctx = make();
  await addInvite(ctx);
  assert.deepEqual(await dec(ctx, { name: 'gateway.json' }), { status: 404 });
  assert.equal(count(ctx.storage, 'allfails'), 1);
});

test('malformed input throws and spends no budget (D1: only well-formed guesses count)', async () => {
  const ctx = await ready();
  const bad = [
    { src: 'xyz' }, { src: '0123456789ABCDEF' }, { tag: 'nope' }, { tag: TAG.toUpperCase() },
    { serial: -1 }, { serial: 1.5 }, { serial: '5' }, { serial: 1e10 }, { name: 'other.tar' }, { name: undefined },
  ];
  for (const o of bad) await assert.rejects(dec(ctx, o), TypeError);
  assert.equal(count(ctx.storage, 'fails'), 0);
  assert.equal(count(ctx.storage, 'allfails'), 0);
});

// ---- budgets ---------------------------------------------------------------

const tagN = (i) => i.toString(16).padStart(64, '0');
const hexSrc = (i) => i.toString(16).padStart(16, '0');

test('30 failures an hour from one source: the 31st is a 429 and writes nothing', async () => {
  const ctx = await ready();
  for (let i = 0; i < 30; i++) assert.deepEqual(await dec(ctx, { tag: TAG2 }), { status: 404 });
  const mark = ctx.storage.stats.execs.length;
  assert.deepEqual(await dec(ctx, { tag: TAG2 }), { status: 429 });
  assert.deepEqual(await dec(ctx), { status: 429 }, 'even a valid code gets no answer once spent');
  assert.deepEqual(writes(ctx.storage.stats.execs.slice(mark)), []);
  assert.equal(used(ctx.storage), 0);
  // another source is unaffected
  assert.deepEqual(await dec(ctx, { src: hexSrc(2), tag: TAG2 }), { status: 404 });
  assert.equal((await dec(ctx, { src: hexSrc(2) })).status, 200);
});

test('600 failures an hour in all: every source gets 429', async () => {
  const ctx = await ready();
  for (let i = 0; i < 600; i++) assert.deepEqual(await dec(ctx, { src: hexSrc(1 + (i % 25)), tag: TAG2 }), { status: 404 });
  assert.deepEqual(await dec(ctx, { src: hexSrc(99), tag: TAG2 }), { status: 429 });
  assert.deepEqual(await dec(ctx, { src: hexSrc(100) }), { status: 429 });
});

test('the window is an hour: still spent at 50 min, free again after 70 min', async () => {
  const ctx = await ready();
  for (let i = 0; i < 30; i++) await dec(ctx, { tag: TAG2 });
  ctx.clk.add(50 * 60 * 1000);
  assert.deepEqual(await dec(ctx), { status: 429 });
  ctx.clk.add(20 * 60 * 1000);
  assert.equal((await dec(ctx)).status, 200);
});

test('buckets are deleted after 2 h (on the next failure write)', async () => {
  const ctx = await ready();
  await dec(ctx, { tag: TAG2 });
  ctx.clk.add(3 * H);
  await dec(ctx, { tag: TAG2 });
  assert.equal(count(ctx.storage, 'fails'), 1);
  assert.equal(count(ctx.storage, 'allfails'), 1);
});

test('D4: budgets, reservations and invites survive a restart', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'kit-gate-'));
  try {
    const path = join(dir, 'gate.sqlite');
    const a = await ready({ storage: fakeStorage(path) });
    for (let i = 0; i < 30; i++) await dec(a, { tag: TAG2 });
    assert.equal((await dec(a, { src: hexSrc(3) })).status, 200); // one reservation
    a.storage.db.close();

    const b = make({ storage: fakeStorage(path), clk: a.clk });
    assert.deepEqual(await dec(b, { tag: TAG2 }), { status: 429 });
    assert.equal(used(b.storage), 1);
    assert.equal((await dec(b, { src: hexSrc(3) })).status, 200);
    assert.equal(used(b.storage), 2);
    b.storage.db.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a new GateCore over the same storage keeps everything (migration is idempotent)', async () => {
  const ctx = await ready();
  await dec(ctx, { tag: TAG2 });
  const again = new GateCore(ctx.storage, { now: ctx.clk.now });
  assert.equal(count(ctx.storage, 'allfails'), 1);
  assert.equal((await again.decide({ src: SRC, tag: TAG, serial: 5, name: 'bundle.tar' })).status, 200);
});

// ---- release / reject ------------------------------------------------------

test('a client cut restores the count, at most 3 refunds per invite, no double refund', async () => {
  const ctx = await ready();
  for (let i = 0; i < 3; i++) {
    const r = await dec(ctx);
    assert.deepEqual(await ctx.core.release({ rid: r.rid }), { released: true });
    assert.deepEqual(await ctx.core.release({ rid: r.rid }), { released: false }, 'second release is a no-op');
    assert.equal(used(ctx.storage), 0);
  }
  const r4 = await dec(ctx);
  assert.deepEqual(await ctx.core.release({ rid: r4.rid }), { released: false });
  assert.equal(used(ctx.storage), 1, 'the fourth cut stays spent');
  assert.equal(count(ctx.storage, 'reservations'), 0);
});

test('reject: R2 fault releases the reservation (no refund cap) and makes the one budget write', async () => {
  const ctx = await ready();
  for (let i = 0; i < 5; i++) {
    const r = await dec(ctx);
    assert.deepEqual(await ctx.core.reject({ src: SRC, rid: r.rid }), { status: 404 });
    assert.equal(used(ctx.storage), 0);
  }
  assert.equal(ctx.storage.db.prepare('SELECT n FROM fails').get().n, 5);
  assert.equal(ctx.storage.db.prepare('SELECT refunds FROM invites').get().refunds, 0);
  assert.deepEqual(await ctx.core.reject({ src: SRC, rid: null }), { status: 404 });
  assert.equal(ctx.storage.db.prepare('SELECT n FROM fails').get().n, 6);
});

test('reject on an already-spent source still releases and answers 404', async () => {
  const ctx = await ready();
  const r = await dec(ctx);
  for (let i = 0; i < 30; i++) await dec(ctx, { tag: TAG2 });
  assert.deepEqual(await ctx.core.reject({ src: SRC, rid: r.rid }), { status: 404 });
  assert.equal(used(ctx.storage), 0);
});

test('release/reject validate their input', async () => {
  const ctx = await ready();
  await assert.rejects(ctx.core.release({ rid: 0 }), TypeError);
  await assert.rejects(ctx.core.release({ rid: '1' }), TypeError);
  await assert.rejects(ctx.core.reject({ src: 'x', rid: null }), TypeError);
  await assert.rejects(ctx.core.reject({ src: SRC, rid: 'a' }), TypeError);
});

// ---- admin: roles, clock, replay -------------------------------------------

test('each role can call only its own ops', async () => {
  const ctx = make();
  assert.deepEqual(await adm(ctx, 'upload', 'addInvite', invite(ctx.clk)), { ok: false, error: 'forbidden' });
  assert.deepEqual(await adm(ctx, 'gateway', 'putBundle', { serial: 1, sha256: SHA, size: 1 }), { ok: false, error: 'forbidden' });
  assert.deepEqual(await adm(ctx, 'gateway', 'setFloor', { floor: 1 }), { ok: false, error: 'forbidden' });
  assert.deepEqual(await adm(ctx, 'gateway', 'setGateway', {}), { ok: false, error: 'forbidden' });
  assert.deepEqual(await adm(ctx, 'root', 'health', {}), { ok: false, error: 'forbidden' });
  assert.deepEqual(await adm(ctx, 'gateway', '_migrate', {}), { ok: false, error: 'forbidden' });
  assert.deepEqual(await adm(ctx, 'gateway', 'constructor', {}), { ok: false, error: 'forbidden' });
  assert.deepEqual(await adm(ctx, '__proto__', 'health', {}), { ok: false, error: 'forbidden' });
  assert.equal(count(ctx.storage, 'meta'), 0, 'a forbidden call burns no timestamp');
});

test('timestamp: within 300 s and strictly greater than the role\'s last', async () => {
  const ctx = make();
  const t = ctx.clk.t;
  assert.equal((await ctx.core.admin('gateway', t, 'health', {})).ok, true);
  assert.deepEqual(await ctx.core.admin('gateway', t, 'health', {}), { ok: false, error: 'replay' });
  assert.deepEqual(await ctx.core.admin('gateway', t - 1, 'health', {}), { ok: false, error: 'replay' });
  assert.equal((await ctx.core.admin('gateway', t + 1, 'health', {})).ok, true);
  // the other role has its own clock
  assert.equal((await ctx.core.admin('upload', t, 'setFloor', { floor: 1 })).ok, true);
  // skew
  assert.deepEqual(await ctx.core.admin('gateway', t - 301000, 'health', {}), { ok: false, error: 'stale' });
  assert.deepEqual(await ctx.core.admin('gateway', t + 301000, 'health', {}), { ok: false, error: 'stale' });
  assert.equal((await ctx.core.admin('gateway', t + 300000, 'health', {})).ok, true);
  assert.deepEqual(await ctx.core.admin('gateway', 'now', 'health', {}), { ok: false, error: 'stale' });
  assert.deepEqual(await ctx.core.admin('gateway', NaN, 'health', {}), { ok: false, error: 'stale' });
});

test('an admin call spends no source budget', async () => {
  const ctx = make();
  await adm(ctx, 'upload', 'addInvite', {});
  await ctx.core.admin('gateway', 1, 'health', {});
  assert.equal(count(ctx.storage, 'fails'), 0);
  assert.equal(count(ctx.storage, 'allfails'), 0);
});

// ---- invites: ceilings, idempotence, tombstones ----------------------------

const refN = (i) => `ref-${String(i).padStart(8, '0')}`;

test('ceilings: 16 open invites, 72 h life, 10 downloads', async () => {
  const ctx = make();
  for (let i = 0; i < 16; i++) assert.equal((await addInvite(ctx, { ref: refN(i), tag: tagN(i + 1) })).ok, true);
  assert.deepEqual(await addInvite(ctx, { ref: refN(90), tag: tagN(90) }), { ok: false, error: 'ceiling-open' });
  assert.deepEqual(await addInvite(ctx, { ref: refN(91), tag: tagN(91), exp: ctx.clk.t + 73 * H }), { ok: false, error: 'ceiling-life' });
  assert.deepEqual(await addInvite(ctx, { ref: refN(92), tag: tagN(92), cap: 11 }), { ok: false, error: 'ceiling-downloads' });
  assert.deepEqual(await addInvite(ctx, { ref: refN(93), tag: tagN(93), cap: 0 }), { ok: false, error: 'ceiling-downloads' });
  assert.deepEqual(await addInvite(ctx, { ref: refN(94), tag: tagN(94), exp: ctx.clk.t - 1 }), { ok: false, error: 'expired' });
});

test('ceilings: a revoked or expired invite frees a slot; 72 h exactly is allowed', async () => {
  const ctx = make();
  for (let i = 0; i < 16; i++) await addInvite(ctx, { ref: refN(i), tag: tagN(i + 1) });
  assert.equal((await addInvite(ctx, { ref: refN(80), tag: tagN(80) })).error, 'ceiling-open');
  await adm(ctx, 'gateway', 'revokeInvite', { ref: refN(3) });
  assert.equal((await addInvite(ctx, { ref: refN(81), tag: tagN(81), exp: ctx.clk.t + 72 * H })).ok, true);
  assert.equal((await addInvite(ctx, { ref: refN(82), tag: tagN(82) })).error, 'ceiling-open');
  ctx.clk.add(25 * H); // the 24 h invites expire
  assert.equal((await addInvite(ctx, { ref: refN(83), tag: tagN(83), exp: ctx.clk.t + H })).ok, true);
});

test('add is idempotent for the same record, a conflict for a different one', async () => {
  const ctx = make();
  const rec = invite(ctx.clk);
  assert.deepEqual(await adm(ctx, 'gateway', 'addInvite', rec), { ok: true, created: true });
  assert.deepEqual(await adm(ctx, 'gateway', 'addInvite', rec), { ok: true, created: false });
  assert.deepEqual(await adm(ctx, 'gateway', 'addInvite', { ...rec, cap: 3 }), { ok: false, error: 'conflict' });
  assert.deepEqual(await adm(ctx, 'gateway', 'addInvite', { ...rec, ref: 'ref-00000002' }), { ok: false, error: 'conflict' }, 'one tag, one ref');
  await putBundle(ctx);
  await dec(ctx);
  await adm(ctx, 'gateway', 'addInvite', rec);
  assert.equal(used(ctx.storage), 1, 'a retried add never resets the count');
});

test('a retried identical add succeeds even when its life is at the ceiling edge', async () => {
  const ctx = make();
  const rec = invite(ctx.clk, { exp: ctx.clk.t + 72 * H });
  assert.equal((await adm(ctx, 'gateway', 'addInvite', rec)).created, true);
  ctx.clk.add(60 * 1000);
  assert.equal((await adm(ctx, 'gateway', 'addInvite', rec)).ok, true);
});

test('revoke leaves a tombstone: no resurrection, known or unknown ref', async () => {
  const ctx = await ready();
  assert.deepEqual(await adm(ctx, 'gateway', 'revokeInvite', { ref: 'ref-00000001' }), { ok: true, existed: true });
  assert.deepEqual(await adm(ctx, 'gateway', 'revokeInvite', { ref: 'ref-00000001' }), { ok: true, existed: true });
  assert.deepEqual(await addInvite(ctx), { ok: false, error: 'revoked' });
  assert.deepEqual(await dec(ctx), { status: 404 });
  // revoke before the add arrives
  assert.deepEqual(await adm(ctx, 'gateway', 'revokeInvite', { ref: 'ref-late0000' }), { ok: true, existed: false });
  assert.deepEqual(await addInvite(ctx, { ref: 'ref-late0000', tag: TAG2 }), { ok: false, error: 'revoked' });
  assert.deepEqual(await dec(ctx, { tag: TAG2 }), { status: 404 });
});

test('invite fields are validated', async () => {
  const ctx = make();
  const bad = [
    { ref: 'short' }, { ref: 'has space 1' }, { tag: 'zz' }, { tag: TAG.toUpperCase() }, { tier: '' }, { tier: 'a b' }, { tier: 'helper' }, { tier: 'Install' },
    { lo: 0 }, { hi: 0 }, { lo: 50, hi: 10 }, { lo: 1.5 }, { hi: 2 ** 31 + 1 }, { exp: 'soon' }, { cap: 1.5 },
  ];
  for (const o of bad) assert.deepEqual(await addInvite(ctx, o), { ok: false, error: 'bad-request' }, JSON.stringify(o));
  assert.deepEqual(await adm(ctx, 'gateway', 'revokeInvite', {}), { ok: false, error: 'bad-request' });
  assert.equal(count(ctx.storage, 'invites'), 0);
});

test('expired invites are pruned from the table after an hour', async () => {
  const ctx = make();
  await addInvite(ctx);
  ctx.clk.add(26 * H);
  await addInvite(ctx, { ref: 'ref-00000002', tag: TAG2 });
  assert.equal(count(ctx.storage, 'invites'), 1);
});

// ---- files, gateway pair, floor --------------------------------------------

test('bundle.tar is write-once per serial: same bytes ok, different bytes conflict', async () => {
  const ctx = make();
  assert.deepEqual(await putBundle(ctx, 9), { ok: true, created: true, key: 'kit/9/bundle.tar' });
  assert.deepEqual(await putBundle(ctx, 9), { ok: true, created: false, key: 'kit/9/bundle.tar' });
  assert.deepEqual(await putBundle(ctx, 9, { sha256: hex64('f') }), { ok: false, error: 'conflict' });
  assert.deepEqual(await putBundle(ctx, 9, { size: 1001 }), { ok: false, error: 'conflict' });
  assert.equal((await putBundle(ctx, 10)).created, true);
  for (const o of [{ serial: 0 }, { serial: 1e9 }, { sha256: 'zz' }, { size: 0 }, { size: 100 * 1024 * 1024 + 1 }]) {
    assert.deepEqual(await putBundle(ctx, 11, o), { ok: false, error: 'bad-request' }, JSON.stringify(o));
  }
});

test('gateway pair: anti-rollback, idempotent, newer replaces, served pair flips together', async () => {
  const ctx = await ready();
  assert.deepEqual(await setGateway(ctx, 1), { ok: true, created: false, gserial: 1 });
  assert.deepEqual(await setGateway(ctx, 1, { json: { sha256: hex64('1'), size: 300 } }), { ok: false, error: 'conflict' });
  assert.deepEqual(await setGateway(ctx, 0), { ok: false, error: 'bad-request' });
  assert.equal((await setGateway(ctx, 3, { json: { sha256: hex64('3'), size: 310 }, sig: { sha256: hex64('4'), size: 210 } })).created, true);
  assert.deepEqual(await setGateway(ctx, 2), { ok: false, error: 'rollback' });
  assert.deepEqual(await setGateway(ctx, 1), { ok: false, error: 'rollback' });
  const j = await dec(ctx, { name: 'gateway.json' });
  const s = await dec(ctx, { name: 'gateway.json.sig' });
  assert.equal(j.key, 'kit/gateway/3/gateway.json');
  assert.equal(s.key, 'kit/gateway/3/gateway.json.sig');
  assert.equal(j.sha256, hex64('3'));
  assert.equal(s.size, 210);
});

test('gateway pair: sizes are bounded and both files are required', async () => {
  const ctx = make();
  assert.equal((await setGateway(ctx, 1, { json: { sha256: hex64('1'), size: 65537 } })).error, 'bad-request');
  assert.equal((await setGateway(ctx, 1, { sig: { sha256: hex64('1'), size: 4097 } })).error, 'bad-request');
  assert.equal((await setGateway(ctx, 1, { sig: undefined })).error, 'bad-request');
  assert.equal(count(ctx.storage, 'gateway'), 0);
});

test('gateway pair: the pointer flip is atomic (a failure half way leaves the old pair served)', async () => {
  const ctx = await ready();
  let inserts = 0;
  ctx.storage.beforeExec = (q) => {
    if (/INSERT INTO gateway/.test(q) && ++inserts === 2) throw new Error('boom');
  };
  await assert.rejects(setGateway(ctx, 4), /boom/);
  ctx.storage.beforeExec = null;
  assert.equal(count(ctx.storage, 'gateway'), 2);
  assert.equal((await dec(ctx, { name: 'gateway.json' })).key, 'kit/gateway/1/gateway.json');
  assert.equal((await setGateway(ctx, 4)).created, true, 'and the same call can be retried');
});

test('floor: max of the stored floor and KIT_FLOOR; below it is the 404', async () => {
  const ctx = await ready();
  assert.equal((await dec(ctx)).status, 200);
  assert.deepEqual(await adm(ctx, 'upload', 'setFloor', { floor: 5 }), { ok: true, floor: 5 });
  assert.equal((await dec(ctx)).status, 200, 'serial == floor is served');
  ctx.env.KIT_FLOOR = '9';
  assert.equal((await dec(ctx)).status, 404);
  ctx.env.KIT_FLOOR = undefined;
  await adm(ctx, 'upload', 'setFloor', { floor: 6 });
  assert.equal((await dec(ctx)).status, 404);
  assert.equal((await dec(ctx, { name: 'gateway.json' })).status, 404, 'the floor covers the gateway files too');
  await adm(ctx, 'upload', 'setFloor', { floor: 0 });
  assert.equal((await dec(ctx)).status, 200);
  assert.deepEqual(await adm(ctx, 'upload', 'setFloor', { floor: -1 }), { ok: false, error: 'bad-request' });
});

// ---- what admin can read ----------------------------------------------------

test('health exposes no tag, no code, no source', async () => {
  const ctx = await ready();
  await dec(ctx, { tag: TAG2 });
  const h = await adm(ctx, 'gateway', 'health', {});
  assert.deepEqual(h, {
    ok: true, now: ctx.clk.t, floor: 0, effectiveFloor: 0, floorError: false, gateway: 1, openInvites: 1, bundles: 1, failuresLastHour: 1,
  });
  const text = JSON.stringify(h);
  assert.ok(!text.includes(TAG) && !text.includes(SRC));
  // The spec gives the gateway role add, revoke and health only: no listing op.
  assert.deepEqual(await adm(ctx, 'gateway', 'invites', {}), { ok: false, error: 'forbidden' });
  assert.deepEqual(await adm(ctx, 'upload', 'invites', {}), { ok: false, error: 'forbidden' });
});

test('the tables hold no plain code and no raw address: only tags and 16-hex source keys', async () => {
  const ctx = await ready();
  await dec(ctx, { tag: TAG2 });
  const dump = JSON.stringify(['invites', 'fails', 'meta', 'files'].map((t) => ctx.storage.db.prepare(`SELECT * FROM ${t}`).all()));
  assert.ok(!/FleetInvite/.test(dump));
  assert.ok(!/\d+\.\d+\.\d+\.\d+/.test(dump));
});

test('limits match the spec', () => {
  assert.equal(LIMITS.perSource, 30);
  assert.equal(LIMITS.total, 600);
  assert.equal(LIMITS.maxOpenInvites, 16);
  assert.equal(LIMITS.maxLifeMs, 72 * H);
  assert.equal(LIMITS.maxDownloads, 10);
  assert.equal(LIMITS.maxRefunds, 3);
  assert.equal(LIMITS.bucketMs, 600000);
  assert.equal(LIMITS.keepMs, 2 * H);
  assert.equal(T0 % 600000, 0);
});

// ---- review fixes ----------------------------------------------------------

test('KIT_FLOOR set but unreadable fails closed (every request a 404), unset is no floor', async () => {
  const ctx = await ready();
  let n = 0;
  for (const bad of ['garbage', '12abc', 'O12', '1O', '1,000', '10.5', '-1', 'Infinity', 'true', 12.5, -1, NaN, Infinity, true, {}, '  ']) {
    ctx.env.KIT_FLOOR = bad;
    const src = String(++n).padStart(16, '0'); // a fresh source each time: stay under the budget
    assert.deepEqual(await dec(ctx, { src }), { status: 404 }, `bundle with ${JSON.stringify(bad)}`);
    assert.deepEqual(await dec(ctx, { src, name: 'gateway.json' }), { status: 404 }, `gateway with ${JSON.stringify(bad)}`);
    const h = await adm(ctx, 'gateway', 'health', {});
    assert.equal(h.floorError, true, String(bad));
  }
  for (const good of [undefined, null, '', '0', 0, '5', ' 5 ', 5]) {
    ctx.env.KIT_FLOOR = good;
    assert.equal((await dec(ctx, { name: 'gateway.json' })).status, 200, `with ${JSON.stringify(good)}`);
    assert.equal((await adm(ctx, 'gateway', 'health', {})).floorError, false);
  }
  ctx.env.KIT_FLOOR = '6';
  assert.equal((await dec(ctx)).status, 404);
  assert.equal((await adm(ctx, 'gateway', 'health', {})).effectiveFloor, 6);
});

test('an exhausted invite still reads the gateway pair: the exemption is deliberate and writes nothing', async () => {
  const ctx = make();
  await addInvite(ctx, { cap: 1 });
  await putBundle(ctx);
  await setGateway(ctx);
  assert.equal((await dec(ctx)).status, 200);
  assert.deepEqual(await dec(ctx), { status: 404 });
  const before = count(ctx.storage, 'allfails') && ctx.storage.db.prepare('SELECT SUM(n) AS n FROM allfails').get().n;
  const execs = ctx.storage.stats.execs.length;
  for (const name of ['gateway.json', 'gateway.json.sig']) {
    const r = await dec(ctx, { name });
    assert.equal(r.status, 200);
    assert.equal(r.rid, null);
  }
  assert.equal(ctx.storage.db.prepare('SELECT SUM(n) AS n FROM allfails').get().n, before);
  assert.equal(used(ctx.storage), 1);
  assert.ok(execs < ctx.storage.stats.execs.length);
  assert.equal(writes(ctx.storage.stats.execs.slice(execs)).length, 0);
});

test('a tombstone for an unknown ref outlives the longest invite, even after other adds prune the table', async () => {
  const ctx = make();
  assert.deepEqual(await adm(ctx, 'gateway', 'revokeInvite', { ref: 'ref-late0000' }), { ok: true, existed: false });
  ctx.clk.add(71 * H);
  // A different add runs the prune of expired rows; the tombstone must survive it.
  assert.equal((await addInvite(ctx, { ref: 'ref-00000002', tag: TAG2 })).created, true);
  assert.deepEqual(await addInvite(ctx, { ref: 'ref-late0000', tag: TAG }), { ok: false, error: 'revoked' });
  assert.deepEqual(await dec(ctx, { tag: TAG }), { status: 404 });
});

test('serial range and expiry boundaries are inclusive for the range and exclusive for exp', async () => {
  const ctx = make();
  await addInvite(ctx, { lo: 3, hi: 5, exp: T0 + 10 * H });
  for (const s of [2, 3, 4, 5, 6]) await putBundle(ctx, s);
  const results = [];
  for (const s of [2, 3, 4, 5, 6]) results.push((await dec(ctx, { serial: s })).status);
  assert.deepEqual(results, [404, 200, 200, 200, 404]);
  ctx.clk.t = T0 + 10 * H - 1;
  assert.equal((await dec(ctx, { serial: 4 })).status, 200, 'one ms before exp');
  ctx.clk.t = T0 + 10 * H;
  assert.equal((await dec(ctx, { serial: 4 })).status, 404, 'at exp it is expired');
});

test('reservations older than an hour are pruned', async () => {
  const ctx = await ready();
  assert.equal((await dec(ctx)).status, 200);
  assert.equal(count(ctx.storage, 'reservations'), 1);
  ctx.clk.add(H + 1);
  assert.equal((await dec(ctx)).status, 200);
  assert.equal(count(ctx.storage, 'reservations'), 1, 'only the new one is left');
  assert.deepEqual(await ctx.core.release({ rid: 1 }), { released: false }, 'the pruned one can no longer be released');
});

test('release, reject and every admin write wait for storage.sync(); reads and no-ops do not', async () => {
  const ctx = await ready();
  const a = await dec(ctx);
  const syncs = () => ctx.storage.stats.syncs;
  let s = syncs();
  await ctx.core.release({ rid: a.rid });
  assert.equal(syncs(), s + 1, 'release');
  s = syncs();
  await ctx.core.release({ rid: a.rid });
  assert.equal(syncs(), s, 'a second release is a no-op');
  const b = await dec(ctx);
  s = syncs();
  await ctx.core.reject({ src: SRC, rid: b.rid });
  assert.equal(syncs(), s + 1, 'reject');
  s = syncs();
  await ctx.core.reject({ src: SRC, rid: null });
  assert.equal(syncs(), s, 'reject without a reservation');
  s = syncs();
  await adm(ctx, 'upload', 'setFloor', { floor: 1 });
  assert.equal(syncs(), s + 1, 'admin write');
  s = syncs();
  await adm(ctx, 'gateway', 'health', {});
  assert.equal(syncs(), s, 'health');
});

test('a write is judged only after its cursor is drained (rowsWritten is final then)', async () => {
  const ctx = await ready();
  // The fake reports 0 until toArray(); these all branch on the count.
  assert.deepEqual(await adm(ctx, 'gateway', 'revokeInvite', { ref: 'ref-00000001' }), { ok: true, existed: true });
  assert.equal(ctx.storage.db.prepare('SELECT revoked FROM invites').get().revoked, 1);
  const ctx2 = await ready();
  const a = await dec(ctx2);
  assert.equal(a.status, 200);
  assert.deepEqual(await ctx2.core.release({ rid: a.rid }), { released: true });
  assert.equal(used(ctx2.storage), 0);
});
