// Shared test fixtures (not a test file: the name does not end in .test.js).
import { fakeStorage } from './fake-storage.js';
import { GateCore } from './gate-core.js';

export const H = 60 * 60 * 1000;
export const T0 = Date.UTC(2026, 9, 10, 12, 0, 0);
export const hex64 = (c) => c.repeat(64);
export const TAG = hex64('a');
export const TAG2 = hex64('b');
export const SRC = '0123456789abcdef';
export const SHA = hex64('c');

export function clock(start = T0) {
  const c = { t: start, now: () => c.t, add(ms) { c.t += ms; } };
  return c;
}

export function make({ env = {}, storage = fakeStorage(), clk = clock() } = {}) {
  const core = new GateCore(storage, { now: clk.now, envFloor: () => env.KIT_FLOOR });
  return { core, storage, clk, env };
}

export const invite = (clk, o = {}) => ({
  ref: 'ref-00000001', tag: TAG, tier: 'install', lo: 1, hi: 100, exp: clk.t + 24 * H, cap: 10, ...o,
});

// Run an admin op as an always-fresh timestamp.
export async function adm(ctx, role, op, args) {
  ctx.clk.add(1);
  return ctx.core.admin(role, ctx.clk.t, op, args);
}

export const addInvite = (ctx, o) => adm(ctx, 'gateway', 'addInvite', invite(ctx.clk, o));
export const putBundle = (ctx, serial = 5, o = {}) => adm(ctx, 'upload', 'putBundle', { serial, sha256: SHA, size: 1000, ...o });
export const setGateway = (ctx, gserial = 1, o = {}) =>
  adm(ctx, 'upload', 'setGateway', { gserial, json: { sha256: hex64('d'), size: 300 }, sig: { sha256: hex64('e'), size: 200 }, ...o });

export const dec = (ctx, o = {}) => ctx.core.decide({ src: SRC, tag: TAG, serial: 5, name: 'bundle.tar', ...o });

export const count = (storage, table) => storage.db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get().n;
export const used = (storage, tag = TAG) => storage.db.prepare('SELECT used FROM invites WHERE tag = ?').get(tag).used;
export const writes = (execs) => execs.filter((q) => /^\s*(INSERT|UPDATE|DELETE)/i.test(q));
