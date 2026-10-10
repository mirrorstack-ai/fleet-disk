// The shared kit decision vectors (vectors/kit_vectors.json, vendored from mirrorstack-fleet, pinned in
// vectors/VENDORED.sha256) run against the Worker's real front and the real Gate over fake storage. The Python
// kit-serve runs the same file (tests/gw/test_kitserve.py, class Vectors), so the Worker cannot drift from this pinned
// copy unseen; the fleet's test_kitserve.py holds its file to the same pin (VENDORED_SHA256), the other half of the sync.
// Format and semantics: the file's own `about`. Never asserted here: its `known_differences`.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { makeHarness, worker, addInvite, uploadBundle, uploadGateway, admin, read, bytesOf } from './worker-harness.test-util.js';

const file = (n) => readFileSync(new URL(`./vectors/${n}`, import.meta.url));
const VECTORS = JSON.parse(file('kit_vectors.json').toString('utf8'));
const { base: BASE } = VECTORS;
const NOW = BASE.now;

// A vector that is not in known_differences and that the Worker answers differently stays here, visible and skipped
// with its reason: key `<section>: <vector name>` -> { worker: what the Worker answers, spec: the line that decides }.
// Never fixed in worker.js, gate.js or gate-core.js by this test file, and never weakened.
const DIVERGES = new Map([]);
const skipOf = (section, name) => {
  const d = DIVERGES.get(`${section}: ${name}`);
  return d ? `DIVERGES: Worker answers ${d.worker}; ${d.spec}` : false;
};

test('the vendored copy is the one the pin line names', () => {
  const pin = /^([0-9a-f]{64}) {2}kit_vectors\.json {2}(mirrorstack-fleet@[0-9a-f]{7,40} tests\/gw\/kit_vectors\.json)\n$/.exec(
    file('VENDORED.sha256').toString('utf8'),
  );
  assert.ok(pin, 'VENDORED.sha256 must be one line: <sha256>  kit_vectors.json  <repo>@<sha> <path>');
  assert.equal(createHash('sha256').update(file('kit_vectors.json')).digest('hex'), pin[1], 'copy changed without the pin line');
});

test('the vectors are whole', () => {
  assert.equal(VECTORS.format, 'kit-vectors-v1');
  for (const s of ['answers', 'headers', 'counters', 'budgets', 'known_differences']) assert.ok(VECTORS[s].length, s);
  for (const s of ['answers', 'headers', 'counters', 'budgets']) {
    assert.equal(new Set(VECTORS[s].map((c) => c.name)).size, VECTORS[s].length, `${s} names are unique`);
  }
  const answered = new Set(VECTORS.answers.map((a) => a.status));
  assert.ok(answered.has(200) && answered.has(404), 'the answers hold both a 200 and a 404');
  assert.deepEqual([...new Set(VECTORS.answers.map((a) => a.layer))].sort(), ['front', 'gate']);
  assert.doesNotMatch(JSON.stringify(VECTORS), /[23456789CFGHJMPQRVWX]{10}/, 'no code literal in the data');
  for (const key of DIVERGES.keys()) {
    const i = key.indexOf(': '); // a vector name may itself hold ': '; a section name never does
    const section = key.slice(0, i);
    const name = key.slice(i + 2);
    assert.ok(VECTORS[section].some((c) => c.name === name), `DIVERGES names a vector that exists: ${key}`);
  }
});

// ---- the world and the request -----------------------------------------------------------------

// Date.now is the clock of the Gate and of the Worker's admin skew check: one controllable clock for both (ms).
// A vector's seconds (base.now is 1e6) are mapped onto a fixed 2025 epoch: admin timestamps need 13+ digits. The
// anchor sits in the middle of a 10-minute budget bucket (a vector may not sit on a bucket edge).
const ANCHOR_MS = 1_760_000_100_000;
const ms = (sec) => ANCHOR_MS + (sec - NOW) * 1000;
const clk = { t: 0 };
async function withClock(fn) {
  const real = Date.now;
  Date.now = () => clk.t;
  try {
    return await fn();
  } finally {
    Date.now = real;
  }
}

const DEFAULT = { method: 'GET', serial: 7, name: 'bundle.tar', src: '192.0.2.1', code: 'valid' };
// Code kinds (the data holds none). valid has a letter, so lower is a different string.
const VALID = 'CCCC2222VV';
const CODES = { valid: VALID, other: 'WWWW2222HH', unknown: 'PPPP4444QQ', none: null, short: 'abc', long: `${VALID}X`, lower: VALID.toLowerCase() };
assert.notEqual(CODES.lower, CODES.valid);

const FILES = { 'gateway.json': new TextEncoder().encode('{"serial": 7}\n'), 'gateway.json.sig': new TextEncoder().encode('sig\n') };
const bundleOf = (serial) => bytesOf(3 * 65536 + 5, serial); // several chunks, so a cut lands mid-body

// A fresh Worker, Gate and R2 holding base + change: invites, bundles with the gateway pair, the floor.
async function world(change = {}) {
  const w = { ...BASE, ...Object.fromEntries(Object.entries(change).filter(([k]) => k !== 'invites')) };
  clk.t = ms(NOW - 1); // admin calls run one second before the answers: an invite with ttl 0 is not yet expired
  const h = await makeHarness();
  const ok = (r, what) => assert.equal(r.status, 200, `setup ${what}`);
  for (const [id, v0] of Object.entries(BASE.invites)) {
    const v = { ...v0, ...(change.invites ?? {})[id] };
    ok(await addInvite(h, { ref: `ref-${id}-0001`, code: CODES[id], tier: v.tier, lo: v.lo, hi: v.hi, exp: ms(NOW + v.ttl), cap: v.cap }), `invite ${id}`);
  }
  for (const serial of w.bundles) ok(await uploadBundle(h, serial, bundleOf(serial)), `bundle ${serial}`);
  if (w.bundles.length) ok(await uploadGateway(h, 1, FILES['gateway.json'], FILES['gateway.json.sig']), 'gateway pair');
  ok(await admin(h, 'upload', 'PUT', '/_k/floor', JSON.stringify({ floor: w.floor })), 'floor');
  return h;
}

// One request as bytes through the real front: the Authorization header is parsed by the Worker, never handed over.
// Request and Headers normalise what they are given, as the Workers runtime does before the Worker sees it. So these
// vectors arrive normalised, not as the raw bytes their names say: `path /v1/kit/7/../floor` and `.../%2e%2e/floor`
// arrive as `/v1/kit/floor`, and `bare-scheme-and-space` (`FleetInvite `) as `FleetInvite`. All are 404 either way;
// the raw-path rule itself (rawPathAndQuery decodes and normalises nothing) is pinned by the test further down.
async function send(h, req, { at = 0, cut = false, headers = null } = {}) {
  const r = { ...DEFAULT, ...req };
  const pairs = headers ?? (CODES[r.code] === null ? [] : [['Authorization', `FleetInvite ${CODES[r.code]}`]]);
  const hd = new Headers();
  for (const [n, v] of pairs) hd.append(n, v.replace(/\{(\w+)\}/g, (_, k) => CODES[k]));
  hd.set('cf-connecting-ip', r.src);
  clk.t = ms(NOW + at);
  const res = await worker.fetch(new Request(`https://kit.test${r.target ?? `/v1/kit/${r.serial}/${r.name}`}`, { method: r.method, headers: hd }), h.env, h.ctx);
  let out;
  if (cut && res.status === 200) {
    // the client drops the connection after the head and the first bytes
    const reader = res.body.getReader();
    await reader.read();
    await reader.cancel();
    out = { status: 200, headers: [], body: null };
  } else {
    out = await read(res);
  }
  await h.settle();
  return out;
}

// Every 404 is the same bytes and headers as every other 404, and every 429 the same as every other 429
// (a valid code from a spent source included), across answers, headers, counters and budgets.
const refs = new Map();
function status(out, label) {
  if (out.status === 404 || out.status === 429) {
    const { status: s, headers, body } = out;
    assert.deepEqual({ s, headers, body }, refs.get(s) ?? refs.set(s, { s, headers, body }).get(s), label);
  }
  return out.status;
}

// ---- the vectors --------------------------------------------------------------------------------

for (const c of VECTORS.answers) {
  test(`answers: ${c.name}`, { skip: skipOf('answers', c.name) }, () =>
    withClock(async () => {
      const h = await world(c.set);
      const out = await send(h, c.req);
      assert.equal(status(out, c.name), c.status);
      // layer front: answered before the Gate is called (no budget spent); layer gate: the Gate decided, once
      assert.equal(h.calls.decide, c.layer === 'gate' ? 1 : 0, `${c.layer} layer`);
      // ... and the front spends nothing: no failure written, no release, for any front answer
      assert.equal(h.calls.reject, 0, 'reject');
      assert.equal(h.q('SELECT COALESCE(SUM(n), 0) AS n FROM allfails')[0].n, c.layer === 'gate' && c.status === 404 ? 1 : 0, 'budget writes');
      if (c.status === 200) {
        const name = { ...DEFAULT, ...c.req }.name;
        const want = name === 'bundle.tar' ? bundleOf({ ...DEFAULT, ...c.req }.serial) : FILES[name];
        assert.deepEqual(out.body, new Uint8Array(want));
      }
      if (c.status === 404) assert.equal(new TextDecoder().decode(out.body), 'not found\n');
    }));
}

// Exactly one `Authorization: FleetInvite <code>` (that case, one space) opens a file; every other shape is the 404.
for (const c of VECTORS.headers) {
  test(`headers: ${c.name}`, { skip: skipOf('headers', c.name) }, () =>
    withClock(async () => {
      const h = await world();
      assert.equal(status(await send(h, {}, { headers: c.headers }), c.name), c.status);
    }));
}

// Counters and budgets are sequences against ONE world.
async function runSteps(c) {
  const h = await world(c.set);
  for (const [n, step] of c.steps.entries()) {
    for (const src of step.src_each?.length ? step.src_each : [step.req.src ?? DEFAULT.src]) {
      for (let k = 0; k < (step.times ?? 1); k++) {
        const label = `${c.name}: step ${n} (${src}, #${k}) ${JSON.stringify(step)}`;
        assert.equal(status(await send(h, { ...step.req, src }, { at: step.at ?? 0, cut: step.cut ?? false }), label), step.status, label);
      }
    }
  }
}

for (const sect of ['counters', 'budgets']) {
  for (const c of VECTORS[sect]) test(`${sect}: ${c.name}`, { skip: skipOf(sect, c.name) }, () => withClock(() => runSteps(c)));
}

// ---- what the vectors cannot say --------------------------------------------------------------------

// The Worker slices the URL string and normalises nothing (rawPathAndQuery), so a dot-segment is a different, unknown
// path. A Request would hand it over already collapsed (see send); this stand-in hands it over raw, with a valid code.
test('a dot-segment path is the 404 and no Gate call, not the file it would normalise to', () =>
  withClock(async () => {
    const h = await world();
    clk.t = ms(NOW);
    const headers = new Headers([['Authorization', `FleetInvite ${VALID}`], ['cf-connecting-ip', DEFAULT.src]]);
    const res = await worker.fetch({ method: 'GET', url: 'https://kit.test/v1/kit/9/../7/bundle.tar', headers }, h.env, h.ctx);
    const out = await read(res);
    await h.settle();
    assert.equal(status(out, 'dot-segment'), 404);
    assert.equal(h.calls.decide, 0);
  }));

// The pinned copy is byte-exact: no end-of-line rewrite (core.autocrlf) may touch it, or the pin test would fail
// on a checkout where nothing changed.
test('the vendored files are marked -text', () => {
  const attrs = readFileSync(new URL('../.gitattributes', import.meta.url), 'utf8').split('\n');
  assert.ok(attrs.some((l) => /^kit\/vectors\/\*\*\s+-text\s*$/.test(l)), '.gitattributes needs: kit/vectors/** -text');
});
