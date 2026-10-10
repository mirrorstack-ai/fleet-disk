// The Worker front of the serverless kit host (K5). One Durable Object (Gate,
// gate.js) decides; this file only shapes requests, computes the HMAC tags,
// reads and writes R2 and verifies admin signatures. Nothing here logs: the
// deploy gate greps this folder for console calls, and observability is off.
//
// Public:  GET /v1/kit/<serial>/<bundle.tar|gateway.json|gateway.json.sig>
//          Authorization: FleetInvite <code>
// Admin:   /_k/* with Authorization: KitAdmin <role> <ts_ms> <sig_hex>
//          (see README.md, "Admin calls").
//
// Platform facts this file depends on (checked 2026-10-10):
// - R2 put(key, stream, {sha256: <hex string>, onlyIf: {etagDoesNotMatch: '*'}})
//   makes R2 itself refuse other bytes (it throws) and refuse an overwrite
//   (it returns null): https://developers.cloudflare.com/r2/api/workers/workers-api-reference/
//   R2Object.checksums.sha256 is an ArrayBuffer.
// - FixedLengthStream(n) errors on too many or too few bytes, and as a
//   Response body gives an exact Content-Length instead of chunked encoding:
//   https://developers.cloudflare.com/workers/runtime-apis/streams/transformstream/
// - ctx.waitUntil keeps the isolate alive for the release after the response
//   body is cancelled by a client that went away.
// - Ed25519 is crypto.subtle "Ed25519", raw 32-byte public key import:
//   https://developers.cloudflare.com/workers/runtime-apis/web-crypto/
// - A Durable Object namespace: idFromName + get(id, {locationHint}); RPC
//   methods on the stub (compatibility_date >= 2024-04-03):
//   https://developers.cloudflare.com/durable-objects/api/namespace/

import { Gate } from './gate.js';
import { LIMITS, bundleKey, gatewayKey, GATEWAY_JSON, GATEWAY_SIG } from './gate-core.js';
import {
  TARGET, INVITE_AUTH, CODE, rawPathAndQuery, hmacHex, sourceKey, sha256Hex, toHex, fromHex,
  readCapped, fromBase64, parseJson,
} from './worker-util.js';

export { Gate };

// ---- the fixed answers --------------------------------------------------------

// One constant per answer, one builder: every non-200 public answer is
// byte-identical (apart from the date and cf-ray the platform adds).
const BODIES = { 404: 'not found\n', 429: 'try later\n', 503: 'unavailable\n' };
const fixed = (status) =>
  new Response(BODIES[status], {
    status,
    headers: { 'content-type': 'text/plain', 'cache-control': 'no-store, no-transform' },
  });

const json = (status, obj) =>
  new Response(`${JSON.stringify(obj)}\n`, {
    status,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store, no-transform' },
  });

const isSet = (v) => v !== undefined && v !== null && v !== '';

const gateStub = (env) => env.GATE.get(env.GATE.idFromName('gate'), { locationHint: 'apac' });

// ---- the public route -----------------------------------------------------------

async function publicRoute(request, env, ctx, pq) {
  // The front check: a GET, the exact path (no query), exactly one well-formed
  // Authorization. Anything else is the 404, spends no budget, touches no database.
  if (request.method !== 'GET') return fixed(404);
  const m = TARGET.exec(pq);
  if (!m) return fixed(404);
  const a = INVITE_AUTH.exec(request.headers.get('authorization') ?? '');
  if (!a) return fixed(404);
  const serial = Number(m[1]);
  const name = m[2];

  // A Worker without its pepper cannot judge any guess: the same 503 for every well-formed request.
  if (typeof env.INVITE_PEPPER !== 'string' || env.INVITE_PEPPER.length < 16) return fixed(503);

  let stub;
  let src;
  let verdict;
  try {
    const tag = await hmacHex(env.INVITE_PEPPER, 'invite', a[1]);
    src = await sourceKey(env.INVITE_PEPPER, request.headers.get('cf-connecting-ip'));
    stub = gateStub(env);
    verdict = await stub.decide({ src, tag, serial, name });
  } catch {
    return fixed(503); // the Gate call itself failed, before any decision
  }
  if (!verdict) return fixed(503);
  if (verdict.status === 429) return fixed(429);
  if (verdict.status !== 200) return fixed(404);

  // After the gate: any fault is the same 404 and the same one budget write,
  // and the reservation is released. Only the gate's decision may change an answer.
  const rid = verdict.rid ?? null;
  const fault = async (body) => {
    if (body) await body.cancel().catch(() => undefined);
    try {
      await stub.reject({ src, rid });
    } catch {
      // not written: the count stays spent (the safe direction), the answer stays the 404
    }
    return fixed(404);
  };

  let obj = null;
  try {
    obj = await env.KIT.get(verdict.key);
  } catch {
    return fault(null);
  }
  if (!obj || !obj.body) return fault(null);
  const stored = obj.checksums && obj.checksums.sha256 ? toHex(obj.checksums.sha256) : '';
  if (obj.size !== verdict.size || stored !== verdict.sha256) return fault(obj.body);

  // Range is never read, the Cache API never used, nothing redirects.
  const { readable, writable } = new FixedLengthStream(verdict.size);
  const pump = obj.body.pipeTo(writable);
  // A client that cuts the stream cancels the readable, and pipeTo rejects: give the download back.
  // A Worker that dies mid-send never gets here: the count stays spent (safe).
  // Whether this fires on a real disconnect is measured on staging (spec (a)).
  ctx.waitUntil(
    pump.then(
      () => undefined,
      async () => {
        if (rid === null) return;
        try {
          await stub.release({ rid });
        } catch {
          // not released: the count stays spent
        }
      },
    ),
  );
  return new Response(readable, {
    status: 200,
    headers: { 'content-type': 'application/octet-stream', 'cache-control': 'no-store, no-transform' },
  });
}

// ---- admin calls ------------------------------------------------------------------

// Authorization: KitAdmin <role> <ts_ms> <128 hex>. The signed message is
// kit-admin-v1\n<role>\n<ts_ms>\n<METHOD>\n<path>\n<sha256hex(body)>, Ed25519
// over the raw bytes (openssl pkeyutl -rawin makes it).
const ADMIN_AUTH = /^KitAdmin (upload|gateway) ([1-9][0-9]{12,15}) ([0-9a-f]{128})$/;
const HEX64 = /^[0-9a-f]{64}$/;
const SKEW_MS = LIMITS.adminSkewMs;
// The Gate trusts the size and sha256 of a file record, so the bytes go to R2 first and are read back.

const ERROR_STATUS = {
  'bad-request': 400, expired: 400, stale: 401, forbidden: 403, replay: 409, conflict: 409,
  rollback: 409, revoked: 409, 'ceiling-life': 422, 'ceiling-downloads': 422, 'ceiling-open': 422,
};

const gateAdmin = async (env, role, ts, op, args) => {
  let r;
  try {
    r = await gateStub(env).admin(role, ts, op, args);
  } catch {
    return json(503, { ok: false, error: 'unavailable' });
  }
  if (r && r.ok) return json(200, r);
  return json(ERROR_STATUS[r && r.error] ?? 400, { ok: false, error: (r && r.error) || 'bad-request' });
};

// R2 holds the bytes and says what it holds: {size, sha256} or null.
async function readBack(env, key) {
  const o = await env.KIT.head(key);
  if (!o || !o.checksums || !o.checksums.sha256) return null;
  return { size: o.size, sha256: toHex(o.checksums.sha256) };
}

// One write-once object. Returns null when R2 holds exactly {sha256, size}
// afterwards (this write or an earlier identical one), else a reply.
async function putOnce(env, key, body, sha256, size) {
  try {
    // onlyIf etagDoesNotMatch '*': an existing key is never overwritten (put returns null).
    // sha256: R2 itself refuses other bytes (put throws), so nothing wrong is ever stored.
    await env.KIT.put(key, body, { sha256, onlyIf: { etagDoesNotMatch: '*' } });
  } catch {
    return json(422, { ok: false, error: 'checksum' });
  }
  const held = await readBack(env, key);
  if (!held) return json(502, { ok: false, error: 'readback' });
  if (held.sha256 !== sha256 || held.size !== size) return json(409, { ok: false, error: 'conflict' });
  return null;
}

async function putBundle(request, env, ctx, a) {
  const serial = Number(a.params[0]);
  const declared = request.headers.get('content-length');
  if (declared === null || !/^[1-9][0-9]{0,11}$/.test(declared)) return json(411, { ok: false, error: 'length-required' });
  const size = Number(declared);
  if (size > LIMITS.maxBundleBytes) return json(413, { ok: false, error: 'too-large' });
  if (request.body === null) return json(400, { ok: false, error: 'bad-request' });
  const refused = await putOnce(env, bundleKey(serial), request.body, a.digest, size);
  if (refused) return refused;
  return gateAdmin(env, a.role, a.ts, 'putBundle', { serial, sha256: a.digest, size });
}

async function putGateway(request, env, ctx, a) {
  const doc = parseJson(a.body);
  const json_ = doc && fromBase64(doc.json);
  const sig = doc && fromBase64(doc.sig);
  if (!json_ || !sig || json_.byteLength > LIMITS.maxGatewayJsonBytes || sig.byteLength > LIMITS.maxGatewaySigBytes) {
    return json(400, { ok: false, error: 'bad-request' });
  }
  const gserial = Number(a.params[0]);
  const parts = [
    [GATEWAY_JSON, json_],
    [GATEWAY_SIG, sig],
  ];
  const meta = {};
  // Both objects first (a lower serial only writes its own keys: the served pointer
  // does not move until setGateway, which refuses a rollback), then the pair at once.
  for (const [n, bytes] of parts) {
    const sha256 = await sha256Hex(bytes);
    const refused = await putOnce(env, gatewayKey(gserial, n), bytes, sha256, bytes.byteLength);
    if (refused) return refused;
    meta[n] = { sha256, size: bytes.byteLength };
  }
  return gateAdmin(env, a.role, a.ts, 'setGateway', { gserial, json: meta[GATEWAY_JSON], sig: meta[GATEWAY_SIG] });
}

async function setFloor(request, env, ctx, a) {
  const doc = parseJson(a.body);
  if (!doc) return json(400, { ok: false, error: 'bad-request' });
  return gateAdmin(env, a.role, a.ts, 'setFloor', { floor: doc.floor });
}

async function addInvite(request, env, ctx, a) {
  const d = parseJson(a.body);
  if (!d || typeof d.code !== 'string' || !CODE.test(d.code)) return json(400, { ok: false, error: 'bad-request' });
  if (typeof env.INVITE_PEPPER !== 'string' || env.INVITE_PEPPER.length < 16) return json(503, { ok: false, error: 'unavailable' });
  // The Worker computes the HMAC tag and drops the code: only the tag goes to the Gate.
  const tag = await hmacHex(env.INVITE_PEPPER, 'invite', d.code);
  const { ref, tier, lo, hi, exp, cap } = d;
  return gateAdmin(env, a.role, a.ts, 'addInvite', { ref, tag, tier, lo, hi, exp, cap });
}

const revokeInvite = (request, env, ctx, a) => gateAdmin(env, a.role, a.ts, 'revokeInvite', { ref: a.params[0] });
const health = (request, env, ctx, a) => gateAdmin(env, a.role, a.ts, 'health', {});

// `stream`: the body goes straight to R2, so its digest comes from X-Kit-Sha256
// (signed, and enforced by R2 itself); every other body is small and hashed here.
const ADMIN_ROUTES = [
  { method: 'PUT', re: /^\/_k\/file\/([1-9][0-9]{0,8})\/bundle\.tar$/, role: 'upload', stream: true, run: putBundle },
  { method: 'PUT', re: /^\/_k\/gateway\/([1-9][0-9]{0,8})$/, role: 'upload', max: 131072, run: putGateway },
  { method: 'PUT', re: /^\/_k\/floor$/, role: 'upload', max: 1024, run: setFloor },
  { method: 'POST', re: /^\/_k\/invite$/, role: 'gateway', max: 4096, run: addInvite },
  { method: 'DELETE', re: /^\/_k\/invite\/([A-Za-z0-9_-]{8,64})$/, role: 'gateway', max: 0, run: revokeInvite },
  { method: 'GET', re: /^\/_k\/state$/, role: 'gateway', max: 0, run: health },
];

async function adminRoute(request, env, ctx, pq) {
  let route = null;
  let params = [];
  for (const r of ADMIN_ROUTES) {
    const m = r.method === request.method ? r.re.exec(pq) : null;
    if (m) {
      route = r;
      params = m.slice(1);
      break;
    }
  }
  const auth = ADMIN_AUTH.exec(request.headers.get('authorization') ?? '');
  if (!route || !auth) return fixed(404);
  const [, role, tsText, sigHex] = auth;
  const ts = Number(tsText);
  if (!Number.isSafeInteger(ts) || Math.abs(Date.now() - ts) > SKEW_MS) return fixed(404);
  const pubHex = role === 'upload' ? env.KIT_UP_PUB : env.KIT_GW_PUB;
  if (typeof pubHex !== 'string' || !HEX64.test(pubHex)) return fixed(404); // key not set: no admin

  let body = null;
  let digest;
  if (route.stream) {
    digest = request.headers.get('x-kit-sha256');
    if (typeof digest !== 'string' || !HEX64.test(digest)) return fixed(404);
  } else {
    body = await readCapped(request, route.max);
    if (body === null) return fixed(404);
    digest = await sha256Hex(body);
  }

  let good = false;
  try {
    const key = await crypto.subtle.importKey('raw', fromHex(pubHex), { name: 'Ed25519' }, false, ['verify']);
    const message = `kit-admin-v1\n${role}\n${tsText}\n${request.method}\n${pq}\n${digest}`;
    good = await crypto.subtle.verify({ name: 'Ed25519' }, key, fromHex(sigHex), new TextEncoder().encode(message));
  } catch {
    good = false;
  }
  if (!good) return fixed(404); // a bad or unsigned call spends no budget

  // Authentic from here on: replies may say why.
  if (role !== route.role) return json(403, { ok: false, error: 'forbidden' });
  return route.run(request, env, ctx, { role, ts, digest, body, params });
}

// ---- entry -----------------------------------------------------------------------------

export default {
  async fetch(request, env, ctx) {
    try {
      // The phone break-glass: set (any non-empty value) and every request is the 404.
      if (isSet(env.KIT_DISABLED)) return fixed(404);
      const pq = rawPathAndQuery(request.url);
      if (pq.startsWith('/_k/')) return await adminRoute(request, env, ctx, pq);
      return await publicRoute(request, env, ctx, pq);
    } catch {
      return fixed(503); // a platform fault, not a decision
    }
  },
};
