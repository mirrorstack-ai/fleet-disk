// Test harness for the Worker front: the real worker.js and the real Gate
// class, over the node:sqlite stand-in for Durable Object storage, a Map-backed
// stand-in for R2, and Node's WebCrypto (the same Ed25519 and HMAC as Workers).
// Not a test file: the name does not end in .test.js.
import { registerHooks } from 'node:module';
import { fakeStorage } from './fake-storage.js';
import { sha256Hex, toHex, fromHex } from './worker-util.js';

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

// FixedLengthStream is a Workers global: too many or too few bytes is an error.
const PolyfillFixedLengthStream = class FixedLengthStream {
  constructor(length) {
    let seen = 0;
    const ts = new TransformStream({
      transform(chunk, controller) {
        seen += chunk.byteLength;
        if (seen > length) throw new TypeError('too many bytes');
        controller.enqueue(chunk);
      },
      flush() {
        if (seen !== length) throw new TypeError('too few bytes');
      },
    });
    this.readable = ts.readable;
    this.writable = ts.writable;
  }
};
// Every constructor length is recorded: a test pins that the Worker streams with an exact length.
export const fixedLengths = [];
const BaseFixedLengthStream = globalThis.FixedLengthStream ?? PolyfillFixedLengthStream;
globalThis.FixedLengthStream = class extends BaseFixedLengthStream {
  constructor(length) {
    super(length);
    fixedLengths.push(length);
  }
};

const { default: worker, Gate } = await import('./worker.js');
export { worker, Gate };

const enc = new TextEncoder();
export const bytesOf = (n, seed = 7) => Uint8Array.from({ length: n }, (_, i) => (i * 31 + seed) & 255);

export function streamOf(bytes, chunk = 65536) {
  let at = 0;
  return new ReadableStream({
    pull(c) {
      if (at >= bytes.byteLength) return c.close();
      c.enqueue(bytes.slice(at, at + chunk));
      at += chunk;
    },
  });
}

const metaOf = (o) => ({ size: o.bytes.byteLength, etag: o.sha.slice(0, 32), checksums: { sha256: fromHex(o.sha).buffer } });

export function fakeR2() {
  const objs = new Map();
  const r2 = {
    objs,
    failGet: false,
    puts: 0,
    async head(key) {
      const o = objs.get(key);
      return o ? metaOf(o) : null;
    },
    async get(key) {
      if (r2.failGet) throw new Error('r2 down');
      const o = objs.get(key);
      return o ? { ...metaOf(o), body: streamOf(o.bytes) } : null;
    },
    async put(key, body, opts = {}) {
      r2.puts++;
      if (opts.onlyIf && opts.onlyIf.etagDoesNotMatch === '*' && objs.has(key)) return null;
      const bytes = body instanceof Uint8Array ? body : new Uint8Array(await new Response(body).arrayBuffer());
      const sha = await sha256Hex(bytes);
      if (opts.sha256 && opts.sha256 !== sha) throw new Error('checksum mismatch');
      objs.set(key, { bytes, sha });
      return metaOf(objs.get(key));
    },
  };
  return r2;
}

export async function makeHarness(extra = {}) {
  const storage = fakeStorage();
  const keys = {};
  const pub = {};
  for (const role of ['upload', 'gateway']) {
    keys[role] = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    pub[role] = toHex(await crypto.subtle.exportKey('raw', keys[role].publicKey));
  }
  const env = {
    INVITE_PEPPER: 'test-pepper-0123456789abcdef',
    KIT: fakeR2(),
    KIT_UP_PUB: pub.upload,
    KIT_GW_PUB: pub.gateway,
    ...extra,
  };
  const gate = new Gate({ storage, blockConcurrencyWhile: (f) => f() }, env);
  const calls = { namespace: 0, hints: [], decide: 0, release: 0, reject: 0, admin: 0 };
  const h = { env, storage, gate, keys, calls, broken: false, lastTs: 0, pending: [] };
  const stub = {};
  for (const m of ['decide', 'release', 'reject', 'admin']) {
    stub[m] = (...a) => {
      calls[m]++;
      if (h.broken) throw new Error('gate down');
      return gate[m](...a);
    };
  }
  env.GATE = {
    idFromName: (n) => `id:${n}`,
    get(id, opts) {
      calls.namespace++;
      calls.hints.push([id, opts]);
      return stub;
    },
  };
  h.ctx = { waitUntil: (p) => h.pending.push(p) };
  h.settle = async () => {
    await Promise.allSettled(h.pending.splice(0));
  };
  h.q = (sql, ...a) => storage.db.prepare(sql).all(...a).map((r) => ({ ...r }));
  return h;
}

// ---- public requests ---------------------------------------------------------------

export const CODE = 'CCCC2222VV';
export const url = (path) => `https://kit.test${path}`;

export function get(h, path, { code = CODE, headers = {}, method = 'GET', ip = '203.0.113.9', auth } = {}) {
  const hd = new Headers({ 'cf-connecting-ip': ip, ...headers });
  const a = auth ?? (code === null ? null : `FleetInvite ${code}`);
  if (a !== null) hd.set('authorization', a);
  return worker.fetch(new Request(url(path), { method, headers: hd }), h.env, h.ctx);
}

export async function read(res) {
  return { status: res.status, headers: [...res.headers].sort(), body: new Uint8Array(await res.arrayBuffer()) };
}

// ---- admin requests -----------------------------------------------------------------------

export async function admin(h, role, method, path, body = null, o = {}) {
  const bytes = body === null ? new Uint8Array(0) : typeof body === 'string' ? enc.encode(body) : body;
  h.lastTs = Math.max(Date.now(), h.lastTs + 1);
  const ts = o.ts ?? h.lastTs;
  const digest = o.digest ?? (await sha256Hex(bytes));
  const signedPath = o.signedPath ?? path;
  const signedMethod = o.signedMethod ?? method;
  const message = `kit-admin-v1\n${o.signedRole ?? role}\n${ts}\n${signedMethod}\n${signedPath}\n${digest}`;
  const sigBytes = await crypto.subtle.sign('Ed25519', keysFor(h, o.keyRole ?? role), enc.encode(message));
  const headers = new Headers({
    authorization: o.auth ?? `KitAdmin ${role} ${ts} ${toHex(sigBytes)}`,
    'content-length': String(o.contentLength ?? bytes.byteLength),
  });
  if (o.stream) headers.set('x-kit-sha256', digest);
  if (o.noAuth) headers.delete('authorization');
  if (o.contentLength === null) headers.delete('content-length');
  const init = { method, headers };
  if (bytes.byteLength || o.stream) {
    init.body = bytes;
    init.duplex = 'half';
  }
  return worker.fetch(new Request(url(path), init), h.env, h.ctx);
}
const keysFor = (h, role) => h.keys[role].privateKey;

export const jsonOf = async (res) => JSON.parse(await res.text());

export const day = 24 * 60 * 60 * 1000;
export const inviteBody = (o = {}) =>
  JSON.stringify({ ref: 'ref-00000001', code: CODE, tier: 'install', lo: 1, hi: 100, exp: Date.now() + day, cap: 10, ...o });

export const addInvite = (h, o = {}) => admin(h, 'gateway', 'POST', '/_k/invite', inviteBody(o));

export const uploadBundle = (h, serial, bytes, o = {}) =>
  admin(h, 'upload', 'PUT', `/_k/file/${serial}/bundle.tar`, bytes, { stream: true, ...o });

export const b64 = (bytes) => Buffer.from(bytes).toString('base64');
export const uploadGateway = (h, gserial, jsonBytes, sigBytes, o = {}) =>
  admin(h, 'upload', 'PUT', `/_k/gateway/${gserial}`, JSON.stringify({ json: b64(jsonBytes), sig: b64(sigBytes) }), o);

// A harness with one invite (CODE) and bundle 5 served.
export async function ready(extra = {}, bytes = bytesOf(200000)) {
  const h = await makeHarness(extra);
  const r1 = await addInvite(h);
  const r2 = await uploadBundle(h, 5, bytes);
  if (r1.status !== 200 || r2.status !== 200) throw new Error(`setup failed ${r1.status} ${r2.status}`);
  h.bytes = bytes;
  return h;
}
