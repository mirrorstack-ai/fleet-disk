// Pure helpers of the Worker front (worker.js). No Cloudflare import, so plain
// Node tests load it directly. Nothing in here logs or stores an address, a
// code or a key.
//
// WebCrypto (HMAC, SHA-256, Ed25519) is the global `crypto.subtle` in Workers
// and in Node. Ed25519 is the standard "Ed25519" algorithm name:
// https://developers.cloudflare.com/workers/runtime-apis/web-crypto/

const enc = new TextEncoder();

export const toHex = (bytes) => {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = '';
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
  return s;
};

export const fromHex = (h) => {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
};

export const sha256Hex = async (bytes) => toHex(await crypto.subtle.digest('SHA-256', bytes));

// HMAC-SHA256(pepper, label \n value) as hex. The label separates the uses of
// the one pepper (invite tags, source keys), so one can never stand in for the other.
export async function hmacHex(pepper, label, value) {
  const key = await crypto.subtle.importKey('raw', enc.encode(pepper), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return toHex(await crypto.subtle.sign('HMAC', key, enc.encode(`${label}\n${value}`)));
}

// ---- the public front shape ------------------------------------------------

// The only public path: /v1/kit/<1-9 digits>/<one of three names>, no query.
export const TARGET = /^\/v1\/kit\/([0-9]{1,9})\/(bundle\.tar|gateway\.json|gateway\.json\.sig)$/;
// The one Authorization value: the scheme and a code of 10 symbols of the invite alphabet (N02).
export const INVITE_AUTH = /^FleetInvite ([23456789CFGHJMPQRVWX]{10})$/;
export const CODE = /^[23456789CFGHJMPQRVWX]{10}$/;

// Path and query exactly as the client sent them: sliced from the URL string,
// never re-built from a parsed URL, so nothing is normalised or decoded.
export function rawPathAndQuery(url) {
  const i = url.indexOf('//');
  const j = url.indexOf('/', i < 0 ? 0 : i + 2);
  return j < 0 ? '/' : url.slice(j);
}

// ---- the source of a request -------------------------------------------------

const octets = (s) => {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return null;
  const o = m.slice(1).map(Number);
  return o.every((n) => n <= 255) ? o : null;
};

function parseV6(s) {
  if (!/^[0-9a-f:.]+$/.test(s) || !s.includes(':')) return null;
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const part = (p) => {
    if (p === '') return [];
    const items = p.split(':');
    const out = [];
    for (let i = 0; i < items.length; i++) {
      const it = items[i];
      if (it.includes('.')) {
        const o = i === items.length - 1 ? octets(it) : null;
        if (!o) return null;
        out.push(o[0] * 256 + o[1], o[2] * 256 + o[3]);
      } else {
        if (!/^[0-9a-f]{1,4}$/.test(it)) return null;
        out.push(parseInt(it, 16));
      }
    }
    return out;
  };
  const head = part(halves[0]);
  const tail = halves.length === 2 ? part(halves[1]) : [];
  if (!head || !tail) return null;
  if (halves.length === 1) return head.length === 8 ? head : null;
  const fill = 8 - head.length - tail.length;
  return fill < 1 ? null : [...head, ...Array(fill).fill(0), ...tail];
}

/**
 * The address a budget is kept for, as a plain string that is hashed at once:
 * an IPv4 address is a /32 (all of it); an IPv6 address is a /64 (its first
 * four groups, so a client cannot dodge the budget by rotating inside its own
 * prefix); an IPv4-mapped IPv6 address counts as the IPv4 address. Anything
 * unreadable shares one 'unknown' source, which is the safe direction: it
 * spends its own budget, not another client's.
 */
export function sourceOf(raw) {
  if (typeof raw !== 'string') return 'unknown';
  let s = raw.trim().toLowerCase();
  const z = s.indexOf('%');
  if (z >= 0) s = s.slice(0, z); // an IPv6 zone id
  const v4 = octets(s);
  if (v4) return `4:${v4.join('.')}`;
  const g = parseV6(s);
  if (!g) return 'unknown';
  if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) {
    return `4:${[g[6] >> 8, g[6] & 255, g[7] >> 8, g[7] & 255].join('.')}`;
  }
  return `6:${g.slice(0, 4).map((x) => x.toString(16).padStart(4, '0')).join(':')}`;
}

/** The 16-hex source key the Gate stores: no raw address leaves this function. */
export async function sourceKey(pepper, rawAddress) {
  return (await hmacHex(pepper, 'src', sourceOf(rawAddress))).slice(0, 16);
}

// ---- request bodies -------------------------------------------------------------

/**
 * The whole body, if it is at most `max` bytes; otherwise null (the caller
 * answers the one 404: a body that cannot be authentic is a bad call). The
 * declared length is checked first, and the stream is cut off at the cap.
 */
export async function readCapped(request, max) {
  const declared = request.headers.get('content-length');
  if (declared !== null && (!/^[0-9]{1,12}$/.test(declared) || Number(declared) > max)) return null;
  if (request.body === null) return new Uint8Array(0);
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel().catch(() => undefined);
      return null;
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let at = 0;
  for (const c of chunks) {
    out.set(c, at);
    at += c.byteLength;
  }
  return out;
}

// Strict base64: canonical padding, standard alphabet; null for anything else.
export function fromBase64(s) {
  if (typeof s !== 'string' || s.length === 0 || s.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(s)) return null;
  try {
    const bin = atob(s);
    const out = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    return btoa(bin) === s ? out : null;
  } catch {
    return null;
  }
}

export function parseJson(bytes) {
  try {
    const v = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    return v !== null && typeof v === 'object' && !Array.isArray(v) ? v : null;
  } catch {
    return null;
  }
}
