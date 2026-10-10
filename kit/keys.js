// Pure helpers the Worker front uses before it calls the Gate. WebCrypto only,
// so they run in Workers and in Node. Nothing here logs or stores anything.
//
//   inviteTag(pepper, code)    D2: HMAC-SHA256(pepper, code), 64 hex
//   sourceKey(pepper, address) D3: first 16 hex of HMAC(pepper, source), IPv4 as
//                              /32, IPv6 as /64, nothing parseable -> "?"
//   parseGuess(method, url, authorization)
//                              D1: the well-formed test; null = not a guess,
//                              answer 404 and spend no budget

const enc = new TextEncoder();
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');

async function hmacHex(pepper, message) {
  const key = await crypto.subtle.importKey('raw', typeof pepper === 'string' ? enc.encode(pepper) : pepper, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return hex(await crypto.subtle.sign('HMAC', key, enc.encode(message)));
}

export const CODE_ALPHABET = '23456789CFGHJMPQRVWX';
const GUESS_PATH = /^\/v1\/kit\/([0-9]{1,9})\/(bundle\.tar|gateway\.json|gateway\.json\.sig)$/;
const AUTH = /^FleetInvite ([23456789CFGHJMPQRVWX]{10})$/;

export function inviteTag(pepper, code) {
  return hmacHex(pepper, code);
}

export async function sourceKey(pepper, address) {
  return (await hmacHex(pepper, canonicalSource(address))).slice(0, 16);
}

export function canonicalSource(address) {
  if (typeof address !== 'string') return '?';
  let a = address.trim();
  if (a.startsWith('[') && a.endsWith(']')) a = a.slice(1, -1);
  const v4 = parseIPv4(a);
  if (v4) return `4:${v4.join('.')}`;
  const g = parseIPv6(a);
  if (!g) return '?';
  // IPv4-mapped (::ffff:a.b.c.d) is the same host as a.b.c.d.
  if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) {
    return `4:${[g[6] >> 8, g[6] & 255, g[7] >> 8, g[7] & 255].join('.')}`;
  }
  return `6:${g.slice(0, 4).map((x) => x.toString(16).padStart(4, '0')).join(':')}`; // the /64
}

function parseIPv4(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return null;
  const o = m.slice(1).map(Number);
  return o.every((x) => x <= 255) ? o : null;
}

function parseIPv6(s) {
  const z = s.indexOf('%'); // zone id
  if (z >= 0) s = s.slice(0, z);
  if (!s.includes(':')) return null;
  let tail = [];
  const lastColon = s.lastIndexOf(':');
  const last = s.slice(lastColon + 1);
  if (last.includes('.')) {
    const v4 = parseIPv4(last);
    if (!v4) return null;
    tail = [(v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]];
    s = s.slice(0, lastColon + 1) + '0:0'; // placeholder groups, replaced below
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const grp = (t) => (t === '' ? [] : t.split(':'));
  const head = grp(halves[0]);
  const rest = halves.length === 2 ? grp(halves[1]) : [];
  const all = [...head, ...rest];
  if (!all.every((x) => /^[0-9a-fA-F]{1,4}$/.test(x))) return null;
  let groups;
  if (halves.length === 2) {
    if (all.length > 7) return null;
    groups = [...head, ...Array(8 - all.length).fill('0'), ...rest];
  } else {
    if (all.length !== 8) return null;
    groups = head;
  }
  const out = groups.map((x) => parseInt(x, 16));
  if (tail.length) {
    out[6] = tail[0];
    out[7] = tail[1];
  }
  return out;
}

/**
 * D1. `url` is the raw request URL or path+query. Returns {serial, name, code}
 * only for GET /v1/kit/<1-9 digits>/(bundle.tar|gateway.json|gateway.json.sig)
 * with no query string and one Authorization header of exactly
 * `FleetInvite <10 symbols of the alphabet>`; anything else is null.
 */
export function parseGuess(method, url, authorization) {
  if (method !== 'GET' || typeof url !== 'string' || typeof authorization !== 'string') return null;
  let pathAndQuery = url;
  if (!url.startsWith('/')) {
    const m = /^https?:\/\/[^/?#]*(\/[^#]*)?/i.exec(url);
    if (!m) return null;
    pathAndQuery = m[1] || '/';
  }
  const p = GUESS_PATH.exec(pathAndQuery); // a query string makes this a non-match
  const a = AUTH.exec(authorization);
  if (!p || !a) return null;
  return { serial: Number(p[1]), name: p[2], code: a[1] };
}
