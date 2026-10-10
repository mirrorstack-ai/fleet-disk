# kit/ - the serverless kit host (K4: the Gate, K5: the Worker front)

Public on purpose: this is access-control code, better audited than hidden.
Nothing secret lives here. The only secret, `INVITE_PEPPER`, is a write-only
Worker secret; the Gate never sees it (it receives HMAC tags and 16-hex source
keys, both computed by the Worker front, K5).

| File | What |
|---|---|
| `gate.js` | `export class Gate extends DurableObject` (SQLite-backed, one instance). RPC: `decide`, `release`, `reject`, `admin`. Migration: `new_sqlite_classes: ["Gate"]`. |
| `gate-core.js` | All logic over `storage.sql.exec / transactionSync / sync`. No Cloudflare import. |
| `worker.js` | The Worker: `export default {fetch}` and `export {Gate}`. Public route, fixed answers, R2 reads and writes, `/_k/*` admin routes. |
| `worker-util.js` | Pure helpers: path and header shapes, HMAC, source key (IPv4 /32, IPv6 /64), capped body reads, strict base64. |
| `wrangler.jsonc` | Deploy config for `fleet-kit` and, under `env.staging`, `fleet-kit-staging`. |
| `worker-harness.test-util.js` | Tests only: real `worker.js` and `Gate` over `node:sqlite`, a Map-backed R2, Node WebCrypto. |
| `fake-storage.js` | `node:sqlite` stand-in for `ctx.storage` (tests only). |
| `*.test.js`, `run-tests.js` | `node --test kit/` from the repo root, or `npm test` in `kit/` (Node 22.15+; built-ins only). `run-tests.js` exists because `node --test <directory>` does not resolve on recent Node. |

## Gate RPC

- `decide({src, tag, serial, name})` returns `{status: 429}`, `{status: 404}` or
  `{status: 200, key, size, sha256, rid}` (`rid` is null for the gateway pair).
  - The per-invite download cap applies to `bundle.tar` only. The gateway pair
    (`gateway.json`, `gateway.json.sig`) never counts against the cap and never
    reserves: it stays readable behind a live (found, not revoked, in range,
    unexpired) invite until that invite expires, even when every download is
    used. This is deliberate (the bootstrap may fetch the pair after the bundle).
  - A failed decision is one budget write; a 429 writes nothing.
- `release({rid})` gives a cut download back (at most 3 per invite).
- `reject({src, rid})` is a fault after a yes (R2 missing, wrong size or sha256).
- `admin(role, ts_ms, op, args)` after the Worker has verified the Ed25519 signature.
  - `upload`: `putBundle {serial, sha256, size}`, `setGateway {gserial, json:{sha256,size}, sig:{sha256,size}}`, `setFloor {floor}`.
  - `gateway`: `addInvite {ref, tag, tier, lo, hi, exp, cap}`, `revokeInvite {ref}`, `health`.
  - `tier` is `install` or `update`. Every timestamp, `ts` and `exp` included, is
    epoch MILLISECONDS (kit-serve uses seconds; the pusher converts).

## Ordering the Worker must keep

`putBundle` and `setGateway` record metadata and, for `setGateway`, flip the
served pointer at once. The Gate trusts that metadata. So the Worker writes the
R2 objects first, reads them back (size and sha256), and only then calls
`putBundle` / `setGateway`. Recording first, or an R2 write that then fails,
makes every fetch pass the gate and miss in R2; each miss is a `reject`, which
is a budget write, and installers lock themselves out (30 an hour per source,
600 in all).

## KIT_FLOOR

The dashboard `KIT_FLOOR` is the break-glass for a bad serial. Unset
(undefined, null, empty) is no floor. A number or digit string is the floor. Any
other value fails closed: every request is a 404 and `health` reports
`floorError: true`.

## The Worker front (K5)

Public: `GET /v1/kit/<1-9 digits>/<bundle.tar|gateway.json|gateway.json.sig>` with exactly
`Authorization: FleetInvite <10 symbols of 23456789CFGHJMPQRVWX>`. Anything else (method,
path, query, header) is the one 404 and never reaches the Gate. Fixed answers: 404
`not found\n`, 429 `try later\n`, 503 `unavailable\n`; `text/plain`, `no-store, no-transform`.
A 200 is `application/octet-stream` with an exact Content-Length (`FixedLengthStream`);
Range, the Cache API and redirects are never used. After a yes from the Gate, an R2
miss, wrong size or wrong stored sha256, or an R2 error is `reject` (release plus one
budget write) and the same 404. A cut stream is `release` through `ctx.waitUntil`.
Worker variables: `INVITE_PEPPER` (secret, 16+ chars; absent is a 503 for well-formed
requests), `KIT_DISABLED` (any non-empty value: all 404), `KIT_FLOOR` (read by the Gate),
`KIT_GW_PUB` / `KIT_UP_PUB` (raw Ed25519 public keys, 64 hex; empty switches that role off).

### Admin calls

`Authorization: KitAdmin <role> <ts_ms> <signature hex>` where the signature is Ed25519 over the
raw bytes of `kit-admin-v1\n<role>\n<ts_ms>\n<METHOD>\n<path>\n<sha256hex(body)>`
(`openssl pkeyutl -sign -rawin`). `ts_ms` is epoch milliseconds, within 300 s, and strictly
greater than the role's last. The path has no query. A bad, stale-by-clock or unsigned call, an
unknown route, an unset key, or a body over the route's cap is the one 404 and spends no
budget. Once the signature is good, replies are JSON and may say why (400 bad-request,
401 stale, 403 forbidden, 409 replay/conflict/rollback/revoked, 422 ceiling-* or checksum,
503 unavailable).

| Role | Route | Body |
|---|---|---|
| upload | `PUT /_k/file/<serial>/bundle.tar` | the tar. Needs `Content-Length` (at most 100 MiB) and `X-Kit-Sha256: <hex>`, the digest in the signed message. R2 stores it with `sha256` and `onlyIf: {etagDoesNotMatch: '*'}`: other bytes are refused (422), an existing key is never overwritten. Identical bytes: 200 `created:false`. Other bytes: 409. The upload must finish within 300 s of its signed `ts_ms` (the Gate checks the clock when it records the file). |
| upload | `PUT /_k/gateway/<gserial>` | JSON `{"json": "<base64>", "sig": "<base64>"}` (at most 64 KiB and 4 KiB decoded). Both objects go to R2 first (write-once), are read back, then the Gate flips the pointer. A lower serial is 409 rollback. |
| upload | `PUT /_k/floor` | `{"floor": <int>}` |
| gateway | `POST /_k/invite` | `{ref, code, tier, lo, hi, exp, cap}` (`exp` in epoch ms). The Worker computes the HMAC tag from `code` and drops the code. |
| gateway | `DELETE /_k/invite/<ref>` | none |
| gateway | `GET /_k/state` | none: health counts |

### Measured on staging (K6), not here

(a) a real client cut fires the release; (c) R2 refuses wrong bytes and overwrites; (d) the
Free over-quota status; (g) CPU time. The unit tests use stand-ins and say nothing about these.
