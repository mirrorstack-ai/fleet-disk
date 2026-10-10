# kit/ - the serverless kit host (K4: the Gate)

Public on purpose: this is access-control code, better audited than hidden.
Nothing secret lives here. The only secret, `INVITE_PEPPER`, is a write-only
Worker secret; the Gate never sees it (it receives HMAC tags and 16-hex source
keys).

| File | What |
|---|---|
| `gate.js` | `export class Gate extends DurableObject` (SQLite-backed, one instance). RPC: `decide`, `release`, `reject`, `admin`. Migration: `new_sqlite_classes: ["Gate"]`. |
| `gate-core.js` | All logic over `storage.sql.exec / transactionSync / sync`. No Cloudflare import. |
| `keys.js` | Front helpers: `inviteTag` (D2), `sourceKey` (D3, IPv6 per /64), `parseGuess` (D1). |
| `fake-storage.js` | `node:sqlite` stand-in for `ctx.storage` (tests only). |
| `*.test.js`, `run-tests.js` | `node --test kit/` (Node 22.15+; built-ins only). |

Front contract (for the Worker, K5):

1. `parseGuess(method, url, authorization)` is null: answer the 404, call nothing, spend nothing (D1).
2. Else `decide({src: await sourceKey(pepper, ip), tag: await inviteTag(pepper, code), serial, name})`.
   - `{status: 429}` or `{status: 404}`: send the fixed answer.
   - `{status: 200, key, size, sha256, rid}`: read R2 `key`; if missing, wrong size or wrong stored sha256, or R2 errors, call `reject({src, rid})` and send the same 404; else stream with an exact Content-Length. If the client cuts the stream, call `release({rid})` (rid is null for the gateway pair: nothing to release).
   - A thrown error from the Gate is the 503.
3. Admin: verify the Ed25519 signature, then `admin(role, ts_ms, op, args)`.
   `upload`: `putBundle {serial, sha256, size}`, `setGateway {gserial, json:{sha256,size}, sig:{sha256,size}}`, `setFloor {floor}`.
   `gateway`: `addInvite {ref, tag, tier, lo, hi, exp, cap}`, `revokeInvite {ref}`, `health`, `invites`.
   Any `{ok: false}` is the front's 404 (or 409/422 for the signed callers, as K5 decides); nothing spends source budget.
