# kit/ - the serverless kit host (K4: the Gate)

Public on purpose: this is access-control code, better audited than hidden.
Nothing secret lives here. The only secret, `INVITE_PEPPER`, is a write-only
Worker secret; the Gate never sees it (it receives HMAC tags and 16-hex source
keys, both computed by the Worker front, K5).

| File | What |
|---|---|
| `gate.js` | `export class Gate extends DurableObject` (SQLite-backed, one instance). RPC: `decide`, `release`, `reject`, `admin`. Migration: `new_sqlite_classes: ["Gate"]`. |
| `gate-core.js` | All logic over `storage.sql.exec / transactionSync / sync`. No Cloudflare import. |
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
