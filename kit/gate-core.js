// Gate core: every decision, counter and admin record of the kit host.
//
// Runs inside the Gate Durable Object (see gate.js) and, unchanged, in plain
// Node over node:sqlite (see fake-storage.js). It only needs the part of the
// Durable Object storage API that both provide:
//
//   storage.sql.exec(query, ...bindings) -> cursor with toArray(), rowsWritten
//   storage.transactionSync(fn)          -> runs fn (sync) as one transaction
//   storage.sync()                       -> Promise, resolves once writes are durable
//
// Nothing in here logs, and nothing stores a raw address or a plain invite
// code: invites are keyed by an HMAC tag the Worker front computes, sources by
// a 16-hex HMAC key (see keys.js).
//
// Deviations from kit-serve (spec H10b): D1 only well-formed guesses spend
// budget (the front never calls decide() for anything else; decide() itself
// refuses malformed input without touching the budget), D2 HMAC tags, D3 IPv6
// per /64 (keys.js), D4 budgets live in SQLite and survive restarts.

export const BUNDLE = 'bundle.tar';
export const GATEWAY_JSON = 'gateway.json';
export const GATEWAY_SIG = 'gateway.json.sig';
export const NAMES = [BUNDLE, GATEWAY_JSON, GATEWAY_SIG];

export const LIMITS = Object.freeze({
  perSource: 30, // well-formed failures an hour from one source
  total: 600, // well-formed failures an hour in all
  bucketMs: 10 * 60 * 1000, // budget buckets
  windowMs: 60 * 60 * 1000, // a bucket counts while it overlaps the last hour
  keepMs: 2 * 60 * 60 * 1000, // buckets are deleted after 2 h
  reservationKeepMs: 60 * 60 * 1000, // a reservation can be released for 1 h
  maxOpenInvites: 16,
  maxLifeMs: 72 * 60 * 60 * 1000,
  lifeSlackMs: 5 * 60 * 1000, // = the admin clock window
  maxDownloads: 10,
  maxRefunds: 3,
  adminSkewMs: 5 * 60 * 1000,
  maxSerial: 2 ** 31,
  maxBundleBytes: 100 * 1024 * 1024,
  maxGatewayJsonBytes: 65536,
  maxGatewaySigBytes: 4096,
  tombstoneGraceMs: 60 * 60 * 1000,
});

// Which admin operation each role may call (spec: "Each role can call only its own routes").
export const ROLE_OPS = Object.freeze({
  upload: Object.freeze(['putBundle', 'setGateway', 'setFloor']),
  gateway: Object.freeze(['addInvite', 'revokeInvite', 'health', 'invites']),
});

const HEX64 = /^[0-9a-f]{64}$/;
const SRC = /^[0-9a-f]{16}$/;
const REF = /^[A-Za-z0-9_-]{8,64}$/;
const TIER = /^[A-Za-z0-9_.-]{1,32}$/;

const isInt = (v, lo, hi) => Number.isInteger(v) && v >= lo && v <= hi;
const fail = (error) => ({ ok: false, error });

export class GateCore {
  /**
   * @param storage  the Durable Object storage (or the fake)
   * @param opts.now        () => ms since epoch (default Date.now)
   * @param opts.envFloor   () => the dashboard KIT_FLOOR value (string|number|undefined)
   */
  constructor(storage, opts = {}) {
    this.storage = storage;
    this.sql = storage.sql;
    this.now = opts.now || Date.now;
    this.envFloor = opts.envFloor || (() => undefined);
    this.#migrate();
  }

  #rows(query, ...bindings) {
    return this.sql.exec(query, ...bindings).toArray();
  }

  #run(query, ...bindings) {
    return this.sql.exec(query, ...bindings).rowsWritten;
  }

  #migrate() {
    const ddl = [
      `CREATE TABLE IF NOT EXISTS invites(
         ref TEXT PRIMARY KEY, tag TEXT UNIQUE, tier TEXT NOT NULL,
         lo INTEGER NOT NULL, hi INTEGER NOT NULL, exp INTEGER NOT NULL,
         cap INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0,
         refunds INTEGER NOT NULL DEFAULT 0, revoked INTEGER NOT NULL DEFAULT 0,
         made INTEGER NOT NULL)`,
      `CREATE TABLE IF NOT EXISTS files(
         serial INTEGER NOT NULL, name TEXT NOT NULL, sha256 TEXT NOT NULL,
         size INTEGER NOT NULL, key TEXT NOT NULL, made INTEGER NOT NULL,
         PRIMARY KEY(serial, name))`,
      `CREATE TABLE IF NOT EXISTS gateway(
         gserial INTEGER NOT NULL, name TEXT NOT NULL, sha256 TEXT NOT NULL,
         size INTEGER NOT NULL, key TEXT NOT NULL, made INTEGER NOT NULL,
         PRIMARY KEY(gserial, name))`,
      `CREATE TABLE IF NOT EXISTS fails(
         src TEXT NOT NULL, bucket INTEGER NOT NULL, n INTEGER NOT NULL,
         PRIMARY KEY(src, bucket))`,
      `CREATE TABLE IF NOT EXISTS allfails(
         bucket INTEGER PRIMARY KEY, n INTEGER NOT NULL)`,
      `CREATE TABLE IF NOT EXISTS reservations(
         rid INTEGER PRIMARY KEY AUTOINCREMENT, tag TEXT NOT NULL, made INTEGER NOT NULL)`,
      `CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v)`,
    ];
    for (const d of ddl) this.sql.exec(d);
  }

  // ---- meta -------------------------------------------------------------

  #meta(k) {
    const r = this.#rows('SELECT v FROM meta WHERE k = ?', k);
    return r.length ? r[0].v : undefined;
  }

  #setMeta(k, v) {
    this.#run('INSERT INTO meta(k, v) VALUES(?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v', k, v);
  }

  #effectiveFloor() {
    const stored = Number(this.#meta('floor') || 0);
    const raw = Number(this.envFloor());
    const env = Number.isInteger(raw) && raw > 0 ? raw : 0;
    return Math.max(stored, env);
  }

  // ---- budgets ----------------------------------------------------------

  #minBucket(now) {
    return Math.floor((now - LIMITS.windowMs) / LIMITS.bucketMs);
  }

  #budgetSpent(src, now) {
    const min = this.#minBucket(now);
    const s = this.#rows('SELECT COALESCE(SUM(n), 0) AS n FROM fails WHERE src = ? AND bucket >= ?', src, min)[0].n;
    const t = this.#rows('SELECT COALESCE(SUM(n), 0) AS n FROM allfails WHERE bucket >= ?', min)[0].n;
    return s >= LIMITS.perSource || t >= LIMITS.total;
  }

  // The one budget write of a failed request.
  #recordFailure(src, now) {
    const b = Math.floor(now / LIMITS.bucketMs);
    this.#run('INSERT INTO fails(src, bucket, n) VALUES(?, ?, 1) ON CONFLICT(src, bucket) DO UPDATE SET n = n + 1', src, b);
    this.#run('INSERT INTO allfails(bucket, n) VALUES(?, 1) ON CONFLICT(bucket) DO UPDATE SET n = n + 1', b);
    const old = Math.floor((now - LIMITS.keepMs) / LIMITS.bucketMs);
    this.#run('DELETE FROM fails WHERE bucket < ?', old);
    this.#run('DELETE FROM allfails WHERE bucket < ?', old);
  }

  // ---- public path: decide / release / reject ---------------------------

  /**
   * One decision for one well-formed guess. Runs the same statements for every
   * case. Returns {status: 429} (budget spent, nothing written),
   * {status: 404} (one budget write) or
   * {status: 200, serial, name, key, size, sha256, rid} where rid is the
   * reservation id for bundle.tar (null for the gateway pair). For bundle.tar
   * the reservation is durable (storage.sync) before this resolves.
   */
  async decide({ src, tag, serial, name }) {
    if (typeof src !== 'string' || !SRC.test(src)) throw new TypeError('gate: bad src');
    if (typeof tag !== 'string' || !HEX64.test(tag)) throw new TypeError('gate: bad tag');
    if (!isInt(serial, 0, 999999999)) throw new TypeError('gate: bad serial');
    if (!NAMES.includes(name)) throw new TypeError('gate: bad name');
    const now = this.now();
    let out;
    this.storage.transactionSync(() => {
      out = this.#decideSync(src, tag, serial, name, now);
    });
    if (out.status === 200 && out.rid !== null) await this.storage.sync();
    return out;
  }

  #decideSync(src, tag, serial, name, now) {
    if (this.#budgetSpent(src, now)) return { status: 429 };

    const inv = this.#rows('SELECT * FROM invites WHERE tag = ?', tag)[0];
    const bundle = this.#rows('SELECT * FROM files WHERE serial = ? AND name = ?', serial, BUNDLE)[0];
    const active = this.#meta('gateway_active');
    const gw = this.#rows('SELECT * FROM gateway WHERE gserial = ? AND name = ?', active === undefined ? -1 : active, name)[0];
    const floor = this.#effectiveFloor();
    const isBundle = name === BUNDLE;
    const file = isBundle ? bundle : gw;

    // Every check is evaluated; none is skipped.
    const checks = [
      !!inv,
      !!inv && inv.revoked === 0,
      !!inv && serial >= inv.lo && serial <= inv.hi,
      serial >= floor,
      !!inv && now < inv.exp,
      !!inv && (!isBundle || inv.used < inv.cap),
      !!file,
    ];
    let ok = checks.every(Boolean);
    let rid = null;
    if (ok && isBundle) {
      // The reservation: used+1 and a reservation row, atomically, before any byte.
      if (this.#run('UPDATE invites SET used = used + 1 WHERE tag = ? AND used < cap', tag) > 0) {
        this.#run('INSERT INTO reservations(tag, made) VALUES(?, ?)', tag, now);
        rid = this.#rows('SELECT last_insert_rowid() AS id')[0].id;
        this.#run('DELETE FROM reservations WHERE made < ?', now - LIMITS.reservationKeepMs);
      } else {
        ok = false;
      }
    }
    if (!ok) {
      this.#recordFailure(src, now);
      return { status: 404 };
    }
    return {
      status: 200,
      serial,
      name,
      key: isBundle ? bundleKey(serial) : gatewayKey(file.gserial, name),
      size: file.size,
      sha256: file.sha256,
      rid,
    };
  }

  /**
   * The client cut the stream: give the download back. At most maxRefunds per
   * invite; a second release of the same reservation is a no-op.
   */
  async release({ rid }) {
    if (!isInt(rid, 1, Number.MAX_SAFE_INTEGER)) throw new TypeError('gate: bad rid');
    let released = false;
    this.storage.transactionSync(() => {
      released = this.#releaseSync(rid, true);
    });
    if (released) await this.storage.sync();
    return { released };
  }

  /**
   * A fault after the gate said yes (R2 missing, wrong size or sha256, R2
   * error): release the reservation (no refund cap, it is not the client's
   * doing) and make the same single budget write as any failure. The caller
   * answers the same 404. Only the gate's decision may change an answer.
   */
  async reject({ src, rid }) {
    if (typeof src !== 'string' || !SRC.test(src)) throw new TypeError('gate: bad src');
    if (rid !== null && !isInt(rid, 1, Number.MAX_SAFE_INTEGER)) throw new TypeError('gate: bad rid');
    const now = this.now();
    this.storage.transactionSync(() => {
      if (rid !== null) this.#releaseSync(rid, false);
      this.#recordFailure(src, now);
    });
    if (rid !== null) await this.storage.sync();
    return { status: 404 };
  }

  #releaseSync(rid, countRefund) {
    const r = this.#rows('SELECT tag FROM reservations WHERE rid = ?', rid)[0];
    if (!r) return false;
    this.#run('DELETE FROM reservations WHERE rid = ?', rid);
    if (countRefund) {
      return this.#run('UPDATE invites SET used = used - 1, refunds = refunds + 1 WHERE tag = ? AND used > 0 AND refunds < ?', r.tag, LIMITS.maxRefunds) > 0;
    }
    return this.#run('UPDATE invites SET used = used - 1 WHERE tag = ? AND used > 0', r.tag) > 0;
  }

  // ---- admin ------------------------------------------------------------

  /**
   * The one admin entry. The Worker has already verified the Ed25519
   * signature for (role, ts); here: the role may call only its own ops, the
   * timestamp is within 300 s and strictly greater than the role's last one,
   * then the op runs. Spends no source budget (a bad call is the front's 404).
   * Returns {ok: true, ...} or {ok: false, error}.
   */
  async admin(role, ts, op, args = {}) {
    if (!Object.hasOwn(ROLE_OPS, role)) return fail('forbidden');
    if (!ROLE_OPS[role].includes(op)) return fail('forbidden');
    if (!Number.isSafeInteger(ts)) return fail('stale');
    const now = this.now();
    if (Math.abs(now - ts) > LIMITS.adminSkewMs) return fail('stale');
    let out;
    this.storage.transactionSync(() => {
      const k = `last_ts:${role}`;
      const last = Number(this.#meta(k) || 0);
      if (ts <= last) {
        out = fail('replay');
        return;
      }
      this.#setMeta(k, ts);
      out = this[`_${op}`](args || {}, now);
    });
    if (out.ok && op !== 'health' && op !== 'invites') await this.storage.sync();
    return out;
  }

  _addInvite(a, now) {
    const { ref, tag, tier, lo, hi, exp, cap } = a;
    if (typeof ref !== 'string' || !REF.test(ref)) return fail('bad-request');
    if (typeof tag !== 'string' || !HEX64.test(tag)) return fail('bad-request');
    if (typeof tier !== 'string' || !TIER.test(tier)) return fail('bad-request');
    if (!isInt(lo, 1, LIMITS.maxSerial) || !isInt(hi, 1, LIMITS.maxSerial) || lo > hi) return fail('bad-request');
    if (!Number.isSafeInteger(exp) || !Number.isSafeInteger(cap)) return fail('bad-request');

    const byRef = this.#rows('SELECT * FROM invites WHERE ref = ?', ref)[0];
    if (byRef) {
      if (byRef.revoked) return fail('revoked'); // tombstone: never resurrected
      const same = byRef.tag === tag && byRef.tier === tier && byRef.lo === lo && byRef.hi === hi && byRef.exp === exp && byRef.cap === cap;
      return same ? { ok: true, created: false } : fail('conflict');
    }
    if (this.#rows('SELECT 1 AS x FROM invites WHERE tag = ?', tag).length) return fail('conflict');

    // Ceilings, whatever the signer sends.
    if (exp <= now) return fail('expired');
    if (exp - now > LIMITS.maxLifeMs + LIMITS.lifeSlackMs) return fail('ceiling-life');
    if (!isInt(cap, 1, LIMITS.maxDownloads)) return fail('ceiling-downloads');
    const open = this.#rows('SELECT COUNT(*) AS n FROM invites WHERE revoked = 0 AND exp > ?', now)[0].n;
    if (open >= LIMITS.maxOpenInvites) return fail('ceiling-open');

    this.#run('DELETE FROM invites WHERE exp < ?', now - LIMITS.tombstoneGraceMs);
    this.#run(
      'INSERT INTO invites(ref, tag, tier, lo, hi, exp, cap, made) VALUES(?, ?, ?, ?, ?, ?, ?, ?)',
      ref, tag, tier, lo, hi, exp, cap, now,
    );
    return { ok: true, created: true };
  }

  _revokeInvite(a, now) {
    const { ref } = a;
    if (typeof ref !== 'string' || !REF.test(ref)) return fail('bad-request');
    const hit = this.#run('UPDATE invites SET revoked = 1 WHERE ref = ?', ref);
    if (hit > 0) return { ok: true, existed: true };
    // Unknown ref: leave a tombstone so a late or replayed add cannot create it.
    this.#run(
      'INSERT INTO invites(ref, tag, tier, lo, hi, exp, cap, revoked, made) VALUES(?, NULL, ?, 1, 1, ?, 1, 1, ?)',
      ref, 'tombstone', now + LIMITS.maxLifeMs + LIMITS.lifeSlackMs, now,
    );
    return { ok: true, existed: false };
  }

  _putBundle(a, now) {
    const { serial, sha256, size } = a;
    if (!isInt(serial, 1, 999999999)) return fail('bad-request');
    if (typeof sha256 !== 'string' || !HEX64.test(sha256)) return fail('bad-request');
    if (!isInt(size, 1, LIMITS.maxBundleBytes)) return fail('bad-request');
    const have = this.#rows('SELECT * FROM files WHERE serial = ? AND name = ?', serial, BUNDLE)[0];
    if (have) {
      return have.sha256 === sha256 && have.size === size
        ? { ok: true, created: false, key: have.key }
        : fail('conflict'); // write-once per serial
    }
    const key = bundleKey(serial);
    this.#run('INSERT INTO files(serial, name, sha256, size, key, made) VALUES(?, ?, ?, ?, ?, ?)', serial, BUNDLE, sha256, size, key, now);
    return { ok: true, created: true, key };
  }

  _setGateway(a, now) {
    const { gserial, json, sig } = a;
    if (!isInt(gserial, 1, LIMITS.maxSerial)) return fail('bad-request');
    const parts = [
      [GATEWAY_JSON, json, LIMITS.maxGatewayJsonBytes],
      [GATEWAY_SIG, sig, LIMITS.maxGatewaySigBytes],
    ];
    for (const [, f, max] of parts) {
      if (!f || typeof f.sha256 !== 'string' || !HEX64.test(f.sha256) || !isInt(f.size, 1, max)) return fail('bad-request');
    }
    const active = this.#meta('gateway_active');
    if (active !== undefined && gserial < active) return fail('rollback');
    if (active === gserial) {
      const same = parts.every(([name, f]) => {
        const r = this.#rows('SELECT sha256, size FROM gateway WHERE gserial = ? AND name = ?', gserial, name)[0];
        return r && r.sha256 === f.sha256 && r.size === f.size;
      });
      return same ? { ok: true, created: false, gserial } : fail('conflict');
    }
    // Both records and the pointer move together (the caller runs inside one transaction).
    for (const [name, f] of parts) {
      this.#run(
        'INSERT INTO gateway(gserial, name, sha256, size, key, made) VALUES(?, ?, ?, ?, ?, ?)',
        gserial, name, f.sha256, f.size, gatewayKey(gserial, name), now,
      );
    }
    this.#setMeta('gateway_active', gserial);
    return { ok: true, created: true, gserial };
  }

  _setFloor(a) {
    if (!isInt(a.floor, 0, LIMITS.maxSerial)) return fail('bad-request');
    this.#setMeta('floor', a.floor);
    return { ok: true, floor: a.floor };
  }

  _health(_a, now) {
    const min = this.#minBucket(now);
    const gs = this.#meta('gateway_active');
    return {
      ok: true,
      now,
      floor: Number(this.#meta('floor') || 0),
      effectiveFloor: this.#effectiveFloor(),
      gateway: gs === undefined ? null : gs,
      openInvites: this.#rows('SELECT COUNT(*) AS n FROM invites WHERE revoked = 0 AND exp > ?', now)[0].n,
      bundles: this.#rows('SELECT COUNT(*) AS n FROM files')[0].n,
      failuresLastHour: this.#rows('SELECT COALESCE(SUM(n), 0) AS n FROM allfails WHERE bucket >= ?', min)[0].n,
    };
  }

  // By ref only: no tag, no code.
  _invites() {
    return {
      ok: true,
      invites: this.#rows('SELECT ref, tier, lo, hi, exp, cap, used, refunds, revoked FROM invites ORDER BY made, ref'),
    };
  }
}

export const bundleKey = (serial) => `kit/${serial}/${BUNDLE}`;
export const gatewayKey = (gserial, name) => `kit/gateway/${gserial}/${name}`;
