// The Gate Durable Object: one SQLite-backed instance (idFromName "gate",
// locationHint apac) holds every invite, file record, floor and failure budget.
// All logic is in gate-core.js; this class only binds it to the Workers
// runtime. Public methods are RPC methods (compatibility_date >= 2024-04-03),
// so keep the list short; the Worker front (K5) is the only caller.
//
// wrangler migration: { "tag": "v1", "new_sqlite_classes": ["Gate"] }
import { DurableObject } from 'cloudflare:workers';
import { GateCore } from './gate-core.js';

export class Gate extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    // KIT_FLOOR is the phone break-glass dashboard variable; read at every call.
    this.core = new GateCore(ctx.storage, { envFloor: () => this.env.KIT_FLOOR });
  }

  // One well-formed guess: {src, tag, serial, name} -> {status, ...}
  decide(req) {
    return this.core.decide(req);
  }

  // The client cut the stream: {rid} -> {released}
  release(req) {
    return this.core.release(req);
  }

  // A fault after the gate said yes: {src, rid} -> {status: 404}
  reject(req) {
    return this.core.reject(req);
  }

  // Admin (signature already verified by the Worker): role, ts_ms, op, args
  admin(role, ts, op, args) {
    return this.core.admin(role, ts, op, args);
  }
}
