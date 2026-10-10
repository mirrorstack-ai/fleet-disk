// Stand-in for the Durable Object storage so the Gate runs in plain Node
// (node:sqlite, no npm). Same shape as ctx.storage: sql.exec(), transactionSync(),
// sync(). Test-only; the Worker bundle never imports it.
import { DatabaseSync } from 'node:sqlite';

export function fakeStorage(path = ':memory:') {
  const db = new DatabaseSync(path);
  const stats = { syncs: 0, execs: [] };
  let depth = 0;
  const storage = {
    db,
    stats,
    // Optional hooks for tests.
    beforeExec: null,
    syncImpl: null,
    sql: {
      exec(query, ...bindings) {
        stats.execs.push(query);
        if (storage.beforeExec) storage.beforeExec(query, bindings);
        const stmt = db.prepare(query);
        if (stmt.columns().length > 0) {
          const rows = stmt.all(...bindings);
          return { toArray: () => rows, rowsRead: rows.length, rowsWritten: 0 };
        }
        const r = stmt.run(...bindings);
        return { toArray: () => [], rowsRead: 0, rowsWritten: Number(r.changes) };
      },
    },
    transactionSync(fn) {
      if (depth > 0) throw new Error('nested transactionSync');
      db.exec('BEGIN');
      depth++;
      try {
        const r = fn();
        if (r && typeof r.then === 'function') throw new Error('transactionSync callback must be synchronous');
        db.exec('COMMIT');
        return r;
      } catch (e) {
        db.exec('ROLLBACK');
        throw e;
      } finally {
        depth--;
      }
    },
    async sync() {
      stats.syncs++;
      if (storage.syncImpl) await storage.syncImpl();
    },
  };
  return storage;
}
