import { Effect, Semaphore } from 'effect';
import { effunct, implementing, type EffectGen } from 'effective-modules';
import { Database } from 'bun:sqlite';
import path from 'node:path';
import fs from 'node:fs';
import { modules } from '../index';
import { DbError, type IDb } from './interface';
import { MIGRATIONS } from './schema';

/**
 * Where the database is, resolved on every call rather than once at import.
 *
 * It used to be a module-level const, and that silently let a TEST write to
 * the system of record. `subject.test.ts` sets `DECOMP_DB` to a scratch path
 * and then dynamically imports this module so the new value is picked up --
 * which works only if nothing has imported it yet. Bun runs a suite in one
 * process, so when any other test file loaded this module first, the import
 * returned the CACHED module still holding the live path, and the test wrote
 * 6,570 inventory rows into the live database.
 *
 * That is how five addresses recorded as NOT function entries came back,
 * labelled `discovered_by='inventory'` by a test fixture, and how roughly one
 * run in three failed with "database is locked" -- the test was contending
 * with the running service for the live write lock. The flake was the
 * harmless symptom of a test mutating production data.
 *
 * Resolved per call, the scratch path is honoured whatever the import order.
 */
export const dbPath = (): string =>
  path.resolve(
    process.env.DECOMP_DB ?? path.join(import.meta.dir, '../../../data/decomp.db'),
  );

/** @deprecated Read `dbPath()`. Kept so existing imports keep compiling; it
 *  is the path as of module load, which is the bug described above. */
export const DB_PATH = dbPath();

const KEY = Symbol.for('open-empires.decomp.db');
const TX_KEY = Symbol.for('open-empires.decomp.db.transaction');

/**
 * One transaction at a time on the one connection.
 *
 * SQLite has no nested transactions and this process has a single handle, so
 * two overlapping `tx` calls make the second `BEGIN` fail with "cannot start
 * a transaction within a transaction". That is not hypothetical: the server
 * runs five background workers, three of them transactional, and they tick
 * together. Two of them failed on every tick -- the globals inventory and the
 * import-name derivation both recorded nothing for as long as they were
 * scheduled alongside each other.
 *
 * Parked on globalThis beside the connection, for the same reason: `bun
 * --watch` reloading this module must not mint a second lock over the first
 * lock's connection.
 */
const transactionLock = (): Semaphore.Semaphore => {
  const g = globalThis as Record<symbol, unknown>;
  const existing = g[TX_KEY];
  if (existing !== undefined) return existing as Semaphore.Semaphore;
  const lock = Semaphore.makeUnsafe(1);
  g[TX_KEY] = lock;
  return lock;
};

/** One connection for the process. Parked on globalThis so `bun --watch`
 *  reloading a module does not leak a handle per edit. */
export const handle = (): Database => {
  const g = globalThis as Record<symbol, unknown>;
  const want = dbPath();
  const existing = g[KEY] as { db: Database; path: string } | undefined;
  // Keyed by PATH. A cached connection to a different file is not this
  // database, and returning it anyway is what let a test's writes land in
  // the live one.
  if (existing !== undefined && existing.path === want) return existing.db;
  fs.mkdirSync(path.dirname(want), { recursive: true });
  const db = new Database(want, { create: true });
  db.exec('PRAGMA journal_mode = WAL');
  db.exec('PRAGMA foreign_keys = ON');
  // Readers must not fail while the gate worker is committing a batch.
  db.exec('PRAGMA busy_timeout = 10000');
  g[KEY] = { db, path: want };
  return db;
};

/** The file the live connection is open on. A harness has to be able to name
 *  its subject: a test that believes it is on a scratch database and is not
 *  reports success about the wrong file. */
export const openPath = (): string => dbPath();

const fail = (sql: string) => (cause: unknown) =>
  new DbError({
    sql: sql.trim().split('\n')[0]!.slice(0, 160),
    reason: cause instanceof Error ? cause.message : String(cause),
  });

export class DbImpl extends implementing(modules.Db) implements IDb {
  *all(
    sql: string,
    params: ReadonlyArray<unknown> = [],
  ): EffectGen<ReadonlyArray<unknown>, DbError> {
    return yield* Effect.try({
      try: () => handle().query(sql).all(...(params as never[])),
      catch: fail(sql),
    });
  }

  *one(sql: string, params: ReadonlyArray<unknown> = []): EffectGen<unknown, DbError> {
    return yield* Effect.try({
      try: () => handle().query(sql).get(...(params as never[])) ?? null,
      catch: fail(sql),
    });
  }

  *run(sql: string, params: ReadonlyArray<unknown> = []): EffectGen<number, DbError> {
    return yield* Effect.try({
      try: () => Number(handle().query(sql).run(...(params as never[])).changes),
      catch: fail(sql),
    });
  }

  *insert(sql: string, params: ReadonlyArray<unknown> = []): EffectGen<number, DbError> {
    return yield* Effect.try({
      try: () =>
        Number(handle().query(sql).run(...(params as never[])).lastInsertRowid),
      catch: fail(sql),
    });
  }

  *tx<A, E>(body: () => EffectGen<A, E>): EffectGen<A, E | DbError> {
    // Serialized on the single connection. A caller that would otherwise see
    // "cannot start a transaction within a transaction" waits instead.
    return yield* transactionLock().withPermits(1)(effunct(() => this.transact(body))());
  }

  private *transact<A, E>(body: () => EffectGen<A, E>): EffectGen<A, E | DbError> {
    const db = handle();
    yield* Effect.try({ try: () => db.exec('BEGIN IMMEDIATE'), catch: fail('BEGIN') });
    // A verdict batch that half-lands would leave functions claiming a proof
    // from a run that never finished, so the rollback is not optional.
    // `effunct` is what turns the caller's generator into a real Effect.
    // Calling the generator and handing the Generator object to
    // Effect.result dies with "Not a valid effect" -- and dies INSIDE an open
    // transaction, so neither arm below runs and the connection is left in
    // one.
    const result = yield* Effect.result(effunct(body)());
    if (result._tag === 'Success') {
      yield* Effect.try({ try: () => db.exec('COMMIT'), catch: fail('COMMIT') });
      // Effect 4's Result carries `success`, not `value`.
      return result.success as A;
    }
    yield* Effect.try({ try: () => db.exec('ROLLBACK'), catch: fail('ROLLBACK') });
    return yield* Effect.fail(result.failure as E);
  }

  *migrate(): EffectGen<ReadonlyArray<string>, DbError> {
    const db = handle();
    yield* Effect.try({
      try: () =>
        db.exec(
          `CREATE TABLE IF NOT EXISTS migrations (
             id TEXT PRIMARY KEY, applied_at REAL NOT NULL)`,
        ),
      catch: fail('create migrations'),
    });
    // `sql_sha256` arrives in migration 009; before it is applied the column
    // is absent, so the hash of each applied migration is read only when the
    // column exists.
    const hashed = (
      db.query('PRAGMA table_info(migrations)').all() as { name: string }[]
    ).some((c) => c.name === 'sql_sha256');
    const done = new Map(
      (
        db
          .query(
            hashed
              ? 'SELECT id, sql_sha256 FROM migrations'
              : 'SELECT id, NULL AS sql_sha256 FROM migrations',
          )
          .all() as { id: string; sql_sha256: string | null }[]
      ).map((r) => [r.id, r.sql_sha256]),
    );

    const sha = (s: string): string =>
      new Bun.CryptoHasher('sha256').update(s).digest('hex');

    const applied: string[] = [];
    const drifted: string[] = [];
    for (const m of MIGRATIONS) {
      const priorHash = done.get(m.id);
      if (done.has(m.id)) {
        // An applied migration is SKIPPED, so editing one does nothing and
        // reports nothing. That is not hypothetical: a trigger was added to
        // migration 007 after 007 had been applied, so it never ran, while
        // the table from the same migration existed and made everything look
        // correct. Five rejected addresses were back in the inventory within
        // the hour. Comparing the text against what was actually run turns
        // that into a loud message instead of a silent no-op.
        if (priorHash != null && priorHash !== sha(m.sql)) drifted.push(m.id);
        continue;
      }
      yield* Effect.try({
        try: () => {
          db.exec('BEGIN');
          try {
            db.exec(m.sql);
            // Proof that the change landed, checked before it is recorded.
            // A migration can run without error and without effect: 018
            // updated a parent key three tables reference under
            // foreign_keys=ON, and SQLite changed nothing and raised nothing.
            if (m.verify !== undefined) {
              const row = db.query(m.verify).get() as Record<string, unknown> | null;
              const first = row === null ? undefined : Object.values(row)[0];
              const value = Number(first ?? 0);
              const wanted = m.verifyExpects ?? 'nonzero';
              const ok = wanted === 'nonzero' ? value !== 0 : value === 0;
              if (!ok) {
                throw new Error(
                  `migration ${m.id} ran without error but its verify query ` +
                    `returned ${String(first)}, which is not ${wanted}; ` +
                    'the change did not land, so it is not being recorded',
                );
              }
            }
            // 009 adds the column in its own body, so by the time its row is
            // written the column exists -- hence the hash is read back from
            // the schema rather than from the flag computed above.
            const nowHashed = (
              db.query('PRAGMA table_info(migrations)').all() as { name: string }[]
            ).some((c) => c.name === 'sql_sha256');
            if (nowHashed) {
              db.query(
                'INSERT INTO migrations(id, applied_at, sql_sha256) VALUES (?,?,?)',
              ).run(m.id, Date.now() / 1000, sha(m.sql));
            } else {
              db.query('INSERT INTO migrations(id, applied_at) VALUES (?,?)').run(
                m.id,
                Date.now() / 1000,
              );
            }
            db.exec('COMMIT');
          } catch (e) {
            db.exec('ROLLBACK');
            throw e;
          }
        },
        catch: fail(`migration ${m.id}`),
      });
      applied.push(m.id);
    }

    // Backfill, once: rows applied before hashing existed are presumed
    // correct as of now, so that any edit AFTER this point is caught instead
    // of silently assumed to have run.
    yield* Effect.try({
      try: () => {
        if (
          !(
            db.query('PRAGMA table_info(migrations)').all() as { name: string }[]
          ).some((c) => c.name === 'sql_sha256')
        ) {
          return;
        }
        const stmt = db.query(
          'UPDATE migrations SET sql_sha256 = ? WHERE id = ? AND sql_sha256 IS NULL',
        );
        for (const m of MIGRATIONS) stmt.run(sha(m.sql), m.id);
      },
      catch: fail('backfill migration hashes'),
    });

    if (drifted.length > 0) {
      console.error(
        `MIGRATION TEXT EDITED AFTER BEING APPLIED, so the edit never ran: ` +
          `${drifted.join(', ')}. Put the change in a NEW migration.`,
      );
    }
    return applied;
  }

  /** Migrations whose text no longer matches what was run. Surfaced so health
   *  can refuse, rather than living only in a log line at boot. */
  *driftedMigrations(): EffectGen<ReadonlyArray<string>, DbError> {
    const db = handle();
    return yield* Effect.try({
      try: () => {
        const cols = db.query('PRAGMA table_info(migrations)').all() as { name: string }[];
        if (!cols.some((c) => c.name === 'sql_sha256')) return [];
        const rows = db
          .query('SELECT id, sql_sha256 FROM migrations WHERE sql_sha256 IS NOT NULL')
          .all() as { id: string; sql_sha256: string }[];
        const current = new Map(
          MIGRATIONS.map((m) => [
            m.id,
            new Bun.CryptoHasher('sha256').update(m.sql).digest('hex'),
          ]),
        );
        return rows
          .filter((r) => current.has(r.id) && current.get(r.id) !== r.sql_sha256)
          .map((r) => r.id);
      },
      catch: fail('check migration drift'),
    });
  }
}
