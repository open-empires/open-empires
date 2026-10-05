import { Effect } from 'effect';
import { effunct, implementing, type EffectGen } from 'effective-modules';
import { Database } from 'bun:sqlite';
import path from 'node:path';
import fs from 'node:fs';
import { modules } from '../index';
import { DbError, type IDb } from './interface';
import { MIGRATIONS } from './schema';

export const DB_PATH = path.resolve(
  process.env.DECOMP_DB ?? path.join(import.meta.dir, '../../../data/decomp.db'),
);

const KEY = Symbol.for('open-empires.decomp.db');

/** One connection for the process. Parked on globalThis so `bun --watch`
 *  reloading a module does not leak a handle per edit. */
export const handle = (): Database => {
  const g = globalThis as Record<symbol, unknown>;
  const existing = g[KEY];
  if (existing !== undefined) return existing as Database;
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
  const db = new Database(DB_PATH, { create: true });
  db.exec('PRAGMA journal_mode = WAL');
  db.exec('PRAGMA foreign_keys = ON');
  // Readers must not fail while the gate worker is committing a batch.
  db.exec('PRAGMA busy_timeout = 10000');
  g[KEY] = db;
  return db;
};

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
    const done = new Set(
      (db.query('SELECT id FROM migrations').all() as { id: string }[]).map((r) => r.id),
    );
    const applied: string[] = [];
    for (const m of MIGRATIONS) {
      if (done.has(m.id)) continue;
      yield* Effect.try({
        try: () => {
          db.exec('BEGIN');
          try {
            db.exec(m.sql);
            db.query('INSERT INTO migrations(id, applied_at) VALUES (?,?)').run(
              m.id,
              Date.now() / 1000,
            );
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
    return applied;
  }
}
