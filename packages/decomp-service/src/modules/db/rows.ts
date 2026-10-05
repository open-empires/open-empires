import { Effect, Schema } from 'effect';
import type { EffectGen } from 'effective-modules';
import { DbError, type IDb } from './interface';

/**
 * Decode query results, or fail.
 *
 * `IDb.all` returns `unknown` on purpose: SQLite will hand back whatever the
 * statement happened to select, and a module that cast the rows into the shape
 * it wanted would turn a renamed column into `undefined` and then into a
 * plausible-looking zero. Every caller decodes, and a row that does not match
 * is a `DbError` naming the statement.
 */
export const rows = function* <A>(
  db: IDb,
  schema: Schema.Codec<A, unknown, never, never>,
  sql: string,
  params: ReadonlyArray<unknown> = [],
): EffectGen<ReadonlyArray<A>, DbError> {
  const raw = yield* db.all(sql, params);
  return yield* Effect.mapError(
    Schema.decodeUnknownEffect(Schema.Array(schema))(raw),
    (cause) =>
      new DbError({ sql, reason: `row does not match its schema: ${cause.message}` }),
  );
};
