import { Schema } from 'effect';
import type { EffectGen } from 'effective-modules';

export class DbError extends Schema.TaggedError<DbError>()('DbError', {
  sql: Schema.String,
  reason: Schema.String,
}) {}

export interface IDb {
  all(sql: string, params?: ReadonlyArray<unknown>): EffectGen<ReadonlyArray<unknown>, DbError>;
  one(sql: string, params?: ReadonlyArray<unknown>): EffectGen<unknown, DbError>;
  run(sql: string, params?: ReadonlyArray<unknown>): EffectGen<number, DbError>;
  /** Last inserted rowid for the statement just run. */
  insert(sql: string, params?: ReadonlyArray<unknown>): EffectGen<number, DbError>;
  /** All-or-nothing. A verdict batch that half-lands is worse than none. */
  tx<A, E>(body: () => EffectGen<A, E>): EffectGen<A, E | DbError>;
  /**
   * Migrations whose text no longer matches the text they were applied from.
   *
   * An applied migration is skipped, so editing one changes nothing and says
   * nothing. A trigger added to migration 007 after 007 had been applied
   * never ran, and because the table from the same migration did exist,
   * everything looked correct while five rejected addresses came back.
   */
  driftedMigrations(): EffectGen<ReadonlyArray<string>, DbError>;

  migrate(): EffectGen<ReadonlyArray<string>, DbError>;
}
