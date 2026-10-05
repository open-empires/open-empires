import { Schema } from 'effect';
import type { EffectGen } from 'effective-modules';
import type { DbError } from '../db/interface';
import type { GateUnavailable } from '../gate/interface';

/**
 * The one-time move of the project's state out of loose files and JSON.
 *
 * Everything the Python tooling knew lived in `decomp/*.json` and in 2,696
 * `.cpp` files, with no prover identity on any verdict. This module reads all
 * of it once and writes it into the database, which then IS the state. The
 * files are not deleted: they stay as the reference the generated ports are
 * checked against until every port agrees, and deleting them is a separate,
 * later step.
 *
 * It runs twice safely. Every write is keyed on a fact from the files -- the
 * subject's hash, a source's hash, a gate run's own timestamp -- so a second
 * run recognises its own rows instead of adding more, and never overwrites a
 * field another module has since filled in.
 */

/** A file this import must read could not be read, or is not the shape it has to be. */
export class LegacyUnreadable extends Schema.TaggedError<LegacyUnreadable>()(
  'LegacyUnreadable',
  { path: Schema.String, reason: Schema.String },
) {}

/**
 * Two of the files disagree about a fact both record, or a file disagrees with
 * the bytes it describes.
 *
 * Fatal on purpose. The import is the one moment at which these files are read
 * together, so a disagreement found here is a disagreement that was already
 * live; importing the half of it that happened to be read first would bake it
 * into the system of record.
 */
export class LegacyInconsistent extends Schema.TaggedError<LegacyInconsistent>()(
  'LegacyInconsistent',
  { what: Schema.String, reason: Schema.String },
) {}

export type LegacyError = LegacyUnreadable | LegacyInconsistent;

/** How many rows one table holds for this subject once the import is done. */
export interface TableRows {
  readonly table: string;
  readonly rows: number;
}

/**
 * A fact the files carry that the schema has nowhere to put.
 *
 * Reported, never dropped quietly: a count in a summary says how many rows
 * landed, and it is what did NOT land that someone has to decide about.
 */
export interface Unexpressed {
  readonly what: string;
  readonly detail: string;
}

export interface ImportSummary {
  readonly subjectSha: string;
  readonly toolchainId: string;
  readonly gateRunId: number;
  readonly written: ReadonlyArray<TableRows>;
  readonly unexpressed: ReadonlyArray<Unexpressed>;
}

/**
 * One question asked of the database, with the answer the files say it must
 * give.
 *
 * `sql` is carried so the answer can be re-asked by hand. A check that only
 * reports "passed" asks the reader to trust the checker.
 */
export interface Check {
  readonly question: string;
  readonly sql: string;
  readonly expected: string;
  readonly actual: string;
  readonly passed: boolean;
  /**
   * What the counts hide: the addresses, names or paths in one side and not
   * the other. Populated whether or not the check passed, because a pair of
   * equal counts over different sets is the failure this exists to catch.
   */
  readonly detail: ReadonlyArray<string>;
}

export interface ILegacy {
  /**
   * Read every file and write every row, inside one transaction.
   *
   * The toolchain the verdicts are attributed to is obtained from the gate
   * rather than described here, so the compiler's identity has exactly one
   * derivation in the service. This is also why the import can fail with
   * `GateUnavailable`: a verdict with no prover is what the database exists to
   * make impossible, so there is nothing to write if the prover cannot be
   * identified.
   */
  importState(): EffectGen<ImportSummary, LegacyError | GateUnavailable | DbError>;

  /**
   * Ask the database what it now holds and compare it against the files.
   *
   * Separate from `importState` so it can be re-run against a database nobody
   * is importing into, and so the import's own bookkeeping is never the thing
   * that proves the import.
   */
  audit(): EffectGen<ReadonlyArray<Check>, LegacyError | DbError>;
}
