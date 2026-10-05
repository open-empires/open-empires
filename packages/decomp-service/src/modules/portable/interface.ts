import { Option, Schema } from 'effect';
import type { EffectGen } from 'effective-modules';
import type { DbError } from '../db/interface';
import type { NoCurrentSubject, SubjectIoError, SubjectParseError } from '../subject/interface';

/**
 * The phase-4 portable tree.
 *
 * The reconstructions exist to be PROVEN, not to be portable: they are written
 * for MSVC 6 because that is the only way to compare against the shipped
 * bytes, and most of them use constructs WebAssembly has no equivalent for. So
 * the MSVC sources stay the verification artifact and this derives a second
 * tree from them, which can be regenerated whenever a source changes.
 *
 * WHAT THE RECORD HAS TO HOLD, AND WHY
 * ------------------------------------
 * The Python wrote a `port_status.json` carrying `"refused": 30` -- a count
 * with no address list. Which thirty could not be recovered from it at all, so
 * "30 files need hand-written assembly rewritten" was a number nobody could
 * act on. The 357 files needing the globals model WERE listed, by filename.
 *
 * Here every file's outcome is a row keyed by address, so the refused set is
 * the answer to a query rather than a number in a summary. Nothing is reported
 * as a bare count that a reader would then have to ask "which?" about.
 *
 * The converted TEXT is deliberately not stored. It is a pure function of the
 * source in `attempts`, and a second copy would be a second thing to keep in
 * step; `emit` writes the tree wherever a build wants it.
 */

export class PortWriteError extends Schema.TaggedError<PortWriteError>()('PortWriteError', {
  path: Schema.String,
  reason: Schema.String,
}) {}

/**
 * `converted`     portable C++ was produced.
 * `needs_globals` converted, and its literal addresses were routed through the
 *                 globals model, so it only builds with `gameimage.h` and the
 *                 loaded data image present. A sub-state of converted, not an
 *                 alternative to it.
 * `refused`       no portable rendering exists. Today that means exactly one
 *                 thing: hand-written `__asm`.
 */
export type PortState = 'converted' | 'needs_globals' | 'refused';

export interface PortFile {
  readonly va: number;
  readonly state: PortState;
  readonly reason: Option.Option<string>;
}

export interface PortReport {
  readonly subjectSha: string;
  readonly considered: number;
  /** Every converted file, the globals-model ones included. */
  readonly converted: number;
  readonly needsGlobals: number;
  readonly refused: number;
  /**
   * The refused addresses, by address.
   *
   * Carried in the report and not only in the database because this list did
   * not previously exist in any form: `port_status.json` recorded the count
   * and dropped the identities.
   */
  readonly refusedVas: ReadonlyArray<number>;
  /**
   * Literal addresses inside the globals model that the rewrite pattern does
   * not reach, so they are left as bare numbers in the generated output.
   *
   * The pattern matches `0x6` plus five hex digits; the model spans
   * 0x629000..0x7A28A6. Anything from 0x700000 up is inside the model and
   * outside the pattern, and would be a wasm dereference of an address that
   * does not exist there. Reported even when empty, because "none today" and
   * "never checked" are different facts.
   */
  readonly strandedLiterals: ReadonlyArray<{ readonly va: number; readonly literal: number }>;
  /** Where the tree was written, when it was. */
  readonly writtenTo: Option.Option<string>;
  readonly filesWritten: number;
}

export type PortFailure =
  | DbError
  | NoCurrentSubject
  | PortWriteError
  | SubjectIoError
  | SubjectParseError;

export interface IPortable {
  /**
   * Convert every reconstruction in force and record what became of each one.
   *
   * `into` writes the generated tree as well. It does NOT write
   * `gameimage.h`: that header is the globals model's output, not this
   * conversion's, and generating a second copy of it here would be a second
   * answer to where the game's static data lives.
   */
  generate(into: Option.Option<string>): EffectGen<PortReport, PortFailure>;

  /** What is recorded for the current subject, by state. The refused set is a
   *  query, which is the point of recording addresses rather than a count. */
  files(state: Option.Option<PortState>): EffectGen<ReadonlyArray<PortFile>, DbError>;
}
