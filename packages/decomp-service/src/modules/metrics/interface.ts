import { Option, Schema } from 'effect';
import type { EffectGen } from 'effective-modules';
import type { DbError } from '../db/interface';

/**
 * Every figure the dashboard shows, each one a QUERY over the fact tables.
 *
 * Nothing here is a stored answer. A new question is a new method plus one
 * SQL statement, never a change to how facts are collected -- which is the
 * whole reason the store holds one row per function, per binding, per agent
 * rather than pre-aggregated counters.
 *
 * History works the same way: `proven` records when each function was first
 * accepted, so progress over time is read off real events instead of being
 * sampled by a polling loop with gaps in it.
 */

export const Counted = Schema.Struct({ key: Schema.String, n: Schema.Number });
export type Counted = typeof Counted.Type;

export interface Phase2 {
  readonly inventory: number;
  readonly proven: number;
  readonly near: number;
  readonly open: number;
  readonly bytesProven: number;
  readonly textSpan: number;
  readonly pctText: number;
  readonly weak: number;
  readonly crt: number;
  readonly reconstructions: number;
  readonly superseded: number;
}

export interface GateRun {
  readonly id: number;
  readonly at: number;
  readonly exact: number;
  readonly bytesExact: number;
  readonly toolchainId: string;
}

export interface Composition {
  readonly runId: number;
  readonly at: Option.Option<number>;
  readonly placed: number;
  readonly placedBytes: number;
  readonly maskedBytes: number;
  readonly diffBytes: number;
  readonly spanBytes: number;
}

export interface ImportSurface {
  readonly slots: number;
  readonly byResolution: ReadonlyArray<Counted>;
  readonly bindings: number;
  readonly bindingsVerified: number;
  readonly distinctApis: number;
}

export interface SymbolMap {
  readonly named: number;
  readonly classes: number;
  readonly byConfidence: ReadonlyArray<Counted>;
}

export interface SeriesPoint {
  readonly at: number;
  readonly proven: number;
  readonly bytes: number;
}

export interface InventoryHealth {
  /** None until the first audit has run. */
  readonly audit: Option.Option<{
    readonly at: number;
    readonly entries: number;
    readonly workable: number;
    readonly undecodable: number;
    readonly undecodableProven: number;
    readonly repaired: number;
  }>;
  readonly rejected: number;
  /**
   * Executable bytes no inventory extent claims, from the newest gap scan.
   *
   * Every discovery rule follows a reference, so none can find a function
   * nothing references. This is the only figure that says how much of the
   * game's code is still invisible to all of them.
   */
  readonly gaps: Option.Option<{
    readonly at: number;
    readonly textBytes: number;
    readonly coveredBytes: number;
    readonly paddingBytes: number;
    readonly residueGaps: number;
    readonly residueBytes: number;
  }>;
  /** How each entry entered the inventory, and how much of each kind is
   *  proven -- the question "is discovery producing workable functions". */
  readonly byEvidence: ReadonlyArray<{
    readonly evidence: string;
    readonly functions: number;
    readonly proven: number;
  }>;
}

/**
 * What is standing between here and a browser build, as counted facts.
 *
 * Every other figure says what has been achieved. These say what has not, and
 * why -- which is the only input to deciding what to do next. Each carries the
 * size of the thing blocked, because a blocker holding 250KB of the game and
 * one holding 150 bytes are not the same problem however similar they look.
 */
export interface Blockers {
  /** Functions parked with a stated cause, worst first by bytes held. */
  readonly parked: ReadonlyArray<{
    readonly cause: string;
    readonly functions: number;
    readonly bytes: number;
  }>;
  /** Parked with NO stated cause. These cannot be aggregated at all, so they
   *  are invisible to any decision about what to build next. */
  readonly parkedWithoutCause: number;
  /** Executable bytes no discovery rule can reach, because every rule follows
   *  a reference and nothing refers to these. */
  readonly unfoundCodeBytes: number;
  readonly unfoundCodeStretches: number;
  /** Inventory entries whose recorded extent does not decode, so no agent can
   *  read them. */
  readonly undecodableEntries: number;
  /** Import slots no memory capture has ever caught a call through. Each is a
   *  Windows function the browser build cannot yet name. */
  readonly unansweredImportSlots: number;
  readonly importSlotsTotal: number;
  /** Pointers stored inside the data region that cannot be placed inside a
   *  variable whose extent is settled. The browser build has to resolve every
   *  one of them. */
  readonly unattributedDataPointers: number;
  readonly dataPointersTotal: number;
  /**
   * Literal addresses in the portable rendering that the rewrite does not
   * match, so they stay bare numbers. Each is a dereference, in the browser
   * build, of an address that does not exist there -- the one correctness
   * hole between a proven function and a running one.
   */
  readonly strandedLiterals: number;
  readonly strandedInFunctions: number;
}

export interface IMetrics {
  phase2(): EffectGen<Phase2, DbError>;
  lastGateRun(): EffectGen<Option.Option<GateRun>, DbError>;
  /** The composition run made under the configuration currently in force.
   *  A run under a retired toolchain is not an answer about today. */
  composition(): EffectGen<Option.Option<Composition>, DbError>;
  blockedClasses(): EffectGen<ReadonlyArray<Counted>, DbError>;
  importSurface(): EffectGen<ImportSurface, DbError>;
  symbolMap(): EffectGen<SymbolMap, DbError>;
  portSurface(): EffectGen<ReadonlyArray<Counted>, DbError>;
  /** Cumulative proven count over time, from each function's own first
   *  acceptance. Not sampled. */
  progress(sinceSeconds: number, buckets: number):
    EffectGen<ReadonlyArray<SeriesPoint>, DbError>;
  queue(): EffectGen<{ depth: number; claimed: number }, DbError>;

  /**
   * Whether the inventory describes the bytes.
   *
   * Three figures that were invisible until an entry recorded 436 bytes short
   * of its true extent turned out to reach agents as an EMPTY disassembly,
   * with nothing anywhere reporting it:
   *
   *   workable     entries whose recorded extent decodes, so an agent can
   *                actually read the function. Anything else is an address
   *                that cannot leave the queue however long it sits there.
   *   undecodable  the rest, which is the count that must stay at zero
   *   rejected     addresses recorded as NOT function entries, with the
   *                decode that justifies each one
   *
   * Read from the newest stored audit rather than recomputed: the audit
   * decodes every entry and takes seconds, and a dashboard polls far faster
   * than that.
   */
  inventoryHealth(): EffectGen<InventoryHealth, DbError>;

  /** What is blocking the browser build, counted rather than described. */
  blockers(): EffectGen<Blockers, DbError>;

  /**
   * The current working note, and when it was written.
   *
   * None when nothing has been written yet, so the page can say so rather
   * than show an empty panel that looks like a rendering fault.
   */
  workingOn(): EffectGen<
    Option.Option<{ readonly note: string; readonly updatedAt: number }>,
    DbError
  >;

  /** Replace the working note. The timestamp is set here, not supplied, so it
   *  always describes when the text was actually written. */
  setWorkingOn(note: string): EffectGen<void, DbError>;
}
