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
}
