import { Option, Schema } from 'effect';
import type { EffectGen } from 'effective-modules';
import type { DbError } from '../db/interface';

/**
 * Agents register themselves, so a row means one really STARTED -- where a
 * roster written by whoever launched the fleet only records who was asked to.
 * Silence is the only available death signal: an agent runs inside a host
 * process with no pid to watch.
 */
export class UnknownAgent extends Schema.TaggedError<UnknownAgent>()('UnknownAgent', {
  id: Schema.String,
}) {}

export type AgentState = 'live' | 'gone' | 'finished';

export interface Agent {
  readonly id: string;
  readonly role: Option.Option<string>;
  readonly started: number;
  readonly lastBeat: number;
  readonly beats: number;
  readonly finished: Option.Option<number>;
  readonly note: Option.Option<string>;
  readonly state: AgentState;
  readonly silentFor: Option.Option<number>;
}

export interface IRegistry {
  register(id: string, role: Option.Option<string>): EffectGen<void, DbError>;
  beat(id: string): EffectGen<void, DbError | UnknownAgent>;
  deregister(id: string, note: Option.Option<string>):
    EffectGen<void, DbError | UnknownAgent>;
  list(): EffectGen<ReadonlyArray<Agent>, DbError>;
}

/** An agent silent this long is presumed gone. It beats on every submit, and
 *  a submit cycle is minutes, so a ten-minute gap means stopped. */
export const STALE_AFTER_SECONDS = 600;
