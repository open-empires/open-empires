import { Option, Schema } from 'effect';
import type { EffectGen } from 'effective-modules';
import type { DbError } from '../db/interface';
import type { GateUnavailable } from '../gate/interface';
import type { DisasmError } from '../disasm/interface';
import type { SubjectIoError, SubjectParseError } from '../subject/interface';

/**
 * The work queue agents talk to.
 *
 * An agent holds no files and no locks. It claims functions, submits source,
 * and receives a verdict. Previously an agent wrote .cpp files into a shared
 * tree and ran the gate itself, which meant: two agents could edit one file,
 * a crashed agent left its work half-written, the gate's single-writer lock
 * had to be negotiated by every caller, and the source on disk could drift
 * from the verdict recorded for it. None of that is possible here.
 *
 * Claims are LEASES, not assignments. An agent that dies must return its work
 * to the queue by its lease expiring, never by someone noticing it is gone.
 */

export class NotClaimed extends Schema.TaggedError<NotClaimed>()('NotClaimed', {
  va: Schema.Number,
  agentId: Schema.String,
}) {}

export class UnknownFunction extends Schema.TaggedError<UnknownFunction>()(
  'UnknownFunction',
  { va: Schema.Number },
) {}

/** No subject has been ingested, so there is nothing to reconstruct against.
 *  A failure, not an empty queue: an empty queue means the work is done. */
export class NoSubject extends Schema.TaggedError<NoSubject>()('NoSubject', {
  reason: Schema.String,
}) {}

/** Everything that can stop work being described or decided. The gate being
 *  unreachable and the compiler rejecting a source are DIFFERENT outcomes:
 *  the first is this error channel, the second is a verdict with
 *  `compiled: false`. Folding them together would record proof-shaped rows
 *  for compiles that never ran. */
export type WorkFailure =
  | DbError | NoSubject | DisasmError | SubjectIoError | SubjectParseError;
export type SubmitFailure = WorkFailure | GateUnavailable | NotClaimed | UnknownFunction;

export interface WorkItem {
  readonly va: number;
  readonly size: number;
  /** The bytes to reconstruct, as the agent needs to see them. */
  readonly disassembly: string;
  /** Already-solved functions with the same shape. The single biggest time
   *  saver available to an agent, so it ships WITH the work. */
  readonly siblings: ReadonlyArray<{ va: number; similarity: number; source: string }>;
  readonly previousAttempts: ReadonlyArray<{
    readonly flags: string;
    readonly exact: boolean;
    readonly firstDiff: Option.Option<number>;
    readonly detail: Option.Option<string>;
  }>;
  readonly nearMiss: Option.Option<{
    readonly blockedClass: Option.Option<string>;
    readonly eliminated: Option.Option<string>;
  }>;
}

export interface Verdict {
  readonly exact: boolean;
  readonly compiled: boolean;
  readonly emittedSize: Option.Option<number>;
  readonly masked: Option.Option<number>;
  readonly compared: Option.Option<number>;
  readonly firstDiff: Option.Option<number>;
  readonly detail: Option.Option<string>;
  /** True when over a quarter of the compared bytes were masked relocations:
   *  byte-exact, but a weaker claim than it appears. */
  readonly weak: boolean;
}

/**
 * Most flag sets one sweep may ask for.
 *
 * The compiler is a shared, serialised resource: one container, one Wine
 * prefix, and every other agent's submissions queued behind whatever is in it.
 * A sweep is the cheapest way to ask a broad question and therefore the
 * easiest way to starve everyone else.
 */
export const MAX_SWEEP_FLAG_SETS = 24;

/** What one flag set did to one source. */
export interface SweepOutcome {
  readonly flags: string;
  readonly compiled: boolean;
  /** Byte-identical to the subject, relocation fields excused. */
  readonly exact: boolean;
  /**
   * The match is at the emitted function's ENTRY, which is the claim a
   * reconstruction of this address makes. A match at a non-zero offset is the
   * weaker "these bytes occur inside something larger" and is reported
   * separately, because reading one as the other is how a broken
   * reconstruction passed on a correct sibling's bytes.
   */
  readonly matchedAtEntry: boolean;
  readonly emittedSize: Option.Option<number>;
  readonly masked: Option.Option<number>;
  readonly firstDiff: Option.Option<number>;
  readonly detail: Option.Option<string>;
  /**
   * These flags are not one the configuration names, so a match here is a
   * FINDING and not a pass.
   *
   * The subject is one link, but a 1999 build has no obligation to compile
   * every translation unit alike. A hit under unknown flags means the gate may
   * need a third bucket -- which is a change to the configuration every verdict
   * is keyed on, and therefore a decision for a person, not a row this writes.
   */
  readonly offConfiguration: boolean;
}

export interface SweepReport {
  readonly va: number;
  readonly size: number;
  readonly outcomes: ReadonlyArray<SweepOutcome>;
  /** Flag sets that matched at the entry. Empty is the common answer. */
  readonly matched: ReadonlyArray<string>;
  /** True when something matched under flags the configuration does not name.
   *  The one field a caller must not ignore. */
  readonly finding: boolean;
}

export interface IWork {
  /** Lease up to `count` unsolved functions, preferring ones that share a
   *  shape with something already solved. Returns fewer if the queue is
   *  short, and none if it is empty -- which is the signal to run the
   *  producer, not to spin. */
  claim(agentId: string, count: number, leaseSeconds: number):
    EffectGen<ReadonlyArray<WorkItem>, WorkFailure>;

  /** Submit source for a claimed function. The service compiles it and
   *  returns the verdict; the agent never runs the compiler. */
  submit(agentId: string, va: number, source: string, flags: string):
    EffectGen<Verdict, SubmitFailure>;

  /**
   * Compile ONE source under MANY flag sets and report which reproduce.
   *
   * A function that has resisted every source spelling may simply not have
   * been built with the flags the gate assumes, and that is a different
   * question from "is this spelling right". Asking it used to cost one tool
   * call per flag set, each one re-sending the agent's whole context; this
   * costs one.
   *
   * It records NOTHING. A verdict is a claim about the toolchain the
   * configuration names, and `attempts.flags` holds exactly the two buckets
   * that configuration has -- writing a third into it would make a finding
   * look like a proof, and the `superseded` view would then hide it. A hit off
   * the configuration is reported for a person to act on.
   *
   * Needs the same live lease `submit` does: the compiler is shared, and a
   * sweep is the easiest way to spend it on an address another agent already
   * holds.
   */
  sweep(agentId: string, va: number, source: string, flagSets: ReadonlyArray<string>):
    EffectGen<SweepReport, SubmitFailure>;

  /** Record a diagnosed near-miss and give the lease back. */
  park(agentId: string, va: number, blockedClass: string, eliminated: string):
    EffectGen<void, DbError | NotClaimed>;

  release(agentId: string, va: number): EffectGen<void, DbError>;

  /** Expire leases whose time is up. Owned by the server, run on a timer --
   *  never something a caller must remember. */
  reapExpiredClaims(): EffectGen<number, DbError>;

  /** How much claimable work remains. Zero means the producer must run. */
  queueDepth(): EffectGen<number, DbError>;
}
