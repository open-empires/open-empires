import { Option } from 'effect';
import type { EffectGen } from 'effective-modules';
import type { DbError } from '../db/interface';
import type { GateUnavailable } from '../gate/interface';
import type {
  NoCurrentSubject,
  SubjectIoError,
  SubjectParseError,
} from '../subject/interface';

/**
 * The composition proof.
 *
 * Every other proof here is per-function and in isolation: the gate compiles
 * one reconstruction and compares one function's bytes. Nothing in that says
 * the proofs COMPOSE. A reconstruction can be byte-exact and still be wrong
 * about where it belongs -- claiming a size the inventory does not, or a span
 * its neighbour also claims -- and a per-function comparison cannot see any of
 * it, because it never puts two functions in the same place at once.
 *
 * So the whole executable span is assembled: each proven function from the
 * bytes its own source compiles to, the subject's own bytes everywhere nothing
 * is reconstructed. The result is diffed against the subject. Zero means every
 * reconstruction composes at its real address.
 *
 * HOW THIS DIFFERS FROM THE PYTHON IT REPLACES, AND WHY IT HAD TO
 * ---------------------------------------------------------------
 * `image.py` reported 0 bytes differing, and that zero was true of any input
 * whatsoever. It compiled each function, and if the compiled bytes did not
 * equal the original it wrote the ORIGINAL instead -- and when they did equal
 * it, the bytes it wrote were equal to the original by definition. Every
 * branch wrote the subject's own bytes, so the assembled image was a copy of
 * the subject and the diff could not be anything but zero. It would have
 * reported zero with every reconstruction deleted.
 *
 * Here the compiled bytes are written whether or not they reproduce. That is
 * the whole difference: the diff can now be non-zero, and a zero means
 * something.
 *
 * THE ONE PLACE THE ORIGINAL IS STILL TRUSTED
 * -------------------------------------------
 * Relocation fields -- the four-byte call targets and global addresses the
 * LINKER fills in -- are taken from the subject, because the project has no
 * symbol map and nothing here can resolve them. Those bytes therefore match by
 * construction and are counted and reported as masked rather than silently
 * folded into the result. What they leave unverified is the business of the
 * relocation check, which derives each field's intended target independently.
 */

/** What one reconstruction did when it was placed at its own address. */
export type ContributionOrigin =
  /** Compiled, long enough, and written into the image. */
  | 'placed'
  /** The compiler rejected the stored source, or emitted no code for it. */
  | 'not-built'
  /** It compiled, but to fewer bytes than the inventory claims the function
   *  has, so there is nothing honest to put in the remainder. */
  | 'too-short'
  /** The function is not inside the executable span, so it has no place in
   *  this image. Reported rather than skipped: a proven function outside
   *  .text means the inventory and the section header disagree. */
  | 'outside-span';

export interface Contribution {
  readonly va: number;
  readonly attemptId: number;
  readonly origin: ContributionOrigin;
  /** What the inventory claims this function occupies. */
  readonly size: number;
  readonly emitted: Option.Option<number>;
  /** Relocation fields taken from the subject rather than compared. */
  readonly masked: number;
  /** Bytes this contribution wrote that disagree with the subject. Non-zero
   *  for a function recorded as proven is a retraction, not a rounding error. */
  readonly diffBytes: number;
  readonly firstDiff: Option.Option<number>;
  readonly detail: Option.Option<string>;
}

/** Two inventory entries that claim the same bytes. */
export interface Overlap {
  readonly va: number;
  readonly size: number;
  readonly nextVa: number;
  readonly overlappingBytes: number;
}

export interface CompositionReport {
  readonly runId: number;
  readonly subjectSha: string;
  /** The toolchain the configuration names, which is what `proven` is relative
   *  to and therefore what this composition is a statement about. */
  readonly toolchainInForce: string;
  /** The toolchain the gate identified when this ran. Reported next to the one
   *  in force because if they differ, every source composed here was proved by
   *  a compiler that is not the one that just built it. */
  readonly toolchainUsed: string;
  readonly textLo: number;
  readonly textHi: number;
  readonly spanBytes: number;
  readonly considered: number;
  /**
   * How `considered` was reached. A run may carry a contribution forward
   * instead of recompiling it -- only when a previous finished run under the
   * same toolchain recorded the same attempt as `placed` with no differing
   * byte, which makes re-emitting it provably a no-op against a canvas
   * initialised from the subject.
   *
   * Reported separately because a run that recompiled twelve functions and
   * carried 3,350 must not read as having verified 3,362. A cache that claimed
   * work it had not done is a defect this project has already shipped once.
   */
  readonly recompiled: number;
  readonly carried: number;
  readonly placed: number;
  readonly notBuilt: number;
  readonly tooShort: number;
  readonly outsideSpan: number;
  /** Placed, and did not reproduce the subject. Each one is a recorded proof
   *  that no longer holds. */
  readonly disagreeing: number;
  readonly placedBytes: number;
  readonly maskedBytes: number;
  readonly overlaps: ReadonlyArray<Overlap>;
  /**
   * Bytes of the span where the assembled image differs from the subject.
   *
   * This is the number the proof rests on. Zero means every reconstruction in
   * force compiles, at its real address, to the bytes the subject has there.
   */
  readonly diffBytes: number;
  /** Differing bytes no contribution accounts for. Stored and reported
   *  separately from the total because "the parts add up" is a claim, and only
   *  keeping both numbers can refute it. */
  readonly unattributedDiffBytes: number;
  /** Every contribution that disagreed or could not be placed. The ones that
   *  worked are in the database; these are the ones a reader needs. */
  readonly problems: ReadonlyArray<Contribution>;
}

export type ComposeFailure =
  | DbError
  | GateUnavailable
  | NoCurrentSubject
  | SubjectIoError
  | SubjectParseError;

export interface ICompose {
  /**
   * Assemble the executable span and diff it against the subject, recording
   * the run and every contribution to it.
   *
   * Recorded rather than returned-and-forgotten: a diff is only useful if it
   * can still be interrogated after the process that found it has gone, and
   * only meaningful if it names the compiler and subject it was made against.
   */
  run(): EffectGen<CompositionReport, ComposeFailure>;

  /**
   * The most recent composition made under the configuration currently in
   * force, or `None`. One made against another subject or compiler is not
   * returned -- it is not a statement about this one.
   */
  current(): EffectGen<Option.Option<CompositionReport>, DbError>;
}
