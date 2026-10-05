import { Option } from 'effect';
import type { EmittedFunction } from './coff';

/**
 * The byte-exactness comparison.
 *
 * Pure, and deliberately ignorant of how the candidate bytes were produced:
 * it takes the subject's bytes and the compiler's output, so it works the same
 * for MSVC 6 output, hand-written assembly, or anything else, and it cannot be
 * satisfied by a harness bug that only makes two runs of one compiler agree.
 * Behavioural agreement is not consulted and cannot produce a pass.
 */

export interface Comparison {
  /**
   * The only field that may be read as a proof: some emitted function holds
   * the subject's bytes, every one of them agreeing except those the linker
   * would patch.
   */
  readonly exact: boolean;
  /**
   * Where the subject's bytes sit inside the emitted function named by
   * `symbol`.
   *
   * `Some(0)` is the claim a reconstruction of this address makes: the match
   * is at the emitted function's ENTRY. The emitted function may be LONGER
   * than the subject without weakening that -- a section is padded to its
   * alignment, and a switch's jump and byte tables sit after the code while
   * the subject's recorded size counts only the code.
   *
   * `Some(n)` for n > 0 is a FRAGMENT match: the subject's bytes appear in the
   * middle of something larger, which answers the weaker question "do these
   * bytes occur somewhere" rather than "is this that function". It is reported
   * rather than rejected, because some subjects genuinely are fragments --
   * hand-written assembly that falls through into the next routine has no
   * entry of its own -- but it is never the same claim.
   *
   * `None` when nothing matched.
   */
  readonly matchedAt: Option.Option<number>;
  /** The emitted function the verdict describes: the one that matched, or, on
   *  a failure, the closest candidate. `None` when nothing was emitted. */
  readonly symbol: Option.Option<string>;
  /**
   * That same function, as the compiler emitted it.
   *
   * Carried because a caller that must PLACE these bytes -- the composition
   * proof, the relocation check -- needs the function this comparison
   * SELECTED, and re-deriving the choice by searching the object for a
   * matching symbol name would be a second answer to the question this module
   * already answered.
   */
  readonly selected: Option.Option<EmittedFunction>;
  /** That function's own emitted length, which is not the subject's size. */
  readonly emittedSize: Option.Option<number>;
  /**
   * Bytes the gate had to EXCUSE: positions carrying a relocation record whose
   * compiled byte differs from the subject's. Not every byte carrying a
   * relocation -- a relocation whose compiled byte already equals the
   * subject's is agreement, and counting those put three bytes per exception
   * frame in the unverified column when all twelve matched exactly.
   *
   * Reported so a pass can never quietly rest on having masked most of the
   * function. Over a quarter of the subject's size is weakly verified.
   */
  readonly masked: number;
  /** Bytes actually compared: the subject's size minus `masked`. */
  readonly compared: number;
  /**
   * Offset of the first byte that differs and is NOT a relocation field, in
   * the function this verdict describes. Diagnostic only: it never
   * contributes to `exact`, and it is `None` on an exact match or when nothing
   * was emitted.
   */
  readonly firstDiff: Option.Option<number>;
}

export interface ComparisonInput {
  /** The subject's own bytes at the address under test. */
  readonly original: Uint8Array;
  /** Every function the compiler emitted, in symbol-table order. */
  readonly functions: ReadonlyArray<EmittedFunction>;
}

/** The first byte that differs and is not excused by a relocation, or -1. */
const firstUnexcusedDiff = (fn: EmittedFunction, original: Uint8Array, at: number): number => {
  for (let k = 0; k < original.length; k += 1) {
    if (fn.relocated.has(at + k)) continue;
    if (fn.code[at + k] === original[k]) continue;
    return k;
  }
  return -1;
};

/** Relocation bytes that had to be excused to call this position a match. */
const excused = (fn: EmittedFunction, original: Uint8Array, at: number): number => {
  let count = 0;
  for (let k = 0; k < original.length; k += 1) {
    if (fn.relocated.has(at + k) && fn.code[at + k] !== original[k]) count += 1;
  }
  return count;
};

/** How many bytes disagree, unexcused, with the subject at this function's
 *  entry. A byte the function is too short to hold counts as a disagreement. */
const entryDisagreements = (fn: EmittedFunction, original: Uint8Array): number => {
  let count = 0;
  for (let k = 0; k < original.length; k += 1) {
    if (k >= fn.code.length) {
      count += 1;
      continue;
    }
    if (fn.relocated.has(k) || fn.code[k] === original[k]) continue;
    count += 1;
  }
  return count;
};

const describe = (
  fn: EmittedFunction,
  original: Uint8Array,
  at: number,
  exact: boolean,
): Comparison => {
  const masked = excused(fn, original, at);
  const diff = firstUnexcusedDiff(fn, original, at);
  return {
    exact,
    matchedAt: exact ? Option.some(at) : Option.none(),
    symbol: Option.some(fn.symbol),
    selected: Option.some(fn),
    emittedSize: Option.some(fn.code.length),
    masked,
    compared: original.length - masked,
    firstDiff: diff < 0 ? Option.none() : Option.some(diff),
  };
};

/**
 * Look for the subject's bytes in the compiler's output.
 *
 * The strongest claim is tried first, across EVERY emitted function, before
 * any weaker one is considered: a match at a function's entry anywhere in the
 * object outranks a fragment match anywhere in it.
 */
export const compareToSubject = ({ original, functions }: ComparisonInput): Comparison => {
  const n = original.length;

  for (const fn of functions) {
    if (fn.code.length >= n && firstUnexcusedDiff(fn, original, 0) < 0) {
      return describe(fn, original, 0, true);
    }
  }
  for (const fn of functions) {
    for (let at = 1; at + n <= fn.code.length; at += 1) {
      if (firstUnexcusedDiff(fn, original, at) < 0) return describe(fn, original, at, true);
    }
  }

  if (functions.length === 0) {
    return {
      exact: false,
      matchedAt: Option.none(),
      symbol: Option.none(),
      selected: Option.none(),
      emittedSize: Option.none(),
      masked: 0,
      compared: 0,
      firstDiff: Option.none(),
    };
  }

  // Nothing matched, so the verdict describes the closest candidate: the
  // function with the fewest unexcused disagreements at its entry. Reporting
  // its first difference is the whole value of a failing verdict to whoever
  // has to fix the reconstruction.
  let closest = functions[0]!;
  let fewest = entryDisagreements(closest, original);
  for (const fn of functions.slice(1)) {
    const count = entryDisagreements(fn, original);
    if (count < fewest) {
      closest = fn;
      fewest = count;
    }
  }
  return describe(closest, original, 0, false);
};
