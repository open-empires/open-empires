import { Option, Schema } from 'effect';
import type { EffectGen } from 'effective-modules';
import type { DbError } from '../db/interface';
import type { DisasmError } from '../disasm/interface';
import type { SubjectIoError, SubjectParseError } from '../subject/interface';

/**
 * Finding functions, continuously, from evidence that can be checked.
 *
 * The previous pass was a one-off run of hand-written rules, and its rules
 * were the problem. It rejected an address whose first byte was not in a
 * whitelist of eight — while 468 of our own 3,314 byte-exact functions (14%)
 * start with a byte outside that list. It also silently discarded 1,462
 * addresses as "compiler-generated". A validator that rejects known-good
 * input is worse than none, and this project has already lost a pass that way.
 *
 * So the basis here is evidence strength, and the strongest kind was never
 * used at all:
 *
 *   PROVEN CALL -- a `call rel32` inside a function whose bytes we have
 *   reproduced exactly. We compiled source that emits those bytes, so the
 *   instruction is not a guess about where an instruction boundary falls;
 *   it is a fact about verified bytes, and its target is a function entry by
 *   proof. 3,314 proven functions had never been harvested.
 *
 *   DATA POINTER -- a dword outside the executable span holding an address
 *   inside it. That is what a vtable slot is, and it is a fact about bytes
 *   regardless of how anything decodes.
 *
 *   DECODED CALL -- a call inside a function we have NOT proven. It depends
 *   on the decode being right, so it is evidence, but weaker.
 *
 * Nothing is rejected and discarded. An address that cannot be measured, or
 * that looks compiler-generated, is RECORDED with that reason, so a rule that
 * turns out to be wrong can be revisited against the addresses it excluded
 * rather than silently costing us functions nobody can see.
 */

export class DiscoveryFailed extends Schema.TaggedError<DiscoveryFailed>()(
  'DiscoveryFailed',
  { reason: Schema.String },
) {}

export type Evidence = 'proven-call' | 'data-pointer' | 'decoded-call';

export interface Candidate {
  readonly va: number;
  readonly evidence: Evidence;
  /** The proven function, or the data address, the evidence came from. */
  readonly from: number;
}

export interface ExpansionReport {
  readonly at: number;
  readonly scanned: number;
  readonly candidates: number;
  readonly added: number;
  /** Candidates skipped because a rejection is on record for that address. */
  readonly refused: number;
  readonly alreadyKnown: number;
  readonly interior: number;
  /** Recorded, not discarded: why each unmeasurable candidate was set aside. */
  readonly deferred: ReadonlyArray<{ va: number; reason: string }>;
  readonly byEvidence: Readonly<Record<Evidence, number>>;
}

/** The outcome of asking the service to reject an address. */
export interface RejectionOutcome {
  readonly va: number;
  readonly accepted: boolean;
  /** Why not, when `accepted` is false. */
  readonly refusedBecause: Option.Option<string>;
  /** Entries whose extent measurement this address was truncating. A
   *  spurious entry bounds its predecessor, so removing it is what makes
   *  that predecessor measurable. */
  readonly unblocks: ReadonlyArray<number>;
}

/**
 * Whether each inventory entry is WORKABLE as recorded.
 *
 * `decodeFunctionBody` requires the instruction sizes to sum exactly to the
 * recorded size, and rightly: a partial decode is not a function. The
 * consequence is that an entry whose recorded size cuts mid-instruction is
 * handed to an agent with an EMPTY disassembly. Nothing errors. The agent
 * sees a function with no body, and the address sits in the queue forever.
 *
 * Two such entries were found by hand, at 0x5a4afa and 0x5a4e99 -- both
 * textbook __thiscall members recorded 436 and 482 bytes short. So the
 * question "how many functions can no agent work on" has to be asked of the
 * whole inventory, by the service, on a schedule.
 */
export interface WorkabilityAudit {
  readonly at: number;
  readonly entries: number;
  /** Decodes to exactly its recorded span: an agent gets a real listing. */
  readonly workable: number;
  /** Recorded extent does not decode. These are unsolvable as recorded. */
  readonly undecodable: ReadonlyArray<{
    readonly va: number;
    readonly size: number;
    /** What the bytes measure instead, when that can be determined. */
    readonly measured: Option.Option<number>;
    readonly proven: boolean;
    /** True when `repair` wrote `measured` back for this entry. The report
     *  carries the size as FOUND, so without this flag a repaired entry
     *  reads identically to one nothing was done about. */
    readonly repaired: boolean;
    /** Bytes the decode covers. Far short of `size` means data inside the
     *  body; a few bytes over means the recorded size is wrong. */
    readonly covered: number;
  }>;
}

export interface IDiscovery {
  /**
   * Harvest entries from specific proven functions. Called when a proof
   * lands, so the inventory grows as a consequence of progress rather than
   * when someone remembers to run a script.
   */
  expandFrom(vas: ReadonlyArray<number>):
    EffectGen<ExpansionReport, DbError | DisasmError | SubjectIoError | SubjectParseError | DiscoveryFailed>;

  /**
   * Harvest from every proven function and from the data image, repeating
   * until no new entry appears. Safe to re-run: it only ever adds addresses
   * that carry evidence and do not fall inside a known extent.
   */
  expandAll(maxRounds: number):
    EffectGen<ReadonlyArray<ExpansionReport>, DbError | DisasmError | SubjectIoError | SubjectParseError | DiscoveryFailed>;

  /**
   * Re-measure recorded extents from the bytes.
   *
   * The inventory's sizes came from several producers over months, and three
   * of them were reported wrong by an agent reading the disassembly. A size
   * is not an opinion -- it is a property of the bytes -- so the service
   * measures it rather than accepting a correction by hand.
   *
   * `apply` writes a differing measurement back. It REFUSES to touch a
   * function that has a proof: the proof was obtained against the recorded
   * span, so changing the span would silently invalidate it. Those come back
   * with `applied: false` and the disagreement visible.
   */
  remeasure(vas: ReadonlyArray<number>, apply: boolean):
    EffectGen<ReadonlyArray<Remeasurement>, DbError | DisasmError | SubjectIoError | SubjectParseError | DiscoveryFailed>;

  /**
   * Record that an address is NOT a function entry.
   *
   * Deleting the row was the obvious move and it does not work: the evidence
   * that produced the address is still in the bytes, so the next producer
   * re-adds it. Three such rows came back that way. So a rejection is stored,
   * with its reason and the decode that justifies it, and every producer
   * consults it.
   *
   * REFUSED for an address that has a proof. A proof means source was
   * compiled that reproduces those bytes at that address, which is far better
   * evidence of an entry than any rule here; a rejection that could overrule
   * a proof would let a judgement delete a fact.
   */
  reject(entries: ReadonlyArray<{ readonly va: number; readonly reason: string }>):
    EffectGen<ReadonlyArray<RejectionOutcome>, DbError | DisasmError | SubjectIoError | SubjectParseError | DiscoveryFailed>;

  /**
   * Ask of every inventory entry whether its recorded extent decodes.
   *
   * `repair` writes a differing measurement back for the undecodable ones,
   * which is what makes them workable. It never touches a proven function:
   * a proof was obtained against the recorded span.
   */
  auditWorkability(repair: boolean):
    EffectGen<WorkabilityAudit, DbError | DisasmError | SubjectIoError | SubjectParseError | DiscoveryFailed>;

  /** Every recorded rejection, for the subject in force. */
  rejections():
    EffectGen<ReadonlyArray<{ readonly va: number; readonly reason: string; readonly evidence: string }>, DbError | DiscoveryFailed>;
}

/** One address's recorded size against what its bytes actually measure. */
export interface Remeasurement {
  readonly va: number;
  readonly recorded: number;
  /** None when the bytes do not decode to a bounded function. */
  readonly measured: Option.Option<number>;
  /** The entry the measurement was bounded by. A recorded size that runs past
   *  it is describing more than one function. */
  readonly nextEntry: number;
  readonly applied: boolean;
}
