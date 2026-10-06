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

export type Evidence =
  | 'proven-call'
  | 'data-pointer'
  | 'decoded-call'
  /**
   * GAP RESIDUE -- executable bytes between two known extents that are not
   * padding.
   *
   * This is evidence by ELIMINATION rather than by reference, and it is the
   * only kind that can find a function nothing points at. The inventory grows
   * from calls and from pointer tables, so a function reached only through a
   * computed call, or whose only reference is in data this derivation has not
   * read, is invisible to every other rule however many rounds it runs.
   *
   * Measured: the inventory covers 85.81% of the executable span. Of the
   * 291,413 bytes it does not claim, 5,771 gaps totalling 44,529 bytes are
   * nothing but 0x90/0xCC/0x00 padding, and 527 gaps totalling 246,884 bytes
   * -- 10.93% of all executable bytes -- hold real content. The largest
   * begins `64 a1 00 00 00 00 6a ff`: `mov eax, fs:[0]` then `push -1`, which
   * is MSVC's structured-exception frame setup and appears only at a function
   * entry.
   *
   * It is deliberately NOT a prologue whitelist. The question asked is "do
   * these bytes decode contiguously to a terminator, inside a region two
   * known functions bound" -- a property of the bytes, not a guess about what
   * entries look like. A first-byte whitelist was tried here before and
   * rejected 14% of the functions we had already proven.
   */
  | 'gap-residue'
  /**
   * PADDING-ALIGNED -- a run of 0x90/0xCC ending at a 16-byte-aligned
   * address, with real content after it.
   *
   * MSVC aligns each function and fills the space before it, so the end of a
   * padding run at an alignment boundary is where the next function begins.
   * Measured against the 3,356 functions already proven byte-exact: 89.5% of
   * them are preceded by exactly this, and across the whole executable span
   * 6,182 of 7,630 such boundaries (81%) land on an address the inventory
   * already holds. The remaining 1,448 are candidate entries no reference
   * reaches.
   *
   * The 16-byte test is what makes it usable. Single 0x90 bytes are common
   * INSIDE functions -- MSVC pads to align a loop target -- and in one
   * 12,544-byte stretch 23 of 26 padding runs were that, not boundaries.
   * Requiring the run to end on an alignment boundary separates the two.
   *
   * This is the only evidence kind that does not follow a reference, so it is
   * the only one that can reach a function nothing points at.
   */
  | 'padding-aligned';

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

export interface GapReport {
  readonly at: number;
  readonly textBytes: number;
  /** Bytes claimed by some inventory extent. */
  readonly coveredBytes: number;
  readonly gaps: number;
  /** Gaps that are nothing but padding. Not a finding; the compiler aligns
   *  functions and the space between them is real. */
  readonly paddingGaps: number;
  readonly paddingBytes: number;
  /** Gaps holding bytes that are not padding: unfound code, or data the
   *  linker placed in the executable section. */
  readonly residueGaps: number;
  readonly residueBytes: number;
  /** Spans whose extent the bytes DO settle. `added` counts only those
   *  written, which on a dry run is zero -- so without this the report could
   *  not tell a span that measured from one that failed. */
  readonly measured: number;
  readonly added: number;
  /** Residue that could not be measured into an extent, with the reason and
   *  its first bytes, so a rule that is wrong can be revisited against what
   *  it excluded rather than silently costing functions nobody can see. */
  readonly deferred: ReadonlyArray<{
    readonly va: number;
    readonly bytes: number;
    readonly reason: string;
    readonly head: string;
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
   * Find functions in the space BETWEEN known functions.
   *
   * Every other rule follows a reference, so none of them can find a function
   * nothing references. This one works by elimination: executable bytes that
   * no extent claims and that are not padding are either an unfound function
   * or data, and asking whether they decode contiguously to a terminator
   * separates the two.
   *
   * `add` records what it measures. Run with it false to size the gap without
   * changing the inventory.
   */
  scanGaps(add: boolean):
    EffectGen<GapReport, DbError | DisasmError | SubjectIoError | SubjectParseError | DiscoveryFailed>;

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
  /**
   * Withdraw a rejection, so the address can be recorded as an entry again.
   *
   * A rejection is enforced by a trigger that raises IGNORE on every insert
   * into `functions` for that address, which makes it permanent: there was no
   * way to undo one. A worker then rejected four real functions -- 0x565DB0,
   * 0x566080, 0x566420 and 0x567A30 -- because the extents it measured around
   * them were too long, and found out afterwards. It deliberately did NOT
   * reject the four over-long entries it had recorded, because doing so would
   * have blocked the real functions inside them from ever entering the
   * inventory at all. Both halves of that correction needed this.
   *
   * It takes a reason of its own. A rejection carried the decode that
   * justified it, and withdrawing one without saying why would leave the
   * record claiming the opposite of what someone decided, with nothing to
   * weigh against it.
   */
  unreject(
    entries: ReadonlyArray<{ readonly va: number; readonly reason: string }>,
  ): EffectGen<
    ReadonlyArray<{ readonly va: number; readonly withdrawn: boolean; readonly because: string }>,
    DbError | DiscoveryFailed
  >;

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

  /**
   * Record a function entry an agent established by reading the bytes.
   *
   * The counterpart to `reject`. An inventory entry can start mid-instruction
   * -- 0x50241E is the second byte of a `mov ecx, esi` -- and the enclosing
   * function's real entry then exists nowhere in the inventory, so no rule
   * finds it and no agent can claim it. Correcting that is work done OUTSIDE
   * a claim, and there was no way to record the answer.
   *
   * The claim is CHECKED, not trusted: the address must decode, its extent
   * must measure, and it must not overlap a function that has a proof. An
   * agent can be wrong -- the same report said there was an unlisted function
   * at 0x502280 when the inventory already held it.
   */
  recordEntry(entries: ReadonlyArray<{ readonly va: number; readonly evidence: string }>):
    EffectGen<ReadonlyArray<{
      readonly va: number;
      readonly accepted: boolean;
      readonly size: Option.Option<number>;
      readonly refusedBecause: Option.Option<string>;
    }>, DbError | DisasmError | SubjectIoError | SubjectParseError | DiscoveryFailed>;

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
