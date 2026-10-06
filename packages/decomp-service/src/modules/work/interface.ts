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

/**
 * The caller does not hold a live lease on this address.
 *
 * `because` exists because this one tag covered four different situations and
 * the caller had to guess which. Worker r37-b read a 409 as "already proven"
 * when the addresses certainly were not, and spent its time re-deriving work
 * it already held the answer to. Each of these needs a different response:
 *
 *   never-claimed    claim it
 *   lease-expired    claim it again; the work is still there
 *   held-by-another  leave it alone, someone else is on it
 *   already-proven   nothing to do
 *
 * `urllib` raises on a 409 and the body is only visible through `e.read()`,
 * so the reason is also in the message itself.
 */
/**
 * A park with no stated blocker.
 *
 * Parking is how a function leaves the queue, so the reason is the only thing
 * that says what to build next. 53 of 111 parked functions carry no class --
 * 50 of them do record what was eliminated, so the knowledge was not lost,
 * but "what is blocking us" could not be counted over half the evidence, and
 * that count is exactly what decides where effort goes.
 */
export class ParkWithoutReason extends Schema.TaggedError<ParkWithoutReason>()(
  'ParkWithoutReason',
  { va: Schema.Number, missing: Schema.String },
) {}

export class NotClaimed extends Schema.TaggedError<NotClaimed>()('NotClaimed', {
  va: Schema.Number,
  agentId: Schema.String,
  because: Schema.Literals([
    'never-claimed',
    'lease-expired',
    'held-by-another',
    'already-proven',
  ]),
  /** Plain-language form of `because`, for a client that only shows a message. */
  detail: Schema.String,
}) {}

export class UnknownFunction extends Schema.TaggedError<UnknownFunction>()(
  'UnknownFunction',
  { va: Schema.Number },
) {}

/**
 * The gate found the source exact at the entry, and the record does not hold
 * it as proven afterwards.
 *
 * This exists because the service did exactly that, twice in 87 submissions,
 * under load: a full positive verdict with no attempt row and no verdict row
 * behind it. Re-submitting the identical source stored them, so nothing was
 * permanently lost -- but a caller that believed the first answer would have
 * recorded a proof the project does not have.
 *
 * It is raised INSTEAD of a positive verdict, never alongside one. A caller
 * cannot be asked to check whether the answer it was given is true.
 */
export class NotStored extends Schema.TaggedError<NotStored>()('NotStored', {
  va: Schema.Number,
  reason: Schema.String,
}) {}

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
export type SubmitFailure =
  | WorkFailure | GateUnavailable | NotClaimed | UnknownFunction | NotStored;

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
  /**
   * Byte-exact AND at the emitted function's entry. The two are conjoined
   * here on purpose: this is the field a caller acts on, and the weaker "the
   * bytes occur somewhere inside a larger emission" must never be readable as
   * a proof.
   */
  readonly exact: boolean;
  readonly compiled: boolean;
  /**
   * Where the bytes matched, when they matched anywhere: `0` at the entry, a
   * positive offset for a fragment match, `None` for no match at all.
   *
   * Reported alongside `exact` because a fragment match used to arrive as a
   * bare `exact: false`, indistinguishable from matching nothing -- and
   * "your bytes are in there, just not at the entry" is one of the more
   * useful things the gate can say.
   */
  readonly matchedAt: Option.Option<number>;
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

/**
 * How many source spellings one probe may compile.
 *
 * The compiler is one serialised container shared by every agent and by the
 * composition proof, so a probe is capped the way a sweep is. Sixteen is
 * enough for the cross products workers actually submit -- the largest so far
 * was nineteen, run as nineteen separate calls -- and small enough that one
 * probe cannot hold the container for minutes.
 */
export const MAX_PROBE_SOURCES = 16;

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
   * sha256 of the code this flag set emitted, so "these flag sets produce the
   * same bytes" can be CHECKED across a sweep's outcomes instead of inferred
   * from `emittedSize` and `firstDiff` -- which cannot establish it, and were
   * read that way once for a finding that rested entirely on the claim.
   */
  readonly emittedSha: Option.Option<string>;
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

/**
 * What the best-performing source actually compiled to, beside the subject.
 *
 * `firstDiff` alone is a one-bit oracle on a large function: it reports the
 * first differing byte and stops, so a divergence at offset 52 of 3,942 says
 * nothing about the other 3,890. These two listings are addressed at the
 * same VA so they can be read side by side.
 */
export interface SweepComparison {
  readonly flags: string;
  readonly firstDiff: Option.Option<number>;
  readonly emittedBytes: string;
  readonly emittedListing: string;
  readonly subjectListing: string;
  /** Offsets the LINKER fills. A difference at one of these is not a
   *  difference in the reconstruction. */
  readonly relocatedOffsets: ReadonlyArray<number>;
  /**
   * EVERY offset that differs, with the relocation fields already excused.
   *
   * `firstDiff` alone is actively misleading and has cost whole rounds. One
   * function read `firstDiff 14` both before and after a fix that took its
   * true count of differing bytes from 17 to 1: the first difference stayed
   * where it was while almost everything behind it was repaired, so the only
   * number the caller had said nothing had happened. Another was abandoned
   * twice because a 3,942-byte function diverged at offset 52 -- the low byte
   * of a branch displacement near the front -- and nothing reported that the
   * remaining 3,890 bytes were already right.
   *
   * Computed here because the gate holds both byte arrays and the relocation
   * set at the moment of comparison, and every worker was otherwise
   * re-implementing this from `emittedBytes` and the two listings. Several did
   * it differently.
   */
  readonly differingOffsets: ReadonlyArray<number>;
  /** How many bytes differ, which is the figure to watch across attempts.
   *  Carried beside the list so a caller can see progress without parsing
   *  it. */
  readonly differingBytes: number;
}

/**
 * Whether one named address can be claimed, and if not, which of the mutually
 * exclusive reasons applies. The order they are decided in is the order they
 * are listed here, so an address that is both absent and unproven reports the
 * absence -- the more fundamental fact.
 */
export type ClaimabilityReason =
  | 'claimable'
  /** No inventory entry for this address under the current subject. */
  | 'not-in-inventory'
  /** An entry with no bytes: a discovery defect, not work. */
  | 'zero-extent'
  | 'already-proven'
  | 'held-by-another';

export interface Claimability {
  readonly va: number;
  readonly reason: ClaimabilityReason;
  readonly size: Option.Option<number>;
  /**
   * Whether a proof exists, and whether it is parked, INDEPENDENTLY of
   * `reason`.
   *
   * `reason` is one mutually-exclusive verdict about claiming, and parked is
   * not one of its values: a parked function can still be claimed by explicit
   * address, which is how a second pass happens. So "is this proven / parked /
   * an entry at all" could not be answered for one address by any route, and a
   * worker read the database to find out. These two fields make this the one
   * place to ask.
   */
  readonly proven: boolean;
  readonly parked: boolean;
  /** The class it was parked under, when it is parked. */
  readonly blockedClass: Option.Option<string>;
  /** Who holds it, when the reason is `held-by-another`. */
  readonly heldBy: Option.Option<string>;
  readonly secondsLeft: Option.Option<number>;
}

/** A parked function and the reasoning that parked it. */
export interface ParkedRecord {
  readonly va: number;
  readonly size: number;
  readonly blockedClass: Option.Option<string>;
  /** What the author ruled out, verbatim. The reason a second pass is cheaper
   *  than a first. */
  readonly eliminated: Option.Option<string>;
  readonly note: Option.Option<string>;
  readonly updatedAt: number;
  /** True while someone holds it, so a reader does not start on work in
   *  flight. */
  readonly claimed: boolean;
}

/** One live lease, as its holder needs to see it. */
export interface HeldClaim {
  readonly va: number;
  readonly size: number;
  readonly claimedAt: number;
  readonly expiresAt: number;
  /** Seconds until the lease lapses and the work returns to the queue.
   *  Negative would mean it already has, so such a claim is not reported. */
  readonly secondsLeft: number;
  /** True when a proof for this address already exists, which makes the claim
   *  releasable rather than workable. */
  readonly proven: boolean;
}

/**
 * One source spelling's outcome under one flag set.
 *
 * Deliberately the same fields a sweep outcome carries, minus the flag set:
 * a probe varies the SOURCE where a sweep varies the flags, and a reader
 * should not have to learn two shapes to compare them.
 */
export interface ProbeOutcome {
  /** Index into the `sources` array as it was submitted, so an outcome can be
   *  matched back to the spelling that produced it. */
  readonly index: number;
  readonly compiled: boolean;
  /**
   * The gate's verdict on the bytes, which is NOT on its own a proof.
   *
   * A probe is a diagnostic and reports the raw facts, exactly as `sweep`
   * does: this is true for a match at any offset. The rule across both is one
   * rule -- a proof is `exact` AND `matchedAt` 0 -- and `matched` below is the
   * list of indices where both hold.
   *
   * `submit` and `amend` are different on purpose: they return the
   * conjunction, because what they return is acted on as a proof.
   */
  readonly exact: boolean;
  /**
   * Where the bytes matched: 0 at the entry, a positive offset for a fragment
   * match, None for no match.
   *
   * A probe carried no such field at all, so a worker reading `matchedAt` on
   * each outcome got `null` every time and could not tell an entry match from
   * a fragment -- which is the weaker claim that has already let three
   * reconstructions pass on a correct sibling's bytes.
   */
  readonly matchedAt: Option.Option<number>;
  readonly emittedSize: Option.Option<number>;
  readonly masked: Option.Option<number>;
  readonly firstDiff: Option.Option<number>;
  readonly emittedSha: Option.Option<string>;
  readonly detail: Option.Option<string>;
}

export interface ProbeReport {
  readonly va: number;
  readonly size: number;
  readonly flags: string;
  readonly outcomes: ReadonlyArray<ProbeOutcome>;
  /** Indices of sources that are exact at the entry. Empty is the usual
   *  answer. */
  readonly matched: ReadonlyArray<number>;
  /**
   * Sources grouped by the bytes they emitted, largest group first.
   *
   * This is the answer a structural question actually wants. A worker
   * established that nineteen structurally different spellings of one function
   * -- three guard forms crossed with four inner-arm forms, a `switch`, a
   * `do{break;}while(0)`, the body as a `static inline` helper -- all emit
   * byte-identical output, and it cost nineteen round trips to find out.
   * Grouping by digest says it in one call, and says which axes are inert
   * before any of them is reasoned about.
   */
  readonly identical: ReadonlyArray<{
    readonly emittedSha: string;
    readonly indices: ReadonlyArray<number>;
  }>;
}

export interface SweepReport {
  readonly va: number;
  readonly size: number;
  readonly outcomes: ReadonlyArray<SweepOutcome>;
  /** Flag sets that matched at the entry. Empty is the common answer. */
  readonly matched: ReadonlyArray<string>;
  /** Absent when nothing compiled. */
  readonly comparison?: SweepComparison;
  /** True when something matched under flags the configuration does not name.
   *  The one field a caller must not ignore. */
  readonly finding: boolean;
}

export interface IWork {
  /** Lease up to `count` unsolved functions, preferring ones that share a
   *  shape with something already solved. Returns fewer if the queue is
   *  short, and none if it is empty -- which is the signal to run the
   *  producer, not to spin. */
  /** `vas` asks for specific addresses instead of taking the queue's choice.
   *  Needed whenever an agent already knows what it wants: resuming after an
   *  outage dropped its lease, or re-attempting a parked near-miss. Without
   *  it, work solved but not yet recorded could not be recovered at all. */
  claim(
    agentId: string,
    count: number,
    leaseSeconds: number,
    vas?: ReadonlyArray<number>,
  ): EffectGen<ReadonlyArray<WorkItem>, WorkFailure>;

  /**
   * Every parked function, or every one in a named class, with what its
   * author ruled out.
   *
   * The `eliminated` text is the most valuable thing a second pass has --
   * every function above 1,024 bytes that has been proved closed on a second
   * pass over an earlier worker's written reading -- and a claim returned it
   * only for addresses the caller held. To read the other members of its own
   * class, a worker had to query `near_misses` directly, which is the one
   * thing agents are told never to do, and two of them did it in one day.
   *
   * `klass` matches a substring, because the classes are sentences written by
   * whoever parked the function and nobody can be expected to reproduce one
   * exactly.
   */
  parked(
    klass: Option.Option<string>,
    limit: number,
  ): EffectGen<ReadonlyArray<ParkedRecord>, WorkFailure>;

  /**
   * Compile MANY SOURCES under ONE flag set, and group them by the bytes they
   * emitted.
   *
   * `sweep` varies the flags over one source. Every structural question is the
   * other way round: which spelling of this function emits the subject's
   * bytes. Asking it meant one HTTP call and one container round trip per
   * spelling, and two workers reported that the round trip rather than the
   * reasoning set their pace -- a fifteen-variant cross product is fifteen
   * calls at about four seconds each.
   *
   * Writes nothing, for the same reason `sweep` writes nothing: a spelling
   * that happens to match under flags the configuration does not name is a
   * finding for a person, not a verdict. Needs a live claim, also like
   * `sweep`, because it costs the one serialised compiler.
   */
  probe(
    agentId: string,
    va: number,
    sources: ReadonlyArray<string>,
    flags: string,
    install?: string,
  ): EffectGen<ProbeReport, SubmitFailure>;

  /**
   * Measure the shape facts that decide what the queue hands out, for every
   * unsolved function that has no current measurement.
   *
   * Incremental on purpose: a corrected extent invalidates the measurement,
   * so a row whose recorded size no longer matches is re-measured, and
   * everything else is left alone. Decoding thousands of functions is the
   * expensive part.
   */
  measureClosability(limit: number): EffectGen<{
    readonly measured: number;
    readonly vetoed: number;
    readonly remaining: number;
  }, WorkFailure | DisasmError>;

  /**
   * Why each named address can or cannot be claimed.
   *
   * `claim` with explicit addresses silently returns fewer rows than it was
   * asked for: the query refuses an address that is already proven or under
   * someone else's lease, and the caller gets an array with nothing missing
   * from it that it can name. A worker asked for two addresses, received
   * `[]`, and could not tell "someone else is on it" from "it is already
   * done" -- which are opposite instructions.
   *
   * Kept as its own answer rather than folded into `claim`'s array, because
   * that array is what every live agent iterates and changing its shape
   * mid-run would break them.
   */
  claimable(vas: ReadonlyArray<number>): EffectGen<ReadonlyArray<Claimability>, WorkFailure>;

  /**
   * What this agent holds right now.
   *
   * The working protocol requires an agent's last action to be a gate run on
   * every address it still holds, and until now nothing could tell it what
   * those were: a worker had to read the database directly to confirm it had
   * released everything, which is the one thing agents are told never to do.
   * An obligation a caller cannot enumerate is an obligation it cannot meet.
   */
  claims(agentId: string): EffectGen<ReadonlyArray<HeldClaim>, WorkFailure>;

  /** Submit source for a claimed function. The service compiles it and
   *  returns the verdict; the agent never runs the compiler. */
  submit(agentId: string, va: number, source: string, flags: string, install?: string):
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
  sweep(
    agentId: string,
    va: number,
    source: string,
    flagSets: ReadonlyArray<string>,
    /** Which compiler install. The subject was built by two -- 306 objects
     *  from build 8447 and 169 from 8168 -- so a sweep can ask either. */
    install?: string,
  ): EffectGen<SweepReport, SubmitFailure>;

  /**
   * Replace the stored source of an ALREADY-PROVEN function.
   *
   * An exact submit makes an address unclaimable, so the text that happened
   * to be in hand at that moment became the permanent record. Agents kept
   * losing documentation to it -- proven functions stored as bare two-line
   * probes, and one stored with a comment claiming evidence a later control
   * disproved. There was no way to correct either.
   *
   * The proof is not weakened: the new source is compiled and must be exact
   * AT THE ENTRY, exactly as the original was. If it is not, nothing changes
   * and the caller is told. So this can improve the record and can never
   * launder a worse one into it.
   */
  amend(agentId: string, va: number, source: string, flags: string, toolchain?: string):
    EffectGen<Verdict, SubmitFailure>;

  /** Record a diagnosed near-miss and give the lease back. */
  park(agentId: string, va: number, blockedClass: string, eliminated: string):
    EffectGen<void, DbError | NotClaimed | ParkWithoutReason>;

  /** True when a live claim was actually given back. False means the caller
   *  did not hold that address, which must not read as success. */
  release(agentId: string, va: number): EffectGen<boolean, DbError>;

  /** Expire leases whose time is up. Owned by the server, run on a timer --
   *  never something a caller must remember. */
  reapExpiredClaims(): EffectGen<number, DbError>;

  /** How much claimable work remains. Zero means the producer must run. */
  queueDepth(): EffectGen<number, DbError>;
}
