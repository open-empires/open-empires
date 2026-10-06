import { Schema } from 'effect';

/**
 * The wire shapes of the HTTP API.
 *
 * Without these the service returned Effect's own internal representation --
 * `{"_id":"Option","_tag":"Some","value":"smoke"}` for a field that is
 * conceptually just a string or null. That is not a contract anyone outside
 * this process can code against, and it would change shape if the library's
 * internals did.
 *
 * So every response is ENCODED through a schema on the way out: an absent
 * value becomes `null`, which is what a JSON client expects. Decoding on the
 * way in and encoding on the way out are the only two places Option crosses
 * the boundary, and both are here.
 */

export const AgentWire = Schema.Struct({
  id: Schema.String,
  role: Schema.OptionFromNullOr(Schema.String),
  started: Schema.Number,
  lastBeat: Schema.Number,
  beats: Schema.Number,
  finished: Schema.OptionFromNullOr(Schema.Number),
  note: Schema.OptionFromNullOr(Schema.String),
  /** What the agent last said it was doing, and when it said it. The "when"
   *  is separate from the beat on purpose: an agent can keep beating while
   *  its description ages. */
  doing: Schema.OptionFromNullOr(Schema.String),
  doingAt: Schema.OptionFromNullOr(Schema.Number),
  state: Schema.Literals(['live', 'gone', 'finished']),
  silentFor: Schema.OptionFromNullOr(Schema.Number),
});

export const VerdictWire = Schema.Struct({
  exact: Schema.Boolean,
  compiled: Schema.Boolean,
  emittedSize: Schema.OptionFromNullOr(Schema.Number),
  masked: Schema.OptionFromNullOr(Schema.Number),
  compared: Schema.OptionFromNullOr(Schema.Number),
  firstDiff: Schema.OptionFromNullOr(Schema.Number),
  detail: Schema.OptionFromNullOr(Schema.String),
  weak: Schema.Boolean,
});

export const WorkItemWire = Schema.Struct({
  va: Schema.Number,
  size: Schema.Number,
  disassembly: Schema.String,
  siblings: Schema.Array(
    Schema.Struct({
      va: Schema.Number,
      similarity: Schema.Number,
      source: Schema.String,
    }),
  ),
  previousAttempts: Schema.Array(
    Schema.Struct({
      flags: Schema.String,
      exact: Schema.Boolean,
      firstDiff: Schema.OptionFromNullOr(Schema.Number),
      detail: Schema.OptionFromNullOr(Schema.String),
    }),
  ),
  nearMiss: Schema.OptionFromNullOr(
    Schema.Struct({
      blockedClass: Schema.OptionFromNullOr(Schema.String),
      eliminated: Schema.OptionFromNullOr(Schema.String),
    }),
  ),
});

/**
 * One flag sweep.
 *
 * `offConfiguration` and `finding` are on the wire for the same reason they are
 * in the report: a match under flags the configuration does not name is not a
 * pass, and a client that only read `matched` would record one as though it
 * were.
 */
export const SweepReportWire = Schema.Struct({
  va: Schema.Number,
  size: Schema.Number,
  outcomes: Schema.Array(
    Schema.Struct({
      flags: Schema.String,
      compiled: Schema.Boolean,
      exact: Schema.Boolean,
      matchedAtEntry: Schema.Boolean,
      emittedSize: Schema.OptionFromNullOr(Schema.Number),
      masked: Schema.OptionFromNullOr(Schema.Number),
      firstDiff: Schema.OptionFromNullOr(Schema.Number),
      detail: Schema.OptionFromNullOr(Schema.String),
      /** Digest of the code this flag set emitted, so a caller can tell which
       *  flag sets produced the SAME bytes. `emittedSize` and `firstDiff`
       *  cannot answer that, and were read as if they could. */
      emittedSha: Schema.OptionFromNullOr(Schema.String),
      offConfiguration: Schema.Boolean,
    }),
  ),
  matched: Schema.Array(Schema.String),
  /**
   * What the best candidate actually compiled to, beside the subject.
   *
   * This is the field whose absence made a sweep a one-bit oracle on a large
   * function. The gate has carried the emitted bytes all along -- only this
   * wire format dropped them -- so a worker facing a 3,942-byte function was
   * told the offset of the first differing byte and nothing more. Optional
   * because nothing is emitted when no flag set compiles.
   */
  comparison: Schema.optional(
    Schema.Struct({
      flags: Schema.String,
      firstDiff: Schema.OptionFromNullOr(Schema.Number),
      emittedBytes: Schema.String,
      emittedListing: Schema.String,
      subjectListing: Schema.String,
      relocatedOffsets: Schema.Array(Schema.Number),
    }),
  ),
  finding: Schema.Boolean,
});

/**
 * One recorded composition run.
 *
 * `problems` is on the wire and the functions that worked are not: a reader of
 * this needs the ones that did not, and the rest are a query against
 * `composition_contributions`.
 */
export const CompositionRunWire = Schema.Struct({
  runId: Schema.Number,
  subjectSha: Schema.String,
  toolchainInForce: Schema.String,
  toolchainUsed: Schema.String,
  textLo: Schema.Number,
  textHi: Schema.Number,
  spanBytes: Schema.Number,
  considered: Schema.Number,
  placed: Schema.Number,
  notBuilt: Schema.Number,
  tooShort: Schema.Number,
  outsideSpan: Schema.Number,
  disagreeing: Schema.Number,
  placedBytes: Schema.Number,
  maskedBytes: Schema.Number,
  overlaps: Schema.Array(
    Schema.Struct({
      va: Schema.Number,
      size: Schema.Number,
      nextVa: Schema.Number,
      overlappingBytes: Schema.Number,
    }),
  ),
  diffBytes: Schema.Number,
  unattributedDiffBytes: Schema.Number,
  problems: Schema.Array(
    Schema.Struct({
      va: Schema.Number,
      attemptId: Schema.Number,
      origin: Schema.Literals(['placed', 'not-built', 'too-short', 'outside-span']),
      size: Schema.Number,
      emitted: Schema.OptionFromNullOr(Schema.Number),
      masked: Schema.Number,
      diffBytes: Schema.Number,
      firstDiff: Schema.OptionFromNullOr(Schema.Number),
      detail: Schema.OptionFromNullOr(Schema.String),
    }),
  ),
});

export const AgentsWire = Schema.Array(AgentWire);
export const WorkItemsWire = Schema.Array(WorkItemWire);

export const encodeAgents = Schema.encodeUnknownSync(AgentsWire);
export const encodeVerdict = Schema.encodeUnknownSync(VerdictWire);
export const encodeWorkItems = Schema.encodeUnknownSync(WorkItemsWire);
export const encodeSweep = Schema.encodeUnknownSync(SweepReportWire);
export const encodeComposition = Schema.encodeUnknownSync(CompositionRunWire);

/**
 * The recovered-name report.
 *
 * `withheld` is on the wire beside `names`, and carries its reason. A client
 * that only read `names` would see 50 functions named and no sign that 13
 * candidates were refused -- which is the finding most likely to be undone by
 * someone who cannot see it.
 */
export const NameReportWire = Schema.Struct({
  subjectSha256: Schema.String,
  references: Schema.Number,
  unanchoredReferences: Schema.Number,
  distinctStrings: Schema.Number,
  qualifiedStrings: Schema.Number,
  namedFunctions: Schema.Number,
  byConfidence: Schema.Array(
    Schema.Struct({
      confidence: Schema.Literals(['lock-tag', 'self-named-other']),
      functions: Schema.Number,
    }),
  ),
  referencedOnly: Schema.Number,
  names: Schema.Array(
    Schema.Struct({
      va: Schema.Number,
      name: Schema.String,
      className: Schema.OptionFromNullOr(Schema.String),
      confidence: Schema.Literals(['lock-tag', 'self-named-other']),
      stringVa: Schema.Number,
      refSites: Schema.Array(Schema.Number),
      surfaceMemberOffsets: Schema.Array(Schema.Number),
    }),
  ),
  withheld: Schema.Array(
    Schema.Struct({
      va: Schema.Number,
      candidates: Schema.Array(Schema.String),
      reason: Schema.String,
    }),
  ),
  classes: Schema.Array(
    Schema.Struct({
      className: Schema.String,
      methodsSeen: Schema.Array(Schema.String),
      namedFunctions: Schema.Array(
        Schema.Struct({ va: Schema.Number, name: Schema.String }),
      ),
      surfaceMemberOffsets: Schema.Array(Schema.Number),
    }),
  ),
  surface: Schema.Struct({
    classes: Schema.Number,
    withObservedSurface: Schema.Number,
    commonMemberOffset: Schema.OptionFromNullOr(Schema.Number),
    agreeing: Schema.Number,
    contradicting: Schema.Array(
      Schema.Struct({
        className: Schema.String,
        memberOffsets: Schema.Array(Schema.Number),
      }),
    ),
    withoutObservedSurface: Schema.Array(Schema.String),
  }),
});

export const encodeNames = Schema.encodeUnknownSync(NameReportWire);

/**
 * The globals inventory.
 *
 * `deferrals` is on the wire beside `globals`, like `withheld` beside
 * `names`: a client that only read the inventory would see a count of
 * globals and no sign of the addresses whose size, name or contents the
 * evidence refused to settle -- which is the finding most likely to be undone
 * by someone who cannot see it.
 *
 * `pointers` carries BOTH numbers on purpose. `enumerated` is every dword in
 * the data region holding an address, which is what the missing relocation
 * table would have said; `attributed` is the subset that falls inside a
 * global whose extent is settled. They are different claims and the second is
 * much the smaller, so reporting one would misstate what is known.
 */
export const GlobalEntryWire = Schema.Struct({
  address: Schema.Number,
  section: Schema.String,
  evidence: Schema.Literals(['proven-literal', 'library-symbol', 'decoded-literal', 'pointer-dword']),
  size: Schema.OptionFromNullOr(Schema.Number),
  sizeBasis: Schema.OptionFromNullOr(
    Schema.Literals(['library-section', 'library-next-symbol', 'pointer-run', 'access-width']),
  ),
  name: Schema.OptionFromNullOr(Schema.String),
  nameFrom: Schema.OptionFromNullOr(Schema.String),
  holds: Schema.OptionFromNullOr(Schema.Literals(['code-pointer', 'data-pointer', 'float'])),
  holdsBasis: Schema.OptionFromNullOr(
    Schema.Literals(['indirect-call', 'indirect-jump', 'x87-access', 'stored-address']),
  ),
  pointsTo: Schema.OptionFromNullOr(Schema.Number),
  functions: Schema.Array(Schema.Number),
  references: Schema.Number,
});

export const GlobalsReportWire = Schema.Struct({
  subjectSha256: Schema.String,
  dataRegion: Schema.Array(
    Schema.Struct({ name: Schema.String, lo: Schema.Number, hi: Schema.Number }),
  ),
  references: Schema.Number,
  unconfirmedReferences: Schema.Number,
  globals: Schema.Number,
  byEvidence: Schema.Array(
    Schema.Struct({
      evidence: Schema.Literals([
        'proven-literal', 'library-symbol', 'decoded-literal', 'pointer-dword',
      ]),
      globals: Schema.Number,
    }),
  ),
  sized: Schema.Number,
  bySizeBasis: Schema.Array(
    Schema.Struct({
      basis: Schema.Literals([
        'library-section', 'library-next-symbol', 'pointer-run', 'access-width',
      ]),
      globals: Schema.Number,
    }),
  ),
  named: Schema.Number,
  holdsKnown: Schema.Array(
    Schema.Struct({
      holds: Schema.Literals(['code-pointer', 'data-pointer', 'float']),
      globals: Schema.Number,
    }),
  ),
  importSlotsSkipped: Schema.Number,
  deferrals: Schema.Array(
    Schema.Struct({
      what: Schema.Literals(['identity', 'size', 'name', 'holds']),
      addresses: Schema.Number,
    }),
  ),
  pointers: Schema.Array(
    Schema.Struct({
      target: Schema.Literals(['code', 'data']),
      enumerated: Schema.Number,
      attributed: Schema.Number,
    }),
  ),
  librarySymbols: Schema.Number,
  libraryRefusals: Schema.Array(
    Schema.Struct({ reason: Schema.String, count: Schema.Number }),
  ),
});

export const encodeGlobal = Schema.encodeUnknownSync(GlobalEntryWire);
export const encodeGlobals = Schema.encodeUnknownSync(GlobalsReportWire);
