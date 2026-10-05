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
      offConfiguration: Schema.Boolean,
    }),
  ),
  matched: Schema.Array(Schema.String),
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
