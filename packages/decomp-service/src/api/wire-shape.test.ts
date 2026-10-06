/**
 * Which fields arrive as plain values and which as Option wrappers.
 *
 * Two shapes reach the dashboard. `Schema.OptionFromNullOr` puts the value or
 * null straight on the wire, while an `Option` encoded as itself arrives as
 * `{_tag: 'Some', value}`. The page has one helper for the second shape, and
 * applying it to the first returns undefined for everything.
 *
 * That is not hypothetical: the agents table showed a dash in its "doing"
 * column for every row while the agents were reporting perfectly well, because
 * `doing` is `OptionFromNullOr` and was being read as a wrapper. It passed a
 * contract check I wrote at the time, because that check read the fields
 * DIRECTLY rather than through the expression the component uses -- the
 * harness has to exercise the path, not an equivalent one.
 *
 * So the shape is asserted here, on the producing side, where it is decided.
 */
import { expect, test } from 'bun:test';
import { Option, Schema } from 'effect';
import { AgentsWire, ProbeReportWire, SweepReportWire, VerdictWire } from './wire';

const encodeAgents = Schema.encodeUnknownSync(AgentsWire);

const one = (over: Record<string, unknown> = {}) =>
  encodeAgents([
    {
      id: 'probe',
      role: Option.some('a role'),
      started: 1,
      lastBeat: 2,
      beats: 3,
      finished: Option.none(),
      note: Option.none(),
      doing: Option.some('what it is doing'),
      doingAt: Option.some(4),
      state: 'live',
      silentFor: Option.some(5),
      ...over,
    },
  ])[0] as Record<string, unknown>;

test('an agent row carries plain values, not Option wrappers', () => {
  const row = one();
  // The dashboard reads each of these as `a.field ?? fallback`. If any became
  // a wrapper, that expression would silently render the wrapper or a dash.
  expect(row.doing).toBe('what it is doing');
  expect(row.role).toBe('a role');
  expect(row.doingAt).toBe(4);
  expect(row.silentFor).toBe(5);
  expect(typeof row.doing).toBe('string');
  expect(typeof row.doingAt).toBe('number');
});

test('absent values are null, which is what the page falls back from', () => {
  const row = one({ doing: Option.none(), doingAt: Option.none(), role: Option.none() });
  expect(row.doing).toBeNull();
  expect(row.doingAt).toBeNull();
  expect(row.role).toBeNull();
});

test('no agent field is an Option wrapper', () => {
  // Stated as a property rather than field by field, so a field added later
  // is covered without anyone remembering to add a case.
  const row = one();
  for (const [name, value] of Object.entries(row)) {
    const wrapped =
      typeof value === 'object' && value !== null && '_tag' in (value as object);
    expect(wrapped, `${name} arrived as an Option wrapper`).toBe(false);
  }
});

/**
 * A sweep's per-flag-set digest, which is what makes "these flag sets emit the
 * same bytes" checkable.
 *
 * The claim that eight of fourteen flag sets gave byte-identical output was
 * recorded from `emittedSize` and `firstDiff` alone, and those two numbers
 * cannot establish it: two different codegens can agree on length and on the
 * offset of their first difference from the subject while differing from each
 * other. The digest is the field that settles it, so it has to reach the wire
 * as a plain string -- read as an Option wrapper it would compare unequal for
 * every pair and quietly invert the finding.
 */
const encodeSweepReport = Schema.encodeUnknownSync(SweepReportWire);

const sweepOutcome = (over: Record<string, unknown> = {}) =>
  (
    encodeSweepReport({
      va: 0x401000,
      size: 16,
      outcomes: [
        {
          flags: '/O2 /GX /GR-',
          compiled: true,
          exact: false,
          matchedAtEntry: false,
          emittedSize: Option.some(16),
          masked: Option.some(0),
          firstDiff: Option.some(4),
          detail: Option.none(),
          emittedSha: Option.some('a'.repeat(64)),
          offConfiguration: false,
          ...over,
        },
      ],
      matched: [],
      finding: false,
    }) as { outcomes: ReadonlyArray<Record<string, unknown>> }
  ).outcomes[0]!;

test('a sweep outcome carries its emitted digest as a plain string', () => {
  const o = sweepOutcome();
  expect(o.emittedSha).toBe('a'.repeat(64));
  expect(typeof o.emittedSha).toBe('string');
});

test('an outcome that compiled nothing reports a null digest, not a wrapper', () => {
  const o = sweepOutcome({ compiled: false, emittedSha: Option.none(), emittedSize: Option.none() });
  expect(o.emittedSha).toBeNull();
});

test('two outcomes are comparable for identical codegen by digest alone', () => {
  // The property the finding needed and did not have: equal digests mean equal
  // bytes, and equal size plus equal firstDiff does NOT.
  const a = sweepOutcome({ emittedSha: Option.some('a'.repeat(64)) });
  const b = sweepOutcome({ emittedSha: Option.some('b'.repeat(64)) });
  expect(a.emittedSize).toBe(b.emittedSize);
  expect(a.firstDiff).toBe(b.firstDiff);
  expect(a.emittedSha).not.toBe(b.emittedSha);
});

test('no sweep outcome field is an Option wrapper', () => {
  for (const [name, value] of Object.entries(sweepOutcome())) {
    const wrapped =
      typeof value === 'object' && value !== null && '_tag' in (value as object);
    expect(wrapped, `${name} arrived as an Option wrapper`).toBe(false);
  }
});

/**
 * A probe groups source spellings by the bytes they emitted, and the group is
 * the answer. If `identical` or the digests inside it arrived wrapped, a
 * reader would see every spelling as its own group and conclude that an inert
 * axis mattered -- the opposite of what the field exists to say.
 */
const encodeProbeReport = Schema.encodeUnknownSync(ProbeReportWire);

test('a probe reports its groups and digests as plain values', () => {
  const r = encodeProbeReport({
    va: 0x401000,
    size: 8,
    flags: '/O2 /GX /GR-',
    outcomes: [
      {
        index: 0, compiled: true, exact: true, matchedAt: Option.some(0),
        emittedSize: Option.some(16), masked: Option.some(0),
        firstDiff: Option.none(), emittedSha: Option.some('a'.repeat(64)),
        differingBytes: Option.some(0), differingOffsets: [],
        detail: Option.none(),
      },
      {
        index: 1, compiled: false, exact: false, matchedAt: Option.none(),
        emittedSize: Option.none(), masked: Option.none(),
        firstDiff: Option.none(), emittedSha: Option.none(),
        differingBytes: Option.none(), differingOffsets: [],
        detail: Option.some("error C2065: 'q' : undeclared identifier"),
      },
    ],
    matched: [0],
    identical: [{ emittedSha: 'a'.repeat(64), indices: [0] }],
  }) as {
    identical: ReadonlyArray<Record<string, unknown>>;
    outcomes: ReadonlyArray<Record<string, unknown>>;
  };
  expect(r.identical[0]!.emittedSha).toBe('a'.repeat(64));
  expect(r.identical[0]!.indices).toEqual([0]);
  // A spelling the compiler rejected is an OUTCOME carrying the diagnostic,
  // never a failed request: a probe exists to be given sources that may be
  // wrong, so one bad one must not discard the rest.
  expect(r.outcomes[1]!.compiled).toBe(false);
  expect(r.outcomes[1]!.emittedSha).toBeNull();
  // The count the guide tells agents to steer by reaches a probe outcome, and
  // is null rather than 0 when nothing compiled -- 0 would read as "identical".
  expect(r.outcomes[0]!.differingBytes).toBe(0);
  expect(r.outcomes[1]!.differingBytes).toBeNull();
  expect(String(r.outcomes[1]!.detail)).toContain('C2065');
});

/**
 * `exact` on a verdict is already "byte-exact AND at the entry". `matchedAt`
 * is beside it so the middle case is visible: bytes that matched at a
 * non-zero offset are a fragment match, which is a weaker and different
 * claim, and used to arrive as a bare `exact: false` that looked exactly like
 * matching nothing.
 */
const encodeVerdictWire = Schema.encodeUnknownSync(VerdictWire);

const verdict = (over: Record<string, unknown> = {}) =>
  encodeVerdictWire({
    exact: false, compiled: true, matchedAt: Option.some(2),
    emittedSize: Option.some(16), masked: Option.some(0), compared: Option.some(8),
    firstDiff: Option.none(), detail: Option.none(), weak: false,
    ...over,
  }) as Record<string, unknown>;

test('a fragment match is distinguishable from no match at all', () => {
  expect(verdict().matchedAt).toBe(2);
  expect(verdict().exact).toBe(false);
  expect(verdict({ matchedAt: Option.none() }).matchedAt).toBeNull();
  // The entry match, which is the only one that may be read as a proof.
  expect(verdict({ exact: true, matchedAt: Option.some(0) }).matchedAt).toBe(0);
});

test('no verdict field is an Option wrapper', () => {
  for (const [name, value] of Object.entries(verdict())) {
    const wrapped =
      typeof value === 'object' && value !== null && '_tag' in (value as object);
    expect(wrapped, `${name} arrived as an Option wrapper`).toBe(false);
  }
});
