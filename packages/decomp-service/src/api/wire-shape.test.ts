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
import { AgentsWire, SweepReportWire } from './wire';

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
