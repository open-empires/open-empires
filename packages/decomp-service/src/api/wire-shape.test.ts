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
import { AgentsWire } from './wire';

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
