import { Option } from 'effect';
import { LOCK_PAIR } from './references';
import { classOfName } from './strings';
import type {
  RecoveredName,
  StringReference,
  WithheldName,
} from './interface';

export interface Attribution {
  readonly names: ReadonlyArray<RecoveredName>;
  readonly withheld: ReadonlyArray<WithheldName>;
}

const hex = (va: number) => va.toString(16).toUpperCase().padStart(8, '0');

/**
 * Where a tag was pushed from, as a place rather than an address.
 *
 * Every site in a region the inventory attributes to no function is ONE place,
 * not one per site: the question is whether two different bodies push the same
 * tag, and an unattributed region is a body whose extent is unknown.
 */
const UNATTRIBUTED = 'an unattributed .text region';

const placeLabel = (place: Option.Option<number>) =>
  Option.match(place, { onNone: () => UNATTRIBUTED, onSome: hex });

const MULTIPLE_TAGS =
  'the function pushes more than one distinct tag, so these label sub-regions ' +
  "of one body and which one is the function's own name is not evidenced";

const pushedFromSeveralPlaces = (places: ReadonlyArray<string>) =>
  `the same tag is pushed from ${places.length} places (${places.join(', ')}), ` +
  'so it cannot be shown to name this one';

/**
 * Decide which strings name their containing function, and withhold the rest
 * with the reason.
 *
 * The two refusals are checked in this order because a function that pushes
 * several tags is a statement about THAT FUNCTION, while a tag pushed from
 * several places is a statement about the string: 0x005BF650 is both, and the
 * useful thing to tell its reader is that its own body carries three tags.
 */
export const attribute = (references: ReadonlyArray<StringReference>): Attribution => {
  const tags = references.filter((r) => r.role !== 'referenced-only');

  /** string -> the distinct places it is pushed as a tag from, by label. */
  const places = new Map<string, Map<string, Option.Option<number>>>();
  /** function -> the distinct strings it pushes as a tag. */
  const pushed = new Map<number, Set<string>>();
  for (const ref of tags) {
    const byLabel = places.get(ref.text) ?? new Map<string, Option.Option<number>>();
    byLabel.set(placeLabel(ref.containingFunction), ref.containingFunction);
    places.set(ref.text, byLabel);
    if (Option.isNone(ref.containingFunction)) continue;
    const mine = pushed.get(ref.containingFunction.value) ?? new Set<string>();
    mine.add(ref.text);
    pushed.set(ref.containingFunction.value, mine);
  }

  /** The places a tag is pushed from, by address, with the unattributed one
   *  last: it has no address to sort by and is the weakest of the set. */
  const orderedPlaces = (text: string): ReadonlyArray<string> =>
    [...(places.get(text) ?? new Map<string, Option.Option<number>>()).entries()]
      .sort(([, a], [, b]) =>
        Option.isNone(a) ? 1 : Option.isNone(b) ? -1 : a.value - b.value,
      )
      .map(([label]) => label);

  const inThisFunction = (va: number, text: string) =>
    tags.filter(
      (r) =>
        r.text === text &&
        Option.isSome(r.containingFunction) &&
        r.containingFunction.value === va,
    );

  const names: RecoveredName[] = [];
  const withheld: WithheldName[] = [];
  for (const va of [...pushed.keys()].sort((a, b) => a - b)) {
    const candidates = [...pushed.get(va)!].sort();
    if (candidates.length > 1) {
      withheld.push({ va, candidates, reason: MULTIPLE_TAGS });
      continue;
    }
    const name = candidates[0]!;
    const where = orderedPlaces(name);
    if (where.length > 1) {
      withheld.push({ va, candidates, reason: pushedFromSeveralPlaces(where) });
      continue;
    }
    const here = inThisFunction(va, name);
    names.push({
      va,
      name,
      className: classOfName(name),
      // The stronger pair wins where both carry the same tag: 14 (function,
      // tag) pairs are carried by both, and reporting those as the weaker
      // reading would understate evidence that is actually doubled.
      confidence: here.some(
        (r) => Option.isSome(r.consumer) && LOCK_PAIR.has(r.consumer.value),
      )
        ? 'lock-tag'
        : 'self-named-other',
      stringVa: here[0]!.stringVa,
      refSites: here.map((r) => r.site).sort((a, b) => a - b),
      surfaceMemberOffsets: [
        ...new Set(
          here.flatMap((r) =>
            Option.isNone(r.surface) ? [] : [r.surface.value.memberOffset],
          ),
        ),
      ].sort((a, b) => a - b),
    });
  }
  return { names, withheld };
};
