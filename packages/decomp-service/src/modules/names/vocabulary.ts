import { Option } from 'effect';
import { classOfName } from './strings';
import type {
  NameClass,
  RecoveredName,
  StringReference,
  SurfaceCorroboration,
} from './interface';

/**
 * The classes the strings describe, and the independent check on them.
 *
 * A method seen only as a string is still vocabulary: it says the class HAS
 * that method even where no address can be shown to be it. Five classes are
 * known this way and nothing else -- dropping them would lose the only record
 * that those methods exist.
 */
export const classesOf = (
  references: ReadonlyArray<StringReference>,
  names: ReadonlyArray<RecoveredName>,
): ReadonlyArray<NameClass> => {
  const methods = new Map<string, Set<string>>();
  const surfaces = new Map<string, Set<number>>();
  for (const ref of references) {
    const className = classOfName(ref.text);
    if (Option.isNone(className)) continue;
    const seen = methods.get(className.value) ?? new Set<string>();
    seen.add(ref.text);
    methods.set(className.value, seen);
    if (ref.role === 'referenced-only' || Option.isNone(ref.surface)) continue;
    const offsets = surfaces.get(className.value) ?? new Set<number>();
    offsets.add(ref.surface.value.memberOffset);
    surfaces.set(className.value, offsets);
  }
  const named = new Map<string, { readonly va: number; readonly name: string }[]>();
  for (const n of names) {
    if (Option.isNone(n.className)) continue;
    const list = named.get(n.className.value) ?? [];
    list.push({ va: n.va, name: n.name });
    named.set(n.className.value, list);
  }
  return [...methods.keys()]
    .sort()
    .map((className) => ({
      className,
      methodsSeen: [...methods.get(className)!].sort(),
      namedFunctions: (named.get(className) ?? []).sort((a, b) => a.va - b.va),
      surfaceMemberOffsets: [...(surfaces.get(className) ?? new Set<number>())].sort(
        (a, b) => a - b,
      ),
    }));
};

/**
 * How well the classes agree about where their locked surface lives.
 *
 * The common member is DERIVED as the most frequent one rather than written
 * down. Writing `0x20` into this file would make the corroboration circular:
 * the whole point is that an offset recurs across classes whose names share no
 * prefix and whose offsets were read independently of one another.
 */
export const corroborate = (
  classes: ReadonlyArray<NameClass>,
): SurfaceCorroboration => {
  const withSurface = classes.filter((c) => c.surfaceMemberOffsets.length > 0);
  const frequency = new Map<number, number>();
  for (const c of withSurface) {
    for (const offset of c.surfaceMemberOffsets) {
      frequency.set(offset, (frequency.get(offset) ?? 0) + 1);
    }
  }
  const common = [...frequency.entries()].sort((a, b) => b[1] - a[1])[0];
  const commonMemberOffset =
    common === undefined ? Option.none<number>() : Option.some(common[0]);
  const agrees = (c: NameClass) =>
    Option.isSome(commonMemberOffset) &&
    c.surfaceMemberOffsets.includes(commonMemberOffset.value);
  return {
    classes: classes.length,
    withObservedSurface: withSurface.length,
    commonMemberOffset,
    agreeing: withSurface.filter(agrees).length,
    contradicting: withSurface
      .filter((c) => !agrees(c))
      .map((c) => ({ className: c.className, memberOffsets: c.surfaceMemberOffsets })),
    withoutObservedSurface: classes
      .filter((c) => c.surfaceMemberOffsets.length === 0)
      .map((c) => c.className),
  };
};
