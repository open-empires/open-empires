/**
 * Where a library object's sections sit in the subject, confirmed byte by
 * byte.
 *
 * `crt_identifications` names an address in the image and the library symbol
 * whose bytes are there. Subtracting the symbol's offset in its own section
 * gives a candidate base for that whole section, and the section's
 * non-relocated bytes must then match the image at that base -- so a
 * placement is never taken from the stored identification alone.
 *
 * This lives here, beside the COFF parser, because TWO derivations need the
 * same answer and a second copy of it would be free to disagree:
 *
 *   - import names read the `__imp_*` relocations of a placed section to
 *     learn which import slot each call site uses;
 *   - the globals inventory reads the remaining `Dir32` relocations of the
 *     same sections to learn the ADDRESS and NAME of the data each one
 *     touches.
 *
 * Nothing here decides what a relocation means. It establishes only that a
 * section's bytes are at an address, which is the premise both derivations
 * rest on.
 */
import { Option } from 'effect';
import {
  relocations,
  sections,
  symbols,
  type CoffRelocation,
  type CoffSection,
  type CoffSymbol,
} from './parse';

/** The subject's bytes, indexed from the address its first byte occupies.
 *  This is the WHOLE image: a section of a library object may be placed in
 *  code or in data, and a reader restricted to one span cannot confirm the
 *  other. */
export interface ImageBytes {
  readonly base: number;
  readonly bytes: Uint8Array;
}

/** One CRT symbol the matcher placed in the image, as recorded. */
export interface PlacedIdentification {
  readonly va: number;
  readonly symbol: string;
  readonly library: string;
  readonly member: string;
}

/** An archive member, parsed once. The symbol table and section table are
 *  carried because every consumer of a placement needs both and reparsing
 *  them per consumer is the same walk twice. */
export interface LibraryMember {
  readonly library: string;
  readonly member: string;
  readonly object: Uint8Array;
  readonly symbols: ReadonlyArray<CoffSymbol>;
  readonly symbolByIndex: ReadonlyMap<number, CoffSymbol>;
  readonly sections: ReadonlyArray<CoffSection>;
}

/** One object section, confirmed to sit at `base` in the image. */
export interface PlacedSection {
  readonly member: LibraryMember;
  readonly section: CoffSection;
  readonly base: number;
  readonly relocations: ReadonlyArray<CoffRelocation>;
}

/** A section that could not be placed, or could not be confirmed where it was
 *  proposed. Kept because a count answers "how many" and this answers "which
 *  one and why". */
export interface PlacementRefusal {
  readonly library: string;
  readonly member: string;
  readonly sectionIndex: number;
  readonly reason: string;
}

export interface Placements {
  readonly placed: ReadonlyArray<PlacedSection>;
  readonly refused: ReadonlyArray<PlacementRefusal>;
}

const hex = (value: number): string => `0x${(value >>> 0).toString(16)}`;

export const bytesAt = (
  image: ImageBytes,
  va: number,
  length: number,
): Option.Option<Uint8Array> => {
  const at = va - image.base;
  if (at < 0 || length < 0 || at + length > image.bytes.length) return Option.none();
  return Option.some(image.bytes.subarray(at, at + length));
};

/** The bytes each relocation patches. The linker chose them, so they are not
 *  part of what the object and the image must agree on. */
const patchedBytes = (entries: ReadonlyArray<CoffRelocation>): ReadonlySet<number> => {
  const patched = new Set<number>();
  for (const entry of entries) for (let k = 0; k < 4; k += 1) patched.add(entry.offset + k);
  return patched;
};

/**
 * Confirm that `section`'s own bytes are in the image at `base`.
 *
 * Returns the reason it is NOT there, or None when it is. A section with no
 * bytes in the object -- `.bss` -- cannot be confirmed at all, and saying so
 * is the answer rather than an absence.
 */
export const refusalForPlacement = (input: {
  readonly image: ImageBytes;
  readonly member: LibraryMember;
  readonly section: CoffSection;
  readonly base: number;
}): Option.Option<string> => {
  const { image, member, section, base } = input;
  if (section.data.length === 0) {
    return Option.some(
      `${section.name} holds no bytes in the object, so nothing can be confirmed at ` +
        `${hex(base)}`,
    );
  }
  const placed = bytesAt(image, base, section.data.length);
  if (Option.isNone(placed)) {
    return Option.some(
      `placed at ${hex(base)}..${hex(base + section.data.length)}, which leaves the image ` +
        `${hex(image.base)}..${hex(image.base + image.bytes.length)}`,
    );
  }
  const patched = patchedBytes(relocations(member.object, section));
  for (let k = 0; k < section.data.length; k += 1) {
    if (!patched.has(k) && placed.value[k] !== section.data[k]) {
      return Option.some(
        `the image at ${hex(base)} differs from the object at byte ${k} outside every ` +
          'relocation field, so it is not placed there',
      );
    }
  }
  return Option.none();
};

/** Parse every member of every library once, keyed by (library, member). */
export const openLibraries = (
  libraries: ReadonlyArray<{
    readonly path: string;
    readonly members: ReadonlyArray<{ readonly name: string; readonly body: Uint8Array }>;
  }>,
): ReadonlyMap<string, LibraryMember> => {
  const out = new Map<string, LibraryMember>();
  for (const library of libraries) {
    for (const member of library.members) {
      const key = memberKey(library.path, member.name);
      if (out.has(key)) continue;
      const parsed = symbols(member.body);
      out.set(key, {
        library: library.path,
        member: member.name,
        object: member.body,
        symbols: parsed,
        symbolByIndex: new Map(parsed.map((s) => [s.index, s])),
        sections: sections(member.body),
      });
    }
  }
  return out;
};

export const memberKey = (library: string, member: string): string => `${library}\u0000${member}`;

/**
 * Place the sections the identifications name.
 *
 * An identification fixes one section: the identified address less the
 * symbol's offset in the section it is defined in. Several identifications in
 * one section must agree on that base, and a section whose identifications
 * disagree is refused rather than resolved by a vote.
 */
export const placeIdentifiedSections = (input: {
  readonly identifications: ReadonlyArray<PlacedIdentification>;
  readonly members: ReadonlyMap<string, LibraryMember>;
  readonly image: ImageBytes;
}): Placements => {
  const placed: PlacedSection[] = [];
  const refused: PlacementRefusal[] = [];

  for (const [key, group] of groupByMember(input.identifications)) {
    const member = input.members.get(key);
    if (member === undefined) {
      const [library, name] = splitMemberKey(key);
      refused.push({
        library,
        member: name,
        sectionIndex: 0,
        reason: `no member named ${name} could be read from ${library}`,
      });
      continue;
    }
    const where = (sectionIndex: number, reason: string): void => {
      refused.push({ library: member.library, member: member.member, sectionIndex, reason });
    };

    const basesPerSection = new Map<number, Set<number>>();
    for (const identification of group) {
      const defining = member.symbols.find(
        (s) => s.name === identification.symbol && s.sectionNumber > 0,
      );
      if (defining === undefined) {
        where(
          0,
          `the member defines no section-relative symbol named ${identification.symbol}, so ` +
            `the identification at ${hex(identification.va)} fixes no placement`,
        );
        continue;
      }
      const bases = basesPerSection.get(defining.sectionNumber) ?? new Set<number>();
      bases.add(identification.va - defining.value);
      basesPerSection.set(defining.sectionNumber, bases);
    }

    for (const [sectionIndex, bases] of basesPerSection) {
      if (bases.size !== 1) {
        where(
          sectionIndex,
          `its identified symbols place it at ${[...bases].map(hex).join(' and ')}, so no one ` +
            'address is its placement',
        );
        continue;
      }
      const base = [...bases][0]!;
      const section = member.sections.find((s) => s.index === sectionIndex);
      if (section === undefined) {
        where(sectionIndex, 'the object has no section with that number');
        continue;
      }
      const refusal = refusalForPlacement({ image: input.image, member, section, base });
      if (Option.isSome(refusal)) {
        where(sectionIndex, refusal.value);
        continue;
      }
      placed.push({ member, section, base, relocations: relocations(member.object, section) });
    }
  }
  return { placed, refused };
};

const groupByMember = (
  identifications: ReadonlyArray<PlacedIdentification>,
): ReadonlyArray<readonly [string, ReadonlyArray<PlacedIdentification>]> => {
  const groups = new Map<string, PlacedIdentification[]>();
  for (const identification of identifications) {
    const key = memberKey(identification.library, identification.member);
    const existing = groups.get(key);
    if (existing === undefined) groups.set(key, [identification]);
    else existing.push(identification);
  }
  return [...groups.entries()];
};

const splitMemberKey = (key: string): readonly [string, string] => {
  const [library, member] = key.split('\u0000') as [string, string];
  return [library, member] as const;
};
