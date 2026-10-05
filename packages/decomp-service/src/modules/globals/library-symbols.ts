/**
 * Global names and sizes, read out of the CRT libraries' own relocation and
 * symbol tables.
 *
 * `crt_identifications` places 297 library symbols in the image by matching
 * the shipped LIBC.LIB objects against it byte for byte. A placed object's
 * relocation table then states, for every absolute field in it, WHICH SYMBOL
 * the linker wrote there -- and for data that is the name of a global, from
 * the library's own symbol table rather than from any shape of access.
 *
 * TWO ROUTES, AND WHY BOTH ARE NEEDED
 * -----------------------------------
 * `external-relocation`. The object refers to a symbol it does not define, so
 * the linker patched the symbol's final address into the field. Read the field
 * out of the image and the address is a fact. The library states the NAME;
 * nothing here states a size, so a size is looked up from whichever member of
 * the same libraries DEFINES that symbol.
 *
 * `placed-data-section`. The relocation names a symbol the object DOES define
 * -- a constant pool entry, a static table -- so `field - addend - offset` is
 * where that whole section landed. Confirm the section's bytes at that base
 * and every symbol it defines has both an address and a size, bounded by the
 * next symbol or by the section's end. This is the only route that produces
 * sizes directly, and it is how `_XcptActTab` is 120 bytes at 0x682670.
 *
 * THE ADDEND IS NOT OPTIONAL
 * --------------------------
 * A `Dir32` field holds `symbol + addend`, and the addend is whatever the
 * object had in those bytes. `_iob + 64` and `_iob + 32` are two references to
 * ONE global; read without subtracting the addend they are two globals at
 * addresses `_iob` does not occupy, and `_XcptActTab` appears at 0x682678
 * instead of 0x682670. Every address below is `field - addend`, and the
 * addend is stored so the subtraction is re-checkable.
 */
import { Option } from 'effect';
import { RelocationType, StorageClass, type CoffSection, type CoffSymbol } from '../../coff/parse';
import {
  bytesAt,
  openLibraries,
  placeIdentifiedSections,
  refusalForPlacement,
  type ImageBytes,
  type LibraryMember,
  type PlacedIdentification,
} from '../../coff/placement';
import type { LibrarySymbol, SizeBasis } from './interface';

/** An import symbol names an API, not a global; `import_slots` owns those. */
const IMPORT_PREFIX = '__imp_';

const hex = (value: number): string => `0x${(value >>> 0).toString(16)}`;

export interface LibrarySymbolRefusal {
  readonly library: string;
  readonly member: string;
  readonly sectionIndex: number;
  readonly relocationOffset: Option.Option<number>;
  readonly symbol: Option.Option<string>;
  readonly reason: string;
}

export interface LibrarySymbolDerivation {
  readonly symbols: ReadonlyArray<LibrarySymbol>;
  readonly refusals: ReadonlyArray<LibrarySymbolRefusal>;
  /** Code sections placed from the identifications, and data sections placed
   *  from the relocations found in them. */
  readonly sectionsPlaced: number;
  readonly dataSectionsPlaced: number;
  /** `Dir32` relocations examined, excluding the `__imp_` ones. */
  readonly relocations: number;
}

/**
 * A COFF section symbol -- storage class STATIC, value 0, named after its own
 * section -- is the section itself, not a variable in it. Admitting one puts
 * a global called `.data` at the first byte of every placed section and makes
 * it collide with the real symbol there.
 */
const isSectionSymbol = (symbol: CoffSymbol, section: CoffSection): boolean =>
  symbol.storageClass === StorageClass.Static &&
  symbol.value === 0 &&
  symbol.name === section.name;

const namesData = (symbol: CoffSymbol): boolean =>
  symbol.name !== '' && !symbol.name.startsWith(IMPORT_PREFIX);

/** Symbols a section defines, lowest offset first, with the section symbol
 *  dropped. */
const definedIn = (
  member: LibraryMember,
  section: CoffSection,
): ReadonlyArray<CoffSymbol> =>
  member.symbols
    .filter(
      (s) =>
        s.sectionNumber === section.index &&
        (s.storageClass === StorageClass.External || s.storageClass === StorageClass.Static) &&
        namesData(s) &&
        !isSectionSymbol(s, section),
    )
    .sort((a, b) => a.value - b.value);

/**
 * Every data symbol the two libraries DEFINE, with the size their own tables
 * state. Keyed by name, so an external reference resolved in the image can be
 * given a size without that section having to be placed.
 *
 * A name defined with two different sizes is dropped: the library itself does
 * not then say how big it is, and choosing one would be a guess dressed as a
 * fact.
 */
export const definedDataSizes = (
  members: ReadonlyMap<string, LibraryMember>,
): ReadonlyMap<string, { readonly size: number; readonly basis: SizeBasis }> => {
  const found = new Map<string, { size: number; basis: SizeBasis } | 'ambiguous'>();
  for (const member of members.values()) {
    for (const section of member.sections) {
      // A code section defines functions, and a function's size is the
      // inventory's answer, not this one's.
      if (section.name.startsWith('.text')) continue;
      const own = definedIn(member, section);
      for (let k = 0; k < own.length; k += 1) {
        const symbol = own[k]!;
        const next = own[k + 1]?.value ?? section.size;
        if (next <= symbol.value) continue;
        const entry = {
          size: next - symbol.value,
          // Alone in its section, the section's size IS its size. Otherwise
          // the gap to the next symbol may include alignment padding.
          basis: (own.length === 1 ? 'library-section' : 'library-next-symbol') as SizeBasis,
        };
        const already = found.get(symbol.name);
        if (already === undefined) found.set(symbol.name, entry);
        else if (already === 'ambiguous') continue;
        else if (already.size !== entry.size) found.set(symbol.name, 'ambiguous');
      }
    }
  }
  const out = new Map<string, { size: number; basis: SizeBasis }>();
  for (const [name, entry] of found) if (entry !== 'ambiguous') out.set(name, entry);
  return out;
};

/**
 * Name the globals the placed CRT objects refer to.
 *
 * `inDataRegion` decides what counts as data, from the subject's own section
 * flags: a relocation naming a function is a reference to code and belongs to
 * the function inventory, not here.
 */
export const deriveLibrarySymbols = (input: {
  readonly identifications: ReadonlyArray<PlacedIdentification>;
  readonly libraries: ReadonlyArray<{
    readonly path: string;
    readonly members: ReadonlyArray<{ readonly name: string; readonly body: Uint8Array }>;
  }>;
  readonly image: ImageBytes;
  readonly inDataRegion: (va: number) => boolean;
}): LibrarySymbolDerivation => {
  const members = openLibraries(input.libraries);
  const sizes = definedDataSizes(members);
  const placements = placeIdentifiedSections({
    identifications: input.identifications,
    members,
    image: input.image,
  });

  const symbols: LibrarySymbol[] = [];
  const refusals: LibrarySymbolRefusal[] = placements.refused.map((r) => ({
    library: r.library,
    member: r.member,
    sectionIndex: r.sectionIndex,
    relocationOffset: Option.none(),
    symbol: Option.none(),
    reason: r.reason,
  }));
  let relocations = 0;
  let dataSectionsPlaced = 0;

  /** Candidate bases for the data sections an object defines, discovered from
   *  the relocations of its placed code. */
  const dataBases = new Map<string, Map<number, Set<number>>>();

  for (const placement of placements.placed) {
    const { member, section, base } = placement;
    const reject = (
      reason: string,
      relocationOffset: Option.Option<number>,
      symbol: Option.Option<string>,
    ): void => {
      refusals.push({
        library: member.library,
        member: member.member,
        sectionIndex: section.index,
        relocationOffset,
        symbol,
        reason,
      });
    };

    for (const relocation of placement.relocations) {
      const symbol = member.symbolByIndex.get(relocation.symbolIndex);
      if (symbol === undefined) {
        reject(
          `relocation at ${relocation.offset} names symbol index ${relocation.symbolIndex}, ` +
            'which the object does not have',
          Option.some(relocation.offset),
          Option.none(),
        );
        continue;
      }
      // A REL32 relocation patches a displacement, not an address, and MSVC
      // uses it for direct calls. Those name code; skipping them is not a
      // refusal, there is simply no global in question.
      if (relocation.type !== RelocationType.Dir32) continue;
      if (!namesData(symbol)) continue;
      relocations += 1;

      const field = readDword(input.image, base + relocation.offset);
      if (Option.isNone(field)) {
        reject(
          `the field at ${hex(base + relocation.offset)} leaves the image`,
          Option.some(relocation.offset),
          Option.some(symbol.name),
        );
        continue;
      }
      const addend = readDword(
        { base: 0, bytes: section.data },
        relocation.offset,
      );
      if (Option.isNone(addend)) {
        reject(
          `the object's own four bytes at ${relocation.offset} are not in its section data, so ` +
            'the addend cannot be subtracted',
          Option.some(relocation.offset),
          Option.some(symbol.name),
        );
        continue;
      }
      const address = (field.value - addend.value) >>> 0;
      if (!input.inDataRegion(address)) {
        // Either a function (the inventory's answer) or outside every
        // section. Only the second is a refusal: there is no global there to
        // record and nothing downstream can use the row.
        if (!inAnySection(input.image, address)) {
          reject(
            `${symbol.name} resolves to ${hex(address)}, which is outside the image`,
            Option.some(relocation.offset),
            Option.some(symbol.name),
          );
        }
        continue;
      }

      if (symbol.sectionNumber > 0) {
        // The object defines it, so this fixes where that whole section sits.
        const perMember = dataBases.get(memberIdOf(member)) ?? new Map<number, Set<number>>();
        const bases = perMember.get(symbol.sectionNumber) ?? new Set<number>();
        bases.add((address - symbol.value) >>> 0);
        perMember.set(symbol.sectionNumber, bases);
        dataBases.set(memberIdOf(member), perMember);
        continue;
      }

      const known = sizes.get(symbol.name);
      symbols.push({
        address,
        name: symbol.name,
        library: member.library,
        member: member.member,
        route: 'external-relocation',
        sectionIndex: section.index,
        relocationOffset: Option.some(relocation.offset),
        fieldValue: Option.some(field.value),
        addend: Option.some(addend.value),
        offsetReached: addend.value,
        size: known === undefined ? Option.none() : Option.some(known.size),
        sizeBasis: known === undefined ? Option.none() : Option.some(known.basis),
      });
    }
  }

  // Confirm each discovered data-section placement and harvest its symbols.
  const byId = new Map([...members.values()].map((m) => [memberIdOf(m), m]));
  for (const [id, perSection] of dataBases) {
    const member = byId.get(id);
    if (member === undefined) continue;
    for (const [sectionIndex, bases] of perSection) {
      const section = member.sections.find((s) => s.index === sectionIndex);
      const reject = (reason: string): void => {
        refusals.push({
          library: member.library,
          member: member.member,
          sectionIndex,
          relocationOffset: Option.none(),
          symbol: Option.none(),
          reason,
        });
      };
      if (section === undefined) {
        reject('the object has no section with that number');
        continue;
      }
      if (bases.size !== 1) {
        reject(
          `relocations place ${section.name} at ${[...bases].map(hex).join(' and ')}, so no one ` +
            'address is its placement',
        );
        continue;
      }
      const base = [...bases][0]!;
      const refusal = refusalForPlacement({ image: input.image, member, section, base });
      if (Option.isSome(refusal)) {
        reject(refusal.value);
        continue;
      }
      dataSectionsPlaced += 1;
      const own = definedIn(member, section);
      for (let k = 0; k < own.length; k += 1) {
        const symbol = own[k]!;
        const next = own[k + 1]?.value ?? section.size;
        const address = base + symbol.value;
        if (!input.inDataRegion(address)) continue;
        symbols.push({
          address,
          name: symbol.name,
          library: member.library,
          member: member.member,
          route: 'placed-data-section',
          sectionIndex,
          relocationOffset: Option.none(),
          fieldValue: Option.none(),
          addend: Option.none(),
          offsetReached: 0,
          size: next > symbol.value ? Option.some(next - symbol.value) : Option.none(),
          sizeBasis: Option.some(own.length === 1 ? 'library-section' : 'library-next-symbol'),
        });
      }
    }
  }

  return {
    symbols: symbols.sort((a, b) => a.address - b.address || a.name.localeCompare(b.name)),
    refusals,
    sectionsPlaced: placements.placed.length,
    dataSectionsPlaced,
    relocations,
  };
};

const memberIdOf = (member: LibraryMember): string => `${member.library}\u0000${member.member}`;

const readDword = (image: ImageBytes, va: number): Option.Option<number> => {
  const four = bytesAt(image, va, 4);
  if (Option.isNone(four)) return Option.none();
  return Option.some(
    new DataView(four.value.buffer, four.value.byteOffset, four.value.byteLength).getUint32(
      0,
      true,
    ),
  );
};

const inAnySection = (image: ImageBytes, va: number): boolean =>
  va >= image.base && va < image.base + image.bytes.length;
