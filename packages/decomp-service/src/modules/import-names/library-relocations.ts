import { Option } from 'effect';
import { RelocationType, relocations, sections, symbols } from '../../coff/parse';
import { archiveMembers } from '../subject/coff';
import type {
  LibraryImportReference,
  LibraryImportRefusal,
  ReferenceForm,
} from './interface';

/** A library object's own name for an imported symbol is prefixed with this. */
const IMPORT_PREFIX = '__imp_';

/** Opcode and ModRM occupy two bytes before the disp32 the linker patches, in
 *  every form that reads a 32-bit absolute address through `[disp32]`. */
const OPERAND_OFFSET = 2;

const hex = (value: number): string => `0x${(value >>> 0).toString(16)}`;

/**
 * The API name a decorated import symbol refers to.
 *
 * MSVC's decoration is mechanical, so this is a transformation and not a
 * guess: `_Name@N` is `__stdcall`, `@Name@N` is `__fastcall`, `_Name` is
 * `__cdecl`, and the loader resolves all three against the undecorated name.
 * A C++-mangled symbol (`?...`) encodes a type, not a Windows API, so it has
 * no undecorated form and is refused rather than approximated.
 */
export const undecorate = (decorated: string): Option.Option<string> => {
  if (!decorated.startsWith(IMPORT_PREFIX)) return Option.none();
  const inner = decorated.slice(IMPORT_PREFIX.length);
  if (inner.startsWith('?')) return Option.none();
  const name = inner.replace(/^[_@]/, '').replace(/@\d+$/, '');
  return /^[A-Za-z_][A-Za-z0-9_]*$/.test(name) ? Option.some(name) : Option.none();
};

/** Which instruction reads a slot through `[disp32]`, from the two bytes
 *  before the operand. A `mov r32, [disp32]` is `8B /r` with ModRM mod 00 and
 *  r/m 101, which is exactly `(modrm & 0xc7) === 0x05`. */
const formOf = (opcode: number, modrm: number): Option.Option<ReferenceForm> => {
  if (opcode === 0xff && modrm === 0x15) return Option.some('call-indirect');
  if (opcode === 0xff && modrm === 0x25) return Option.some('jmp-indirect');
  if (opcode === 0xff && modrm === 0x35) return Option.some('push-pointer');
  if (opcode === 0x8b && (modrm & 0xc7) === 0x05) return Option.some('load-pointer');
  return Option.none();
};

/** One CRT function the matcher placed in the image, as recorded. */
export interface PlacedIdentification {
  readonly va: number;
  readonly symbol: string;
  readonly library: string;
  readonly member: string;
}

export interface LibraryImportDerivation {
  readonly references: ReadonlyArray<LibraryImportReference>;
  readonly refusals: ReadonlyArray<LibraryImportRefusal>;
  readonly sectionsPlaced: number;
  /** `__imp_` relocations reached in placed sections. */
  readonly relocations: number;
}

/**
 * Read import slot names out of the libraries' own relocation tables.
 *
 * Each identification fixes where one library section sits in the image; the
 * section's non-relocated bytes are then confirmed against the image there,
 * so a placement is never taken from the stored row alone. Only then is the
 * section's relocation table read, and only a relocation whose own operand in
 * the IMAGE names a declared slot produces a reference.
 *
 * Every step that drops something records why it dropped it. A slot with no
 * name must be distinguishable from a slot whose name was refused.
 */
export const deriveLibraryImportReferences = (input: {
  readonly identifications: ReadonlyArray<PlacedIdentification>;
  readonly libraries: ReadonlyArray<{ readonly path: string; readonly bytes: Uint8Array }>;
  /** The image span the placements and call sites must fall inside. */
  readonly text: { readonly lo: number; readonly bytes: Uint8Array };
  /** Every address the subject's import descriptors declare as a slot. */
  readonly slots: ReadonlySet<number>;
}): LibraryImportDerivation => {
  const archives = new Map<string, ReadonlyMap<string, Uint8Array>>();
  for (const library of input.libraries) {
    const members = new Map<string, Uint8Array>();
    for (const member of archiveMembers(library.bytes)) {
      if (!members.has(member.name)) members.set(member.name, member.body);
    }
    archives.set(library.path, members);
  }

  const references = new Map<number, LibraryImportReference>();
  const refusals: LibraryImportRefusal[] = [];
  let sectionsPlaced = 0;
  let relocationsSeen = 0;

  const refuse = (
    where: { library: string; member: string; sectionIndex: number },
    reason: string,
    relocationOffset = -1,
    decorated = '',
  ): void => {
    refusals.push({ ...where, relocationOffset, decorated, reason });
  };

  for (const [key, group] of groupByMember(input.identifications)) {
    const { library, member } = key;
    const members = archives.get(library);
    if (members === undefined) {
      refuse({ library, member, sectionIndex: 0 }, `library ${library} could not be opened`);
      continue;
    }
    const object = members.get(member);
    if (object === undefined) {
      refuse({ library, member, sectionIndex: 0 }, `${library} holds no member named ${member}`);
      continue;
    }

    const objectSymbols = symbols(object);
    const symbolByIndex = new Map(objectSymbols.map((s) => [s.index, s]));
    const sectionByIndex = new Map(sections(object).map((s) => [s.index, s]));

    for (const [sectionIndex, placement] of placementsPerSection({
      group,
      objectSymbols,
      refuse: (reason, symbol) => refuse({ library, member, sectionIndex: 0 }, reason, -1, symbol),
    })) {
      const where = { library, member, sectionIndex };
      if (placement.bases.size !== 1) {
        refuse(
          where,
          `its identified symbols place it at ${[...placement.bases]
            .map(hex)
            .join(' and ')}, so no one address is its placement`,
        );
        continue;
      }
      const base = [...placement.bases][0]!;
      const section = sectionByIndex.get(sectionIndex);
      if (section === undefined || section.data.length === 0) {
        refuse(where, 'the section has no bytes in the object, so nothing can be confirmed');
        continue;
      }

      const placed = imageBytesAt(input.text, base, section.data.length);
      if (Option.isNone(placed)) {
        refuse(
          where,
          `placed at ${hex(base)}..${hex(base + section.data.length)}, which leaves the ` +
            `.text span ${hex(input.text.lo)}..${hex(input.text.lo + input.text.bytes.length)}`,
        );
        continue;
      }
      const patched = relocatedBytes(relocations(object, section));
      const differs = firstDifference(placed.value, section.data, patched);
      if (Option.isSome(differs)) {
        refuse(
          where,
          `the image at ${hex(base)} differs from the object at byte ` +
            `${differs.value} outside every relocation field, so it is not placed there`,
        );
        continue;
      }
      sectionsPlaced += 1;

      for (const relocation of relocations(object, section)) {
        const symbol = symbolByIndex.get(relocation.symbolIndex);
        if (symbol === undefined || !symbol.name.startsWith(IMPORT_PREFIX)) continue;
        relocationsSeen += 1;
        const reject = (reason: string): void =>
          refuse(where, reason, relocation.offset, symbol.name);

        if (relocation.type !== RelocationType.Dir32) {
          reject(
            `relocation type ${relocation.type} does not write an absolute address, ` +
              'so the four bytes it patches are not a slot',
          );
          continue;
        }
        const api = undecorate(symbol.name);
        if (Option.isNone(api)) {
          reject(`${symbol.name} has no undecorated Windows API name to read`);
          continue;
        }
        const site = base + relocation.offset - OPERAND_OFFSET;
        const instruction = imageBytesAt(input.text, site, OPERAND_OFFSET + 4);
        if (Option.isNone(instruction)) {
          reject(`the referencing instruction at ${hex(site)} leaves the .text span`);
          continue;
        }
        const bytes = instruction.value;
        const form = formOf(bytes[0]!, bytes[1]!);
        if (Option.isNone(form)) {
          reject(
            `the image at ${hex(site)} begins ${hex(bytes[0]!)} ${hex(bytes[1]!)}, which is ` +
              'not an instruction that reads a slot through [disp32]',
          );
          continue;
        }
        const slot = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(
          OPERAND_OFFSET,
          true,
        );
        if (!input.slots.has(slot)) {
          reject(
            `the operand at ${hex(site)} is ${hex(slot)}, which the subject's import ` +
              'descriptors do not declare as a slot',
          );
          continue;
        }
        const already = references.get(site);
        if (already !== undefined) {
          reject(
            `${already.member} already claims ${hex(site)} for ${already.decorated}, so the ` +
              'two placements cannot both be right',
          );
          continue;
        }
        references.set(site, {
          site,
          slot,
          api: api.value,
          decorated: symbol.name,
          library,
          member,
          sectionIndex,
          sectionBase: base,
          relocationOffset: relocation.offset,
          form: form.value,
        });
      }
    }
  }

  return {
    references: [...references.values()].sort((a, b) => a.slot - b.slot || a.site - b.site),
    refusals,
    sectionsPlaced,
    relocations: relocationsSeen,
  };
};

// ------------------------------------------------------------------ helpers

interface MemberKey {
  readonly library: string;
  readonly member: string;
}

const groupByMember = (
  identifications: ReadonlyArray<PlacedIdentification>,
): ReadonlyArray<readonly [MemberKey, ReadonlyArray<PlacedIdentification>]> => {
  const groups = new Map<string, PlacedIdentification[]>();
  for (const identification of identifications) {
    const key = `${identification.library}\u0000${identification.member}`;
    const existing = groups.get(key);
    if (existing === undefined) groups.set(key, [identification]);
    else existing.push(identification);
  }
  return [...groups.entries()].map(([key, group]) => {
    const [library, member] = key.split('\u0000') as [string, string];
    return [{ library, member }, group] as const;
  });
};

/**
 * Where each section of this object sits, from the identifications that name
 * symbols inside it: an identified address less the symbol's offset in its
 * section. Several identifications in one section must agree, and a section
 * whose identifications disagree is refused rather than resolved by a vote.
 */
const placementsPerSection = (input: {
  readonly group: ReadonlyArray<PlacedIdentification>;
  readonly objectSymbols: ReadonlyArray<{
    readonly name: string;
    readonly value: number;
    readonly sectionNumber: number;
  }>;
  readonly refuse: (reason: string, symbol: string) => void;
}): ReadonlyMap<number, { readonly bases: ReadonlySet<number> }> => {
  const perSection = new Map<number, Set<number>>();
  for (const identification of input.group) {
    const defining = input.objectSymbols.find(
      (s) => s.name === identification.symbol && s.sectionNumber > 0,
    );
    if (defining === undefined) {
      input.refuse(
        `the member defines no section-relative symbol named ${identification.symbol}, ` +
          `so the identification at ${hex(identification.va)} fixes no placement`,
        identification.symbol,
      );
      continue;
    }
    const bases = perSection.get(defining.sectionNumber) ?? new Set<number>();
    bases.add(identification.va - defining.value);
    perSection.set(defining.sectionNumber, bases);
  }
  return new Map([...perSection.entries()].map(([index, bases]) => [index, { bases }]));
};

/** The four bytes each relocation patches. The linker chose them, so they are
 *  not part of what the object and the image must agree on. */
const relocatedBytes = (
  entries: ReadonlyArray<{ readonly offset: number }>,
): ReadonlySet<number> => {
  const patched = new Set<number>();
  for (const entry of entries) for (let k = 0; k < 4; k += 1) patched.add(entry.offset + k);
  return patched;
};

const firstDifference = (
  placed: Uint8Array,
  object: Uint8Array,
  patched: ReadonlySet<number>,
): Option.Option<number> => {
  for (let k = 0; k < object.length; k += 1) {
    if (!patched.has(k) && placed[k] !== object[k]) return Option.some(k);
  }
  return Option.none();
};

const imageBytesAt = (
  text: { readonly lo: number; readonly bytes: Uint8Array },
  va: number,
  length: number,
): Option.Option<Uint8Array> => {
  const at = va - text.lo;
  if (at < 0 || at + length > text.bytes.length) return Option.none();
  return Option.some(text.bytes.subarray(at, at + length));
};
