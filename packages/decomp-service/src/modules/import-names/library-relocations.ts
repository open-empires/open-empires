import { Option } from 'effect';
import { RelocationType } from '../../coff/parse';
import {
  bytesAt,
  openLibraries,
  placeIdentifiedSections,
  type ImageBytes,
  type PlacedIdentification,
} from '../../coff/placement';
import { archiveMembers } from '../subject/coff';
import type {
  LibraryImportReference,
  LibraryImportRefusal,
  ReferenceForm,
} from './interface';

export type { PlacedIdentification } from '../../coff/placement';

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
 * The placement step is shared with the globals inventory and lives in
 * `coff/placement`: each identification fixes where one library section sits,
 * and the section's non-relocated bytes are confirmed against the image
 * there, so a placement is never taken from the stored row alone. Only a
 * relocation whose own operand in the IMAGE names a declared slot produces a
 * reference.
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
  const image: ImageBytes = { base: input.text.lo, bytes: input.text.bytes };
  const members = openLibraries(
    input.libraries.map((library) => ({
      path: library.path,
      members: [...archiveMembers(library.bytes)],
    })),
  );
  const placements = placeIdentifiedSections({
    identifications: input.identifications,
    members,
    image,
  });

  const references = new Map<number, LibraryImportReference>();
  const refusals: LibraryImportRefusal[] = placements.refused.map((r) => ({
    library: r.library,
    member: r.member,
    sectionIndex: r.sectionIndex,
    relocationOffset: -1,
    decorated: '',
    reason: r.reason,
  }));
  let relocationsSeen = 0;

  for (const placement of placements.placed) {
    const { member, section, base } = placement;
    const where = { library: member.library, member: member.member, sectionIndex: section.index };
    for (const relocation of placement.relocations) {
      const symbol = member.symbolByIndex.get(relocation.symbolIndex);
      if (symbol === undefined || !symbol.name.startsWith(IMPORT_PREFIX)) continue;
      relocationsSeen += 1;
      const reject = (reason: string): void => {
        refusals.push({
          ...where,
          relocationOffset: relocation.offset,
          decorated: symbol.name,
          reason,
        });
      };

      if (relocation.type !== RelocationType.Dir32) {
        reject(
          `relocation type ${relocation.type} does not write an absolute address, so the four ` +
            'bytes it patches are not a slot',
        );
        continue;
      }
      const api = undecorate(symbol.name);
      if (Option.isNone(api)) {
        reject(`${symbol.name} has no undecorated Windows API name to read`);
        continue;
      }
      const site = base + relocation.offset - OPERAND_OFFSET;
      const instruction = bytesAt(image, site, OPERAND_OFFSET + 4);
      if (Option.isNone(instruction)) {
        reject(`the referencing instruction at ${hex(site)} leaves the .text span`);
        continue;
      }
      const bytes = instruction.value;
      const form = formOf(bytes[0]!, bytes[1]!);
      if (Option.isNone(form)) {
        reject(
          `the image at ${hex(site)} begins ${hex(bytes[0]!)} ${hex(bytes[1]!)}, which is not ` +
            'an instruction that reads a slot through [disp32]',
        );
        continue;
      }
      const slot = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(
        OPERAND_OFFSET,
        true,
      );
      if (!input.slots.has(slot)) {
        reject(
          `the operand at ${hex(site)} is ${hex(slot)}, which the subject's import descriptors ` +
            'do not declare as a slot',
        );
        continue;
      }
      const already = references.get(site);
      if (already !== undefined) {
        reject(
          `${already.member} already claims ${hex(site)} for ${already.decorated}, so the two ` +
            'placements cannot both be right',
        );
        continue;
      }
      references.set(site, {
        site,
        slot,
        api: api.value,
        decorated: symbol.name,
        library: member.library,
        member: member.member,
        sectionIndex: section.index,
        sectionBase: base,
        relocationOffset: relocation.offset,
        form: form.value,
      });
    }
  }

  return {
    references: [...references.values()].sort((a, b) => a.slot - b.slot || a.site - b.site),
    refusals,
    sectionsPlaced: placements.placed.length,
    relocations: relocationsSeen,
  };
};
