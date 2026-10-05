import { Option, Result } from 'effect';
import {
  SubjectParseError,
  type CompIdRecord,
  type RichHeader,
  type Section,
} from './interface';

const LATIN1 = new TextDecoder('latin1');

const SECTION_HEADER_SIZE = 40;
const IMPORT_DESCRIPTOR_SIZE = 20;
const PE32_MAGIC = 0x10b;
/** "DanS", the Rich header's own start marker, stored XORed with the key. */
const DANS = 0x536e6144;
const RICH = 0x68636952;

const fail = (what: string, reason: string) =>
  Result.fail(new SubjectParseError({ what, reason }));

/** A PE image laid out as the loader would map it, read from a flat file. */
export interface PeImage {
  readonly bytes: Uint8Array;
  readonly view: DataView;
  readonly imageBase: number;
  readonly sections: ReadonlyArray<Section>;
  readonly importDirectoryRva: number;
}

export const parsePeImage = (bytes: Uint8Array): Result.Result<PeImage, SubjectParseError> => {
  if (bytes.length < 0x40 || bytes[0] !== 0x4d || bytes[1] !== 0x5a) {
    return fail('PE image', 'no MZ signature');
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const nt = view.getUint32(0x3c, true);
  if (nt + 24 > bytes.length || view.getUint32(nt, true) !== 0x00004550) {
    return fail('PE image', `no PE signature at ${nt.toString(16)}`);
  }
  const sectionCount = view.getUint16(nt + 6, true);
  const optionalHeaderSize = view.getUint16(nt + 20, true);
  const optional = nt + 24;
  const magic = view.getUint16(optional, true);
  if (magic !== PE32_MAGIC) {
    return fail('PE image', `optional header magic 0x${magic.toString(16)} is not PE32`);
  }
  const imageBase = view.getUint32(optional + 28, true);
  const importDirectoryRva = view.getUint32(optional + 96 + 8, true);
  const sections: Section[] = [];
  for (let i = 0; i < sectionCount; i++) {
    const o = optional + optionalHeaderSize + i * SECTION_HEADER_SIZE;
    if (o + SECTION_HEADER_SIZE > bytes.length) {
      return fail('PE image', `section header ${i} runs past the end of the file`);
    }
    sections.push({
      name: LATIN1.decode(bytes.subarray(o, o + 8)).replace(/\0+$/, ''),
      va: imageBase + view.getUint32(o + 12, true),
      virtualSize: view.getUint32(o + 8, true),
      rawOffset: view.getUint32(o + 20, true),
      rawSize: view.getUint32(o + 16, true),
      characteristics: view.getUint32(o + 36, true),
    });
  }
  return Result.succeed({ bytes, view, imageBase, sections, importDirectoryRva });
};

/**
 * The section bounds `.text` declares. Derived from the header rather than
 * from how far the known functions reach, so an address in the tail of .text
 * is still .text.
 */
export const textSpan = (
  image: PeImage,
): Result.Result<{ readonly lo: number; readonly hi: number }, SubjectParseError> => {
  const text = image.sections.find((s) => s.name === '.text');
  if (text === undefined) return fail('PE image', 'no .text section');
  return Result.succeed({ lo: text.va, hi: text.va + text.virtualSize });
};

/**
 * Is this file a MEMORY image rather than an on-disk PE?
 *
 * It decides how a virtual address maps to a file offset, and getting it
 * wrong reads the wrong bytes without failing. A loaded image has each
 * section at its RVA, so the offset is `va - imageBase`. An on-disk PE packs
 * them at their raw offsets, which are smaller because uninitialised data and
 * page padding are not stored.
 *
 * The file states which it is: a memory image spans the whole virtual image,
 * while a PE on disk stops at the end of its raw data. For this subject the
 * file is 0x3a5000 bytes, exactly the page-aligned virtual span of 0x3a4866,
 * and the raw data ends at 0x293000 -- 1.1MB short.
 *
 * This mattered because the two mappings AGREE for the first four sections of
 * this subject and disagree by 0x112000 for the last three, so reads from
 * .text, THIS_COD, .rdata and .data were correct and nothing suggested a
 * problem. Reads from THIS_DAT, Inf32Dat and .rsrc landed in a zero-filled
 * region and returned zeros: at 0x7a1000 the real bytes are a resource
 * directory -- 3 named and 3 id entries -- and the reader handed back 48
 * zeros instead. A reader that cannot fail fabricates data, and zeros are
 * the most plausible-looking fabrication there is.
 */
const isMemoryImage = (image: PeImage): boolean => {
  const span = image.sections.reduce(
    (hi, s) => Math.max(hi, s.va + s.virtualSize),
    0,
  ) - image.imageBase;
  if (span <= 0) return false;
  return image.bytes.length >= ((span + 0xfff) & ~0xfff);
};

/**
 * Where a virtual address sits in the file. `max(virtualSize, rawSize)`
 * because a section may declare less raw data than it occupies in memory, and
 * the structures read through this live in the overlap.
 *
 * ONE answer per image, chosen from the image: `va - imageBase` for a memory
 * image, the section's raw offset for a PE on disk. The disassembler and the
 * globals derivation both already read this subject as `va - imageBase`, so
 * before this there were two mappings in the codebase that disagreed about
 * three sections, and which one you got depended on which module you asked.
 */
export const fileOffsetOfVa = (image: PeImage, va: number): Option.Option<number> => {
  const flat = isMemoryImage(image);
  for (const s of image.sections) {
    if (va >= s.va && va < s.va + Math.max(s.virtualSize, s.rawSize)) {
      return Option.some(
        flat ? va - image.imageBase : s.rawOffset + (va - s.va),
      );
    }
  }
  return Option.none();
};

export const bytesAtVa = (
  image: PeImage,
  va: number,
  length: number,
): Option.Option<Uint8Array> => {
  const start = fileOffsetOfVa(image, va);
  if (Option.isNone(start)) return Option.none();
  if (start.value + length > image.bytes.length) return Option.none();
  return Option.some(image.bytes.slice(start.value, start.value + length));
};

const cstringAt = (bytes: Uint8Array, offset: number): Option.Option<string> => {
  if (offset < 0 || offset >= bytes.length) return Option.none();
  const end = bytes.indexOf(0, offset);
  if (end < 0) return Option.none();
  return Option.some(LATIN1.decode(bytes.subarray(offset, end)));
};

// ------------------------------------------------------------- Rich header

/**
 * The `@comp.id` records the linker stamps into the DOS stub: one per tool
 * that contributed object files, with how many it contributed.
 *
 * This is the only measurement of which compiler builds produced the subject,
 * and it is what separates code we can reproduce from code we cannot: a build
 * number read here is a fact about the bytes, where "linker 6.0" is not
 * specific enough to act on.
 */
export const parseRichHeader = (
  bytes: Uint8Array,
): Result.Result<RichHeader, SubjectParseError> => {
  if (bytes.length < 0x40) return fail('Rich header', 'file is shorter than a DOS header');
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const stubEnd = Math.min(view.getUint32(0x3c, true), bytes.length - 8);
  let richOffset = -1;
  for (let i = 0x40; i <= stubEnd - 8; i++) {
    if (view.getUint32(i, true) === RICH) {
      richOffset = i;
      break;
    }
  }
  if (richOffset < 0) return fail('Rich header', 'no "Rich" marker in the DOS stub');
  const xorKey = view.getUint32(richOffset + 4, true);
  const encodedDans = (DANS ^ xorKey) >>> 0;
  let dansOffset = -1;
  for (let i = 0x40; i + 16 <= richOffset; i += 4) {
    if (view.getUint32(i, true) === encodedDans) {
      dansOffset = i;
      break;
    }
  }
  if (dansOffset < 0) {
    return fail(
      'Rich header',
      `"Rich" at ${richOffset.toString(16)} keys on 0x${xorKey.toString(16)}, but no ` +
        '"DanS" encoded with that key precedes it',
    );
  }
  const first = dansOffset + 16;
  if ((richOffset - first) % 8 !== 0) {
    return fail(
      'Rich header',
      `${richOffset - first} bytes of records between "DanS" and "Rich" is not a ` +
        'whole number of 8-byte entries',
    );
  }
  const records: CompIdRecord[] = [];
  for (let o = first, index = 0; o < richOffset; o += 8, index++) {
    const compId = (view.getUint32(o, true) ^ xorKey) >>> 0;
    const objects = (view.getUint32(o + 4, true) ^ xorKey) >>> 0;
    records.push({
      index,
      compId,
      prodId: compId >>> 16,
      build: compId & 0xffff,
      objects,
    });
  }
  return Result.succeed({ dansOffset, richOffset, xorKey, records });
};

// --------------------------------------------------------- import descriptors

/** One IAT slot the image's own import directory declares. */
export interface DeclaredImportSlot {
  readonly va: number;
  readonly dll: string;
  /**
   * The name the descriptor still carries. Absent where OriginalFirstThunk is
   * zero: the loader read those names out of the import table and overwrote
   * them in place with resolved addresses, destroying the only copy.
   */
  readonly descriptorName: Option.Option<string>;
  readonly descriptorOrdinal: Option.Option<number>;
}

export const parseImportSlots = (
  image: PeImage,
): Result.Result<ReadonlyArray<DeclaredImportSlot>, SubjectParseError> => {
  const { view, imageBase } = image;
  const at = (rva: number, what: string): Result.Result<number, SubjectParseError> =>
    Result.fromOption(
      fileOffsetOfVa(image, imageBase + rva),
      () => new SubjectParseError({ what, reason: `rva 0x${rva.toString(16)} is in no section` }),
    );

  return Result.gen(function* () {
    let descriptor = yield* at(image.importDirectoryRva, 'import directory');
    const slots: DeclaredImportSlot[] = [];
    for (;;) {
      const originalFirstThunk = view.getUint32(descriptor, true);
      const nameRva = view.getUint32(descriptor + 12, true);
      const firstThunk = view.getUint32(descriptor + 16, true);
      if (originalFirstThunk === 0 && nameRva === 0 && firstThunk === 0) break;
      const nameOffset = yield* at(nameRva, 'import descriptor name');
      const dll = yield* Result.fromOption(
        cstringAt(image.bytes, nameOffset),
        () =>
          new SubjectParseError({
            what: 'import descriptor name',
            reason: `no NUL-terminated name at rva 0x${nameRva.toString(16)}`,
          }),
      );
      const thunks = yield* at(firstThunk, `${dll} thunk array`);
      const hints = originalFirstThunk === 0
        ? Option.none<number>()
        : Option.some(yield* at(originalFirstThunk, `${dll} hint array`));
      for (let i = 0; view.getUint32(thunks + 4 * i, true) !== 0; i++) {
        let descriptorName = Option.none<string>();
        let descriptorOrdinal = Option.none<number>();
        if (Option.isSome(hints)) {
          const hint = view.getUint32(hints.value + 4 * i, true);
          if ((hint & 0x80000000) !== 0) {
            descriptorOrdinal = Option.some(hint & 0xffff);
          } else {
            const hintOffset = yield* at((hint & 0x7fffffff) >>> 0, `${dll} hint name`);
            descriptorName = cstringAt(image.bytes, hintOffset + 2);
          }
        }
        slots.push({
          va: imageBase + firstThunk + 4 * i,
          dll,
          descriptorName,
          descriptorOrdinal,
        });
      }
      descriptor += IMPORT_DESCRIPTOR_SIZE;
    }
    return slots satisfies ReadonlyArray<DeclaredImportSlot>;
  });
};

/**
 * The slot a six-byte `call dword ptr [disp32]` at `callSite` reads.
 *
 * SafeDisc stores the game's return address minus six, which lands exactly on
 * that form's opcode, so the operand can be read back and compared with the
 * record's own slot. For a two-byte `call reg` it lands inside earlier
 * instructions and there is nothing to check -- absent, not a failure.
 */
export const callSiteSlotOperand = (
  image: PeImage,
  callSite: number,
): Option.Option<number> => {
  const start = fileOffsetOfVa(image, callSite);
  if (Option.isNone(start) || start.value + 6 > image.bytes.length) return Option.none();
  const o = start.value;
  if (image.bytes[o] !== 0xff || image.bytes[o + 1] !== 0x15) return Option.none();
  return Option.some(image.view.getUint32(o + 2, true));
};
