import { Option } from 'effect';
import { StorageClass, symbols as sharedSymbols } from '../../coff/parse';

const LATIN1 = new TextDecoder('latin1');

const SECTION_HEADER_SIZE = 40;
const SYMBOL_SIZE = 18;
const RELOCATION_SIZE = 10;
const IMAGE_SYM_CLASS_EXTERNAL = 2;

/** One real member of a `.LIB` archive, with long names resolved. */
export interface ArchiveMember {
  readonly name: string;
  readonly body: Uint8Array;
}

/**
 * The object files inside a library archive.
 *
 * The two special members are skipped rather than returned: `/` is the symbol
 * index and `//` is the long-name string table, which later members reference
 * by offset.
 */
export const archiveMembers = (bytes: Uint8Array): ReadonlyArray<ArchiveMember> => {
  const out: ArchiveMember[] = [];
  let longNames = bytes.subarray(0, 0);
  let position = 8;
  while (position + 60 <= bytes.length) {
    const header = bytes.subarray(position, position + 60);
    const raw = LATIN1.decode(header.subarray(0, 16)).replace(/\s+$/, '');
    const size = Number.parseInt(LATIN1.decode(header.subarray(48, 58)).trim(), 10);
    if (!Number.isFinite(size) || size < 0) break;
    const body = bytes.subarray(position + 60, position + 60 + size);
    position += 60 + size + (size & 1);
    if (raw === '//') {
      longNames = body;
      continue;
    }
    if (raw === '/') continue;
    let name = raw;
    if (raw.startsWith('/') && /^\d+$/.test(raw.slice(1)) && longNames.length > 0) {
      const offset = Number.parseInt(raw.slice(1), 10);
      let end = longNames.indexOf(0, offset);
      if (end < 0) end = longNames.indexOf(0x2f /* '/' */, offset);
      name = LATIN1.decode(longNames.subarray(offset, end < 0 ? longNames.length : end));
    }
    if (body.length > 20) out.push({ name: name.replace(/\/+$/, ''), body });
  }
  return out;
};

export interface CoffTextSection {
  /** One-based section number, as the symbol table refers to it. */
  readonly index: number;
  readonly bytes: Uint8Array;
  /**
   * Byte offsets the linker patches. The object STATES these, so there is no
   * need to guess which bytes are addresses -- a heuristic mask was wrong in
   * both directions, masking vtable pointer values that should have been
   * compared and refusing to mask a disp32 that had a base register.
   */
  readonly relocated: ReadonlySet<number>;
}

/**
 * Every `.text` section of a COFF object.
 *
 * MSVC 6 emits each function into its OWN `.text` COMDAT -- a 261-function
 * object has 261 sections all named `.text` -- so anything that looks at only
 * the first one sees 16 bytes.
 */
export const coffTextSections = (object: Uint8Array): ReadonlyArray<CoffTextSection> => {
  if (object.length < 20) return [];
  const view = new DataView(object.buffer, object.byteOffset, object.byteLength);
  const sectionCount = view.getUint16(2, true);
  const headers = 20 + view.getUint16(16, true);
  const out: CoffTextSection[] = [];
  for (let i = 0; i < sectionCount; i++) {
    const o = headers + i * SECTION_HEADER_SIZE;
    if (o + SECTION_HEADER_SIZE > object.length) break;
    const name = LATIN1.decode(object.subarray(o, o + 8)).replace(/\0+$/, '');
    const size = view.getUint32(o + 16, true);
    const pointer = view.getUint32(o + 20, true);
    const relocationPointer = view.getUint32(o + 24, true);
    const relocationCount = view.getUint16(o + 32, true);
    if (!name.startsWith('.text') || pointer === 0 || size === 0) continue;
    if (pointer + size > object.length) continue;
    const relocated = new Set<number>();
    for (let r = 0; r < relocationCount; r++) {
      const at = relocationPointer + r * RELOCATION_SIZE;
      if (at + RELOCATION_SIZE > object.length) break;
      const rva = view.getUint32(at, true);
      for (let k = 0; k < 4; k++) relocated.add(rva + k);
    }
    out.push({ index: i + 1, bytes: object.subarray(pointer, pointer + size), relocated });
  }
  return out;
};

export interface CoffSymbol {
  readonly offset: number;
  readonly name: string;
}

/**
 * External function symbols defined in one section, ascending by offset.
 *
 * This is what makes an identification possible at all: the archive's own
 * symbol table carries the real function names, so placing an object's bytes
 * in the subject names the functions rather than guessing at them.
 */
export const coffExternalSymbols = (
  object: Uint8Array,
  sectionIndex: number,
): ReadonlyArray<CoffSymbol> =>
  // The walk is shared (src/coff/parse.ts); only the FILTER is ours. CRT
  // matching identifies library exports, so it wants storage class 2 with
  // real names -- `@`-prefixed symbols are compiler bookkeeping, not exports.
  // The gate's filter differs deliberately: a COMDAT function may be static,
  // so it also accepts class 3.
  sharedSymbols(object)
    .filter(
      (s) =>
        s.sectionNumber === sectionIndex &&
        s.storageClass === StorageClass.External &&
        s.name !== '' &&
        !s.name.startsWith('@'),
    )
    .map((s) => ({ offset: s.value, name: s.name }))
    .sort((a, b) => a.offset - b.offset || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));

const symbolName = (
  object: Uint8Array,
  view: DataView,
  at: number,
  stringTable: number,
): Option.Option<string> => {
  if (view.getUint32(at, true) === 0) {
    const offset = stringTable + view.getUint32(at + 4, true);
    if (offset < 0 || offset >= object.length) return Option.none();
    const end = object.indexOf(0, offset);
    if (end < 0) return Option.none();
    return Option.some(LATIN1.decode(object.subarray(offset, end)));
  }
  return Option.some(LATIN1.decode(object.subarray(at, at + 8)).replace(/\0+$/, ''));
};
