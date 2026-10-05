import { Option } from 'effect';
import { StorageClass, symbols as sharedSymbols } from '../../coff/parse';

/**
 * Reader for the COFF objects MSVC 6 emits.
 *
 * Pure: object bytes in, emitted functions and compiler stamp out. Nothing
 * here knows about the subject, the verdict, or how the object was produced.
 *
 * MSVC 6 gives every function its OWN section named `.text`, so a 261-function
 * object has 261 sections all with that name and the symbol table is the only
 * thing that says which section is which function. Reading just the first
 * section yields 16 bytes; concatenating them all answers the weaker question
 * "do these bytes occur SOMEWHERE in this object", which is how a broken
 * reconstruction passed on a correct sibling's bytes.
 */

/** One function as the compiler emitted it. */
export interface EmittedFunction {
  /** The decorated symbol name the compiler gave it. */
  readonly symbol: string;
  /** Its own section, exactly as emitted. */
  readonly code: Uint8Array;
  /**
   * Byte offsets inside `code` that the LINKER would patch, taken from the
   * object's own relocation records. The object states these, so the gate
   * never guesses which bytes are addresses: the heuristic mask this replaces
   * was wrong in both directions -- it excused every 32-bit immediate inside
   * the image's address range, so vtable pointer VALUES went unchecked, and it
   * refused to excuse a 32-bit displacement that had a base register, so
   * `[ecx + disp32]` against a fixed table could never match.
   */
  readonly relocated: ReadonlySet<number>;
}

const SECTION_HEADER_SIZE = 40;
const SYMBOL_SIZE = 18;
const RELOCATION_SIZE = 10;
/** A relocation patches the four bytes at its recorded address. */
const RELOCATION_WIDTH = 4;
/** COFF storage classes: 2 is EXTERNAL, 3 is STATIC. Both name real code. */
const STORAGE_CLASS_EXTERNAL = 2;
const STORAGE_CLASS_STATIC = 3;

interface Section {
  readonly code: Uint8Array;
  readonly relocated: ReadonlySet<number>;
}

const sectionName = (obj: Uint8Array, at: number): string => {
  let end = at;
  while (end < at + 8 && obj[end] !== 0) end += 1;
  return new TextDecoder('latin1').decode(obj.subarray(at, end));
};

/** Sections holding code, keyed by their 1-based COFF section number. */
const textSections = (obj: Uint8Array, view: DataView): ReadonlyMap<number, Section> => {
  const sectionCount = view.getUint16(2, true);
  const optionalHeaderSize = view.getUint16(16, true);
  const first = 20 + optionalHeaderSize;
  const sections = new Map<number, Section>();
  for (let i = 0; i < sectionCount; i += 1) {
    const at = first + i * SECTION_HEADER_SIZE;
    const name = sectionName(obj, at);
    const size = view.getUint32(at + 16, true);
    const pointer = view.getUint32(at + 20, true);
    const relocationPointer = view.getUint32(at + 24, true);
    const relocationCount = view.getUint16(at + 32, true);
    if (!name.startsWith('.text') || pointer === 0 || size === 0) continue;
    const relocated = new Set<number>();
    for (let r = 0; r < relocationCount; r += 1) {
      const address = view.getUint32(relocationPointer + r * RELOCATION_SIZE, true);
      for (let k = 0; k < RELOCATION_WIDTH; k += 1) relocated.add(address + k);
    }
    sections.set(i + 1, { code: obj.subarray(pointer, pointer + size), relocated });
  }
  return sections;
};

const symbolName = (obj: Uint8Array, view: DataView, at: number, stringTable: number): string => {
  // Four leading zero bytes mean the name did not fit the slot and the next
  // four are its offset into the string table.
  if (view.getUint32(at, true) !== 0) return sectionName(obj, at);
  const offset = stringTable + view.getUint32(at + 4, true);
  let end = offset;
  while (end < obj.length && obj[end] !== 0) end += 1;
  return new TextDecoder('latin1').decode(obj.subarray(offset, end));
};

/**
 * Every function in the object, in symbol-table order.
 *
 * A section symbol just repeats the section's name -- `.text` for every one of
 * them -- so those are skipped; the first real symbol naming a section wins,
 * because several symbols can name one function's section.
 *
 * An object with no code yields an empty list rather than an error: the
 * compiler accepting a source and emitting nothing is a reconstruction that
 * does not match, not a broken gate.
 */
export const emittedFunctions = (obj: Uint8Array): ReadonlyArray<EmittedFunction> => {
  const view = new DataView(obj.buffer, obj.byteOffset, obj.byteLength);
  const sections = textSections(obj, view);
  const seen = new Set<string>();
  const functions: EmittedFunction[] = [];
  // The walk is shared (src/coff/parse.ts); the FILTER stays the gate's.
  // Classes 2 AND 3: a COMDAT function may be static, and dropping class 3
  // would lose those functions' verdicts entirely. `.text`-prefixed names are
  // the section symbols themselves, not functions.
  for (const sym of sharedSymbols(obj)) {
    const section = sections.get(sym.sectionNumber);
    if (
      section !== undefined &&
      (sym.storageClass === StorageClass.External ||
        sym.storageClass === StorageClass.Static) &&
      !sym.name.startsWith('.text') &&
      !seen.has(sym.name)
    ) {
      seen.add(sym.name);
      functions.push({
        symbol: sym.name,
        code: section.code,
        relocated: section.relocated,
      });
    }
  }
  return functions;
};

/**
 * The `@comp.id` the compiler stamps into every object it emits.
 *
 * This is a fact about the compiler's BYTES, not a version banner: the low 16
 * bits are its build number, so SP3's 8447 reads back as 0x20ff. It names the
 * code generator (c1xx/c2), which cl.exe's own hash does not cover, so the two
 * together identify the whole toolchain a verdict was proved against.
 */
export const compilerStamp = (obj: Uint8Array): Option.Option<number> => {
  const view = new DataView(obj.buffer, obj.byteOffset, obj.byteLength);
  const symbolPointer = view.getUint32(8, true);
  const symbolCount = view.getUint32(12, true);
  const stringTable = symbolPointer + symbolCount * SYMBOL_SIZE;
  let k = 0;
  while (k < symbolCount) {
    const at = symbolPointer + k * SYMBOL_SIZE;
    if (symbolName(obj, view, at, stringTable) === '@comp.id') {
      return Option.some(view.getUint32(at + 8, true));
    }
    k += 1 + obj[at + 17]!;
  }
  return Option.none();
};
