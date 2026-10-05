/**
 * COFF object parsing: ONE walk of the section headers and the symbol table.
 *
 * There were two of these, and they had already drifted. `gate/coff.ts`
 * skipped auxiliary records and accepted storage classes 2 and 3;
 * `subject/coff.ts` accepted class 2 only and iterated every 18-byte slot as
 * if it were a symbol. The second is a latent corruption: an auxiliary record
 * is binary payload, not a symbol, so any aux slot whose byte 16 happens to
 * equal 2 and whose section field happens to match is admitted as a symbol
 * with a garbage name and offset. Nothing would announce it.
 *
 * Their FILTERS genuinely differ and both are right:
 *   - the gate wants classes 2 and 3, because a COMDAT function may be static
 *   - CRT matching wants class 2 with real names, because it is identifying
 *     library exports and `@`-prefixed symbols are not those
 *
 * So the fix is one parser and two filters, not one winner. This file is pure
 * and dependency-free: no Effect, no service, nothing to inject.
 */

export const SYMBOL_SIZE = 18;

export const StorageClass = {
  External: 2,
  Static: 3,
} as const;

export interface CoffSection {
  readonly index: number; // 1-based, as symbols reference it
  readonly name: string;
  readonly data: Uint8Array;
  readonly size: number;
  readonly relocationPointer: number;
  readonly relocationCount: number;
}

export interface CoffSymbol {
  readonly name: string;
  /**
   * Index in the object's symbol table, COUNTING auxiliary records. A
   * relocation refers to its symbol by this number, so it is not the position
   * in the array `symbols` returns -- that array has the auxiliary records
   * skipped, which shifts every index after the first one.
   */
  readonly index: number;
  /** Offset within its section. */
  readonly value: number;
  /** 1-based section number; <= 0 means absolute/undefined/debug. */
  readonly sectionNumber: number;
  readonly storageClass: number;
  readonly auxiliaryCount: number;
}

const ascii = (b: Uint8Array): string => {
  let s = '';
  for (const c of b) {
    if (c === 0) break;
    s += String.fromCharCode(c);
  }
  return s;
};

/** A symbol's name is either inline in 8 bytes, or an offset into the string
 *  table when the first dword is zero. */
const symbolName = (
  obj: Uint8Array,
  view: DataView,
  at: number,
  stringTable: number,
): string => {
  if (view.getUint32(at, true) === 0) {
    const off = stringTable + view.getUint32(at + 4, true);
    if (off >= obj.length) return '';
    return ascii(obj.subarray(off, Math.min(off + 512, obj.length)));
  }
  return ascii(obj.subarray(at, at + 8));
};

export const sections = (obj: Uint8Array): ReadonlyArray<CoffSection> => {
  if (obj.length < 20) return [];
  const view = new DataView(obj.buffer, obj.byteOffset, obj.byteLength);
  const count = view.getUint16(2, true);
  const optionalSize = view.getUint16(16, true);
  const base = 20 + optionalSize;
  const out: CoffSection[] = [];
  for (let i = 0; i < count; i++) {
    const at = base + i * 40;
    if (at + 40 > obj.length) break;
    const size = view.getUint32(at + 16, true);
    const pointer = view.getUint32(at + 20, true);
    // A section with no raw data (.bss) has pointer 0; its bytes are not
    // present in the file and must not be read from offset 0.
    const data =
      pointer === 0 || pointer + size > obj.length
        ? new Uint8Array(0)
        : obj.subarray(pointer, pointer + size);
    out.push({
      index: i + 1,
      name: ascii(obj.subarray(at, at + 8)),
      data,
      size,
      relocationPointer: view.getUint32(at + 24, true),
      relocationCount: view.getUint16(at + 32, true),
    });
  }
  return out;
};

/**
 * Every symbol, with auxiliary records SKIPPED rather than yielded.
 *
 * `auxiliaryCount` at byte 17 says how many 18-byte slots follow that belong
 * to this symbol. Walking them as symbols is the bug this file exists to
 * remove, so the loop advances by `1 + auxiliaryCount` and never by 1.
 */
export const symbols = (obj: Uint8Array): ReadonlyArray<CoffSymbol> => {
  if (obj.length < 20) return [];
  const view = new DataView(obj.buffer, obj.byteOffset, obj.byteLength);
  const pointer = view.getUint32(8, true);
  const count = view.getUint32(12, true);
  const stringTable = pointer + count * SYMBOL_SIZE;
  const out: CoffSymbol[] = [];
  let k = 0;
  while (k < count) {
    const at = pointer + k * SYMBOL_SIZE;
    if (at + SYMBOL_SIZE > obj.length) break;
    const auxiliaryCount = obj[at + 17]!;
    out.push({
      name: symbolName(obj, view, at, stringTable),
      index: k,
      value: view.getUint32(at + 8, true),
      sectionNumber: view.getInt16(at + 12, true),
      storageClass: obj[at + 16]!,
      auxiliaryCount,
    });
    k += 1 + auxiliaryCount;
  }
  return out;
};

/** Absolute 32-bit address. The linker writes the symbol's final address into
 *  the four bytes at the relocation's offset. */
export const RelocationType = { Dir32: 6 } as const;

export interface CoffRelocation {
  readonly offset: number;
  readonly type: number;
  /** `CoffSymbol.index` of the symbol this relocation names. */
  readonly symbolIndex: number;
}

/**
 * Relocation fields of one section.
 *
 * `symbolIndex` is the whole point for anything that asks WHAT a patched field
 * refers to: the object states the external symbol each `call dword ptr [...]`
 * site targets, so the name comes from the library's own symbol table rather
 * than from the shape of the call.
 */
export const relocations = (
  obj: Uint8Array,
  section: CoffSection,
): ReadonlyArray<CoffRelocation> => {
  if (section.relocationCount === 0 || section.relocationPointer === 0) return [];
  const view = new DataView(obj.buffer, obj.byteOffset, obj.byteLength);
  const out: CoffRelocation[] = [];
  for (let i = 0; i < section.relocationCount; i++) {
    const at = section.relocationPointer + i * 10;
    if (at + 10 > obj.length) break;
    out.push({
      offset: view.getUint32(at, true),
      symbolIndex: view.getUint32(at + 4, true),
      type: view.getUint16(at + 8, true),
    });
  }
  return out;
};
