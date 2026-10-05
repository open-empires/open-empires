/**
 * Aligned dwords in the data region that hold a valid address.
 *
 * This is the weakest evidence the inventory admits, and it is also the one
 * the browser build cannot do without. The subject carries no relocation
 * table -- `IMAGE_DIRECTORY_ENTRY_BASERELOC` is rva 0, size 0 -- so nothing
 * in the binary distinguishes a dword that happens to be 7,000,000 from one
 * that is the address of a function. Enumerating them IS reconstructing the
 * relocation table the linker threw away.
 *
 * The weakness is stated rather than hidden: 0x6ACFC0 is both a plausible
 * byte count and an address inside `.data`, so every candidate carries where
 * it sits and where it points, and callers can see that 166 of them are in
 * `.rsrc`, where a dword that looks like an address is almost certainly a
 * resource offset.
 *
 * THE RUN IS THE USEFUL PART. A vtable is a run of consecutive aligned dwords
 * all pointing into code. A run whose first address the code NAMES is a table
 * the program itself declares, and 214 such runs account for 11,354 of the
 * 13,259 code-valued dwords in this subject. An isolated dword is a pointer
 * field in a struct, and says nothing about its own extent.
 */
import type { PointerCandidate } from './interface';

export interface DataRegionSection {
  readonly name: string;
  readonly lo: number;
  readonly hi: number;
}

export interface PointerScan {
  readonly candidates: ReadonlyArray<PointerCandidate>;
  readonly aligned: number;
  readonly zero: number;
}

/**
 * Scan the data region for pointer-valued dwords and group them into maximal
 * runs of consecutive aligned ones.
 *
 * `sectionOf` answers where an address sits, and returns undefined for an
 * address in no section -- which is most of the 32-bit space and the reason
 * the great majority of dwords here are not candidates at all.
 */
export const scanPointerCandidates = (input: {
  readonly image: { readonly base: number; readonly bytes: Uint8Array };
  readonly dataRegion: ReadonlyArray<DataRegionSection>;
  readonly sectionOf: (va: number) => string | undefined;
}): PointerScan => {
  const { image } = input;
  const view = new DataView(image.bytes.buffer, image.bytes.byteOffset, image.bytes.byteLength);
  let aligned = 0;
  let zero = 0;

  // Address -> where it points, before runs are computed. A run needs to know
  // which neighbours are candidates, which is only knowable once the whole
  // region is scanned.
  const found: { address: number; value: number; section: string; targetSection: string }[] = [];
  for (const section of input.dataRegion) {
    // Start aligned to four from the image base, which is how the linker
    // aligns a pointer: a section always begins on a page boundary here, but
    // deriving the first offset keeps that from being an assumption.
    const first = section.lo + ((4 - ((section.lo - image.base) % 4)) % 4);
    for (let va = first; va + 4 <= section.hi; va += 4) {
      const at = va - image.base;
      if (at < 0 || at + 4 > image.bytes.length) continue;
      aligned += 1;
      const value = view.getUint32(at, true);
      // A null pointer is not a relocation: the linker writes nothing for it
      // and the browser build needs nothing resolved.
      if (value === 0) {
        zero += 1;
        continue;
      }
      const targetSection = input.sectionOf(value);
      if (targetSection === undefined) continue;
      found.push({ address: va, value, section: section.name, targetSection });
    }
  }

  const addresses = new Set(found.map((f) => f.address));
  const runStartOf = new Map<number, { start: number; length: number }>();
  for (const f of found) {
    if (runStartOf.has(f.address)) continue;
    let start = f.address;
    while (addresses.has(start - 4)) start -= 4;
    let end = start;
    const members: number[] = [];
    while (addresses.has(end)) {
      members.push(end);
      end += 4;
    }
    const run = { start, length: (end - start) / 4 };
    for (const member of members) runStartOf.set(member, run);
  }

  return {
    candidates: found.map((f) => {
      const run = runStartOf.get(f.address)!;
      return {
        address: f.address,
        value: f.value,
        section: f.section,
        targetSection: f.targetSection,
        runStart: run.start,
        runLength: run.length,
      };
    }),
    aligned,
    zero,
  };
};
