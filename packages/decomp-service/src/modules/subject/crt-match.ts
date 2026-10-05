import { Option } from 'effect';
import { archiveMembers, coffExternalSymbols, coffTextSections } from './coff';

/** One address named by placing a library object's own bytes in the subject. */
export interface CrtIdentification {
  readonly va: number;
  readonly symbol: string;
  readonly library: string;
  readonly member: string;
  /** Size of the `.text` section the symbol was found in. */
  readonly sectionSize: number;
}

export interface CrtMatch {
  readonly identifications: ReadonlyArray<CrtIdentification>;
  readonly sectionsPlacedUniquely: number;
  /** Sections with no placement, or more than one. An ambiguity is refused. */
  readonly sectionsRefused: number;
}

const MIN_SECTION_SIZE = 16;
const ANCHOR_LENGTH = 8;

/**
 * Identify CRT functions by placing the shipped library's objects in the
 * subject, rather than reconstructing them.
 *
 * The subject's Rich header records objects from compiler build 8168 as well
 * as the 8447 that built the game's own code, and our own LIBC.LIB holds 498 C
 * and 22 C++ objects all stamped 8168 whose counts are supersets of the
 * game's. So those objects are the PREBUILT CRT from this very install, not a
 * second compiler someone used on game code -- which means CRT code needs no
 * reconstruction at all.
 *
 * A match here is an IDENTIFICATION, a stronger claim than a byte-exact
 * reconstruction: it names the function and shows the bytes came from that
 * object, rather than showing that source we invented compiles to the same
 * thing.
 */
export const identifyCrtFunctions = (input: {
  readonly region: Uint8Array;
  readonly regionBase: number;
  readonly libraries: ReadonlyArray<{ readonly path: string; readonly bytes: Uint8Array }>;
}): CrtMatch => {
  const anchors = anchorIndex(input.region);
  const identifications = new Map<number, CrtIdentification>();
  let sectionsPlacedUniquely = 0;
  let sectionsRefused = 0;
  for (const library of input.libraries) {
    for (const member of archiveMembers(library.bytes)) {
      for (const section of coffTextSections(member.body)) {
        if (section.bytes.length < MIN_SECTION_SIZE) continue;
        const placement = uniquePlacement(input.region, anchors, section.bytes, section.relocated);
        if (Option.isNone(placement)) {
          sectionsRefused++;
          continue;
        }
        sectionsPlacedUniquely++;
        for (const symbol of coffExternalSymbols(member.body, section.index)) {
          if (symbol.offset >= section.bytes.length) continue;
          const va = input.regionBase + placement.value + symbol.offset;
          if (identifications.has(va)) continue;
          identifications.set(va, {
            va,
            symbol: symbol.name,
            library: library.path,
            member: member.name,
            sectionSize: section.bytes.length,
          });
        }
      }
    }
  }
  return {
    identifications: [...identifications.values()].sort((a, b) => a.va - b.va),
    sectionsPlacedUniquely,
    sectionsRefused,
  };
};

/**
 * Every position in the region by its first four bytes, so a candidate
 * placement is found without rescanning the whole region per section.
 */
const anchorIndex = (region: Uint8Array): ReadonlyMap<number, ReadonlyArray<number>> => {
  const view = new DataView(region.buffer, region.byteOffset, region.byteLength);
  const index = new Map<number, number[]>();
  for (let i = 0; i + 4 <= region.length; i++) {
    const key = view.getUint32(i, true);
    const at = index.get(key);
    if (at === undefined) index.set(key, [i]);
    else at.push(i);
  }
  return index;
};

/**
 * Where this section sits in the region, if exactly one place fits.
 *
 * The anchor is the first eight-byte run the linker does not patch, so the
 * search is over bytes the object and the image must agree on exactly.
 * Relocated bytes are excluded from the comparison because the linker chose
 * them; everything else must match. More than one fit is refused rather than
 * guessed: a search for A match answers the weaker question "does SOME
 * function of this shape sit here", which three separate reconstructions
 * passed a deliberately broken control on.
 */
const uniquePlacement = (
  region: Uint8Array,
  anchors: ReadonlyMap<number, ReadonlyArray<number>>,
  code: Uint8Array,
  relocated: ReadonlySet<number>,
): Option.Option<number> => {
  const limit = Math.max(1, code.length - ANCHOR_LENGTH);
  let anchor = -1;
  for (let i = 0; i < limit; i++) {
    let clean = true;
    for (let k = i; k < i + ANCHOR_LENGTH; k++) {
      if (relocated.has(k)) {
        clean = false;
        break;
      }
    }
    if (clean) {
      anchor = i;
      break;
    }
  }
  if (anchor < 0) return Option.none();

  const codeView = new DataView(code.buffer, code.byteOffset, code.byteLength);
  const prefix = codeView.getUint32(anchor, true);
  const candidates = anchors.get(prefix) ?? [];
  let found = -1;
  for (const position of candidates) {
    if (position + ANCHOR_LENGTH > region.length) continue;
    let same = true;
    for (let k = 4; k < ANCHOR_LENGTH; k++) {
      if (region[position + k] !== code[anchor + k]) {
        same = false;
        break;
      }
    }
    if (!same) continue;
    const base = position - anchor;
    if (base < 0 || base + code.length > region.length) continue;
    let matches = true;
    for (let k = 0; k < code.length; k++) {
      if (!relocated.has(k) && region[base + k] !== code[k]) {
        matches = false;
        break;
      }
    }
    if (!matches) continue;
    if (found >= 0) return Option.none(); // ambiguous: refuse to guess
    found = base;
  }
  return found < 0 ? Option.none() : Option.some(found);
};
