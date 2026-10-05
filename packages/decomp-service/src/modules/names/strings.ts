import { Option } from 'effect';
import type { Section } from '../subject/interface';

/**
 * Identifier-shaped strings in the subject's data.
 *
 * `::`-qualification is not required and must not be: four of the recovered
 * names carry no class at all. `:` is allowed inside because two real strings
 * end in one (`LOGDIR:`, `LOGNAME:`), and excluding them would silently
 * shorten the vocabulary.
 */
const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_:]*$/;

/** Shorter than this and a three-byte coincidence in a jump table reads as a
 *  name. The shortest real strings are exactly three (`Cmd`, `PID`, `SND`). */
const MIN_LENGTH = 3;

/** A name longer than this is not a name; the longest real one is 40. */
const MAX_LENGTH = 255;

const LATIN1 = new TextDecoder('latin1');

export interface DataStrings {
  /**
   * The identifier-shaped, NUL-terminated string at `va`, or absent.
   *
   * Absent covers every way this is not a name: the address is in no section,
   * it is inside the executable span, the bytes run to the end of the image
   * without a NUL, or the text is not identifier-shaped.
   */
  readonly at: (va: number) => Option.Option<string>;
}

/**
 * Read strings out of the image.
 *
 * The data region is "any section, outside the executable span" rather than a
 * list of section names. Naming `.rdata` and `.data` would be writing down
 * something the subject already states, and the real filter is the identifier
 * test: the two definitions select exactly the same 866 references here, and
 * only one of them keeps working on a subject laid out differently.
 */
export const dataStrings = (input: {
  readonly bytes: Uint8Array;
  readonly sections: ReadonlyArray<Section>;
  readonly textLo: number;
  readonly textHi: number;
}): DataStrings => {
  const { bytes, sections, textLo, textHi } = input;
  const offsetOf = (va: number): Option.Option<number> => {
    for (const s of sections) {
      if (va >= s.va && va < s.va + Math.max(s.virtualSize, s.rawSize)) {
        const offset = s.rawOffset + (va - s.va);
        return offset < bytes.length ? Option.some(offset) : Option.none();
      }
    }
    return Option.none();
  };
  const cache = new Map<number, Option.Option<string>>();
  const read = (va: number): Option.Option<string> => {
    if (va >= textLo && va < textHi) return Option.none();
    const start = offsetOf(va);
    if (Option.isNone(start)) return Option.none();
    const limit = Math.min(bytes.length, start.value + MAX_LENGTH + 1);
    let end = start.value;
    while (end < limit && bytes[end] !== 0) end += 1;
    if (end >= limit) return Option.none();
    const text = LATIN1.decode(bytes.subarray(start.value, end));
    if (text.length < MIN_LENGTH) return Option.none();
    return IDENTIFIER.test(text) ? Option.some(text) : Option.none();
  };
  return {
    at: (va) => {
      const hit = cache.get(va);
      if (hit !== undefined) return hit;
      const got = read(va);
      cache.set(va, got);
      return got;
    },
  };
};

/** The class part of a `::`-qualified name. Absent for an unqualified one. */
export const classOfName = (name: string): Option.Option<string> => {
  const at = name.indexOf('::');
  return at > 0 ? Option.some(name.slice(0, at)) : Option.none();
};
