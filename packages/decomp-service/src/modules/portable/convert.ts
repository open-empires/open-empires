/**
 * MSVC-6 reconstruction in, portable C++ out.
 *
 * Pure, and the only place this translation exists. The reconstructions are
 * written for a 1998 compiler because that is the only way to compare against
 * the shipped bytes, so they stay the verification artifact and this GENERATES
 * a second tree from them. Byte-exactness is never traded for portability, and
 * the conversion can be re-run whenever a source changes.
 *
 * WHAT IT DOES, AND WHAT IT REFUSES TO DO
 * ---------------------------------------
 *   calling conventions   stripped. `__stdcall`, `__cdecl`, `__fastcall` and
 *                         `__thiscall` describe how x86 passes arguments;
 *                         WebAssembly has exactly one convention, so the
 *                         keywords are meaningless there rather than wrong.
 *   __declspec(...)       stripped, including dllimport -- there is no import
 *                         library in a wasm build.
 *   #pragma pack          KEPT. Clang honours it, and these structs mirror the
 *                         game's real memory layout, so dropping it would
 *                         change field offsets and silently corrupt
 *                         everything.
 *   __asm blocks          REFUSED. There is no portable rendering of
 *                         hand-written x86, so the source is listed for manual
 *                         rewriting rather than mangled into something that
 *                         compiles and lies.
 *   literal addresses     routed through the globals model. `(T *)0x684480`
 *                         becomes `(T *)GPTR(0x684480)`, and the file gains the
 *                         include that defines it. The literal is what makes
 *                         the byte comparison work, so it is not a defect to
 *                         remove -- it is an address that has to keep meaning
 *                         what it meant natively.
 */

/** Calling conventions, which x86 needs and WebAssembly does not have. */
const CONVENTIONS = /\b__(stdcall|cdecl|fastcall|thiscall)\b/g;
const DECLSPEC = /__declspec\s*\([^)]*\)/g;
const ASM = /\b__asm\b/;

/**
 * A cast of a literal address in the game's static data region.
 *
 * `0x6` plus five hex digits, which is 0x600000..0x6FFFFF -- deliberately
 * narrow, and NOT the whole region the globals model covers. The model's base
 * is 0x629000 and it spans 1,554,534 bytes, so it reaches 0x7A28A6: a literal
 * at or above 0x700000 is inside the model and is NOT rewritten by this.
 * `literalsOutsideThePattern` reports those rather than leaving them to be
 * discovered as a wasm null dereference.
 */
const ADDRESS_CAST = /\(\s*([\w:]+(?:\s*\*)+)\s*\)\s*(0x6[0-9a-fA-F]{5})/g;

/** Any cast of a literal address in the globals model's whole span, so the
 *  ones `ADDRESS_CAST` cannot reach can be counted instead of missed. */
const ANY_ADDRESS_CAST = /\(\s*[\w:]+(?:\s*\*)+\s*\)\s*(0x[0-9a-fA-F]{6,8})/g;

/** The first and last address the globals model maps, from its own header. */
export const GLOBALS_BASE = 0x629000;
export const GLOBALS_END = GLOBALS_BASE + 1554534;

const GLOBALS_INCLUDE = '#include "gameimage.h"\n';

export const PORT_HEADER = (va: number): string =>
  `// GENERATED from the reconstruction proved for sub_${va
    .toString(16)
    .toUpperCase()
    .padStart(8, '0')} -- do not edit.\n` +
  '// The MSVC source in the database is the verification artifact; this is\n' +
  '// the portable rendering of it for the WebAssembly build.\n';

/**
 * What became of one source.
 *
 * `needsGlobals` is not a failure and not a separate state from `converted`:
 * it says the file's literal addresses were routed through the globals model,
 * so it only builds where `gameimage.h` and the loaded data image are present.
 */
export type Conversion =
  | { readonly state: 'refused'; readonly reason: string }
  | {
      readonly state: 'converted';
      readonly text: string;
      readonly needsGlobals: boolean;
      /**
       * Literal addresses inside the globals model that the rewrite pattern
       * does not match, so they are still bare numbers in the output. Each one
       * is a wasm dereference of an address that does not exist there.
       */
      readonly literalsOutsideThePattern: ReadonlyArray<number>;
    };

/** The source with comment-only lines removed, which is what a detection must
 *  look at: an `__asm` named in a comment is not hand-written assembly, and a
 *  refusal caused by one would withhold a file that converts cleanly. */
const code = (source: string): string =>
  source
    .split('\n')
    .filter((line) => !line.trim().startsWith('//'))
    .join('\n');

export const convert = (source: string): Conversion => {
  const body = code(source);
  if (ASM.test(body)) return { state: 'refused', reason: 'hand-written __asm' };

  const stripped = source.replace(CONVENTIONS, '').replace(DECLSPEC, '');

  // ONE criterion, read off the CODE: does this file dereference a literal
  // address. It decides the rewrite and it decides the recorded state, so the
  // two cannot disagree.
  //
  // The Python asked it twice and got two answers: it rewrote whenever the
  // pattern matched anywhere INCLUDING comments, which prepended the include,
  // but recorded `needs_globals` only when the pattern matched the
  // comment-stripped code. Fourteen files therefore carried `#include
  // "gameimage.h"` while being reported as not needing the globals model. A
  // literal address in a comment is prose, so the code is what is asked.
  const needsGlobals = new RegExp(ADDRESS_CAST.source).test(
    body.replace(CONVENTIONS, '').replace(DECLSPEC, ''),
  );
  const rewritten = needsGlobals
    ? stripped.replace(ADDRESS_CAST, '($1)GPTR($2)')
    : stripped;
  const text = needsGlobals ? GLOBALS_INCLUDE + rewritten : rewritten;

  // Measured on the OUTPUT's code, so what is reported is what is actually
  // left as a bare literal to be dereferenced -- not what the input happened
  // to contain, and not a number written in a comment.
  const stranded: number[] = [];
  for (const match of code(rewritten).matchAll(ANY_ADDRESS_CAST)) {
    const value = Number(match[1]);
    if (value >= GLOBALS_BASE && value < GLOBALS_END) stranded.push(value);
  }
  return {
    state: 'converted',
    text,
    needsGlobals,
    literalsOutsideThePattern: [...new Set(stranded)].sort((a, b) => a - b),
  };
};
