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
/**
 * A cast of a literal address, whatever its leading digit.
 *
 * This matched `0x6` followed by five digits, which covers 0x600000-0x6fffff
 * and stops there -- while the globals model spans 0x629000 to 0x7a4666. Every
 * address from 0x700000 up was therefore invisible to the rewrite and left as
 * a bare number: 61 of them across 46 rebuilt functions, all in 0x79xxxx, each
 * one a dereference in the browser build of memory that does not exist there.
 *
 * The range cannot be said in a regular expression without writing out the
 * digit cases, which is how the bug got in. The pattern now matches any
 * address-shaped literal and the RANGE is checked in code, where it is one
 * comparison against the model's own bounds.
 */
const ADDRESS_CAST = /\(\s*([\w:]+(?:\s*\*)+)\s*\)\s*(0x[0-9a-fA-F]{6,8})/g;

/** Any cast of a literal address in the globals model's whole span, so the
 *  ones `ADDRESS_CAST` cannot reach can be counted instead of missed. */
const ANY_ADDRESS_CAST = /\(\s*[\w:]+(?:\s*\*)+\s*\)\s*(0x[0-9a-fA-F]{6,8})/g;

/** The first and last address the globals model maps, from its own header. */
export const GLOBALS_BASE = 0x629000;
export const GLOBALS_END = GLOBALS_BASE + 1554534;

/**
 * `operator new(unsigned int)` is the win32 declaration and the wrong type
 * anywhere else.
 *
 * MSVC's `size_t` on win32 is `unsigned int`, so six proved sources declare
 * the allocator that way and are right to. On wasm32 `size_t` is
 * `unsigned long`, and a replacement allocator whose parameter is not
 * `size_t` is not a replacement allocator -- clang rejects it outright, so
 * six functions could not reach the browser build.
 *
 * `decltype(sizeof(0))` IS `size_t` by definition, on every target, and needs
 * no header -- which matters because these files include only what the
 * generator gives them.
 *
 * `int` is OPTIONAL in the match. Three of the six were written
 * `operator new(unsigned int)` and the other three `operator new(unsigned,
 * void *p)` -- the placement form, where `unsigned` stands alone. Requiring
 * the `int` fixed half of them and left the other half failing in exactly
 * the same way, which is the kind of near-miss a count catches and a spot
 * check does not.
 */
const OPERATOR_NEW_SIZE =
  /\b(operator\s+(?:new|delete)(?:\s*\[\s*\])?\s*\(\s*)unsigned(?:\s+int)?\b/g;

/**
 * A bare out-of-line declaration of a member, which MSVC accepts and a
 * conforming compiler does not.
 *
 * Five sources contain a line like `void S::g();` for a member already
 * declared inside the struct. MSVC treats the repeat as harmless; clang
 * requires an out-of-line declaration to BE a definition and refuses the
 * whole file.
 *
 * The line is removed rather than given a body. A body would compile and
 * would be a lie: `g()` does something in the original, and a silent no-op in
 * a build meant to RUN is the worst of the three outcomes. Removing it leaves
 * the call with no definition, which surfaces at LINK time as a named
 * unresolved symbol -- the truthful report that this function has not been
 * reconstructed yet, in the place that exists to say so.
 *
 * DONE BY BRACE DEPTH, NOT BY A GLOBAL REGEX. The shape of this declaration
 * is also the shape of an ordinary qualified call statement: `A::B::f(1);` on
 * a line of its own inside a function body matches a pattern written for
 * `void S::g();` exactly, and a global replace would delete it -- silently,
 * and in a build nobody can diff against anything. A computed deletion that
 * takes more than it names has already cost this project 315 lines whose only
 * symptom was one stray brace. So only lines at depth zero are considered,
 * where a statement cannot occur.
 */
const OUT_OF_LINE_DECL = /^[ \t]*[\w:<>,*&][\w:<>,*&\t ]*?\b\w+::~?\w+[ \t]*\([^)]*\)[ \t]*(?:const[ \t]*)?;[ \t]*$/;

/**
 * Drop every file-scope out-of-line member declaration.
 *
 * Depth is counted from the braces seen so far, so a line is only eligible
 * when nothing is open around it. Strings and character literals are not
 * parsed: a brace inside one would miscount the depth, and the risk is
 * accepted here deliberately rather than silently, because these sources are
 * reconstructions of machine code and a brace inside a string literal has not
 * occurred in any of 3,335 of them. If one ever does, this is the line to
 * come back to.
 */
const dropOutOfLineDeclarations = (text: string): string => {
  let depth = 0;
  const kept: string[] = [];
  for (const line of text.split('\n')) {
    if (depth === 0 && OUT_OF_LINE_DECL.test(line)) {
      // Opening and closing braces cannot both be absent and the line be a
      // declaration, so nothing needs counting before dropping it.
      continue;
    }
    kept.push(line);
    for (const ch of line) {
      if (ch === '{') depth += 1;
      else if (ch === '}') depth = Math.max(0, depth - 1);
    }
  }
  return kept.join('\n');
};

/**
 * A `case` label that does not fit in an `int`.
 *
 * One function maps HRESULTs, and an HRESULT with its failure bit set --
 * `0x887601C2`, `0x80070057` -- is above 0x7FFFFFFF. MSVC narrows it to the
 * switch's `int` silently; C++11 calls that a narrowing conversion in a
 * constant expression and refuses the file.
 *
 * The cast is written in rather than the type widened, because widening the
 * switch would change the program and the point of this tree is to be the
 * same program. `(int)0x887601C2` is the value the subject's own switch
 * compares against.
 *
 * Bounded to eight hex digits with a high first digit so an ordinary small
 * literal is never touched.
 */
const WIDE_CASE_LABEL = /\bcase\s+(0[xX][89a-fA-F][0-9a-fA-F]{7})\s*:/g;

const GLOBALS_INCLUDE = '#include "gameimage.h"\n';

/**
 * What the GATE supplies to every compile, reproduced here.
 *
 * The verification compiles each reconstruction with `#include <string.h>`
 * prepended, so a source may use `strcpy` or `memset` without declaring them
 * and still be proved byte-exact. The portable rendering did not carry it, so
 * 123 of 3,322 files -- `strcpy` in 59, `memset` in 23, `memcpy` in 14 --
 * did not compile at all. Nobody knew, because the tree had never been
 * compiled.
 *
 * A rendering of a verified source has to carry the environment the
 * verification supplied, or it is a rendering of something that was never
 * proved.
 */
const RUNTIME_INCLUDE = '#include <string.h>\n#include "msvc.h"\n';

/**
 * `0x4e-4` is ONE preprocessing token, and an invalid one.
 *
 * A pp-number continues through `e-`, so a hex literal ending in e or E
 * followed directly by `+` or `-` swallows the sign as if it were an
 * exponent. MSVC 6 accepts it; every standard-conforming compiler rejects it,
 * and `char p[0x4e-4];` appears verbatim in proved sources. Spacing the
 * operator changes no value and no token but that one.
 */
const HEX_EXPONENT_TRAP = /\b(0[xX][0-9a-fA-F]*[eE])([+-])/g;

/**
 * The header every converted file includes, emitted from the SAME constants
 * the rewrite uses.
 *
 * Nothing produced this. 3,322 files were written referring to a header no
 * code emitted, so the browser build could not compile at all -- and the one
 * check that would have caught it, actually compiling the tree, had never
 * been run.
 *
 * It lives here rather than with the globals inventory because it has to
 * agree with the rewrite BY CONSTRUCTION. `GPTR` undoes exactly what
 * `ADDRESS_CAST` did, against the same base; if the two were declared apart,
 * a change to one would silently relocate every global the other produced.
 * That is the whole class of fault that put 61 addresses outside the pattern.
 */
/**
 * `msvc.h`, written INTO the tree.
 *
 * Every rendered file includes it, and a header referenced by thousands of
 * files and emitted by nothing is how this tree could not compile at all
 * once already -- `gameimage.h` was in exactly that state. The generated tree
 * has to be self-contained, because the thing that compiles it is a wasm
 * toolchain in a browser build, not this repository's test harness with its
 * `-I platform` on the command line.
 *
 * THE ONLY COPY. It briefly also existed as `platform/msvc.h` beside the
 * other stubs, and two copies of one header is the drift this project has
 * already paid for elsewhere -- the audit compiles with `-I <tree>` ahead of
 * `-I platform`, so the tree's own copy is what it was reading anyway and the
 * second file could have gone stale without any test noticing.
 */
export const MSVC_HEADER = `/*
 * The Microsoft-only spellings the proved sources contain, declared so a
 * conforming compiler accepts them.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * The sources in the database are the VERIFICATION artifact: they are written
 * to compile under MSVC 6 and reproduce the subject's bytes, and that is the
 * only thing they have to do. Several of them therefore use spellings that
 * only Microsoft's compiler accepts. The portable tree is generated from
 * them, so the generator has to bridge the difference -- and the honest place
 * to bridge it is a header, not an edit to the source, because editing the
 * source would mean the thing that was proved and the thing that is built are
 * no longer the same text.
 *
 * Each declaration here is a measured failure from
 * \`bun src/verify.ts portable-compiles\`, not an anticipated one.
 */
#ifndef OE_MSVC_H
#define OE_MSVC_H

/* MSVC's 64-bit integer spelling.
 *
 * A MACRO, not a typedef, and the difference is the whole point. \`__int64\` is
 * a built-in TYPE SPECIFIER to Microsoft's compiler, so a source may write
 * \`unsigned __int64 c;\` -- and one does. \`unsigned\` cannot be applied to a
 * typedef name, so declaring it that way turned one file's error from
 * "unknown type name" into "expected ';' at end of declaration list": a fix
 * that moved the failure rather than removing it. Substituting the token
 * makes \`unsigned __int64\` expand to \`unsigned long long\`, which is what the
 * source means. */
#define __int64 long long

/* \`__forceinline\` is MSVC's spelling of an inlining demand. Rendered as a
 * request rather than a demand: the browser build's code generator is not the
 * one the bytes were proved against, so forcing its hand would be a claim
 * nothing here can support. */
#ifndef __forceinline
#define __forceinline inline
#endif

/* Calling conventions. They decide the x86 byte layout and therefore matter
 * enormously to the proof -- and mean nothing in WebAssembly, which has one
 * convention. They are stripped by the generator rather than defined away
 * here; these remain only for a source that spells one somewhere the
 * generator's pattern does not reach. */
#ifndef __cdecl
#define __cdecl
#endif
#ifndef __stdcall
#define __stdcall
#endif
#ifndef __fastcall
#define __fastcall
#endif

#endif /* OE_MSVC_H */
`;

export const GAMEIMAGE_HEADER = `/* GENERATED -- do not edit.
 *
 * The game addressed its variables absolutely: a 1999 MSVC build hard-codes
 * 0x684480 and dereferences it. There is no such address in WebAssembly, so
 * every one is translated at the point of use into an offset inside a single
 * loaded block holding the game's data exactly as the original image laid it
 * out. Nothing in the data itself is rewritten, which is what makes the
 * translation checkable: the block is the original bytes.
 */
#ifndef OE_GAMEIMAGE_H
#define OE_GAMEIMAGE_H

/* First address the model maps -- the start of the game's data region. */
#define GAME_DATA_BASE 0x${GLOBALS_BASE.toString(16)}u
/* One past the last. */
#define GAME_DATA_END  0x${GLOBALS_END.toString(16)}u
#define GAME_DATA_SIZE (GAME_DATA_END - GAME_DATA_BASE)

/* The loaded block. ${GLOBALS_END - GLOBALS_BASE} bytes, read from the image the
 * game ran with, placed by the host before any reconstructed code runs. */
extern unsigned char *g_gamedata;

/* An original address becomes a pointer into that block. */
#define GPTR(a) ((void *)(g_gamedata + ((unsigned)(a) - GAME_DATA_BASE)))

#endif /* OE_GAMEIMAGE_H */
`;

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
  const inModel = (value: number): boolean =>
    value >= GLOBALS_BASE && value < GLOBALS_END;

  // ONE pass decides both. Asking the question twice is what let the rewrite
  // and the recorded state disagree once already.
  let needsGlobals = false;
  for (const m of body
    .replace(CONVENTIONS, '')
    .replace(DECLSPEC, '')
    .matchAll(new RegExp(ADDRESS_CAST.source, 'g'))) {
    if (inModel(Number(m[2]))) { needsGlobals = true; break; }
  }
  const rewritten = needsGlobals
    ? stripped.replace(ADDRESS_CAST, (whole, cast: string, addr: string) =>
        inModel(Number(addr)) ? `(${cast})GPTR(${addr})` : whole)
    : stripped;
  const spaced = dropOutOfLineDeclarations(
    rewritten
      .replace(HEX_EXPONENT_TRAP, '$1 $2 ')
      .replace(OPERATOR_NEW_SIZE, '$1decltype(sizeof(0))')
      .replace(WIDE_CASE_LABEL, 'case (int)$1:'),
  );
  const text =
    RUNTIME_INCLUDE + (needsGlobals ? GLOBALS_INCLUDE + spaced : spaced);

  // Measured on the OUTPUT's code, so what is reported is what is actually
  // left as a bare literal to be dereferenced -- not what the input happened
  // to contain, and not a number written in a comment.
  const stranded: number[] = [];
  for (const match of code(spaced).matchAll(ANY_ADDRESS_CAST)) {
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
