/**
 * The MSVC-to-portable conversion, against what it must and must not do.
 *
 * Pure, so this needs no subject, no compiler and no database -- which is why
 * it is the one part of the phase-4 port that can be held to its rules by a
 * test rather than by a corpus run.
 */
import { expect, test } from 'bun:test';
import { convert, GLOBALS_BASE, GLOBALS_END } from './convert';

const converted = (source: string) => {
  const out = convert(source);
  if (out.state !== 'converted') throw new Error(`refused: ${out.reason}`);
  return out;
};

test('calling conventions are stripped', () => {
  const out = converted('int __stdcall f(int a) { return a; }\n');
  expect(out.text).toContain('int  f(int a)');
  expect(out.text).not.toContain('__stdcall');
});

test('every convention keyword goes, not just the first', () => {
  const out = converted('void __cdecl a(); void __fastcall b(); void __thiscall c();\n');
  for (const kw of ['__cdecl', '__fastcall', '__thiscall']) {
    expect(out.text).not.toContain(kw);
  }
});

test('__declspec goes, dllimport included -- a wasm build has no import library', () => {
  const out = converted('__declspec(dllimport) int f(void);\n');
  expect(out.text).not.toContain('__declspec');
  expect(out.text).toContain('int f(void);');
});

test('#pragma pack is KEPT: these structs mirror the game\'s real layout', () => {
  const out = converted('#pragma pack(1)\nstruct S { char a; int b; };\n');
  expect(out.text).toContain('#pragma pack(1)');
});

test('__asm is refused, never mangled into something that compiles and lies', () => {
  const out = convert('void f() { __asm { mov eax, 1 } }\n');
  expect(out.state).toBe('refused');
  if (out.state === 'refused') expect(out.reason).toBe('hand-written __asm');
});

test('__asm named in a comment is prose, not hand-written assembly', () => {
  // A refusal caused by a comment would withhold a file that converts cleanly.
  const out = convert('// the original used __asm here; this does not.\nint f() { return 1; }\n');
  expect(out.state).toBe('converted');
});

test('a literal address is routed through the globals model, with its include', () => {
  const out = converted('int f() { return *(int *)0x684480; }\n');
  expect(out.needsGlobals).toBe(true);
  expect(out.text).toContain('#include "gameimage.h"');
  expect(out.text).toContain('(int *)GPTR(0x684480)');
});

test('a literal address only in a comment gets neither the rewrite nor the include', () => {
  // The Python rewrote on the full text and recorded the state from the
  // comment-stripped code, so fourteen files carried an include while being
  // reported as not needing the globals model. One criterion, read off the code.
  const out = converted('// vptr = (void *)0x63c51c; would fix the shape\nint f() { return 1; }\n');
  expect(out.needsGlobals).toBe(false);
  expect(out.text).not.toContain('gameimage.h');
  expect(out.text).not.toContain('GPTR');
});

test('a file with no literal address gains no dependency on the globals model', () => {
  const out = converted('int f(int a) { return a * 2; }\n');
  expect(out.needsGlobals).toBe(false);
  expect(out.text).not.toContain('gameimage.h');
});

test('a literal high in the model is rewritten, not stranded', () => {
  // This test used to assert the opposite, and in doing so recorded a bug as
  // the specification. The rewrite matched `0x6` followed by five digits,
  // which stops at 0x6fffff, while the model spans 0x629000..0x7a4666 -- so
  // every address from 0x700000 up was left as a bare number. Measured over
  // the proven corpus that was 61 literals across 46 rebuilt functions, all
  // in 0x79xxxx, each one a dereference in the browser build of memory that
  // is not there.
  //
  // The range is now checked in code rather than spelled as digit cases in a
  // regular expression, which is how it went wrong.
  expect(0x792454).toBeGreaterThanOrEqual(GLOBALS_BASE);
  expect(0x792454).toBeLessThan(GLOBALS_END);
  const out = converted('int f() { return *(int *)0x792454; }\n');
  expect(out.needsGlobals).toBe(true);
  expect(out.text).toContain('GPTR(0x792454)');
  expect(out.literalsOutsideThePattern).toEqual([]);
});

test('an address just past the end of the model is left alone', () => {
  // The boundary matters in both directions: rewriting an address the model
  // does not map would point it at nothing.
  const past = `0x${GLOBALS_END.toString(16)}`;
  const out = converted(`int f() { return *(int *)${past}; }\n`);
  expect(out.needsGlobals).toBe(false);
  expect(out.text).not.toContain('GPTR');
  expect(out.literalsOutsideThePattern).toEqual([]);
});

test('an address outside the model is not reported as stranded', () => {
  const out = converted('int f() { return *(int *)0x401000; }\n');
  expect(out.literalsOutsideThePattern).toEqual([]);
});

test('a rewritten literal is not then counted as stranded', () => {
  const out = converted('int f() { return *(int *)0x6355a8; }\n');
  expect(out.needsGlobals).toBe(true);
  expect(out.literalsOutsideThePattern).toEqual([]);
});

test('the rendering carries the include the gate compiles with', () => {
  // A source may use strcpy without declaring it and still be proved, because
  // the gate prepends <string.h> to every compile. 123 of 3,322 rendered files
  // did not compile for want of it -- which nobody knew, because the tree had
  // never been compiled.
  const out = converted('void f(char *d, const char *s) { strcpy(d, s); }\n');
  expect(out.text).toContain('#include <string.h>');
});

test('a hex literal ending in e, followed by a sign, is spaced', () => {
  // `0x4e-4` is ONE preprocessing token and an invalid one: a pp-number
  // continues through `e-`, so the sign is swallowed as an exponent. MSVC 6
  // accepts it and standard compilers reject it, and it appears verbatim in
  // proved sources.
  const out = converted('void f() { char p[0x4e-4]; (void)p; }\n');
  expect(out.text).toContain('0x4e - 4');
  expect(out.text).not.toContain('0x4e-4');
});

test('a hex literal not ending in e is left alone', () => {
  const out = converted('void f() { char p[0x4f-4]; (void)p; }\n');
  expect(out.text).toContain('0x4f-4');
});

/**
 * The out-of-line member declaration MSVC accepts and clang refuses.
 *
 * The removal is a COMPUTED DELETION, which is the dangerous kind: the shape
 * of `void S::g();` is also the shape of a qualified call statement, so these
 * tests exist mainly to pin down what must NOT be removed.
 */
test('a bare out-of-line member declaration is dropped', () => {
  const out = convert(
    '#pragma pack(push,1)\n' +
      'struct S { void g(); void f(int x); };\n' +
      'void S::g();\n' +
      'void S::f(int x) { if (x) g(); }\n' +
      '#pragma pack(pop)\n',
  );
  expect(out.state).toBe('converted');
  if (out.state !== 'converted') return;
  expect(out.text).not.toContain('void S::g();');
  // The definition beside it survives untouched.
  expect(out.text).toContain('void S::f(int x) { if (x) g(); }');
  // And so does the in-class declaration, which is what makes the call legal.
  expect(out.text).toContain('void g();');
});

test('a qualified call statement inside a body is NOT dropped', () => {
  // This is the failure the brace-depth walk exists to prevent: the line
  // matches the declaration pattern exactly, and deleting it would remove a
  // real statement from a build meant to run.
  const src =
    'struct S { static void f(int); };\n' +
    'void run() {\n' +
    '  S::f(1);\n' +
    '}\n';
  const out = convert(src);
  expect(out.state).toBe('converted');
  if (out.state !== 'converted') return;
  expect(out.text).toContain('S::f(1);');
});

test('a destructor definition and a multi-line definition both survive', () => {
  const out = convert(
    'struct S { ~S(); int v; };\n' +
      'S::~S()\n' +
      '{\n' +
      '  v = 0;\n' +
      '}\n',
  );
  expect(out.state).toBe('converted');
  if (out.state !== 'converted') return;
  expect(out.text).toContain('S::~S()');
  expect(out.text).toContain('v = 0;');
});

test("operator new's win32 parameter becomes size_t without a header", () => {
  // MSVC's size_t on win32 is `unsigned int` and the source is right to say
  // so; on wasm32 it is `unsigned long`, and an allocator whose parameter is
  // not size_t is not an allocator. `decltype(sizeof(0))` IS size_t on every
  // target and needs nothing included.
  const out = convert('void *operator new(unsigned int);\nint f() { return 0; }\n');
  expect(out.state).toBe('converted');
  if (out.state !== 'converted') return;
  expect(out.text).toContain('operator new(decltype(sizeof(0)))');
  expect(out.text).not.toContain('operator new(unsigned int)');
});

test('an unrelated `unsigned int` parameter is left alone', () => {
  const out = convert('int f(unsigned int n) { return (int)n; }\n');
  expect(out.state).toBe('converted');
  if (out.state !== 'converted') return;
  expect(out.text).toContain('f(unsigned int n)');
});

test('every rendered file carries the MSVC-spelling header', () => {
  // `__int64` is named by one source and defined by nothing off Microsoft's
  // compiler, so the rendering has to supply it the way it already supplies
  // <string.h>.
  const out = convert('int f() { return 0; }\n');
  expect(out.state).toBe('converted');
  if (out.state !== 'converted') return;
  expect(out.text).toContain('#include "msvc.h"');
});

test('placement new, where `unsigned` stands alone, is rewritten too', () => {
  // Three of the six failures were `operator new(unsigned int)` and three were
  // `operator new(unsigned, void *p)`. Matching only the first spelling fixed
  // half of them and left the rest failing identically -- caught by the count,
  // not by a spot check.
  const out = convert('inline void *operator new(unsigned, void *p) { return p; }\n');
  expect(out.state).toBe('converted');
  if (out.state !== 'converted') return;
  expect(out.text).toContain('operator new(decltype(sizeof(0)), void *p)');
});

test('operator delete is rewritten on the same rule', () => {
  const out = convert('void operator delete(unsigned int p);\nint f() { return 0; }\n');
  expect(out.state).toBe('converted');
  if (out.state !== 'converted') return;
  expect(out.text).toContain('operator delete(decltype(sizeof(0)) p)');
});

test('an HRESULT case label is cast rather than the switch widened', () => {
  // 0x887601C2 does not fit in int. MSVC narrows it silently; C++11 refuses.
  // The cast is written in because widening the switch would change the
  // program, and this tree exists to be the same program.
  const out = convert('int f(int h) { switch (h) { case 0x887601c2: return 1; } return 0; }\n');
  expect(out.state).toBe('converted');
  if (out.state !== 'converted') return;
  expect(out.text).toContain('case (int)0x887601c2:');
});

test('an ordinary small case label is left alone', () => {
  const out = convert('int f(int h) { switch (h) { case 0x10: return 1; case 7: return 2; } return 0; }\n');
  expect(out.state).toBe('converted');
  if (out.state !== 'converted') return;
  expect(out.text).toContain('case 0x10:');
  expect(out.text).toContain('case 7:');
  expect(out.text).not.toContain('(int)0x10');
});
