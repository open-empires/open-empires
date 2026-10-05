/**
 * The derivation that reads import names out of the libraries' relocations.
 *
 * The pure pieces are tested directly. The derivation itself is tested against
 * the real subject and the real LIBC.LIB, with every count asserted: a
 * derivation that "looks right" and counts differently is wrong, and the whole
 * point of this route is that it refuses rather than approximates, so a change
 * that starts approximating must fail here.
 *
 * Where the inputs are absent the test SKIPS LOUDLY rather than passing. A
 * green run against missing inputs is the worst outcome available.
 */
import { expect, test as buntest } from 'bun:test';
import { Option, Result } from 'effect';
import fs from 'node:fs';
import { identifyCrtFunctions } from '../subject/crt-match';
import { bytesAtVa, parseImportSlots, parsePeImage, textSpan } from '../subject/pe';
import {
  CRT_LIBRARY_PATHS,
  CRT_SEARCH_HI,
  CRT_SEARCH_LO,
  SUBJECT_IMAGE_PATH,
} from '../subject/paths';
import { deriveLibraryImportReferences, undecorate } from './library-relocations';

buntest('an import symbol undecorates to the name the loader resolves', () => {
  expect(undecorate('__imp__HeapAlloc@12')).toEqual(Option.some('HeapAlloc'));
  expect(undecorate('__imp__GetLastError@0')).toEqual(Option.some('GetLastError'));
  // __cdecl carries no @N.
  expect(undecorate('__imp__atexit')).toEqual(Option.some('atexit'));
  // __fastcall decorates with a leading @.
  expect(undecorate('__imp_@Thing@8')).toEqual(Option.some('Thing'));
  // A C++-mangled symbol encodes a type, not a Windows API: refused, never
  // approximated to something identifier-shaped.
  expect(undecorate('__imp_?name@Class@@QAEXZ')).toEqual(Option.none());
  // Not an import symbol at all.
  expect(undecorate('_HeapAlloc@12')).toEqual(Option.none());
});

const inputs = [SUBJECT_IMAGE_PATH, ...CRT_LIBRARY_PATHS];
const missing = inputs.filter((p) => !fs.existsSync(p));

if (missing.length > 0) {
  buntest('the subject image and the CRT libraries are present', () => {
    throw new Error(
      `cannot verify the import-name derivation: ${missing.join(', ')} absent. ` +
        'Nothing below ran; this is a skip, not a pass.',
    );
  });
} else {
  const image = (() => {
    const parsed = parsePeImage(Bun.mmap(SUBJECT_IMAGE_PATH, { shared: false }));
    if (Result.isFailure(parsed)) throw new Error(JSON.stringify(parsed.failure));
    return parsed.success;
  })();
  const span = (() => {
    const parsed = textSpan(image);
    if (Result.isFailure(parsed)) throw new Error(JSON.stringify(parsed.failure));
    return parsed.success;
  })();
  const declared = (() => {
    const parsed = parseImportSlots(image);
    if (Result.isFailure(parsed)) throw new Error(JSON.stringify(parsed.failure));
    return parsed.success;
  })();
  const libraries = CRT_LIBRARY_PATHS.map((path) => ({
    path,
    bytes: Bun.mmap(path, { shared: false }),
  }));
  const region = bytesAtVa(image, CRT_SEARCH_LO, CRT_SEARCH_HI - CRT_SEARCH_LO);
  if (Option.isNone(region)) throw new Error('the CRT search region is in no section');
  const text = bytesAtVa(image, span.lo, span.hi - span.lo);
  if (Option.isNone(text)) throw new Error('the .text span is in no section');

  const identifications = identifyCrtFunctions({
    region: region.value,
    regionBase: CRT_SEARCH_LO,
    libraries,
  }).identifications;

  const derived = deriveLibraryImportReferences({
    identifications,
    libraries,
    text: { lo: span.lo, bytes: text.value },
    slots: new Set(declared.map((s) => s.va)),
  });

  buntest('every identified CRT function places its section in the image', () => {
    expect(identifications.length).toBe(297);
    // 297 symbols in 234 sections: MSVC 6 emits each function into its own
    // .text COMDAT, and several of them carry more than one external symbol.
    expect(derived.sectionsPlaced).toBe(234);
  });

  buntest('every __imp_ relocation in those sections is confirmed, none refused', () => {
    expect(derived.relocations).toBe(114);
    expect(derived.references.length).toBe(114);
    expect(derived.refusals).toEqual([]);
  });

  buntest('107 of the references are call sites and 7 only load the pointer', () => {
    const byForm = new Map<string, number>();
    for (const reference of derived.references) {
      byForm.set(reference.form, (byForm.get(reference.form) ?? 0) + 1);
    }
    expect(byForm.get('call-indirect')).toBe(107);
    expect(byForm.get('load-pointer')).toBe(7);
    expect(byForm.get('jmp-indirect')).toBeUndefined();
    expect(byForm.get('push-pointer')).toBeUndefined();
    expect(new Set(derived.references.map((r) => r.slot)).size).toBe(65);
  });

  buntest('the image itself names the slot at every confirmed reference', () => {
    const bytes = text.value;
    for (const reference of derived.references) {
      const at = reference.site - span.lo;
      const slot = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(
        at + 2,
        true,
      );
      expect(slot).toBe(reference.slot);
      expect(reference.sectionBase + reference.relocationOffset - 2).toBe(reference.site);
    }
  });

  buntest('0x6350E0 is HeapAlloc at sbheap.obj\'s call site, as the lead established', () => {
    const found = derived.references.filter(
      (r) => r.slot === 0x6350e0 && r.member.includes('sbheap'),
    );
    expect(found.length).toBe(1);
    expect(found[0]).toMatchObject({
      api: 'HeapAlloc',
      decorated: '__imp__HeapAlloc@12',
      site: 0x6191d1,
      form: 'call-indirect',
    });
  });

  buntest('the one call site rmdir.obj names is RemoveDirectoryA', () => {
    const found = derived.references.filter((r) => r.member.includes('rmdir.obj'));
    expect(found.map((r) => r.api).sort()).toEqual(['GetLastError', 'RemoveDirectoryA']);
  });
}
