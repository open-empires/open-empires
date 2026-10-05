/**
 * Naming globals from the CRT libraries' own tables, against the real subject
 * and the real LIBC.LIB.
 *
 * Every count is asserted. The whole value of this route is that it REFUSES
 * rather than approximates, so a change that starts approximating must fail
 * here rather than quietly produce more names.
 *
 * Where the inputs are absent the test SKIPS LOUDLY rather than passing. A
 * green run against missing inputs is the worst outcome available.
 */
import { expect, test as buntest } from 'bun:test';
import { Option, Result } from 'effect';
import fs from 'node:fs';
import { archiveMembers } from '../subject/coff';
import { identifyCrtFunctions } from '../subject/crt-match';
import { parsePeImage, textSpan } from '../subject/pe';
import {
  CRT_LIBRARY_PATHS,
  CRT_SEARCH_HI,
  CRT_SEARCH_LO,
  SUBJECT_IMAGE_PATH,
} from '../subject/paths';
import { SECTION_EXECUTABLE } from '../subject/interface';
import { definedDataSizes, deriveLibrarySymbols } from './library-symbols';
import { memberKey, openLibraries, refusalForPlacement } from '../../coff/placement';

const inputs = [SUBJECT_IMAGE_PATH, ...CRT_LIBRARY_PATHS];
const missing = inputs.filter((p) => !fs.existsSync(p));

if (missing.length > 0) {
  buntest('the subject image and the CRT libraries are present', () => {
    throw new Error(
      `cannot verify the globals name derivation: ${missing.join(', ')} absent. Nothing below ` +
        'ran; this is a skip, not a pass.',
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
  const libraries = CRT_LIBRARY_PATHS.map((path) => ({
    path,
    members: [...archiveMembers(Bun.mmap(path, { shared: false }))],
  }));

  // The subject is a RAM image, so `va - imageBase` is every address's own
  // offset in it. Reading through the PE header's RAW offsets instead gives
  // zeros for the three sections of this subject where raw offset and RVA
  // diverge, and zeros are indistinguishable from real data.
  const bytes = image.bytes;
  const spans = image.sections.map((s) => ({
    lo: s.va,
    hi: s.va + Math.max(s.virtualSize, s.rawSize),
    code: (s.characteristics & SECTION_EXECUTABLE) !== 0,
  }));
  const inDataRegion = (va: number): boolean => {
    const found = spans.find((s) => va >= s.lo && va < s.hi);
    return found !== undefined && !found.code;
  };

  const region = bytes.subarray(
    CRT_SEARCH_LO - image.imageBase,
    CRT_SEARCH_HI - image.imageBase,
  );
  const identifications = identifyCrtFunctions({
    region,
    regionBase: CRT_SEARCH_LO,
    libraries: CRT_LIBRARY_PATHS.map((path) => ({
      path,
      bytes: Bun.mmap(path, { shared: false }),
    })),
  }).identifications;

  const derived = deriveLibrarySymbols({
    identifications,
    libraries,
    image: { base: image.imageBase, bytes },
    inDataRegion,
  });

  buntest('the identifications place the same 234 code sections the import route places', () => {
    expect(identifications.length).toBe(297);
    expect(derived.sectionsPlaced).toBe(234);
    expect(span.lo).toBe(0x401000);
  });

  buntest('804 relocations name data or code, and they decompose exactly', () => {
    // Every Dir32 relocation in those sections naming a symbol that is not an
    // import. The three outcomes must add up: 734 resolve into the data
    // region, 39 into .text (a function reference, which the function
    // inventory owns), and 31 outside every section. A total that does not
    // equal its parts means one outcome is being silently dropped.
    expect(derived.relocations).toBe(804);
    const outside = derived.refusals.filter((r) => r.reason.includes('outside the image'));
    expect(outside.length).toBe(31);
    expect(derived.dataSectionsPlaced).toBe(58);
    expect(derived.symbols.length).toBe(559);
    expect(new Set(derived.symbols.map((s) => s.address)).size).toBe(153);
  });

  buntest('the addend is subtracted, so _XcptActTab is at 0x682670 and is 120 bytes', () => {
    // The lead that found this global by hand reported 0x682670. A Dir32
    // field holds `symbol + addend`, and winsig.obj reaches it at +8: read
    // without the subtraction it lands at 0x682678, eight bytes into itself.
    const reached = derived.symbols.filter((s) => s.name === '__XcptActTab');
    expect(reached.length).toBeGreaterThan(0);
    expect(new Set(reached.map((s) => s.address))).toEqual(new Set([0x682670]));
    expect(reached.some((s) => s.offsetReached === 8)).toBe(true);
    const sized = reached.find((s) => Option.isSome(s.size));
    expect(sized?.size).toEqual(Option.some(120));
  });

  buntest('one global, not two: _iob is reached 32 and 64 bytes into itself', () => {
    // A FILE is 32 bytes, so the CRT reaches `_iob[1]` and `_iob[2]` through
    // the same symbol. Without the addend correction those are two globals at
    // 0x681b68 and 0x681b88 -- addresses _iob does not begin at.
    const reached = derived.symbols.filter((s) => s.name === '__iob');
    expect(new Set(reached.map((s) => s.address))).toEqual(new Set([0x681b48]));
    expect([...new Set(reached.map((s) => s.offsetReached))].sort((a, b) => a - b)).toEqual([
      32, 64,
    ]);
  });

  buntest('the CRT globals an agent named by hand come out of the libraries', () => {
    const byName = new Map(derived.symbols.map((s) => [s.name, s.address]));
    expect(byName.get('___error_mode')).toBe(0x792b2c);
    expect(byName.get('__pctype')).toBe(0x68208c);
    expect(byName.get('___mb_cur_max')).toBe(0x682298);
    expect(byName.get('_errno')).toBe(0x792c4c);
  });

  buntest('a COFF section symbol is not a global called .data', () => {
    // A storage-class STATIC symbol at offset 0 named after its own section
    // IS the section. Admitting one puts a global called `.data` at the first
    // byte of every placed section, colliding with the real symbol there and
    // withholding 50 names as "conflicting".
    expect(derived.symbols.filter((s) => s.name.startsWith('.'))).toEqual([]);
  });

  buntest('every address is named by exactly one symbol, so no name is withheld', () => {
    const names = new Map<number, Set<string>>();
    for (const symbol of derived.symbols) {
      const at = names.get(symbol.address) ?? new Set<string>();
      at.add(symbol.name);
      names.set(symbol.address, at);
    }
    const conflicting = [...names.entries()].filter(([, set]) => set.size > 1);
    expect(conflicting).toEqual([]);
  });

  buntest('every refusal is one of three kinds, all of them real', () => {
    const kinds = new Map<string, number>();
    for (const refusal of derived.refusals) {
      const kind = refusal.reason.startsWith('.bss')
        ? 'bss has no bytes to confirm'
        : refusal.reason.includes('outside the image')
          ? 'symbol resolves outside the image'
          : refusal.reason.includes('differs from the object')
            ? 'image differs from the object'
            : refusal.reason;
      kinds.set(kind, (kinds.get(kind) ?? 0) + 1);
    }
    // __except_list is the fs:[0] exception registration, which resolves to
    // address zero: a segment offset, not a dangling pointer, and every /GX
    // prologue has one.
    expect(kinds.get('symbol resolves outside the image')).toBe(31);
    // A .bss section has no bytes in the object, so its placement cannot be
    // confirmed and is refused rather than assumed.
    expect(kinds.get('bss has no bytes to confirm')).toBe(22);
    expect(kinds.get('image differs from the object')).toBe(3);
    expect(derived.refusals.length).toBe(56);
  });

  buntest('every data-section placement re-confirms from the address it produced', () => {
    // Independent of the derivation: take each stored symbol address, subtract
    // the offset the LIBRARY gives that symbol, and confirm the section's
    // bytes at the base that implies. A placement admitted without
    // confirmation would pass the counts above and fail here.
    const members = openLibraries(libraries);
    const image_ = { base: image.imageBase, bytes };
    const checked = new Set<string>();
    const unconfirmed: string[] = [];
    for (const symbol of derived.symbols) {
      if (symbol.route !== 'placed-data-section') continue;
      const member = members.get(memberKey(symbol.library, symbol.member));
      if (member === undefined) throw new Error(`no member ${symbol.member}`);
      const section = member.sections.find((x) => x.index === symbol.sectionIndex);
      const defining = member.symbols.find(
        (x) => x.name === symbol.name && x.sectionNumber === symbol.sectionIndex,
      );
      if (section === undefined || defining === undefined) {
        throw new Error(`no definition of ${symbol.name} in ${symbol.member}`);
      }
      const key = `${symbol.member}#${symbol.sectionIndex}`;
      if (checked.has(key)) continue;
      checked.add(key);
      const refusal = refusalForPlacement({
        image: image_,
        member,
        section,
        base: symbol.address - defining.value,
      });
      if (Option.isSome(refusal)) unconfirmed.push(`${key}: ${refusal.value}`);
    }
    expect(checked.size).toBe(58);
    expect(unconfirmed).toEqual([]);
  });

  buntest('a size the libraries state twice over, differently, is dropped', () => {
    // The index is what gives an externally-referenced symbol a size without
    // its section having to be placed. A name two members define with
    // different extents states no size, and choosing one would be a guess
    // dressed as a fact.
    const members = openLibraries(libraries);
    const sizes = definedDataSizes(members);
    expect(sizes.size).toBe(891);
    // Spot-check one the derivation actually uses.
    expect(sizes.get('__XcptActTab')?.size).toBe(120);
  });
}
