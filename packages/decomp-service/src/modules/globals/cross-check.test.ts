/**
 * The derivation against the only prior answer that exists.
 *
 * `decomp/globals_used.json` is an artifact of the Python tooling this
 * service replaced. It records, for 503 addresses, which reconstruction
 * source files mention them -- read out of the C++ TEXT, not out of the
 * subject's instructions. So it is a cross-check and not a source: it cannot
 * say what an access width is, it cannot distinguish a proven function from
 * an unproven one, and it only ever saw the 503 addresses that happened to be
 * written into 503 files.
 *
 * What makes it worth asserting is the direction of containment. This
 * derivation reads the instructions, so it must find EVERY data address the
 * old artifact found -- a missing one means the instruction-level derivation
 * is blind to something a human already wrote down. The reverse is expected
 * and is the point: reading the bytes finds many times more.
 *
 * Where the inputs are absent the test SKIPS LOUDLY rather than passing.
 */
import { expect, test as buntest } from 'bun:test';
import { Option, Result } from 'effect';
import fs from 'node:fs';
import path from 'node:path';
import { loadDecoder, decodeFunctionBody } from '../disasm/decoder';
import { parsePeImage } from '../subject/pe';
import { SUBJECT_IMAGE_PATH } from '../subject/paths';
import { SECTION_EXECUTABLE } from '../subject/interface';
import type { SubjectImage } from '../disasm/interface';
import { dataReferences } from './code-references';

/** The Python artifact, beside the sources it was read out of. Not written
 *  to, and not a dependency of anything the service does. */
const GLOBALS_USED = path.resolve(
  path.join(import.meta.dir, '../../../../aoe2-in-browser/decomp/globals_used.json'),
);
/** The inventory the artifact's addresses were gathered against. Its own
 *  function list, so the comparison is not distorted by the inventory having
 *  grown since. */
const FUNCTIONS = path.resolve(
  path.join(import.meta.dir, '../../../../aoe2-in-browser/decomp/functions.json'),
);

const inputs = [SUBJECT_IMAGE_PATH, GLOBALS_USED, FUNCTIONS];
const missing = inputs.filter((p) => !fs.existsSync(p));

if (missing.length > 0) {
  buntest('the subject image and the Python artifacts are present', () => {
    throw new Error(
      `cannot cross-check the globals derivation: ${missing.join(', ')} absent. Nothing below ` +
        'ran; this is a skip, not a pass.',
    );
  });
} else {
  const image = (() => {
    const parsed = parsePeImage(Bun.mmap(SUBJECT_IMAGE_PATH, { shared: false }));
    if (Result.isFailure(parsed)) throw new Error(JSON.stringify(parsed.failure));
    return parsed.success;
  })();
  const text = image.sections.find((s) => s.name === '.text');
  if (text === undefined) throw new Error('the subject has no .text section');
  const subject: SubjectImage = {
    sha256: 'cross-check',
    bytes: image.bytes,
    imageBase: image.imageBase,
    textLo: text.va,
    textHi: text.va + text.virtualSize,
  };
  const spans = image.sections.map((s) => ({
    name: s.name,
    lo: s.va,
    hi: s.va + Math.max(s.virtualSize, s.rawSize),
    code: (s.characteristics & SECTION_EXECUTABLE) !== 0,
  }));
  const sectionOf = (va: number) => spans.find((s) => va >= s.lo && va < s.hi);
  const inDataRegion = (va: number): boolean => {
    const found = sectionOf(va);
    return found !== undefined && !found.code;
  };

  const recorded = JSON.parse(fs.readFileSync(GLOBALS_USED, 'utf8')) as Record<
    string,
    { readonly uses: number; readonly section: string; readonly files: ReadonlyArray<string> }
  >;
  const inventory = JSON.parse(fs.readFileSync(FUNCTIONS, 'utf8')) as {
    readonly subject_sha256: string;
    readonly count: number;
    readonly functions: ReadonlyArray<{ readonly va: number; readonly size: number }>;
  };
  const functions = inventory.functions;

  const found = await (async () => {
    const decoder = await loadDecoder();
    const addresses = new Set<number>();
    let references = 0;
    let unconfirmed = 0;
    for (const fn of functions) {
      const body = decodeFunctionBody(decoder, subject, fn);
      if (body === undefined) continue;
      const read = dataReferences({
        instructions: body,
        containingFunction: Option.some(fn.va),
        inDataRegion,
      });
      references += read.references.length;
      unconfirmed += read.unconfirmed.length;
      for (const reference of read.references) addresses.add(reference.address);
    }
    return { addresses, references, unconfirmed };
  })();

  buntest('both artifacts are about this very subject', () => {
    // A cross-check against a different binary proves nothing. The artifact
    // names the subject it was produced from, so this is checkable.
    expect(inventory.subject_sha256).toBe(
      '71cfff63113ab46d99f22fce5b987143de8c1582a7bd4dce10776a3ddffd7d4d',
    );
    // The artifact's own `count` field says 5,565 while its array holds
    // 6,570. Asserted as it stands rather than reconciled: the file is a
    // frozen legacy artifact this service does not write, and the
    // disagreement is a reason to treat its numbers as a cross-check and
    // never as a source.
    expect(inventory.count).toBe(5565);
    expect(inventory.functions.length).toBe(6570);
  });

  buntest('the Python artifact holds 503 addresses, 42 of them in .text', () => {
    const entries = Object.entries(recorded);
    expect(entries.length).toBe(503);
    // Its `.text` entries are function pointers, which the function inventory
    // owns; this module answers for the data region only.
    expect(entries.filter(([, v]) => v.section === '.text').length).toBe(42);
  });

  buntest('every data address the artifact recorded is found in the instructions', () => {
    const expected = Object.entries(recorded)
      .filter(([, v]) => v.section !== '.text')
      .map(([address]) => Number.parseInt(address, 16));
    expect(expected.length).toBe(461);
    const absent = expected.filter((address) => !found.addresses.has(address));
    expect(absent.map((a) => `0x${a.toString(16)}`)).toEqual([]);
  });

  buntest('reading the instructions finds far more than the 461 written down', () => {
    // The artifact saw only the addresses someone had already typed into a
    // reconstruction. The instructions carry every one the code touches.
    expect(found.addresses.size).toBeGreaterThan(4000);
    expect(found.unconfirmed).toBe(0);
  });

  buntest('every address in the artifact sits in the section it claims', () => {
    // The artifact's own section column, checked against the subject's
    // section table. A disagreement would mean one of the two is reading a
    // different layout, and every count in this file would be about a
    // different binary.
    const wrong: string[] = [];
    for (const [hex, entry] of Object.entries(recorded)) {
      const address = Number.parseInt(hex, 16);
      const section = sectionOf(address);
      if (section?.name !== entry.section) {
        wrong.push(`0x${hex}: artifact says ${entry.section}, image says ${section?.name}`);
      }
    }
    expect(wrong).toEqual([]);
  });
}
