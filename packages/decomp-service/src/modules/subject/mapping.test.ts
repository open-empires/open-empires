/**
 * A virtual address must map to the bytes that are actually there.
 *
 * `fileOffsetOfVa` mapped a VA through its section's PE raw offset. The
 * subject is a flat memory image, so the correct offset is `va - imageBase`,
 * and the two agree for its first four sections and differ by 0x112000 for
 * the last three. Reads from .text, THIS_COD, .rdata and .data were therefore
 * correct and nothing hinted at a problem, while reads from THIS_DAT,
 * Inf32Dat and .rsrc landed in a zero-filled region and returned zeros. At
 * 0x7a1000 the real bytes are a resource directory; the reader handed back
 * zeros, which look exactly like a section that is legitimately empty.
 *
 * These assertions are about CONTENT, not about the arithmetic, because the
 * arithmetic was self-consistent the whole time.
 */
import { expect, test } from 'bun:test';
import fs from 'node:fs';
import { Option, Result } from 'effect';
import { parsePeImage, bytesAtVa, fileOffsetOfVa } from './pe';
import { SUBJECT_IMAGE_PATH } from './paths';

const image = (() => {
  const parsed = parsePeImage(new Uint8Array(fs.readFileSync(SUBJECT_IMAGE_PATH)));
  if (Result.isFailure(parsed)) throw new Error('subject image does not parse');
  return parsed.success;
})();

test('the subject is recognised as a memory image, so VA maps flat', () => {
  for (const s of image.sections) {
    const off = fileOffsetOfVa(image, s.va);
    expect(Option.isSome(off), s.name).toBe(true);
    expect(Option.getOrThrow(off), s.name).toBe(s.va - image.imageBase);
  }
});

test('.rsrc reads a real resource directory, not zeros', () => {
  const bytes = bytesAtVa(image, 0x7a1000, 32);
  expect(Option.isSome(bytes)).toBe(true);
  const b = Option.getOrThrow(bytes);
  // IMAGE_RESOURCE_DIRECTORY: DWORD Characteristics, DWORD TimeDateStamp,
  // WORD MajorVersion, WORD MinorVersion, WORD NumberOfNamedEntries,
  // WORD NumberOfIdEntries -- so the counts are at 12 and 14, and the first
  // IMAGE_RESOURCE_DIRECTORY_ENTRY follows at 16 as { id, offsetToData }.
  const view = new DataView(b.buffer, b.byteOffset, b.byteLength);
  expect(view.getUint16(12, true)).toBe(0); // no entries named by string
  expect(view.getUint16(14, true)).toBe(3); // three named by numeric type id
  expect(view.getUint32(16, true)).toBe(3); // first type is 3, RT_ICON
  // Its offset has the high bit set, which marks a subdirectory rather than
  // a leaf. Zeros could not produce that bit.
  expect(view.getUint32(20, true) & 0x80000000).not.toBe(0);
  expect(b.every((x) => x === 0)).toBe(false);
});

test('THIS_DAT reads real data, not zeros', () => {
  const bytes = bytesAtVa(image, 0x795000, 32);
  expect(Option.isSome(bytes)).toBe(true);
  expect(Option.getOrThrow(bytes).some((x) => x !== 0)).toBe(true);
});

test('a section whose bytes are genuinely zero still reads as zero', () => {
  // Inf32Dat IS empty in this dump. The point of the fix is to read what is
  // there, which includes reading nothing where there is nothing -- not to
  // make every section look populated.
  const bytes = bytesAtVa(image, 0x796000, 32);
  expect(Option.isSome(bytes)).toBe(true);
  expect(Option.getOrThrow(bytes).every((x) => x === 0)).toBe(true);
});

test('the mapping agrees with the disassembler for the first four sections', () => {
  // These four are where the two mappings coincided, which is why the fault
  // stayed hidden. A regression here would mean the fix moved what worked.
  for (const va of [0x401000, 0x629000, 0x635000, 0x66b000]) {
    const off = Option.getOrThrow(fileOffsetOfVa(image, va));
    const s = image.sections.find((x) => x.va === va)!;
    expect(off).toBe(s.rawOffset + (va - s.va));
  }
});
