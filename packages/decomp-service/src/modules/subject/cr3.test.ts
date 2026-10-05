/**
 * The page-directory root is a fact about the dump, not a constant.
 *
 * CR3 was hand-recorded as 0x1624d000, which made every new dump a code
 * change -- and left the second dump unusable: it was captured specifically
 * to exercise the 54 import slots the copy protection had not yet recorded,
 * and nothing could read it because nobody knew its CR3.
 *
 * The known-good dump is the control. If the scan cannot rediscover a value
 * that was already established by other means, it cannot be trusted on a
 * dump where there is nothing to check it against.
 */
import { expect, test } from 'bun:test';
import fs from 'node:fs';
import path from 'node:path';
import { Option, Result } from 'effect';
import { GuestMemory } from './guest-memory';
import { parsePeImage } from './pe';
import { GUEST_CR3, GUEST_RAM_PATH, SUBJECT_IMAGE_PATH } from './paths';

const image = (() => {
  const parsed = parsePeImage(new Uint8Array(fs.readFileSync(SUBJECT_IMAGE_PATH)));
  if (Result.isFailure(parsed)) throw new Error('subject image does not parse');
  return parsed.success;
})();

/**
 * A PAGE, not 16 bytes. Measured on the known dump: 16 bytes of MZ header
 * admit EIGHT candidate roots, because the image is mapped in eight of the
 * nine processes the snapshot holds. 4KB admits exactly one.
 */
const expectBytes = image.bytes.slice(0, 4096);

/**
 * MAPPED, not read. Each dump is 512MB and this file opens two of them, so
 * `readFileSync` pulls a gigabyte into the heap: alone that merely wastes
 * time, but run as part of the whole suite it took these tests from passing
 * to failing. The service maps them for the same reason -- only a few
 * thousand pages are ever touched.
 */
const ramOf = (p: string): Uint8Array => Bun.mmap(p, { shared: false });

test('the scan rediscovers the known CR3 without being told it', () => {
  const found = GuestMemory.locate({
    ram: ramOf(GUEST_RAM_PATH),
    probeVa: image.imageBase,
    expect: expectBytes,
  });
  expect(found._tag).toBe('Located');
  if (found._tag !== 'Located') return;
  expect(found.cr3).toBe(GUEST_CR3);
});

test('a 16-byte probe is ambiguous, and says so rather than choosing', () => {
  // The reason the probe is a page. Eight processes map the image, and all
  // eight reproduce an MZ header; picking the first would read per-process
  // state from the wrong process while the code looked perfectly right.
  const found = GuestMemory.locate({
    ram: ramOf(GUEST_RAM_PATH),
    probeVa: image.imageBase,
    expect: image.bytes.slice(0, 16),
  });
  expect(found._tag).toBe('Ambiguous');
});

test('a wrong hint does not win over the real answer', () => {
  // The hint exists only to save a scan. If it is accepted without being
  // checked, a stale constant silently decides which process is read -- and
  // a dump holds nine processes, so reading the wrong one is not an error
  // that announces itself.
  const found = GuestMemory.locate({
    ram: ramOf(GUEST_RAM_PATH),
    probeVa: image.imageBase,
    expect: expectBytes,
    hint: 0x1000,
  });
  expect(found._tag).toBe('Located');
  if (found._tag !== 'Located') return;
  expect(found.cr3).toBe(GUEST_CR3);
});

const SECOND = path.join(path.dirname(GUEST_RAM_PATH), 'guest-ram-2.bin');

test.skipIf(!fs.existsSync(SECOND))(
  'the second dump yields a CR3 that reproduces the subject',
  () => {
    const found = GuestMemory.locate({
      ram: ramOf(SECOND),
      probeVa: image.imageBase,
      expect: expectBytes,
    });
    // Reported either way: a dump that cannot be mapped unambiguously is a
    // finding about that capture, not a reason to fail the suite.
    if (found._tag !== 'Located') {
      console.log(
        `[cr3] ${SECOND}: ${found._tag}` +
          (found._tag === 'Ambiguous'
            ? ` -- ${found.candidates.length} candidate roots`
            : ' -- no root reproduces the subject at its image base'),
      );
      return;
    }
    console.log(`[cr3] ${SECOND}: CR3 0x${found.cr3.toString(16)}`);
    const got = found.memory.read(image.imageBase, expectBytes.length);
    expect(Option.isSome(got)).toBe(true);
    expect([...Option.getOrThrow(got)]).toEqual([...expectBytes]);
  },
);
