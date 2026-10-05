import fs from 'node:fs';
import path from 'node:path';

/**
 * Where the artifacts this module reads live, resolved once so no part of the
 * module reads the environment for itself.
 *
 * Only LOCATIONS belong here. Everything the service records about the subject
 * -- its hash, its size, its image base, its section layout, the compiler
 * builds that produced it -- is derived from the bytes at these paths, because
 * a stored fact sourced from anywhere else was wrong for 1,445 blocks once and
 * nothing offline could tell.
 */
const WORK_ROOT = path.resolve(
  process.env.DECOMP_WORK ?? path.join(import.meta.dir, '../../../../aoe2-in-browser'),
);

/** The binary under reconstruction: the game's code as it ran, decrypted. */
export const SUBJECT_IMAGE_PATH = path.join(WORK_ROOT, 'work/dump/age2_x1-decrypted.bin');

/** 512MB physical RAM image of the machine the subject was dumped from. */
export const GUEST_RAM_PATH = path.join(WORK_ROOT, 'work/dump/guest-ram.bin');

/**
 * EVERY dump on disk, newest capture last.
 *
 * One dump is not enough evidence about the import surface and never could
 * be. SafeDisc records a slot's API in its cache only once the game actually
 * calls through that slot, so a capture answers for the slots the session
 * happened to exercise and is silent about the rest -- 54 of 255 slots are
 * unanswered by the first dump. The remedy is more captures, so the set of
 * dumps is discovered rather than named, and a new one is picked up by
 * existing it rather than by a code change.
 *
 * Each carries its OWN page-directory root and its own loader-DLL base; both
 * move between boots and both are derived per dump.
 */
export const guestRamPaths = (): ReadonlyArray<string> => {
  const dir = path.join(WORK_ROOT, 'work/dump');
  const found = fs
    .readdirSync(dir)
    .filter((n) => /^guest-ram.*\.bin$/.test(n))
    .sort()
    .map((n) => path.join(dir, n));
  // The canonical dump first, so a single-dump read is unchanged and the
  // first answer for any (slot, call site) still comes from it.
  return [
    GUEST_RAM_PATH,
    ...found.filter((f) => f !== GUEST_RAM_PATH),
  ].filter((f) => fs.existsSync(f));
};

/**
 * CR3 of the process the dump was taken from. A fact about the dump, not a
 * choice: the page tables it points at are the only route to the guest's
 * virtual address space.
 */
export const GUEST_CR3 = 0x1624d000;

/**
 * The CRT libraries shipped with the compiler that built the subject. Their
 * objects ARE the game's CRT code, so a match against them identifies a
 * function rather than reconstructing it.
 */
export const CRT_LIBRARY_PATHS: ReadonlyArray<string> = [
  path.join(WORK_ROOT, 'work/toolchain/vc98/VC98/Lib/LIBC.LIB'),
  path.join(WORK_ROOT, 'work/toolchain/vc98/VC98/Lib/LIBCMT.LIB'),
];

/**
 * The span of the image searched for CRT library objects. Generously bounded:
 * a false negative costs an identification, a false positive is refused by the
 * uniqueness test rather than accepted.
 */
export const CRT_SEARCH_LO = 0x600000;
export const CRT_SEARCH_HI = 0x626080;
