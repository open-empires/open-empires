/**
 * The Subject module against the facts it is supposed to recover.
 *
 * Every number here was produced by the Python tooling this module replaces,
 * and is asserted rather than described: a port that "looks right" and counts
 * differently is a port that is wrong, and the project has already shipped
 * thousands of results that nothing checked.
 *
 * The test needs the 512MB RAM image and the VC98 libraries. Where they are
 * absent it SKIPS LOUDLY rather than passing: a green run against missing
 * inputs is the worst outcome available.
 */
import { afterAll, expect, test as buntest } from 'bun:test';
import { Effect, Layer, Option, pipe } from 'effect';
import type { EffectGen } from 'effective-modules';
import fs from 'node:fs';
import path from 'node:path';
import type { Modules } from '../index';
import { CRT_LIBRARY_PATHS, GUEST_RAM_PATH, SUBJECT_IMAGE_PATH } from './paths';

/** The sha256 the subject was recorded under when the dump was taken. */
const SUBJECT_SHA = '71cfff63113ab46d99f22fce5b987143de8c1582a7bd4dce10776a3ddffd7d4d';
const INVENTORY = path.join(path.dirname(SUBJECT_IMAGE_PATH), '../../decomp/functions.json');

const inputs = [SUBJECT_IMAGE_PATH, GUEST_RAM_PATH, ...CRT_LIBRARY_PATHS, INVENTORY];
const missing = inputs.filter((p) => !fs.existsSync(p));

if (missing.length > 0) {
  buntest('subject inputs are present', () => {
    throw new Error(
      `cannot verify the Subject port: ${missing.join(', ')} absent. ` +
        'Nothing below ran; this is a skip, not a pass.',
    );
  });
} else {
  // db/impl resolves its path once, at import, so the scratch database has to
  // be chosen before that module is loaded.
  const dbPath = path.join(
    process.env.TMPDIR ?? '/tmp',
    `decomp-subject-verify-${process.pid}.db`,
  );
  for (const suffix of ['', '-wal', '-shm']) fs.rmSync(`${dbPath}${suffix}`, { force: true });
  process.env.DECOMP_DB = dbPath;

  const { DbImpl, openPath } = await import('../db/impl');

  // NAME THE SUBJECT. Setting DECOMP_DB and re-importing only worked while
  // this module had not been imported yet; Bun runs the suite in one process,
  // so when any other test file loaded db/impl first, the import returned the
  // cached module holding the LIVE path and this fixture wrote 6,570 rows
  // into the system of record -- resurrecting addresses recorded as not being
  // function entries, and failing about one run in three on the live write
  // lock. The connection is now keyed by path, and this asserts it, so the
  // fixture can never again be about the wrong file.
  if (openPath() !== dbPath) {
    throw new Error(
      `this test must run against a scratch database. Expected ${dbPath}, ` +
        `the connection resolves to ${openPath()}.`,
    );
  }

  const { SubjectImpl } = await import('./impl');
  const { modules } = await import('../index');

  type Needs = Modules.Db | Modules.Subject;
  const layer = pipe(SubjectImpl.Layer, Layer.provideMerge(DbImpl.Layer));
  const run = <A, E>(body: () => EffectGen<A, E, Needs>): Promise<A> => {
    const program: Effect.Effect<A, E, Needs> = Effect.fn(body)();
    return Effect.runPromise(Effect.provide(program, layer));
  };

  const test = buntest;
  // The scratch database is transient by construction, not by anyone
  // remembering: a directory full of old verification databases makes the one
  // that matters invisible.
  afterAll(() => {
    for (const suffix of ['', '-wal', '-shm']) fs.rmSync(`${dbPath}${suffix}`, { force: true });
  });

  // The inventory is another module's product; it is fixture data here, and
  // only the CRT overlap count depends on it.
  const inventory = (await Bun.file(INVENTORY).json()) as {
    functions: { va: number; size: number }[];
  };

  await run(function* () {
    const db = yield* modules.Db;
    yield* db.migrate();
    yield* db.run(
      `INSERT OR IGNORE INTO subjects(sha256, path, size, image_base, text_lo, text_hi, added_at)
       VALUES (?,?,?,?,?,?,?)`,
      [SUBJECT_SHA, SUBJECT_IMAGE_PATH, 0, 0x400000, 0x401000, 0x62847d, 0],
    );
    yield* db.tx(function* () {
      for (const f of inventory.functions) {
        yield* db.run(
          `INSERT OR IGNORE INTO functions(subject_sha, va, size, discovered_by)
           VALUES (?,?,?,?)`,
          [SUBJECT_SHA, f.va, f.size, 'inventory'],
        );
      }
    });
  });

  const subject = await run(function* () {
    return yield* (yield* modules.Subject).ingest();
  });
  const compIds = await run(function* () {
    return yield* (yield* modules.Subject).compIds();
  });
  const guestModules = await run(function* () {
    return yield* (yield* modules.Subject).mapGuestModules();
  });
  const imports = await run(function* () {
    return yield* (yield* modules.Subject).mapImports();
  });
  const crt = await run(function* () {
    return yield* (yield* modules.Subject).identifyCrtFunctions();
  });
  const image = new Uint8Array(await Bun.file(SUBJECT_IMAGE_PATH).arrayBuffer());

  // --------------------------------------------------------------- identity

  test('the subject hashes to the recorded dump', () => {
    expect(subject.sha256).toBe(SUBJECT_SHA);
    expect(subject.size).toBe(3821568);
    expect(subject.imageBase).toBe(0x400000);
  });

  test('the .text span comes from the section header', () => {
    expect(subject.textLo).toBe(0x401000);
    expect(subject.textHi).toBe(0x62847d);
  });

  // ----------------------------------------------- guestmem: the page tables

  test('the paging mode is pinned by evidence, and it is legacy', () => {
    expect(guestModules.pagingMode).toBe('legacy');
  });

  test('the image base reads back byte-for-byte through the page tables', async () => {
    const read = await run(function* () {
      return yield* (yield* modules.Subject).readGuest({ va: 0x400000, length: 64 });
    });
    expect(Option.isSome(read)).toBe(true);
    expect([...Option.getOrElse(read, () => new Uint8Array())]).toEqual([
      ...image.subarray(0, 64),
    ]);
  });

  test('0x401000 reads back byte-for-byte through the page tables', async () => {
    const read = await run(function* () {
      return yield* (yield* modules.Subject).readGuest({ va: 0x401000, length: 32 });
    });
    expect([...Option.getOrElse(read, () => new Uint8Array())]).toEqual([
      ...image.subarray(0x1000, 0x1000 + 32),
    ]);
  });

  test('a non-resident page is absent, not zeros', async () => {
    const read = await run(function* () {
      return yield* (yield* modules.Subject).readGuest({ va: 0x7f000000, length: 16 });
    });
    expect(Option.isNone(read)).toBe(true);
  });

  // ------------------------------------------------- toolchain: Rich header

  test('the Rich header names both compiler builds and their object counts', () => {
    const found = compIds.filter((r) => r.build === 8168 || r.build === 8447);
    expect(found).toEqual([
      { prodId: 10, build: 8168, objects: 153 },
      { prodId: 11, build: 8168, objects: 16 },
      { prodId: 10, build: 8447, objects: 2 },
      { prodId: 11, build: 8447, objects: 304 },
    ]);
  });

  // ------------------------------------------------------ modmap: the guest

  test('56 modules from the PEB loader list, with 11,591 exports', () => {
    expect(guestModules.modules).toBe(56);
    expect(guestModules.exports).toBe(11591);
    expect(guestModules.named).toBe(10379);
    expect(guestModules.ordinalOnly).toBe(1212);
    expect(guestModules.forwarders).toBe(124);
  });

  test('the four modules with no export directory are named, not just counted', () => {
    expect(guestModules.withoutExportDirectory.map((m) => m.name).sort()).toEqual([
      'AGE2_X1.ICD',
      'language.dll',
      'language_x1.dll',
      'language_x1_p1.dll',
    ]);
  });

  // ------------------------------------------------- importnames: the join

  test('255 IAT slots, all readable', () => {
    expect(imports.slots).toBe(255);
    expect(imports.unreadableSlots).toBe(0);
    expect(imports.firstSlot).toBe(0x635000);
    expect(imports.lastSlot).toBe(0x635428);
  });

  test('every slot is answered in exactly one of four ways', () => {
    expect(imports.resolutions).toEqual({
      'export-exact': 150,
      'multiple-apis': 51,
      'no-cached-call-site': 54,
      'not-an-export': 0,
    });
  });

  test('297 call-site bindings, all named, 222 corroborated by the call operand', () => {
    expect(imports.bindings).toBe(297);
    expect(imports.namedBindings).toBe(297);
    expect(imports.evidence).toEqual({
      'call-operand-verified': 222,
      'record-entry': 75,
      'call-operand-names-another-slot': 0,
    });
  });

  test('187 distinct APIs are named', () => {
    expect(imports.distinctApis).toBe(187);
  });

  test('each SafeDisc module index is verified against one single DLL', () => {
    expect(imports.moduleIndexToDll).toEqual([
      { moduleIndex: 0, dll: 'KERNEL32.dll' },
      { moduleIndex: 1, dll: 'USER32.dll' },
    ]);
  });

  test('a slot serving several APIs is recorded per call site, never per slot', async () => {
    const perSlot = await run(function* () {
      const db = yield* modules.Db;
      return yield* db.all(
        `SELECT s.slot, COUNT(DISTINCT b.api) AS apis
         FROM import_slots s JOIN import_bindings b
           ON b.subject_sha = s.subject_sha AND b.slot = s.slot
         WHERE s.subject_sha = ? AND s.resolution = 'multiple-apis'
         GROUP BY s.slot`,
        [subject.sha256],
      );
    });
    expect(perSlot.length).toBe(51);
    for (const row of perSlot as { apis: number }[]) expect(row.apis).toBeGreaterThan(1);
  });

  // ---------------------------------------------------- crtmatch: libraries

  test('518 library sections place uniquely, naming 297 addresses', () => {
    expect(crt.sectionsPlacedUniquely).toBe(518);
    expect(crt.sectionsRefused).toBe(1562);
    expect(crt.addressesNamed).toBe(297);
    expect(crt.declaredFunctionsIdentified).toBe(238);
  });

  // ------------------------------------------------------------- classifying

  test('an address is classified by what the project declares, not by guess', async () => {
    const classes = await run(function* () {
      return yield* (yield* modules.Subject).classifyAddresses([
        0, 0x401000, 0x635000, 0x66b000, 0x7a1000, 0xcc3270,
      ]);
    });
    expect(classes.map((c) => c._tag)).toEqual([
      'ExceptionRegistration',
      'FunctionEntry',
      'ImportSlot',
      'Data',
      'Data',
      'Unknown',
    ]);
  });
}
