import fs from 'node:fs';
import { Effect, Option, Result, Schema } from 'effect';
import { implementing, type EffectGen } from 'effective-modules';
import { modules } from '../index';
import { DbError, type IDb } from '../db/interface';
import {
  GuestMapError,
  SubjectIoError,
  SubjectParseError,
  type AddressClass,
  type CrtIdentificationTotals,
  type GuestModuleTotals,
  type ImportMapTotals,
  type SlotResolutionKey,
  type ImportSurfaceTotals,
  type ISubject,
  type Section,
  type Subject,
  type SubjectError,
} from './interface';
import { AddressClass as Address } from './interface';
import { GuestMemory, hex } from './guest-memory';
import {
  bytesAtVa,
  parseImportSlots,
  parsePeImage,
  parseRichHeader,
  textSpan,
  type PeImage,
} from './pe';
import { ModuleMap } from './module-map';
import { moduleRecordCounts, RedirectTable, SAFEDISC_LOADER_DLL } from './safedisc';
import { buildImportMap } from './import-map';
import { identifyCrtFunctions } from './crt-match';
import {
  CRT_LIBRARY_PATHS,
  CRT_SEARCH_HI,
  CRT_SEARCH_LO,
  GUEST_CR3,
  GUEST_RAM_PATH,
  guestRamPaths,
  SUBJECT_IMAGE_PATH,
} from './paths';

/** A pure parse outcome, raised into the Effect error channel where it fails. */
const required = <A, E>(result: Result.Result<A, E>): Effect.Effect<A, E> =>
  Result.isFailure(result) ? Effect.fail(result.failure) : Effect.succeed(result.success);

/**
 * Map a file rather than read it. The RAM image is 512MB and only a few
 * thousand of its pages are ever touched.
 */
/**
 * Size and modification time, which with the name identify a capture without
 * hashing half a gigabyte.
 *
 * Size alone is not enough and that is not theoretical: every capture of the
 * same region is 512MB, so replacing a weak capture with a strong one left
 * the name and size identical and the re-read never fired.
 */
const fileStamp = (
  path: string,
): Effect.Effect<{ size: number; mtime: number }, SubjectIoError> =>
  Effect.try({
    try: () => {
      const st = fs.statSync(path);
      return { size: st.size, mtime: st.mtimeMs / 1000 };
    },
    catch: (cause) =>
      new SubjectIoError({
        path,
        reason: cause instanceof Error ? cause.message : String(cause),
      }),
  });

const mapFile = (path: string): Effect.Effect<Uint8Array, SubjectIoError> =>
  Effect.try({
    try: () => Bun.mmap(path, { shared: false }),
    catch: (cause) =>
      new SubjectIoError({
        path,
        reason: cause instanceof Error ? cause.message : String(cause),
      }),
  });

const nullable = <A>(value: Option.Option<A>): A | null => Option.getOrElse(value, () => null);

const Count = Schema.Struct({ n: Schema.Number });
const Va = Schema.Struct({ va: Schema.Number });
const Slot = Schema.Struct({ slot: Schema.Number });
const Sha = Schema.Struct({ subject_sha: Schema.String });
const CompIdRow = Schema.Struct({
  record_index: Schema.Number,
  comp_id: Schema.Number,
  prod_id: Schema.Number,
  build: Schema.Number,
  objects: Schema.Number,
});

export class SubjectImpl
  extends implementing(modules.Subject).uses(modules.Db)
  implements ISubject
{
  // ----------------------------------------------------------------- loading

  /**
   * The subject as its own bytes describe it. Nothing here is read from a
   * stored record: a fact sourced anywhere but the bytes was wrong for 1,445
   * blocks once, and nothing offline could tell.
   */
  private *loadSubject(): EffectGen<
    { readonly subject: Subject; readonly image: PeImage },
    SubjectIoError | SubjectParseError
  > {
    const bytes = yield* mapFile(SUBJECT_IMAGE_PATH);
    const image = yield* required(parsePeImage(bytes));
    const span = yield* required(textSpan(image));
    const rich = yield* required(parseRichHeader(bytes));
    return {
      image,
      subject: {
        sha256: new Bun.CryptoHasher('sha256').update(bytes).digest('hex'),
        path: SUBJECT_IMAGE_PATH,
        size: bytes.length,
        imageBase: image.imageBase,
        textLo: span.lo,
        textHi: span.hi,
        sections: image.sections,
        rich,
      },
    };
  }

  /** `dumpPath` defaults to the canonical dump, so every existing caller is
   *  unchanged; the import derivation passes each dump in turn. */
  private *openGuest(dumpPath: string = GUEST_RAM_PATH): EffectGen<
    {
      readonly memory: GuestMemory;
      readonly cr3: number;
      readonly subject: Subject;
      readonly image: PeImage;
    },
    SubjectIoError | SubjectParseError | GuestMapError
  > {
    const loaded = yield* this.loadSubject();
    const ram = yield* mapFile(dumpPath);
    // CR3 is DERIVED, with the recorded value as a hint it still has to earn.
    // A hand-recorded root makes every new dump a code change, and that is
    // why a second capture -- taken to exercise the 54 import slots the
    // protection had not recorded yet -- sat unusable: nobody knew its root.
    //
    // The probe is a PAGE. 16 bytes of MZ header admit eight candidate roots,
    // because eight of the nine processes in the snapshot map the game image;
    // 4KB admits exactly one, and on the known dump that one is the value
    // that had been recorded by other means.
    const located = GuestMemory.locate({
      ram,
      probeVa: loaded.subject.imageBase,
      expect: loaded.image.bytes.slice(0, 4096),
      hint: dumpPath === GUEST_RAM_PATH ? GUEST_CR3 : undefined,
    });
    if (located._tag !== 'Located') {
      return yield* Effect.fail(
        new GuestMapError({
          reason:
            located._tag === 'Ambiguous'
              ? `${located.candidates.length} page-directory roots reproduce the subject's ` +
                `first 4096 bytes at ${hex(loaded.subject.imageBase)} ` +
                `(${located.candidates.map(hex).join(', ')}) in ${dumpPath}; the dump does ` +
                'not say which process to read, and per-process state read from the wrong ' +
                'one would look correct'
              : `no page-directory root, under legacy or PAE paging, reproduces the ` +
                `subject's first 4096 bytes at ${hex(loaded.subject.imageBase)} in ` +
                `${dumpPath}, so nothing read through this dump could be trusted`,
        }),
      );
    }
    return { memory: located.memory, cr3: located.cr3, ...loaded };
  }

  private *rows<A>(
    schema: Schema.Codec<A, unknown, never, never>,
    sql: string,
    params: ReadonlyArray<unknown> = [],
  ): EffectGen<ReadonlyArray<A>, DbError> {
    const raw = yield* this.dependencies.Db.all(sql, params);
    return yield* Effect.mapError(
      Schema.decodeUnknownEffect(Schema.Array(schema))(raw),
      (cause) => new DbError({ sql, reason: `row does not match its schema: ${cause.message}` }),
    );
  }

  // ---------------------------------------------------------------- identity

  /**
   * Record the subject and the compiler builds that produced it.
   *
   * Idempotent: an unchanged file hashes to the same subject and re-records
   * the same facts. A changed file is a DIFFERENT subject, and every verdict
   * proved against the old one is retired by the `superseded` view rather than
   * by anything this writes.
   *
   * The configuration in force names a toolchain as well as a subject, and
   * this module does not own the compiler. Where a configuration already
   * exists it is repointed at this subject; where none does, it stays absent
   * until the module that owns the compiler registers one.
   */
  *ingest(): EffectGen<Subject, SubjectIoError | SubjectParseError | DbError> {
    const { subject } = yield* this.loadSubject();
    const db: IDb = this.dependencies.Db;
    yield* db.tx(function* () {
      yield* db.run(
        `INSERT INTO subjects(sha256, path, size, image_base, text_lo, text_hi, added_at)
         VALUES (?,?,?,?,?,?,?)
         ON CONFLICT(sha256) DO UPDATE SET
           path = excluded.path, size = excluded.size, image_base = excluded.image_base,
           text_lo = excluded.text_lo, text_hi = excluded.text_hi`,
        [
          subject.sha256,
          subject.path,
          subject.size,
          subject.imageBase,
          subject.textLo,
          subject.textHi,
          Date.now() / 1000,
        ],
      );
      yield* db.run('DELETE FROM subject_comp_ids WHERE subject_sha = ?', [subject.sha256]);
      for (const record of subject.rich.records) {
        yield* db.run(
          `INSERT INTO subject_comp_ids(subject_sha, record_index, comp_id, prod_id, build, objects)
           VALUES (?,?,?,?,?,?)`,
          [
            subject.sha256,
            record.index,
            record.compId,
            record.prodId,
            record.build,
            record.objects,
          ],
        );
      }
      yield* db.run('UPDATE current_config SET subject_sha = ?, set_at = ? WHERE only_row = 1', [
        subject.sha256,
        Date.now() / 1000,
      ]);
    });
    return subject;
  }

  *current(): EffectGen<
    Option.Option<Subject>,
    SubjectIoError | SubjectParseError | DbError
  > {
    const configured = yield* this.rows(Sha, 'SELECT subject_sha FROM current_config WHERE only_row = 1');
    if (configured.length === 0) return Option.none();
    const { subject } = yield* this.loadSubject();
    return subject.sha256 === configured[0]!.subject_sha ? Option.some(subject) : Option.none();
  }

  *imageBytes(): EffectGen<Uint8Array, SubjectIoError | SubjectParseError> {
    const { image } = yield* this.loadSubject();
    return image.bytes;
  }

  *bytesAt(input: {
    readonly va: number;
    readonly length: number;
  }): EffectGen<Option.Option<Uint8Array>, SubjectIoError | SubjectParseError> {
    const { image } = yield* this.loadSubject();
    return bytesAtVa(image, input.va, input.length);
  }

  *readGuest(input: {
    readonly va: number;
    readonly length: number;
  }): EffectGen<
    Option.Option<Uint8Array>,
    SubjectIoError | SubjectParseError | GuestMapError
  > {
    const { memory } = yield* this.openGuest();
    return memory.read(input.va, input.length);
  }

  // ------------------------------------------------------------ guest modules

  *mapGuestModules(): EffectGen<GuestModuleTotals, SubjectError | DbError> {
    const { memory, subject } = yield* this.openGuest();
    const map = yield* required(ModuleMap.load(memory, subject.imageBase));
    const db: IDb = this.dependencies.Db;
    yield* db.tx(function* () {
      yield* db.run('DELETE FROM guest_exports WHERE subject_sha = ?', [subject.sha256]);
      yield* db.run('DELETE FROM guest_modules WHERE subject_sha = ?', [subject.sha256]);
      for (const module of map.modules) {
        yield* db.run(
          `INSERT INTO guest_modules(subject_sha, base, size, path, name, export_error)
           VALUES (?,?,?,?,?,?)`,
          [
            subject.sha256,
            module.base,
            module.size,
            module.path,
            module.name,
            nullable(module.exportError),
          ],
        );
        for (const entry of module.exports) {
          yield* db.run(
            `INSERT INTO guest_exports(subject_sha, module_base, ordinal, name, va, forwarder)
             VALUES (?,?,?,?,?,?)`,
            [
              subject.sha256,
              module.base,
              entry.ordinal,
              nullable(entry.name),
              nullable(entry.va),
              nullable(entry.forwarder),
            ],
          );
        }
      }
    });
    const all = map.modules.flatMap((m) => m.exports);
    return {
      pagingMode: memory.mode,
      modules: map.modules.length,
      exports: all.length,
      named: all.filter((e) => Option.isSome(e.name)).length,
      ordinalOnly: all.filter((e) => Option.isNone(e.name)).length,
      forwarders: all.filter((e) => Option.isSome(e.forwarder)).length,
      withoutExportDirectory: map.modules
        .filter((m) => Option.isSome(m.exportError))
        .map((m) => ({
          base: m.base,
          name: m.name,
          reason: Option.getOrElse(m.exportError, () => ''),
        })),
    };
  }

  // -------------------------------------------------------------- import map

  *mapImports(): EffectGen<ImportSurfaceTotals, SubjectError | DbError> {
    const dumps = guestRamPaths();
    const db: IDb = this.dependencies.Db;
    const { subject } = yield* this.loadSubject();

    // Retracted ONCE, before any dump is read, because one pass re-derives
    // every dump's contribution together. The library-derived bindings come
    // out of the LIBRARIES' relocation tables and the image's own bytes,
    // which no dump read touches, so deleting those here would retract
    // evidence this pass says nothing about. A refresh is not a retraction.
    yield* db.tx(function* () {
      yield* db.run('DELETE FROM import_bindings WHERE subject_sha = ? AND evidence <> ?', [
        subject.sha256,
        'library-relocation',
      ]);
      yield* db.run('DELETE FROM safedisc_records WHERE subject_sha = ?', [subject.sha256]);
    });

    // The most informative classification any dump gave each slot.
    //
    // `buildImportMap` classifies from the cache state of the capture it is
    // reading, and that is the right question -- 'no-cached-call-site' means
    // the protection never recorded this slot, which is a fact about the
    // session, not about whether a call site was identified. Reporting the
    // LAST dump's answer beside the UNION of the bindings was the bug; so was
    // my first fix, which recomputed the category from the bindings table and
    // called 117 slots uncached when 48 were, because a slot can have a cache
    // entry and no identified call site.
    //
    // So the per-dump answers are UNIONED, by how much each one says:
    // multiple-apis beats not-an-export beats export-exact beats
    // no-cached-call-site. A slot is only uncached if every capture found it
    // uncached.
    const rank: Readonly<Record<SlotResolutionKey, number>> = {
      'multiple-apis': 3,
      'not-an-export': 2,
      'export-exact': 1,
      'no-cached-call-site': 0,
    };
    const bestResolution = new Map<number, SlotResolutionKey>();

    const byDump: Array<{
      dump: string;
      cr3: number;
      loaderBase: number;
      bindingsOffered: number;
      bindingsAdded: number;
      contradictions: Array<{ slot: number; callSite: number; existing: string; offered: string }>;
    }> = [];
    let last: ImportMapTotals | undefined;

    for (const dumpPath of dumps) {
      const { memory, cr3, image } = yield* this.openGuest(dumpPath);
      const map = yield* required(ModuleMap.load(memory, subject.imageBase));
      const declared = yield* required(parseImportSlots(image));
      // SafeDisc's dispatcher and tables are addressed from the base its
      // loader DLL is actually mapped at in THIS dump, because that base
      // moves between boots -- 0x00CC0000 in the first dump and a different
      // value in the next, which is why it is read per dump rather than
      // recorded.
      const loader = map.moduleNamed(SAFEDISC_LOADER_DLL);
      if (Option.isNone(loader)) {
        return yield* Effect.fail(
          new GuestMapError({
            reason:
              `${SAFEDISC_LOADER_DLL} is not in the loader list of ${dumpPath}, so ` +
              "SafeDisc's redirection tables have no base to be read from",
          }),
        );
      }
      const table = yield* required(
        RedirectTable.read(
          memory,
          loader.value.base,
          moduleRecordCounts(memory, loader.value.base),
        ),
      );
      const imports = yield* required(
        buildImportMap({ image, memory, moduleMap: map, table, declared }),
      );
      last = imports.totals;

      const account = {
        dump: dumpPath.split('/').pop() ?? dumpPath,
        cr3,
        loaderBase: loader.value.base,
        bindingsOffered: 0,
        bindingsAdded: 0,
        contradictions: [] as Array<{
          slot: number; callSite: number; existing: string; offered: string;
        }>,
      };

      for (const slot of imports.slots) {
        const prior = bestResolution.get(slot.va);
        if (prior === undefined || rank[slot.resolution] > rank[prior]) {
          bestResolution.set(slot.va, slot.resolution);
        }
      }

      yield* db.tx(function* () {
        for (const slot of imports.slots) {
          // The declared slot set is a function of the subject's own bytes,
          // so these rows are the same for every dump; `name` is COALESCEd so
          // a name one dump cannot produce survives a pass that re-reads it.
          yield* db.run(
            `INSERT INTO import_slots(subject_sha, slot, dll, target, resolution, name,
                                      descriptor_name, descriptor_ordinal, blocked_by)
             VALUES (?,?,?,?,?,?,?,?,?)
             ON CONFLICT(subject_sha, slot) DO UPDATE SET
               dll = excluded.dll,
               target = COALESCE(excluded.target, import_slots.target),
               resolution = excluded.resolution,
               name = COALESCE(excluded.name, import_slots.name),
               descriptor_name = excluded.descriptor_name,
               descriptor_ordinal = excluded.descriptor_ordinal,
               blocked_by = excluded.blocked_by`,
            [
              subject.sha256,
              slot.va,
              slot.dll,
              nullable(slot.target),
              slot.resolution,
              nullable(slot.name),
              nullable(slot.descriptorName),
              nullable(slot.descriptorOrdinal),
              nullable(slot.blockedBy),
            ],
          );
          if (Option.isSome(slot.record)) {
            const record = slot.record.value;
            // DO NOTHING: a record is per-dump runtime state and the table is
            // keyed by slot, so a second dump's record for a slot the first
            // already answered would collide. The first answer stands.
            yield* db.run(
              `INSERT INTO safedisc_records(subject_sha, slot, module_index, import_index,
                                            record_va, stub_va, placeholder, remapped_index,
                                            resolved_address)
               VALUES (?,?,?,?,?,?,?,?,?)
               ON CONFLICT(subject_sha, slot) DO NOTHING`,
              [
                subject.sha256,
                slot.va,
                record.moduleIndex,
                record.importIndex,
                record.address,
                record.stub,
                record.placeholder,
                record.remappedIndex,
                nullable(record.resolvedAddress),
              ],
            );
          }
          for (const binding of slot.bindings) {
            account.bindingsOffered += 1;
            // ACCUMULATE across dumps. A capture answers only for the slots
            // its session exercised, so a later dump's value is the point --
            // but where an earlier dump already answered the same (slot, call
            // site) pair, the earlier answer stands and a disagreement is
            // RECORDED rather than overwritten: one of the two reads is wrong
            // about that call site, and silently preferring either would hide
            // it.
            const existing = (yield* db.one(
              `SELECT api, evidence FROM import_bindings
                WHERE subject_sha = ? AND slot = ? AND call_site = ?`,
              [subject.sha256, slot.va, binding.callSite],
            )) as { api: string | null; evidence: string } | null;

            const offered = nullable(binding.api);
            if (existing !== null && existing.evidence !== 'library-relocation') {
              if (
                offered !== null &&
                existing.api !== null &&
                existing.api.toLowerCase() !== offered.toLowerCase()
              ) {
                account.contradictions.push({
                  slot: slot.va,
                  callSite: binding.callSite,
                  existing: existing.api,
                  offered,
                });
              }
              continue;
            }

            // A library relocation names a call site from the image's own
            // bytes; the dump's cache is direct evidence of what that site
            // actually resolved to, so it replaces that row. The library
            // derivation re-reads this and reports the pair as agreeing or
            // contradicting, which is where that comparison belongs.
            const added = yield* db.run(
              `INSERT INTO import_bindings(subject_sha, slot, call_site, api, evidence,
                                           target, bucket, call_operand, blocked_by)
               VALUES (?,?,?,?,?,?,?,?,?)
               ON CONFLICT(subject_sha, slot, call_site) DO UPDATE SET
                 api = excluded.api, evidence = excluded.evidence, target = excluded.target,
                 bucket = excluded.bucket, call_operand = excluded.call_operand,
                 blocked_by = excluded.blocked_by`,
              [
                subject.sha256,
                slot.va,
                binding.callSite,
                offered,
                binding.evidence,
                binding.target,
                binding.bucket,
                nullable(binding.callOperand),
                nullable(binding.blockedBy),
              ],
            );
            if (added > 0) account.bindingsAdded += 1;
          }
        }
      });
      // Recorded as the pass runs: these rows are both the report and the
      // trigger. A dump on disk that is not listed here, or listed with a
      // different size or modification time, means the surface has never
      // been read from THAT capture.
      const stamp = yield* fileStamp(dumpPath);
      yield* db.run(
        `INSERT INTO import_dumps(subject_sha, dump, bytes, mtime, cr3, loader_base,
                                  bindings_offered, bindings_added, contradictions, read_at)
         VALUES (?,?,?,?,?,?,?,?,?,?)
         ON CONFLICT(subject_sha, dump) DO UPDATE SET
           bytes = excluded.bytes, mtime = excluded.mtime, cr3 = excluded.cr3,
           loader_base = excluded.loader_base,
           bindings_offered = excluded.bindings_offered,
           bindings_added = excluded.bindings_added,
           contradictions = excluded.contradictions,
           read_at = excluded.read_at`,
        [
          subject.sha256,
          account.dump,
          stamp.size,
          stamp.mtime,
          account.cr3,
          account.loaderBase,
          account.bindingsOffered,
          account.bindingsAdded,
          account.contradictions.length,
          Date.now() / 1000,
        ],
      );
      byDump.push(account);
    }

    if (last === undefined) {
      return yield* Effect.fail(
        new GuestMapError({
          reason: 'no memory dump is on disk, so the import surface cannot be read at all',
        }),
      );
    }
    // EVERYTHING union-scoped is re-read from the table. Taking the binding
    // counts from the union while taking `resolutions` from the last dump's
    // in-memory view put two scopes in one report, and produced a slot
    // classified 'multiple-apis' whose recorded bindings named one API.
    const union = (yield* db.one(
      `SELECT COUNT(*) AS bindings,
              COUNT(api) AS named,
              COUNT(DISTINCT LOWER(api)) AS apis
         FROM import_bindings WHERE subject_sha = ?`,
      [subject.sha256],
    )) as { bindings: number; named: number; apis: number } | null;

    // One further promotion, from what was actually recorded: if the union of
    // bindings names more than one API for a slot, that slot serves several
    // however any single capture classified it. This is the case an
    // API-per-slot model gets wrong, so it must not be lost to a dump that
    // happened to see only one of them.
    const multi = (yield* db.all(
      `SELECT slot FROM import_bindings
        WHERE subject_sha = ?
        GROUP BY slot HAVING COUNT(DISTINCT LOWER(api)) > 1`,
      [subject.sha256],
    )) as ReadonlyArray<{ slot: number }>;
    for (const row of multi) bestResolution.set(row.slot, 'multiple-apis');

    yield* db.tx(function* () {
      for (const [slot, resolution] of bestResolution) {
        yield* db.run(
          'UPDATE import_slots SET resolution = ? WHERE subject_sha = ? AND slot = ?',
          [resolution, subject.sha256, slot],
        );
      }
    });

    const resolutions: Record<SlotResolutionKey, number> = {
      'export-exact': 0,
      'multiple-apis': 0,
      'no-cached-call-site': 0,
      'not-an-export': 0,
    };
    for (const resolution of bestResolution.values()) resolutions[resolution] += 1;

    return {
      ...last,
      resolutions,
      bindings: union?.bindings ?? last.bindings,
      namedBindings: union?.named ?? last.namedBindings,
      distinctApis: union?.apis ?? last.distinctApis,
      byDump,
    };
  }

  // ------------------------------------------------------------ CRT identity

  *identifyCrtFunctions(): EffectGen<
    CrtIdentificationTotals,
    SubjectIoError | SubjectParseError | DbError
  > {
    const { image, subject } = yield* this.loadSubject();
    const region = bytesAtVa(image, CRT_SEARCH_LO, CRT_SEARCH_HI - CRT_SEARCH_LO);
    if (Option.isNone(region)) {
      return yield* Effect.fail(
        new SubjectParseError({
          what: 'CRT search region',
          reason: `${hex(CRT_SEARCH_LO)}..${hex(CRT_SEARCH_HI)} is not covered by any section`,
        }),
      );
    }
    const libraries: { path: string; bytes: Uint8Array }[] = [];
    for (const path of CRT_LIBRARY_PATHS) {
      const bytes = yield* Effect.result(mapFile(path));
      // A library that is not installed is a smaller search, not a failure:
      // every identification still names the archive member it came from.
      if (Result.isSuccess(bytes)) libraries.push({ path, bytes: bytes.success });
    }
    const matched = identifyCrtFunctions({
      region: region.value,
      regionBase: CRT_SEARCH_LO,
      libraries,
    });
    const db: IDb = this.dependencies.Db;
    yield* db.tx(function* () {
      yield* db.run('DELETE FROM crt_identifications WHERE subject_sha = ?', [subject.sha256]);
      for (const found of matched.identifications) {
        yield* db.run(
          `INSERT INTO crt_identifications(subject_sha, va, symbol, library, member, section_size)
           VALUES (?,?,?,?,?,?)`,
          [
            subject.sha256,
            found.va,
            found.symbol,
            found.library,
            found.member,
            found.sectionSize,
          ],
        );
      }
    });
    const overlap = yield* this.rows(
      Count,
      `SELECT COUNT(*) AS n FROM crt_identifications c
       JOIN functions f ON f.subject_sha = c.subject_sha AND f.va = c.va
       WHERE c.subject_sha = ?`,
      [subject.sha256],
    );
    return {
      sectionsPlacedUniquely: matched.sectionsPlacedUniquely,
      sectionsRefused: matched.sectionsRefused,
      addressesNamed: matched.identifications.length,
      declaredFunctionsIdentified: overlap[0]?.n ?? 0,
    };
  }

  // ------------------------------------------------------------ classification

  *classifyAddresses(
    vas: ReadonlyArray<number>,
  ): EffectGen<ReadonlyArray<AddressClass>, SubjectIoError | SubjectParseError | DbError> {
    const { subject } = yield* this.loadSubject();
    const entries = new Set(
      (
        yield* this.rows(Va, 'SELECT va FROM functions WHERE subject_sha = ?', [subject.sha256])
      ).map((r) => r.va),
    );
    const slots = new Set(
      (
        yield* this.rows(Slot, 'SELECT slot FROM import_slots WHERE subject_sha = ?', [
          subject.sha256,
        ])
      ).map((r) => r.slot),
    );
    return vas.map((va) => classify(va, { entries, slots, subject }));
  }

  /** The Rich header records, as stored. */
  *compIds(): EffectGen<
    ReadonlyArray<{
      readonly prodId: number;
      readonly build: number;
      readonly objects: number;
    }>,
    SubjectIoError | SubjectParseError | DbError
  > {
    const { subject } = yield* this.loadSubject();
    const stored = yield* this.rows(
      CompIdRow,
      `SELECT record_index, comp_id, prod_id, build, objects FROM subject_comp_ids
       WHERE subject_sha = ? ORDER BY record_index`,
      [subject.sha256],
    );
    return stored.map((r) => ({ prodId: r.prod_id, build: r.build, objects: r.objects }));
  }
}

const classify = (
  va: number,
  known: {
    readonly entries: ReadonlySet<number>;
    readonly slots: ReadonlySet<number>;
    readonly subject: Subject;
  },
): AddressClass => {
  // MSVC emits a relocation for `fs:[0]` exception registration (64 a1 00 00
  // 00 00), so it looks like a reference to address 0. It is a segment offset,
  // and every /GX prologue has two of them.
  if (va === 0) return Address.ExceptionRegistration();
  if (known.entries.has(va)) return Address.FunctionEntry();
  if (known.slots.has(va)) return Address.ImportSlot();
  if (va >= known.subject.textLo && va < known.subject.textHi) return Address.TextNonEntry();
  const section: Section | undefined = known.subject.sections.find(
    (s) => va >= s.va && va < s.va + s.virtualSize,
  );
  return section === undefined ? Address.Unknown() : Address.Data({ section: section.name });
};
