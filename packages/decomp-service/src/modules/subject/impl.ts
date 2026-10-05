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
import { moduleRecordCounts, RedirectTable } from './safedisc';
import { buildImportMap } from './import-map';
import { identifyCrtFunctions } from './crt-match';
import {
  CRT_LIBRARY_PATHS,
  CRT_SEARCH_HI,
  CRT_SEARCH_LO,
  GUEST_CR3,
  GUEST_RAM_PATH,
  SUBJECT_IMAGE_PATH,
} from './paths';

/** A pure parse outcome, raised into the Effect error channel where it fails. */
const required = <A, E>(result: Result.Result<A, E>): Effect.Effect<A, E> =>
  Result.isFailure(result) ? Effect.fail(result.failure) : Effect.succeed(result.success);

/**
 * Map a file rather than read it. The RAM image is 512MB and only a few
 * thousand of its pages are ever touched.
 */
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

  private *openGuest(): EffectGen<
    {
      readonly memory: GuestMemory;
      readonly subject: Subject;
      readonly image: PeImage;
    },
    SubjectIoError | SubjectParseError | GuestMapError
  > {
    const loaded = yield* this.loadSubject();
    const ram = yield* mapFile(GUEST_RAM_PATH);
    const memory = GuestMemory.detect({
      ram,
      cr3: GUEST_CR3,
      probeVa: loaded.subject.imageBase,
      expect: loaded.image.bytes.slice(0, 16),
    });
    if (Option.isNone(memory)) {
      return yield* Effect.fail(
        new GuestMapError({
          reason:
            `neither legacy nor PAE paging through CR3 ${hex(GUEST_CR3)} reproduces the ` +
            `subject's first 16 bytes at ${hex(loaded.subject.imageBase)}, so nothing read ` +
            'through either could be trusted',
        }),
      );
    }
    return { memory: memory.value, ...loaded };
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

  *mapImports(): EffectGen<ImportMapTotals, SubjectError | DbError> {
    const { memory, subject, image } = yield* this.openGuest();
    const map = yield* required(ModuleMap.load(memory, subject.imageBase));
    const declared = yield* required(parseImportSlots(image));
    const table = yield* required(RedirectTable.read(memory, moduleRecordCounts(memory)));
    const imports = yield* required(
      buildImportMap({ image, memory, moduleMap: map, table, declared }),
    );
    const db: IDb = this.dependencies.Db;
    yield* db.tx(function* () {
      // Scoped to the rows this derivation produces. The library-derived
      // bindings come out of the LIBRARIES' relocation tables and the image's
      // own bytes, neither of which this read touches, so deleting them here
      // would retract evidence a refresh says nothing about. A refresh is not
      // a retraction.
      yield* db.run('DELETE FROM import_bindings WHERE subject_sha = ? AND evidence <> ?', [
        subject.sha256,
        'library-relocation',
      ]);
      yield* db.run('DELETE FROM safedisc_records WHERE subject_sha = ?', [subject.sha256]);
      // Upserted rather than deleted and reinserted, for the same reason: a
      // name this read cannot produce must survive it. The declared slot set
      // is a function of the subject's own bytes, which `subject_sha` pins, so
      // there is no row here that this read could have made obsolete.
      for (const slot of imports.slots) {
        yield* db.run(
          `INSERT INTO import_slots(subject_sha, slot, dll, target, resolution, name,
                                    descriptor_name, descriptor_ordinal, blocked_by)
           VALUES (?,?,?,?,?,?,?,?,?)
           ON CONFLICT(subject_sha, slot) DO UPDATE SET
             dll = excluded.dll, target = excluded.target, resolution = excluded.resolution,
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
          yield* db.run(
            `INSERT INTO safedisc_records(subject_sha, slot, module_index, import_index,
                                          record_va, stub_va, placeholder, remapped_index,
                                          resolved_address)
             VALUES (?,?,?,?,?,?,?,?,?)`,
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
          yield* db.run(
            // The dump's cache is direct evidence of what a call site actually
            // resolved to, so where it covers a site a library relocation also
            // names, it replaces that row rather than colliding with it. The
            // library derivation then re-reads this and reports the pair as
            // agreeing or contradicting, which is where that comparison
            // belongs.
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
              nullable(binding.api),
              binding.evidence,
              binding.target,
              binding.bucket,
              nullable(binding.callOperand),
              nullable(binding.blockedBy),
            ],
          );
        }
      }
    });
    return imports.totals;
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
