import { Effect, Option, Result, Schema } from 'effect';
import { implementing, type EffectGen } from 'effective-modules';
import { modules } from '../index';
import type { IDb } from '../db/interface';
import { rows } from '../db/rows';
import { CRT_LIBRARY_PATHS } from '../subject/paths';
import { NoCurrentSubject, SubjectIoError } from '../subject/interface';
import {
  deriveLibraryImportReferences,
  type PlacedIdentification,
} from './library-relocations';
import type {
  IImportNames,
  ImportNameReport,
  ImportNamesError,
  LibraryImportReference,
  LibraryImportRefusal,
  ReferenceForm,
  SlotApiDisagreement,
} from './interface';

/** The evidence value these bindings are written under, and the only rows in
 *  `import_bindings` this module owns. */
const LIBRARY_RELOCATION = 'library-relocation';

/** A binding is a CALL site. The other two forms read the slot into a register
 *  or onto the stack, and the call they feed is somewhere else. */
const CALL_FORMS: ReadonlySet<ReferenceForm> = new Set<ReferenceForm>([
  'call-indirect',
  'jmp-indirect',
]);

const IdentificationRow = Schema.Struct({
  va: Schema.Number,
  symbol: Schema.String,
  library: Schema.String,
  member: Schema.String,
});

const SlotRow = Schema.Struct({
  slot: Schema.Number,
  dll: Schema.NullOr(Schema.String),
  name: Schema.NullOr(Schema.String),
});

/**
 * What `import_slot_apis` answers for one slot: how many APIs it serves, one
 * of their names when there is only one, and whether the DUMP contributed any
 * of them. The last is the provenance: a slot the dump names nothing for is
 * named by the libraries alone, and that stays true after the name is stored,
 * so re-running reports the same answer instead of calling it pre-existing.
 */
const SlotApiRow = Schema.Struct({
  slot: Schema.Number,
  api: Schema.String,
  apis: Schema.Number,
  cached_rows: Schema.Number,
});

/** One (slot, call site) both sources name, as `import_binding_agreement`
 *  judges it, with every export at the address the call resolved to. */
const AgreementRow = Schema.Struct({
  slot: Schema.Number,
  call_site: Schema.Number,
  cached_api: Schema.String,
  cached_target: Schema.Number,
  library_api: Schema.String,
  verdict: Schema.Literals(['agrees', 'same-address-other-name', 'disagrees']),
  target_exports: Schema.NullOr(Schema.String),
});

const CachedSitesRow = Schema.Struct({ slot: Schema.Number, sites: Schema.Number });

/** A call site this derivation must not write, because the dump already
 *  answers it. */
const pairKey = (slot: number, callSite: number): string => `${slot}:${callSite}`;

const ReferenceRow = Schema.Struct({
  site: Schema.Number,
  slot: Schema.Number,
  api: Schema.String,
  decorated: Schema.String,
  library: Schema.String,
  member: Schema.String,
  section_index: Schema.Number,
  section_base: Schema.Number,
  relocation_offset: Schema.Number,
  form: Schema.Literals(['call-indirect', 'jmp-indirect', 'load-pointer', 'push-pointer']),
});

/**
 * Map a library rather than read it, as the CRT matcher does: the archives are
 * tens of megabytes and only a few hundred members are ever touched.
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

const qualified = (dll: string, api: string): string => `${dll}!${api}`;

export class ImportNamesImpl
  extends implementing(modules.ImportNames).uses(modules.Db, modules.Subject)
  implements IImportNames
{
  *nameImportSlots(): EffectGen<ImportNameReport, ImportNamesError> {
    const db: IDb = this.dependencies.Db;
    const maybeSubject = yield* this.dependencies.Subject.current();
    if (Option.isNone(maybeSubject)) {
      return yield* Effect.fail(
        new NoCurrentSubject({
          reason:
            'no subject is configured, so there is no import table to name and no image ' +
            'to confirm a placement against',
        }),
      );
    }
    const subject = maybeSubject.value;

    const identifications: ReadonlyArray<PlacedIdentification> = yield* rows(
      db,
      IdentificationRow,
      `SELECT va, symbol, library, member FROM crt_identifications
       WHERE subject_sha = ? ORDER BY va`,
      [subject.sha256],
    );
    const slotRows = yield* rows(
      db,
      SlotRow,
      'SELECT slot, dll, name FROM import_slots WHERE subject_sha = ? ORDER BY slot',
      [subject.sha256],
    );
    const slots = new Map(slotRows.map((r) => [r.slot, r]));

    const text = yield* this.dependencies.Subject.bytesAt({
      va: subject.textLo,
      length: subject.textHi - subject.textLo,
    });
    if (Option.isNone(text)) {
      return yield* Effect.fail(
        new SubjectIoError({
          path: subject.path,
          reason:
            `the recorded .text span 0x${subject.textLo.toString(16)}..` +
            `0x${subject.textHi.toString(16)} is not covered by any section of the image`,
        }),
      );
    }

    // A library that is not installed is a smaller search, not a failure --
    // every reference names the archive member it came from, so what was read
    // is always visible. The refusal rows say which members could not be
    // opened, so a missing archive cannot look like an absence of evidence.
    const libraries: { path: string; bytes: Uint8Array }[] = [];
    for (const path of CRT_LIBRARY_PATHS) {
      const mapped = yield* Effect.result(mapFile(path));
      if (Result.isSuccess(mapped)) libraries.push({ path, bytes: mapped.success });
    }

    const derived = deriveLibraryImportReferences({
      identifications,
      libraries,
      text: { lo: subject.textLo, bytes: text.value },
      slots: new Set(slots.keys()),
    });

    const callSites = derived.references.filter((r) => CALL_FORMS.has(r.form));
    const sha = subject.sha256;
    yield* db.tx(function* () {
      yield* db.run('DELETE FROM library_import_references WHERE subject_sha = ?', [sha]);
      yield* db.run('DELETE FROM library_import_refusals WHERE subject_sha = ?', [sha]);
      yield* db.run('DELETE FROM import_bindings WHERE subject_sha = ? AND evidence = ?', [
        sha,
        LIBRARY_RELOCATION,
      ]);
      for (const reference of derived.references) {
        yield* db.run(
          `INSERT INTO library_import_references(subject_sha, site, slot, api, decorated,
                                                 library, member, section_index, section_base,
                                                 relocation_offset, form)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
          [
            sha,
            reference.site,
            reference.slot,
            reference.api,
            reference.decorated,
            reference.library,
            reference.member,
            reference.sectionIndex,
            reference.sectionBase,
            reference.relocationOffset,
            reference.form,
          ],
        );
      }
      for (const refusal of derived.refusals) {
        yield* db.run(
          `INSERT INTO library_import_refusals(subject_sha, library, member, section_index,
                                               relocation_offset, decorated, reason)
           VALUES (?,?,?,?,?,?,?)`,
          [
            sha,
            refusal.library,
            refusal.member,
            refusal.sectionIndex,
            refusal.relocationOffset < 0 ? null : refusal.relocationOffset,
            refusal.decorated === '' ? null : refusal.decorated,
            refusal.reason,
          ],
        );
      }
    });

    // Asked AFTER the references are written and BEFORE any binding of this
    // derivation is, because `import_binding_agreement` is the one place the
    // two sources are held against each other -- and it must see only the
    // dump's rows on the other side. A pair it already answers is left to the
    // dump: the cache is direct evidence of what that call actually resolved
    // to, and overwriting it would destroy a contradiction rather than report
    // one.
    const agreements = yield* rows(
      db,
      AgreementRow,
      `SELECT a.slot, a.call_site, a.cached_api, a.cached_target, a.library_api, a.verdict,
              (SELECT GROUP_CONCAT(e.name, ', ') FROM guest_exports e
                WHERE e.subject_sha = a.subject_sha AND e.va = a.cached_target
                  AND e.name IS NOT NULL) AS target_exports
       FROM import_binding_agreement a WHERE a.subject_sha = ? ORDER BY a.slot, a.call_site`,
      [subject.sha256],
    );
    const answeredByDump = new Set(agreements.map((a) => pairKey(a.slot, a.call_site)));
    const bindings = callSites.filter((r) => !answeredByDump.has(pairKey(r.slot, r.site)));

    yield* db.tx(function* () {
      for (const binding of bindings) {
        const dll = slots.get(binding.slot)?.dll;
        yield* db.run(
          // DO NOTHING on conflict. Without it this INSERT raised
          // "UNIQUE constraint failed: import_bindings.subject_sha, slot,
          // call_site" on every tick after the first, and because it runs
          // inside a transaction the WHOLE batch rolled back -- so the
          // derivation recorded nothing, forever, while the worker logged the
          // same ten slots as freshly named every twenty minutes. An existing
          // binding is deliberately not overwritten: where this derivation
          // and the memory dump disagree about a call site, that is a finding,
          // and `import_binding_agreement` is the view that reports it.
          `INSERT INTO import_bindings(subject_sha, slot, call_site, api, evidence)
           VALUES (?,?,?,?,?)
           ON CONFLICT(subject_sha, slot, call_site) DO NOTHING`,
          [
            sha,
            binding.slot,
            binding.site,
            dll === null || dll === undefined ? binding.api : qualified(dll, binding.api),
            LIBRARY_RELOCATION,
          ],
        );
      }
    });

    // Asked AFTER the references are written, because `import_slot_apis` is
    // the one place "which APIs does this slot serve" is answered and it reads
    // them. Deciding it here from the in-memory derivation instead would be a
    // second implementation of the same question.
    const slotApis = yield* rows(
      db,
      SlotApiRow,
      `SELECT slot, MIN(api) AS api, COUNT(DISTINCT LOWER(api)) AS apis,
              SUM(source = 'safedisc-cache') AS cached_rows
       FROM import_slot_apis WHERE subject_sha = ? GROUP BY slot`,
      [subject.sha256],
    );
    const apisPerSlot = new Map(slotApis.map((r) => [r.slot, r]));

    // A slot is named by THIS derivation when the libraries are the only
    // source that names anything through it and they name exactly one API.
    // Where the dump names one too and they agree, the name is already there
    // and this is a reproduction, not a new name.
    const named = [...apisPerSlot.values()]
      .filter((answer) => answer.apis === 1 && answer.cached_rows === 0)
      .map((answer) => ({ slot: answer.slot, name: answer.api }))
      .sort((a, b) => a.slot - b.slot);
    // What the UPDATE actually changed, not what it was asked to do. The
    // UPDATE carries `AND name IS NULL`, so a slot already named is a no-op
    // -- yet `named` is a query over `import_slot_apis` that keeps listing it,
    // so the worker reported "10 slot(s) named from library relocations" with
    // the same ten slots on every tick for as long as it had been running.
    // Nothing was wrong with the derivation; the report was counting its
    // intent.
    const newlyNamed: { slot: number; name: string }[] = [];
    yield* db.tx(function* () {
      for (const entry of named) {
        const changed = yield* db.run(
          'UPDATE import_slots SET name = ? WHERE subject_sha = ? AND slot = ? AND name IS NULL',
          [entry.name, sha, entry.slot],
        );
        if (changed > 0) newlyNamed.push(entry);
      }
    });

    const cachedSitesPerSlot = new Map<number, number>();
    for (const row of yield* rows(
      db,
      CachedSitesRow,
      `SELECT slot, COUNT(*) AS sites FROM import_bindings
       WHERE subject_sha = ? AND evidence <> ? GROUP BY slot`,
      [subject.sha256, LIBRARY_RELOCATION],
    )) {
      cachedSitesPerSlot.set(row.slot, row.sites);
    }

    const exportsAt = (row: { readonly target_exports: string | null }): ReadonlyArray<string> =>
      row.target_exports === null ? [] : row.target_exports.split(', ');

    return report({
      identifications: identifications.length,
      derived,
      bindingsWritten: bindings.length,
      bindingsReproduced: agreements.filter((a) => a.verdict === 'agrees').length,
      bindingsAliasResolved: agreements
        .filter((a) => a.verdict === 'same-address-other-name')
        .map((a) => ({
          slot: a.slot,
          callSite: a.call_site,
          cachedApi: a.cached_api,
          libraryApi: a.library_api,
          cachedTargetExports: exportsAt(a),
        })),
      bindingDisagreements: agreements
        .filter((a) => a.verdict === 'disagrees')
        .map((a) => ({
          slot: a.slot,
          callSite: a.call_site,
          cachedApi: a.cached_api,
          cachedTarget: a.cached_target,
          cachedTargetExports: exportsAt(a),
          libraryApi: a.library_api,
        })),
      slots,
      apisPerSlot,
      named,
      newlyNamed,
      cached: cachedSitesPerSlot,
    });
  }

  *references(): EffectGen<ReadonlyArray<LibraryImportReference>, ImportNamesError> {
    const maybeSubject = yield* this.dependencies.Subject.current();
    if (Option.isNone(maybeSubject)) {
      return yield* Effect.fail(
        new NoCurrentSubject({ reason: 'no subject is configured, so no derivation is in force' }),
      );
    }
    const stored = yield* rows(
      this.dependencies.Db,
      ReferenceRow,
      `SELECT site, slot, api, decorated, library, member, section_index, section_base,
              relocation_offset, form
       FROM library_import_references WHERE subject_sha = ? ORDER BY slot, site`,
      [maybeSubject.value.sha256],
    );
    return stored.map((r) => ({
      site: r.site,
      slot: r.slot,
      api: r.api,
      decorated: r.decorated,
      library: r.library,
      member: r.member,
      sectionIndex: r.section_index,
      sectionBase: r.section_base,
      relocationOffset: r.relocation_offset,
      form: r.form,
    }));
  }
}

// ----------------------------------------------------------------- the report

/**
 * What the derivation established, what it refused, and how much of the
 * already-named half of the import table it reproduces.
 *
 * The reproduction count is the validation: 150 slots were named from the
 * dump by a completely different route, so agreeing with them is the only
 * independent check this method has. A disagreement is carried with both
 * values and the size of each side's evidence, never resolved.
 */
const report = (input: {
  readonly identifications: number;
  readonly derived: {
    readonly references: ReadonlyArray<LibraryImportReference>;
    readonly refusals: ReadonlyArray<LibraryImportRefusal>;
    readonly sectionsPlaced: number;
    readonly relocations: number;
  };
  readonly bindingsWritten: number;
  readonly bindingsReproduced: number;
  readonly bindingsAliasResolved: ImportNameReport['bindingsAliasResolved'];
  readonly bindingDisagreements: ImportNameReport['bindingDisagreements'];
  readonly slots: ReadonlyMap<number, { readonly dll: string | null; readonly name: string | null }>;
  readonly apisPerSlot: ReadonlyMap<
    number,
    { readonly api: string; readonly apis: number; readonly cached_rows: number }
  >;
  readonly named: ReadonlyArray<{ readonly slot: number; readonly name: string }>;
  readonly newlyNamed: ReadonlyArray<{ readonly slot: number; readonly name: string }>;
  readonly cached: ReadonlyMap<number, number>;
}): ImportNameReport => {
  const libraryApis = new Map<number, Set<string>>();
  const librarySites = new Map<number, number>();
  for (const reference of input.derived.references) {
    const apis = libraryApis.get(reference.slot) ?? new Set<string>();
    apis.add(reference.api);
    libraryApis.set(reference.slot, apis);
    librarySites.set(reference.slot, (librarySites.get(reference.slot) ?? 0) + 1);
  }

  // Every verdict below comes from `import_slot_apis`, so "how many APIs does
  // this slot serve" has one implementation and the Wine aliases are already
  // folded into one name per entry point there.
  const namedHere = new Set(input.named.map((n) => n.slot));
  const reproduced: { slot: number; name: string }[] = [];
  const disagreements: SlotApiDisagreement[] = [];
  const stillUnnamed: { slot: number; apis: ReadonlyArray<string>; reason: string }[] = [];
  for (const [slot, apis] of [...libraryApis.entries()].sort(([a], [b]) => a - b)) {
    if (namedHere.has(slot)) continue;
    const row = input.slots.get(slot);
    const answer = input.apisPerSlot.get(slot);
    const derivedApis = [...apis].sort();
    if (answer !== undefined && answer.apis === 1) {
      reproduced.push({ slot, name: answer.api });
      continue;
    }
    if (row === undefined || row.name === null) {
      stillUnnamed.push({
        slot,
        apis: derivedApis,
        reason:
          `its evidence names ${answer?.apis ?? derivedApis.length} APIs, so it has no single ` +
          'name: the stub serves several and the dispatcher picks on the return address',
      });
      continue;
    }
    disagreements.push({
      slot,
      dll: row.dll ?? '',
      storedName: row.name,
      libraryApis: derivedApis,
      cachedSites: input.cached.get(slot) ?? 0,
      librarySites: librarySites.get(slot) ?? 0,
    });
  }

  const tally = <A extends string>(values: ReadonlyArray<A>): ReadonlyArray<{ key: A; count: number }> => {
    const counts = new Map<A, number>();
    for (const value of values) counts.set(value, (counts.get(value) ?? 0) + 1);
    return [...counts.entries()]
      .sort(([, a], [, b]) => b - a)
      .map(([key, count]) => ({ key, count }));
  };

  return {
    identifications: input.identifications,
    sectionsPlaced: input.derived.sectionsPlaced,
    relocations: input.derived.relocations,
    referencesConfirmed: input.derived.references.length,
    refusals: input.derived.refusals.length,
    refusalReasons: tally(input.derived.refusals.map((r) => r.reason)).map((e) => ({
      reason: e.key,
      count: e.count,
    })),
    formCounts: tally(input.derived.references.map((r) => r.form)).map((e) => ({
      form: e.key,
      count: e.count,
    })),
    bindingsWritten: input.bindingsWritten,
    bindingsReproduced: input.bindingsReproduced,
    bindingsAliasResolved: input.bindingsAliasResolved,
    bindingDisagreements: input.bindingDisagreements,
    slotsReferenced: libraryApis.size,
    slotsNamed: [...input.named].sort((a, b) => a.slot - b.slot),
    slotsNewlyNamed: [...input.newlyNamed].sort((a, b) => a.slot - b.slot),
    slotsStillUnnamed: stillUnnamed,
    slotsReproduced: reproduced,
    disagreements,
  };
};
