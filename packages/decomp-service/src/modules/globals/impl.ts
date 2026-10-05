import { Effect, Option, Result, Schema } from 'effect';
import { implementing, type EffectGen } from 'effective-modules';
import { modules } from '../index';
import type { IDb } from '../db/interface';
import { rows } from '../db/rows';
import { archiveMembers } from '../subject/coff';
import { CRT_LIBRARY_PATHS } from '../subject/paths';
import {
  NoCurrentSubject,
  SECTION_EXECUTABLE,
  SubjectIoError,
  type Section,
  type Subject,
} from '../subject/interface';
import type { SubjectImage } from '../disasm/interface';
import { dataReferences, type UnconfirmedReference } from './code-references';
import { deriveLibrarySymbols, type LibrarySymbolRefusal } from './library-symbols';
import { scanPointerCandidates } from './pointer-candidates';
import { assembleInventory } from './inventory';
import { assemble } from './report';
import {
  GlobalsFailed,
  type Deferral,
  type Deferred,
  type Evidence,
  type GlobalEntry,
  type GlobalReference,
  type GlobalsError,
  type GlobalsReport,
  type Holds,
  type HoldsBasis,
  type IGlobals,
  type LibrarySymbol,
  type PointerCandidate,
  type ReferenceForm,
  type SizeBasis,
} from './interface';

const EVIDENCE = ['proven-literal', 'library-symbol', 'decoded-literal', 'pointer-dword'] as const;
const SIZE_BASES = [
  'library-section',
  'library-next-symbol',
  'pointer-run',
  'access-width',
] as const;
const HOLDS = ['code-pointer', 'data-pointer', 'float'] as const;
const HOLDS_BASES = ['indirect-call', 'indirect-jump', 'x87-access', 'stored-address'] as const;
const DEFERRED = ['identity', 'size', 'name', 'holds'] as const;

const FunctionRow = Schema.Struct({ va: Schema.Number, size: Schema.Number });
const VaRow = Schema.Struct({ va: Schema.Number });
const SlotRow = Schema.Struct({ slot: Schema.Number });
const IdentificationRow = Schema.Struct({
  va: Schema.Number,
  symbol: Schema.String,
  library: Schema.String,
  member: Schema.String,
});

const GlobalRow = Schema.Struct({
  address: Schema.Number,
  section: Schema.String,
  evidence: Schema.Literals(EVIDENCE),
  size: Schema.NullOr(Schema.Number),
  size_basis: Schema.NullOr(Schema.Literals(SIZE_BASES)),
  name: Schema.NullOr(Schema.String),
  name_from: Schema.NullOr(Schema.String),
  holds: Schema.NullOr(Schema.Literals(HOLDS)),
  holds_basis: Schema.NullOr(Schema.Literals(HOLDS_BASES)),
  points_to: Schema.NullOr(Schema.Number),
  functions: Schema.NullOr(Schema.String),
  references: Schema.Number,
});

const DeferralRow = Schema.Struct({
  address: Schema.Number,
  what: Schema.Literals(DEFERRED),
  reason: Schema.String,
});

const CountRow = Schema.Struct({ n: Schema.Number });
const ReasonRow = Schema.Struct({ reason: Schema.String, n: Schema.Number });
const CandidateRow = Schema.Struct({
  address: Schema.Number,
  value: Schema.Number,
  section: Schema.String,
  target_section: Schema.String,
  run_start: Schema.Number,
  run_length: Schema.Number,
});

const option = <A>(value: A | null): Option.Option<A> =>
  value === null ? Option.none() : Option.some(value);

/** Map a library rather than read it, as the CRT matcher does: the archives
 *  are tens of megabytes and only a few hundred members are ever touched. */
const mapFile = (path: string): Effect.Effect<Uint8Array, SubjectIoError> =>
  Effect.try({
    try: () => Bun.mmap(path, { shared: false }),
    catch: (cause) =>
      new SubjectIoError({
        path,
        reason: cause instanceof Error ? cause.message : String(cause),
      }),
  });

/**
 * Where each address sits, and whether that section is code.
 *
 * Read from the section table's own flags rather than from a list of section
 * names: this subject's SafeDisc code sits in `THIS_COD`, which is
 * executable and is not called `.text`, and a globals inventory that treated
 * it as data would invent globals inside the copy protection's own code.
 */
const regionOf = (sections: ReadonlyArray<Section>) => {
  const spans = sections
    .map((s) => ({
      name: s.name,
      lo: s.va,
      // Virtual size, not raw size: the subject is a RAM image, so `.data`
      // really does carry the 1.16 MB its header claims and not the 96 KB a
      // file on disk would have held.
      hi: s.va + Math.max(s.virtualSize, s.rawSize),
      code: (s.characteristics & SECTION_EXECUTABLE) !== 0,
    }))
    .sort((a, b) => a.lo - b.lo);
  const find = (va: number) => spans.find((s) => va >= s.lo && va < s.hi);
  return {
    dataRegion: spans
      .filter((s) => !s.code)
      .map((s) => ({ name: s.name, lo: s.lo, hi: s.hi })),
    sectionOf: (va: number): string | undefined => find(va)?.name,
    isCode: (va: number): boolean => find(va)?.code === true,
    inDataRegion: (va: number): boolean => {
      const found = find(va);
      return found !== undefined && !found.code;
    },
  };
};

export class GlobalsImpl
  extends implementing(modules.Globals).uses(modules.Db, modules.Subject, modules.Disasm)
  implements IGlobals
{
  private *subject(): EffectGen<Subject, GlobalsError> {
    const current = yield* this.dependencies.Subject.current();
    if (Option.isNone(current)) {
      return yield* Effect.fail(
        new NoCurrentSubject({
          reason:
            'no subject is configured, so there is no data region to inventory and no image ' +
            'to confirm a library placement against',
        }),
      );
    }
    return current.value;
  }

  *rebuild(): EffectGen<GlobalsReport, GlobalsError> {
    const db: IDb = this.dependencies.Db;
    const subject = yield* this.subject();
    const sha = subject.sha256;
    const region = regionOf(subject.sections);
    if (region.dataRegion.length === 0) {
      return yield* Effect.fail(
        new GlobalsFailed({
          reason:
            `every section of ${sha} is marked executable, so the subject declares no data ` +
            'region at all -- which cannot be true of a program with globals',
        }),
      );
    }

    // The whole image, indexed from the image base. The subject is a RAM
    // image, so `va - imageBase` is the offset of every address in it --
    // which is also why this does not go through `bytesAt`, whose section
    // walk uses the PE header's RAW offsets and so reads the wrong bytes for
    // the three sections of this subject where raw offset and RVA diverge.
    const bytes = yield* this.dependencies.Subject.imageBytes();
    const image = { base: subject.imageBase, bytes };
    const decoderImage: SubjectImage = {
      sha256: sha,
      bytes,
      imageBase: subject.imageBase,
      textLo: subject.textLo,
      textHi: subject.textHi,
    };

    // ------------------------------------------------- evidence 1 and 3
    const functions = yield* rows(
      db,
      FunctionRow,
      'SELECT va, size FROM functions WHERE subject_sha = ? ORDER BY va',
      [sha],
    );
    const proven = new Set(
      (yield* rows(db, VaRow, 'SELECT DISTINCT va FROM proven WHERE subject_sha = ?', [sha])).map(
        (r) => r.va,
      ),
    );
    const references: GlobalReference[] = [];
    const unconfirmed: UnconfirmedReference[] = [];
    for (const fn of functions) {
      const decoded = yield* this.dependencies.Disasm.decodeFunction(decoderImage, fn);
      // A function whose bytes do not decode to exactly its recorded size is
      // not a function, and its operands are not facts about instruction
      // boundaries. Skipping it is not a loss: `Discovery.remeasure` is what
      // settles a disputed size, and this derivation re-runs after it.
      if (Option.isNone(decoded)) continue;
      const found = dataReferences({
        instructions: decoded.value,
        containingFunction: Option.some(fn.va),
        inDataRegion: region.inDataRegion,
      });
      for (const reference of found.references) references.push(reference);
      for (const refusal of found.unconfirmed) unconfirmed.push(refusal);
    }

    // ------------------------------------------------------- evidence 2
    const identifications = yield* rows(
      db,
      IdentificationRow,
      `SELECT va, symbol, library, member FROM crt_identifications
       WHERE subject_sha = ? ORDER BY va`,
      [sha],
    );
    // A library that is not installed is a smaller search, not a failure:
    // every symbol names the archive member it came from, so what was read is
    // always visible, and the refusal rows say which members could not be
    // opened so a missing archive cannot look like an absence of evidence.
    const libraries: { path: string; members: ReadonlyArray<{ name: string; body: Uint8Array }> }[] =
      [];
    for (const path of CRT_LIBRARY_PATHS) {
      const mapped = yield* Effect.result(mapFile(path));
      if (Result.isSuccess(mapped)) {
        libraries.push({ path, members: [...archiveMembers(mapped.success)] });
      }
    }
    const derived = deriveLibrarySymbols({
      identifications,
      libraries,
      image,
      inDataRegion: region.inDataRegion,
    });

    // ------------------------------------------------------- evidence 4
    const scan = scanPointerCandidates({
      image,
      dataRegion: region.dataRegion,
      sectionOf: region.sectionOf,
    });

    const importSlots = new Set(
      (yield* rows(db, SlotRow, 'SELECT slot FROM import_slots WHERE subject_sha = ?', [sha])).map(
        (r) => r.slot,
      ),
    );

    const inventory = assembleInventory({
      references,
      provenFunctions: proven,
      librarySymbols: derived.symbols,
      pointerCandidates: scan.candidates,
      importSlots,
      sectionOf: region.sectionOf,
      isCode: region.isCode,
    });

    yield* db.tx(function* () {
      for (const table of [
        'global_references',
        'global_reference_refusals',
        'global_library_symbols',
        'global_library_refusals',
        'global_pointer_candidates',
        'globals',
        'global_deferrals',
      ]) {
        yield* db.run(`DELETE FROM ${table} WHERE subject_sha = ?`, [sha]);
      }
      for (const r of references) {
        yield* db.run(
          `INSERT INTO global_references(subject_sha, site, address, form, width, mnemonic,
                                         op_str, containing_function)
           VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(subject_sha, site, address, form) DO NOTHING`,
          [
            sha,
            r.site,
            r.address,
            r.form,
            Option.getOrNull(r.width),
            r.mnemonic,
            r.opStr,
            Option.getOrNull(r.containingFunction),
          ],
        );
      }
      for (const r of unconfirmed) {
        yield* db.run(
          `INSERT INTO global_reference_refusals(subject_sha, site, address, mnemonic, op_str,
                                                 reason)
           VALUES (?,?,?,?,?,?) ON CONFLICT(subject_sha, site, address) DO NOTHING`,
          [
            sha,
            r.site,
            r.address,
            r.mnemonic,
            r.opStr,
            'the decoder printed this address but no 32-bit field of the instruction holds it, ' +
              'so the instruction does not name it',
          ],
        );
      }
      for (const s of derived.symbols) {
        yield* db.run(
          `INSERT INTO global_library_symbols(subject_sha, address, name, library, member, route,
                                              section_index, relocation_offset, field_value,
                                              addend, offset_reached, size, size_basis)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(subject_sha, address, name, member, route) DO NOTHING`,
          [
            sha,
            s.address,
            s.name,
            s.library,
            s.member,
            s.route,
            s.sectionIndex,
            Option.getOrNull(s.relocationOffset),
            Option.getOrNull(s.fieldValue),
            Option.getOrNull(s.addend),
            s.offsetReached,
            Option.getOrNull(s.size),
            Option.getOrNull(s.sizeBasis),
          ],
        );
      }
      for (const r of derived.refusals) {
        yield* db.run(
          `INSERT INTO global_library_refusals(subject_sha, library, member, section_index,
                                               relocation_offset, symbol, reason)
           VALUES (?,?,?,?,?,?,?)`,
          [
            sha,
            r.library,
            r.member,
            r.sectionIndex,
            Option.getOrNull(r.relocationOffset),
            Option.getOrNull(r.symbol),
            r.reason,
          ],
        );
      }
      for (const c of scan.candidates) {
        yield* db.run(
          `INSERT INTO global_pointer_candidates(subject_sha, address, value, section,
                                                 target_section, run_start, run_length)
           VALUES (?,?,?,?,?,?,?) ON CONFLICT(subject_sha, address) DO NOTHING`,
          [sha, c.address, c.value, c.section, c.targetSection, c.runStart, c.runLength],
        );
      }
      for (const e of inventory.entries) {
        yield* db.run(
          `INSERT INTO globals(subject_sha, address, section, evidence, size, size_basis, name,
                               name_from, holds, holds_basis, points_to)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(subject_sha, address) DO NOTHING`,
          [
            sha,
            e.address,
            e.section,
            e.evidence,
            Option.getOrNull(e.size),
            Option.getOrNull(e.sizeBasis),
            Option.getOrNull(e.name),
            Option.getOrNull(e.nameFrom),
            Option.getOrNull(e.holds),
            Option.getOrNull(e.holdsBasis),
            Option.getOrNull(e.pointsTo),
          ],
        );
      }
      for (const d of inventory.deferrals) {
        yield* db.run(
          `INSERT INTO global_deferrals(subject_sha, address, what, reason) VALUES (?,?,?,?)
           ON CONFLICT(subject_sha, address, what) DO NOTHING`,
          [sha, d.address, d.what, d.reason],
        );
      }
    });

    return assemble({
      subjectSha256: sha,
      dataRegion: region.dataRegion,
      references: references.length,
      unconfirmedReferences: unconfirmed.length,
      entries: inventory.entries,
      deferrals: inventory.deferrals,
      candidates: scan.candidates,
      isCode: region.isCode,
      importSlotsSkipped: inventory.importSlotsSkipped,
      librarySymbols: derived.symbols.length,
      libraryRefusalReasons: derived.refusals.map((r) => r.reason),
    });
  }

  *recorded(): EffectGen<Option.Option<GlobalsReport>, GlobalsError> {
    const subject = yield* this.subject();
    const sha = subject.sha256;
    const stored = yield* rows(
      this.dependencies.Db,
      CountRow,
      'SELECT COUNT(*) AS n FROM globals WHERE subject_sha = ?',
      [sha],
    );
    if ((stored[0]?.n ?? 0) === 0) return Option.none();

    const db: IDb = this.dependencies.Db;
    const entries = yield* this.readEntries(sha);
    const deferrals = yield* this.readDeferrals(sha);
    const candidates = (
      yield* rows(
        db,
        CandidateRow,
        `SELECT address, value, section, target_section, run_start, run_length
         FROM global_pointer_candidates WHERE subject_sha = ? ORDER BY address`,
        [sha],
      )
    ).map(
      (r): PointerCandidate => ({
        address: r.address,
        value: r.value,
        section: r.section,
        targetSection: r.target_section,
        runStart: r.run_start,
        runLength: r.run_length,
      }),
    );
    const references = yield* rows(
      db,
      CountRow,
      'SELECT COUNT(*) AS n FROM global_references WHERE subject_sha = ?',
      [sha],
    );
    const unconfirmed = yield* rows(
      db,
      CountRow,
      'SELECT COUNT(*) AS n FROM global_reference_refusals WHERE subject_sha = ?',
      [sha],
    );
    const librarySymbols = yield* rows(
      db,
      CountRow,
      'SELECT COUNT(*) AS n FROM global_library_symbols WHERE subject_sha = ?',
      [sha],
    );
    const refusals = yield* rows(
      db,
      ReasonRow,
      `SELECT reason, COUNT(*) AS n FROM global_library_refusals WHERE subject_sha = ?
       GROUP BY reason ORDER BY n DESC`,
      [sha],
    );
    // Counted by joining the import map, not by counting `identity`
    // deferrals: that bucket also holds every vtable interior slot and every
    // isolated pointer dword, so it read 15,011 where the derivation had
    // skipped 240 -- a read-back that disagreed with the thing it was
    // reading back.
    const slotsSkipped = yield* rows(
      db,
      CountRow,
      `SELECT COUNT(*) AS n FROM global_deferrals d
        JOIN import_slots s ON s.subject_sha = d.subject_sha AND s.slot = d.address
       WHERE d.subject_sha = ? AND d.what = 'identity'`,
      [sha],
    );
    const region = regionOf(subject.sections);
    return Option.some(
      assemble({
        subjectSha256: sha,
        dataRegion: region.dataRegion,
        references: references[0]?.n ?? 0,
        unconfirmedReferences: unconfirmed[0]?.n ?? 0,
        entries,
        deferrals,
        candidates,
        isCode: region.isCode,
        importSlotsSkipped: slotsSkipped[0]?.n ?? 0,
        librarySymbols: librarySymbols[0]?.n ?? 0,
        libraryRefusalReasons: refusals.flatMap((r) => Array.from({ length: r.n }, () => r.reason)),
      }),
    );
  }

  *at(address: number): EffectGen<Option.Option<GlobalEntry>, GlobalsError> {
    const subject = yield* this.subject();
    const found = yield* this.readEntries(subject.sha256, address);
    return found.length === 0 ? Option.none() : Option.some(found[0]!);
  }

  *entries(): EffectGen<ReadonlyArray<GlobalEntry>, GlobalsError> {
    const subject = yield* this.subject();
    return yield* this.readEntries(subject.sha256);
  }

  *deferrals(): EffectGen<ReadonlyArray<Deferral>, GlobalsError> {
    const subject = yield* this.subject();
    return yield* this.readDeferrals(subject.sha256);
  }

  /** The inventory as stored, with the functions that touch each global
   *  joined from `global_touched_by` -- the one place that question is
   *  answered, so a second derivation of it cannot disagree. */
  private *readEntries(
    sha: string,
    address?: number,
  ): EffectGen<ReadonlyArray<GlobalEntry>, GlobalsError> {
    const stored = yield* rows(
      this.dependencies.Db,
      GlobalRow,
      `SELECT g.address, g.section, g.evidence, g.size, g.size_basis, g.name, g.name_from,
              g.holds, g.holds_basis, g.points_to,
              (SELECT GROUP_CONCAT(t.va) FROM global_touched_by t
                WHERE t.subject_sha = g.subject_sha AND t.address = g.address) AS functions,
              (SELECT COUNT(*) FROM global_references r
                WHERE r.subject_sha = g.subject_sha AND r.address = g.address) AS "references"
       FROM globals g
       WHERE g.subject_sha = ?${address === undefined ? '' : ' AND g.address = ?'}
       ORDER BY g.address`,
      address === undefined ? [sha] : [sha, address],
    );
    return stored.map(
      (r): GlobalEntry => ({
        address: r.address,
        section: r.section,
        evidence: r.evidence,
        size: option(r.size),
        sizeBasis: option<SizeBasis>(r.size_basis),
        name: option(r.name),
        nameFrom: option(r.name_from),
        holds: option<Holds>(r.holds),
        holdsBasis: option<HoldsBasis>(r.holds_basis),
        pointsTo: option(r.points_to),
        functions:
          r.functions === null
            ? []
            : r.functions
                .split(',')
                .map((v) => Number.parseInt(v, 10))
                .sort((a, b) => a - b),
        references: r.references,
      }),
    );
  }

  private *readDeferrals(sha: string): EffectGen<ReadonlyArray<Deferral>, GlobalsError> {
    const stored = yield* rows(
      this.dependencies.Db,
      DeferralRow,
      `SELECT address, what, reason FROM global_deferrals WHERE subject_sha = ?
       ORDER BY address, what`,
      [sha],
    );
    return stored.map((r): Deferral => ({ address: r.address, what: r.what, reason: r.reason }));
  }
}
