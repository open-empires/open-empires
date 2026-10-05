import { Effect, Option, Schema, SchemaIssue, pipe } from 'effect';
import { implementing, type EffectGen } from 'effective-modules';
import fs from 'node:fs';
import path from 'node:path';
import { modules } from '../index';
import type { DbError } from '../db/interface';
import { SUBJECT_FLAGS, type GateUnavailable, type Toolchain } from '../gate/interface';
import {
  CrtIdentifications,
  GateReport,
  ImportMap,
  Inventory,
  Names,
  PortStatus,
  Subject,
  Verdicts,
  addressOf,
  callSitesOf,
  classOf,
  hexOf,
  sha256,
  shortPath,
  type LegacyState,
  type Reconstruction,
} from './artifacts';
import { auditQueries } from './audit';
import { parseNearMissHeader } from './near-miss';
import {
  BUCKETS,
  CRT_IDENTIFIED_JSON,
  GATE_REPORT_JSON,
  GATE_TEXT_HI,
  GATE_TEXT_LO,
  IMPORT_NAMES_JSON,
  INVENTORY_JSON,
  NAMES_JSON,
  PORT_DIR,
  PORT_STATUS_JSON,
  RECONSTRUCTION_FILE,
  SUBJECT_JSON,
  VERDICTS_JSON,
} from './paths';
import {
  LegacyInconsistent,
  LegacyUnreadable,
  type Check,
  type ILegacy,
  type ImportSummary,
  type LegacyError,
  type TableRows,
  type Unexpressed,
} from './interface';

const formatIssue = SchemaIssue.makeFormatterDefault();

/**
 * The marker carried by every verdict this import writes.
 *
 * It is here rather than in a report because a caveat in a report is read once
 * and a caveat on the row is read every time the row is. The Python gate
 * recorded nothing about which compiler decided a verdict, so these 2,614
 * proofs are attributed to the compiler now installed -- which is the honest
 * best available and is not the same as having been observed.
 */
const IMPORTED_VERDICT =
  'imported from decomp/fn_verdicts.json; the Python gate recorded no prover, ' +
  'so this verdict is ATTRIBUTED to the current toolchain, not observed under it';


const vaOf = (file: string): Option.Option<number> => {
  const match = RECONSTRUCTION_FILE.exec(path.basename(file));
  return match === null ? Option.none() : Option.some(addressOf(match[1]!));
};

export class LegacyImpl
  extends implementing(modules.Legacy).uses(modules.Db, modules.Gate)
  implements ILegacy
{
  // ------------------------------------------------------------------ reading

  private *readText(file: string): EffectGen<string, LegacyUnreadable> {
    return yield* Effect.try({
      try: () => fs.readFileSync(file, 'utf8'),
      catch: (cause) =>
        new LegacyUnreadable({
          path: shortPath(file),
          reason: cause instanceof Error ? cause.message : String(cause),
        }),
    });
  }

  private *readJson<A, I>(
    file: string,
    schema: Schema.Codec<A, I>,
  ): EffectGen<A, LegacyError> {
    const text = yield* this.readText(file);
    const parsed = yield* Effect.try({
      try: () => JSON.parse(text) as unknown,
      catch: (cause) =>
        new LegacyUnreadable({
          path: shortPath(file),
          reason: `not JSON: ${cause instanceof Error ? cause.message : String(cause)}`,
        }),
    });
    return yield* pipe(
      Schema.decodeUnknownEffect(schema)(parsed),
      Effect.catchTag('SchemaError', (error) =>
        Effect.fail(
          new LegacyUnreadable({ path: shortPath(file), reason: formatIssue(error.issue) }),
        ),
      ),
    );
  }

  private *readDirectory(dir: string): EffectGen<ReadonlyArray<string>, LegacyUnreadable> {
    return yield* Effect.try({
      try: () => fs.readdirSync(dir),
      catch: (cause) =>
        new LegacyUnreadable({
          path: shortPath(dir),
          reason: cause instanceof Error ? cause.message : String(cause),
        }),
    });
  }

  /**
   * Every reconstruction in every bucket, with its text and that text's hash.
   *
   * The hash is taken from the bytes read here and nothing else. A hash
   * sourced from anywhere but the stored bytes was wrong for 1,445 blocks
   * once, and no offline check could tell.
   */
  private *readReconstructions(
    report: GateReport,
  ): EffectGen<ReadonlyArray<Reconstruction>, LegacyError> {
    const all: Reconstruction[] = [];
    for (const bucket of BUCKETS) {
      const recorded = report.by_bucket[bucket.name];
      if (bucket.gated && recorded === undefined) {
        return yield* Effect.fail(
          new LegacyInconsistent({
            what: `gate_report.json by_bucket.${bucket.name}`,
            reason:
              `${shortPath(bucket.dir)} holds reconstructions the gate checks, but the ` +
              `report names no bucket for it, so their flags are not recorded anywhere`,
          }),
        );
      }
      // `wip/` is not a gate bucket, so no flags were ever recorded for it.
      // The gate's own subject flags are what its headers quote and what any
      // re-check would use; nothing here claims they were observed.
      const flags = recorded === undefined ? SUBJECT_FLAGS : recorded.flags;
      for (const entry of yield* this.readDirectory(bucket.dir)) {
        const file = path.join(bucket.dir, entry);
        const va = vaOf(entry);
        if (Option.isNone(va)) continue;
        const source = yield* this.readText(file);
        all.push({ bucket, file, va: va.value, source, sourceSha: sha256(source), flags });
      }
    }
    return all;
  }

  /**
   * Read every file, then check the files against each other.
   *
   * This is the one moment they are all open at once, so a disagreement found
   * here is one that was already live and silent. Importing the half that
   * happened to be read first would bake it into the system of record, so the
   * ones that would make a written row FALSE stop the import; the ones that
   * are merely a stale scalar are reported by `audit` instead.
   */
  private *readAll(): EffectGen<LegacyState, LegacyError> {
    const subject = yield* this.readJson(SUBJECT_JSON, Subject);
    const inventory = yield* this.readJson(INVENTORY_JSON, Inventory);
    const verdicts = yield* this.readJson(VERDICTS_JSON, Verdicts);
    const report = yield* this.readJson(GATE_REPORT_JSON, GateReport);
    const names = yield* this.readJson(NAMES_JSON, Names);
    const imports = yield* this.readJson(IMPORT_NAMES_JSON, ImportMap);
    const port = yield* this.readJson(PORT_STATUS_JSON, PortStatus);
    const crt = yield* this.readJson(CRT_IDENTIFIED_JSON, CrtIdentifications);
    const reconstructions = yield* this.readReconstructions(report);
    const ported = new Set(
      (yield* this.readDirectory(PORT_DIR)).filter((entry) =>
        RECONSTRUCTION_FILE.test(entry),
      ),
    );

    // Every file must be talking about the same binary. A row attributed to
    // the wrong subject is a proof against something we never compiled.
    for (const [what, sha] of [
      ['functions.json', inventory.subject_sha256],
      ['gate_report.json', report.subject_sha256],
      ['names.json', names.subject_sha256],
      ['import_names.json', imports.subject],
    ] as const) {
      if (sha !== subject.sha256) {
        return yield* Effect.fail(
          new LegacyInconsistent({
            what,
            reason: `names subject ${sha}; subject.json says ${subject.sha256}`,
          }),
        );
      }
    }

    if (report.text_span !== GATE_TEXT_HI - GATE_TEXT_LO) {
      return yield* Effect.fail(
        new LegacyInconsistent({
          what: 'subjects.text_lo / text_hi',
          reason:
            `the span this import would write, ${hexOf(GATE_TEXT_LO)}..${hexOf(GATE_TEXT_HI)}, ` +
            `is ${GATE_TEXT_HI - GATE_TEXT_LO} bytes, but gate_report.json reports ` +
            `text_span ${report.text_span}`,
        }),
      );
    }

    const inventoryVas = new Set(inventory.functions.map((f) => f.va));
    const seen = new Map<number, string>();
    for (const r of reconstructions) {
      if (!inventoryVas.has(r.va)) {
        return yield* Effect.fail(
          new LegacyInconsistent({
            what: shortPath(r.file),
            reason: `claims ${hexOf(r.va)}, which functions.json does not list`,
          }),
        );
      }
      const other = seen.get(r.va);
      if (other !== undefined) {
        return yield* Effect.fail(
          new LegacyInconsistent({
            what: hexOf(r.va),
            reason: `claimed by two buckets, ${other} and ${r.bucket.name}, so its flags are ambiguous`,
          }),
        );
      }
      seen.set(r.va, r.bucket.name);
    }

    // The gated buckets and fn_verdicts.json must name the SAME addresses.
    // Equal counts over different sets is the failure this exists to catch:
    // a verdict written for an address no file claims is a proof of nothing,
    // and a claimed address with no verdict is a proof silently dropped.
    const gated = new Set(
      reconstructions.filter((r) => r.bucket.gated).map((r) => r.va),
    );
    const exact = new Set(verdicts.exact);
    const unclaimed = [...exact].filter((va) => !gated.has(va));
    const unproved = [...gated].filter((va) => !exact.has(va));
    if (unclaimed.length > 0 || unproved.length > 0) {
      return yield* Effect.fail(
        new LegacyInconsistent({
          what: 'fn_verdicts.json against src/fn and src/fn-o1',
          reason:
            `${unclaimed.length} proved address(es) with no source file ` +
            `(${unclaimed.slice(0, 8).map(hexOf).join(', ')}) and ${unproved.length} ` +
            `source file(s) with no verdict (${unproved.slice(0, 8).map(hexOf).join(', ')})`,
        }),
      );
    }
    const parked = reconstructions.filter((r) => !r.bucket.gated && exact.has(r.va));
    if (parked.length > 0) {
      return yield* Effect.fail(
        new LegacyInconsistent({
          what: 'src/wip against fn_verdicts.json',
          reason:
            `${parked.length} near-miss(es) are also recorded as exact ` +
            `(${parked.slice(0, 8).map((r) => hexOf(r.va)).join(', ')})`,
        }),
      );
    }

    // `masked` and `compared` are only ever written from a weak_detail row,
    // and only if that row agrees with the size everything else uses.
    const sizes = new Map(inventory.functions.map((f) => [f.va, f.size]));
    for (const weak of report.weak_detail) {
      const va = addressOf(weak.va);
      if (sizes.get(va) !== weak.total) {
        return yield* Effect.fail(
          new LegacyInconsistent({
            what: `gate_report.json weak_detail ${weak.va}`,
            reason:
              `compares ${weak.total} bytes, but functions.json gives this function ` +
              `${sizes.get(va)}, so the compared figure cannot be derived from it`,
          }),
        );
      }
    }

    return {
      subject, inventory, verdicts, report, names, imports, port, crt,
      reconstructions, ported,
    };
  }

  // ------------------------------------------------------------------ writing

  private *runEach(
    sql: string,
    rows: ReadonlyArray<ReadonlyArray<unknown>>,
  ): EffectGen<number, DbError> {
    let changed = 0;
    for (const row of rows) changed += yield* this.dependencies.Db.run(sql, row);
    return changed;
  }

  /** What the table holds AFTER the write, counted by the database rather than
   *  by adding up what this code believes it inserted. */
  private *rowsIn(
    table: string,
    where: string,
    params: ReadonlyArray<unknown>,
  ): EffectGen<TableRows, DbError> {
    const row = yield* this.dependencies.Db.one(
      `SELECT COUNT(*) AS n FROM ${table} ${where}`,
      params,
    );
    return { table, rows: Number((row as { n: number }).n) };
  }

  *importState(): EffectGen<ImportSummary, LegacyError | GateUnavailable | DbError> {
    const state = yield* this.readAll();

    // Before anything is written: who the prover is. Obtained from the gate,
    // which owns compiler identity, so there is one derivation of it in the
    // service and not a second one here.
    const toolchain = yield* this.dependencies.Gate.toolchain(SUBJECT_FLAGS);

    const db = this.dependencies.Db;
    const sha = state.subject.sha256;
    const at = state.report.at;
    const now = Date.now() / 1000;

    return yield* db.tx(
      (): EffectGen<ImportSummary, LegacyError | DbError> =>
        this.write({ state, toolchain, sha, at, now }),
    );
  }

  private *write(input: {
    readonly state: LegacyState;
    readonly toolchain: Toolchain;
    readonly sha: string;
    readonly at: number;
    readonly now: number;
  }): EffectGen<ImportSummary, LegacyError | DbError> {
    const { state, toolchain, sha, at, now } = input;
    const db = this.dependencies.Db;

    // ---- identity. Seeded, never overwritten: if another module already
    // recorded this subject or this configuration, its answer stands and a
    // disagreement surfaces as a failed audit rather than as a silent change.
    yield* db.run(
      `INSERT OR IGNORE INTO subjects(sha256, path, size, image_base, text_lo, text_hi, added_at)
       VALUES (?,?,?,?,?,?,?)`,
      [sha, state.subject.path, state.subject.size, state.subject.image_base,
        GATE_TEXT_LO, GATE_TEXT_HI, now],
    );
    yield* db.run(
      `INSERT OR IGNORE INTO toolchains(id, cl_sha256, flags, comp_id, added_at)
       VALUES (?,?,?,?,?)`,
      [toolchain.id, toolchain.clSha256, toolchain.flags,
        Option.match(toolchain.compId, {
          onNone: () => null,
          onSome: (id) => `0x${id.toString(16).padStart(8, '0')}`,
        }),
        now],
    );
    yield* db.run(
      `INSERT OR IGNORE INTO current_config(only_row, subject_sha, toolchain_id, set_at)
       VALUES (1,?,?,?)`,
      [sha, toolchain.id, now],
    );

    // ---- the work. The name columns are deliberately NOT written here.
    // INames.recover() derives them from the subject's own bytes, and the
    // bytes cannot be edited behind the service's back while names.json can.
    // Writing them from both places made two answers to "what is this
    // function called", and the JSON's copy would have won on any later
    // re-import -- including for the 13 candidates the derivation REFUSES to
    // name, which is the one answer that must not be quietly restored.
    yield* this.runEach(
      // DO NOTHING on conflict, not DO UPDATE SET size.
      //
      // functions.json is a one-time SEED, not an authority on extents. The
      // service measures extents from the bytes and repairs the ones that do
      // not decode: 0x5a4afa is 594 bytes and 0x5a4e99 is 678, where the JSON
      // says 158 and 196. Updating the size from the JSON on every import
      // silently reverted both to the wrong value, which would have made
      // those two functions unworkable again -- and the JSON cannot be fixed
      // in place, because then there are two authorities disagreeing about
      // every size and whichever ran last wins.
      //
      // So the import only ever ADDS addresses it knows about. An extent in
      // the database came from the bytes and stays.
      `INSERT INTO functions(subject_sha, va, size, discovered_by)
       VALUES (?,?,?,NULL)
       ON CONFLICT(subject_sha, va) DO NOTHING`,
      state.inventory.functions.map((f) => [sha, f.va, f.size]),
    );

    // ---- the attempts. Keyed on (va, source hash, flags), so re-running
    // recognises the same text and an edited file becomes a NEW attempt
    // rather than a rewrite of the one a verdict already points at.
    yield* this.runEach(
      `INSERT OR IGNORE INTO attempts(subject_sha, va, source, source_sha, flags, author, created_at)
       VALUES (?,?,?,?,?,NULL,?)`,
      state.reconstructions.map((r) => [sha, r.va, r.source, r.sourceSha, r.flags, at]),
    );
    const attemptIds = new Map(
      (
        yield* db.all(
          `SELECT id, va, source_sha, flags FROM attempts WHERE subject_sha = ?`,
          [sha],
        )
      ).map((raw) => {
        const row = raw as { id: number; va: number; source_sha: string; flags: string };
        return [`${row.va}:${row.source_sha}:${row.flags}`, row.id];
      }),
    );
    const idOf = (r: Reconstruction): number | undefined =>
      attemptIds.get(`${r.va}:${r.sourceSha}:${r.flags}`);

    // ---- the gate run. Identified by the only facts the report carries about
    // it: the subject, the prover and its own clock. That triple is the key,
    // so a second import reuses the run instead of inventing another prover.
    const existing = yield* db.one(
      `SELECT id FROM gate_runs WHERE subject_sha = ? AND toolchain_id = ? AND started_at = ?`,
      [sha, toolchain.id, at],
    );
    const gateRunId =
      existing === null
        ? yield* db.insert(
            `INSERT INTO gate_runs(subject_sha, toolchain_id, started_at, finished_at, attempted, exact)
             VALUES (?,?,?,?,?,?)`,
            [
              sha, toolchain.id, at, at,
              BUCKETS.filter((b) => b.gated).reduce(
                (total, b) => total + (state.report.by_bucket[b.name]?.total ?? 0),
                0,
              ),
              state.report.exact,
            ],
          )
        : Number((existing as { id: number }).id);

    const weak = new Map(
      state.report.weak_detail.map((w) => [addressOf(w.va), w]),
    );
    const verdictRows: unknown[][] = [];
    const missingAttempt: string[] = [];
    for (const r of state.reconstructions) {
      if (!r.bucket.gated) continue;
      const id = idOf(r);
      if (id === undefined) {
        missingAttempt.push(shortPath(r.file));
        continue;
      }
      const w = weak.get(r.va);
      verdictRows.push([
        id, gateRunId, 1, 1,
        // emitted_size, first_diff: the run did not persist either, and for an
        // exact verdict the first is the subject's own size -- already a
        // column on `functions`, so writing it here would be a second copy.
        null,
        w === undefined ? null : w.masked,
        w === undefined ? null : w.total - w.masked,
        null,
        IMPORTED_VERDICT,
        at,
      ]);
    }
    if (missingAttempt.length > 0) {
      return yield* Effect.fail(
        new LegacyInconsistent({
          what: 'attempts',
          reason:
            `${missingAttempt.length} source file(s) produced no attempt row to attach a ` +
            `verdict to: ${missingAttempt.slice(0, 5).join(', ')}`,
        }),
      );
    }
    yield* this.runEach(
      `INSERT OR IGNORE INTO verdicts(attempt_id, gate_run_id, exact, compiled, emitted_size,
                                      masked, compared, first_diff, detail, decided_at)
       VALUES (?,?,?,?,?,?,?,?,?,?)`,
      verdictRows,
    );

    // ---- the near-misses. The header is kept whole as the note, so the two
    // parsed columns can be null without losing what the author wrote.
    const nearMisses = state.reconstructions.filter((r) => !r.bucket.gated);
    yield* this.runEach(
      `INSERT INTO near_misses(subject_sha, va, attempt_id, blocked_class, eliminated, note, updated_at)
       VALUES (?,?,?,?,?,?,?)
       ON CONFLICT(subject_sha, va) DO UPDATE SET
         attempt_id    = excluded.attempt_id,
         blocked_class = COALESCE(excluded.blocked_class, near_misses.blocked_class),
         eliminated    = COALESCE(excluded.eliminated, near_misses.eliminated),
         note          = excluded.note,
         updated_at    = excluded.updated_at`,
      nearMisses.map((r) => {
        const header = parseNearMissHeader(r.source);
        return [
          sha, r.va, idOf(r) ?? null,
          Option.getOrNull(header.blockedClass),
          Option.getOrNull(header.eliminated),
          header.note, at,
        ];
      }),
    );

    // ---- the import table is NOT imported from JSON.
    //
    // Subject.mapImports() derives the same 255 slots and 297 bindings from
    // the subject's bytes and the guest RAM dump, and the two agree row for
    // row. Two producers for one key is how install order silently picks the
    // winner, so the derivation -- which can be re-run against the bytes and
    // explain every row -- is the single producer, and this importer does not
    // write these tables at all.
    //
    // The JSON that was its source stays readable until the Python goes; it
    // is no longer an input to the system of record.

    // ---- the port tree. One row per file the pass actually produced. The 30
    // refusals are a count in port_status.json with no address list, so they
    // are reported as unexpressed rather than guessed at: the 124 gated
    // sources with no port output are those 30 plus 94 written after the pass
    // last ran, and nothing on disk says which is which.
    const needsGlobals = new Set(state.port.needs_globals);
    const portRows: unknown[][] = [];
    for (const entry of state.ported) {
      const va = vaOf(entry);
      if (Option.isNone(va)) continue;
      portRows.push(
        needsGlobals.has(entry)
          ? [sha, va.value, 'needs_globals',
             'holds literal image addresses; resolved by the globals model, not by text substitution']
          : [sha, va.value, 'converted', null],
      );
    }
    yield* this.runEach(
      `INSERT INTO port_files(subject_sha, va, state, reason)
       VALUES (?,?,?,?)
       ON CONFLICT(subject_sha, va) DO UPDATE SET
         state = excluded.state, reason = excluded.reason`,
      portRows,
    );

    const written: ReadonlyArray<TableRows> = [
      yield* this.rowsIn('subjects', 'WHERE sha256 = ?', [sha]),
      yield* this.rowsIn('toolchains', 'WHERE id = ?', [toolchain.id]),
      yield* this.rowsIn('current_config', '', []),
      yield* this.rowsIn('functions', 'WHERE subject_sha = ?', [sha]),
      yield* this.rowsIn('attempts', 'WHERE subject_sha = ?', [sha]),
      yield* this.rowsIn('gate_runs', 'WHERE id = ?', [gateRunId]),
      yield* this.rowsIn('verdicts', 'WHERE gate_run_id = ?', [gateRunId]),
      yield* this.rowsIn('near_misses', 'WHERE subject_sha = ?', [sha]),
      yield* this.rowsIn('import_slots', 'WHERE subject_sha = ?', [sha]),
      yield* this.rowsIn('import_bindings', 'WHERE subject_sha = ?', [sha]),
      yield* this.rowsIn('port_files', 'WHERE subject_sha = ?', [sha]),
    ];

    return {
      subjectSha: sha,
      toolchainId: toolchain.id,
      gateRunId,
      written,
      unexpressed: this.unexpressed(state),
    };
  }

  /**
   * What the files carry and the schema cannot hold.
   *
   * Computed from the state actually read, so the list is a measurement rather
   * than a remembered caveat that would go stale the moment the schema grows a
   * column.
   */
  private unexpressed(state: LegacyState): ReadonlyArray<Unexpressed> {
    const out: Unexpressed[] = [];

    const crtAddresses = Object.keys(state.crt).map(addressOf);
    const inventoryVas = new Set(state.inventory.functions.map((f) => f.va));
    const inside = crtAddresses.filter((va) => inventoryVas.has(va)).length;
    out.push({
      what: 'crt_identified.json',
      detail:
        `${crtAddresses.length} addresses matched to an object in the shipped CRT libraries ` +
        `(${inside} of them declared functions, ${crtAddresses.length - inside} not in the ` +
        `inventory at all). The schema DOES now express this, in crt_identifications, and that ` +
        `table asks for more than the file holds: library and member and section_size are all ` +
        `NOT NULL, and the file records only the symbol and the member. crtmatch.py had the ` +
        `library it was reading and the matched section's length in hand and persisted neither. ` +
        `NOT IMPORTED, because the only ways to fill two NOT NULL columns from a file that does ` +
        `not contain them are to invent values or to re-run the matcher -- and re-running it is ` +
        `exactly ISubject.identifyCrtFunctions(), which derives all four from the libraries ` +
        `themselves. Let that run; it is better evidence than this file, not a substitute for it.`,
    });

    const noted = state.inventory.functions.filter((f) => Option.isSome(f.note)).length;
    out.push({
      what: 'functions.json note',
      detail:
        `${noted} of ${state.inventory.functions.length} entries carry free text saying how ` +
        `the entry was found or how its bounds were corrected ("size corrected 205 -> 263: the ` +
        `entry ended at a ret in the middle of the function"). functions has no note column, so ` +
        `this text is NOT IMPORTED. discovered_by is also left null: discover.py unions direct ` +
        `call targets with .rdata pointer-table slots before writing, so the column's own ` +
        `call-vs-rdata-pointer split is not recoverable from what it wrote.`,
    });

    const classNames = Object.keys(state.names.classes);
    const attributed = new Set(classOf(state.names).values());
    const unattributed = classNames.filter((name) => !attributed.has(name));
    out.push({
      what: 'names.json functions, classes and withheld candidates',
      detail:
        `${Object.keys(state.names.functions).length} recovered names across ` +
        `${classNames.length} classes, of which ${attributed.size} have an address attributed ` +
        `to them; the other ${unattributed.length} (${unattributed.join(', ')}) have a method ` +
        `name observed in the subject's strings and no address to hang it on. NONE of it is ` +
        `imported, and that is the point: INames.recover() derives all of it from the ` +
        `subject's own bytes into functions.name, string_references, withheld_names and the ` +
        `name_class_* views. Importing it as well would make this file a second answer to what ` +
        `a function is called -- and the one it would win on is the 13 candidates the ` +
        `derivation REFUSES to name.`,
    });

    const gated = state.reconstructions.filter((r) => r.bucket.gated);
    const unported = gated.filter((r) => !state.ported.has(path.basename(r.file)));
    out.push({
      what: 'port_status.json refused',
      detail:
        `${state.port.refused} sources were refused for holding hand-written __asm, as a count ` +
        `with no address list. ${unported.length} gated sources have no file in port/, which is ` +
        `those ${state.port.refused} plus ${unported.length - state.port.refused} written after ` +
        `the pass last ran; nothing on disk separates them. NOT IMPORTED -- splitting them means ` +
        `re-running portable.py's own classifier, which belongs to the port step, not here.`,
    });

    out.push({
      what: 'attempts.author',
      detail:
        `left null for all ${state.reconstructions.length} attempts. The files record no author ` +
        `and the agent ids that wrote them were never persisted beside the source.`,
    });

    const shared = state.imports.slots.flatMap((s) =>
      callSitesOf(s).filter((c) => Option.isSome(c.address_shared_by)),
    );
    out.push({
      what: 'import_names.json address_shared_by',
      detail:
        `${shared.length} call sites report that the address they resolved to is published ` +
        `under more than one export name (_hread and _lread are the same code). There is no ` +
        `column for the alternatives, so import_bindings.api keeps the one name the resolver ` +
        `picked and the others are NOT IMPORTED. Four forwarded slots and one slot-level ` +
        `address_shared_by are lost the same way.`,
    });

    return out;
  }

  // ------------------------------------------------------------------ audit

  *audit(): EffectGen<ReadonlyArray<Check>, LegacyError | DbError> {
    const state = yield* this.readAll();
    const checks: Check[] = [];
    for (const query of auditQueries(state)) {
      const rows = yield* this.dependencies.Db.all(query.sql, query.params);
      const { actual, detail } = query.answer(rows);
      checks.push({
        question: query.question,
        sql: query.sql,
        expected: query.expected,
        actual,
        passed: actual === query.expected,
        detail: detail ?? [],
      });
    }
    return checks;
  }
}
