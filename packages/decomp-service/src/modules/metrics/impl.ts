import { Option } from 'effect';
import { implementing, type EffectGen } from 'effective-modules';
import { modules } from '../index';
import type { DbError } from '../db/interface';
import type {
  Composition, Counted, GateRun, IMetrics, ImportSurface,
  Blockers, InventoryHealth, Phase2, SeriesPoint, SymbolMap,
} from './interface';

const num = (v: unknown): number => (typeof v === 'number' ? v : Number(v ?? 0));
const counted = (rows: ReadonlyArray<unknown>): ReadonlyArray<Counted> =>
  rows.map((r) => {
    const o = r as Record<string, unknown>;
    return { key: String(o.key ?? 'unknown'), n: num(o.n) };
  });

export class MetricsImpl
  extends implementing(modules.Metrics).uses(modules.Db)
  implements IMetrics
{
  *phase2(): EffectGen<Phase2, DbError> {
    const db = this.dependencies.Db;
    // `proven` is a view that joins current_config, so everything below is
    // automatically about the compiler and subject in force -- a toolchain
    // change retires stale proofs with no flag to set and nothing to remember.
    const row = (yield* db.one(`
      SELECT
        (SELECT COUNT(*) FROM functions)                       AS inventory,
        (SELECT COUNT(DISTINCT va) FROM proven)                AS proven,
        (SELECT COUNT(*) FROM near_misses)                     AS near,
        (SELECT COALESCE(SUM(size), 0) FROM
           (SELECT DISTINCT va, size FROM proven))             AS bytes_proven,
        (SELECT COUNT(DISTINCT va) FROM proven
           WHERE compared > 0 AND masked * 1.0 / (masked + compared) > 0.25) AS weak,
        (SELECT COUNT(*) FROM crt_identifications)             AS crt,
        (SELECT COUNT(DISTINCT va) FROM superseded)            AS superseded,
        (SELECT text_hi - text_lo FROM subjects
           JOIN current_config c ON c.subject_sha = subjects.sha256
           WHERE c.only_row = 1)                               AS span
    `)) as Record<string, unknown>;
    const proven = num(row?.proven);
    const bytes = num(row?.bytes_proven);
    const span = num(row?.span) || 0x62847d - 0x401000;
    const crt = num(row?.crt);
    return {
      inventory: num(row?.inventory),
      proven,
      near: num(row?.near),
      open: num(row?.inventory) - proven - num(row?.near),
      bytesProven: bytes,
      textSpan: span,
      pctText: (100 * bytes) / span,
      weak: num(row?.weak),
      crt,
      reconstructions: proven - crt,
      superseded: num(row?.superseded),
    };
  }

  *lastGateRun(): EffectGen<Option.Option<GateRun>, DbError> {
    const r = (yield* this.dependencies.Db.one(
      // gate_runs carries no byte total; bytes are summed from the verdicts
      // that run produced, so the two can never disagree.
      // `at` is the newest VERDICT this run decided, not when the run row was
      // created. A run is reused for the life of a toolchain, so started_at
      // froze at the import and the dashboard said "checked 3.7h ago" while
      // verdicts were landing every few seconds. "Checked" means the last
      // time the compiler actually answered.
      `SELECT g.id AS id, g.exact AS exact, g.toolchain_id AS toolchain_id,
              COALESCE((SELECT MAX(v.decided_at) FROM verdicts v
                        WHERE v.gate_run_id = g.id), g.started_at) AS started_at,
              (SELECT COALESCE(SUM(size), 0) FROM
                 (SELECT DISTINCT va, size FROM proven WHERE gate_run_id = g.id))
                AS bytes_exact
       -- Ordered by the newest VERDICT, not by when the run row was created.
       -- Ordering by started_at picked the run created most recently, which
       -- is the /O1 toolchain's -- a run that answers rarely -- and reported
       -- ITS last verdict as the time the compiler last ran. The dashboard
       -- said the proof had not run in 6 hours while the /O2 run had been
       -- answering 2.5 hours earlier. "Last checked" is the last time the
       -- compiler answered about anything.
       FROM gate_runs g ORDER BY started_at DESC LIMIT 1`,
    )) as Record<string, unknown> | null;
    return r === null
      ? Option.none()
      : Option.some({
          id: num(r.id), at: num(r.started_at), exact: num(r.exact),
          bytesExact: num(r.bytes_exact), toolchainId: String(r.toolchain_id),
        });
  }

  *composition(): EffectGen<Option.Option<Composition>, DbError> {
    const r = (yield* this.dependencies.Db.one(
      `SELECT * FROM composition_current LIMIT 1`,
    )) as Record<string, unknown> | null;
    return r === null
      ? Option.none()
      : Option.some({
          runId: num(r.id),
          at: r.finished_at === null || r.finished_at === undefined
            ? Option.none()
            : Option.some(num(r.finished_at)),
          placed: num(r.placed),
          placedBytes: num(r.placed_bytes),
          maskedBytes: num(r.masked_bytes),
          diffBytes: num(r.diff_bytes),
          spanBytes: num(r.text_hi) - num(r.text_lo),
        });
  }

  *blockedClasses(): EffectGen<ReadonlyArray<Counted>, DbError> {
    return counted(
      yield* this.dependencies.Db.all(
        `SELECT COALESCE(blocked_class, 'unclassified') AS key, COUNT(*) AS n
         FROM near_misses GROUP BY blocked_class ORDER BY n DESC`,
      ),
    );
  }

  *importSurface(): EffectGen<ImportSurface, DbError> {
    const db = this.dependencies.Db;
    const head = (yield* db.one(`
      SELECT (SELECT COUNT(*) FROM import_slots)        AS slots,
             (SELECT COUNT(*) FROM import_bindings)     AS bindings,
             (SELECT COUNT(*) FROM import_bindings
                WHERE evidence = 'call-operand-verified') AS verified,
             (SELECT COUNT(*) FROM (
                SELECT LOWER(api) AS n FROM import_bindings WHERE api IS NOT NULL
                UNION
                SELECT LOWER(name) FROM import_slots WHERE name IS NOT NULL)) AS apis
    `)) as Record<string, unknown>;
    return {
      slots: num(head?.slots),
      bindings: num(head?.bindings),
      bindingsVerified: num(head?.verified),
      distinctApis: num(head?.apis),
      byResolution: counted(
        yield* db.all(`SELECT resolution AS key, COUNT(*) AS n FROM import_slots
                       GROUP BY resolution ORDER BY n DESC`),
      ),
    };
  }

  *symbolMap(): EffectGen<SymbolMap, DbError> {
    const db = this.dependencies.Db;
    const head = (yield* db.one(
      `SELECT COUNT(name) AS named, COUNT(DISTINCT class_name) AS classes
       FROM functions WHERE name IS NOT NULL`,
    )) as Record<string, unknown>;
    return {
      named: num(head?.named),
      classes: num(head?.classes),
      byConfidence: counted(
        yield* db.all(
          `SELECT name_confidence AS key, COUNT(*) AS n FROM functions
           WHERE name IS NOT NULL GROUP BY name_confidence ORDER BY n DESC`,
        ),
      ),
    };
  }

  *portSurface(): EffectGen<ReadonlyArray<Counted>, DbError> {
    return counted(
      yield* this.dependencies.Db.all(
        `SELECT state AS key, COUNT(*) AS n FROM port_files
         GROUP BY state ORDER BY n DESC`,
      ),
    );
  }

  *progress(
    sinceSeconds: number,
    buckets: number,
  ): EffectGen<ReadonlyArray<SeriesPoint>, DbError> {
    const now = Date.now() / 1000;
    // FROM THE FIRST PROOF, not from a fixed window.
    //
    // A 24-hour window answered "what happened today", which is not the
    // question the chart is on the page to answer. Progress on this is
    // measured in weeks, and a window that slides forward hides the shape of
    // it: the early climb drops off the left edge and the curve always looks
    // like whatever the last day did. The series now starts at the earliest
    // recorded proof, so the chart shows the whole record and `sinceSeconds`
    // is only a floor for the case where nothing is proven yet.
    const earliest = (yield* this.dependencies.Db.one(
      'SELECT MIN(decided_at) AS at FROM proven',
    )) as { at: number | null } | null;
    // Exactly the first proof, not the earlier of that and a window. Taking
    // the earlier padded the left of the chart with hours in which nothing
    // had been collected yet, which reads as a flat start that never
    // happened. `sinceSeconds` is only the fallback for an empty record.
    const from = earliest?.at == null ? now - sinceSeconds : earliest.at;
    // Each bucket is a real boundary in the data, not a moment a collector
    // happened to wake up: `proven` carries the decision time of every
    // verdict, so the cumulative count at time t is just a query.
    const rows = yield* this.dependencies.Db.all(
      `WITH RECURSIVE b(i) AS (
         SELECT 0 UNION ALL SELECT i + 1 FROM b WHERE i + 1 < ?
       ),
       t AS (SELECT ? + (? - ?) * (i + 1.0) / ? AS at FROM b)
       SELECT t.at AS at,
              (SELECT COUNT(DISTINCT va) FROM proven p
                 WHERE p.decided_at <= t.at)                      AS proven,
              (SELECT COALESCE(SUM(size), 0) FROM
                 (SELECT DISTINCT va, size FROM proven p2
                    WHERE p2.decided_at <= t.at))                 AS bytes
       FROM t ORDER BY t.at`,
      [buckets, from, now, from, buckets],
    );
    return rows.map((raw) => {
      const o = raw as Record<string, unknown>;
      return { at: num(o.at), proven: num(o.proven), bytes: num(o.bytes) };
    });
  }

  *queue(): EffectGen<{ depth: number; claimed: number }, DbError> {
    const r = (yield* this.dependencies.Db.one(
      `SELECT
         (SELECT COUNT(*) FROM functions f
            WHERE NOT EXISTS (SELECT 1 FROM proven p WHERE p.va = f.va)
              AND NOT EXISTS (SELECT 1 FROM near_misses m WHERE m.va = f.va)
              AND NOT EXISTS (SELECT 1 FROM claims cl WHERE cl.va = f.va
                            AND cl.released_at IS NULL AND cl.expires_at > ?)) AS depth,
         (SELECT COUNT(*) FROM claims
            WHERE released_at IS NULL AND expires_at > ?)                       AS claimed`,
      [Date.now() / 1000, Date.now() / 1000],
    )) as Record<string, unknown>;
    return { depth: num(r?.depth), claimed: num(r?.claimed) };
  }

  *workingOn(): EffectGen<
    Option.Option<{ readonly note: string; readonly updatedAt: number }>,
    DbError
  > {
    const row = (yield* this.dependencies.Db.one(
      'SELECT note, updated_at FROM working_on WHERE only_row = 1',
    )) as { note: string; updated_at: number } | null;
    return row === null
      ? Option.none()
      : Option.some({ note: row.note, updatedAt: num(row.updated_at) });
  }

  *setWorkingOn(note: string): EffectGen<void, DbError> {
    yield* this.dependencies.Db.run(
      `INSERT INTO working_on(only_row, note, updated_at) VALUES (1,?,?)
       ON CONFLICT(only_row) DO UPDATE SET note = excluded.note,
                                          updated_at = excluded.updated_at`,
      [note, Date.now() / 1000],
    );
  }

  *blockers(): EffectGen<Blockers, DbError> {
    const db = this.dependencies.Db;

    const parked = (yield* db.all(
      `SELECT m.blocked_class AS cause, COUNT(*) AS functions,
              COALESCE(SUM(f.size), 0) AS bytes
         FROM near_misses m JOIN functions f ON f.va = m.va
        WHERE m.blocked_class IS NOT NULL AND TRIM(m.blocked_class) <> ''
        GROUP BY m.blocked_class
        ORDER BY bytes DESC`,
    )) as ReadonlyArray<Record<string, unknown>>;

    const row = (yield* db.one(
      `SELECT
         (SELECT COUNT(*) FROM near_misses
            WHERE blocked_class IS NULL OR TRIM(blocked_class) = '')      AS no_cause,
         (SELECT COALESCE(residue_bytes, 0) FROM gap_scans
           ORDER BY at DESC LIMIT 1)                                      AS unfound_bytes,
         (SELECT COALESCE(residue_gaps, 0) FROM gap_scans
           ORDER BY at DESC LIMIT 1)                                      AS unfound_gaps,
         (SELECT COALESCE(undecodable, 0) FROM inventory_audits
           ORDER BY at DESC LIMIT 1)                                      AS undecodable,
         (SELECT COUNT(*) FROM import_slots
           WHERE resolution = 'no-cached-call-site')                      AS unanswered_slots,
         (SELECT COUNT(*) FROM import_slots)                              AS slots_total,
         (SELECT COALESCE(SUM(enumerated - attributed), 0)
            FROM globals_pointer_coverage WHERE target = 'data')          AS unattributed_ptrs,
         (SELECT COALESCE(SUM(enumerated), 0)
            FROM globals_pointer_coverage WHERE target = 'data')          AS ptrs_total,
         (SELECT COUNT(*) FROM port_stranded_literals)                    AS stranded,
         (SELECT COUNT(DISTINCT va) FROM port_stranded_literals)          AS stranded_fns`,
    )) as Record<string, unknown> | null;

    return {
      parked: parked.map((r) => ({
        cause: String(r.cause),
        functions: num(r.functions),
        bytes: num(r.bytes),
      })),
      parkedWithoutCause: num(row?.no_cause),
      unfoundCodeBytes: num(row?.unfound_bytes),
      unfoundCodeStretches: num(row?.unfound_gaps),
      undecodableEntries: num(row?.undecodable),
      unansweredImportSlots: num(row?.unanswered_slots),
      importSlotsTotal: num(row?.slots_total),
      unattributedDataPointers: num(row?.unattributed_ptrs),
      dataPointersTotal: num(row?.ptrs_total),
      strandedLiterals: num(row?.stranded),
      strandedInFunctions: num(row?.stranded_fns),
    };
  }

  *inventoryHealth(): EffectGen<InventoryHealth, DbError> {
    const db = this.dependencies.Db;
    // Newest audit for the subject in force. Joining current_config rather
        // than taking the newest row outright: an audit of a different subject
    // is not an answer about this one.
    const a = (yield* db.one(
      `SELECT ia.at AS at, ia.entries AS entries, ia.workable AS workable,
              ia.undecodable AS undecodable,
              ia.undecodable_proven AS undecodable_proven,
              ia.repaired AS repaired
         FROM inventory_audits ia
         JOIN current_config c ON c.subject_sha = ia.subject_sha
        WHERE c.only_row = 1
        ORDER BY ia.at DESC LIMIT 1`,
    )) as Record<string, unknown> | null;

    const rejected = (yield* db.one(
      `SELECT COUNT(*) AS n FROM rejected_entries r
         JOIN current_config c ON c.subject_sha = r.subject_sha
        WHERE c.only_row = 1`,
    )) as Record<string, unknown> | null;

    const byEvidence = (yield* db.all(
      `SELECT COALESCE(f.discovered_by, 'pre-existing') AS evidence,
              COUNT(*) AS functions,
              SUM(CASE WHEN EXISTS (SELECT 1 FROM proven p WHERE p.va = f.va)
                       THEN 1 ELSE 0 END) AS proven
         FROM functions f
        GROUP BY evidence
        ORDER BY functions DESC`,
    )) as ReadonlyArray<Record<string, unknown>>;

    const gaps = (yield* db.one(
      `SELECT g.at, g.text_bytes, g.covered_bytes, g.padding_bytes,
              g.residue_gaps, g.residue_bytes
         FROM gap_scans g
         JOIN current_config c ON c.subject_sha = g.subject_sha
        WHERE c.only_row = 1 ORDER BY g.at DESC LIMIT 1`,
    )) as Record<string, unknown> | null;

    return {
      gaps:
        gaps === null
          ? Option.none()
          : Option.some({
              at: num(gaps.at),
              textBytes: num(gaps.text_bytes),
              coveredBytes: num(gaps.covered_bytes),
              paddingBytes: num(gaps.padding_bytes),
              residueGaps: num(gaps.residue_gaps),
              residueBytes: num(gaps.residue_bytes),
            }),
      audit:
        a === null
          ? Option.none()
          : Option.some({
              at: num(a.at),
              entries: num(a.entries),
              workable: num(a.workable),
              undecodable: num(a.undecodable),
              undecodableProven: num(a.undecodable_proven),
              repaired: num(a.repaired),
            }),
      rejected: num(rejected?.n),
      byEvidence: byEvidence.map((r) => ({
        evidence: String(r.evidence),
        functions: num(r.functions),
        proven: num(r.proven),
      })),
    };
  }
}
