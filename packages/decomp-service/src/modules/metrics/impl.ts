import { Option } from 'effect';
import { implementing, type EffectGen } from 'effective-modules';
import { modules } from '../index';
import type { DbError } from '../db/interface';
import type {
  Composition, Counted, GateRun, IMetrics, ImportSurface,
  Phase2, SeriesPoint, SymbolMap,
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
      `SELECT g.id AS id, g.started_at AS started_at, g.exact AS exact,
              g.toolchain_id AS toolchain_id,
              (SELECT COALESCE(SUM(size), 0) FROM
                 (SELECT DISTINCT va, size FROM proven WHERE gate_run_id = g.id))
                AS bytes_exact
       FROM gate_runs g ORDER BY g.started_at DESC LIMIT 1`,
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
    const from = now - sinceSeconds;
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
}
