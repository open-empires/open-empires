import { Option } from 'effect';
import {
  callSitesOf,
  hexOf,
  sha256,
  shortPath,
  type LegacyState,
} from './artifacts';

/**
 * What the database must be able to answer once the import has run.
 *
 * Declarations, not code that runs: each one carries the SQL it asks, the
 * answer the files say it must give, and how to read the rows. They live
 * apart from the import so the same questions can be asked of a database
 * nobody is importing into -- the import's own bookkeeping is never allowed
 * to be the thing that proves the import.
 *
 * `detail` is filled in whether or not a question passed, because two equal
 * counts over different sets is the failure these exist to catch.
 */
export interface Query {
  readonly question: string;
  /** Carried so a reader can re-ask it by hand. A check that reports only
   *  "passed" asks to be trusted about the one thing it is proving. */
  readonly sql: string;
  readonly params: ReadonlyArray<unknown>;
  readonly expected: string;
  readonly answer: (rows: ReadonlyArray<unknown>) => {
    readonly actual: string;
    readonly detail?: ReadonlyArray<string>;
  };
}

/** Every question, bound to the files that answer it. */
export const auditQueries = (state: LegacyState): ReadonlyArray<Query> => {
  const sha = state.subject.sha256;
  const scalar = (rows: ReadonlyArray<unknown>): string =>
    String((rows[0] as Record<string, unknown> | undefined)?.n ?? 0);

  const expectedExact = new Set(state.verdicts.exact);
  const gatedFlags = new Map<string, number>();
  for (const r of state.reconstructions) {
    if (!r.bucket.gated) continue;
    gatedFlags.set(r.flags, (gatedFlags.get(r.flags) ?? 0) + 1);
  }
  const apisFromSlots = new Set(
    state.imports.slots.flatMap((s) =>
      Option.match(s.name, { onNone: () => [], onSome: (n) => [n.toLowerCase()] }),
    ),
  );
  const apisFromBindings = new Set(
    state.imports.slots.flatMap((s) => callSitesOf(s).map((c) => c.name.toLowerCase())),
  );

  return [
    {
      question: 'functions in the inventory',
      sql: 'SELECT COUNT(*) AS n FROM functions WHERE subject_sha = ?',
      params: [sha],
      expected: String(state.inventory.functions.length),
      answer: (rows) => ({ actual: scalar(rows) }),
    },
    {
      question: 'rows in the proven view',
      sql: 'SELECT COUNT(*) AS n FROM proven WHERE subject_sha = ?',
      params: [sha],
      expected: String(expectedExact.size),
      answer: (rows) => ({ actual: scalar(rows) }),
    },
    {
      question: 'the proven ADDRESSES are exactly fn_verdicts.json exact',
      sql: 'SELECT va FROM proven WHERE subject_sha = ? ORDER BY va',
      params: [sha],
      expected: 'identical sets',
      answer: (rows) => {
        const got = new Set(rows.map((r) => Number((r as { va: number }).va)));
        const onlyProven = [...got].filter((va) => !expectedExact.has(va));
        const onlyFile = [...expectedExact].filter((va) => !got.has(va));
        return {
          actual:
            onlyProven.length === 0 && onlyFile.length === 0
              ? 'identical sets'
              : `${onlyProven.length} only in proven, ${onlyFile.length} only in fn_verdicts.json`,
          detail: [
            ...onlyProven.map((va) => `only in proven: ${hexOf(va)}`),
            ...onlyFile.map((va) => `only in fn_verdicts.json: ${hexOf(va)}`),
          ],
        };
      },
    },
    {
      question: 'proven split by the flags the attempt claims',
      sql: `SELECT flags, COUNT(*) AS n FROM proven WHERE subject_sha = ?
            GROUP BY flags ORDER BY flags`,
      params: [sha],
      expected: [...gatedFlags.entries()]
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([flags, n]) => `${flags}=${n}`)
        .join(' '),
      answer: (rows) => ({
        actual: rows
          .map((r) => {
            const row = r as { flags: string; n: number };
            return `${row.flags}=${row.n}`;
          })
          .join(' '),
      }),
    },
    {
      question: 'near-misses recorded',
      sql: 'SELECT COUNT(*) AS n FROM near_misses WHERE subject_sha = ?',
      params: [sha],
      expected: String(state.reconstructions.filter((r) => !r.bucket.gated).length),
      answer: (rows) => ({ actual: scalar(rows) }),
    },
    {
      question: 'no near-miss is also proven',
      sql: `SELECT n.va FROM near_misses n
            JOIN proven p ON p.subject_sha = n.subject_sha AND p.va = n.va
            WHERE n.subject_sha = ?`,
      params: [sha],
      expected: '0',
      answer: (rows) => ({
        actual: String(rows.length),
        detail: rows.map((r) => `both near-miss and proven: ${hexOf(Number((r as { va: number }).va))}`),
      }),
    },
    {
      question: 'import slots',
      sql: 'SELECT COUNT(*) AS n FROM import_slots WHERE subject_sha = ?',
      params: [sha],
      expected: String(state.imports.slots.length),
      answer: (rows) => ({ actual: scalar(rows) }),
    },
    {
      question: 'import bindings, one per (slot, call site)',
      sql: 'SELECT COUNT(*) AS n FROM import_bindings WHERE subject_sha = ?',
      params: [sha],
      expected: String(
        state.imports.slots.reduce((n, s) => n + callSitesOf(s).length, 0),
      ),
      answer: (rows) => ({ actual: scalar(rows) }),
    },
    {
      question: 'distinct APIs named anywhere, case-insensitively',
      sql: `SELECT COUNT(*) AS n FROM (
              SELECT DISTINCT LOWER(api) AS api FROM import_bindings WHERE subject_sha = ?
              UNION
              SELECT DISTINCT LOWER(name) AS api FROM import_slots
                WHERE subject_sha = ? AND name IS NOT NULL)`,
      params: [sha, sha],
      expected: String(new Set([...apisFromSlots, ...apisFromBindings]).size),
      answer: (rows) => ({ actual: scalar(rows) }),
    },
    {
      question: 'distinct APIs reachable through a CALL SITE alone',
      sql: `SELECT COUNT(DISTINCT LOWER(api)) AS n FROM import_bindings WHERE subject_sha = ?`,
      params: [sha],
      expected: String(apisFromBindings.size),
      answer: (rows) => ({
        actual: scalar(rows),
        detail: [
          `the 187 figure is the union with import_slots.name: the bindings alone name ` +
            `${apisFromBindings.size} APIs, and ${apisFromSlots.size} are named by a slot's ` +
            `surviving descriptor`,
        ],
      }),
    },
    {
      question: 'every attempt holds its source text',
      sql: `SELECT COUNT(*) AS n FROM attempts
            WHERE subject_sha = ? AND (source IS NULL OR LENGTH(source) = 0)`,
      params: [sha],
      expected: '0',
      answer: (rows) => ({ actual: scalar(rows) }),
    },
    {
      question: 'every stored source hashes to the file it came from',
      sql: 'SELECT va, flags, source, source_sha FROM attempts WHERE subject_sha = ?',
      params: [sha],
      expected: `${state.reconstructions.length} rows, every hash agreeing`,
      answer: (rows) => {
        const onDisk = new Map(
          state.reconstructions.map((r) => [`${r.va}:${r.flags}`, r]),
        );
        const detail: string[] = [];
        for (const raw of rows) {
          const row = raw as { va: number; flags: string; source: string; source_sha: string };
          const file = onDisk.get(`${row.va}:${row.flags}`);
          if (file === undefined) {
            detail.push(`${hexOf(row.va)} (${row.flags}): no file on disk claims this attempt`);
            continue;
          }
          // Two separate questions, both of which have to hold: the stored
          // hash must describe the stored text, and the stored text must be
          // the file's text. Checking only the first lets a correct hash of
          // the wrong source pass.
          if (sha256(row.source) !== row.source_sha) {
            detail.push(`${hexOf(row.va)}: stored source_sha does not describe the stored source`);
          }
          if (row.source_sha !== file.sourceSha) {
            detail.push(`${hexOf(row.va)}: stored source_sha differs from ${shortPath(file.file)}`);
          }
        }
        return {
          actual:
            detail.length === 0
              ? `${rows.length} rows, every hash agreeing`
              : `${rows.length} rows, ${detail.length} disagreement(s)`,
          detail,
        };
      },
    },
    {
      question: 'bytes covered by a current proof',
      sql: 'SELECT COALESCE(SUM(size), 0) AS n FROM proven WHERE subject_sha = ?',
      params: [sha],
      expected: String(state.report.bytes_exact),
      answer: (rows) => ({ actual: scalar(rows) }),
    },
    {
      question: 'proofs made under a configuration no longer in force',
      sql: 'SELECT COUNT(*) AS n FROM superseded',
      params: [],
      expected: '0',
      answer: (rows) => ({ actual: scalar(rows) }),
    },
    {
      question: 'gate runs',
      sql: 'SELECT COUNT(*) AS n FROM gate_runs WHERE subject_sha = ?',
      params: [sha],
      expected: '1',
      answer: (rows) => ({ actual: scalar(rows) }),
    },
    {
      question: 'verdicts carrying the per-function masked/compared figures',
      sql: `SELECT COUNT(*) AS n FROM verdicts v JOIN gate_runs g ON g.id = v.gate_run_id
            WHERE g.subject_sha = ? AND v.masked IS NOT NULL`,
      params: [sha],
      expected: String(state.report.weak_detail.length),
      answer: (rows) => ({
        actual: scalar(rows),
        detail: [
          `the gate computed masked/compared for every function and persisted only the ` +
            `${state.report.weak_detail.length} weakest, so the other verdicts carry null ` +
            `rather than a figure nobody wrote down`,
        ],
      }),
    },
    {
      question: 'port files by state',
      sql: `SELECT state, COUNT(*) AS n FROM port_files WHERE subject_sha = ?
            GROUP BY state ORDER BY state`,
      params: [sha],
      expected: `converted=${state.ported.size - state.port.needs_globals.length} needs_globals=${state.port.needs_globals.length}`,
      answer: (rows) => ({
        actual: rows
          .map((r) => {
            const row = r as { state: string; n: number };
            return `${row.state}=${row.n}`;
          })
          .join(' '),
      }),
    },
    {
      question: 'near-miss headers: how much of each column the prose yielded',
      sql: `SELECT COUNT(*) AS rows_total,
                   COUNT(blocked_class) AS with_class,
                   COUNT(eliminated) AS with_eliminated,
                   COUNT(note) AS with_note
            FROM near_misses WHERE subject_sha = ?`,
      params: [sha],
      expected: `note on all ${state.reconstructions.filter((r) => !r.bucket.gated).length}`,
      answer: (rows) => {
        const row = rows[0] as {
          rows_total: number; with_class: number;
          with_eliminated: number; with_note: number;
        };
        return {
          actual: `note on all ${row.with_note}`,
          detail: [
            `${row.with_class} of ${row.rows_total} headers carry an explicit "Class:" label; ` +
              `the rest are left null rather than classified from prose`,
            `${row.with_eliminated} of ${row.rows_total} carry a labelled elimination list`,
            `all ${row.with_note} keep the whole header verbatim, so nothing the author wrote is lost`,
          ],
        };
      },
    },
    {
      question: 'the prover every current proof is attributed to',
      sql: `SELECT t.cl_sha256, t.flags, t.comp_id, c.subject_sha
            FROM current_config c JOIN toolchains t ON t.id = c.toolchain_id
            WHERE c.only_row = 1`,
      params: [],
      expected: '1 configuration in force',
      answer: (rows) => {
        const row = rows[0] as
          | { cl_sha256: string; flags: string; comp_id: string | null; subject_sha: string }
          | undefined;
        return {
          actual: rows.length === 1 ? '1 configuration in force' : `${rows.length} rows`,
          detail:
            row === undefined
              ? []
              : [
                  `cl.exe sha256 ${row.cl_sha256}`,
                  `flags ${row.flags}`,
                  `@comp.id ${row.comp_id ?? 'not read'}`,
                  `subject ${row.subject_sha}`,
                ],
        };
      },
    },
    {
      question: 'gate_report.json inventory_functions against the inventory it counts',
      sql: 'SELECT COUNT(*) AS n FROM functions WHERE subject_sha = ?',
      params: [sha],
      expected: String(state.report.inventory_functions),
      answer: (rows) => ({ actual: scalar(rows) }),
    },
  ];
};
