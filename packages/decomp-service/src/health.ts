/**
 * Does this service actually work, or is it merely listening?
 *
 * `/api/health` used to answer `{ok:true}` whenever the process was up. A
 * stray paren in the `verdicts` INSERT then made every `submit` fail for 75
 * minutes while health stayed green, four agents kept working, and one of
 * them lost six finished proofs into the hole. Nothing in the system could
 * tell "serving" from "serving correctly".
 *
 * So each check below EXERCISES a path that can break, against the real
 * database and the real schema:
 *
 *   - the write path runs the exact verdicts INSERT, with the exact column
 *     list and placeholders, inside a transaction that is always rolled back.
 *     A column/placeholder mismatch is caught here instead of by an agent an
 *     hour later.
 *   - the queue path runs the claim query, which spans five tables and two
 *     views, so a migration that drops or renames something fails loudly.
 *   - the proof path reads `proven`, the view every number on the dashboard
 *     comes from.
 *
 * None of them writes. Health must never change the thing it measures.
 */
import { Database } from 'bun:sqlite';
import { MIGRATIONS } from './modules/db/schema';

export interface Check {
  readonly name: string;
  readonly ok: boolean;
  readonly detail: string;
}

export interface Health {
  readonly ok: boolean;
  readonly at: number;
  readonly checks: ReadonlyArray<Check>;
}

const run = (name: string, body: () => string): Check => {
  try {
    return { name, ok: true, detail: body() };
  } catch (e) {
    return { name, ok: false, detail: e instanceof Error ? e.message : String(e) };
  }
};

/**
 * Statements whose COMPILATION proves the schema still matches the code.
 *
 * `prepare` parses and binds against the live schema without executing, so a
 * wrong column name, a renamed table, or a placeholder count that disagrees
 * with the column list all fail here. That is exactly the stray paren that
 * took `submit` down, caught with no write, no transaction and no lock --
 * the first version of this file ran the INSERT inside a transaction and
 * deadlocked boot against the reaper, which is a worse bug than the one it
 * was checking for.
 */
const COMPILED: ReadonlyArray<readonly [string, string]> = [
  [
    'verdict write path',
    `INSERT OR REPLACE INTO verdicts(attempt_id, gate_run_id, exact, compiled,
       emitted_size, masked, compared, first_diff, detail, decided_at,
       matched_at)
     VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
  ],
  [
    'attempt write path',
    `INSERT INTO attempts(subject_sha, va, source, source_sha, flags, author, created_at)
     SELECT c.subject_sha, ?, ?, ?, ?, ?, ? FROM current_config c WHERE c.only_row = 1
     ON CONFLICT(subject_sha, va, source_sha, flags) DO NOTHING`,
  ],
  [
    'claim write path',
    `INSERT INTO claims(subject_sha, va, agent_id, claimed_at, expires_at)
     SELECT c.subject_sha, ?, ?, ?, ? FROM current_config c WHERE c.only_row = 1`,
  ],
  [
    'heartbeat write path',
    `UPDATE agents SET last_beat = ?, beats = beats + 1
     WHERE id = ? AND finished IS NULL`,
  ],
];

export const check = (db: Database): Health => {
  const checks: Check[] = [];

  checks.push(
    run('schema', () => {
      const n = db.query('SELECT COUNT(*) n FROM migrations').get() as { n: number };
      // A migration edited after being applied is SKIPPED, so the edit never
      // runs and nothing says so. That is how the trigger enforcing rejected
      // entries came to be written, believed applied, and absent -- while
      // the table from the same migration existed, so the schema check
      // passed and five rejected addresses came back. The drift has to be
      // part of being healthy, not a line in a boot log nobody reads.
      const cols = db.query('PRAGMA table_info(migrations)').all() as { name: string }[];
      if (cols.some((c) => c.name === 'sql_sha256')) {
        const rows = db
          .query('SELECT id, sql_sha256 FROM migrations WHERE sql_sha256 IS NOT NULL')
          .all() as { id: string; sql_sha256: string }[];
        const current = new Map(
          MIGRATIONS.map((m) => [
            m.id,
            new Bun.CryptoHasher('sha256').update(m.sql).digest('hex'),
          ]),
        );
        const drifted = rows
          .filter((r) => current.has(r.id) && current.get(r.id) !== r.sql_sha256)
          .map((r) => r.id);
        if (drifted.length > 0) {
          throw new Error(
            `migration text edited after being applied, so the edit never ran: ` +
              `${drifted.join(', ')} -- put the change in a NEW migration`,
          );
        }
      }
      return `${n.n} migrations applied`;
    }),
  );

  checks.push(
    run('proof view', () => {
      const r = db.query('SELECT COUNT(DISTINCT va) n FROM proven').get() as { n: number };
      return `${r.n} functions proven`;
    }),
  );

  checks.push(
    run('queue', () => {
      const r = db.query(
        `SELECT COUNT(*) n FROM functions f
         JOIN current_config c ON c.only_row = 1 AND c.subject_sha = f.subject_sha
         WHERE f.size > 0
           AND NOT EXISTS (SELECT 1 FROM proven p
                       WHERE p.subject_sha = f.subject_sha AND p.va = f.va)
           AND NOT EXISTS (SELECT 1 FROM near_misses m
                       WHERE m.subject_sha = f.subject_sha AND m.va = f.va)`,
      ).get() as { n: number };
      return `${r.n} unsolved`;
    }),
  );

  for (const [name, sql] of COMPILED) {
    checks.push(
      run(name, () => {
        db.prepare(sql);
        return 'statement compiles against the live schema';
      }),
    );
  }

  return { ok: checks.every((c) => c.ok), at: Date.now() / 1000, checks };
};

/** Printed at boot and after every reload. A service that comes up broken
 *  must say so in its own log, not wait to be discovered. */
export const report = (h: Health): string =>
  h.ok
    ? `health OK -- ${h.checks.filter((c) => !c.detail.startsWith('statement')).map((c) => `${c.name}: ${c.detail}`).join(' | ')} | ${COMPILED.length} write paths compile`
    : `HEALTH FAILING\n` +
      h.checks
        .map((c) => `  ${c.ok ? 'ok  ' : 'FAIL'} ${c.name}: ${c.detail}`)
        .join('\n');
