/**
 * Every SQL statement in this package must compile against the live schema.
 *
 * A one-character error in an INSERT column list took `submit` down for 75
 * minutes. It was valid TypeScript, so nothing before runtime could see it,
 * and `/api/health` reported OK throughout because it only proved the process
 * was listening.
 *
 * `prepare()` parses and binds a statement without executing it, so it catches
 * exactly that class -- unknown column, unknown table, a placeholder count
 * that disagrees with the column list -- with no write and no lock. Running it
 * over every statement in the source turns a production outage into a failing
 * test.
 *
 * This is the stopgap the `effect` skill prescribes while `effect-qb` pins an
 * Effect release candidate: the real fix is a typed query builder, where these
 * are type errors in the editor. Delete this file when that lands.
 */
import { expect, test } from 'bun:test';
import { Database } from 'bun:sqlite';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { DB_PATH } from './modules/db/impl';

const SRC = path.join(import.meta.dir);

const sources = (dir: string): string[] =>
  readdirSync(dir).flatMap((n) => {
    const p = path.join(dir, n);
    if (statSync(p).isDirectory()) return sources(p);
    if (n === 'schema.ts') return [];   // DDL, applied by migrate, not re-run
    return n.endsWith('.ts') && !n.endsWith('.test.ts') ? [p] : [];
  });

/** Comments are stripped first: prose mentioning a table name is not SQL, and
 *  matching it produced six phantom failures on the first run. */
const stripComments = (text: string): string =>
  text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');

/** A string literal that BEGINS with a statement keyword. Interpolations
 *  become `?` so a generated IN-list still parses; a statement whose SHAPE
 *  depends on its interpolation cannot be checked this way and is skipped
 *  rather than guessed at. */
// `WITH` must look like a CTE: the bare word matched the English "with" in a
// prose template and reported it as broken SQL.
const KEYWORD =
  '(?:SELECT|INSERT|UPDATE|DELETE|WITH\\s+(?:RECURSIVE\\s+)?\\w+\\s*(?:\\(|AS\\b))';

/**
 * ALL THREE quote styles, because for a while this checked only backticks and
 * said nothing about the rest. It extracted 106 statements while the package
 * held 153: every single-quoted one -- 47 of them, 31% -- went unchecked by
 * the test whose whole purpose is that an unchecked statement took `submit`
 * down for 75 minutes. A one-line query reaching for the nearest quote mark
 * was enough to leave the harness.
 *
 * A guard with a silent blind spot is worse than a missing one: it reports a
 * pass over the part it can see and nobody asks about the rest.
 */
const STATEMENTS: ReadonlyArray<RegExp> = [
  new RegExp('`(\\s*' + KEYWORD + '[^`]*)`', 'gis'),
  new RegExp("'(\\s*" + KEYWORD + "[^']*)'", 'gis'),
  new RegExp('"(\\s*' + KEYWORD + '[^"]*)"', 'gis'),
];

/**
 * A `${cond ? 'A' : 'B'}` interpolation changes the statement's SHAPE, not a
 * bound value. Substituting `?` for it produced `WHERE x = ??` and reported a
 * working query as broken. Skipping such statements instead would be worse:
 * the globals module reaches the database through two of them, and a skipped
 * statement is one the harness has stopped checking without saying so.
 *
 * So each ternary is expanded into BOTH of its branches, and every resulting
 * statement is checked. A conditional clause is exactly where a column name
 * typo hides, because only one of the two shapes is exercised at a time.
 */
const TERNARY = /\$\{[^}?]*\?\s*(['"`])([^'"`]*)\1\s*:\s*(['"`])([^'"`]*)\3\s*\}/;

const shapes = (sql: string, depth = 0): string[] => {
  const m = TERNARY.exec(sql);
  if (m === null || depth >= 4) return [sql];
  return [m[2]!, m[4]!].flatMap((branch) =>
    shapes(sql.slice(0, m.index) + branch + sql.slice(m.index + m[0].length), depth + 1),
  );
};

const extract = (text: string): string[] => {
  const out: string[] = [];
  const stripped = stripComments(text);
  for (const m of STATEMENTS.flatMap((re) => [...stripped.matchAll(re)])) {
  for (const variant of shapes(m[1]!)) {
    const filled = variant.replace(/\$\{[^}]*\}/g, '?');
    if (filled.includes('${')) continue;
    // An interpolated TABLE name cannot become a placeholder -- the shape
    // depends on the interpolation, so there is nothing to check.
    if (/\b(?:FROM|JOIN|INTO|UPDATE|TABLE)\s+\?/i.test(filled)) continue;
    // PROSE that happens to open with a statement keyword is not SQL. An
    // error message beginning "DELETE matched 0 rows for ..." was reported as
    // a broken statement. Real SQL names what it acts on, so it carries at
    // least one clause keyword; a string with none of them touches no table
    // and has nothing about the schema to check.
    if (!/\b(?:FROM|INTO|SET|VALUES|WHERE|JOIN|TABLE)\b/i.test(filled)) continue;
    out.push(filled);
  }
  }
  return out;
};

test('every SQL statement compiles against the live schema', () => {
  const db = new Database(DB_PATH, { readonly: true });
  const failures: string[] = [];
  let checked = 0;

  for (const file of sources(SRC)) {
    for (const sql of extract(readFileSync(file, 'utf8'))) {
      checked++;
      try {
        db.prepare(sql);
      } catch (e) {
        failures.push(
          `${path.relative(SRC, file)}\n    ${(e as Error).message}\n    ${sql
            .trim()
            .split('\n')[0]!
            .slice(0, 100)}`,
        );
      }
    }
  }

  // A guard that checks nothing passes silently, which is the failure it
  // exists to prevent.
  // Was 40 while the extractor saw only backticks. The package holds 153
  // statements across the three quote styles; a floor well under that still
  // catches an extractor that has stopped matching.
  expect(checked).toBeGreaterThan(140);
  if (failures.length > 0) {
    throw new Error(
      `${failures.length} of ${checked} statements do not compile:\n  ` +
        failures.join('\n  '),
    );
  }
});

test('prepare catches the fault shapes that caused the outage', () => {
  const db = new Database(DB_PATH, { readonly: true });
  const faults: ReadonlyArray<readonly [string, string]> = [
    ['unknown column', 'INSERT INTO verdicts(attempt_id, nope) VALUES (?,?)'],
    ['placeholder mismatch', 'INSERT INTO verdicts(attempt_id, exact) VALUES (?)'],
    ['unknown table', 'SELECT * FROM verdicts_renamed'],
  ];
  for (const [name, sql] of faults) {
    expect(() => db.prepare(sql), name).toThrow();
  }
});
