/**
 * Rejected addresses must stay out of the inventory, whoever inserts them.
 *
 * This existed once as a comment in a migration and not as a trigger. The
 * trigger was written into migration 007 AFTER 007 had already been recorded
 * as applied, so the runner skipped it; the table from the same migration did
 * exist, so the schema check passed and everything looked right. Five
 * addresses already judged not to be function entries -- one of which decodes
 * to `inc ebp; hlt` -- were back in the inventory within the hour, re-seeded
 * by the legacy import from a JSON file that still lists them.
 *
 * So the rule is tested, against a FRESH database, as a property of the
 * schema rather than of whichever producer happens to run. Live state is
 * never touched: a test that writes to the system of record is a test that
 * can corrupt the thing it is checking.
 */
import { expect, test } from 'bun:test';
import { Database } from 'bun:sqlite';
import { MIGRATIONS } from './schema';

const SHA = 'a'.repeat(64);
const OTHER = 'b'.repeat(64);

const migrated = (): Database => {
  const db = new Database(':memory:');
  db.exec('CREATE TABLE IF NOT EXISTS migrations (id TEXT PRIMARY KEY, applied_at REAL NOT NULL)');
  for (const m of MIGRATIONS) db.exec(m.sql);
  db.query(
    `INSERT INTO subjects(sha256, path, size, image_base, text_lo, text_hi, added_at)
     VALUES (?,?,?,?,?,?,?)`,
  ).run(SHA, '/dev/null', 0, 0x400000, 0x401000, 0x62847d, 0);
  return db;
};

const insert = (db: Database, sha: string, va: number, size = 16) =>
  db
    .query(
      `INSERT INTO functions(subject_sha, va, size, discovered_by)
       VALUES (?,?,?,'test') ON CONFLICT(subject_sha, va) DO NOTHING`,
    )
    .run(sha, va, size).changes;

const reject = (db: Database, va: number, sha = SHA) =>
  db
    .query(
      `INSERT INTO rejected_entries(subject_sha, va, reason, evidence, rejected_at)
       VALUES (?,?,'not an entry','inc ebp; hlt',0)`,
    )
    .run(sha, va);

test('the trigger exists at all', () => {
  const names = (
    migrated().query("SELECT name FROM sqlite_master WHERE type='trigger'").all() as {
      name: string;
    }[]
  ).map((r) => r.name);
  expect(names).toContain('functions_honour_rejections');
});

test('a rejected address cannot be inserted, by any writer', () => {
  const db = migrated();
  reject(db, 0x5a4c34);
  expect(insert(db, SHA, 0x5a4c34)).toBe(0);
  expect(
    (db.query('SELECT COUNT(*) n FROM functions WHERE va = ?').get(0x5a4c34) as { n: number }).n,
  ).toBe(0);
});

test('the skip does not abort the rest of the statement', () => {
  const db = migrated();
  reject(db, 0x5a4c34);
  // One multi-row INSERT holding a rejected address beside good ones. With
  // RAISE(ABORT) the whole statement would fail and the legacy import would
  // lose every function after the first rejected address.
  db.exec(`INSERT INTO functions(subject_sha, va, size, discovered_by) VALUES
    (${JSON.stringify(SHA)}, ${0x401000}, 16, 'test'),
    (${JSON.stringify(SHA)}, ${0x5a4c34}, 2,  'test'),
    (${JSON.stringify(SHA)}, ${0x402000}, 16, 'test')`);
  const vas = (db.query('SELECT va FROM functions ORDER BY va').all() as { va: number }[]).map(
    (r) => r.va,
  );
  expect(vas).toEqual([0x401000, 0x402000]);
});

test('a rejection is scoped to its subject', () => {
  const db = migrated();
  db.query(
    `INSERT INTO subjects(sha256, path, size, image_base, text_lo, text_hi, added_at)
     VALUES (?,?,?,?,?,?,?)`,
  ).run(OTHER, '/dev/null', 0, 0x400000, 0x401000, 0x62847d, 0);
  reject(db, 0x5a4c34, SHA);
  // The same address under a DIFFERENT subject is a different question: the
  // bytes there are not the bytes this rejection was decided from.
  expect(insert(db, OTHER, 0x5a4c34)).toBe(1);
  expect(insert(db, SHA, 0x5a4c34)).toBe(0);
});

test('an address with no rejection still inserts', () => {
  const db = migrated();
  reject(db, 0x5a4c34);
  expect(insert(db, SHA, 0x401000)).toBe(1);
});
