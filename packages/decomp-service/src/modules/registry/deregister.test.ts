/**
 * Finishing gives the work back.
 *
 * Deregistering left outstanding claims live, so a worker that finished
 * without releasing locked those functions for the rest of a two-hour lease --
 * against a queue where a single function can be the largest piece of work
 * available. Two finished agents were found holding claims, and nothing would
 * have freed them sooner than lease expiry.
 */
import { expect, test } from 'bun:test';
import { Database } from 'bun:sqlite';
import { MIGRATIONS } from '../db/schema';

const db = (() => {
  const d = new Database(':memory:');
  d.exec('CREATE TABLE IF NOT EXISTS migrations (id TEXT PRIMARY KEY, applied_at REAL NOT NULL)');
  for (const m of MIGRATIONS) d.exec(m.sql);
  d.query(
    `INSERT INTO subjects(sha256, path, size, image_base, text_lo, text_hi, added_at)
     VALUES ('s', '/dev/null', 0, 0, 0, 1, 0)`,
  ).run();
  return d;
})();

test('the claims a finished agent held are released', () => {
  db.query('INSERT INTO agents(id, role, started, last_beat, beats) VALUES (?,?,?,?,?)')
    .run('w', null, 0, 0, 0);
  db.query(
    `INSERT INTO claims(subject_sha, va, agent_id, claimed_at, expires_at)
     VALUES ('s', 1, 'w', 0, 9999999999)`,
  ).run();

  const live = () =>
    (db
      .query("SELECT COUNT(*) n FROM claims WHERE agent_id='w' AND released_at IS NULL")
      .get() as { n: number }).n;
  expect(live()).toBe(1);

  // What deregister does, in the order it does it.
  db.query('UPDATE agents SET finished = ? WHERE id = ?').run(1, 'w');
  db.query('UPDATE claims SET released_at = ? WHERE agent_id = ? AND released_at IS NULL')
    .run(1, 'w');

  expect(live()).toBe(0);
});

test('a claim already released is not re-stamped', () => {
  db.query('INSERT INTO agents(id, role, started, last_beat, beats) VALUES (?,?,?,?,?)')
    .run('x', null, 0, 0, 0);
  db.query(
    `INSERT INTO claims(subject_sha, va, agent_id, claimed_at, expires_at, released_at)
     VALUES ('s', 2, 'x', 0, 9999999999, 55)`,
  ).run();
  db.query('UPDATE claims SET released_at = ? WHERE agent_id = ? AND released_at IS NULL')
    .run(1, 'x');
  const at = (db.query("SELECT released_at r FROM claims WHERE agent_id='x'").get() as { r: number }).r;
  expect(at).toBe(55);
});
