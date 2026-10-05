/**
 * Two transactions at once, on the one connection this process has.
 *
 * SQLite has no nested transactions, so two overlapping `tx` calls make the
 * second `BEGIN` fail with "cannot start a transaction within a transaction".
 * The server runs five background workers and three of them are
 * transactional, so this is the ordinary case, not an edge: two workers --
 * the globals inventory and the import-name derivation -- failed on every
 * tick for as long as they were scheduled together, each recording nothing
 * and logging a blank line.
 *
 * `tx` serializes on a lock parked beside the connection. This test is the
 * only thing that holds it to that: without the lock it fails with the exact
 * production message.
 *
 * IT RUNS IN A CHILD PROCESS, and that is not incidental. `DB_PATH` is
 * resolved once when `./impl` is loaded, so setting `DECOMP_DB` inside this
 * file only works if nothing has imported that module yet -- and `sql.test.ts`
 * imports it. Run in the same process as the rest of the suite, this test
 * opened the database the SERVICE owns and took a write lock on it. A child
 * process with its own environment is the only way to be sure which database
 * is being written.
 */
import { expect, test } from 'bun:test';
// Type-only: the VALUE is imported dynamically below, so that `./impl`
// resolves its database path after this file has set DECOMP_DB.
import type { Effect as EffectNamespace } from 'effect';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

/** Set by the parent for the child run. Its presence is what turns this file
 *  from a test into the probe the test measures. */
const PROBE = 'DECOMP_TX_PROBE';

if (process.env[PROBE] === '1') {
  const { Effect } = await import('effect');
  const { DbImpl } = await import('./impl');
  const { modules } = await import('../index');
  const result = await Effect.runPromise(
    Effect.result(
      Effect.provide(
        Effect.gen(function* () {
          const db = yield* modules.Db;
          yield* db.migrate();
          const one = (label: string) =>
            Effect.gen(function* () {
              return yield* db.tx(function* () {
                yield* db.run('CREATE TABLE IF NOT EXISTS tx_probe (label TEXT PRIMARY KEY)');
                yield* db.run('INSERT INTO tx_probe(label) VALUES (?)', [label]);
                // Long enough that all three are in flight at once, which is
                // what makes the second BEGIN fail without the lock.
                yield* Effect.sleep('100 millis');
                return label;
              });
            });
          yield* Effect.all([one('a'), one('b'), one('c')], { concurrency: 'unbounded' });
          const stored = yield* db.all('SELECT label FROM tx_probe ORDER BY label');
          return stored.map((r) => (r as { label: string }).label).join(',');
        }),
        DbImpl.Layer,
      ) as EffectNamespace.Effect<string, unknown, never>,
    ),
  );
  console.log(
    result._tag === 'Success'
      ? `PROBE OK ${result.success}`
      : `PROBE FAILED ${JSON.stringify(result.failure)}`,
  );
} else {
  test('three transactions started together all commit', async () => {
    const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'decomp-tx-'));
    try {
      const child = Bun.spawn(['bun', import.meta.path], {
        env: { ...process.env, [PROBE]: '1', DECOMP_DB: path.join(scratch, 'tx.db') },
        stdout: 'pipe',
        stderr: 'pipe',
      });
      const [out, err] = await Promise.all([
        new Response(child.stdout).text(),
        new Response(child.stderr).text(),
      ]);
      await child.exited;
      // The whole output, not a match: a probe that died before printing must
      // not read as a silent pass.
      expect(`${out}${err}`.trim()).toContain('PROBE OK a,b,c');
    } finally {
      fs.rmSync(scratch, { recursive: true, force: true });
    }
  });
}
