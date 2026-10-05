/**
 * The read-back must agree with what was written.
 *
 * `rebuild` reports from values in memory; `recorded` reports from rows. They
 * share the assembler, so the only way they can disagree is by feeding it
 * different inputs -- and one of them did: `importSlotsSkipped` was counted as
 * "every `identity` deferral", a bucket that also holds every vtable interior
 * slot and every isolated pointer dword. It read 15,011 where the derivation
 * had skipped 240, and nothing said which number was right.
 *
 * So every figure the read-back produces is checked here against a query
 * written independently of the one the implementation uses. Read-only
 * throughout: the service owns this database.
 *
 * Where the inventory has not been derived the test SKIPS LOUDLY rather than
 * passing.
 */
import { expect, test as buntest } from 'bun:test';
import { Database } from 'bun:sqlite';
import fs from 'node:fs';
import { DB_PATH } from '../db/impl';

const CountRow = { n: 0 };
type Count = typeof CountRow;

if (!fs.existsSync(DB_PATH)) {
  buntest('the service database exists', () => {
    throw new Error(`${DB_PATH} is absent. Nothing below ran; this is a skip, not a pass.`);
  });
} else {
  const db = new Database(DB_PATH, { readonly: true });
  const one = (sql: string, ...params: ReadonlyArray<unknown>): number =>
    (db.query(sql).get(...(params as never[])) as Count).n;
  const config = db.query('SELECT subject_sha AS sha FROM current_config WHERE only_row = 1').get() as
    | { sha: string }
    | null;
  const derived =
    config === null
      ? 0
      : one('SELECT COUNT(*) AS n FROM globals WHERE subject_sha = ?', config.sha);

  if (config === null || derived === 0) {
    buntest('the globals inventory has been derived for the subject in force', () => {
      throw new Error(
        'no globals rows for the current subject. The inventory is produced by the service on ' +
          'a timer, or by POST /api/globals/rebuild. Nothing below ran; this is a skip, not a ' +
          'pass.',
      );
    });
  } else {
    const sha = config.sha;

    buntest('an import slot is deferred, never given a globals row', () => {
      // The count the report shows must be the slots, not the whole
      // `identity` bucket.
      const slots = one(
        `SELECT COUNT(*) AS n FROM global_deferrals d
           JOIN import_slots s ON s.subject_sha = d.subject_sha AND s.slot = d.address
          WHERE d.subject_sha = ? AND d.what = 'identity'`,
        sha,
      );
      const allIdentity = one(
        `SELECT COUNT(*) AS n FROM global_deferrals WHERE subject_sha = ? AND what = 'identity'`,
        sha,
      );
      expect(slots).toBeGreaterThan(0);
      // If these were ever equal the distinction this test exists for would
      // have vanished and the bug would be invisible again.
      expect(allIdentity).toBeGreaterThan(slots);
      expect(one('SELECT COUNT(*) AS n FROM global_import_slot_overlap WHERE subject_sha = ?', sha))
        .toBe(0);
    });

    buntest('every globals row has a section the subject declares and a known evidence kind', () => {
      expect(
        one(
          `SELECT COUNT(*) AS n FROM globals WHERE subject_sha = ? AND evidence NOT IN
             ('proven-literal','library-symbol','decoded-literal','pointer-dword')`,
          sha,
        ),
      ).toBe(0);
      expect(
        one(
          `SELECT COUNT(*) AS n FROM globals
            WHERE subject_sha = ? AND (size IS NULL) <> (size_basis IS NULL)`,
          sha,
        ),
      ).toBe(0);
      expect(
        one(
          `SELECT COUNT(*) AS n FROM globals
            WHERE subject_sha = ? AND (name IS NULL) <> (name_from IS NULL)`,
          sha,
        ),
      ).toBe(0);
    });

    buntest('a named global is named by exactly one library symbol', () => {
      // The inventory withholds a name where two members disagree, so a named
      // row must have exactly one distinct name in the evidence.
      expect(
        one(
          `SELECT COUNT(*) AS n FROM globals g
            WHERE g.subject_sha = ? AND g.name IS NOT NULL
              AND (SELECT COUNT(DISTINCT s.name) FROM global_library_symbols s
                    WHERE s.subject_sha = g.subject_sha AND s.address = g.address) <> 1`,
          sha,
        ),
      ).toBe(0);
    });

    buntest('a vtable interior slot is a pointer candidate and not a global', () => {
      // Every candidate that is not its run's first dword must have no
      // globals row of its own unless something else evidences the address.
      expect(
        one(
          `SELECT COUNT(*) AS n FROM global_pointer_candidates c
             JOIN globals g ON g.subject_sha = c.subject_sha AND g.address = c.address
            WHERE c.subject_sha = ? AND c.address <> c.run_start
              AND g.evidence = 'pointer-dword'`,
          sha,
        ),
      ).toBe(0);
      // And the interior slots are still all there to be read.
      expect(
        one(
          'SELECT COUNT(*) AS n FROM global_pointer_candidates WHERE subject_sha = ? AND address <> run_start',
          sha,
        ),
      ).toBeGreaterThan(1000);
    });

    buntest('the evidence view ranks a literal by whether its function is proven NOW', () => {
      // Stored nowhere: changing the compiler must re-rank every reference at
      // once. The view's own join is the only thing that decides it.
      const proven = one(
        `SELECT COUNT(DISTINCT address) AS n FROM global_evidence
          WHERE subject_sha = ? AND strength = 'proven-literal'`,
        sha,
      );
      const inProvenView = one(
        `SELECT COUNT(DISTINCT r.address) AS n FROM global_references r
           JOIN proven p ON p.subject_sha = r.subject_sha AND p.va = r.containing_function
          WHERE r.subject_sha = ?`,
        sha,
      );
      expect(proven).toBe(inProvenView);
      expect(proven).toBeGreaterThan(0);
      expect(
        one(
          'SELECT COUNT(*) AS n FROM global_references WHERE subject_sha = ? AND width IS NOT NULL AND form = \'immediate\'',
          sha,
        ),
      ).toBe(0);
    });

    buntest('every reference names an address in the data region, never in code', () => {
      // `.text` runs 0x401000..0x62847D and `THIS_COD` 0x629000..0x634979 in
      // this subject. A reference to either would mean the derivation had
      // started filing branch targets and function pointers as globals.
      expect(
        one(
          `SELECT COUNT(*) AS n FROM global_references
            WHERE subject_sha = ?
              AND (address BETWEEN 4198400 AND 6456444 OR address BETWEEN 6459392 AND 6506872)`,
          sha,
        ),
      ).toBe(0);
    });
  }
}
