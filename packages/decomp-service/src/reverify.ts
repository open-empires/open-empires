/**
 * Re-run the gate on every stored source and record WHERE the match landed.
 *
 * Every verdict predates the `matched_at` column, so none of them records
 * whether its match was at the function's entry or merely somewhere inside a
 * larger emission. One was a fragment match and was believed for hours. The
 * only way to know about the rest is to compile them again.
 *
 * This writes `matched_at` and nothing else: a verdict is never rewritten,
 * so a proof that still holds keeps its original decision and timestamp.
 */
import { Effect, Layer, Option, pipe } from 'effect';
import { Database } from 'bun:sqlite';
import { modules } from './modules';
import { DbImpl } from './modules/db/impl';
import { GateImpl } from './modules/gate/impl';
import { SubjectImpl } from './modules/subject/impl';

const db = new Database('data/decomp.db');
const rows = db.query(
  `SELECT pv.attempt_id AS id, pv.va AS va, pv.flags AS flags,
          a.source AS source, f.size AS size
   FROM proven pv
   JOIN attempts a ON a.id = pv.attempt_id
   JOIN functions f ON f.va = pv.va
   WHERE EXISTS (SELECT 1 FROM verdicts v
                 WHERE v.attempt_id = pv.attempt_id AND v.matched_at IS NULL)
   ORDER BY pv.va`,
).all() as { id: number; va: number; flags: string; source: string; size: number }[];

console.log(`${rows.length} proofs with no recorded match offset`);
const layer = pipe(GateImpl.Layer, Layer.provideMerge(SubjectImpl.Layer), Layer.provideMerge(DbImpl.Layer));
const write = db.query('UPDATE verdicts SET matched_at = ? WHERE attempt_id = ?');

let entry = 0, fragment = 0, lost = 0, failed = 0;
const fragments: number[] = [];
const regressed: number[] = [];

for (const [i, r] of rows.entries()) {
  try {
    const v = await Effect.runPromise(Effect.provide(Effect.gen(function* () {
      const subject = yield* modules.Subject; const gate = yield* modules.Gate;
      const bytes = yield* subject.bytesAt({ va: r.va, length: r.size });
      if (Option.isNone(bytes)) return null;
      return yield* gate.check({ va: r.va, original: bytes.value, source: r.source, flags: r.flags });
    }), layer));
    if (v === null) { failed++; continue; }
    const at = Option.getOrElse(v.matchedAt, () => -1);
    if (!v.exact) { lost++; regressed.push(r.va); write.run(-1, r.id); }
    else if (at === 0) { entry++; write.run(0, r.id); }
    else { fragment++; fragments.push(r.va); write.run(at, r.id); }
  } catch { failed++; }
  if ((i + 1) % 250 === 0)
    console.log(`  ${i + 1}/${rows.length}  entry ${entry}  fragment ${fragment}  no-longer-exact ${lost}  error ${failed}`);
}

console.log(`\nentry matches      ${entry}`);
console.log(`FRAGMENT matches   ${fragment}${fragment ? '  ' + fragments.map(v => '0x' + v.toString(16).toUpperCase()).join(' ') : ''}`);
console.log(`no longer exact    ${lost}${lost ? '  ' + regressed.map(v => '0x' + v.toString(16).toUpperCase()).join(' ') : ''}`);
console.log(`could not check    ${failed}`);
