import { Schema } from 'effect';
import type { EffectGen } from 'effective-modules';
import type { DbError, IDb } from './interface';
import { rows } from './rows';

/**
 * The reconstructions in force: one per function, source included.
 *
 * ONE query, in one place, because every whole-corpus answer this project
 * reports is an answer about this set. The composition proof, the relocation
 * check and the portable tree all have to agree on which sources they are
 * talking about -- three copies of this SELECT would be three sets that drift,
 * and the project has already shipped 6,953 "verified" blocks of which 1,450
 * were real for exactly that kind of reason.
 *
 * Drawn from the `proven` view, so it is already restricted to verdicts made
 * under the configuration currently in force; nothing here re-implements that
 * rule.
 */
export const Reconstruction = Schema.Struct({
  va: Schema.Number,
  size: Schema.Number,
  attempt_id: Schema.Number,
  source: Schema.String,
  flags: Schema.String,
});
export type Reconstruction = typeof Reconstruction.Type;

/**
 * Exactly one row per address.
 *
 * A function may carry several accepted attempts -- the same source
 * resubmitted under the other bucket, or a second spelling that also matched --
 * and a join that returned all of them would count that function twice and let
 * the order rows came back in pick which source the answer was about. The most
 * recently decided verdict wins, with the attempt id breaking a tie, so the
 * set is the same on every run.
 */
const SQL = `
SELECT p.va AS va, f.size AS size, p.attempt_id AS attempt_id,
       a.source AS source, a.flags AS flags
FROM proven p
JOIN attempts  a ON a.id = p.attempt_id
JOIN functions f ON f.subject_sha = p.subject_sha AND f.va = p.va
WHERE p.attempt_id = (
  SELECT q.attempt_id FROM proven q
  WHERE q.subject_sha = p.subject_sha AND q.va = p.va
  ORDER BY q.decided_at DESC, q.attempt_id DESC
  LIMIT 1)
ORDER BY p.va`;

export const reconstructionsInForce = function* (
  db: IDb,
): EffectGen<ReadonlyArray<Reconstruction>, DbError> {
  return yield* rows(db, Reconstruction, SQL);
};
