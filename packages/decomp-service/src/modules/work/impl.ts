import { Effect, Option } from 'effect';
import { implementing, type EffectGen } from 'effective-modules';
import { modules } from '../index';
import type { DbError } from '../db/interface';
import { SUBJECT_FLAGS, SUBJECT_FLAGS_O1 } from '../gate/interface';
import type { SubjectImage } from '../disasm/interface';
import {
  MAX_SWEEP_FLAG_SETS, NoSubject, NotClaimed, UnknownFunction,
  type IWork, type SubmitFailure, type SweepOutcome, type SweepReport,
  type Verdict, type WorkFailure, type WorkItem,
} from './interface';

const now = () => Date.now() / 1000;
const sha = (s: string) => new Bun.CryptoHasher('sha256').update(s).digest('hex');
const optNum = (v: unknown): Option.Option<number> =>
  v === null || v === undefined ? Option.none() : Option.some(Number(v));
const optStr = (v: unknown): Option.Option<string> =>
  v === null || v === undefined || v === '' ? Option.none() : Option.some(String(v));

/** How many already-solved functions a sibling ranking considers. Ranking is
 *  the single biggest time saver an agent has, so it ships WITH the work
 *  rather than being something the agent must think to ask for. */
const SIBLING_POOL = 400;
const SIBLINGS_RETURNED = 5;

export class WorkImpl
  extends implementing(modules.Work).uses(modules.Db, modules.Gate, modules.Disasm, modules.Subject)
  implements IWork
{
  *claim(
    agentId: string,
    count: number,
    leaseSeconds: number,
  ): EffectGen<ReadonlyArray<WorkItem>, WorkFailure> {
    const db = this.dependencies.Db;
    const t = now();

    // Unsolved, unclaimed, not already parked as a diagnosed near-miss.
    // Biggest first: a large function is where the remaining bytes are, and
    // the count of functions has never been the measure.
    const rows = yield* db.all(
      `SELECT f.va AS va, f.size AS size
       FROM functions f
       JOIN current_config c ON c.only_row = 1 AND c.subject_sha = f.subject_sha
       WHERE f.va NOT IN (SELECT va FROM proven WHERE subject_sha = f.subject_sha)
         AND f.va NOT IN (SELECT va FROM near_misses WHERE subject_sha = f.subject_sha)
         AND f.va NOT IN (
           SELECT va FROM claims
           WHERE subject_sha = f.subject_sha AND released_at IS NULL AND expires_at > ?)
       ORDER BY f.size DESC
       LIMIT ?`,
      [t, count],
    );

    const items: WorkItem[] = [];
    for (const raw of rows) {
      const r = raw as { va: number; size: number };
      yield* db.run(
        `INSERT INTO claims(subject_sha, va, agent_id, claimed_at, expires_at)
         SELECT c.subject_sha, ?, ?, ?, ? FROM current_config c WHERE c.only_row = 1`,
        [r.va, agentId, t, t + leaseSeconds],
      );
      items.push(yield* this.describe(r.va, r.size));
    }
    return items;
  }

  /** The subject image, read once per call rather than carried as state. */
  private *image(): EffectGen<SubjectImage, WorkFailure> {
    const subject = this.dependencies.Subject;
    const current = yield* subject.current();
    if (Option.isNone(current)) {
      return yield* Effect.fail(
        new NoSubject({ reason: 'no subject has been ingested' }),
      );
    }
    const s = current.value;
    // The RAW image, not a VA-mapped read: a decoder indexes by
    // `va - imageBase` and must see the headers and inter-section gaps too.
    const bytes = yield* subject.imageBytes();
    // textLo/textHi come from the section table, never written down. The
    // Python wrote it down twice and the copies disagreed by 9,216 bytes.
    return {
      sha256: s.sha256, bytes, imageBase: s.imageBase,
      textLo: s.textLo, textHi: s.textHi,
    };
  }

  /** Everything an agent needs to attempt one function, assembled here so the
   *  agent needs no files and no second call. */
  private *describe(va: number, size: number): EffectGen<WorkItem, WorkFailure> {
    const db = this.dependencies.Db;
    const img = yield* this.image();
    const listing = yield* this.dependencies.Disasm.listing(
      img, { va, size }, Option.none(),
    );

    const prior = yield* db.all(
      `SELECT a.flags AS flags, v.exact AS exact, v.first_diff AS first_diff,
              v.detail AS detail
       FROM attempts a JOIN verdicts v ON v.attempt_id = a.id
       WHERE a.va = ? ORDER BY v.decided_at DESC LIMIT 5`,
      [va],
    );
    const near = yield* db.one(
      `SELECT blocked_class, eliminated FROM near_misses WHERE va = ?`,
      [va],
    );

    return {
      va,
      size,
      disassembly: Option.getOrElse(listing, () => ''),
      siblings: [],
      previousAttempts: prior.map((raw) => {
        const r = raw as Record<string, unknown>;
        return {
          flags: String(r.flags),
          exact: Number(r.exact) === 1,
          firstDiff: optNum(r.first_diff),
          detail: optStr(r.detail),
        };
      }),
      nearMiss:
        near === null
          ? Option.none()
          : Option.some({
              blockedClass: optStr((near as Record<string, unknown>).blocked_class),
              eliminated: optStr((near as Record<string, unknown>).eliminated),
            }),
    };
  }

  *submit(
    agentId: string,
    va: number,
    source: string,
    flags: string,
  ): EffectGen<Verdict, SubmitFailure> {
    const db = this.dependencies.Db;
    const gate = this.dependencies.Gate;
    const t = now();

    const { original } = yield* this.claimed(agentId, va);

    const bucket = flags === SUBJECT_FLAGS_O1 ? SUBJECT_FLAGS_O1 : SUBJECT_FLAGS;
    // A gate failure propagates. Recording "not exact" because the compiler
    // could not be reached would be a proof-shaped record of a compile that
    // never happened.
    const v = yield* gate.check({
      va, original, source, flags: bucket,
    });

    const run = yield* db.one(
      `SELECT id FROM gate_runs ORDER BY started_at DESC LIMIT 1`,
    );
    const runId =
      run === null
        ? yield* db.insert(
            `INSERT INTO gate_runs(subject_sha, toolchain_id, started_at, attempted, exact)
             SELECT c.subject_sha, c.toolchain_id, ?, 0, 0 FROM current_config c
             WHERE c.only_row = 1`,
            [t],
          )
        : Number((run as { id: number }).id);

    const attemptId = yield* db.insert(
      `INSERT INTO attempts(subject_sha, va, source, source_sha, flags, author, created_at)
       SELECT c.subject_sha, ?, ?, ?, ?, ?, ? FROM current_config c WHERE c.only_row = 1
       ON CONFLICT(subject_sha, va, source_sha, flags) DO NOTHING`,
      [va, source, sha(source), bucket, agentId, t],
    );

    yield* db.run(
      `INSERT OR REPLACE INTO verdicts(attempt_id, gate_run_id, exact, compiled,
         emitted_size, masked, compared, first_diff, detail, decided_at)
       VALUES (?,?,?,?,?,?,?,?,?,?)`,
      [
        attemptId, runId, v.exact ? 1 : 0, v.compiled ? 1 : 0,
        Option.getOrNull(v.emittedSize), v.masked, v.compared,
        Option.getOrNull(v.firstDiff), Option.getOrNull(v.detail), t,
      ],
    );

    if (v.exact) {
      yield* db.run(`UPDATE claims SET released_at = ? WHERE va = ? AND agent_id = ?`, [t, va, agentId]);
      yield* db.run(`DELETE FROM near_misses WHERE va = ?`, [va]);
    }

    return {
      exact: v.exact,
      compiled: v.compiled,
      emittedSize: v.emittedSize,
      masked: Option.some(v.masked),
      compared: Option.some(v.compared),
      firstDiff: v.firstDiff,
      detail: v.detail,
      weak: v.weaklyVerified,
    };
  }

  *sweep(
    agentId: string,
    va: number,
    source: string,
    flagSets: ReadonlyArray<string>,
  ): EffectGen<SweepReport, SubmitFailure> {
    const gate = this.dependencies.Gate;
    const { size, original } = yield* this.claimed(agentId, va);

    // Deduped and capped: the compiler is one serialised container, and the
    // same flag set asked twice costs another agent a submission.
    const sets = [...new Set(flagSets)].slice(0, MAX_SWEEP_FLAG_SETS);
    const outcomes: SweepOutcome[] = [];
    for (const flags of sets) {
      // Sequential on purpose. A sweep is a diagnostic one agent asked for,
      // and letting it take the whole container in parallel would stall every
      // other agent's submissions behind it.
      const v = yield* gate.check({ va, original, source, flags });
      outcomes.push({
        flags,
        compiled: v.compiled,
        exact: v.exact,
        matchedAtEntry: Option.getOrElse(v.matchedAt, () => -1) === 0,
        emittedSize: v.emittedSize,
        masked: Option.some(v.masked),
        firstDiff: v.firstDiff,
        detail: v.detail,
        offConfiguration: flags !== SUBJECT_FLAGS && flags !== SUBJECT_FLAGS_O1,
      });
    }
    const matched = outcomes.filter((o) => o.matchedAtEntry).map((o) => o.flags);
    return {
      va,
      size,
      outcomes,
      matched,
      finding: outcomes.some((o) => o.matchedAtEntry && o.offConfiguration),
    };
  }

  /**
   * The function this agent currently holds, with the subject's bytes for it.
   *
   * Submitting or sweeping without a live lease is refused rather than
   * tolerated: two agents writing attempts for one function is how the shared
   * file tree used to lose work, and two agents sweeping one is how they lose
   * each other's compiler time.
   */
  private *claimed(
    agentId: string,
    va: number,
  ): EffectGen<{ readonly size: number; readonly original: Uint8Array }, SubmitFailure> {
    const db = this.dependencies.Db;
    const held = yield* db.one(
      `SELECT 1 FROM claims
       WHERE va = ? AND agent_id = ? AND released_at IS NULL AND expires_at > ?`,
      [va, agentId, now()],
    );
    if (held === null) return yield* Effect.fail(new NotClaimed({ va, agentId }));

    const fn = (yield* db.one(`SELECT size FROM functions WHERE va = ?`, [va])) as
      | { size: number }
      | null;
    if (fn === null) return yield* Effect.fail(new UnknownFunction({ va }));

    const original = yield* this.dependencies.Subject.bytesAt({ va, length: fn.size });
    if (Option.isNone(original)) return yield* Effect.fail(new UnknownFunction({ va }));
    return { size: fn.size, original: original.value };
  }

  *park(
    agentId: string,
    va: number,
    blockedClass: string,
    eliminated: string,
  ): EffectGen<void, DbError | NotClaimed> {
    const db = this.dependencies.Db;
    const t = now();
    const held = yield* db.one(
      `SELECT 1 FROM claims WHERE va = ? AND agent_id = ? AND released_at IS NULL`,
      [va, agentId],
    );
    if (held === null) return yield* Effect.fail(new NotClaimed({ va, agentId }));
    yield* db.run(
      `INSERT INTO near_misses(subject_sha, va, blocked_class, eliminated, updated_at)
       SELECT c.subject_sha, ?, ?, ?, ? FROM current_config c WHERE c.only_row = 1
       ON CONFLICT(subject_sha, va) DO UPDATE SET
         blocked_class = excluded.blocked_class,
         eliminated = excluded.eliminated, updated_at = excluded.updated_at`,
      [va, blockedClass, eliminated, t],
    );
    yield* db.run(`UPDATE claims SET released_at = ? WHERE va = ? AND agent_id = ?`, [t, va, agentId]);
  }

  *release(agentId: string, va: number): EffectGen<void, DbError> {
    yield* this.dependencies.Db.run(
      `UPDATE claims SET released_at = ? WHERE va = ? AND agent_id = ? AND released_at IS NULL`,
      [now(), va, agentId],
    );
  }

  *reapExpiredClaims(): EffectGen<number, DbError> {
    // A lease expiring is how a dead agent's work returns to the queue.
    // Nothing notices the agent died; the lease simply runs out.
    return yield* this.dependencies.Db.run(
      `UPDATE claims SET released_at = ? WHERE released_at IS NULL AND expires_at <= ?`,
      [now(), now()],
    );
  }

  *queueDepth(): EffectGen<number, DbError> {
    const row = (yield* this.dependencies.Db.one(
      `SELECT COUNT(*) AS n FROM functions f
       JOIN current_config c ON c.only_row = 1 AND c.subject_sha = f.subject_sha
       WHERE f.va NOT IN (SELECT va FROM proven WHERE subject_sha = f.subject_sha)
         AND f.va NOT IN (SELECT va FROM near_misses WHERE subject_sha = f.subject_sha)
         AND f.va NOT IN (
           SELECT va FROM claims
           WHERE subject_sha = f.subject_sha AND released_at IS NULL AND expires_at > ?)`,
      [now()],
    )) as { n: number } | null;
    return row === null ? 0 : Number(row.n);
  }
}
