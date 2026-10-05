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
  /**
   * Touch the agent's heartbeat.
   *
   * Called by every work method, because a heartbeat an agent has to
   * REMEMBER is one that stops being accurate exactly when the agent is busy.
   * Wiring it only to an explicit /beat endpoint -- which the guide never
   * told anyone to call -- meant `gone` really meant "has been working for
   * more than ten minutes", and two agents were shown as dead while
   * holding live claims and making progress.
   *
   * An unregistered or finished agent simply updates no rows, which is the
   * right outcome -- a heartbeat must not invent an agent. A DbError does
   * propagate, because a failing write here means the database is broken and
   * the caller is about to find that out anyway.
   */
  private *touch(agentId: string): EffectGen<void, DbError> {
    yield* this.dependencies.Db.run(
      `UPDATE agents SET last_beat = ?, beats = beats + 1
       WHERE id = ? AND finished IS NULL`,
      [now(), agentId],
    );
  }

  *claim(
    agentId: string,
    count: number,
    leaseSeconds: number,
    vas?: ReadonlyArray<number>,
  ): EffectGen<ReadonlyArray<WorkItem>, WorkFailure> {
    const db = this.dependencies.Db;
    const t = now();
    yield* this.touch(agentId);

    // Named addresses bypass the queue's ordering but NOT its rules: an
    // address already proven, or under someone else's live lease, is still
    // refused.
    if (vas !== undefined && vas.length > 0) {
      const named = yield* db.all(
        `SELECT f.va AS va, f.size AS size FROM functions f
         JOIN current_config c ON c.only_row = 1 AND c.subject_sha = f.subject_sha
         WHERE f.size > 0
           AND f.va IN (${vas.map(() => '?').join(',')})
           AND NOT EXISTS (SELECT 1 FROM proven p
                       WHERE p.subject_sha = f.subject_sha AND p.va = f.va)
           AND NOT EXISTS (SELECT 1 FROM claims cl
                       WHERE cl.subject_sha = f.subject_sha AND cl.va = f.va
                         AND cl.released_at IS NULL AND cl.expires_at > ?
                         AND cl.agent_id != ?)`,
        [...vas, t, agentId],
      );
      const out: WorkItem[] = [];
      for (const raw of named) {
        const r = raw as { va: number; size: number };
        yield* db.run(
          `INSERT INTO claims(subject_sha, va, agent_id, claimed_at, expires_at)
           SELECT c.subject_sha, ?, ?, ?, ? FROM current_config c WHERE c.only_row = 1`,
          [r.va, agentId, t, t + leaseSeconds],
        );
        out.push(yield* this.describe(r.va, r.size));
      }
      return out;
    }

    // Unsolved, unclaimed, not already parked as a diagnosed near-miss.
    // Biggest first: a large function is where the remaining bytes are, and
    // the count of functions has never been the measure.
    const rows = yield* db.all(
      `SELECT f.va AS va, f.size AS size
       FROM functions f
       JOIN current_config c ON c.only_row = 1 AND c.subject_sha = f.subject_sha
       -- A zero-extent entry cannot be reconstructed: there are no bytes to
       -- match. Two exist in the inventory and they are a discovery defect
       -- rather than work -- the gap sweep starting at one of them is why
       -- name recovery misses the reference at 0x460E0C.
       WHERE f.size > 0
         AND NOT EXISTS (SELECT 1 FROM proven p
                       WHERE p.subject_sha = f.subject_sha AND p.va = f.va)
         AND NOT EXISTS (SELECT 1 FROM near_misses m
                       WHERE m.subject_sha = f.subject_sha AND m.va = f.va)
         AND NOT EXISTS (SELECT 1 FROM claims cl
                     WHERE cl.subject_sha = f.subject_sha AND cl.va = f.va
                       AND cl.released_at IS NULL AND cl.expires_at > ?)
       -- Smallest first. Ordering by size DESC gave the first caller the
       -- largest function in the binary (13,791 bytes, 3,901 instructions),
       -- which is the least likely thing in the queue to be solved. Agents
       -- succeed by adapting an already-solved sibling, so the queue serves
       -- the most tractable work and the byte total follows from throughput.
       ORDER BY f.size ASC
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

    // Rank the already-proven set by shape. An EXACT row means a solved
    // function with the same instruction shape, which is usually finished by
    // changing one offset -- so the agent is handed the answer rather than
    // the means to find it.
    const solvedRows = yield* db.all(
      `SELECT p.va AS va, p.size AS size FROM proven p
       ORDER BY ABS(p.va - ?) LIMIT ?`,
      [va, SIBLING_POOL],
    );
    const ranked = yield* this.dependencies.Disasm.rankSiblings(
      img,
      { va, size },
      solvedRows.map((r) => {
        const o = r as { va: number; size: number };
        return { va: o.va, size: o.size };
      }),
    );
    const top = ranked.slice(0, SIBLINGS_RETURNED);
    const sources = new Map<number, string>();
    for (const s of top) {
      const row = (yield* db.one(
        `SELECT a.source AS source FROM proven p
         JOIN attempts a ON a.id = p.attempt_id
         WHERE p.va = ? LIMIT 1`,
        [s.va],
      )) as { source: string } | null;
      if (row !== null) sources.set(s.va, row.source);
    }

    return {
      va,
      size,
      disassembly: Option.getOrElse(listing, () => ''),
      siblings: top.map((s) => ({
        va: s.va,
        similarity: s.exactShape ? 1 : s.mnemonicSimilarity,
        source: sources.get(s.va) ?? '',
      })),
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
    yield* this.touch(agentId);

    const { original } = yield* this.claimed(agentId, va);

    const bucket = flags === SUBJECT_FLAGS_O1 ? SUBJECT_FLAGS_O1 : SUBJECT_FLAGS;
    // A gate failure propagates. Recording "not exact" because the compiler
    // could not be reached would be a proof-shaped record of a compile that
    // never happened.
    const v = yield* gate.check({
      va, original, source, flags: bucket,
    });

    // The run must carry the toolchain the compile ACTUALLY used. Taking the
    // newest run regardless of flags recorded every /O1 proof against the
    // /O2 toolchain -- 8 of them -- which is the prover identity the whole
    // schema exists to keep honest.
    const toolchain = yield* gate.toolchain(bucket);
    yield* db.run(
      `INSERT INTO toolchains(id, cl_sha256, flags, comp_id, added_at)
       VALUES (?,?,?,?,?) ON CONFLICT(id) DO NOTHING`,
      [toolchain.id, toolchain.clSha256, bucket,
       Option.getOrNull(toolchain.compId), t],
    );
    const run = (yield* db.one(
      `SELECT g.id AS id FROM gate_runs g
       JOIN current_config c ON c.only_row = 1 AND c.subject_sha = g.subject_sha
       WHERE g.toolchain_id = ? ORDER BY g.started_at DESC LIMIT 1`,
      [toolchain.id],
    )) as { id: number } | null;
    const runId =
      run === null
        ? yield* db.insert(
            `INSERT INTO gate_runs(subject_sha, toolchain_id, started_at, attempted, exact)
             SELECT c.subject_sha, ?, ?, 0, 0 FROM current_config c
             WHERE c.only_row = 1`,
            [toolchain.id, t],
          )
        : Number(run.id);

    // Resubmitting identical source is normal -- an agent re-runs a candidate
    // after a service restart, or two sweep variants collapse to the same
    // text. The ON CONFLICT then inserts nothing and lastInsertRowid is a
    // STALE rowid from some earlier insert, so the verdict below was written
    // against the wrong attempt or failed its foreign key outright. An EXACT
    // verdict was lost that way: no proof recorded, and the claim not
    // released. So the id is read back rather than assumed.
    // A match at a non-zero offset says the bytes occur somewhere inside a
    // larger emission, not that the compiler emits them AT this address. It
    // is a weaker claim and must never release the claim or enter `proven`.
    const atEntry =
      v.exact && Option.getOrElse(v.matchedAt, () => 0) === 0;

    const sourceSha = sha(source);
    yield* db.run(
      `INSERT INTO attempts(subject_sha, va, source, source_sha, flags, author, created_at)
       SELECT c.subject_sha, ?, ?, ?, ?, ?, ? FROM current_config c WHERE c.only_row = 1
       ON CONFLICT(subject_sha, va, source_sha, flags) DO NOTHING`,
      [va, source, sourceSha, bucket, agentId, t],
    );
    const attemptRow = (yield* db.one(
      `SELECT a.id AS id FROM attempts a
       JOIN current_config c ON c.only_row = 1 AND c.subject_sha = a.subject_sha
       WHERE a.va = ? AND a.source_sha = ? AND a.flags = ?`,
      [va, sourceSha, bucket],
    )) as { id: number } | null;
    if (attemptRow === null) return yield* Effect.fail(new UnknownFunction({ va }));
    const attemptId = attemptRow.id;

    yield* db.run(
      `INSERT OR REPLACE INTO verdicts(attempt_id, gate_run_id, exact, compiled,
         emitted_size, masked, compared, first_diff, detail, decided_at,
         matched_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
      [
        attemptId, runId, atEntry ? 1 : 0, v.compiled ? 1 : 0,
        Option.getOrNull(v.emittedSize), v.masked, v.compared,
        Option.getOrNull(v.firstDiff), Option.getOrNull(v.detail), t,
        Option.getOrNull(v.matchedAt),
      ],
    );

    if (atEntry) {
      yield* db.run(`UPDATE claims SET released_at = ? WHERE va = ? AND agent_id = ?`, [t, va, agentId]);
      yield* db.run(`DELETE FROM near_misses WHERE va = ?`, [va]);
    }

    return {
      exact: atEntry,
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

  *amend(
    agentId: string,
    va: number,
    source: string,
    flags: string,
  ): EffectGen<Verdict, SubmitFailure> {
    const db = this.dependencies.Db;
    const gate = this.dependencies.Gate;
    const t = now();
    yield* this.touch(agentId);

    const fn = (yield* db.one(`SELECT size FROM functions WHERE va = ?`, [va])) as
      | { size: number }
      | null;
    if (fn === null) return yield* Effect.fail(new UnknownFunction({ va }));

    const original = yield* this.dependencies.Subject.bytesAt({ va, length: fn.size });
    if (Option.isNone(original)) return yield* Effect.fail(new UnknownFunction({ va }));

    const bucket = flags === SUBJECT_FLAGS_O1 ? SUBJECT_FLAGS_O1 : SUBJECT_FLAGS;
    const v = yield* gate.check({ va, original: original.value, source, flags: bucket });
    const atEntry = v.exact && Option.getOrElse(v.matchedAt, () => 0) === 0;

    // The replacement must stand on its own. A source that does not reproduce
    // the subject at the entry never becomes the record, whatever the old one
    // looked like.
    if (atEntry) {
      const proven = (yield* db.one(
        `SELECT attempt_id FROM proven WHERE va = ? LIMIT 1`,
        [va],
      )) as { attempt_id: number } | null;
      if (proven !== null) {
        yield* db.run(
          `UPDATE attempts SET source = ?, source_sha = ?, author = ?, created_at = ?
           WHERE id = ?`,
          [source, sha(source), agentId, t, proven.attempt_id],
        );
      }
    }

    return {
      exact: atEntry,
      compiled: v.compiled,
      emittedSize: v.emittedSize,
      masked: Option.some(v.masked),
      compared: Option.some(v.compared),
      firstDiff: v.firstDiff,
      detail: v.detail,
      weak: v.weaklyVerified,
    };
  }

  *park(
    agentId: string,
    va: number,
    blockedClass: string,
    eliminated: string,
  ): EffectGen<void, DbError | NotClaimed> {
    const db = this.dependencies.Db;
    const t = now();
    yield* this.touch(agentId);
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
    yield* this.touch(agentId);
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
       -- A zero-extent entry cannot be reconstructed: there are no bytes to
       -- match. Two exist in the inventory and they are a discovery defect
       -- rather than work -- the gap sweep starting at one of them is why
       -- name recovery misses the reference at 0x460E0C.
       WHERE f.size > 0
         AND NOT EXISTS (SELECT 1 FROM proven p
                       WHERE p.subject_sha = f.subject_sha AND p.va = f.va)
         AND NOT EXISTS (SELECT 1 FROM near_misses m
                       WHERE m.subject_sha = f.subject_sha AND m.va = f.va)
         AND NOT EXISTS (SELECT 1 FROM claims cl
                     WHERE cl.subject_sha = f.subject_sha AND cl.va = f.va
                       AND cl.released_at IS NULL AND cl.expires_at > ?)`,
      [now()],
    )) as { n: number } | null;
    return row === null ? 0 : Number(row.n);
  }
}
