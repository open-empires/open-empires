import { Effect, Option, Result } from 'effect';
import { effunct, implementing, type EffectGen } from 'effective-modules';
import { modules } from '../index';
import type { DbError } from '../db/interface';
import { SUBJECT_FLAGS, SUBJECT_FLAGS_O1, type EmittedCode } from '../gate/interface';
import type { SubjectImage } from '../disasm/interface';
import {
  MAX_PROBE_SOURCES, MAX_SWEEP_FLAG_SETS, NoSubject, NotClaimed, UnknownFunction,
  ParkWithoutReason,
  type Claimability, type HeldClaim, type ProbeOutcome, type ProbeReport,
  type IWork, type SubmitFailure, type SweepComparison, type SweepOutcome,
  type SweepReport,
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
       -- Largest first, but never larger than twice the biggest function
       -- anyone has actually proven.
       --
       -- Smallest-first was right while there were no solved siblings to
       -- adapt, and its stated premise was that "the byte total follows from
       -- throughput". Measured today, it does not. 3,355 functions are proven
       -- and they hold 221,332 bytes, mean 65; the 3,627 unproven hold
       -- 1,716,228 bytes, mean 473. Only 4,519 of those remaining bytes --
       -- 0.26% -- are in functions under 64 bytes, while 75% are in functions
       -- of 256 bytes or more.
       --
       -- The success rate by size says agents can do that work. Of the
       -- functions ever attempted: 100% proven under 16 bytes, 99% at 16-63,
       -- 96% at 64-255, 76% at 256-1023, 75% at 1024-4095. The two bands
       -- holding the bytes succeed three times in four, and had been sampled
       -- at 8% and 2% respectively -- not because they fail, but because the
       -- queue never served them. Expected bytes per attempt is about 144 in
       -- the 64-255 band against 378 at 256-1023 and 1,312 at 1024-4095.
       --
       -- Ordering by size DESC outright is what served the 13,791-byte
       -- function to the first caller, so the ceiling is derived from
       -- evidence instead: twice the largest proven extent, floored at 1024
       -- so the queue is never trivially small. It ratchets -- the largest
       -- proven is 2,009 bytes today, which admits up to 4,018, and proving
       -- one of those raises the ceiling again. A plain 'at most the largest proven'
       -- could never rise at all, because nothing above the ceiling would
       -- ever be served to raise it.
       -- UNCORRELATED. Written so the subquery referenced the outer row's
       -- subject_sha, SQLite re-ran a full aggregate over the proven VIEW --
       -- itself a join across several tables -- once per row of functions. A
       -- two-item claim took 51.7 seconds, of which describing the two items
       -- accounted for 462ms; all the rest was this clause, 6,982 times. The
       -- subject is already fixed by the join to current_config above, so the
       -- ceiling is one value and is computed once.
         AND f.size <= (
           SELECT MAX(1024, 2 * COALESCE(MAX(p2.size), 0))
             FROM proven p2
             JOIN current_config c2
               ON c2.only_row = 1 AND c2.subject_sha = p2.subject_sha
         )
       -- WITHIN the ceiling, by BAND, not by raw size.
       --
       -- size DESC under a ratcheting ceiling has a perverse effect that
       -- took a worker measuring the remaining bytes to see. The bands of
       -- what is still open:
       --
       --     <128        1,065 fns     71,211 B    4.3%
       --     128-511     1,969 fns    516,559 B   30.9%
       --     512-2047      776 fns    718,663 B   43.0%
       --     2048-4095      86 fns    229,721 B   13.8%
       --     4096+          22 fns    133,496 B    8.0%
       --
       -- Ordering by size descending serves those 22 functions first, and
       -- they hold 8% of the work. The 512-4095 bands hold 56.8% in 862
       -- functions and were being reached only after the 4096+ band was
       -- exhausted -- and it does not get exhausted, because every attempt on
       -- it so far has parked: 0x502290, 0x528350, 0x5754C0, 0x56D3C0 and
       -- 0x5F0690 are all 6KB or more and all unproven, while today's three
       -- closes were 1,836, 1,964 and 3,495 bytes.
       --
       -- Worse, the ratchet made it self-reinforcing: proving one large
       -- function raises the ceiling, which floods the queue with more of the
       -- band nothing closes.
       --
       -- So the bytes and the evidence agree, and the order follows them:
       -- 512-4095 first, then 128-511, then the big band, then the stubs.
       -- The ceiling is unchanged -- it still ratchets, and it still keeps a
       -- 13,791-byte function away from the first caller -- this only decides
       -- what is served underneath it.
       ORDER BY CASE
                  WHEN f.size BETWEEN 512 AND 4095 THEN 0
                  WHEN f.size BETWEEN 128 AND 511  THEN 1
                  WHEN f.size >= 4096              THEN 2
                  ELSE 3
                END,
                f.size DESC
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
      // YIELD THE EVENT LOOP between items.
      //
      // Describing one function disassembles it and fingerprints 400
      // candidate siblings, which is synchronous CPU work -- about four
      // seconds for a function of a few thousand bytes. Six of those in one
      // request is 25 seconds during which nothing else is answered,
      // /api/health included, so the supervisor's probe timed out and it
      // killed the child MID-REQUEST: the agent saw a dead connection and
      // the claim it had just been granted was lost. The service's own
      // watchdog was shooting it for being busy.
      //
      // A one-millisecond sleep is a real turn of the loop, so health is
      // answered between items and a long claim costs latency instead of the
      // process. It cannot be an Effect-level yield: the expensive part is a
      // synchronous callback the runtime cannot preempt.
      yield* Effect.sleep(1);
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
    // Timed, because a claim of six large functions took 63 seconds and
    // nearly tripped the supervisor's watchdog, and nothing could say which
    // part was slow. A queue nobody can see is a queue nobody fixes.
    const started = Date.now();
    const marks: string[] = [];
    const mark = (what: string) => {
      marks.push(`${what}=${Date.now() - started}ms`);
    };
    const img = yield* this.image();
    mark('image');
    // A proof is the only thing that establishes the recorded extent is the
    // function's true extent, and it decides whether an undecodable tail is
    // a switch table in the body or half an instruction past a wrong size.
    const provenHere = (yield* db.one(
      'SELECT COUNT(*) AS n FROM proven WHERE va = ?',
      [va],
    )) as { n: number } | null;
    const listing = yield* this.dependencies.Disasm.listing(
      img, { va, size }, Option.none(), (provenHere?.n ?? 0) > 0,
    );
    mark('listing');

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
    mark('queries');
    const ranked = yield* this.dependencies.Disasm.rankSiblings(
      img,
      { va, size },
      solvedRows.map((r) => {
        const o = r as { va: number; size: number };
        return { va: o.va, size: o.size };
      }),
    );
    mark('rankSiblings');
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

    mark('siblingSources');
    console.log(
      `[claim] 0x${va.toString(16)} ${size}B described in ` +
        `${Date.now() - started}ms (${marks.join(' ')})`,
    );
    // How this entry was found, because for one evidence kind the extent is
    // derived from LAYOUT rather than from a reference, and its size is right
    // about nine times in ten.
    const found = (yield* db.one(
      'SELECT discovered_by FROM functions WHERE va = ?',
      [va],
    )) as { discovered_by: string | null } | null;
    const caution =
      found?.discovered_by === 'padding-aligned'
        ? '\n\n;; HOW THIS ONE WAS FOUND: nothing in the game refers to it. It was\n' +
          ';; located by layout -- MSVC aligns each function to 16 bytes and fills\n' +
          ';; the gap before it, so the end of that filler is where a function\n' +
          ';; begins. Measured against 1,119 functions already proven: the size\n' +
          ';; this gives is exactly right 89.7% of the time and is NEVER too\n' +
          ';; short. The 8.3% that are wrong are too LONG -- they cover this\n' +
          ';; function and the next one, which happens when a function has no\n' +
          ';; filler after it because the next was already aligned.\n' +
          ';;\n' +
          ';; So before reconstructing, check the listing for a SECOND prologue\n' +
          ';; after a ret. If you find one, this entry is two functions: park it\n' +
          ';; with blockedClass "padding-aligned extent covers two functions" and\n' +
          ';; the address where the second begins. Do not try to write one\n' +
          ';; function for both.'
        : '';

    return {
      va,
      size,
      // NEVER a silent empty string. An entry whose extent does not decode
      // used to arrive as `''`, so an agent saw a function with no body and
      // no reason given, and the address stayed in the queue forever. Two
      // such entries were found by hand at 0x5a4afa and 0x5a4e99.
      disassembly: Option.getOrElse(
        listing,
        () =>
          `;; NO LISTING. The ${size} bytes recorded at ` +
          `0x${va.toString(16)} do not decode as instructions. Either the ` +
          `recorded size cuts an instruction in half, or the body ends in a ` +
          `switch table; nothing here can tell which, and no proof exists ` +
          `against this span to settle it. Do NOT reconstruct from a guess ` +
          `-- the extent has to be established first ` +
          `(POST /api/discovery/workability).`,
      ) + caution,
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
    /** Which compiler install proved it. A proof is only a proof under the
     *  compiler that made it, and the subject was built by two. */
    install?: string,
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
    // The SAME install the compile used. Recording the default here while
    // compiling with another would attribute the proof to a compiler that
    // never saw it -- the exact failure the identity work exists to prevent.
    const toolchain = yield* gate.toolchain(bucket, install);
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
      matchedAt: v.matchedAt,
      emittedSize: v.emittedSize,
      masked: Option.some(v.masked),
      compared: Option.some(v.compared),
      firstDiff: v.firstDiff,
      detail: v.detail,
      weak: v.weaklyVerified,
    };
  }

  /**
   * Why the caller does not hold this address. Asked only on the failure
   * path, so it costs nothing when a lease is live.
   *
   * One tag used to cover four situations and the caller had to guess. A 409
   * read as "already proven" sent one worker back to re-derive answers it was
   * still holding.
   */
  private *whyNotClaimed(
    va: number,
    agentId: string,
  ): EffectGen<NotClaimed, DbError> {
    const db = this.dependencies.Db;
    const now = Date.now() / 1000;
    const proven = (yield* db.one('SELECT COUNT(*) AS n FROM proven WHERE va = ?', [va])) as
      | { n: number }
      | null;
    if ((proven?.n ?? 0) > 0) {
      return new NotClaimed({
        va, agentId, because: 'already-proven',
        detail: `0x${va.toString(16)} is already proven byte-exact; there is nothing to do`,
      });
    }
    const mine = (yield* db.one(
      `SELECT expires_at FROM claims
        WHERE va = ? AND agent_id = ? AND released_at IS NULL
        ORDER BY expires_at DESC LIMIT 1`,
      [va, agentId],
    )) as { expires_at: number } | null;
    if (mine !== null) {
      return new NotClaimed({
        va, agentId, because: 'lease-expired',
        detail:
          `your lease on 0x${va.toString(16)} expired ` +
          `${Math.round(now - mine.expires_at)}s ago; claim it again -- the work is still there`,
      });
    }
    const other = (yield* db.one(
      `SELECT agent_id FROM claims
        WHERE va = ? AND released_at IS NULL AND expires_at > ? LIMIT 1`,
      [va, now],
    )) as { agent_id: string } | null;
    if (other !== null) {
      return new NotClaimed({
        va, agentId, because: 'held-by-another',
        detail: `0x${va.toString(16)} is held by ${other.agent_id}; leave it to them`,
      });
    }
    return new NotClaimed({
      va, agentId, because: 'never-claimed',
      detail:
        `you have never claimed 0x${va.toString(16)}; ` +
        `POST /api/work/claim with {"vas":[${va}]} to take it`,
    });
  }

  *probe(
    agentId: string,
    va: number,
    sources: ReadonlyArray<string>,
    flags: string,
    install?: string,
  ): EffectGen<ProbeReport, SubmitFailure> {
    const gate = this.dependencies.Gate;
    const { size, original } = yield* this.claimed(agentId, va);
    const asked = sources.slice(0, MAX_PROBE_SOURCES);

    const outcomes: ProbeOutcome[] = [];
    for (const [index, source] of asked.entries()) {
      // Sequential, like a sweep: the container is shared, and letting one
      // diagnostic take it in parallel would stall every other agent's
      // submissions behind it.
      //
      // A source that cannot be built is an outcome, not a failed request --
      // the whole point of a probe is to submit spellings that might be
      // wrong, so a compiler rejection is the expected case rather than an
      // error, and one bad spelling must not discard the other fifteen.
      const attempted = yield* Effect.result(
        effunct(function* () {
          return yield* gate.contribute({ va, original, source, flags, toolchain: install });
        })(),
      );
      if (!Result.isSuccess(attempted)) {
        const why: unknown = attempted.failure;
        outcomes.push({
          index,
          compiled: false,
          exact: false,
          matchedAtEntry: false,
          emittedSize: Option.none(),
          masked: Option.none(),
          firstDiff: Option.none(),
          emittedSha: Option.none(),
          detail: Option.some(
            `could not be built: ${
              typeof why === 'object' && why !== null && 'reason' in why
                ? String((why as { reason: unknown }).reason)
                : String(why)
            }`,
          ),
        });
        continue;
      }
      const v = attempted.success.verdict;
      outcomes.push({
        index,
        compiled: v.compiled,
        exact: v.exact,
        matchedAtEntry: Option.getOrElse(v.matchedAt, () => -1) === 0,
        emittedSize: v.emittedSize,
        masked: Option.some(v.masked),
        firstDiff: v.firstDiff,
        emittedSha: v.emittedSha,
        detail: v.detail,
      });
    }

    // Group by what was EMITTED, not by what was written. Two spellings in one
    // group are the same program to this compiler, so the axis between them is
    // inert and nothing is learned by varying it further.
    const byBytes = new Map<string, number[]>();
    for (const o of outcomes) {
      if (Option.isNone(o.emittedSha)) continue;
      const key = o.emittedSha.value;
      const group = byBytes.get(key);
      if (group === undefined) byBytes.set(key, [o.index]);
      else group.push(o.index);
    }

    return {
      va,
      size,
      flags,
      outcomes,
      matched: outcomes.filter((o) => o.matchedAtEntry).map((o) => o.index),
      identical: [...byBytes.entries()]
        .map(([emittedSha, indices]) => ({ emittedSha, indices }))
        .sort((a, b) => b.indices.length - a.indices.length),
    };
  }

  *claimable(vas: ReadonlyArray<number>): EffectGen<ReadonlyArray<Claimability>, WorkFailure> {
    const db = this.dependencies.Db;
    if (vas.length === 0) return [];
    const at = now();
    // `IN (...)`, not a dynamic `VALUES` list. The SQL audit normalises an
    // interpolated placeholder list to a single `?` so it can compile every
    // statement against the live schema; `IN (?)` is valid SQL and
    // `VALUES ?` is not, so the audit could not check the query at all.
    //
    // The consequence is that an address with no inventory row returns no row
    // here, so absence is worked out below against the asked list -- which is
    // where the asked list actually is.
    const rows = (yield* db.all(
      `SELECT f.va AS va, f.size AS size,
              EXISTS(SELECT 1 FROM proven p
                      WHERE p.subject_sha = f.subject_sha AND p.va = f.va) AS proven,
              (SELECT cl.agent_id FROM claims cl
                WHERE cl.subject_sha = f.subject_sha AND cl.va = f.va
                  AND cl.released_at IS NULL AND cl.expires_at > ?
                ORDER BY cl.expires_at DESC LIMIT 1) AS held_by,
              (SELECT cl.expires_at FROM claims cl
                WHERE cl.subject_sha = f.subject_sha AND cl.va = f.va
                  AND cl.released_at IS NULL AND cl.expires_at > ?
                ORDER BY cl.expires_at DESC LIMIT 1) AS expires_at
         FROM functions f
         JOIN current_config c ON c.only_row = 1 AND c.subject_sha = f.subject_sha
        WHERE f.va IN (${vas.map(() => '?').join(',')})`,
      [at, at, ...vas],
    )) as ReadonlyArray<{
      va: number; size: number; proven: number;
      held_by: string | null; expires_at: number | null;
    }>;
    const found = new Map(rows.map((r) => [r.va, r]));
    return vas.map((va) => {
      const r = found.get(va);
      if (r === undefined) {
        return {
          va,
          reason: 'not-in-inventory' as const,
          size: Option.none(),
          heldBy: Option.none(),
          secondsLeft: Option.none(),
        };
      }
      const reason = r.size === 0
        ? 'zero-extent' as const
        : r.proven === 1
          ? 'already-proven' as const
          : r.held_by !== null
            ? 'held-by-another' as const
            : 'claimable' as const;
      return {
        va,
        reason,
        size: Option.some(r.size),
        heldBy: reason === 'held-by-another' ? Option.fromNullishOr(r.held_by) : Option.none(),
        secondsLeft:
          reason === 'held-by-another' && r.expires_at !== null
            ? Option.some(Math.round(r.expires_at - at))
            : Option.none(),
      };
    });
  }

  *claims(agentId: string): EffectGen<ReadonlyArray<HeldClaim>, WorkFailure> {
    const db = this.dependencies.Db;
    const current = yield* this.dependencies.Subject.current();
    if (Option.isNone(current)) {
      return yield* Effect.fail(new NoSubject({ reason: 'no subject has been ingested' }));
    }
    const subjectSha = current.value.sha256;
    const at = now();
    const rows = (yield* db.all(
      `SELECT c.va AS va, f.size AS size, c.claimed_at AS claimed_at,
              c.expires_at AS expires_at,
              EXISTS(SELECT 1 FROM proven p
                      WHERE p.subject_sha = c.subject_sha AND p.va = c.va) AS proven
         FROM claims c
         JOIN functions f ON f.subject_sha = c.subject_sha AND f.va = c.va
        WHERE c.subject_sha = ? AND c.agent_id = ?
          AND c.released_at IS NULL AND c.expires_at > ?
        ORDER BY f.size DESC`,
      [subjectSha, agentId, at],
    )) as ReadonlyArray<{
      va: number; size: number; claimed_at: number; expires_at: number; proven: number;
    }>;
    return rows.map((r) => ({
      va: r.va,
      size: r.size,
      claimedAt: r.claimed_at,
      expiresAt: r.expires_at,
      secondsLeft: Math.round(r.expires_at - at),
      proven: r.proven === 1,
    }));
  }

  *sweep(
    agentId: string,
    va: number,
    source: string,
    flagSets: ReadonlyArray<string>,
    install?: string,
  ): EffectGen<SweepReport, SubmitFailure> {
    const gate = this.dependencies.Gate;
    const { size, original } = yield* this.claimed(agentId, va);

    // Deduped and capped: the compiler is one serialised container, and the
    // same flag set asked twice costs another agent a submission.
    const sets = [...new Set(flagSets)].slice(0, MAX_SWEEP_FLAG_SETS);
    const outcomes: SweepOutcome[] = [];
    /** What each flag set emitted, kept so the comparison needs no recompile. */
    const entries = new Map<string, Option.Option<EmittedCode>>();
    for (const flags of sets) {
      // Sequential on purpose. A sweep is a diagnostic one agent asked for,
      // and letting it take the whole container in parallel would stall every
      // other agent's submissions behind it.
      // `contribute`, not `check`. `check` IS `contribute().verdict` -- it
      // discards the emitted bytes and nothing else -- so asking for them
      // here costs nothing, and keeping them is what removes the second
      // compile that used to follow this loop.
      //
      // ONE FLAG SET MAY NOT SINK THE SWEEP. The gate builds an identity probe
      // per flag set, and a flag this compiler does not accept failed the
      // whole request: a twelve-set sweep returned
      // `GateUnavailable ... status=2 size=0`, threw away the eleven results
      // that had compiled, and did not say which set was at fault. The flag
      // was `/GZ`, which is VC6 SP5 and not SP3. A caller then has to bisect
      // by hand, at one full compile cycle per attempt, to recover work the
      // service already did.
      //
      // So the failure is recorded AS AN OUTCOME for that flag set, carrying
      // the gate's own reason, and the rest of the sweep proceeds. A flag set
      // that cannot be built is a fact about the flag set, not about the
      // reconstruction.
      const attempted = yield* Effect.result(
        effunct(function* () {
          return yield* gate.contribute({ va, original, source, flags, toolchain: install });
        })(),
      );
      if (!Result.isSuccess(attempted)) {
        const why: unknown = attempted.failure;
        outcomes.push({
          flags,
          compiled: false,
          exact: false,
          matchedAtEntry: false,
          emittedSize: Option.none(),
          masked: Option.none(),
          firstDiff: Option.none(),
          detail: Option.some(
            `this flag set could not be built: ${
              typeof why === 'object' && why !== null && 'reason' in why
                ? String((why as { reason: unknown }).reason)
                : String(why)
            }`,
          ),
          emittedSha: Option.none(),
          offConfiguration: flags !== SUBJECT_FLAGS && flags !== SUBJECT_FLAGS_O1,
        });
        continue;
      }
      const c = attempted.success;
      const v = c.verdict;
      entries.set(flags, c.entry);
      outcomes.push({
        flags,
        compiled: v.compiled,
        exact: v.exact,
        matchedAtEntry: Option.getOrElse(v.matchedAt, () => -1) === 0,
        emittedSize: v.emittedSize,
        masked: Option.some(v.masked),
        firstDiff: v.firstDiff,
        detail: v.detail,
        emittedSha: v.emittedSha,
        offConfiguration: flags !== SUBJECT_FLAGS && flags !== SUBJECT_FLAGS_O1,
      });
    }
    const matched = outcomes.filter((o) => o.matchedAtEntry).map((o) => o.flags);

    // WHAT THE SOURCE ACTUALLY COMPILED TO, for the candidate that got
    // furthest.
    //
    // Until now a sweep answered with `firstDiff` and nothing else: the
    // offset of the first byte that differs. On a small function that is
    // enough to act on. On a large one it is a one-bit oracle -- worker
    // r38-a's 3,942-byte function diverged at offset 52, the low byte of a
    // branch displacement near the front, so 3,890 of its bytes were never
    // examined and there was no way to tell a wrong instruction from a
    // correctly-written one whose branch had to reach somewhere else. Two
    // functions were abandoned for want of this, and the gate had the bytes
    // the whole time: `contribute` returns them and only the wire format
    // dropped them.
    //
    // NOTHING is recompiled here any more. This used to call `contribute` for
    // the best candidate, which compiled the same source under the same flags
    // a second time -- because the loop above called `check`, and `check` is
    // `contribute().verdict`. The bytes had already been produced and thrown
    // away. On one serialised container shared by every agent and by the
    // composition proof, that was a wasted compile on every sweep.
    //
    // Only the best candidate's LISTING is rendered, which is cheap and local:
    // the other thirteen would answer a question nobody asked.
    const best = outcomes
      .filter((o) => o.compiled)
      .sort(
        (a, b) =>
          Option.getOrElse(b.firstDiff, () => -1) -
          Option.getOrElse(a.firstDiff, () => -1),
      )[0];

    let comparison: SweepComparison | undefined;
    if (best !== undefined) {
      const stored = entries.get(best.flags) ?? Option.none();
      if (Option.isSome(stored)) {
        const emitted = stored.value;
        const disasm = this.dependencies.Disasm;
        comparison = {
          flags: best.flags,
          firstDiff: best.firstDiff,
          emittedBytes: [...emitted.bytes]
            .map((b) => b.toString(16).padStart(2, '0'))
            .join(''),
          // Addressed at the subject's own VA, so a branch target in one
          // listing is the same number as in the other and the two can be
          // read side by side.
          emittedListing: yield* disasm.listingOfBytes(emitted.bytes, va, 'EMITTED'),
          subjectListing: yield* disasm.listingOfBytes(original, va, 'SUBJECT'),
          // The linker fills these, so a difference at one of them is not a
          // difference in the reconstruction.
          relocatedOffsets: [...emitted.relocated].sort((a, b) => a - b),
        };
      }
    }

    return {
      va,
      size,
      outcomes,
      matched,
      comparison,
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
    if (held === null) return yield* Effect.fail(yield* this.whyNotClaimed(va, agentId));

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
    toolchain?: string,
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
    const v = yield* gate.check({
      va, original: original.value, source, flags: bucket, toolchain,
    });
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
      matchedAt: v.matchedAt,
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
  ): EffectGen<void, DbError | NotClaimed | ParkWithoutReason> {
    const db = this.dependencies.Db;
    const t = now();
    yield* this.touch(agentId);
    // A park with no stated blocker is refused. The class is the only thing
    // that aggregates: it is what answers "what is stopping us", and that
    // answer is what decides what to build next. Half the parked set carries
    // none, so the question could only ever be asked of the other half.
    if (blockedClass.trim() === '') {
      return yield* Effect.fail(
        new ParkWithoutReason({ va, missing: 'blockedClass' }),
      );
    }
    if (eliminated.trim() === '') {
      return yield* Effect.fail(
        new ParkWithoutReason({ va, missing: 'eliminated' }),
      );
    }
    const held = yield* db.one(
      `SELECT 1 FROM claims WHERE va = ? AND agent_id = ? AND released_at IS NULL`,
      [va, agentId],
    );
    if (held === null) return yield* Effect.fail(yield* this.whyNotClaimed(va, agentId));
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

  /**
   * Give a claim back. Answers whether anything was actually released.
   *
   * It used to return void, so a release of an address the caller did not
   * hold -- a typo, a wrong hex conversion, an id that does not match -- was
   * a silent success. Two were issued against wrong addresses today and both
   * reported 200 while the real claim stayed held. An acknowledgement that
   * does not check what it did is the same fault `reject` had.
   */
  *release(agentId: string, va: number): EffectGen<boolean, DbError> {
    yield* this.touch(agentId);
    const freed = yield* this.dependencies.Db.run(
      `UPDATE claims SET released_at = ? WHERE va = ? AND agent_id = ? AND released_at IS NULL`,
      [now(), va, agentId],
    );
    return freed > 0;
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
