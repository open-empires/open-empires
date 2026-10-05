import { Effect, Option } from 'effect';
import { implementing, type EffectGen } from 'effective-modules';
import { modules } from '../index';
import type { DbError } from '../db/interface';
import type { DisasmError, SubjectImage } from '../disasm/interface';
import type { SubjectIoError, SubjectParseError } from '../subject/interface';
import {
  DiscoveryFailed,
  type Candidate, type Evidence, type ExpansionReport, type IDiscovery,
  type Remeasurement, type RejectionOutcome, type WorkabilityAudit,
  type GapReport,
} from './interface';

type Failure = DbError | DisasmError | SubjectIoError | SubjectParseError | DiscoveryFailed;

interface Extent { readonly va: number; readonly size: number }

/** Does `va` fall strictly inside a known function? Such an address is a
 *  jump target or a mid-function pointer, never a new entry. */
const interiorOf = (sorted: ReadonlyArray<Extent>, va: number): boolean => {
  let lo = 0, hi = sorted.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const f = sorted[mid]!;
    if (va < f.va) hi = mid - 1;
    else if (va >= f.va + f.size) lo = mid + 1;
    else return va !== f.va;
  }
  return false;
};

export class DiscoveryImpl
  extends implementing(modules.Discovery).uses(modules.Db, modules.Disasm, modules.Subject)
  implements IDiscovery
{
  private *image(): EffectGen<SubjectImage, Failure> {
    const subject = this.dependencies.Subject;
    const current = yield* subject.current();
    if (Option.isNone(current)) {
      return yield* Effect.fail(new DiscoveryFailed({ reason: 'no subject ingested' }));
    }
    const s = current.value;
    return {
      sha256: s.sha256,
      bytes: yield* subject.imageBytes(),
      imageBase: s.imageBase,
      textLo: s.textLo,
      textHi: s.textHi,
    };
  }

  private *inventory(): EffectGen<ReadonlyArray<Extent>, DbError> {
    const rows = yield* this.dependencies.Db.all(
      'SELECT va, size FROM functions ORDER BY va',
    );
    return rows.map((r: unknown) => {
      const o = r as { va: number; size: number };
      return { va: o.va, size: o.size };
    });
  }

  /** Call targets inside a function, read from its bytes. */
  private *callTargets(
    img: SubjectImage,
    fn: Extent,
  ): EffectGen<ReadonlyArray<number>, DisasmError> {
    const decoded = yield* this.dependencies.Disasm.decodeFunction(img, fn);
    if (Option.isNone(decoded)) return [];
    const out: number[] = [];
    for (const i of decoded.value) {
      if (i.mnemonic !== 'call') continue;
      const m = /^0x([0-9a-f]+)$/.exec(i.opStr.trim());
      if (m === null) continue;           // indirect call: no static target
      const t = parseInt(m[1]!, 16);
      if (t >= img.textLo && t < img.textHi) out.push(t);
    }
    return out;
  }

  private *record(
    candidates: ReadonlyArray<Candidate>,
    img: SubjectImage,
    scanned: number,
  ): EffectGen<ExpansionReport, Failure> {
    const db = this.dependencies.Db;
    const disasm = this.dependencies.Disasm;
    const known = yield* this.inventory();
    const starts = new Set(known.map((f) => f.va));

    const byEvidence: Record<Evidence, number> = {
      'proven-call': 0, 'data-pointer': 0, 'decoded-call': 0, 'gap-residue': 0,
      'padding-aligned': 0,
    };
    const deferred: { va: number; reason: string }[] = [];
    const fresh = new Map<number, Candidate>();
    let alreadyKnown = 0, interior = 0;

    for (const c of candidates) {
      byEvidence[c.evidence]++;
      if (starts.has(c.va)) { alreadyKnown++; continue; }
      if (interiorOf(known, c.va)) { interior++; continue; }
      // Strongest evidence wins when the same address arrives twice.
      const prior = fresh.get(c.va);
      if (prior === undefined || c.evidence === 'proven-call') fresh.set(c.va, c);
    }

    const sha = yield* this.subjectSha();

    // Addresses already judged not to be entries. Without this the producer
    // re-adds them on its next pass -- which is how three rows deleted by
    // hand were back in the inventory within the hour.
    const rejected = new Set(
      (yield* db.all('SELECT va FROM rejected_entries WHERE subject_sha = ?', [sha]))
        .map((r: unknown) => (r as { va: number }).va),
    );

    let added = 0, refused = 0;
    for (const c of fresh.values()) {
      if (rejected.has(c.va)) { refused++; continue; }
      // An entry needs a measurable extent. Without one an agent would be
      // handed an impossible target, so it is DEFERRED with its reason rather
      // than dropped -- a rule that proves wrong can then be revisited
      // against the addresses it excluded.
      // Bound the measurement by the next known entry: a scan that runs past
      // it would swallow whole functions.
      const next = known.find((f) => f.va > c.va)?.va ?? img.textHi;
      const extent = yield* disasm.measureExtent(img, c.va, next);
      if (Option.isNone(extent)) {
        deferred.push({ va: c.va, reason: 'no measurable extent' });
        continue;
      }
      const size = extent.value;
      if (interiorOf(known, c.va + size - 1)) {
        deferred.push({ va: c.va, reason: 'extent overlaps a known function' });
        continue;
      }
      added += yield* db.run(
        `INSERT INTO functions(subject_sha, va, size, discovered_by)
         VALUES (?,?,?,?) ON CONFLICT(subject_sha, va) DO NOTHING`,
        [sha, c.va, size, c.evidence],
      );
    }

    return {
      at: Date.now() / 1000,
      scanned,
      candidates: candidates.length,
      added,
      refused,
      alreadyKnown,
      interior,
      deferred,
      byEvidence,
    };
  }

  *expandFrom(vas: ReadonlyArray<number>): EffectGen<ExpansionReport, Failure> {
    const db = this.dependencies.Db;
    const img = yield* this.image();
    const candidates: Candidate[] = [];

    for (const va of vas) {
      const row = (yield* db.one(
        'SELECT f.va AS va, f.size AS size, (SELECT COUNT(*) FROM proven p WHERE p.va = f.va) AS proven FROM functions f WHERE f.va = ?',
        [va],
      )) as { va: number; size: number; proven: number } | null;
      if (row === null) continue;
      // A call inside a PROVEN function is a fact about verified bytes; the
      // same call inside an unproven one depends on the decode being right.
      const evidence: Evidence = row.proven > 0 ? 'proven-call' : 'decoded-call';
      for (const t of yield* this.callTargets(img, row)) {
        candidates.push({ va: t, evidence, from: row.va });
      }
    }
    return yield* this.record(candidates, img, vas.length);
  }

  *scanGaps(add: boolean): EffectGen<GapReport, Failure> {
    const db = this.dependencies.Db;
    const disasm = this.dependencies.Disasm;
    const img = yield* this.image();
    const sha = yield* this.subjectSha();
    const known = yield* this.inventory();

    const rejected = new Set(
      (yield* db.all('SELECT va FROM rejected_entries WHERE subject_sha = ?', [sha]))
        .map((r: unknown) => (r as { va: number }).va),
    );

    /**
     * Every address where a padding run ends on a 16-byte boundary.
     *
     * These bound each other, which is what the gap walk was missing: a
     * function inside a dense stretch could not be measured because the only
     * available end bound was the next INVENTORY entry, often thousands of
     * bytes away past several other functions. Boundary-to-boundary is the
     * span MSVC actually laid out.
     */
    // 0x90 is NOP and 0xCC is INT3; MSVC pads between functions with either.
    // 0x00 is counted as padding too: the linker zero-fills to a boundary,
    // and `00 00` decodes as a valid instruction, which is exactly how
    // unreadable bytes once became phantom entries.
    const PAD = new Set([0x90, 0xcc, 0x00]);
    const byteAt = (va: number): number | undefined => img.bytes[va - img.imageBase];

    const report = {
      at: Date.now() / 1000,
      textBytes: img.textHi - img.textLo,
      coveredBytes: known.reduce((n, f) => n + f.size, 0),
      gaps: 0,
      paddingGaps: 0,
      paddingBytes: 0,
      residueGaps: 0,
      residueBytes: 0,
      measured: 0,
      added: 0,
      deferred: [] as Array<{ va: number; bytes: number; reason: string; head: string }>,
    };

    for (let i = 0; i + 1 < known.length; i++) {
      const gapLo = known[i]!.va + known[i]!.size;
      const gapHi = known[i + 1]!.va;
      if (gapHi <= gapLo) continue;
      report.gaps += 1;

      let allPadding = true;
      for (let va = gapLo; va < gapHi; va++) {
        const b = byteAt(va);
        if (b === undefined || !PAD.has(b)) { allPadding = false; break; }
      }
      if (allPadding) {
        report.paddingGaps += 1;
        report.paddingBytes += gapHi - gapLo;
        continue;
      }
      report.residueGaps += 1;
      report.residueBytes += gapHi - gapLo;

      // Split the gap at padding boundaries first, then measure each span
      // against the NEXT boundary rather than against the far end of the gap.
      const bounds: number[] = [gapLo];
      for (let va = gapLo; va < gapHi; va++) {
        const b = byteAt(va);
        if (b === undefined || !PAD.has(b)) continue;
        let end = va;
        while (end < gapHi && PAD.has(byteAt(end) ?? 0)) end += 1;
        if (end % 16 === 0 && end < gapHi && !PAD.has(byteAt(end) ?? 0x90)) {
          bounds.push(end);
        }
        va = end;
      }
      bounds.push(gapHi);

      for (let k = 0; k + 1 < bounds.length; k++) {
        const at = bounds[k]!;
        const until = bounds[k + 1]!;
        const b = byteAt(at);
        if (b === undefined || PAD.has(b) || rejected.has(at)) continue;

        // MEASURED AT ONE BOUNDARY ONLY, and the alternative was tried.
        //
        // A padding run ending on a 16-byte boundary is usually where a
        // function starts, but MSVC also emits single 0x90 bytes INSIDE a
        // function to align a loop target, and one landing on a boundary is
        // indistinguishable. Such a false boundary truncates the span of the
        // real function before it, which is why 0x518700 -- opening
        // `64 a1 00 00 00 00 6a ff`, MSVC's structured-exception frame setup,
        // which appears nowhere but at an entry -- cannot be measured here.
        //
        // Letting a failed span retry against successive boundaries fixes
        // exactly that case, and was measured against 1,119 proven functions
        // before being kept: it took the unmeasured share from 2.0% to 0.1%,
        // and of the 21 it newly measured, 4 were right and 17 OVERRAN into
        // the next function. Exact went 89.7% to 90.1% while too-long went
        // 8.3% to 9.8%. Seventeen wrong entries, each costing an agent a
        // reconstruction of two functions written as one, is not worth four
        // right ones, so it is not done.
        //
        // What would settle these is evidence that a span START is an entry,
        // independent of layout -- which is what a reference provides and
        // these addresses by definition lack.
        const extent = yield* disasm.measureExtent(img, at, until);
        if (Option.isNone(extent)) {
          const head = [...img.bytes.subarray(at - img.imageBase, at - img.imageBase + 8)]
            .map((x) => x.toString(16).padStart(2, '0'))
            .join(' ');
          report.deferred.push({
            va: at,
            bytes: until - at,
            reason:
              'does not decode contiguously to a terminator before the next ' +
              'padding boundary',
            head,
          });
          continue;
        }
        const size = extent.value;
        report.measured += 1;
        if (add) {
          // `padding-aligned` when the span starts at a boundary this scan
          // found, which is the evidence that it is an entry at all.
          const evidence = k === 0 ? 'gap-residue' : 'padding-aligned';
          report.added += yield* db.run(
            `INSERT INTO functions(subject_sha, va, size, discovered_by)
             VALUES (?,?,?,?) ON CONFLICT(subject_sha, va) DO NOTHING`,
            [sha, at, size, evidence],
          );
        }
      }
    }
    // Stored: the frontier has to be countable, and its size needs a history.
    // 10.93% of the executable being unclaimed is the kind of fact that stays
    // invisible precisely because no rule covers it.
    yield* db.run('DELETE FROM executable_gaps WHERE subject_sha = ?', [sha]);
    for (const d of report.deferred) {
      yield* db.run(
        `INSERT INTO executable_gaps(subject_sha, va, bytes, head, reason, found_at)
         VALUES (?,?,?,?,?,?)
         ON CONFLICT(subject_sha, va) DO UPDATE SET
           bytes = excluded.bytes, head = excluded.head,
           reason = excluded.reason, found_at = excluded.found_at`,
        [sha, d.va, d.bytes, d.head, d.reason, report.at],
      );
    }
    yield* db.run(
      `INSERT INTO gap_scans(subject_sha, at, text_bytes, covered_bytes, padding_gaps,
                             padding_bytes, residue_gaps, residue_bytes, added)
       VALUES (?,?,?,?,?,?,?,?,?)`,
      [
        sha, report.at, report.textBytes, report.coveredBytes, report.paddingGaps,
        report.paddingBytes, report.residueGaps, report.residueBytes, report.added,
      ],
    );
    return report;
  }

  *remeasure(
    vas: ReadonlyArray<number>,
    apply: boolean,
  ): EffectGen<ReadonlyArray<Remeasurement>, Failure> {
    const db = this.dependencies.Db;
    const disasm = this.dependencies.Disasm;
    const img = yield* this.image();
    const known = yield* this.inventory();
    const out: Remeasurement[] = [];

    for (const va of vas) {
      const row = (yield* db.one(
        `SELECT f.size AS size,
                (SELECT COUNT(*) FROM proven p WHERE p.va = f.va) AS proven
           FROM functions f WHERE f.va = ?`,
        [va],
      )) as { size: number; proven: number } | null;
      if (row === null) continue;

      const nextEntry = known.find((f) => f.va > va)?.va ?? img.textHi;
      const measured = yield* disasm.measureExtent(img, va, nextEntry);

      // A proof was obtained against the recorded span. Rewriting the span
      // would leave a proof that no longer describes the function it names,
      // which is exactly the failure the `proven` view exists to prevent.
      const differs = Option.isSome(measured) && measured.value !== row.size;
      const writable = apply && differs && row.proven === 0;
      if (writable) {
        yield* db.run('UPDATE functions SET size = ? WHERE va = ?', [
          Option.getOrThrow(measured),
          va,
        ]);
      }
      out.push({ va, recorded: row.size, measured, nextEntry, applied: writable });
    }
    return out;
  }

  /** The subject hash the inventory is keyed on. */
  private *subjectSha(): EffectGen<string, DbError | DiscoveryFailed> {
    const row = (yield* this.dependencies.Db.one(
      'SELECT subject_sha FROM current_config WHERE only_row = 1',
    )) as { subject_sha: string } | null;
    if (row === null) {
      return yield* Effect.fail(new DiscoveryFailed({ reason: 'no current config' }));
    }
    return row.subject_sha;
  }

  *reject(
    entries: ReadonlyArray<{ readonly va: number; readonly reason: string }>,
  ): EffectGen<ReadonlyArray<RejectionOutcome>, Failure> {
    const db = this.dependencies.Db;
    const disasm = this.dependencies.Disasm;
    const img = yield* this.image();
    const sha = yield* this.subjectSha();
    const known = yield* this.inventory();
    const out: RejectionOutcome[] = [];

    for (const { va, reason } of entries) {
      const refuse = (why: string) =>
        out.push({ va, accepted: false, refusedBecause: Option.some(why), unblocks: [] });

      const row = (yield* db.one(
        `SELECT f.size AS size,
                (SELECT COUNT(*) FROM proven p WHERE p.va = f.va) AS proven
           FROM functions f WHERE f.va = ?`,
        [va],
      )) as { size: number; proven: number } | null;
      if (row === null) { refuse('not in the inventory'); continue; }
      // A proof is source that compiles to those bytes at that address. No
      // rule here outranks that.
      if (row.proven > 0) { refuse('this address has a byte-exact proof'); continue; }

      // Store the decode, so the rejection can be checked later against the
      // same bytes rather than taken on trust.
      // false: the whole point of a rejection is that this extent is not
      // trusted, so an undecodable tail must not be dressed up as data.
      const listing = yield* disasm.listing(
        img, { va, size: row.size }, Option.none(), false,
      );
      const evidence = Option.getOrElse(
        listing,
        () => `${row.size} bytes at 0x${va.toString(16)} do not decode to exactly that span`,
      );

      // Which entries was this address truncating? Its predecessor's extent
      // is bounded by it, so that predecessor becomes measurable once it is
      // gone -- the whole reason a spurious entry matters.
      const prior = known.filter((f) => f.va < va);
      const unblocks = prior.length === 0 ? [] : [prior[prior.length - 1]!.va];

      yield* db.run(
        `INSERT INTO rejected_entries(subject_sha, va, reason, evidence, rejected_at)
         VALUES (?,?,?,?,?)
         ON CONFLICT(subject_sha, va) DO UPDATE SET
           reason = excluded.reason, evidence = excluded.evidence,
           rejected_at = excluded.rejected_at`,
        [sha, va, reason, evidence, Date.now() / 1000],
      );
      // The deletion is CHECKED. `accepted: true` was reported five times
      // over rows that were still in the inventory afterwards, because the
      // result of the DELETE was thrown away -- an acknowledgement that says
      // the work was done without asking whether it was.
      const removed = yield* db.run(
        'DELETE FROM functions WHERE subject_sha = ? AND va = ?',
        [sha, va],
      );
      if (removed === 0) {
        refuse(
          'the rejection is recorded, but the inventory row was not removed: ' +
            `no row at 0x${va.toString(16)} under subject ` +
            `${sha.slice(0, 12)} matched the deletion`,
        );
        continue;
      }
      out.push({ va, accepted: true, refusedBecause: Option.none(), unblocks });
    }
    return out;
  }

  *auditWorkability(repair: boolean): EffectGen<WorkabilityAudit, Failure> {
    const db = this.dependencies.Db;
    const disasm = this.dependencies.Disasm;
    const img = yield* this.image();
    const sha = yield* this.subjectSha();

    const rows = (yield* db.all(
      `SELECT f.va AS va, f.size AS size,
              (SELECT COUNT(*) FROM proven p WHERE p.va = f.va) AS proven
         FROM functions f WHERE f.subject_sha = ? ORDER BY f.va`,
      [sha],
    )) as ReadonlyArray<{ va: number; size: number; proven: number }>;

    const undecodable: Array<{
      va: number; size: number; measured: Option.Option<number>;
      proven: boolean; repaired: boolean; covered: number;
    }> = [];
    let workable = 0;

    for (let k = 0; k < rows.length; k++) {
      const f = rows[k]!;
      // `decodeFunction` is the SAME call the work item uses to build the
      // listing an agent reads. Asking it here is the point: a check that
      // tests a different path cannot see this path break.
      const decoded = yield* disasm.decodeFunction(img, f);
      if (Option.isSome(decoded)) { workable++; continue; }

      const next = rows[k + 1]?.va ?? img.textHi;
      const measured = yield* disasm.measureExtent(img, f.va, next);
      const proven = f.proven > 0;
      const repaired =
        repair && !proven && Option.isSome(measured) && measured.value !== f.size;
      if (repaired) {
        yield* db.run('UPDATE functions SET size = ? WHERE subject_sha = ? AND va = ?', [
          Option.getOrThrow(measured), sha, f.va,
        ]);
      }
      undecodable.push({
        va: f.va, size: f.size, measured, proven, repaired,
        covered: yield* disasm.coverage(img, f),
      });
    }

    const at = Date.now() / 1000;
    // Stored, so the dashboard reads a fact rather than re-deriving one, and
    // so the trend is answerable.
    yield* db.run(
      `INSERT INTO inventory_audits(subject_sha, at, entries, workable,
         undecodable, undecodable_proven, repaired)
       VALUES (?,?,?,?,?,?,?)`,
      [
        sha, at, rows.length, workable, undecodable.length,
        undecodable.filter((u) => u.proven).length,
        undecodable.filter((u) => u.repaired).length,
      ],
    );
    return { at, entries: rows.length, workable, undecodable };
  }

  *rejections(): EffectGen<
    ReadonlyArray<{ readonly va: number; readonly reason: string; readonly evidence: string }>,
    DbError | DiscoveryFailed
  > {
    const sha = yield* this.subjectSha();
    const rows = yield* this.dependencies.Db.all(
      `SELECT va, reason, evidence FROM rejected_entries
        WHERE subject_sha = ? ORDER BY va`,
      [sha],
    );
    return rows as ReadonlyArray<{ va: number; reason: string; evidence: string }>;
  }

  *expandAll(maxRounds: number): EffectGen<ReadonlyArray<ExpansionReport>, Failure> {
    const db = this.dependencies.Db;
    const reports: ExpansionReport[] = [];

    for (let round = 0; round < maxRounds; round++) {
      const proven = (yield* db.all('SELECT DISTINCT va FROM proven')).map(
        (r: unknown) => (r as { va: number }).va,
      );
      const report = yield* this.expandFrom(proven);
      reports.push(report);
      // Fixpoint: stop as soon as a full pass adds nothing.
      if (report.added === 0) break;
    }
    return reports;
  }
}
