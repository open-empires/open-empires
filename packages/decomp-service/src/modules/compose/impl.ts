import { Effect, Option, Schema } from 'effect';
import { effunct, implementing, type EffectGen } from 'effective-modules';
import { modules } from '../index';
import type { DbError, IDb } from '../db/interface';
import { reconstructionsInForce, type Reconstruction } from '../db/reconstructions';
import { rows } from '../db/rows';
import { NoCurrentSubject, type Subject } from '../subject/interface';
import type { EmittedCode } from '../gate/interface';
import {
  type Contribution,
  type CompositionReport,
  type ComposeFailure,
  type ContributionOrigin,
  type ICompose,
  type Overlap,
} from './interface';

/**
 * How many reconstructions are compiled at once.
 *
 * The gate holds one container and one Wine prefix, and each attempt gets its
 * own build directory and TMP inside it, so concurrency here is bounded by the
 * container rather than by anything this module knows. Eight is what the gate
 * was already run at.
 */
const CONCURRENCY = 8;

const now = () => Date.now() / 1000;

const ContributionRow = Schema.Struct({
  va: Schema.Number,
  attempt_id: Schema.Number,
  origin: Schema.String,
  size: Schema.Number,
  emitted: Schema.NullOr(Schema.Number),
  masked: Schema.Number,
  diff_bytes: Schema.Number,
  first_diff: Schema.NullOr(Schema.Number),
  detail: Schema.NullOr(Schema.String),
});

const RunRow = Schema.Struct({
  id: Schema.Number,
  subject_sha: Schema.String,
  toolchain_id: Schema.String,
  text_lo: Schema.Number,
  text_hi: Schema.Number,
  considered: Schema.Number,
  placed: Schema.Number,
  not_built: Schema.Number,
  too_short: Schema.Number,
  outside_span: Schema.Number,
  disagreeing: Schema.Number,
  placed_bytes: Schema.Number,
  masked_bytes: Schema.Number,
  overlaps: Schema.Number,
  diff_bytes: Schema.Number,
  unattributed_diff_bytes: Schema.Number,
});

const ConfigRow = Schema.Struct({
  subject_sha: Schema.String,
  toolchain_id: Schema.String,
  /** Read from the toolchains row rather than split back out of the id, which
   *  is `${clSha256}:${flags}` and would make this a second parser for a
   *  format only the gate gets to define. */
  flags: Schema.String,
});
const CONFIG_SQL = `
SELECT c.subject_sha AS subject_sha, c.toolchain_id AS toolchain_id, t.flags AS flags
FROM current_config c JOIN toolchains t ON t.id = c.toolchain_id
WHERE c.only_row = 1`;

const optNum = (v: number | null): Option.Option<number> =>
  v === null ? Option.none() : Option.some(v);
const optStr = (v: string | null): Option.Option<string> =>
  v === null || v === '' ? Option.none() : Option.some(v);

/** One reconstruction's own bytes, before anything is written anywhere. */
interface Placement {
  readonly reconstruction: Reconstruction;
  readonly origin: ContributionOrigin;
  readonly emitted: Option.Option<number>;
  /** Exactly `size` bytes to write at `va`, with relocation fields already
   *  taken from the subject. Absent for every origin but `placed`. */
  readonly bytes: Option.Option<Uint8Array>;
  readonly masked: number;
  readonly detail: Option.Option<string>;
}

/**
 * The bytes one reconstruction contributes, with the relocation fields taken
 * from the subject.
 *
 * This is the one place the original is still trusted, and it is counted:
 * `masked` is how many bytes of this function were not compared at all. The
 * project has no symbol map, so the four-byte call targets and global
 * addresses the linker fills in cannot be resolved here -- excusing them is
 * honest about the surrounding code and says nothing about the targets, which
 * is the relocation check's question.
 */
const place = (
  entry: EmittedCode,
  original: Uint8Array,
): { readonly bytes: Uint8Array; readonly masked: number } => {
  const out = entry.bytes.slice(0, original.length);
  let masked = 0;
  for (let k = 0; k < out.length; k += 1) {
    if (!entry.relocated.has(k)) continue;
    masked += 1;
    out[k] = original[k]!;
  }
  return { bytes: out, masked };
};

/** Inventory entries that claim bytes their neighbour also claims. */
const overlapsIn = (
  entries: ReadonlyArray<{ readonly va: number; readonly size: number }>,
): ReadonlyArray<Overlap> => {
  const sorted = [...entries].sort((a, b) => a.va - b.va);
  const found: Overlap[] = [];
  for (let i = 0; i + 1 < sorted.length; i += 1) {
    const a = sorted[i]!;
    const b = sorted[i + 1]!;
    const over = a.va + a.size - b.va;
    if (over > 0) found.push({ va: a.va, size: a.size, nextVa: b.va, overlappingBytes: over });
  }
  return found;
};

export class ComposeImpl
  extends implementing(modules.Compose).uses(modules.Db, modules.Gate, modules.Subject)
  implements ICompose
{
  *run(): EffectGen<CompositionReport, ComposeFailure> {
    const db: IDb = this.dependencies.Db;
    const gate = this.dependencies.Gate;
    const subject = this.dependencies.Subject;
    const startedAt = now();

    const current = yield* subject.current();
    if (Option.isNone(current)) {
      return yield* Effect.fail(
        new NoCurrentSubject({
          reason: 'no subject is configured, so there is no span to compose over',
        }),
      );
    }
    const s: Subject = current.value;
    const config = yield* rows(db, ConfigRow, CONFIG_SQL);
    if (config.length === 0) {
      return yield* Effect.fail(
        new NoCurrentSubject({ reason: 'current_config holds no row' }),
      );
    }
    const inForce = config[0]!.toolchain_id;

    // The span comes from the subject, never written down. The Python carried
    // a literal 0x62607D -- max(va + size) over an old inventory, 9,216 bytes
    // short of the section header's end.
    const spanBytes = s.textHi - s.textLo;
    const span = yield* subject.bytesAt({ va: s.textLo, length: spanBytes });
    if (Option.isNone(span)) {
      return yield* Effect.fail(
        new NoCurrentSubject({
          reason:
            `the subject's own bytes do not cover ${s.textLo.toString(16)}..` +
            `${s.textHi.toString(16)}, which its section header declares as .text`,
        }),
      );
    }
    const original = span.value;
    // The canvas, indexed by `va - textLo`. One buffer for the whole span, so
    // there is exactly one mapping from an address to a byte in this module.
    const composed = new Uint8Array(original);

    // Compiled here rather than inside the loop so the identity is read once,
    // and so a gate that cannot run stops the whole thing rather than turning
    // into thousands of "did not build" rows.
    const used = yield* gate.toolchain(config[0]!.flags);

    const corpus = yield* reconstructionsInForce(db);

    const placements = yield* Effect.forEach(
      corpus,
      effunct((r: Reconstruction) =>
        this.placementFor(r, s, original),
      ),
      { concurrency: CONCURRENCY },
    );

    const contributions: Contribution[] = [];
    let placed = 0;
    let notBuilt = 0;
    let tooShort = 0;
    let outsideSpan = 0;
    let disagreeing = 0;
    let placedBytes = 0;
    let maskedBytes = 0;

    for (const p of placements) {
      const { va, size } = p.reconstruction;
      let diffBytes = 0;
      let firstDiff: Option.Option<number> = Option.none();
      if (Option.isSome(p.bytes)) {
        const at = va - s.textLo;
        const bytes = p.bytes.value;
        for (let k = 0; k < bytes.length; k += 1) {
          composed[at + k] = bytes[k]!;
          if (bytes[k] !== original[at + k]) {
            diffBytes += 1;
            if (Option.isNone(firstDiff)) firstDiff = Option.some(k);
          }
        }
        placed += 1;
        placedBytes += bytes.length;
        maskedBytes += p.masked;
        if (diffBytes > 0) disagreeing += 1;
      }
      if (p.origin === 'not-built') notBuilt += 1;
      if (p.origin === 'too-short') tooShort += 1;
      if (p.origin === 'outside-span') outsideSpan += 1;
      contributions.push({
        va,
        attemptId: p.reconstruction.attempt_id,
        origin: p.origin,
        size,
        emitted: p.emitted,
        masked: p.masked,
        diffBytes,
        firstDiff,
        detail: p.detail,
      });
    }

    let diffBytes = 0;
    for (let i = 0; i < spanBytes; i += 1) if (composed[i] !== original[i]) diffBytes += 1;
    const attributed = contributions.reduce((n, c) => n + c.diffBytes, 0);
    const overlaps = overlapsIn(corpus);

    const runId = yield* db.tx(function* () {
      const id = yield* db.insert(
        `INSERT INTO composition_runs(
           subject_sha, toolchain_id, started_at, finished_at, text_lo, text_hi,
           considered, placed, not_built, too_short, outside_span, disagreeing,
           placed_bytes, masked_bytes, overlaps, diff_bytes, unattributed_diff_bytes)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        [
          s.sha256, inForce, startedAt, now(), s.textLo, s.textHi,
          corpus.length, placed, notBuilt, tooShort, outsideSpan, disagreeing,
          placedBytes, maskedBytes, overlaps.length, diffBytes, diffBytes - attributed,
        ],
      );
      for (const c of contributions) {
        yield* db.run(
          `INSERT INTO composition_contributions(
             run_id, va, attempt_id, origin, size, emitted, masked, diff_bytes,
             first_diff, detail)
           VALUES (?,?,?,?,?,?,?,?,?,?)`,
          [
            id, c.va, c.attemptId, c.origin, c.size,
            Option.getOrNull(c.emitted), c.masked, c.diffBytes,
            Option.getOrNull(c.firstDiff), Option.getOrNull(c.detail),
          ],
        );
      }
      return id;
    });

    return {
      runId,
      subjectSha: s.sha256,
      toolchainInForce: inForce,
      toolchainUsed: used.id,
      textLo: s.textLo,
      textHi: s.textHi,
      spanBytes,
      considered: corpus.length,
      placed,
      notBuilt,
      tooShort,
      outsideSpan,
      disagreeing,
      placedBytes,
      maskedBytes,
      overlaps,
      diffBytes,
      unattributedDiffBytes: diffBytes - attributed,
      problems: contributions.filter((c) => c.origin !== 'placed' || c.diffBytes > 0),
    };
  }

  /** Compile one reconstruction and work out what it contributes. Writes
   *  nothing: the caller owns the canvas, so concurrent compiles cannot race
   *  over it. */
  private *placementFor(
    r: Reconstruction,
    s: Subject,
    original: Uint8Array,
  ): EffectGen<Placement, ComposeFailure> {
    const none = {
      reconstruction: r,
      emitted: Option.none<number>(),
      bytes: Option.none<Uint8Array>(),
      masked: 0,
    };
    if (r.va < s.textLo || r.va + r.size > s.textHi) {
      return {
        ...none,
        origin: 'outside-span',
        detail: Option.some(
          `${r.va.toString(16)}+${r.size} is not inside ` +
            `${s.textLo.toString(16)}..${s.textHi.toString(16)}`,
        ),
      };
    }
    const at = r.va - s.textLo;
    const mine = original.slice(at, at + r.size);

    const contribution = yield* this.dependencies.Gate.contribute({
      va: r.va, original: mine, source: r.source, flags: r.flags,
    });
    if (Option.isNone(contribution.entry)) {
      return {
        ...none,
        origin: 'not-built',
        detail: contribution.verdict.detail,
      };
    }
    const entry = contribution.entry.value;
    if (entry.bytes.length < r.size) {
      return {
        ...none,
        origin: 'too-short',
        emitted: Option.some(entry.bytes.length),
        detail: Option.some(
          `emitted ${entry.bytes.length} bytes for a function the inventory ` +
            `claims is ${r.size}`,
        ),
      };
    }
    const { bytes, masked } = place(entry, mine);
    return {
      reconstruction: r,
      origin: 'placed',
      emitted: Option.some(entry.bytes.length),
      bytes: Option.some(bytes),
      masked,
      detail: Option.none(),
    };
  }

  *current(): EffectGen<Option.Option<CompositionReport>, DbError> {
    const db: IDb = this.dependencies.Db;
    const found = yield* rows(db, RunRow, 'SELECT * FROM composition_current');
    if (found.length === 0) return Option.none();
    const run = found[0]!;
    const problems = yield* rows(
      db,
      ContributionRow,
      `SELECT va, attempt_id, origin, size, emitted, masked, diff_bytes, first_diff, detail
       FROM composition_contributions
       WHERE run_id = ? AND (origin != 'placed' OR diff_bytes > 0)
       ORDER BY va`,
      [run.id],
    );
    return Option.some({
      runId: run.id,
      subjectSha: run.subject_sha,
      toolchainInForce: run.toolchain_id,
      // A stored run names the toolchain it was made under; there is no second
      // one to compare it with after the fact, and inventing one would be a
      // claim about a compiler this call never ran.
      toolchainUsed: run.toolchain_id,
      textLo: run.text_lo,
      textHi: run.text_hi,
      spanBytes: run.text_hi - run.text_lo,
      considered: run.considered,
      placed: run.placed,
      notBuilt: run.not_built,
      tooShort: run.too_short,
      outsideSpan: run.outside_span,
      disagreeing: run.disagreeing,
      placedBytes: run.placed_bytes,
      maskedBytes: run.masked_bytes,
      // Overlaps are a fact about the inventory, re-derivable at any time; the
      // run stores how many it saw so a later change in that number is visible.
      overlaps: [],
      diffBytes: run.diff_bytes,
      unattributedDiffBytes: run.unattributed_diff_bytes,
      problems: problems.map((c) => ({
        va: c.va,
        attemptId: c.attempt_id,
        origin: c.origin as ContributionOrigin,
        size: c.size,
        emitted: optNum(c.emitted),
        masked: c.masked,
        diffBytes: c.diff_bytes,
        firstDiff: optNum(c.first_diff),
        detail: optStr(c.detail),
      })),
    });
  }
}
