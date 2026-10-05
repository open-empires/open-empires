import { Effect, Option, Schema } from 'effect';
import { implementing, type EffectGen } from 'effective-modules';
import { modules } from '../index';
import type { IDb } from '../db/interface';
import { rows } from '../db/rows';
import type { Instruction, SubjectImage } from '../disasm/interface';
import { NoCurrentSubject, type Subject } from '../subject/interface';
import { attribute } from './attribution';
import { referencesIn, type DecodedRegion } from './references';
import { assemble } from './report';
import { dataStrings } from './strings';
import type {
  INames,
  NameReport,
  NamesError,
  RecoveredName,
  StringReference,
  WithheldName,
} from './interface';

const FunctionRow = Schema.Struct({ va: Schema.Number, size: Schema.Number });

const ReferenceRow = Schema.Struct({
  site: Schema.Number,
  string_va: Schema.Number,
  text: Schema.String,
  mnemonic: Schema.String,
  anchored: Schema.Number,
  containing_function: Schema.NullOr(Schema.Number),
  consumer: Schema.NullOr(Schema.Number),
  consumed_at: Schema.NullOr(Schema.Number),
  arg_index: Schema.NullOr(Schema.Number),
  receiver_at: Schema.NullOr(Schema.Number),
  receiver_offset: Schema.NullOr(Schema.Number),
  receiver_insn: Schema.NullOr(Schema.String),
  role: Schema.Literals(['lock-tag', 'self-named-other', 'referenced-only']),
});

const NameRow = Schema.Struct({
  va: Schema.Number,
  name: Schema.String,
  class_name: Schema.NullOr(Schema.String),
  name_confidence: Schema.Literals(['lock-tag', 'self-named-other']),
});

const WithheldRow = Schema.Struct({
  va: Schema.Number,
  reason: Schema.String,
  name: Schema.String,
});

/**
 * Original function names, recovered from the subject's own strings.
 *
 * WHY THE EXECUTABLE SPAN IS READ IN TWO WAYS AND NOT ONE
 * ------------------------------------------------------
 * A single linear decode of .text is not available: the decoder stops dead
 * 11 KB in, at the first run of bytes that are not instructions, and a sweep
 * that resynchronises by stepping one byte has no privileged alignment -- it
 * answers a different question depending on where it starts.
 *
 * So the span is read as the inventory describes it. A function whose body
 * decodes to exactly its recorded size HAS known instruction boundaries, and
 * 6,559 of 6,570 do; those references are facts. Everything else -- the 5,927
 * gaps between inventory functions, and the 11 functions whose bodies do not
 * decode cleanly -- is swept with resynchronisation and marked `anchored = 0`,
 * because in those regions a different alignment gives a different answer.
 *
 * That distinction is not cosmetic. The 13 withheld candidates turn on tags
 * pushed from unattributed regions, so the weakest rows in the table are the
 * ones carrying the most consequential finding, and a reader has to be able to
 * see which they are.
 */
export class NamesImpl
  extends implementing(modules.Names).uses(modules.Db, modules.Disasm, modules.Subject)
  implements INames
{
  *recover(): EffectGen<NameReport, NamesError> {
    const db: IDb = this.dependencies.Db;
    const subject = yield* this.currentSubject();
    const image: SubjectImage = {
      sha256: subject.sha256,
      bytes: yield* this.dependencies.Subject.imageBytes(),
      imageBase: subject.imageBase,
      textLo: subject.textLo,
      textHi: subject.textHi,
    };
    const inventory = yield* rows(
      db,
      FunctionRow,
      'SELECT va, size FROM functions WHERE subject_sha = ? ORDER BY va',
      [subject.sha256],
    );
    const references = referencesIn(
      yield* this.decodeSpan(image, inventory),
      dataStrings({
        bytes: image.bytes,
        sections: subject.sections,
        textLo: subject.textLo,
        textHi: subject.textHi,
      }),
    );
    const { names, withheld } = attribute(references);
    yield* db.tx(() => this.record(subject.sha256, references, names, withheld));
    return assemble({ subjectSha256: subject.sha256, references, names, withheld });
  }

  *recorded(): EffectGen<Option.Option<NameReport>, NamesError> {
    const db: IDb = this.dependencies.Db;
    const subject = yield* this.currentSubject();
    const stored = yield* rows(
      db,
      ReferenceRow,
      `SELECT site, string_va, text, mnemonic, anchored, containing_function,
              consumer, consumed_at, arg_index, receiver_at, receiver_offset,
              receiver_insn, role
         FROM string_references WHERE subject_sha = ? ORDER BY site`,
      [subject.sha256],
    );
    if (stored.length === 0) return Option.none();
    const references: ReadonlyArray<StringReference> = stored.map((r) => ({
      site: r.site,
      stringVa: r.string_va,
      text: r.text,
      mnemonic: r.mnemonic,
      anchored: r.anchored !== 0,
      containingFunction: Option.fromNullishOr(r.containing_function),
      consumer: Option.fromNullishOr(r.consumer),
      consumedAt: Option.fromNullishOr(r.consumed_at),
      argIndex: Option.fromNullishOr(r.arg_index),
      surface:
        r.receiver_at === null || r.receiver_offset === null || r.receiver_insn === null
          ? Option.none()
          : Option.some({
              at: r.receiver_at,
              memberOffset: r.receiver_offset,
              instruction: r.receiver_insn,
            }),
      role: r.role,
    }));
    const named = yield* rows(
      db,
      NameRow,
      `SELECT va, name, class_name, name_confidence FROM functions
         WHERE subject_sha = ? AND name IS NOT NULL ORDER BY va`,
      [subject.sha256],
    );
    const names: ReadonlyArray<RecoveredName> = named.map((n) => {
      const mine = references.filter(
        (r) =>
          r.text === n.name &&
          r.role !== 'referenced-only' &&
          Option.isSome(r.containingFunction) &&
          r.containingFunction.value === n.va,
      );
      return {
        va: n.va,
        name: n.name,
        className: Option.fromNullishOr(n.class_name),
        confidence: n.name_confidence,
        stringVa: mine[0]?.stringVa ?? 0,
        refSites: mine.map((r) => r.site),
        surfaceMemberOffsets: [
          ...new Set(
            mine.flatMap((r) =>
              Option.isNone(r.surface) ? [] : [r.surface.value.memberOffset],
            ),
          ),
        ].sort((a, b) => a - b),
      };
    });
    const refused = yield* rows(
      db,
      WithheldRow,
      `SELECT w.va, w.reason, c.name
         FROM withheld_names w
         JOIN withheld_name_candidates c
           ON c.subject_sha = w.subject_sha AND c.va = w.va
        WHERE w.subject_sha = ? ORDER BY w.va, c.name`,
      [subject.sha256],
    );
    const byVa = new Map<number, WithheldName>();
    for (const r of refused) {
      const held = byVa.get(r.va) ?? { va: r.va, candidates: [], reason: r.reason };
      byVa.set(r.va, { ...held, candidates: [...held.candidates, r.name] });
    }
    return Option.some(
      assemble({
        subjectSha256: subject.sha256,
        references,
        names,
        withheld: [...byVa.values()],
      }),
    );
  }

  private *currentSubject(): EffectGen<Subject, NamesError> {
    const current = yield* this.dependencies.Subject.current();
    if (Option.isNone(current)) {
      return yield* Effect.fail(
        new NoCurrentSubject({
          reason: 'no subject is configured, so there are no strings to read names out of',
        }),
      );
    }
    return current.value;
  }

  /**
   * The executable span, as the inventory describes it.
   *
   * One region per inventory function and one per gap between them, so every
   * byte of .text is covered exactly once and every region states whether its
   * instruction boundaries are known.
   */
  private *decodeSpan(
    image: SubjectImage,
    inventory: ReadonlyArray<{ readonly va: number; readonly size: number }>,
  ): EffectGen<ReadonlyArray<DecodedRegion>, NamesError> {
    const regions: DecodedRegion[] = [];
    let at = image.textLo;
    for (const fn of inventory) {
      if (fn.va > at) {
        regions.push({
          owner: Option.none(),
          anchored: false,
          instructions: yield* this.sweep(image, at, fn.va),
        });
      }
      // A zero-size entry is an address the discovery reached and could not
      // measure. It owns no bytes, so it gets no region -- the bytes at it
      // belong to the gap that follows and are swept there.
      if (fn.size > 0) {
        const body = yield* this.dependencies.Disasm.decodeFunction(image, fn);
        regions.push({
          owner: Option.some(fn.va),
          anchored: Option.isSome(body),
          instructions: Option.isSome(body)
            ? body.value
            : yield* this.sweep(image, fn.va, fn.va + fn.size),
        });
      }
      at = Math.max(at, fn.va + fn.size);
    }
    if (at < image.textHi) {
      regions.push({
        owner: Option.none(),
        anchored: false,
        instructions: yield* this.sweep(image, at, image.textHi),
      });
    }
    return regions;
  }

  /**
   * Whatever decodes in `[lo, hi)`, resynchronising where the decoder stops.
   *
   * The decoder halts at the first bytes that are not an instruction, and
   * .text is full of them -- a single decode from the start of the section
   * reaches 0x403df9 and gives up. Stepping one byte past the halt is the only
   * way to see the rest, and it is also why these instructions are reported
   * unanchored: the first real instruction after a run of data is wherever the
   * step happens to land, not wherever the compiler put it.
   */
  private *sweep(
    image: SubjectImage,
    lo: number,
    hi: number,
  ): EffectGen<ReadonlyArray<Instruction>, NamesError> {
    const out: Instruction[] = [];
    let at = lo;
    while (at < hi) {
      const decoded = yield* this.dependencies.Disasm.decodeBytes({
        bytes: image.bytes.subarray(at - image.imageBase, hi - image.imageBase),
        address: at,
      });
      if (decoded.length === 0) {
        at += 1;
        continue;
      }
      for (const insn of decoded) out.push(insn);
      const last = decoded[decoded.length - 1]!;
      at = Math.max(at + 1, last.address + last.size);
    }
    return out;
  }

  /**
   * Replace the whole derivation for this subject.
   *
   * Cleared first, in the same transaction: a name this run no longer derives
   * must be gone rather than left looking current, and a stale name in
   * `functions.name` is worse than none because every reader downstream takes
   * it for an answer. This retracts nothing that was proved -- names are
   * derived facts about the subject's bytes and no verdict rests on them.
   */
  private *record(
    subjectSha: string,
    references: ReadonlyArray<StringReference>,
    names: ReadonlyArray<RecoveredName>,
    withheld: ReadonlyArray<WithheldName>,
  ): EffectGen<void, NamesError> {
    const db: IDb = this.dependencies.Db;
    yield* db.run('DELETE FROM withheld_name_candidates WHERE subject_sha = ?', [subjectSha]);
    yield* db.run('DELETE FROM withheld_names WHERE subject_sha = ?', [subjectSha]);
    yield* db.run('DELETE FROM string_references WHERE subject_sha = ?', [subjectSha]);
    yield* db.run(
      `UPDATE functions SET name = NULL, class_name = NULL, name_confidence = NULL
        WHERE subject_sha = ?`,
      [subjectSha],
    );
    for (const r of references) {
      yield* db.run(
        `INSERT INTO string_references(
           subject_sha, site, string_va, text, mnemonic, anchored,
           containing_function, consumer, consumed_at, arg_index,
           receiver_at, receiver_offset, receiver_insn, role)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        [
          subjectSha, r.site, r.stringVa, r.text, r.mnemonic, r.anchored ? 1 : 0,
          Option.getOrNull(r.containingFunction),
          Option.getOrNull(r.consumer),
          Option.getOrNull(r.consumedAt),
          Option.getOrNull(r.argIndex),
          Option.getOrNull(Option.map(r.surface, (s) => s.at)),
          Option.getOrNull(Option.map(r.surface, (s) => s.memberOffset)),
          Option.getOrNull(Option.map(r.surface, (s) => s.instruction)),
          r.role,
        ],
      );
    }
    for (const n of names) {
      yield* db.run(
        `UPDATE functions SET name = ?, class_name = ?, name_confidence = ?
          WHERE subject_sha = ? AND va = ?`,
        [n.name, Option.getOrNull(n.className), n.confidence, subjectSha, n.va],
      );
    }
    for (const w of withheld) {
      yield* db.run(
        'INSERT INTO withheld_names(subject_sha, va, reason) VALUES (?,?,?)',
        [subjectSha, w.va, w.reason],
      );
      for (const candidate of w.candidates) {
        yield* db.run(
          'INSERT INTO withheld_name_candidates(subject_sha, va, name) VALUES (?,?,?)',
          [subjectSha, w.va, candidate],
        );
      }
    }
  }
}
