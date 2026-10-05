import { Effect, Option } from 'effect';
import { effunct, implementing, type EffectGen } from 'effective-modules';
import { modules } from '../index';
import type { IDb } from '../db/interface';
import { reconstructionsInForce, type Reconstruction } from '../db/reconstructions';
import type { Instruction, SubjectImage } from '../disasm/interface';
import type { EmittedCode } from '../gate/interface';
import { AddressClass, NoCurrentSubject, type Subject } from '../subject/interface';
import type { IReloc, RelocationField, RelocationReport, RelocFailure } from './interface';

/** Compiles at once; bounded by the gate's single container, as elsewhere. */
const CONCURRENCY = 8;

/** A relocation patches the four bytes at its recorded address. */
const FIELD_WIDTH = 4;

/**
 * The four-byte fields inside `[0, size)` the linker would patch.
 *
 * The object records a relocation's ADDRESS; the gate expands each one into
 * the four byte offsets it covers. Grouping them back means taking a run of
 * four consecutive marked offsets and consuming it, so two adjacent
 * relocations yield two fields rather than seven overlapping ones.
 */
const fieldsOf = (entry: EmittedCode, size: number): ReadonlyArray<number> => {
  const marked = [...entry.relocated].filter((k) => k >= 0 && k + FIELD_WIDTH <= size).sort((a, b) => a - b);
  const fields: number[] = [];
  const consumed = new Set<number>();
  for (const k of marked) {
    if (consumed.has(k)) continue;
    let whole = true;
    for (let j = 0; j < FIELD_WIDTH; j += 1) if (!entry.relocated.has(k + j)) whole = false;
    if (!whole) continue;
    fields.push(k);
    for (let j = 0; j < FIELD_WIDTH; j += 1) consumed.add(k + j);
  }
  return fields;
};

/** The decoded instruction whose bytes contain `offset`, excluding its first
 *  byte -- an opcode is never a relocation field. */
const containing = (
  instructions: ReadonlyArray<Instruction>,
  va: number,
  offset: number,
): Option.Option<Instruction> => {
  for (const ins of instructions) {
    const start = ins.address - va;
    if (start < offset && offset < start + ins.size) return Option.some(ins);
  }
  return Option.none();
};

/**
 * Where the field points.
 *
 * A direct `call`/`jmp` carries a displacement from the END of the
 * instruction, which for these is always the field's own end. An indirect one
 * -- `call dword ptr [...]` -- carries the ADDRESS of a slot, which is already
 * absolute, and so does every other instruction with a relocated operand.
 */
const targetOf = (
  stored: number,
  va: number,
  offset: number,
  instruction: Option.Option<Instruction>,
): { readonly kind: 'rel32' | 'absolute'; readonly target: number } => {
  const relative =
    Option.isSome(instruction) &&
    (instruction.value.mnemonic === 'call' || instruction.value.mnemonic === 'jmp') &&
    !instruction.value.opStr.startsWith('dword');
  return relative
    ? { kind: 'rel32', target: (va + offset + FIELD_WIDTH + stored) >>> 0 }
    : { kind: 'absolute', target: stored >>> 0 };
};

const label = (c: AddressClass): string =>
  AddressClass.$match(c, {
    ExceptionRegistration: () => 'fs:[0] exception registration',
    FunctionEntry: () => 'function entry',
    ImportSlot: () => 'import slot',
    TextNonEntry: () => 'compiler-generated code in .text',
    Data: ({ section }) => `data (${section})`,
    Unknown: () => 'unknown',
  });

/** One function's fields, before anything is classified. */
interface Derived {
  readonly reproduced: boolean;
  readonly fields: ReadonlyArray<Omit<RelocationField, 'classification'>>;
}

export class RelocImpl
  extends implementing(modules.Reloc).uses(modules.Db, modules.Gate, modules.Disasm, modules.Subject)
  implements IReloc
{
  *check(): EffectGen<RelocationReport, RelocFailure> {
    const db: IDb = this.dependencies.Db;
    const subject = this.dependencies.Subject;

    const current = yield* subject.current();
    if (Option.isNone(current)) {
      return yield* Effect.fail(
        new NoCurrentSubject({
          reason: 'no subject is configured, so no address can be classified',
        }),
      );
    }
    const s: Subject = current.value;
    // The span comes from here, and is handed to the decoder as the subject
    // declares it. Writing it down is what cost the Python 9,216 bytes of
    // .text.
    const image: SubjectImage = {
      sha256: s.sha256,
      bytes: yield* subject.imageBytes(),
      imageBase: s.imageBase,
      textLo: s.textLo,
      textHi: s.textHi,
    };

    const corpus = yield* reconstructionsInForce(db);
    const derived = yield* Effect.forEach(
      corpus,
      effunct((r: Reconstruction) => this.deriveFields(r, image)),
      { concurrency: CONCURRENCY },
    );

    const flat = derived.flatMap((d) => d.fields);
    // One batched classification: the answer is drawn from the whole declared
    // symbol set, and reading it once per field would read it 5,000 times.
    const classes = yield* subject.classifyAddresses(flat.map((f) => f.target));

    const fields: RelocationField[] = flat.map((f, i) => ({
      ...f,
      classification: classes[i]!,
    }));

    const tally = new Map<string, number>();
    for (const f of fields) {
      const key = label(f.classification);
      tally.set(key, (tally.get(key) ?? 0) + 1);
    }
    const dangling = fields.filter((f) => f.classification._tag === 'Unknown');

    return {
      considered: corpus.length,
      reproduced: derived.filter((d) => d.reproduced).length,
      notReproduced: derived.filter((d) => !d.reproduced).length,
      fields: fields.length,
      explained: fields.length - dangling.length,
      byClass: [...tally.entries()]
        .map(([l, n]) => ({ label: l, fields: n }))
        .sort((a, b) => b.fields - a.fields),
      dangling,
    };
  }

  /**
   * Compile one reconstruction and derive its relocation fields.
   *
   * Only a source that still reproduces the subject's bytes AT THE ENTRY
   * contributes: the fields are read from the object's relocation records but
   * their VALUES are read from the subject, so the two only describe the same
   * instructions when the object's code is the subject's code. A reproduction
   * that has lapsed is reported as such rather than returning no fields, which
   * would have made a broken corpus read as "0 dangling".
   */
  private *deriveFields(r: Reconstruction, image: SubjectImage): EffectGen<Derived, RelocFailure> {
    const original = yield* this.dependencies.Subject.bytesAt({ va: r.va, length: r.size });
    if (Option.isNone(original)) return { reproduced: false, fields: [] };
    const bytes = original.value;

    const contribution = yield* this.dependencies.Gate.contribute({
      va: r.va, original: bytes, source: r.source, flags: r.flags,
    });
    const entryMatch =
      contribution.verdict.exact &&
      Option.getOrElse(contribution.verdict.matchedAt, () => -1) === 0;
    if (!entryMatch || Option.isNone(contribution.entry)) {
      return { reproduced: false, fields: [] };
    }

    const offsets = fieldsOf(contribution.entry.value, r.size);
    if (offsets.length === 0) return { reproduced: true, fields: [] };

    const instructions = yield* this.dependencies.Disasm.decodeBytes({
      bytes, address: r.va,
    });
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    return {
      reproduced: true,
      fields: offsets.map((offset) => {
        const stored = view.getUint32(offset, true);
        const { kind, target } = targetOf(
          stored, r.va, offset, containing(instructions, r.va, offset),
        );
        return { va: r.va, offset, stored, kind, target };
      }),
    };
  }
}
