import { Effect, Option } from 'effect';
import { implementing, type EffectGen } from 'effective-modules';
import { modules } from '../index';
import { planBatches, type Candidate } from './batch';
import {
  decodeFunctionBody,
  decodeLinear,
  instructionAt,
  loadDecoder,
  offsetOf,
  type Decoder,
} from './decoder';
import { buildInventory } from './inventory';
import { discover, isCompilerGenerated } from './discovery';
import {
  coarseShape,
  equivalentModuloIdioms,
  shape,
  thisOffsets,
} from './fingerprint';
import { renderListing } from './listing';
import { matchRatio } from './similarity';
import {
  DecoderUnavailable,
  OutsideImage,
  type BatchPlan,
  type BatchRequest,
  type CodeBytes,
  type Discovery,
  type DisasmError,
  type Fingerprint,
  type FunctionExtent,
  type IDisasm,
  type Instruction,
  type Inventory,
  type Sibling,
  type SubjectImage,
} from './interface';

/**
 * The decoder is loaded once per process and the decoding itself is plain
 * synchronous code: the wasm boundary is crossed here and nowhere else, so a
 * basic-block walk over half a million instructions does not pay for an
 * Effect per instruction.
 */
export class DisasmImpl extends implementing(modules.Disasm) implements IDisasm {
  /** Run `body` over the decoder, turning anything it throws into a tagged
   *  failure. Unreadable bytes must never arrive as plausible instructions. */
  private *decoding<A>(body: (d: Decoder) => A): EffectGen<A, DecoderUnavailable> {
    const unavailable = (cause: unknown) =>
      new DecoderUnavailable({
        reason: cause instanceof Error ? cause.message : String(cause),
      });
    const d = yield* Effect.tryPromise({ try: () => loadDecoder(), catch: unavailable });
    return yield* Effect.try({ try: () => body(d), catch: unavailable });
  }

  *decodeBytes(code: CodeBytes): EffectGen<ReadonlyArray<Instruction>, DecoderUnavailable> {
    return yield* this.decoding((d) => decodeLinear(d, code.bytes, code.address));
  }

  *decodeFunction(
    subject: SubjectImage,
    fn: FunctionExtent,
  ): EffectGen<Option.Option<ReadonlyArray<Instruction>>, DisasmError> {
    if (offsetOf(subject, fn.va, fn.size) === undefined) {
      return yield* Effect.fail(new OutsideImage({ va: fn.va, size: fn.size }));
    }
    return Option.fromNullishOr(
      yield* this.decoding((d) => decodeFunctionBody(d, subject, fn)),
    );
  }

  *decodeAt(
    subject: SubjectImage,
    va: number,
  ): EffectGen<Option.Option<Instruction>, DisasmError> {
    if (offsetOf(subject, va, 0) === undefined) {
      return yield* Effect.fail(new OutsideImage({ va, size: 0 }));
    }
    const insn = yield* this.decoding((d) => instructionAt(d, subject, va, new Map()));
    return Option.fromNullishOr(insn);
  }

  *listing(
    subject: SubjectImage,
    fn: FunctionExtent,
    relocationMask: Option.Option<Uint8Array>,
  ): EffectGen<Option.Option<string>, DisasmError> {
    const insns = yield* this.decodeFunction(subject, fn);
    return Option.map(insns, (l) => renderListing(fn, l, relocationMask));
  }

  *fingerprint(
    subject: SubjectImage,
    fn: FunctionExtent,
  ): EffectGen<Option.Option<Fingerprint>, DisasmError> {
    const insns = yield* this.decodeFunction(subject, fn);
    return Option.map(insns, (l) => ({
      shape: shape(l),
      coarseShape: coarseShape(l),
      thisOffsets: thisOffsets(l),
    }));
  }

  *buildInventory(subject: SubjectImage): EffectGen<Inventory, DisasmError> {
    return yield* this.decoding((d) => buildInventory(d, subject));
  }

  *discover(
    subject: SubjectImage,
    inventory: ReadonlyArray<FunctionExtent>,
  ): EffectGen<Discovery, DisasmError> {
    return yield* this.decoding((d) => discover(d, subject, inventory));
  }

  *compilerGenerated(
    subject: SubjectImage,
    functions: ReadonlyArray<FunctionExtent>,
  ): EffectGen<ReadonlyArray<number>, DisasmError> {
    return yield* this.decoding((d) =>
      functions.filter((f) => isCompilerGenerated(d, subject, f)).map((f) => f.va),
    );
  }

  *rankSiblings(
    subject: SubjectImage,
    target: FunctionExtent,
    solved: ReadonlyArray<FunctionExtent>,
  ): EffectGen<ReadonlyArray<Sibling>, DisasmError> {
    const maybeTarget = yield* this.decodeFunction(subject, target);
    if (Option.isNone(maybeTarget)) return [];
    const targetShape = shape(maybeTarget.value);
    const targetMnemonics = coarseShape(maybeTarget.value);
    const rows = yield* this.decoding((d) => {
      const out: Sibling[] = [];
      for (const fn of solved) {
        // A function is not its own sibling.
        if (fn.va === target.va) continue;
        const insns = decodeFunctionBody(d, subject, fn);
        if (insns === undefined) continue;
        out.push({
          va: fn.va,
          size: fn.size,
          exactShape: shape(insns) === targetShape,
          mnemonicSimilarity: matchRatio(coarseShape(insns), targetMnemonics),
          addressDistance: Math.abs(fn.va - target.va),
        });
      }
      return out;
    });
    // Exact shape first, then mnemonic similarity, then address proximity.
    return [...rows].sort(
      (a, b) =>
        Number(b.exactShape) - Number(a.exactShape) ||
        b.mnemonicSimilarity - a.mnemonicSimilarity ||
        a.addressDistance - b.addressDistance,
    );
  }

  *equivalentModuloIdioms(a: CodeBytes, b: CodeBytes): EffectGen<boolean, DecoderUnavailable> {
    return yield* this.decoding((d) =>
      equivalentModuloIdioms(
        decodeLinear(d, a.bytes, a.address),
        decodeLinear(d, b.bytes, b.address),
      ),
    );
  }

  *planBatches(subject: SubjectImage, request: BatchRequest): EffectGen<BatchPlan, DisasmError> {
    const settled = new Set(request.settled);
    // Solved, plus everything assigned in ANY surviving round -- including a
    // round this plan is about to report as retirable, because its functions
    // are settled anyway and a narrower set is how parked functions got
    // reassigned once before.
    const claimed = new Set(settled);
    for (const r of request.rounds) for (const va of r.vas) claimed.add(va);

    return yield* this.decoding((d) => {
      const candidates: Candidate[] = [];
      const skipped: Array<BatchPlan['skipped'][number]> = [];
      for (const f of request.functions) {
        if (claimed.has(f.va) || f.size < request.minSize || f.size > request.maxSize) continue;
        const insns = decodeFunctionBody(d, subject, f);
        if (insns === undefined) {
          skipped.push({ va: f.va, reason: 'no-clean-decode' });
          continue;
        }
        // A thunk is almost entirely masked relocations, so a pass on one
        // proves nothing.
        if (insns.length <= 2 && insns.some((i) => i.mnemonic === 'jmp')) {
          skipped.push({ va: f.va, reason: 'thunk' });
          continue;
        }
        candidates.push({ va: f.va, size: f.size, instructions: insns });
      }
      return planBatches({
        roundId: request.roundId,
        agentCount: request.agentCount,
        budgetBytes: request.budgetBytes,
        clusterCap: request.clusterCap,
        candidates,
        skipped,
        claimed,
        settled,
        liveVas: new Set(request.functions.map((f) => f.va)),
        rounds: request.rounds,
      });
    });
  }
}
