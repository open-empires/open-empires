import { Effect, Option } from 'effect';
import { implementing, type EffectGen } from 'effective-modules';
import { modules } from '../index';
import { planBatches, type Candidate } from './batch';
import {
  decodeFunctionBody,
  decodeSpan,
  decodeLinear,
  instructionAt,
  loadDecoder,
  offsetOf,
  type Decoder,
} from './decoder';
import { buildInventory } from './inventory';
import { body, discover, isCompilerGenerated } from './discovery';
import {
  coarseShape,
  equivalentModuloIdioms,
  shape,
  thisOffsets,
} from './fingerprint';
import { renderListing } from './listing';
import { matchRatio } from './similarity';
import {
  type Closability,
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
  type SubjectImage, } from './interface';

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

  *coverage(
    subject: SubjectImage,
    fn: FunctionExtent,
  ): EffectGen<number, DisasmError> {
    return yield* this.decoding((d) =>
      decodeSpan(d, subject, fn.va, fn.size).reduce((n, i) => n + i.size, 0),
    );
  }

  *listingOfBytes(
    bytes: Uint8Array,
    baseVa: number,
    label: string,
  ): EffectGen<string, DisasmError> {
    return yield* this.decoding((d) => {
      const insns = decodeLinear(d, bytes, baseVa);
      const covered = insns.reduce((n, i) => n + i.size, 0);
      const head = `${label}  ${bytes.length} bytes`;
      const lines = insns.map((i) => {
        const hex = [...i.bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
        const addr = `0x${i.address.toString(16).padStart(8, '0')}`;
        const off = `+${(i.address - baseVa).toString().padStart(5)}`;
        return `  ${off} ${addr} ${hex.padEnd(20)} ${i.mnemonic.padEnd(7)} ${i.opStr}`;
      });
      // Said rather than hidden: a listing that stops short of the bytes it
      // was given has not shown the caller everything it holds.
      const tail =
        covered < bytes.length
          ? [`  ;; ${bytes.length - covered} trailing byte(s) did not decode as instructions`]
          : [];
      return [head, ...lines, ...tail].join('\n');
    });
  }

  *measureExtent(
    subject: SubjectImage,
    va: number,
    end: number,
  ): EffectGen<Option.Option<number>, DisasmError> {
    return yield* this.decoding((d) => {
      // `body` returns a size, or a string saying why it is not a function.
      const size = body(d, subject, va, Math.min(end, subject.textHi));
      return typeof size === 'number' && size > 0 ? Option.some(size) : Option.none();
    });
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
    trustedExtent: boolean,
  ): EffectGen<Option.Option<string>, DisasmError> {
    const exact = yield* this.decodeFunction(subject, fn);
    if (Option.isSome(exact)) {
      return Option.some(renderListing(fn, exact.value, relocationMask));
    }

    // The decode did not cover the span exactly. That has two causes and only
    // one of them is a defect:
    //
    //   DATA IN THE BODY -- a switch jump table or index table, which MSVC
    //   places inside the function. The size is right, the gate proves those
    //   bytes, and 0x563770 is proven at 2009 bytes with one in it. The
    //   instructions before it are a real listing and the rest is data.
    //
    //   A WRONG SIZE -- the span cuts an instruction in half, so the decode
    //   OVERSHOOTS the span. Nothing here can render that honestly: every
    //   instruction boundary after the cut is a guess. 0x568300 (recorded
    //   1638, cutting `push 0x675714` after 2 bytes) is this case.
    //
    // Only the caller can tell these apart, so only the caller decides.
    // `covered < fn.size` does NOT discriminate: decodeSpan clamps to the
    // span, so an instruction straddling the recorded end fails to decode
    // and the coverage falls short either way. Rendering on that test alone
    // printed 0x568300's half of a `push 0x675714` as though it were a
    // switch table.
    if (!trustedExtent) return Option.none<string>();
    return yield* this.decoding((d) => {
      const insns = decodeSpan(d, subject, fn.va, fn.size);
      if (insns.length === 0) return Option.none<string>();
      const covered = insns.reduce((n, i) => n + i.size, 0);
      if (covered >= fn.size) return Option.none<string>();
      const off = fn.va - subject.imageBase;
      return Option.some(
        renderListing(
          fn,
          insns,
          relocationMask,
          subject.bytes.subarray(off + covered, off + fn.size),
        ),
      );
    });
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

  *codeExtentOf(
    bytes: Uint8Array,
    baseVa: number,
  ): EffectGen<Option.Option<number>, DisasmError> {
    return yield* this.decoding((d) => {
      // The emitted object treated as its own little image, so the one
      // implementation of "where does this function end" answers for it too.
      // `textLo`/`textHi` bound the span, which is what lets the trailing
      // jump-table test recognise a table as in-range addresses.
      const image: SubjectImage = {
        sha256: '',
        bytes,
        imageBase: baseVa,
        textLo: baseVa,
        textHi: baseVa + bytes.length,
      };
      const measured = body(d, image, baseVa, baseVa + bytes.length);
      return typeof measured === 'number' ? Option.some(measured) : Option.none<number>();
    });
  }

  *closability(
    subject: SubjectImage,
    functions: ReadonlyArray<FunctionExtent>,
  ): EffectGen<ReadonlyArray<Closability>, DisasmError> {
    return yield* this.decoding((d) =>
      functions.map((f) => {
        const insns = decodeSpan(d, subject, f.va, f.size);
        let branches = 0;
        let x87 = false;
        let jumpTable = false;
        for (const i of insns) {
          const m = i.mnemonic;
          // Every x87 mnemonic begins with `f` and no integer mnemonic does,
          // so the first character is the whole test. `fs:`/`gs:` are segment
          // PREFIXES and appear in the operand string, never as a mnemonic.
          if (m.charCodeAt(0) === 0x66 /* 'f' */) x87 = true;
          if (m === 'jmp' || m.startsWith('loop') || (m.charCodeAt(0) === 0x6a /* 'j' */)) {
            branches += 1;
            // A switch dispatch, as distinct from a call through a function
            // pointer: the scaled index is what makes it a table.
            if (m === 'jmp' && i.opStr.includes('*4')) jumpTable = true;
          }
        }
        return { va: f.va, instructions: insns.length, branches, x87, jumpTable };
      }),
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
