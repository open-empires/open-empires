import { Option } from 'effect';
import type { Instruction } from '../disasm/interface';
import type { DataStrings } from './strings';
import type { ReferenceRole, StringReference, SurfaceLoad } from './interface';

/**
 * `lock(tag, wait)` and `unlock(tag)`. A scoped lock on a surface the caller
 * loads out of its own `this` -- not a profiler, and the tag is the scope's
 * label.
 */
export const LOCK_PAIR: ReadonlyMap<number, string> = new Map([
  [0x465ba0, 'lock(tag, wait)'],
  [0x465c20, 'unlock(tag)'],
]);

/** The second pair on the same object, used the same way. */
export const ACQUIRE_PAIR: ReadonlyMap<number, string> = new Map([
  [0x465c60, 'acquire(tag)'],
  [0x465cb0, 'release(tag)'],
]);

/**
 * Instructions to look at either side of a reference.
 *
 * An argument sequence is a handful of instructions; the real consumers sit
 * within twelve. The bound exists so a region that decodes into one long run
 * without a terminator cannot make this quadratic.
 */
const WINDOW = 64;

/** Control does not fall through these, so the argument sequence ends. */
const TERMINATORS: ReadonlySet<string> = new Set([
  'ret', 'retf', 'iret', 'iretd', 'int3', 'ud2', 'hlt',
]);

/** `call 0x465ba0`. Anything else in the operand means the target is not a
 *  literal address and the callee is not known from the instruction. */
const DIRECT_CALL = /^0x([0-9a-f]+)$/;

/** `ecx, dword ptr [esi + 0x20]`, or `ecx, dword ptr [esi]`. */
const MEMBER_INTO_ECX = /^ecx, dword ptr \[(e[a-z]{2})(?: \+ (0x[0-9a-f]+))?\]$/;

/** Any instruction whose destination operand is `ecx`. */
const WRITES_ECX = /^ecx(,|$)/;

/**
 * Immediate operand values, which are the hex literals OUTSIDE brackets.
 *
 * A literal inside brackets is a displacement -- `mov eax, dword ptr
 * [0x66b0fc]` READS four bytes of a string rather than referring to it, and
 * counting it would turn every global read of a string's first dword into a
 * name reference. There is no operand detail in the decoded instruction to
 * ask instead, so the distinction is made on the one thing the decoder does
 * print: the brackets.
 */
export const immediates = (opStr: string): ReadonlyArray<number> => {
  const out: number[] = [];
  let depth = 0;
  for (let i = 0; i < opStr.length; i += 1) {
    const c = opStr[i]!;
    if (c === '[') { depth += 1; continue; }
    if (c === ']') { depth -= 1; continue; }
    if (depth !== 0 || c !== '0' || opStr[i + 1] !== 'x') continue;
    let j = i + 2;
    while (j < opStr.length && /[0-9a-f]/.test(opStr[j]!)) j += 1;
    out.push(Number.parseInt(opStr.slice(i + 2, j), 16));
    i = j - 1;
  }
  return out;
};

/** One span of .text that was decoded as a unit. */
export interface DecodedRegion {
  /** The inventory function the span is, or absent for a gap between them. */
  readonly owner: Option.Option<number>;
  /** True when the span is a function body that decoded to exactly its
   *  recorded size, so the instruction boundaries are a fact. */
  readonly anchored: boolean;
  readonly instructions: ReadonlyArray<Instruction>;
}

interface Consumption {
  readonly consumer: Option.Option<number>;
  readonly consumedAt: Option.Option<number>;
  readonly argIndex: Option.Option<number>;
}

const NOT_CONSUMED: Consumption = {
  consumer: Option.none(),
  consumedAt: Option.none(),
  argIndex: Option.none(),
};

/**
 * The call that consumes the pushed string, and how many pushes separate
 * them.
 *
 * An INDIRECT call is stepped over rather than stopped at. `TribePopUpHelp`
 * pushes its tag, makes a virtual call through `[eax + 0xdc]` to produce the
 * receiver, and only then calls `acquire(tag)`; stopping at the virtual call
 * reports no consumer and loses a real name.
 */
const consumptionAfter = (
  instructions: ReadonlyArray<Instruction>,
  from: number,
): Consumption => {
  let pushes = 0;
  for (let j = from + 1; j < Math.min(instructions.length, from + 1 + WINDOW); j += 1) {
    const insn = instructions[j]!;
    if (insn.mnemonic === 'push') { pushes += 1; continue; }
    if (insn.mnemonic === 'call') {
      const direct = DIRECT_CALL.exec(insn.opStr);
      if (direct === null) continue;
      return {
        consumer: Option.some(Number.parseInt(direct[1]!, 16)),
        consumedAt: Option.some(insn.address),
        argIndex: Option.some(pushes),
      };
    }
    if (TERMINATORS.has(insn.mnemonic) || insn.mnemonic.startsWith('j')) break;
  }
  return NOT_CONSUMED;
};

/**
 * The member the call's `this` came from.
 *
 * Anchored on the CALL: the first instruction before it that writes `ecx` is
 * the one that decides, and it only names a member when it loads from a base
 * that is neither `esp` nor `ebp`. Anything else -- `mov ecx, eax` after a
 * virtual call, `pop ecx`, a stack slot -- means no member was observed, which
 * is an answer.
 */
const surfaceBefore = (
  instructions: ReadonlyArray<Instruction>,
  callIndex: number,
): Option.Option<SurfaceLoad> => {
  for (let j = callIndex - 1; j >= Math.max(0, callIndex - WINDOW); j -= 1) {
    const insn = instructions[j]!;
    if (!WRITES_ECX.test(insn.opStr)) continue;
    const member = insn.mnemonic === 'mov' ? MEMBER_INTO_ECX.exec(insn.opStr) : null;
    if (member === null || member[1] === 'esp' || member[1] === 'ebp') return Option.none();
    return Option.some({
      at: insn.address,
      memberOffset: member[2] === undefined ? 0 : Number.parseInt(member[2], 16),
      instruction: `${insn.mnemonic} ${insn.opStr}`,
    });
  }
  return Option.none();
};

const roleOf = (consumption: Consumption): ReferenceRole => {
  if (Option.isNone(consumption.consumer)) return 'referenced-only';
  if (Option.getOrElse(consumption.argIndex, () => -1) !== 0) return 'referenced-only';
  const callee = consumption.consumer.value;
  if (LOCK_PAIR.has(callee)) return 'lock-tag';
  if (ACQUIRE_PAIR.has(callee)) return 'self-named-other';
  return 'referenced-only';
};

/** Every identifier-shaped string reference in the decoded regions. */
export const referencesIn = (
  regions: ReadonlyArray<DecodedRegion>,
  strings: DataStrings,
): ReadonlyArray<StringReference> => {
  const out: StringReference[] = [];
  for (const region of regions) {
    const { instructions } = region;
    const indexOfAddress = new Map(instructions.map((insn, i) => [insn.address, i]));
    for (let k = 0; k < instructions.length; k += 1) {
      const insn = instructions[k]!;
      for (const immediate of immediates(insn.opStr)) {
        const text = strings.at(immediate);
        if (Option.isNone(text)) continue;
        const consumption = consumptionAfter(instructions, k);
        const callIndex = Option.flatMap(consumption.consumedAt, (at) =>
          Option.fromNullishOr(indexOfAddress.get(at)),
        );
        out.push({
          site: insn.address,
          stringVa: immediate,
          text: text.value,
          mnemonic: insn.mnemonic,
          anchored: region.anchored,
          containingFunction: region.owner,
          ...consumption,
          surface: Option.isNone(callIndex)
            ? Option.none()
            : surfaceBefore(instructions, callIndex.value),
          role: roleOf(consumption),
        });
      }
    }
  }
  return out;
};
