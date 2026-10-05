/**
 * Data addresses the code names, read out of its own instructions.
 *
 * Every reference here carries TWO confirmations, because the decoder's text
 * is a rendering and the bytes are the fact:
 *
 *   1. the address falls inside a section the subject's own flags mark as not
 *      executable, so it is data rather than a branch target;
 *   2. the value is present as a 32-bit little-endian field of the
 *      instruction's OWN BYTES. A direct branch is printed as its computed
 *      absolute target, which is nowhere in the encoding, and this is what
 *      keeps such a target from being filed as a global.
 *
 * The instruction is also the only source of the ACCESS WIDTH -- `byte ptr`,
 * `dword ptr`, `qword ptr` -- and of whether the address is dereferenced, used
 * as an array base, or merely taken.
 */
import { Option } from 'effect';
import type { Instruction } from '../disasm/interface';
import type { GlobalReference, ReferenceForm } from './interface';

/** A hex literal as the decoder prints one. */
const LITERAL = /0x([0-9a-f]+)/g;

/** Operand-size prefixes, longest first so `dword` is not read as `word`. */
const WIDTHS: ReadonlyArray<readonly [string, number]> = [
  ['xmmword ptr', 16],
  ['tbyte ptr', 10],
  ['qword ptr', 8],
  ['dword ptr', 4],
  ['word ptr', 2],
  ['byte ptr', 1],
];

/** Bytes the instruction's memory operand accesses. x86 has at most one
 *  memory operand, so one prefix in the operand text is unambiguous. */
export const accessWidth = (opStr: string): Option.Option<number> => {
  for (const [prefix, width] of WIDTHS) {
    if (opStr.includes(prefix)) return Option.some(width);
  }
  return Option.none();
};

/** Is `value` a 32-bit little-endian field of these bytes? */
export const encodesDword = (bytes: Uint8Array, value: number): boolean => {
  const want = value >>> 0;
  if (bytes.length < 4) return false;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  for (let at = 0; at + 4 <= bytes.length; at += 1) {
    if (view.getUint32(at, true) === want) return true;
  }
  return false;
};

/** A register name inside a memory operand, which is what makes the literal a
 *  BASE rather than the whole address. Matched on the x86 register names
 *  rather than on "any letters", so `ptr` and the segment colon do not count. */
const REGISTER =
  /\b(?:e?(?:ax|bx|cx|dx|si|di|bp|sp)|[abcd][hl]|r[0-9]+[dwb]?)\b/;

/**
 * How one literal appears in the operand text.
 *
 * None when the literal is not actually in the string at the offset given,
 * which cannot happen for a match the caller found -- it is here so the
 * bracket search can report "not inside any bracket" as absolute versus
 * immediate without a second scan.
 */
const formOf = (opStr: string, literal: string, at: number): ReferenceForm => {
  const open = opStr.lastIndexOf('[', at);
  const close = opStr.indexOf(']', at);
  if (open < 0 || close < at) return 'immediate';
  const inner = opStr.slice(open + 1, close).replace(literal, '');
  return REGISTER.test(inner) ? 'indexed' : 'absolute';
};

/** An operand literal the decoder printed that the instruction does not
 *  encode. Recorded, never used: the decoder computed it, so it names
 *  something the bytes do not contain. */
export interface UnconfirmedReference {
  readonly site: number;
  readonly address: number;
  readonly mnemonic: string;
  readonly opStr: string;
}

export interface CodeReferences {
  readonly references: ReadonlyArray<GlobalReference>;
  readonly unconfirmed: ReadonlyArray<UnconfirmedReference>;
}

/**
 * Every data address named by the operands of these instructions.
 *
 * `containingFunction` is the function the caller decoded them from; pass
 * None for a stretch the inventory attributes to no function.
 */
export const dataReferences = (input: {
  readonly instructions: ReadonlyArray<Instruction>;
  readonly containingFunction: Option.Option<number>;
  /** True when the address lies in a section that is not executable. */
  readonly inDataRegion: (va: number) => boolean;
}): CodeReferences => {
  const references: GlobalReference[] = [];
  const unconfirmed: UnconfirmedReference[] = [];

  for (const instruction of input.instructions) {
    const { opStr, mnemonic, address: site, bytes } = instruction;
    const width = accessWidth(opStr);
    LITERAL.lastIndex = 0;
    const seen = new Set<string>();
    for (const match of opStr.matchAll(LITERAL)) {
      const literal = match[0];
      const value = Number.parseInt(match[1]!, 16);
      if (!input.inDataRegion(value)) continue;
      const form = formOf(opStr, literal, match.index);
      // One instruction can name the same address twice only by naming it in
      // the same form twice, which is one fact, not two.
      const key = `${value}:${form}`;
      if (seen.has(key)) continue;
      seen.add(key);
      if (!encodesDword(bytes, value)) {
        unconfirmed.push({ site, address: value, mnemonic, opStr });
        continue;
      }
      references.push({
        site,
        address: value,
        form,
        // An immediate carries the address and reads nothing, so the
        // instruction's operand size says nothing about the global's extent.
        width: form === 'immediate' ? Option.none() : width,
        mnemonic,
        opStr,
        containingFunction: input.containingFunction,
      });
    }
  }
  return { references, unconfirmed };
};

/** x87 instructions whose memory operand is a float. `fild`, `fist`, `fistp`
 *  and `fbld` convert an INTEGER and are deliberately absent. */
const X87_FLOAT = new Set([
  'fld', 'fst', 'fstp', 'fadd', 'faddp', 'fsub', 'fsubp', 'fsubr', 'fsubrp',
  'fmul', 'fmulp', 'fdiv', 'fdivp', 'fdivr', 'fdivrp', 'fcom', 'fcomp',
  'fcompp', 'fucom', 'fucomp',
]);

export const readsAsFloat = (mnemonic: string): boolean => X87_FLOAT.has(mnemonic);
