import type { Instruction } from './interface';

/**
 * Shape keys and the codegen substitutions two compilers disagree on.
 *
 * Pure, because every one of these is a function of a decoded instruction
 * sequence and nothing else.
 */

/**
 * The mnemonic and operand sequence with every hex constant replaced by K.
 *
 * Decimal operands are left alone. The Python reference appeared to fold them
 * too, but its pattern was written with escaped backslashes and matched a
 * literal backslash, so it never fired: `mov dword ptr [esp + 8]` keeps its 8
 * on both sides. Folding them here would merge clusters the reference keeps
 * apart and silently change which functions reach one agent together.
 */
export const shape = (insns: ReadonlyArray<Instruction>): string =>
  insns.map((i) => `${i.mnemonic} ${i.opStr.replace(/0x[0-9a-f]+/g, 'K')}`).join(' | ');

/** Mnemonics alone. The shape key keeps operands, so three functions that
 *  differ only in a trailing call fall into three shapes and get solved three
 *  times. */
export const coarseShape = (insns: ReadonlyArray<Instruction>): string =>
  insns.map((i) => i.mnemonic).join(' ');

const THIS_OFFSET = /\[ecx \+ (0x[0-9a-f]+|\d+)\]/g;

/** Offsets reached off ecx -- the object's fields, ascending. */
export const thisOffsets = (insns: ReadonlyArray<Instruction>): ReadonlyArray<number> => {
  const offs = new Set<number>();
  for (const i of insns) {
    for (const m of i.opStr.matchAll(THIS_OFFSET)) {
      const t = m[1]!;
      offs.add(t.startsWith('0x') ? Number.parseInt(t.slice(2), 16) : Number.parseInt(t, 10));
    }
  }
  return [...offs].sort((a, b) => a - b);
};

/** Lexicographic order on two ascending offset lists, so a function touching
 *  no fields sorts before one touching 0x4, and both before 0x8. */
export const compareOffsets = (
  a: ReadonlyArray<number>,
  b: ReadonlyArray<number>,
): number => {
  for (let i = 0; i < Math.min(a.length, b.length); i += 1) {
    if (a[i] !== b[i]) return a[i]! - b[i]!;
  }
  return a.length - b.length;
};

// --------------------------------------------------------------- idioms

/**
 * Known MSVC-6-vs-clang codegen substitutions, folded into one canonical
 * form.
 *
 * Each was observed with the rest of the function matching byte for byte on
 * either side of it -- that is the evidence it is a compiler choice and not a
 * reconstruction error. A match on this measure is weaker than byte-exactness
 * and must never be reported as it.
 */
const canonical = (insns: ReadonlyArray<Instruction>): string[] => {
  const out: string[][] = [];
  for (const i of insns) {
    const m = i.mnemonic;
    const o = i.opStr;
    // xor r,r and sub r,r both zero a register; the encoding differs.
    if (m === 'xor' && o.includes(',')) {
      const [a, b] = o.split(/,(.*)/s).map((p) => p.trim());
      if (a === b) {
        out.push(['zero', a!]);
        continue;
      }
    }
    // mov al,[m] vs movzx eax,byte [m]: the same observable effect only
    // because the callers treat the value as a byte.
    if (m === 'movzx' && o.startsWith('eax, byte ptr ')) {
      out.push(['loadb', o.slice('eax, byte ptr '.length)]);
      continue;
    }
    if (m === 'mov' && o.startsWith('al, byte ptr ')) {
      out.push(['loadb', o.slice('al, byte ptr '.length)]);
      continue;
    }
    // or r,-1 (3 bytes, MSVC) vs mov r,-1 (5 bytes, clang).
    if ((m === 'or' || m === 'mov') && o.endsWith(', 0xffffffff')) {
      out.push(['setminus1', o.split(',')[0]!.trim()]);
      continue;
    }
    // mov r,[m] + test r,r  vs  cmp dword ptr [m],0
    if (m === 'test' && o.includes(',')) {
      const [a, b] = o.split(/,(.*)/s).map((p) => p.trim());
      const prev = out[out.length - 1];
      if (a === b && prev !== undefined && prev[0] === 'mov_from' && prev[1] === a) {
        out[out.length - 1] = ['testmem', prev[2]!];
        continue;
      }
    }
    if (m === 'mov' && o.includes(', dword ptr [')) {
      const [d, s] = o.split(/,(.*)/s).map((p) => p.trim());
      out.push(['mov_from', d!, s!]);
      continue;
    }
    if (m === 'cmp' && o.endsWith(', 0') && o.startsWith('dword ptr [')) {
      out.push(['testmem', o.slice(0, -3).trim()]);
      continue;
    }
    out.push([m, o]);
  }
  return out.map((e) => e.join('\u0000'));
};

/** Branch mnemonics whose displacement legitimately differs because the code
 *  around them does. */
const BRANCHES = new Set(['je', 'jne', 'jmp', 'jz', 'jnz', 'ja', 'jb', 'jg', 'jl']);

export const equivalentModuloIdioms = (
  a: ReadonlyArray<Instruction>,
  b: ReadonlyArray<Instruction>,
): boolean => {
  const na = canonical(a);
  const nb = canonical(b);
  if (na.length !== nb.length) return false;
  for (let i = 0; i < na.length; i += 1) {
    if (na[i] === nb[i]) continue;
    const ka = na[i]!.split('\u0000')[0]!;
    if (ka === nb[i]!.split('\u0000')[0] && BRANCHES.has(ka)) continue;
    return false;
  }
  return true;
};
